# -*- coding: utf-8 -*-
"""packet_parser.py —— 数据包解析（NPA 核心）

职责：
  1. 把 scapy 包转换成轻量的 PacketRecord（供列表、过滤器、流追踪使用）
  2. 识别应用层协议：端口表 + 载荷特征 + 结构化解码
     - HTTP/1.x：请求行、状态行、首部、Content-Length 正文
     - DNS：事务 ID、QNAME、QTYPE、应答 RR
     - TLS：握手类型、ClientHello 中的 SNI
  3. 为详情树生成逐层字段（以太网/ARP/IPv4/IPv6/TCP/UDP/ICMP/应用层）
  4. 生成 Wireshark 风格的十六进制转储

设计说明：协议识别采用与 Wireshark dissector 相同的思路——
“先按端口猜，再用报文结构验证”，避免只靠端口导致 HTTP 跑在 8080
或非标准端口时识别失败。
"""

import datetime
import socket
import struct
from typing import Dict, List, Optional, Set, Tuple

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6Unknown
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw

try:
    from scapy.layers.dns import DNS
except Exception:  # pragma: no cover - scapy 极简安装时
    DNS = None

from models import DNSInfo, HTTPInfo, PacketRecord

# ---------------------------------------------------------------- 常量表

PORT_PROTO: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 162: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "SYSLOG",
    587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "ORACLE", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 27017: "MongoDB",
}

HTTP_METHODS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI",
                b"PATC", b"CONN", b"TRAC")
TLS_HANDSHAKE_NAMES = {
    1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket",
    8: "Encrypted Extensions", 11: "Certificate", 12: "Server Key Exchange",
    13: "Certificate Request", 14: "Server Hello Done", 15: "Certificate Verify",
    16: "Client Key Exchange", 20: "Finished",
}
DNS_QTYPE = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS",
    46: "RRSIG", 47: "NSEC", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}

_TCP_FLAG_ORDER = (("F", "FIN"), ("S", "SYN"), ("R", "RST"),
                   ("P", "PSH"), ("A", "ACK"), ("U", "URG"), ("E", "ECE"),
                   ("C", "CWR"))


# ------------------------------------------------------------ 网卡地址

def local_ip_set() -> Set[str]:
    """本机所有接口地址，用于判断一条连接哪一端在本地（进程溯源需要）。"""
    ips: Set[str] = {"127.0.0.1", "::1"}
    try:
        from scapy.all import conf
        for iface in conf.ifaces.values():
            for key in ("ip", "ips"):
                val = getattr(iface, key, None)
                if isinstance(val, str):
                    ips.add(val)
                elif isinstance(val, (list, tuple)):
                    ips.update(str(x) for x in val if x)
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except Exception:
        pass
    return {ip for ip in ips if ip and ip not in ("0.0.0.0", "::")}


# ------------------------------------------------------------ 工具函数

def flags_to_str(flags) -> str:
    """把 scapy 的 Flags 对象转成 "SYN,ACK" 形式。"""
    s = str(flags)
    return ",".join(name for ch, name in _TCP_FLAG_ORDER if ch in s) or "-"


def tcp_header_len(tcp: TCP) -> int:
    try:
        return (int(tcp.dataofs) or 5) * 4
    except Exception:
        return 20


def format_time(ts: float) -> str:
    dt = datetime.datetime.fromtimestamp(float(ts))
    return dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


# ------------------------------------------------------------ HTTP 解析

def parse_http(data: bytes) -> Optional[HTTPInfo]:
    """解析一段 HTTP/1.x 报文（请求或响应），失败返回 None。

    只支持明文 HTTP；HTTPS 的载荷是 TLS 记录，交给 TLS 解析器。
    """
    if not data:
        return None
    head, sep, rest = data.partition(b"\r\n\r\n")
    if not sep:
        # 首部还没收全，但有请求行时也允许部分解析
        head = data
        rest = b""
    if len(head) > 64 * 1024:
        return None
    text = head.decode("latin-1", errors="replace")
    lines = text.split("\r\n")
    if not lines:
        return None
    first = lines[0]
    info = HTTPInfo(start_line=first)

    if first.startswith("HTTP/"):
        parts = first.split(" ", 2)
        if len(parts) < 2:
            return None
        info.version = parts[0]
        try:
            info.status = int(parts[1])
        except ValueError:
            return None
        info.reason = parts[2] if len(parts) > 2 else ""
        info.is_request = False
    else:
        parts = first.split(" ", 2)
        if len(parts) < 3 or not parts[0].isalpha():
            return None
        info.method, info.uri, info.version = parts[0], parts[1], parts[2]
        if not info.version.startswith("HTTP/"):
            return None
        info.is_request = True

    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        info.headers.append((k, v))
        lk = k.lower()
        if lk == "host":
            info.host = v
        elif lk == "user-agent":
            info.user_agent = v
        elif lk == "content-type":
            info.content_type = v
        elif lk == "content-length":
            try:
                info.content_length = int(v)
            except ValueError:
                pass
        elif lk == "transfer-encoding" and "chunked" in v.lower():
            info.chunked = True

    if rest and info.content_length:
        info.body = rest[:info.content_length]
    elif rest:
        info.body = rest
    if info.chunked and info.body:
        info.body = decode_chunked(info.body)
    return info


def decode_chunked(data: bytes) -> bytes:
    """解码 HTTP/1.1 的 chunked 传输编码（用于显示响应正文）。"""
    out = bytearray()
    pos = 0
    try:
        while pos < len(data):
            line_end = data.find(b"\r\n", pos)
            if line_end < 0:
                break
            size_text = data[pos:line_end].split(b";", 1)[0].strip()
            if not size_text:
                pos = line_end + 2
                continue
            size = int(size_text, 16)
            if size == 0:
                break
            start = line_end + 2
            out.extend(data[start:start + size])
            pos = start + size + 2
    except (ValueError, IndexError):
        return bytes(out)
    return bytes(out)


# ------------------------------------------------------------- DNS 解析

def parse_dns(pkt) -> Optional[DNSInfo]:
    if DNS is None or DNS not in pkt:
        return None
    try:
        d = pkt[DNS]
        info = DNSInfo(is_response=bool(d.qr), txid=int(d.id), rcode=int(d.rcode))
        qd = d.qd
        if isinstance(qd, (list, tuple)):
            qd = qd[0] if qd else None
        if qd is not None:
            qname = qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="replace")
            info.qname = str(qname).rstrip(".") if qname else ""
            info.qtype = int(qd.qtype)
            info.qtype_name = DNS_QTYPE.get(info.qtype, str(info.qtype))
        an = d.an
        rrs = an if isinstance(an, (list, tuple)) else ([an] if an is not None else [])
        for rr in rrs[:16]:
            try:
                val = rr.rdata
                if isinstance(val, bytes):
                    val = val.decode("utf-8", errors="replace")
                info.answers.append(f"{rr.type} {val}")
            except Exception:
                pass
        return info
    except Exception:
        return None


# ------------------------------------------------------------- TLS 解析

def parse_tls(data: bytes) -> Tuple[str, str]:
    """从 TCP 载荷解析 TLS 记录，返回 (handshake_name, sni)。

    只做“看得到”的部分：TLS 1.2/1.3 的 SNI 在 ClientHello 明文里，
    之后的 Application Data 已加密，NPA 能做的只有元数据。
    """
    if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03:
        return "", ""
    try:
        pos = 5                       # record header: type(1) ver(2) len(2)
        if data[pos] != 0x01:         # 只解析 ClientHello
            name = TLS_HANDSHAKE_NAMES.get(data[pos], f"Handshake {data[pos]}")
            return name, ""
        pos += 4                      # handshake type + 3 字节长度
        pos += 2 + 32                 # client_version + random
        sid_len = data[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2 + cs_len
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos + 2 > len(data):
            return "Client Hello", ""
        ext_total = struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2
        end = min(len(data), pos + ext_total)
        sni = ""
        while pos + 4 <= end:
            etype, elen = struct.unpack("!HH", data[pos:pos + 4])
            pos += 4
            body = data[pos:pos + elen]
            pos += elen
            if etype == 0 and len(body) >= 5:
                # server_name_list: list_len(2) + type(1) + name_len(2) + name
                nlen = struct.unpack("!H", body[3:5])[0]
                sni = body[5:5 + nlen].decode("ascii", errors="replace")
        return "Client Hello", sni
    except Exception:
        return "Client Hello", ""


# --------------------------------------------------------- 协议识别

def detect_protocol(pkt, payload: bytes = b"") -> Tuple[str, int]:
    """返回 (协议显示名, IP 版本)。"""
    ipver = 0
    if IP in pkt:
        ipver = 4
    elif IPv6 in pkt:
        ipver = 6

    if ARP in pkt:
        return "ARP", 0

    if TCP in pkt:
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        by_port = PORT_PROTO.get(sport) or PORT_PROTO.get(dport)
        if payload:
            head = payload[:8]
            if any(head.startswith(m) for m in HTTP_METHODS) or head.startswith(b"HTTP/"):
                return "HTTP", ipver
            if payload[:3] == b"\x16\x03\x01" or payload[:3] == b"\x16\x03\x03" or payload[:2] == b"\x16\x03":
                return "TLS", ipver
        if by_port in ("HTTP", "HTTP-ALT"):
            # Wireshark 的协议列只在真正有 HTTP 载荷时显示 HTTP；
            # 三次握手的纯 TCP 段仍显示 TCP。
            return ("HTTP" if payload else "TCP"), ipver
        if by_port in ("HTTPS", "HTTPS-ALT", "TLS"):
            return ("HTTPS" if payload else "TCP"), ipver
        return by_port or "TCP", ipver

    if UDP in pkt:
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
        by_port = PORT_PROTO.get(sport) or PORT_PROTO.get(dport)
        if by_port == "DNS" or DNS is not None and DNS in pkt:
            return "DNS", ipver
        return by_port or "UDP", ipver

    if ICMP in pkt:
        return "ICMP", ipver
    if IPv6 in pkt:
        # 判断 ICMPv6
        layer = pkt.getlayer(IPv6)
        if layer is not None and layer.nh == 58:
            return "ICMPv6", 6
        return "IPv6", 6
    if IP in pkt:
        return "IPv4", 4
    return "OTHER", ipver


# ------------------------------------------------------------ 摘要 Info

def _http_info_line(h: HTTPInfo) -> str:
    if h.is_request:
        return h.summary
    return h.summary


def build_info(record: PacketRecord, pkt) -> str:
    """生成列表 Info 列（尽量接近 Wireshark 的可读摘要）。"""
    if ARP in pkt:
        arp = pkt[ARP]
        if int(arp.op) == 1:
            return f"Who has {arp.pdst}? Tell {arp.psrc}"
        if int(arp.op) == 2:
            return f"{arp.psrc} is at {arp.hwsrc}"
        return f"ARP op={arp.op}"

    if record.http is not None:
        return record.http.summary
    if record.dns is not None:
        return record.dns.summary

    if record.proto == "HTTP":
        if record.payload_len:
            return f"HTTP segment, Len={record.payload_len}（等待流重组）"
    if record.proto in ("HTTPS", "TLS"):
        if record.tls_handshake == "Client Hello":
            sni = f" (SNI={record.tls_sni})" if record.tls_sni else ""
            return f"Client Hello{sni}"
        if record.tls_handshake:
            return record.tls_handshake
        if record.payload_len:
            return f"Application Data (TLS), Len={record.payload_len}"

    if record.proto in ("TCP",) or record.tcp_flags:
        flags = record.tcp_flags or "-"
        extra = ""
        if record.has_flag("S") and not record.has_flag("A"):
            extra = " [SYN]"
        elif record.has_flag("F"):
            extra = " [FIN]"
        elif record.has_flag("R"):
            extra = " [RST]"
        payload = f" Len={record.payload_len}" if record.payload_len else ""
        return (f"{record.sport} -> {record.dport} [{flags}] "
                f"Seq={record.seq} Ack={record.ack} Win={getattr(pkt[TCP], 'window', 0)}"
                f"{payload}{extra}")
    if record.proto == "UDP":
        return f"{record.sport} -> {record.dport} Len={record.payload_len}"
    if record.proto == "ICMP" and ICMP in pkt:
        icmp = pkt[ICMP]
        kind = {0: "Echo (ping) reply", 8: "Echo (ping) request",
                3: "Destination unreachable", 11: "Time-to-live exceeded",
                5: "Redirect"}.get(int(icmp.type), f"type={icmp.type}")
        return f"{kind}  id={getattr(icmp, 'id', 0)}  seq={getattr(icmp, 'seq', 0)}"
    if record.proto == "ICMPv6":
        return f"ICMPv6 type={getattr(pkt[IPv6].payload, 'type', '?')}"
    if record.proto in ("IPv4", "IPv6"):
        return f"{record.length} bytes"
    return record.proto


# ------------------------------------------------------------ 主入口

def build_record(pkt, index: int, local_ips: Optional[Set[str]] = None) -> PacketRecord:
    """把一个 scapy 包转换成 PacketRecord（NPS -> NPA 的桥梁）。"""
    length = len(pkt)
    payload = bytes(pkt[Raw].load) if Raw in pkt else b""
    proto, ipver = detect_protocol(pkt, payload)
    rec = PacketRecord(index=index, time=float(getattr(pkt, "time", 0.0)),
                       raw=pkt, length=length, proto=proto, ip_version=ipver)

    if ARP in pkt:
        arp = pkt[ARP]
        rec.src, rec.dst = str(arp.psrc), str(arp.pdst)
    elif IP in pkt:
        ip = pkt[IP]
        rec.src, rec.dst = str(ip.src), str(ip.dst)
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        rec.src, rec.dst = str(ip6.src), str(ip6.dst)

    if TCP in pkt:
        tcp = pkt[TCP]
        rec.sport, rec.dport = int(tcp.sport), int(tcp.dport)
        rec.tcp_flags = flags_to_str(tcp.flags)
        rec.seq, rec.ack = int(tcp.seq), int(tcp.ack)
        rec.payload = payload
        rec.payload_len = len(payload)
        rec.tls_handshake, rec.tls_sni = parse_tls(payload)
        if rec.proto == "HTTP":
            rec.http = parse_http(payload)
    elif UDP in pkt:
        udp = pkt[UDP]
        rec.sport, rec.dport = int(udp.sport), int(udp.dport)
        rec.payload = payload
        rec.payload_len = len(payload)
        if rec.proto == "DNS" or (DNS is not None and DNS in pkt):
            rec.dns = parse_dns(pkt)
    elif ICMP in pkt:
        rec.payload = payload
        rec.payload_len = len(payload)

    # 判断哪一端是本机（用于进程归属）
    if local_ips and rec.src and rec.dst:
        src_local, dst_local = rec.src in local_ips, rec.dst in local_ips
        if src_local and not dst_local:
            rec.local_side = "src"
        elif dst_local and not src_local:
            rec.local_side = "dst"
        elif src_local and dst_local:
            rec.local_side = "src"

    rec.info = build_info(rec, pkt)
    return rec


# ------------------------------------------------------------ 详情树

def _fmt(value) -> str:
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def parse_layers(pkt) -> List[Tuple[str, List[Tuple[str, str]]]]:
    """逐层解析为 [(层标题, [(字段, 值), ...]), ...]，供详情树展示。"""
    layers: List[Tuple[str, List[Tuple[str, str]]]] = []

    if Ether in pkt:
        eth = pkt[Ether]
        layers.append(("Ethernet II · 以太网帧", [
            ("目的 MAC", eth.dst), ("源 MAC", eth.src),
            ("类型", f"0x{int(eth.type):04x}"),
        ]))

    if ARP in pkt:
        arp = pkt[ARP]
        layers.append(("ARP · 地址解析协议", [
            ("硬件类型", arp.hwtype), ("协议类型", f"0x{int(arp.ptype):04x}"),
            ("操作码", {1: "请求 (1)", 2: "应答 (2)"}.get(int(arp.op), str(arp.op))),
            ("发送方 MAC", arp.hwsrc), ("发送方 IP", arp.psrc),
            ("目标 MAC", arp.hwdst), ("目标 IP", arp.pdst),
        ]))

    if IP in pkt:
        ip = pkt[IP]
        layers.append(("IPv4 · 网际协议", [
            ("版本", ip.version), ("首部长度", f"{(int(ip.ihl) or 5) * 4} 字节"),
            ("服务类型 (TOS)", f"0x{int(ip.tos):02x}"),
            ("总长度", ip.len), ("标识 (ID)", f"0x{int(ip.id):04x}"),
            ("标志", str(ip.flags)), ("分片偏移", ip.frag),
            ("TTL", ip.ttl), ("上层协议", f"{ip.proto} ({_ip_proto_name(int(ip.proto))})"),
            ("首部校验和", f"0x{int(ip.chksum or 0):04x}"),
            ("源地址", ip.src), ("目的地址", ip.dst),
        ]))

    if IPv6 in pkt:
        ip6 = pkt[IPv6]
        layers.append(("IPv6 · 网际协议", [
            ("版本", ip6.version), ("流量类别", ip6.tc),
            ("流标签", f"0x{int(ip6.fl):05x}"), ("载荷长度", ip6.plen),
            ("下一首部", f"{ip6.nh} ({_ip_proto_name(int(ip6.nh))})"),
            ("跳数限制", ip6.hlim),
            ("源地址", ip6.src), ("目的地址", ip6.dst),
        ]))

    if TCP in pkt:
        tcp = pkt[TCP]
        fields = [
            ("源端口", tcp.sport), ("目的端口", tcp.dport),
            ("序号 (Seq)", tcp.seq), ("确认号 (Ack)", tcp.ack),
            ("首部长度", f"{tcp_header_len(tcp)} 字节"),
            ("标志位", flags_to_str(tcp.flags)),
            ("窗口大小", tcp.window),
            ("校验和", f"0x{int(tcp.chksum or 0):04x}"),
            ("紧急指针", tcp.urgptr),
            ("载荷长度", len(bytes(tcp.payload))),
        ]
        opts = _tcp_options(tcp)
        if opts:
            fields.append(("选项", "; ".join(opts)))
        layers.append(("TCP · 传输控制协议", fields))

    if UDP in pkt:
        udp = pkt[UDP]
        layers.append(("UDP · 用户数据报协议", [
            ("源端口", udp.sport), ("目的端口", udp.dport),
            ("长度", udp.len), ("校验和", f"0x{int(udp.chksum or 0):04x}"),
            ("载荷长度", len(bytes(udp.payload))),
        ]))

    if ICMP in pkt:
        icmp = pkt[ICMP]
        fields = [("类型", icmp.type), ("代码", icmp.code),
                  ("校验和", f"0x{int(icmp.chksum or 0):04x}")]
        if hasattr(icmp, "id"):
            fields += [("标识 (id)", icmp.id), ("序号 (seq)", icmp.seq)]
        layers.append(("ICMP · 控制报文协议", fields))

    # 应用层解析
    payload = bytes(pkt[Raw].load) if Raw in pkt else b""
    if payload:
        http = parse_http(payload)
        if http is not None and http.start_line:
            fields = [("类型", "请求" if http.is_request else "响应"),
                      ("起始行", http.start_line)]
            if http.is_request:
                fields += [("方法", http.method), ("URI", http.uri),
                           ("Host", http.host), ("User-Agent", http.user_agent)]
            else:
                fields += [("状态码", http.status), ("原因短语", http.reason),
                           ("Content-Type", http.content_type)]
            fields.append(("Content-Length", http.content_length))
            for k, v in http.headers:
                fields.append((f"首部: {k}", v))
            if http.body:
                preview = http.body[:512].decode("utf-8", errors="replace")
                fields.append(("正文预览", preview))
            if http.chunked:
                fields.append(("传输编码", "chunked（已解码展示）"))
            layers.append(("HTTP · 超文本传输协议", fields))

        hs, sni = parse_tls(payload)
        if hs:
            layers.append(("TLS · 传输层安全", [
                ("握手类型", hs), ("SNI (服务器名称)", sni or "-"),
                ("记录版本", f"{payload[1]}.{payload[2]}"),
                ("说明", "TLS 记录已加密，NPA 只能解析明文握手元数据"),
            ]))

        dns = parse_dns(pkt)
        if dns is not None:
            fields = [("事务 ID", f"0x{dns.txid:04x}"),
                      ("类型", "响应" if dns.is_response else "查询"),
                      ("问题域名", dns.qname),
                      ("问题类型", f"{dns.qtype_name} ({dns.qtype})"),
                      ("返回码", dns.rcode)]
            for i, ans in enumerate(dns.answers, 1):
                fields.append((f"应答 {i}", ans))
            layers.append(("DNS · 域名系统", fields))

        if not layers or layers[-1][0].split(" ")[0] not in ("HTTP", "TLS", "DNS"):
            preview = payload[:256]
            try:
                text = preview.decode("utf-8")
                shown = text if all(31 < ord(c) or c in "\r\n\t" for c in text) else preview.hex()
            except UnicodeDecodeError:
                shown = preview.hex()
            layers.append((f"Data · 应用层载荷（{len(payload)} 字节）", [
                ("长度", len(payload)), ("预览", shown),
                ("ASCII", "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:128])),
            ]))

    return layers


def _ip_proto_name(num: int) -> str:
    return {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
            47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF"}.get(num, "未知")


def _tcp_options(tcp: TCP) -> List[str]:
    out: List[str] = []
    try:
        for opt in tcp.options or []:
            name, val = opt[0], opt[1] if len(opt) > 1 else None
            if name == "MSS":
                out.append(f"MSS={val}")
            elif name == "SAckOK":
                out.append("SACK permitted")
            elif name == "WScale":
                out.append(f"Window Scale={val}")
            elif name == "Timestamp":
                out.append(f"Timestamp={val}")
            elif name == "SAck":
                out.append("SACK")
            else:
                out.append(f"{name}={val}")
    except Exception:
        pass
    return out


# ------------------------------------------------------------ 十六进制

def hex_dump(pkt_or_bytes, width: int = 16) -> str:
    """Wireshark 风格十六进制转储：偏移 + 十六进制 + ASCII。"""
    raw = pkt_or_bytes if isinstance(pkt_or_bytes, (bytes, bytearray)) else bytes(pkt_or_bytes)
    lines = []
    for offset in range(0, len(raw), width):
        chunk = raw[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def printable_payload(data: bytes, limit: int = 20000) -> str:
    """把载荷转成可读文本；不可打印字节用 '.' 代替，保留换行。"""
    if not data:
        return ""
    data = data[:limit]
    return "".join(chr(b) if (32 <= b < 127 or b in (9, 10, 13)) else "." for b in data)
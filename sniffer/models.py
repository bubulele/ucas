# -*- coding: utf-8 -*-
"""数据模型：抓包记录、HTTP/DNS/TLS 解析结果。

所有字段都保持为普通 Python 类型，便于显示过滤器直接取值，
也便于把抓包结果序列化/导出。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class HTTPInfo:
    """一条 HTTP 报文（请求或响应）的解析结果。"""
    is_request: bool = False
    method: str = ""
    uri: str = ""
    version: str = ""
    status: int = 0
    reason: str = ""
    host: str = ""
    user_agent: str = ""
    content_type: str = ""
    content_length: int = 0
    chunked: bool = False
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    start_line: str = ""

    @property
    def summary(self) -> str:
        if self.is_request:
            target = self.uri or "/"
            host = f"  Host: {self.host}" if self.host else ""
            return f"{self.method} {target} {self.version}{host}"
        ctype = f"  ({self.content_type})" if self.content_type else ""
        return f"{self.version} {self.status} {self.reason}{ctype}"


@dataclass
class DNSInfo:
    """DNS 查询/应答的关键字段（不追求完整 RR 解析）。"""
    is_response: bool = False
    txid: int = 0
    qname: str = ""
    qtype: int = 0
    qtype_name: str = ""
    answers: List[str] = field(default_factory=list)
    rcode: int = 0

    @property
    def summary(self) -> str:
        kind = "Standard query response" if self.is_response else "Standard query"
        flags = f"0x{self.txid:04x}"
        q = f"{self.qtype_name} {self.qname}" if self.qname else "?"
        if self.is_response:
            ans = ", ".join(self.answers) if self.answers else "no answer"
            return f"{kind} {flags} {q}  ->  {ans}"
        return f"{kind} {flags} {q}"


@dataclass
class PacketRecord:
    """一个数据包的“索引层”记录。

    原始 scapy 包保留在 raw 中，详情树按需解析（惰性），
    这样抓大流量时不会为每个包都构建完整的协议树。
    """
    index: int
    time: float
    raw: object
    length: int
    proto: str = "OTHER"
    ip_version: int = 0
    src: str = "-"
    dst: str = "-"
    sport: int = 0
    dport: int = 0
    info: str = ""
    # TCP
    tcp_flags: str = ""
    seq: int = 0
    ack: int = 0
    payload_len: int = 0
    payload: bytes = b""
    # 应用层
    http: Optional[HTTPInfo] = None
    dns: Optional[DNSInfo] = None
    tls_sni: str = ""
    tls_handshake: str = ""
    # 归属
    pid: Optional[int] = None
    proc: str = ""
    local_side: str = ""          # "src" / "dst" / ""
    # 流
    stream_id: Optional[int] = None
    # 标记（由流追踪回填）
    tags: List[str] = field(default_factory=list)

    @property
    def src_ep(self) -> str:
        return f"{self.src}:{self.sport}" if self.sport else self.src

    @property
    def dst_ep(self) -> str:
        return f"{self.dst}:{self.dport}" if self.dport else self.dst

    def has_flag(self, flag: str) -> bool:
        wanted = flag.upper()
        return wanted in {f.strip().upper() for f in self.tcp_flags.split(",")}

    def get_fields(self) -> Dict[str, object]:
        """构造显示过滤器使用的字段字典（扁平化，键为小写）。"""
        f: Dict[str, object] = {
            "frame.number": self.index,
            "frame.len": self.length,
            "frame.time": self.time,
            "len": self.length,
            "no": self.index,
            "proto": self.proto,
            "protocol": self.proto,
            "ip": self.ip_version in (4, 6),
            "ipv4": self.ip_version == 4,
            "ipv6": self.ip_version == 6,
            "src": self.src,
            "dst": self.dst,
            "ip.src": self.src,
            "ip.dst": self.dst,
            "ip.addr": (self.src, self.dst),
            "host": (self.src, self.dst),
            "port": (self.sport, self.dport),
            "srcport": self.sport,
            "dstport": self.dport,
            "tcp": self.proto in ("TCP", "HTTP", "HTTPS", "TLS", "HTTP-ALT") or bool(self.tcp_flags),
            "udp": self.proto in ("UDP", "DNS", "DHCP"),
            "icmp": self.proto in ("ICMP", "ICMPv6"),
            "arp": self.proto == "ARP",
            "http": self.http is not None or self.proto == "HTTP",
            "dns": self.dns is not None,
            "tls": bool(self.tls_sni) or self.proto in ("HTTPS", "TLS"),
            "tcp.flags": self.tcp_flags,
            "tcp.seq": self.seq,
            "tcp.ack": self.ack,
            "tcp.len": self.payload_len,
            "payload": self.payload,
            "stream": self.stream_id if self.stream_id is not None else -1,
            "pid": self.pid if self.pid is not None else -1,
            "proc": self.proc,
            "process": self.proc,
        }
        if self.http is not None:
            h = self.http
            f.update({
                "http.method": h.method,
                "http.uri": h.uri,
                "http.host": h.host,
                "http.status": h.status,
                "http.user_agent": h.user_agent,
                "http.content_type": h.content_type,
                "http.request": h.is_request,
            })
        if self.dns is not None:
            f.update({
                "dns.qname": self.dns.qname,
                "dns.qtype": self.dns.qtype,
                "dns.response": self.dns.is_response,
                "dns.answers": self.dns.answers,
            })
        if self.tls_sni:
            f["tls.sni"] = self.tls_sni
        return f
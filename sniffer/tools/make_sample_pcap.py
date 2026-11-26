# -*- coding: utf-8 -*-
"""生成离线演示 pcap，便于在没有网络/没有抓包权限时验证 NPA 与流追踪。

用法：python tools/make_sample_pcap.py samples/demo.pcap
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, ICMP, IP, IPv6, Raw, TCP, UDP, wrpcap


def tls_client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_entry = b"\x00" + len(name).to_bytes(2, "big") + name
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
    sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    exts = sni_ext
    body = (b"\x01" + b"\x00\x00\x00" + b"\x03\x03" + b"\x11" * 32 +
            b"\x00" + b"\x00\x04\x13\x01\x13\x02" + b"\x01\x00" +
            len(exts).to_bytes(2, "big") + exts)
    body = b"\x01" + len(body[1:]).to_bytes(3, "big") + body[4:]
    return b"\x16\x03\x01" + len(body).to_bytes(2, "big") + body


def build():
    pkts = []
    t = 1700000000.0

    def add(pkt, dt=0.001):
        nonlocal t
        t += dt
        pkt.time = t
        pkts.append(pkt)

    # ARP 请求
    add(Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1",
            hwsrc="00:11:22:33:44:55", hwdst="00:00:00:00:00:00"), 0.01)

    # DNS 查询与应答
    add(Ether() / IP(src="192.168.1.10", dst="223.5.5.5") /
        UDP(sport=53000, dport=53) /
        DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
    add(Ether() / IP(src="223.5.5.5", dst="192.168.1.10") /
        UDP(sport=53, dport=53000) /
        DNS(id=0x1234, qr=1, aa=1, rd=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", ttl=60, rdata="93.184.216.34")), 0.02)

    c, s = ("192.168.1.10", 49152), ("93.184.216.34", 80)
    base_c, base_s = 1000, 5000
    add(Ether() / IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="S", seq=base_c))
    add(Ether() / IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="SA",
                                               seq=base_s, ack=base_c + 1), 0.018)
    add(Ether() / IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="A",
                                               seq=base_c + 1, ack=base_s + 1), 0.0005)

    req = (b"GET /demo/index.html HTTP/1.1\r\n"
           b"Host: example.com\r\n"
           b"User-Agent: PyShark-Demo/1.0\r\n"
           b"Accept: text/html\r\n"
           b"Connection: close\r\n\r\n")
    # 故意拆成两段并乱序发送（演示重组）
    add(Ether() / IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="PA",
                                               seq=base_c + 1 + 40, ack=base_s + 1) /
        Raw(load=req[40:]), 0.001)
    add(Ether() / IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="PA",
                                               seq=base_c + 1, ack=base_s + 1) /
        Raw(load=req[:40]), 0.0005)
    # 重传第一段
    add(Ether() / IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="PA",
                                               seq=base_c + 1, ack=base_s + 1) /
        Raw(load=req[:40]), 0.0005)

    resp = (b"HTTP/1.1 200 OK\r\n"
            b"Server: demo\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            b"1a\r\n<html><body>hello PyShark</body>\r\n0\r\n\r\n")
    add(Ether() / IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="PA",
                                               seq=base_s + 1, ack=base_c + 1 + len(req)) /
        Raw(load=resp), 0.03)
    add(Ether() / IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="FA",
                                               seq=base_c + 1 + len(req), ack=base_s + 1 + len(resp)), 0.02)
    add(Ether() / IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="FA",
                                               seq=base_s + 1 + len(resp), ack=base_c + 2 + len(req)), 0.02)
    add(Ether() / IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="A",
                                               seq=base_c + 2 + len(req), ack=base_s + 2 + len(resp)), 0.001)

    # HTTPS ClientHello（含 SNI）
    hello = tls_client_hello("demo.example.com")
    add(Ether() / IP(src="192.168.1.10", dst="104.18.0.1") /
        TCP(sport=49160, dport=443, flags="S", seq=7000), 0.1)
    add(Ether() / IP(src="104.18.0.1", dst="192.168.1.10") /
        TCP(sport=443, dport=49160, flags="SA", seq=8000, ack=7001), 0.02)
    add(Ether() / IP(src="192.168.1.10", dst="104.18.0.1") /
        TCP(sport=49160, dport=443, flags="PA", seq=7001, ack=8001) / Raw(load=hello), 0.001)
    add(Ether() / IP(src="104.18.0.1", dst="192.168.1.10") /
        TCP(sport=443, dport=49160, flags="PA", seq=8001, ack=7001 + len(hello)) /
        Raw(load=b"\x16\x03\x03\x00\x10" + b"\x02" + b"\x00\x00\x0c" + b"\x00" * 8), 0.03)

    # ICMP Echo
    add(Ether() / IP(src="192.168.1.10", dst="223.5.5.5") / ICMP(type=8, id=1, seq=1) /
        Raw(load=b"abcdefghijklmnop"), 0.05)
    add(Ether() / IP(src="223.5.5.5", dst="192.168.1.10") / ICMP(type=0, id=1, seq=1) /
        Raw(load=b"abcdefghijklmnop"), 0.02)

    # 普通 TCP（非 HTTP/HTTPS，用于覆盖 TCP 协议过滤）
    add(Ether() / IP(src="192.168.1.10", dst="203.0.113.9") /
        TCP(sport=49200, dport=9000, flags="S", seq=3333), 0.03)

    # IPv6 TCP
    add(Ether() / IPv6(src="2408:8000::1", dst="2408:8000::2") /
        TCP(sport=50000, dport=8080, flags="S", seq=1234), 0.1)
    add(Ether() / IPv6(src="2408:8000::2", dst="2408:8000::1") /
        TCP(sport=8080, dport=50000, flags="SA", seq=4321, ack=1235), 0.02)
    add(Ether() / IPv6(src="2408:8000::1", dst="2408:8000::2") /
        TCP(sport=50000, dport=8080, flags="PA", seq=1235, ack=4322) /
        Raw(load=b"GET /ipv6 HTTP/1.1\r\nHost: [2408:8000::2]\r\n\r\n"), 0.001)
    return pkts


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "demo.pcap")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    packets = build()
    wrpcap(out, packets)
    print(f"written {len(packets)} packets -> {out}")
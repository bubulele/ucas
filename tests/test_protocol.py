# -*- coding: utf-8 -*-
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw

from packet_parser import build_record, decode_chunked, hex_dump, parse_http, parse_tls
from tools_make_helpers import tls_hello_bytes  # type: ignore


def test_http_request():
    info = parse_http(b"GET /x?q=1 HTTP/1.1\r\nHost: a.com\r\nUser-Agent: ua\r\n\r\n")
    assert info.is_request and info.method == "GET"
    assert info.uri == "/x?q=1" and info.host == "a.com"


def test_http_response_body():
    info = parse_http(b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\nnope")
    assert not info.is_request and info.status == 404
    assert info.body == b"nope"


def test_chunked_decode():
    raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    assert decode_chunked(raw) == b"hello world"
    info = parse_http(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + raw)
    assert info.chunked and info.body == b"hello world"


def test_tls_sni():
    hello = tls_hello_bytes("demo.example.com")
    hs, sni = parse_tls(hello)
    assert hs == "Client Hello" and sni == "demo.example.com"


def test_hex_dump():
    text = hex_dump(b"ABC")
    assert "41 42 43" in text and "|ABC|" in text


def test_dns_record():
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=53, dport=5000) / \
        DNS(id=1, qr=1, qd=DNSQR(qname="a.com", qtype="A"),
            an=DNSRR(rrname="a.com", type="A", rdata="3.3.3.3"))
    rec = build_record(pkt, 1, set())
    assert rec.proto == "DNS"
    assert rec.dns is not None and rec.dns.qname == "a.com" and rec.dns.is_response

# -*- coding: utf-8 -*-
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
import pytest

from display_filter import DisplayFilter, FilterSyntaxError
from packet_parser import build_record
from scapy.all import Ether, IP, TCP, Raw

LOCAL = {"192.168.1.10"}


def rec(payload=b"", sport=40000, dport=80, flags="PA", src="192.168.1.10",
        dst="93.184.216.34", proto_tcp=True):
    p = Ether() / IP(src=src, dst=dst)
    if proto_tcp:
        p = p / TCP(sport=sport, dport=dport, flags=flags, seq=1) / Raw(load=payload)
    return build_record(p, 1, LOCAL)


def test_http_bare_and_logic():
    r = rec(b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert DisplayFilter("http").matches(r)
    assert DisplayFilter("http and tcp.port == 80").matches(r)
    assert not DisplayFilter("http and tcp.port == 8080").matches(r)
    assert DisplayFilter("not arp and (http or dns)").matches(r)
    assert DisplayFilter("not (http and udp)").matches(r)


def test_field_comparisons():
    r = rec(b"GET /login HTTP/1.1\r\nHost: example.com\r\nUser-Agent: pytest\r\n\r\n")
    assert DisplayFilter('http.uri contains "login"').matches(r)
    assert DisplayFilter('http.host == "example.com"').matches(r)
    assert DisplayFilter('http.method == "GET"').matches(r)
    assert DisplayFilter('ip.addr == 192.168.1.10').matches(r)
    assert DisplayFilter('ip.dst == 93.184.216.34').matches(r)
    assert DisplayFilter('tcp.flags contains "PSH"').matches(r)
    assert DisplayFilter('tcp.flags.syn == 0').matches(r)
    assert DisplayFilter("frame.len > 40").matches(r)
    assert not DisplayFilter("frame.len < 10").matches(r)
    assert DisplayFilter("proc == \"\"") is not None  # 不崩溃


def test_case_insensitive_protocol():
    r = rec(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert DisplayFilter("HTTP").matches(r)
    assert DisplayFilter("Http AND tcp").matches(r)


def test_syntax_errors():
    for expr in ("http and (", "tcp.port ==", "and http", "http or"):
        with pytest.raises(FilterSyntaxError):
            DisplayFilter(expr)
        err = DisplayFilter.validate(expr)
        assert err and "^" in err


def test_ipv6_bare():
    from scapy.all import IPv6
    p = Ether() / IPv6(src="2408::1", dst="2408::2") / TCP(sport=1, dport=2, flags="S")
    r = build_record(p, 2, set())
    assert DisplayFilter("ipv6").matches(r)
    assert not DisplayFilter("ipv4").matches(r)
    assert DisplayFilter("ip.addr == 2408::1").matches(r)


def test_empty_matches_all():
    r = rec()
    assert DisplayFilter("").matches(r)

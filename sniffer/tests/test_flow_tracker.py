# -*- coding: utf-8 -*-
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from scapy.all import Ether, IP, TCP, Raw

from flow_tracker import FlowTracker
from packet_parser import build_record


def pkt(src, sport, dst, dport, flags, seq, payload=b"", ts=1.0):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq)
    if payload:
        p = p / Raw(load=payload)
    p.time = ts
    return p


def test_stream_reassembly_with_reorder_and_retrans():
    ft = FlowTracker()
    c, s = ("10.0.0.1", 40000), ("10.0.0.2", 80)
    ft.update(build_record(pkt(c[0], c[1], s[0], s[1], "S", 100), 1, set()))
    ft.update(build_record(pkt(s[0], s[1], c[0], c[1], "SA", 500, ts=1.1), 2, set()))
    data = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n"
    # 后半段先到，再补前半段，最后重传前半段
    ft.update(build_record(pkt(c[0], c[1], s[0], s[1], "PA", 101 + 20, data[20:], ts=1.2), 3, set()))
    ft.update(build_record(pkt(c[0], c[1], s[0], s[1], "PA", 101, data[:20], ts=1.3), 4, set()))
    ft.update(build_record(pkt(c[0], c[1], s[0], s[1], "PA", 101, data[:20], ts=1.4), 5, set()))
    st = ft.sorted_streams()[0]
    re = st.reassemble(0)
    assert re.data == data, re.data
    assert re.retransmissions >= 1
    assert st.app_proto == "HTTP"
    assert st.client == c and st.server == s


def test_http_transaction_and_chunked_response():
    ft = FlowTracker()
    c, s = ("10.0.0.1", 40001), ("10.0.0.2", 80)
    ft.update(build_record(pkt(c[0], c[1], s[0], s[1], "S", 1000), 1, set()))
    ft.update(build_record(pkt(s[0], s[1], c[0], c[1], "SA", 9000, ts=1.1), 2, set()))
    req = b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
    ft.update(build_record(pkt(c[0], c[1], s[0], s[1], "PA", 1001, req, ts=1.2), 3, set()))
    ft.update(build_record(pkt(s[0], s[1], c[0], c[1], "PA", 9001, resp, ts=1.3), 4, set()))
    st = ft.sorted_streams()[0]
    tx = st.http_transactions()
    assert len(tx) == 1
    req_info, resp_info = tx[0]
    assert req_info.uri == "/x"
    assert resp_info.status == 200
    assert resp_info.body == b"hello"


def test_process_grouping():
    ft = FlowTracker()
    c, s = ("10.0.0.1", 40002), ("10.0.0.2", 443)
    rec = build_record(pkt(c[0], c[1], s[0], s[1], "S", 100), 1, {"10.0.0.1"})
    rec.pid, rec.proc = 1234, "demo.exe"
    ft.update(rec)
    assert ft.for_process(1234)
    assert ft.sorted_streams()[0].process_label.startswith("demo.exe")

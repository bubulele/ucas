# -*- coding: utf-8 -*-
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from scapy.all import rdpcap

from flow_tracker import FlowTracker
from packet_parser import build_record

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "demo.pcap")


def load():
    assert os.path.exists(SAMPLE), "先运行 python tools/make_sample_pcap.py"
    pkts = rdpcap(SAMPLE)
    tracker = FlowTracker()
    records = []
    for i, pkt in enumerate(pkts, 1):
        rec = build_record(pkt, i, set())
        tracker.update(rec)
        records.append(rec)
    return records, tracker


def test_protocol_coverage():
    records, _ = load()
    protos = {r.proto for r in records}
    for p in ("HTTP", "TLS", "DNS", "ICMP", "TCP", "ARP"):
        assert p in protos, (p, protos)


def test_http_stream_and_body():
    _, tracker = load()
    http_streams = [s for s in tracker.streams.values() if s.app_proto == "HTTP"]
    assert http_streams
    st = max(http_streams, key=lambda x: x.total_bytes)
    tx = st.http_transactions()
    assert tx and tx[0][0].uri == "/demo/index.html"
    assert b"hello PyShark" in tx[0][1].body


def test_tls_sni_and_ipv6():
    records, tracker = load()
    snis = [r.tls_sni for r in records if r.tls_sni]
    assert "demo.example.com" in snis
    assert any(r.ip_version == 6 for r in records)
    assert any(s.app_proto.startswith("TLS") for s in tracker.streams.values())


def test_dns():
    records, _ = load()
    dns = [r for r in records if r.dns]
    assert dns and dns[0].dns.qname == "example.com"
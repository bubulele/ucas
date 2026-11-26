# -*- coding: utf-8 -*-
"""stats.py —— 抓包统计与流量画像

维护协议分布、Top 会话、Top 端口、每秒包速率，供“统计”面板展示。
所有更新都在 GUI 线程完成（引擎只投递原始包），因此无需加锁。
"""

from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Tuple

from models import PacketRecord


@dataclass
class Stats:
    total: int = 0
    total_bytes: int = 0
    proto_count: Counter = field(default_factory=Counter)
    proto_bytes: Counter = field(default_factory=Counter)
    talkers: Counter = field(default_factory=Counter)       # (src,dst) -> bytes
    ports: Counter = field(default_factory=Counter)         # (proto, port) -> count
    streams: int = 0
    http_requests: int = 0
    dns_queries: int = 0
    tls_sessions: int = 0
    rate: Deque[Tuple[float, int]] = field(default_factory=lambda: deque(maxlen=60))
    _bucket: float = 0.0
    _bucket_count: int = 0

    def clear(self):
        self.total = 0
        self.total_bytes = 0
        self.proto_count.clear()
        self.proto_bytes.clear()
        self.talkers.clear()
        self.ports.clear()
        self.streams = 0
        self.http_requests = 0
        self.dns_queries = 0
        self.tls_sessions = 0
        self.rate.clear()
        self._bucket = 0.0
        self._bucket_count = 0

    def add(self, rec: PacketRecord, stream=None):
        self.total += 1
        self.total_bytes += rec.length
        self.proto_count[rec.proto] += 1
        self.proto_bytes[rec.proto] += rec.length
        if rec.src and rec.dst:
            self.talkers[(rec.src, rec.dst)] += rec.length
        if rec.sport:
            self.ports[(rec.proto, rec.sport)] += 1
        if rec.dport:
            self.ports[(rec.proto, rec.dport)] += 1
        if rec.http is not None and rec.http.is_request:
            self.http_requests += 1
        if rec.dns is not None and not rec.dns.is_response:
            self.dns_queries += 1
        if rec.tls_sni:
            self.tls_sessions += 1

        # 每秒速率（按包时间还是墙钟？用包时间更贴近 pcap 回放）
        ts = rec.time or 0.0
        sec = float(int(ts))
        if self._bucket == 0.0:
            self._bucket = sec
        if sec != self._bucket:
            self.rate.append((self._bucket, self._bucket_count))
            self._bucket = sec
            self._bucket_count = 0
        self._bucket_count += 1

    def top_talkers(self, n: int = 8) -> List[Tuple[str, str, int]]:
        out = []
        for (src, dst), size in self.talkers.most_common(n):
            out.append((src, dst, size))
        return out

    def top_ports(self, n: int = 8) -> List[Tuple[str, int, int]]:
        out = []
        for (proto, port), cnt in self.ports.most_common(n):
            out.append((proto, port, cnt))
        return out

    def proto_share(self) -> List[Tuple[str, int, float]]:
        total = sum(self.proto_count.values()) or 1
        return [(p, c, c * 100.0 / total) for p, c in self.proto_count.most_common()]

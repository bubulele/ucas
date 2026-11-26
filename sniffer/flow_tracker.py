# -*- coding: utf-8 -*-
"""flow_tracker.py —— TCP 流追踪与重组

解决的问题：抓到的包是一个个独立的帧，而“流”是同一 TCP 连接上
双向字节流的集合。Wireshark 的 Follow TCP Stream 之所以好用，
是因为它按四元组归并连接，再按 SEQ 把乱序/重传的报文段还原成
连续的字节流。

本模块实现：
  1. 以 (源IP, 源端口, 目的IP, 目的端口) 的四元组为键归并 TCP 连接
  2. 用 TCP SEQ 做字节级重组（处理重传、部分重叠、乱序、序号回绕）
  3. 解析流内的 HTTP 请求/响应事务，输出可读文本
  4. 生成时序图事件（时间、方向、序号、长度、标志位）
  5. 汇总每条流涉及的本地进程，支持“某进程的所有 TCP 流”
"""

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from models import HTTPInfo, PacketRecord
from packet_parser import decode_chunked, parse_http

SEQ_MOD = 1 << 32
SERVER_HINTS = {21, 22, 25, 53, 80, 110, 143, 443, 445, 8080, 8443}


@dataclass
class Segment:
    ts: float
    seq: int
    payload: bytes
    flags: str
    index: int
    direction: int          # 0: 客户端 -> 服务端, 1: 服务端 -> 客户端


@dataclass
class Reassembly:
    """一个方向重组后的数据。"""
    data: bytes = b""
    gaps: List[Tuple[int, int]] = field(default_factory=list)
    segments: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    base_seq: int = 0

    def text(self, limit: int = 2_000_000) -> str:
        """带缺口标记的文本形式。"""
        if not self.data:
            return ""
        raw = self.data[:limit]
        parts: List[str] = []
        last = 0
        for off, length in self.gaps:
            if off > last:
                parts.append(_to_text(raw[last:off]))
            parts.append(f"\n<<< 缺失 {length} 字节（抓包时丢包或未捕获）>>>\n")
            last = off + length
        if last < len(raw):
            parts.append(_to_text(raw[last:]))
        return "".join(parts)


def _to_text(data: bytes) -> str:
    return "".join(chr(b) if (32 <= b < 127 or b in (9, 10, 13)) else "." for b in data)


def _canonical(ep1: Tuple[str, int], ep2: Tuple[str, int]):
    return (ep1, ep2) if ep1 <= ep2 else (ep2, ep1)


def _guess_client(ep1: Tuple[str, int], ep2: Tuple[str, int], flags: str) -> bool:
    """判断 ep1 是否为客户端。

    优先看 SYN：不带 ACK 的 SYN 由客户端发出。抓包开始时连接已建立
    的情况下，则用端口启发式：知名端口/服务端口一端是服务端。
    """
    if "S" in flags and "A" not in flags:
        return True
    p1, p2 = ep1[1], ep2[1]
    s1, s2 = p1 in SERVER_HINTS or p1 < 1024, p2 in SERVER_HINTS or p2 < 1024
    if s2 and not s1:
        return True
    if s1 and not s2:
        return False
    return p1 > p2


class TCPStream:
    """一条 TCP 连接（双向）。"""

    def __init__(self, stream_id: int, ep1: Tuple[str, int], ep2: Tuple[str, int],
                 client_is_ep1: bool, first_ts: float):
        self.stream_id = stream_id
        self.ep1, self.ep2 = ep1, ep2
        self.client_is_ep1 = client_is_ep1
        self.first_ts = first_ts
        self.last_ts = first_ts
        self.packets: List[int] = []
        self.segments: List[Segment] = []
        self.bytes = [0, 0]               # c2s, s2c（TCP 载荷字节）
        self.frames = [0, 0]
        self.syn_ts: Optional[float] = None
        self.fin_ts: Optional[float] = None
        self.rst = False
        self.syn_seen = False
        self.fin_seen = [False, False]
        self.processes: Dict[int, str] = {}
        self.process_hits: Dict[int, int] = {}
        self.app_proto = "TCP"
        self.http_msgs: List[HTTPInfo] = []
        self._max_seq = [-1, -1]
        self._next_seq = [-1, -1]
        self._seq_origin = [None, None]
        self._cover = [[], []]          # 每个方向已覆盖的字节区间（相对序号）
        self._retrans = [0, 0]
        self._ooo = [0, 0]
        self.notes: List[str] = []

    # ---------------------------------------------------------- 属性
    @property
    def client(self) -> Tuple[str, int]:
        return self.ep1 if self.client_is_ep1 else self.ep2

    @property
    def server(self) -> Tuple[str, int]:
        return self.ep2 if self.client_is_ep1 else self.ep1

    @property
    def key(self) -> Tuple:
        return (self.ep1, self.ep2, "TCP")

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def total_bytes(self) -> int:
        return self.bytes[0] + self.bytes[1]

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def state(self) -> str:
        if self.rst:
            return "RST 重置"
        if self.fin_seen[0] and self.fin_seen[1]:
            return "已关闭"
        if self.fin_seen[0] or self.fin_seen[1]:
            return "半关闭"
        if self.syn_seen:
            return "已建立"
        return "进行中"

    @property
    def process_label(self) -> str:
        if not self.processes:
            return "—"
        pid = max(self.process_hits, key=lambda p: self.process_hits[p])
        name = self.processes.get(pid, "?")
        return f"{name} ({pid})"

    @property
    def pid(self) -> Optional[int]:
        if not self.process_hits:
            return None
        return max(self.process_hits, key=lambda p: self.process_hits[p])

    def endpoint_label(self) -> str:
        c, s = self.client, self.server
        return f"{c[0]}:{c[1]}  →  {s[0]}:{s[1]}"

    # ---------------------------------------------------------- 更新
    def add(self, rec: PacketRecord) -> Segment:
        """加入一个包，并更新重组所需的序号状态。"""
        self.packets.append(rec.index)
        self.last_ts = max(self.last_ts, rec.time)
        flags = rec.tcp_flags or ""
        if "S" in flags:
            self.syn_seen = True
            if self.syn_ts is None:
                self.syn_ts = rec.time
        if "F" in flags:
            self.fin_seen[self._dir(rec)] = True
            if self.fin_ts is None:
                self.fin_ts = rec.time
        if "R" in flags:
            self.rst = True

        d = self._dir(rec)
        self.frames[d] += 1
        if rec.payload:
            self.bytes[d] += len(rec.payload)
        if rec.http is not None:
            self.app_proto = "HTTP"
        elif rec.tls_sni or rec.proto in ("TLS", "HTTPS"):
            if self.app_proto == "TCP":
                self.app_proto = "TLS" if not rec.tls_sni else f"TLS (SNI: {rec.tls_sni})"
        if rec.pid is not None:
            self.processes[rec.pid] = rec.proc or f"PID {rec.pid}"
            self.process_hits[rec.pid] = self.process_hits.get(rec.pid, 0) + 1

        seg = Segment(rec.time, rec.seq, rec.payload, flags, rec.index, d)
        self.segments.append(seg)
        if rec.payload:
            self._track_seq(d, rec)
        return seg

    def _dir(self, rec: PacketRecord) -> int:
        """0 = 客户端 -> 服务端；1 = 服务端 -> 客户端。"""
        src = (rec.src, rec.sport)
        return 0 if src == self.client else 1

    def _track_seq(self, d: int, rec: PacketRecord):
        """用“已覆盖区间”判断重传与乱序。

        只看 SEQ 是否变小是不够的：抓包从连接中途开始时，先抓到的可能
        是较新的段，之后补到的旧段并不是重传。只有“整段字节已经被
        覆盖”才是重传；与已有区间部分重叠的记为部分重传；落在已覆盖
        区间之前但带来新字节的记为乱序。
        """
        if self._seq_origin[d] is None:
            self._seq_origin[d] = rec.seq
        base = self._seq_origin[d]
        off = (rec.seq - base) % SEQ_MOD
        if off > SEQ_MOD // 2:
            off -= SEQ_MOD
        if off < 0:
            self._ooo[d] += 1
            rec.tags.append("乱序")
            return
        end = off + len(rec.payload)
        covers = self._cover[d]
        fully = any(s <= off and end <= e for s, e in covers)
        partial = any(off < e and s < end for s, e in covers)
        if fully:
            self._retrans[d] += 1
            rec.tags.append("重传")
            return
        if partial:
            self._retrans[d] += 1
            rec.tags.append("部分重传")
        elif self._max_seq[d] >= 0 and off < self._max_seq[d]:
            self._ooo[d] += 1
            rec.tags.append("乱序")
        self._max_seq[d] = max(self._max_seq[d], end)
        self._next_seq[d] = end
        # 合并区间（段数很少，直接线性合并即可）
        merged = []
        for s, e in sorted(covers + [(off, end)]):
            if merged and s <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
            else:
                merged.append((s, e))
        self._cover[d] = merged

    # ---------------------------------------------------------- 重组
    def reassemble(self, direction: int) -> Reassembly:
        segs = [s for s in self.segments if s.direction == direction and s.payload]
        if not segs:
            return Reassembly()
        segs.sort(key=lambda s: s.seq)
        base = self._base_seq(direction, segs)
        out = bytearray()
        gaps: List[Tuple[int, int]] = []
        covered = 0
        retrans = 0
        chunks: List[Tuple[int, bytes]] = []

        prepared: List[Tuple[int, bytes, Segment]] = []
        for s in segs:
            off = (s.seq - base) % SEQ_MOD
            if off > SEQ_MOD // 2:       # 视为序号回绕/异常，跳过
                off -= SEQ_MOD
                if off < 0:
                    continue
            prepared.append((off, s.payload, s))
        prepared.sort(key=lambda x: x[0])

        for off, payload, _seg in prepared:
            start, end = off, off + len(payload)
            if end <= covered:
                retrans += 1
                continue
            if start < covered:
                payload = payload[covered - start:]
                start = covered
                retrans += 1
            if start > covered:
                gap_len = start - covered
                gaps.append((covered, gap_len))
                out.extend(b"\x00" * gap_len)
                covered = start
            out.extend(payload)
            covered = end

        return Reassembly(bytes(out), gaps, len(prepared), retrans,
                          sum(self._ooo), base)

    def _base_seq(self, direction: int, segs: List[Segment]) -> int:
        """确定字节 0 对应的绝对序号。

        握手可见时用 SYN 的 seq+1；否则用该方向最小载荷序号。
        这样即使从连接中途开始抓包，也能得到相对偏移。
        """
        syn = [s for s in self.segments
               if s.direction == direction and "S" in s.flags and s.payload == b""]
        if syn:
            return (min(s.seq for s in syn) + 1) % SEQ_MOD
        return min(s.seq for s in segs)

    # ---------------------------------------------------------- HTTP
    def parse_http_messages(self) -> List[HTTPInfo]:
        """按方向解析流中的 HTTP 报文序列（Keep-Alive 多事务）。"""
        msgs: List[HTTPInfo] = []
        for direction in (0, 1):
            data = self.reassemble(direction).data
            if not data:
                continue
            msgs.extend(_split_http(data, direction))
        # 按时间/顺序配对没有绝对必要，界面按方向分组展示
        self.http_msgs = msgs
        return msgs

    def http_transactions(self) -> List[Tuple[Optional[HTTPInfo], Optional[HTTPInfo]]]:
        msgs = self.parse_http_messages()
        reqs = [m for m in msgs if m.is_request]
        resps = [m for m in msgs if not m.is_request]
        out = []
        for i in range(max(len(reqs), len(resps))):
            out.append((reqs[i] if i < len(reqs) else None,
                        resps[i] if i < len(resps) else None))
        return out

    def text_dump(self) -> str:
        """Follow TCP Stream 的文本视图：按方向分段，附统计。"""
        c2s = self.reassemble(0)
        s2c = self.reassemble(1)
        lines: List[str] = []
        lines.append(f"# 流 {self.stream_id}：{self.endpoint_label()}")
        lines.append(f"# 应用协议: {self.app_proto}  状态: {self.state}  "
                     f"包数: {self.packet_count}  载荷: {self.total_bytes} 字节")
        lines.append("")
        lines.append(f"=== 客户端 → 服务端（{len(c2s.data)} 字节，{c2s.segments} 段，"
                     f"重传 {c2s.retransmissions}） ===")
        lines.append(c2s.text() or "(无载荷)")
        lines.append("")
        lines.append(f"=== 服务端 → 客户端（{len(s2c.data)} 字节，{s2c.segments} 段，"
                     f"重传 {s2c.retransmissions}） ===")
        lines.append(s2c.text() or "(无载荷)")
        return "\n".join(lines)

    def http_dump(self) -> str:
        tx = self.http_transactions()
        if not tx:
            return ""
        out: List[str] = [f"# HTTP 事务（{len(tx)} 组）", ""]
        for i, (req, resp) in enumerate(tx, 1):
            out.append(f"===== 事务 {i} =====")
            if req:
                out.append(f">>> {req.summary}")
                for k, v in req.headers:
                    out.append(f">>> {k}: {v}")
                if req.body:
                    out.append(">>> [请求体] " + _to_text(req.body[:2000]))
            if resp:
                out.append(f"<<< {resp.summary}")
                for k, v in resp.headers:
                    out.append(f"<<< {k}: {v}")
                if resp.body:
                    body = resp.body[:4000]
                    ctype = resp.content_type.lower()
                    if "text" in ctype or "json" in ctype or "javascript" in ctype:
                        out.append("<<< [响应体]\n" + _to_text(body))
                    else:
                        out.append(f"<<< [响应体 {len(resp.body)} 字节，二进制]")
            out.append("")
        return "\n".join(out)

    # ---------------------------------------------------------- 时序图
    def timeline(self, max_events: int = 400) -> List[dict]:
        """生成时序图事件；按包顺序，带相对序号/长度/标志位。"""
        events = []
        for seg in self.segments[:max_events]:
            if not seg.payload and "S" not in seg.flags and "F" not in seg.flags and "R" not in seg.flags:
                continue
            events.append({
                "ts": seg.ts,
                "rel": seg.ts - self.first_ts,
                "dir": seg.direction,
                "seq": seg.seq,
                "len": len(seg.payload),
                "flags": seg.flags,
                "index": seg.index,
            })
        return events


def _split_http(data: bytes, direction: int) -> List[HTTPInfo]:
    """把连续字节流切成若干 HTTP 报文（按 Content-Length）。"""
    out: List[HTTPInfo] = []
    pos = 0
    guard = 0
    while pos < len(data) and guard < 200:
        guard += 1
        head_end = data.find(b"\r\n\r\n", pos)
        if head_end < 0:
            break
        head = data[pos:head_end]
        info = parse_http(head + b"\r\n\r\n")
        if info is None:
            break
        body_start = head_end + 4
        if info.chunked:
            info.body = decode_chunked(data[body_start:])
            out.append(info)
            break
        body_len = info.content_length
        if body_len <= 0:
            body_len = 0
        body_end = min(len(data), body_start + body_len)
        info.body = data[body_start:body_end]
        out.append(info)
        if body_len == 0:
            # 无 Content-Length 的响应（如 204/304 或 chunked）：
            # 保守地认为剩余数据属于本条，避免死循环
            if not info.is_request and info.status in (204, 304, 100):
                pos = body_end
                continue
            # 请求通常没有正文；响应无长度则取剩余全部
            if not info.is_request:
                info.body = data[body_start:]
                break
            pos = body_end
            continue
        pos = body_end
    return out


class FlowTracker:
    """管理所有 TCP 流。"""

    def __init__(self):
        self.streams: "OrderedDict[Tuple, TCPStream]" = OrderedDict()
        self._next_id = 1

    def clear(self):
        self.streams.clear()
        self._next_id = 1

    def update(self, rec: PacketRecord) -> Optional[TCPStream]:
        if not rec.tcp_flags and rec.proto not in ("TCP", "HTTP", "HTTPS", "TLS"):
            return None
        ep1, ep2 = (rec.src, rec.sport), (rec.dst, rec.dport)
        key = _canonical(ep1, ep2) + ("TCP",)
        stream = self.streams.get(key)
        if stream is None:
            client_is_ep1 = _guess_client(ep1, ep2, rec.tcp_flags)
            stream = TCPStream(self._next_id, ep1, ep2, client_is_ep1, rec.time)
            self._next_id += 1
            self.streams[key] = stream
        stream.add(rec)
        rec.stream_id = stream.stream_id
        return stream

    def get(self, stream_id: int) -> Optional[TCPStream]:
        for s in self.streams.values():
            if s.stream_id == stream_id:
                return s
        return None

    def sorted_streams(self) -> List[TCPStream]:
        return list(self.streams.values())

    def for_process(self, pid: int) -> List[TCPStream]:
        return [s for s in self.streams.values() if pid in s.processes]

    def process_groups(self) -> Dict[int, List[TCPStream]]:
        groups: Dict[int, List[TCPStream]] = {}
        for s in self.streams.values():
            if s.pid is not None:
                groups.setdefault(s.pid, []).append(s)
        return groups

    def statistics(self) -> dict:
        streams = list(self.streams.values())
        return {
            "count": len(streams),
            "established": sum(1 for s in streams if s.state == "已建立"),
            "closed": sum(1 for s in streams if s.state in ("已关闭", "RST 重置")),
            "http": sum(1 for s in streams if s.app_proto == "HTTP"),
            "bytes": sum(s.total_bytes for s in streams),
            "retrans": sum(s._retrans[0] + s._retrans[1] for s in streams),
        }
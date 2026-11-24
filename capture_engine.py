# -*- coding: utf-8 -*-
"""capture_engine.py —— NPS（网络包嗅探）引擎

NPS 的关键是“真的从网卡拿到帧”，而不是只解析 pcap 文件。本模块：

  * 通过 scapy 的 AsyncSniffer 调用 Npcap/libpcap，在后台线程收包；
  * 支持 BPF 抓包过滤器（如 "tcp port 80"），过滤在驱动/内核层完成，
    不合法的包不会复制到用户态，因而能显著降低高流量下的开销；
  * 通过回调把包交给 GUI；回调异常被隔离，不会拖垮收包线程；
  * 采集收包统计（包数、字节数、速率、错误）。

Windows 依赖 Npcap（libpcap 的 Windows 实现）；Linux/macOS 依赖
libpcap。抓包需要相应权限（Windows 上通常需要管理员/Npcap 授权）。
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from scapy.all import AsyncSniffer, conf


@dataclass
class InterfaceInfo:
    name: str                 # scapy/Npcap 使用的设备名
    description: str = ""     # 人类可读的网卡描述
    ips: List[str] = field(default_factory=list)
    guid: str = ""
    is_loopback: bool = False

    @property
    def label(self) -> str:
        desc = self.description or self.name
        ip = ", ".join(self.ips[:2]) if self.ips else "无 IP"
        return f"{desc}  [{ip}]"

    def __str__(self):
        return self.label


def list_interfaces(include_all: bool = False) -> List[InterfaceInfo]:
    """枚举可用于抓包的网卡。

    优先使用 scapy 的 working ifaces（Npcap 中真正可打开的接口），
    避免把 WAN Miniport、过滤驱动等“假网卡”列出来。
    """
    result: List[InterfaceInfo] = []
    seen = set()
    try:
        ifaces = conf.ifaces.values()
        for iface in ifaces:
            name = getattr(iface, "name", "") or ""
            desc = getattr(iface, "description", "") or ""
            if not name or name in seen:
                continue
            ips = []
            for key in ("ip", "ips"):
                val = getattr(iface, key, None)
                if isinstance(val, str) and val:
                    ips.append(val)
                elif isinstance(val, (list, tuple)):
                    ips.extend(str(v) for v in val if v)
            # 过滤掉没有 NPF 设备名的伪接口；保留 loopback
            if not include_all and not name.startswith("\\Device\\NPF"):
                # scapy 在 Windows 上可能用别名，仍尝试保留有 IP 的
                if not ips:
                    continue
            is_loop = "loopback" in desc.lower() or "loopback" in name.lower()
            seen.add(name)
            result.append(InterfaceInfo(name, desc, sorted(set(ips)),
                                        getattr(iface, "guid", "") or "", is_loop))
    except Exception:
        pass
    if not result:
        try:
            from scapy.all import get_if_list
            result = [InterfaceInfo(n, n) for n in get_if_list()]
        except Exception:
            result = []
    # 有 IP 的网卡排前面
    result.sort(key=lambda i: (not i.ips, i.is_loopback, i.description.lower()))
    return result


class CaptureEngine:
    """后台抓包引擎。GUI 只需提供 on_packet 回调。"""

    def __init__(self, on_packet: Callable[[object], None],
                 on_error: Optional[Callable[[str], None]] = None):
        self.on_packet = on_packet
        self.on_error = on_error
        self._sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()
        self._start_time = 0.0
        self._stop_time = 0.0
        self.packet_count = 0
        self.byte_count = 0
        self.error = ""
        self.iface: Optional[InterfaceInfo] = None
        self.bpf = ""
        self._last_count = 0
        self._last_sample = 0.0
        self.pps = 0.0

    # ---------------------------------------------------------- 状态
    @property
    def is_running(self) -> bool:
        return self._sniffer is not None

    @property
    def elapsed(self) -> float:
        if not self._start_time:
            return 0.0
        end = self._stop_time or time.time()
        return max(0.0, end - self._start_time)

    # ---------------------------------------------------------- 控制
    def start(self, iface: Optional[InterfaceInfo] = None,
              bpf_filter: str = "", promisc: bool = True,
              snaplen: int = 65535):
        with self._lock:
            if self._sniffer is not None:
                raise RuntimeError("抓包已经在运行")
            kwargs = {
                "prn": self._handle_packet,
                "store": False,          # 不在引擎内囤包，内存由 GUI 的环形缓冲控制
                "promisc": promisc,
            }
            if iface and iface.name:
                kwargs["iface"] = iface.name
            expr = (bpf_filter or "").strip()
            if expr:
                kwargs["filter"] = expr
            try:
                sniffer = AsyncSniffer(**kwargs)
                sniffer.start()
            except Exception as exc:
                self.error = f"启动抓包失败：{exc}"
                raise RuntimeError(self.error) from exc
            self._sniffer = sniffer
            self.iface = iface
            self.bpf = expr
            self.packet_count = 0
            self.byte_count = 0
            self.error = ""
            self._start_time = time.time()
            self._stop_time = 0.0
            self._last_count = 0
            self._last_sample = self._start_time
            self.pps = 0.0

    def stop(self):
        with self._lock:
            sniffer, self._sniffer = self._sniffer, None
        if sniffer is None:
            return
        try:
            sniffer.stop()
        except Exception:
            pass
        self._stop_time = time.time()
        # 等收包线程退出，避免 stop 后仍有回调进入 GUI
        try:
            thread = getattr(sniffer, "thread", None)
            if thread is not None and thread.is_alive():
                thread.join(timeout=1.0)
        except Exception:
            pass

    # ---------------------------------------------------------- 回调
    def _handle_packet(self, pkt):
        self.packet_count += 1
        try:
            self.byte_count += len(pkt)
        except Exception:
            pass
        now = time.time()
        if now - self._last_sample >= 1.0:
            self.pps = (self.packet_count - self._last_count) / (now - self._last_sample)
            self._last_count = self.packet_count
            self._last_sample = now
        try:
            self.on_packet(pkt)
        except Exception as exc:
            self.error = f"处理数据包出错：{exc}"
            if self.on_error:
                try:
                    self.on_error(self.error)
                except Exception:
                    pass

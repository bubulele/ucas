# -*- coding: utf-8 -*-
"""process_map.py —— 进程级流溯源

实验要求的加分项之一：“某进程产生的所有 TCP 流”。
要回答“这个包/这条流属于哪个进程”，必须把**五元组**映射到**PID**。

Windows 上没有 /proc，用户态可以通过 IP Helper API 的
GetExtendedTcpTable / GetExtendedUdpTable 拿到整张 TCP/UDP 连接表
（含 owning PID），再用 OpenProcess + QueryFullProcessImageNameW
取进程映像名。本模块用 ctypes 直接调用这些 Win32 API，不依赖 psutil。

注意：
  - 非管理员通常也能读取连接表，但打开其他用户/受保护进程可能失败，
    此时进程名退化为 "PID xxx"；
  - 连接表是**瞬时快照**，短连接可能在两次刷新之间消失，因此抓包时
    每收到一个包就查询一次缓存，缓存每 2 秒刷新；
  - 对于未建立连接的 SYN 包，连接表里可能还没有对应项，这是正常现象。
"""

import ctypes
import platform
import socket
import threading
import time
from ctypes import wintypes
from typing import Dict, List, Optional, Tuple

AF_INET = 2
AF_INET6 = 23
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
ERROR_INSUFFICIENT_BUFFER = 122
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("ucRemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwState", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


def _port(dw_port: int) -> int:
    """dwLocalPort 的低 16 位是网络字节序端口。"""
    return socket.ntohs(int(dw_port) & 0xFFFF)


def _ipv4(dw_addr: int) -> str:
    return socket.inet_ntoa(int(dw_addr).to_bytes(4, "little"))


def _ipv6(arr) -> str:
    return socket.inet_ntop(socket.AF_INET6, bytes(arr))


class ProcessMapper:
    """维护 (协议, 本地端口) -> (PID, 进程名) 的缓存。"""

    def __init__(self, auto_refresh: bool = True, interval: float = 2.0):
        self.enabled = platform.system() == "Windows"
        self.interval = interval
        self._lock = threading.Lock()
        self._by_port: Dict[Tuple[str, int], List[Tuple[str, int, str]]] = {}
        self._names: Dict[int, str] = {}
        self._last_refresh = 0.0
        self._last_count = 0
        self._error = ""
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._iphlpapi = None
        self._kernel32 = None
        if self.enabled:
            try:
                self._iphlpapi = ctypes.WinDLL("iphlpapi")
                self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            except OSError as exc:
                self.enabled = False
                self._error = str(exc)
        if auto_refresh and self.enabled:
            self._thread = threading.Thread(target=self._loop, daemon=True,
                                            name="ProcessMapper")
            self._thread.start()

    # ---------------------------------------------------------- 线程
    def _loop(self):
        while not self._stop.is_set():
            try:
                self.refresh()
            except Exception as exc:  # 权限等问题不应崩溃
                self._error = str(exc)
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()

    # ---------------------------------------------------------- 刷新
    def refresh(self):
        if not self.enabled:
            return
        by_port: Dict[Tuple[str, int], List[Tuple[str, int, str]]] = {}
        names: Dict[int, str] = {}
        try:
            self._collect_tcp(by_port, names)
            self._collect_udp(by_port, names)
        except Exception as exc:
            self._error = str(exc)
            return
        with self._lock:
            self._by_port = by_port
            self._names.update(names)
            self._last_refresh = time.time()
            self._last_count = len(by_port)
            self._error = ""

    def _alloc_table(self, func, family: int, table_class: int):
        size = wintypes.DWORD(0)
        func(None, ctypes.byref(size), False, family, table_class, 0)
        if size.value == 0:
            return None
        buf = ctypes.create_string_buffer(size.value)
        ret = func(buf, ctypes.byref(size), False, family, table_class, 0)
        if ret != 0:
            raise OSError(f"GetExtendedTable 失败，错误码 {ret}")
        return buf

    def _collect_tcp(self, by_port, names):
        func = self._iphlpapi.GetExtendedTcpTable
        for family, row_type, v6 in ((AF_INET, MIB_TCPROW_OWNER_PID, False),
                                     (AF_INET6, MIB_TCP6ROW_OWNER_PID, True)):
            buf = self._alloc_table(func, family, TCP_TABLE_OWNER_PID_ALL)
            if buf is None:
                continue
            count = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
            arr = (row_type * count).from_buffer(buf, ctypes.sizeof(wintypes.DWORD))
            for row in arr:
                port = _port(row.dwLocalPort)
                ip = _ipv6(row.ucLocalAddr) if v6 else _ipv4(row.dwLocalAddr)
                pid = int(row.dwOwningPid)
                if pid <= 0:
                    continue
                name = self._proc_name(pid, names)
                by_port.setdefault(("TCP", port), []).append((ip, pid, name))

    def _collect_udp(self, by_port, names):
        func = self._iphlpapi.GetExtendedUdpTable
        for family, row_type, v6 in ((AF_INET, MIB_UDPROW_OWNER_PID, False),
                                     (AF_INET6, MIB_UDP6ROW_OWNER_PID, True)):
            buf = self._alloc_table(func, family, UDP_TABLE_OWNER_PID)
            if buf is None:
                continue
            count = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
            arr = (row_type * count).from_buffer(buf, ctypes.sizeof(wintypes.DWORD))
            for row in arr:
                port = _port(row.dwLocalPort)
                ip = _ipv6(row.ucLocalAddr) if v6 else _ipv4(row.dwLocalAddr)
                pid = int(row.dwOwningPid)
                if pid <= 0:
                    continue
                name = self._proc_name(pid, names)
                by_port.setdefault(("UDP", port), []).append((ip, pid, name))

    def _proc_name(self, pid: int, cache: Dict[int, str]) -> str:
        if pid in self._names:
            return self._names[pid]
        if pid in cache:
            return cache[pid]
        name = f"PID {pid}"
        if self._kernel32 is not None and pid > 4:
            handle = self._kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                try:
                    buf = ctypes.create_unicode_buffer(1024)
                    size = wintypes.DWORD(1024)
                    ok = self._kernel32.QueryFullProcessImageNameW(
                        handle, 0, buf, ctypes.byref(size))
                    if ok:
                        path = buf.value
                        name = path.rsplit("\\", 1)[-1] or name
                finally:
                    self._kernel32.CloseHandle(handle)
        cache[pid] = name
        return name

    # ---------------------------------------------------------- 查询
    def lookup(self, proto: str, local_ip: str, local_port: int) -> Tuple[Optional[int], str]:
        """根据协议、本地 IP、本地端口查 PID 和进程名。"""
        proto = "TCP" if proto.upper() in ("TCP", "HTTP", "HTTPS", "TLS") else "UDP"
        with self._lock:
            entries = self._by_port.get((proto, int(local_port))) or []
            if not entries:
                return None, ""
            for ip, pid, name in entries:
                if ip == local_ip:
                    return pid, name
            ip, pid, name = entries[0]
            return pid, name

    def lookup_or_refresh(self, proto: str, local_ip: str, local_port: int,
                          min_interval: float = 0.2) -> Tuple[Optional[int], str]:
        """查不到时按需刷新一次连接表，兼顾短连接与开销。"""
        pid, name = self.lookup(proto, local_ip, local_port)
        if pid is not None:
            return pid, name
        if time.time() - self._last_refresh >= min_interval:
            try:
                self.refresh()
            except Exception:
                pass
            return self.lookup(proto, local_ip, local_port)
        return None, ""

    @property
    def entry_count(self) -> int:
        return self._last_count

    @property
    def last_refresh(self) -> float:
        return self._last_refresh

    @property
    def error(self) -> str:
        return self._error
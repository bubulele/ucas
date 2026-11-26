# -*- coding: utf-8 -*-
"""main.py —— PyShark Pro 图形界面

课程实验 1A：带 GUI 的网络嗅探器（NPS）与协议分析器（NPA）。

界面结构：
  ┌ 标题 / 状态徽章 ───────────────────────────────────────────┐
  │ 网卡选择  BPF 抓包过滤器  开始/停止/清空/保存/打开          │
  │ 显示过滤器（支持 and / or / not 逻辑演算）                 │
  ├ 数据包 │ TCP 流 │ 进程 │ 统计 ──────────────────────────────┤
  │ 包列表                                                      │
  │ ────────────── 协议详情树 │ 十六进制转储 ───────────────── │
  └ 状态栏：抓包状态、包数、速率、进程映射 ────────────────────┘

设计目标：NPS 必须真实抓包；NPA 尽量完善；流追踪/进程溯源作为加分项。
"""

import csv
import os
import queue
import sys
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from scapy.all import rdpcap, wrpcap

import ui_theme as T
from capture_engine import CaptureEngine, InterfaceInfo, list_interfaces
from display_filter import DisplayFilter, FilterSyntaxError
from flow_tracker import FlowTracker, TCPStream
from follow_window import FollowStreamWindow
from packet_parser import (build_record, hex_dump, local_ip_set, parse_layers,
                           printable_payload)
from process_map import ProcessMapper
from stats import Stats

APP_TITLE = "PyShark Pro · 网络嗅探与协议分析"
VERSION = "1.0"
MAX_PACKETS = 200_000

BPF_PRESETS = [
    ("全部流量", ""),
    ("HTTP (80)", "tcp port 80"),
    ("HTTPS (443)", "tcp port 443"),
    ("DNS (53)", "udp port 53"),
    ("TCP", "tcp"),
    ("UDP", "udp"),
    ("ICMP / Ping", "icmp"),
    ("IPv4", "ip"),
    ("IPv6", "ip6"),
    ("ARP", "arp"),
    ("排除 mDNS 噪声", "not udp port 5353"),
]

DISPLAY_PRESETS = [
    ("HTTP", "http"),
    ("HTTP 且 80 端口", "http and tcp.port == 80"),
    ("TCP 或 UDP", "tcp or udp"),
    ("IPv4", "ipv4"),
    ("IPv6", "ipv6"),
    ("ICMP", "icmp"),
    ("DNS 查询", "dns and not dns.response"),
    ("TLS SNI", "tls.sni contains \"example\""),
    ("逻辑演算示例", "not arp and (http or dns) and frame.len > 100"),
    ("按进程", "proc contains \"chrome\""),
    ("只看某条流", "stream == 1"),
]


class SnifferApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE}  v{VERSION}")
        self.configure(bg=T.BG)
        self.minsize(1120, 720)
        self._place_window(1500, 940)

        # ---------- 状态 ----------
        self.records = []                 # List[PacketRecord]
        self.by_index = {}                # index -> record
        self.next_index = 1
        self.queue = queue.Queue(maxsize=20000)
        self.tracker = FlowTracker()
        self.stats = Stats()
        self.local_ips = local_ip_set()
        self.mapper = ProcessMapper(auto_refresh=True, interval=2.0)
        self.filter = DisplayFilter("")
        self.capturing = False
        self.mode = "实时"
        self._stream_dirty = True
        self._process_dirty = True
        self._last_stats = 0.0
        self._last_stream = 0.0
        self._last_status = 0.0
        self._dropped = 0
        self._interfaces = []

        self.engine = CaptureEngine(self._enqueue_packet, self._engine_error)

        T.setup_style(self)
        self._build_menu()
        self._build_header()
        self._build_toolbar()
        self._build_statusbar()
        self._build_body()

        self.refresh_ifaces()
        self.after(40, self._drain_queue)
        self.after(800, self._tick)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<Control-s>", lambda _e: self.save_pcap())
        self.bind("<Control-o>", lambda _e: self.open_pcap())
        self.bind("<F5>", lambda _e: self.start_capture())
        self.bind("<Escape>", lambda _e: self.stop_capture())
        self.after(80, self._dark_titlebar)

    def _dark_titlebar(self):
        T.apply_dark_titlebar(self)

    # ================================================================ 布局
    def _place_window(self, w, h):
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = min(w, int(sw * 0.94)), min(h, int(sh * 0.90))
        x, y = max(0, (sw - w) // 2), max(0, (sh - h) // 3)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_menu(self):
        menubar = tk.Menu(self, bg=T.BG_PANEL, fg=T.FG, activebackground=T.SELECT,
                          activeforeground="#fff", tearoff=0, borderwidth=0)
        m_file = tk.Menu(menubar, tearoff=0, bg=T.BG_PANEL, fg=T.FG,
                         activebackground=T.SELECT, activeforeground="#fff")
        m_file.add_command(label="打开 PCAP…        Ctrl+O", command=self.open_pcap)
        m_file.add_command(label="保存 PCAP…        Ctrl+S", command=self.save_pcap)
        m_file.add_command(label="导出包列表 CSV…", command=self.export_csv)
        m_file.add_separator()
        m_file.add_command(label="退出", command=self._on_close)
        menubar.add_cascade(label="文件", menu=m_file)

        m_cap = tk.Menu(menubar, tearoff=0, bg=T.BG_PANEL, fg=T.FG,
                        activebackground=T.SELECT, activeforeground="#fff")
        m_cap.add_command(label="开始抓包        F5", command=self.start_capture)
        m_cap.add_command(label="停止            Esc", command=self.stop_capture)
        m_cap.add_command(label="清空", command=self.clear_packets)
        m_cap.add_separator()
        for name, expr in BPF_PRESETS:
            m_cap.add_command(label=f"{name}    {expr}" if expr else name,
                              command=lambda e=expr: self._set_bpf(e))
        menubar.add_cascade(label="抓包", menu=m_cap)

        m_an = tk.Menu(menubar, tearoff=0, bg=T.BG_PANEL, fg=T.FG,
                       activebackground=T.SELECT, activeforeground="#fff")
        m_an.add_command(label="跟随选中的 TCP 流", command=self.follow_selected)
        m_an.add_command(label="统计面板", command=lambda: self.nb.select(3))
        m_an.add_separator()
        m_an.add_command(label="显示过滤器语法…", command=self.show_filter_help)
        menubar.add_cascade(label="分析", menu=m_an)

        m_help = tk.Menu(menubar, tearoff=0, bg=T.BG_PANEL, fg=T.FG,
                         activebackground=T.SELECT, activeforeground="#fff")
        m_help.add_command(label="使用说明", command=self.show_help)
        m_help.add_command(label="关于", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=m_help)
        self.config(menu=menubar)

    def _build_header(self):
        head = tk.Frame(self, bg=T.BG, padx=12, pady=8)
        head.pack(fill=tk.X)
        left = tk.Frame(head, bg=T.BG)
        left.pack(side=tk.LEFT)
        tk.Label(left, text="PyShark Pro", bg=T.BG, fg=T.ACCENT,
                 font=("Microsoft YaHei UI", 16, "bold")).pack(side=tk.LEFT)
        tk.Label(left, text="  NPS · NPA · TCP Flow · Process Attribution",
                 bg=T.BG, fg=T.FG_DIM, font=T.FONT_UI).pack(side=tk.LEFT, padx=(8, 0), pady=(4, 0))

        right = tk.Frame(head, bg=T.BG)
        right.pack(side=tk.RIGHT)
        self.live_badge = tk.Label(right, text="● 空闲", bg=T.BG_PANEL, fg=T.FG_DIM,
                                   font=T.FONT_UI_BOLD, padx=10, pady=3)
        self.live_badge.pack(side=tk.RIGHT, padx=4)
        self.pid_badge = tk.Label(right, text="进程映射 初始化…", bg=T.BG_PANEL,
                                  fg=T.FG_DIM, font=T.FONT_SUB, padx=8, pady=4)
        self.pid_badge.pack(side=tk.RIGHT, padx=4)
        self.npcap_badge = tk.Label(right, text="Npcap 检测中", bg=T.BG_PANEL,
                                    fg=T.FG_DIM, font=T.FONT_SUB, padx=8, pady=4)
        self.npcap_badge.pack(side=tk.RIGHT, padx=4)

    def _build_toolbar(self):
        wrap = tk.Frame(self, bg=T.BG, padx=10, pady=4)
        wrap.pack(fill=tk.X)
        # 第一行
        row1 = tk.Frame(wrap, bg=T.BG)
        row1.pack(fill=tk.X)
        tk.Label(row1, text="网卡", bg=T.BG, fg=T.FG_DIM).pack(side=tk.LEFT)
        self.iface_var = tk.StringVar()
        self.iface_box = ttk.Combobox(row1, textvariable=self.iface_var, width=34,
                                      state="readonly", font=T.FONT_UI)
        self.iface_box.pack(side=tk.LEFT, padx=(6, 4))
        self.iface_box.bind("<<ComboboxSelected>>", self._on_iface_change)
        T.make_button(row1, "刷新", self.refresh_ifaces, width=5).pack(side=tk.LEFT, padx=2)

        tk.Label(row1, text="BPF 抓包过滤", bg=T.BG, fg=T.FG_DIM).pack(side=tk.LEFT, padx=(14, 0))
        self.bpf_var = tk.StringVar()
        bpf = tk.Entry(row1, textvariable=self.bpf_var, bg=T.BG_INPUT, fg=T.FG,
                       insertbackground=T.FG, relief="flat", font=T.FONT_MONO,
                       highlightthickness=1, highlightbackground=T.BORDER,
                       highlightcolor=T.ACCENT)
        bpf.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 4))
        bpf.bind("<Return>", lambda _e: self.start_capture())
        preset = tk.Menubutton(row1, text="常用 ▾", bg=T.BG_PANEL, fg=T.ACCENT,
                               relief="flat", padx=8, pady=3, cursor="hand2")
        menu = tk.Menu(preset, tearoff=0, bg=T.BG_PANEL, fg=T.FG,
                       activebackground=T.SELECT, activeforeground="#fff")
        for name, expr in BPF_PRESETS:
            menu.add_command(label=f"{name}    {expr}" if expr else name,
                             command=lambda e=expr: self._set_bpf(e))
        preset["menu"] = menu
        preset.pack(side=tk.LEFT)

        # 第二行
        row2 = tk.Frame(wrap, bg=T.BG)
        row2.pack(fill=tk.X, pady=(7, 0))
        self.btn_start = T.make_button(row2, "▶ 开始抓包", self.start_capture, accent=True, width=11)
        self.btn_start.pack(side=tk.LEFT)
        self.btn_stop = T.make_button(row2, "■ 停止", self.stop_capture, stop=True, width=8)
        self.btn_stop.pack(side=tk.LEFT, padx=4)
        self.btn_stop.state(["disabled"])
        T.make_button(row2, "清空", self.clear_packets, width=6).pack(side=tk.LEFT, padx=4)
        T.make_button(row2, "保存 PCAP", self.save_pcap, width=9).pack(side=tk.LEFT, padx=4)
        T.make_button(row2, "打开 PCAP", self.open_pcap, width=9).pack(side=tk.LEFT, padx=4)

        T.make_button(row2, "语法", self.show_filter_help, width=5).pack(side=tk.RIGHT, padx=(4, 0))
        T.make_button(row2, "应用", self.apply_filter, width=6, accent=True).pack(side=tk.RIGHT, padx=4)
        self.filter_var = tk.StringVar()
        self.filter_entry = tk.Entry(row2, textvariable=self.filter_var, bg=T.BG_INPUT,
                                     fg=T.FG, insertbackground=T.FG, relief="flat",
                                     font=T.FONT_MONO, highlightthickness=1,
                                     highlightbackground=T.BORDER, highlightcolor=T.ACCENT)
        self.filter_entry.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=4)
        self.filter_entry.bind("<Return>", lambda _e: self.apply_filter())
        self.filter_entry.bind("<Control-a>", self._select_all_filter)
        tk.Label(row2, text="显示过滤器", bg=T.BG, fg=T.FG_DIM).pack(side=tk.RIGHT)
        preset2 = tk.Menubutton(row2, text="示例 ▾", bg=T.BG_PANEL, fg=T.ACCENT,
                                relief="flat", padx=8, pady=3, cursor="hand2")
        menu2 = tk.Menu(preset2, tearoff=0, bg=T.BG_PANEL, fg=T.FG,
                        activebackground=T.SELECT, activeforeground="#fff")
        for name, expr in DISPLAY_PRESETS:
            menu2.add_command(label=f"{name}    {expr}",
                              command=lambda e=expr: self._set_display(e))
        preset2["menu"] = menu2
        preset2.pack(side=tk.RIGHT, padx=4)

        self.filter_error = tk.Label(wrap, text="", bg=T.BG, fg=T.RED,
                                     font=T.FONT_SUB, anchor="w")
        self.filter_error.pack(fill=tk.X)

    def _build_body(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=(2, 4))
        self.tab_packets = tk.Frame(self.nb, bg=T.BG)
        self.tab_streams = tk.Frame(self.nb, bg=T.BG)
        self.tab_procs = tk.Frame(self.nb, bg=T.BG)
        self.tab_stats = tk.Frame(self.nb, bg=T.BG)
        self.nb.add(self.tab_packets, text="  数据包  ")
        self.nb.add(self.tab_streams, text="  TCP 流  ")
        self.nb.add(self.tab_procs, text="  进程  ")
        self.nb.add(self.tab_stats, text="  统计  ")
        self._build_packet_tab()
        self._build_stream_tab()
        self._build_process_tab()
        self._build_stats_tab()
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab_change)

    def _build_packet_tab(self):
        paned = ttk.Panedwindow(self.tab_packets, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        top = tk.Frame(paned, bg=T.BG)
        cols = ("no", "time", "src", "dst", "proto", "len", "proc", "info")
        heads = ("No.", "时间", "源地址", "目的地址", "协议", "长度", "进程", "Info")
        self.tree = ttk.Treeview(top, columns=cols, show="headings", selectmode="browse")
        widths = {"no": 58, "time": 98, "src": 180, "dst": 180, "proto": 78,
                  "len": 56, "proc": 110, "info": 560}
        for c, h in zip(cols, heads):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=widths[c], anchor=tk.W if c in ("src", "dst", "info", "proc") else tk.CENTER,
                             stretch=(c == "info"), minwidth=40)
        vs = ttk.Scrollbar(top, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        for proto, color in T.PROTO_COLORS.items():
            self.tree.tag_configure(proto, foreground=color)
        self.tree.tag_configure("retrans", background="#3a2d33")
        self.tree.tag_configure("marked", background="#2f3a2f")
        self.tree.bind("<<TreeviewSelect>>", self._on_select_packet)
        self.tree.bind("<Double-1>", lambda _e: self.follow_selected())
        self.tree.bind("<Button-3>", self._packet_menu)
        self.packet_paned = paned
        paned.add(top, weight=3)

        bottom = ttk.Panedwindow(paned, orient=tk.HORIZONTAL)
        detail_frame = tk.Frame(bottom, bg=T.BG)
        head = tk.Frame(detail_frame, bg=T.BG)
        head.pack(fill=tk.X)
        tk.Label(head, text="协议分层详情", bg=T.BG, fg=T.ACCENT,
                 font=T.FONT_UI_BOLD).pack(side=tk.LEFT)
        self.detail_title = tk.Label(head, text="", bg=T.BG, fg=T.FG_DIM, font=T.FONT_SUB)
        self.detail_title.pack(side=tk.LEFT, padx=8)
        self.detail = ttk.Treeview(detail_frame, columns=("val",), show="tree headings")
        self.detail.heading("#0", text="协议层 / 字段")
        self.detail.heading("val", text="值")
        self.detail.column("#0", width=230, stretch=False)
        self.detail.column("val", width=330, stretch=True)
        ds = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self.detail.yview)
        self.detail.configure(yscrollcommand=ds.set)
        self.detail.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ds.pack(side=tk.RIGHT, fill=tk.Y)
        bottom.add(detail_frame, weight=1)

        hex_frame = tk.Frame(bottom, bg=T.BG)
        hh = tk.Frame(hex_frame, bg=T.BG)
        hh.pack(fill=tk.X)
        tk.Label(hh, text="十六进制 / ASCII", bg=T.BG, fg=T.ACCENT,
                 font=T.FONT_UI_BOLD).pack(side=tk.LEFT)
        self.hex_info = tk.Label(hh, text="", bg=T.BG, fg=T.FG_DIM, font=T.FONT_SUB)
        self.hex_info.pack(side=tk.LEFT, padx=8)
        self.hex_text = T.make_text(hex_frame, fg="#9ece6a", font=T.FONT_MONO)
        hs = ttk.Scrollbar(hex_frame, orient=tk.VERTICAL, command=self.hex_text.yview)
        self.hex_text.configure(yscrollcommand=hs.set, state=tk.DISABLED)
        self.hex_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hs.pack(side=tk.RIGHT, fill=tk.Y)
        bottom.add(hex_frame, weight=1)
        paned.add(bottom, weight=2)
        self.after(350, self._init_pane_sash)

        self.packet_menu = tk.Menu(self, tearoff=0, bg=T.BG_PANEL, fg=T.FG,
                                   activebackground=T.SELECT, activeforeground="#fff")
        self.packet_menu.add_command(label="跟随 TCP 流", command=self.follow_selected)
        self.packet_menu.add_separator()
        self.packet_menu.add_command(label="按源地址过滤", command=lambda: self._filter_field("ip.src"))
        self.packet_menu.add_command(label="按目的地址过滤", command=lambda: self._filter_field("ip.dst"))
        self.packet_menu.add_command(label="按端口过滤", command=lambda: self._filter_field("port"))
        self.packet_menu.add_command(label="按进程过滤", command=lambda: self._filter_field("proc"))
        self.packet_menu.add_separator()
        self.packet_menu.add_command(label="复制摘要", command=self._copy_summary)

    def _init_pane_sash(self):
        """首次布局完成后把上下分栏调到 58%，避免详情区抢占列表高度。"""
        try:
            h = self.packet_paned.winfo_height()
            if h > 120:
                self.packet_paned.sashpos(0, int(h * 0.52))
        except Exception:
            pass

    def _build_stream_tab(self):
        bar = tk.Frame(self.tab_streams, bg=T.BG, pady=5)
        bar.pack(fill=tk.X)
        tk.Label(bar, text="TCP 流（按四元组归并）", bg=T.BG, fg=T.ACCENT,
                 font=T.FONT_UI_BOLD).pack(side=tk.LEFT)
        self.stream_summary = tk.Label(bar, text="", bg=T.BG, fg=T.FG_DIM, font=T.FONT_SUB)
        self.stream_summary.pack(side=tk.LEFT, padx=10)
        T.make_button(bar, "跟随流", self.follow_selected_stream, accent=True).pack(side=tk.RIGHT, padx=3)
        T.make_button(bar, "筛选此流", self._filter_selected_stream).pack(side=tk.RIGHT, padx=3)
        T.make_button(bar, "刷新", self.refresh_streams).pack(side=tk.RIGHT, padx=3)

        frame = tk.Frame(self.tab_streams, bg=T.BG)
        frame.pack(fill=tk.BOTH, expand=True)
        cols = ("id", "client", "server", "app", "proc", "state", "packets", "bytes", "duration")
        heads = ("流 ID", "客户端", "服务端", "应用", "进程", "状态", "包数", "载荷字节", "时长(s)")
        self.stream_tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        widths = {"id": 58, "client": 235, "server": 235, "app": 120, "proc": 135,
                  "state": 78, "packets": 60, "bytes": 78, "duration": 70}
        for c, h in zip(cols, heads):
            self.stream_tree.heading(c, text=h)
            self.stream_tree.column(c, width=widths[c], stretch=(c in ("client", "server", "app")),
                                    anchor=tk.W if c in ("client", "server", "app", "proc") else tk.CENTER)
        vs = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.stream_tree.yview)
        self.stream_tree.configure(yscrollcommand=vs.set)
        self.stream_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        self.stream_tree.bind("<Double-1>", lambda _e: self.follow_selected_stream())
        self.stream_tree.bind("<Return>", lambda _e: self.follow_selected_stream())

    def _build_process_tab(self):
        bar = tk.Frame(self.tab_procs, bg=T.BG, pady=5)
        bar.pack(fill=tk.X)
        tk.Label(bar, text="进程级流溯源（IP Helper API）", bg=T.BG, fg=T.ACCENT,
                 font=T.FONT_UI_BOLD).pack(side=tk.LEFT)
        self.proc_summary = tk.Label(bar, text="", bg=T.BG, fg=T.FG_DIM, font=T.FONT_SUB)
        self.proc_summary.pack(side=tk.LEFT, padx=10)
        T.make_button(bar, "跟随所选流", self.follow_selected_stream, accent=True).pack(side=tk.RIGHT, padx=3)
        T.make_button(bar, "筛选此进程", self._filter_selected_process).pack(side=tk.RIGHT, padx=3)
        T.make_button(bar, "刷新", self.refresh_processes).pack(side=tk.RIGHT, padx=3)

        frame = tk.Frame(self.tab_procs, bg=T.BG)
        frame.pack(fill=tk.BOTH, expand=True)
        cols = ("pid", "flows", "packets", "bytes")
        self.proc_tree = ttk.Treeview(frame, columns=cols, show="tree headings", selectmode="browse")
        self.proc_tree.heading("#0", text="进程 / 流")
        for c, h in zip(cols, ("PID", "流数", "包数", "字节")):
            self.proc_tree.heading(c, text=h)
        self.proc_tree.column("#0", width=560, stretch=True)
        self.proc_tree.column("pid", width=80, anchor=tk.CENTER)
        self.proc_tree.column("flows", width=60, anchor=tk.CENTER)
        self.proc_tree.column("packets", width=70, anchor=tk.CENTER)
        self.proc_tree.column("bytes", width=90, anchor=tk.CENTER)
        vs = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.proc_tree.yview)
        self.proc_tree.configure(yscrollcommand=vs.set)
        self.proc_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        self.proc_tree.bind("<Double-1>", lambda _e: self.follow_selected_stream())

    def _build_stats_tab(self):
        bar = tk.Frame(self.tab_stats, bg=T.BG, pady=5)
        bar.pack(fill=tk.X)
        tk.Label(bar, text="流量画像与协议分布", bg=T.BG, fg=T.ACCENT,
                 font=T.FONT_UI_BOLD).pack(side=tk.LEFT)
        T.make_button(bar, "刷新", self.refresh_stats).pack(side=tk.RIGHT)

        body = tk.Frame(self.tab_stats, bg=T.BG)
        body.pack(fill=tk.BOTH, expand=True)
        left = tk.Frame(body, bg=T.BG_PANEL)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6), pady=2)
        tk.Label(left, text="协议分布（按包数）", bg=T.BG_PANEL, fg=T.FG_DIM,
                 font=T.FONT_UI).pack(anchor=tk.W, padx=10, pady=(8, 0))
        self.chart = tk.Canvas(left, bg=T.BG_PANEL, highlightthickness=0, height=300)
        self.chart.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.chart.bind("<Configure>", lambda _e: self._draw_chart())

        right = tk.Frame(body, bg=T.BG)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6, 0), pady=2)
        self.stats_text = T.make_text(right, height=10, font=T.FONT_UI)
        self.stats_text.pack(fill=tk.X)
        self.stats_text.configure(state=tk.DISABLED)

        bottom = tk.Frame(right, bg=T.BG)
        bottom.pack(fill=tk.BOTH, expand=True, pady=(6, 0))
        tf = tk.LabelFrame(bottom, text=" Top 会话 ", bg=T.BG, fg=T.FG_DIM, bd=0)
        tf.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 4))
        self.talker_tree = ttk.Treeview(tf, columns=("src", "dst", "bytes"), show="headings", height=8)
        for c, h, w in (("src", "源", 150), ("dst", "目的", 150), ("bytes", "字节", 80)):
            self.talker_tree.heading(c, text=h)
            self.talker_tree.column(c, width=w, anchor=tk.W if c != "bytes" else tk.E)
        self.talker_tree.pack(fill=tk.BOTH, expand=True)

        pf = tk.LabelFrame(bottom, text=" Top 端口 ", bg=T.BG, fg=T.FG_DIM, bd=0)
        pf.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(4, 0))
        self.port_tree = ttk.Treeview(pf, columns=("proto", "port", "count"), show="headings", height=8)
        for c, h, w in (("proto", "协议", 70), ("port", "端口", 80), ("count", "次数", 80)):
            self.port_tree.heading(c, text=h)
            self.port_tree.column(c, width=w, anchor=tk.CENTER)
        self.port_tree.pack(fill=tk.BOTH, expand=True)

    def _build_statusbar(self):
        bar = tk.Frame(self, bg="#111118", padx=10, pady=4)
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var = tk.StringVar(value="就绪：选择网卡 → 开始抓包；或打开一个 pcap 文件。")
        tk.Label(bar, textvariable=self.status_var, bg="#111118", fg=T.FG_DIM,
                 anchor="w", font=T.FONT_SUB).pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.counter_var = tk.StringVar(value="0 包 / 0 B")
        tk.Label(bar, textvariable=self.counter_var, bg="#111118", fg=T.ACCENT,
                 font=T.FONT_MONO_SM).pack(side=tk.RIGHT)

    # ================================================================ 网卡
    def refresh_ifaces(self):
        self._interfaces = list_interfaces()
        labels = [i.label for i in self._interfaces]
        self.iface_box["values"] = labels
        if labels:
            if self.iface_var.get() not in labels:
                # 优先选有 IPv4 地址的非回环网卡
                idx = 0
                for i, info in enumerate(self._interfaces):
                    if any("." in ip for ip in info.ips) and not info.is_loopback:
                        idx = i
                        break
                self.iface_box.current(idx)
        self.local_ips = local_ip_set()
        self.npcap_badge.config(text=f"Npcap {'已就绪' if self._npcap_ok() else '未安装'}",
                                fg=T.GREEN if self._npcap_ok() else T.RED)
        self.status_var.set(f"已枚举 {len(labels)} 块可抓包网卡；BPF 过滤器在内核层生效。")

    def _npcap_ok(self):
        try:
            import ctypes
            ctypes.WinDLL("wpcap")
            return True
        except Exception:
            return False

    def _current_iface(self):
        label = self.iface_var.get()
        for info in self._interfaces:
            if info.label == label:
                return info
        return self._interfaces[0] if self._interfaces else None

    def _on_iface_change(self, _event=None):
        self.local_ips = local_ip_set()
        if self.capturing:
            self.stop_capture()
            self.start_capture()
        else:
            info = self._current_iface()
            if info:
                self.status_var.set(f"已选择网卡：{info.label}")

    def _set_bpf(self, expr):
        self.bpf_var.set(expr)

    # ================================================================ 抓包
    def start_capture(self):
        if self.capturing:
            return
        iface = self._current_iface()
        if iface is None:
            messagebox.showerror("没有可用网卡",
                                 "未找到可抓包的网卡。\n\n请确认已安装 Npcap，"
                                 "并勾选 WinPcap API-compatible Mode。")
            return
        if not self._npcap_ok():
            messagebox.showerror("缺少 Npcap",
                                 "未检测到 wpcap.dll。\n请安装 Npcap（npcap.com），"
                                 "安装时勾选 WinPcap API-compatible Mode。")
            return
        try:
            self.engine.start(iface=iface, bpf_filter=self.bpf_var.get())
        except RuntimeError as exc:
            messagebox.showerror("启动抓包失败", str(exc))
            return
        self.capturing = True
        self.mode = "实时"
        self.btn_start.state(["disabled"])
        self.btn_stop.state(["!disabled"])
        self.live_badge.config(text="● LIVE 抓包中", fg="#101018", bg=T.GREEN)
        self.status_var.set(f"正在抓包：{iface.label}   BPF: {self.engine.bpf or '无'}")
        self._tick()

    def stop_capture(self):
        if not self.capturing:
            return
        self.engine.stop()
        self.capturing = False
        self.btn_start.state(["!disabled"])
        self.btn_stop.state(["disabled"])
        self.live_badge.config(text="● 已停止", fg=T.FG_DIM, bg=T.BG_PANEL)
        self.status_var.set(f"抓包已停止，共 {self.engine.packet_count} 个包。")
        self.refresh_streams()
        self.refresh_processes()

    def _enqueue_packet(self, pkt):
        try:
            self.queue.put_nowait(pkt)
        except queue.Full:
            self._dropped += 1

    def _engine_error(self, msg):
        self.status_var.set(msg)

    def _drain_queue(self):
        n = 0
        try:
            while n < 300:
                pkt = self.queue.get_nowait()
                self._ingest(pkt, live=True)
                n += 1
        except queue.Empty:
            pass
        if n:
            self._stream_dirty = True
            self._process_dirty = True
        self.after(40, self._drain_queue)

    def _ingest(self, pkt, live=True):
        idx = self.next_index
        self.next_index += 1
        try:
            rec = build_record(pkt, idx, self.local_ips)
        except Exception:
            return
        if live:
            self._attribute_process(rec)
        try:
            stream = self.tracker.update(rec)
        except Exception:
            stream = None
        self.records.append(rec)
        self.by_index[idx] = rec
        self.stats.add(rec, stream)
        if stream is not None:
            self.stats.streams = len(self.tracker.streams)
        if self.filter.matches(rec):
            self._insert_packet(rec)
        if len(self.records) > MAX_PACKETS:
            self._trim()

    def _attribute_process(self, rec):
        if rec.local_side == "src":
            ip, port = rec.src, rec.sport
        elif rec.local_side == "dst":
            ip, port = rec.dst, rec.dport
        else:
            return
        if not port or not ip:
            return
        try:
            pid, name = self.mapper.lookup_or_refresh(rec.proto, ip, port)
        except Exception:
            return
        if pid is not None:
            rec.pid = pid
            rec.proc = name or f"PID {pid}"

    def _trim(self):
        # 超出上限时一次丢 2000 条，避免每包都 pop(0)
        drop = 2000
        removed = self.records[:drop]
        del self.records[:drop]
        for rec in removed:
            self.by_index.pop(rec.index, None)
            iid = str(rec.index)
            if self.tree.exists(iid):
                self.tree.delete(iid)
        self._dropped += drop
        self.status_var.set(f"已达到 {MAX_PACKETS} 包上限，自动丢弃最早 {drop} 个包。")

    def _insert_packet(self, rec):
        tag = rec.proto if rec.proto in T.PROTO_COLORS else "OTHER"
        tags = [tag]
        if "重传" in rec.tags:
            tags.append("retrans")
        iid = str(rec.index)
        self.tree.insert("", tk.END, iid=iid, values=(
            rec.index, _time_str(rec.time), _short_addr(rec.src), _short_addr(rec.dst),
            rec.proto, rec.length, rec.proc or "—", rec.info), tags=tuple(tags))
        if self._near_bottom():
            self.tree.see(iid)

    def _near_bottom(self):
        try:
            return self.tree.yview()[1] > 0.97
        except Exception:
            return True

    # ================================================================ 过滤器
    def _select_all_filter(self, _e=None):
        self.filter_entry.select_range(0, tk.END)
        return "break"

    def _set_display(self, expr):
        self.filter_var.set(expr)
        self.apply_filter()

    def apply_filter(self):
        expr = self.filter_var.get().strip()
        try:
            f = DisplayFilter(expr)
        except FilterSyntaxError as exc:
            self.filter_error.config(text="过滤器语法错误：" + exc.message + "  " + exc.caret())
            self.bell()
            return
        self.filter = f
        self.filter_error.config(text="" if not expr else f"已应用：{expr}   （匹配 {sum(1 for r in self.records if f.matches(r))} 个包）",
                                 fg=T.FG_DIM if expr else T.BG)
        self.tree.delete(*self.tree.get_children())
        for rec in self.records:
            if self.filter.matches(rec):
                self._insert_packet(rec)
        self.refresh_streams()

    def _filter_field(self, field):
        sel = self.tree.selection()
        if not sel:
            return
        rec = self.by_index.get(int(sel[0]))
        if rec is None:
            return
        fields = rec.get_fields()
        value = fields.get(field)
        if isinstance(value, (list, tuple)):
            value = value[0]
        if value in (None, ""):
            return
        if isinstance(value, str) and not value.replace(".", "").replace(":", "").isdigit():
            expr = f'{field} == "{value}"'
        else:
            expr = f"{field} == {value}"
        self._set_display(expr)

    # ================================================================ 选择/详情
    def _on_select_packet(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        rec = self.by_index.get(int(sel[0]))
        if rec is None:
            return
        self.detail.delete(*self.detail.get_children())
        self.detail_title.config(text=f"Frame {rec.index} · {rec.proto} · {rec.length} 字节")
        try:
            layers = parse_layers(rec.raw)
        except Exception as exc:
            layers = [(f"解析失败：{exc}", [])]
        for name, fields in layers:
            node = self.detail.insert("", tk.END, text=name, values=("",), open=True)
            for k, v in fields:
                self.detail.insert(node, tk.END, text=k, values=(v,))
        try:
            raw = bytes(rec.raw)
            self._set_hex(hex_dump(raw), f"{len(raw)} 字节")
        except Exception:
            self._set_hex("", "")

    def _set_hex(self, text, info=""):
        self.hex_text.config(state=tk.NORMAL)
        self.hex_text.delete("1.0", tk.END)
        self.hex_text.insert("1.0", text)
        self.hex_text.config(state=tk.DISABLED)
        self.hex_info.config(text=info)

    def _packet_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.packet_menu.tk_popup(event.x_root, event.y_root)

    def _copy_summary(self):
        sel = self.tree.selection()
        if sel:
            values = self.tree.item(sel[0], "values")
            self.clipboard_clear()
            self.clipboard_append("  ".join(str(v) for v in values))
            self.status_var.set("已复制摘要到剪贴板。")

    def follow_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选中一个 TCP 数据包。")
            return
        rec = self.by_index.get(int(sel[0]))
        if rec is None or rec.stream_id is None:
            messagebox.showinfo("提示", "该数据包不属于 TCP 流（可能是 UDP/ARP/ICMP）。")
            return
        stream = self.tracker.get(rec.stream_id)
        if stream is None:
            messagebox.showinfo("提示", "流信息尚未建立。")
            return
        self._open_follow(stream)

    def _open_follow(self, stream: TCPStream):
        FollowStreamWindow(self, stream)

    # ================================================================ TCP 流
    def refresh_streams(self):
        self._stream_dirty = False
        streams = self.tracker.sorted_streams()
        self.stream_tree.delete(*self.stream_tree.get_children())
        for st in streams[-2000:]:
            self.stream_tree.insert("", tk.END, iid=str(st.stream_id), values=(
                st.stream_id, f"{_short_addr(st.client[0])}:{st.client[1]}",
                f"{_short_addr(st.server[0])}:{st.server[1]}", st.app_proto,
                st.process_label, st.state, st.packet_count,
                st.total_bytes, f"{st.duration:.3f}"))
        stat = self.tracker.statistics()
        self.stream_summary.config(
            text=f"共 {stat['count']} 条流，HTTP {stat['http']} 条，"
                 f"重传 {stat['retrans']} 段，累计载荷 {stat['bytes']} 字节")

    def _selected_stream(self):
        sel = self.stream_tree.selection()
        if not sel:
            return None
        try:
            return self.tracker.get(int(sel[0]))
        except ValueError:
            return None

    def follow_selected_stream(self):
        # 进程页的选中项是子节点 stream:<id>
        if self.nb.index(self.nb.select()) == 2:
            sel = self.proc_tree.selection()
            if sel:
                iid = sel[0]
                if iid.startswith("stream:"):
                    st = self.tracker.get(int(iid.split(":", 1)[1]))
                    if st:
                        self._open_follow(st)
                        return
                messagebox.showinfo("提示", "请选择一个进程下的具体 TCP 流。")
                return
        st = self._selected_stream()
        if st is None:
            messagebox.showinfo("提示", "请先在「TCP 流」列表中选择一条流。")
            return
        self._open_follow(st)

    def _filter_selected_stream(self):
        st = self._selected_stream()
        if st is None:
            return
        self.filter_var.set(f"stream == {st.stream_id}")
        self.apply_filter()
        self.nb.select(0)

    # ================================================================ 进程
    def refresh_processes(self):
        self._process_dirty = False
        self.proc_tree.delete(*self.proc_tree.get_children())
        groups = self.tracker.process_groups()
        items = []
        for pid, streams in groups.items():
            name = streams[0].processes.get(pid, f"PID {pid}")
            packets = sum(s.packet_count for s in streams)
            size = sum(s.total_bytes for s in streams)
            items.append((pid, name, streams, packets, size))
        items.sort(key=lambda x: -x[4])
        for idx, (pid, name, streams, packets, size) in enumerate(items):
            parent = self.proc_tree.insert("", tk.END, iid=f"pid:{pid}",
                                           text=f"{name}", values=(pid, len(streams), packets, size),
                                           open=(idx < 2 and len(streams) > 1))
            for st in streams:
                label = (f"流 #{st.stream_id}  {st.app_proto}  "
                         f"{_short_addr(st.client[0])}:{st.client[1]} → "
                         f"{_short_addr(st.server[0])}:{st.server[1]}")
                self.proc_tree.insert(parent, tk.END, iid=f"stream:{st.stream_id}",
                                      text=label,
                                      values=("", "", st.packet_count, st.total_bytes))
        total = len(self.tracker.streams)
        mapped = sum(len(v) for v in groups.values())
        self.proc_summary.config(text=f"{len(groups)} 个进程 · {mapped}/{total} 条流已归属 · "
                                      f"连接表 {self.mapper.entry_count} 项"
                                      + (f" · {self.mapper.error}" if self.mapper.error else ""))
        self.pid_badge.config(text=f"进程映射 {self.mapper.entry_count} 项",
                              fg=T.GREEN if not self.mapper.error else T.YELLOW)

    def _filter_selected_process(self):
        sel = self.proc_tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请选择一个进程。")
            return
        iid = sel[0]
        if iid.startswith("pid:"):
            pid = int(iid.split(":", 1)[1])
        elif iid.startswith("stream:"):
            st = self.tracker.get(int(iid.split(":", 1)[1]))
            pid = st.pid if st else None
            if pid is None:
                messagebox.showinfo("提示", "该流没有归属进程。")
                return
        else:
            return
        self.filter_var.set(f"pid == {pid}")
        self.apply_filter()
        self.nb.select(0)

    # ================================================================ 统计
    def refresh_stats(self):
        self._last_stats = time.time()
        s = self.stats
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete("1.0", tk.END)
        lines = [
            f"数据包总数        {s.total}",
            f"总字节数          {s.total_bytes:,}",
            f"TCP 流            {len(self.tracker.streams)}",
            f"HTTP 请求         {s.http_requests}",
            f"DNS 查询          {s.dns_queries}",
            f"TLS ClientHello   {s.tls_sessions}",
            f"丢弃/队列溢出      {self._dropped}",
            "",
            "协议占比（包数）：",
        ]
        for proto, cnt, pct in s.proto_share():
            lines.append(f"  {proto:<10} {cnt:>7}  {pct:5.1f}%")
        self.stats_text.insert("1.0", "\n".join(lines))
        self.stats_text.config(state=tk.DISABLED)

        self.talker_tree.delete(*self.talker_tree.get_children())
        for src, dst, size in s.top_talkers(8):
            self.talker_tree.insert("", tk.END, values=(src, dst, f"{size:,}"))
        self.port_tree.delete(*self.port_tree.get_children())
        for proto, port, cnt in s.top_ports(8):
            self.port_tree.insert("", tk.END, values=(proto, port, cnt))
        self._draw_chart()

    def _draw_chart(self):
        c = self.chart
        c.delete("all")
        w = max(200, c.winfo_width())
        h = max(120, c.winfo_height())
        shares = self.stats.proto_share()[:10]
        if not shares:
            c.create_text(w // 2, h // 2, text="暂无数据", fill=T.FG_DIM, font=T.FONT_UI)
            return
        bar_h = min(26, max(16, (h - 30) // max(1, len(shares))))
        max_cnt = max(x[1] for x in shares) or 1
        y = 12
        for proto, cnt, _pct in shares:
            color = T.PROTO_COLORS.get(proto, T.FG_DIM)
            c.create_text(8, y + bar_h / 2, text=proto, fill=color, anchor="w", font=T.FONT_MONO_SM)
            x0 = 92
            bw = (w - x0 - 70) * cnt / max_cnt
            c.create_rectangle(x0, y + 3, x0 + max(2, bw), y + bar_h - 3,
                               fill=color, outline="")
            c.create_text(x0 + max(2, bw) + 6, y + bar_h / 2, text=str(cnt),
                          fill=T.FG_DIM, anchor="w", font=T.FONT_MONO_SM)
            y += bar_h + 4

    # ================================================================ 定时器
    def _tick(self):
        now = time.time()
        if self.capturing:
            self.live_badge.config(text=f"● LIVE  {self.engine.pps:.0f} pkt/s")
            self.counter_var.set(f"{self.engine.packet_count} 包 / {_fmt_bytes(self.engine.byte_count)}")
        if self._stream_dirty and now - self._last_stream > 1.2:
            self._last_stream = now
            self.refresh_streams()
            self._stream_dirty = False
        if self._process_dirty and now - self._last_stats > 1.8:
            self.refresh_processes()
            self._process_dirty = False
        if now - self._last_stats > 2.0 and self.nb.index(self.nb.select()) == 3:
            self.refresh_stats()
        if now - self._last_status > 1.0:
            self._last_status = now
            if self.mode == "实时" and not self.capturing:
                pass
            self.counter_var.set(f"{len(self.records)} 包 / {_fmt_bytes(self.stats.total_bytes)}")
            if not self.mapper.error and self.mapper.entry_count:
                self.pid_badge.config(text=f"进程映射 {self.mapper.entry_count} 项", fg=T.GREEN)
        self.after(500, self._tick)

    def _on_tab_change(self, _event=None):
        idx = self.nb.index(self.nb.select())
        if idx == 1:
            self.refresh_streams()
        elif idx == 2:
            self.refresh_processes()
        elif idx == 3:
            self.refresh_stats()

    # ================================================================ 文件
    def clear_packets(self):
        if self.capturing:
            if not messagebox.askyesno("正在抓包", "清空会丢弃当前已捕获的数据包，是否继续？"):
                return
        self.records.clear()
        self.by_index.clear()
        self.next_index = 1
        self.tree.delete(*self.tree.get_children())
        self.detail.delete(*self.detail.get_children())
        self._set_hex("")
        self.detail_title.config(text="")
        self.tracker.clear()
        self.stats.clear()
        self.stream_tree.delete(*self.stream_tree.get_children())
        self.proc_tree.delete(*self.proc_tree.get_children())
        self.filter_error.config(text="")
        self.status_var.set("已清空所有数据包与流。")
        self.counter_var.set("0 包 / 0 B")

    def save_pcap(self):
        if not self.records:
            messagebox.showinfo("提示", "当前没有可保存的数据包。")
            return
        path = filedialog.asksaveasfilename(
            title="保存抓包结果", defaultextension=".pcap",
            filetypes=[("PCAP 文件", "*.pcap"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            wrpcap(path, [r.raw for r in self.records])
            self.status_var.set(f"已保存 {len(self.records)} 个包到 {path}")
        except Exception as exc:
            messagebox.showerror("保存失败", str(exc))

    def open_pcap(self):
        path = filedialog.askopenfilename(
            title="打开 PCAP 文件",
            filetypes=[("PCAP / PCAPNG", "*.pcap *.pcapng"), ("所有文件", "*.*")])
        if not path:
            return
        if self.capturing:
            self.stop_capture()
        try:
            pkts = rdpcap(path)
        except Exception as exc:
            messagebox.showerror("打开失败", f"{exc}\n\n提示：本程序依赖 scapy 读取 pcap。")
            return
        self.clear_packets()
        self.mode = "离线"
        self.status_var.set(f"正在载入 {len(pkts)} 个包…")
        self.update_idletasks()
        for pkt in pkts:
            self._ingest(pkt, live=False)
        self.live_badge.config(text=f"● 离线  {os.path.basename(path)[:30]}", fg=T.ACCENT, bg=T.BG_PANEL)
        self.status_var.set(f"已载入 {len(pkts)} 个包：{path}（离线模式不做进程归属）")
        self.refresh_streams()
        self.refresh_processes()
        self.refresh_stats()

    def export_csv(self):
        if not self.records:
            messagebox.showinfo("提示", "没有数据可导出。")
            return
        path = filedialog.asksaveasfilename(
            title="导出包列表", defaultextension=".csv",
            filetypes=[("CSV 文件", "*.csv")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                writer = csv.writer(fh)
                writer.writerow(["No", "Time", "Source", "Destination", "Protocol",
                                 "Length", "Process", "Info"])
                for r in self.records:
                    writer.writerow([r.index, _time_str(r.time), r.src, r.dst, r.proto,
                                     r.length, r.proc, r.info])
            self.status_var.set(f"已导出 CSV：{path}")
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc))

    # ================================================================ 帮助
    def show_filter_help(self):
        win = tk.Toplevel(self)
        win.title("显示过滤器语法")
        win.configure(bg=T.BG)
        T.center_window(win, 760, 560, self)
        text = T.make_text(win, wrap=tk.WORD, font=T.FONT_UI)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        help_text = """PyShark 显示过滤器语法（对已捕获的包求值，不影响抓包）

逻辑运算（优先级从低到高）：
    or / ||        and / &&        not / !
    括号 ( ) 可改变优先级

比较运算：
    ==   !=   >   >=   <   <=
    contains "子串"        （字符串包含，忽略大小写）
    matches "正则"         （正则匹配）

常用字段：
    http            http.method    http.uri       http.host
    http.status     http.user_agent
    dns             dns.qname      dns.qtype      dns.response
    tls             tls.sni
    tcp  udp  ip  ipv4  ipv6  icmp  arp
    tcp.port / udp.port / port       srcport / dstport
    ip.src  ip.dst  ip.addr
    tcp.flags  tcp.seq  tcp.ack  tcp.len
    frame.len  frame.number
    stream          pid            proc

示例：
    http and tcp.port == 80
    (http or dns) and not arp
    ip.addr == 192.168.1.10 and tcp.flags contains "SYN"
    http.uri contains "login"
    frame.len > 1000
    proc contains "chrome"
    stream == 3

提示：
  * 字段名、协议名不区分大小写；字符串建议加双引号。
  * 裸写协议名等价于“该协议为真”，例如 http、ipv6。
  * 抓包过滤器（BPF）是另一套语法，例如 tcp port 80，在内核层执行；
    显示过滤器只决定“显示哪些已捕获的包”。
"""
        text.insert("1.0", help_text)
        text.configure(state=tk.DISABLED)

    def show_help(self):
        messagebox.showinfo(
            "使用说明",
            "1. 选择网卡（有 IP 的物理/WiFi 网卡），必要时填写 BPF 过滤器。\n"
            "2. 点击「开始抓包」，列表会实时出现数据包。\n"
            "3. 点击数据包查看协议树与十六进制；双击或右键可「跟随 TCP 流」。\n"
            "4. 显示过滤器支持 and/or/not，对已捕获的包二次筛选。\n"
            "5. 「TCP 流」页按四元组归并连接；「进程」页按 PID 归并流。\n"
            "6. 保存 PCAP 后可用 Wireshark 打开互验。\n\n"
            "依赖：Npcap（Windows）+ scapy；抓包通常需要管理员权限。")

    def show_about(self):
        messagebox.showinfo(
            "关于 PyShark Pro",
            f"{APP_TITLE}  v{VERSION}\n\n"
            "《软件与系统安全》实验 1A：带 GUI 的网络嗅探器\n"
            "NPS：基于 Npcap/libpcap 的实时抓包 + BPF 过滤\n"
            "NPA：协议分层解析、HTTP/DNS/TLS、十六进制转储\n"
            "加分项：TCP 流重组与跟随、进程级流溯源、显示过滤器逻辑演算\n\n"
            "技术栈：Python 3 + tkinter + scapy + Npcap\n"
            "作者：方炳懿  202628018629033")

    # ================================================================ 关闭
    def _on_close(self):
        try:
            self.engine.stop()
        except Exception:
            pass
        try:
            self.mapper.stop()
        except Exception:
            pass
        self.destroy()


# ------------------------------------------------------------------ 工具
def _short_addr(addr: str) -> str:
    """列表中的 IPv6 压缩显示，完整地址仍在详情树/过滤器里可用。"""
    if ":" in addr and len(addr) > 26:
        return addr[:19] + "…" + addr[-6:]
    return addr


def _time_str(ts: float) -> str:
    try:
        lt = time.localtime(float(ts))
        ms = int((float(ts) % 1) * 1000)
        return time.strftime("%H:%M:%S", lt) + f".{ms:03d}"
    except Exception:
        return "-"


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def main():
    T.enable_dpi_awareness()
    app = SnifferApp()
    app.mainloop()


if __name__ == "__main__":
    main()

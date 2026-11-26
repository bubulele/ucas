# -*- coding: utf-8 -*-
"""follow_window.py —— “跟随 TCP 流”窗口

三个视角互补：
  1. 文本：按方向重组后的连续字节流（Wireshark Follow TCP Stream 的做法）
  2. HTTP：把流切成请求/响应事务，便于阅读应用层语义
  3. 时序图：以客户端/服务端为两条生命线，画出每个报文段的方向、
     相对时间、序号、长度和标志位——这正是讲义强调“图形化界面
     对分析流时序图有重要帮助”的落点
"""

import datetime
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from packet_parser import hex_dump
from ui_theme import (ACCENT, ACCENT2, BG, BG_ALT, BG_PANEL, BORDER, CYAN, FG,
                      FG_DIM, FONT_MONO, FONT_MONO_SM, FONT_UI, FONT_UI_BOLD,
                      GREEN, ORANGE, RED, SELECT, YELLOW, center_window,
                      make_text)


class FollowStreamWindow(tk.Toplevel):
    def __init__(self, parent, stream):
        super().__init__(parent)
        self.stream = stream
        self.title(f"跟随 TCP 流 #{stream.stream_id} — {stream.endpoint_label()}")
        self.configure(bg=BG)
        center_window(self, 1180, 800, parent)
        self.minsize(900, 600)
        self.transient(parent)

        self._build_header()
        self._build_tabs()
        self._fill()
        self.after(60, lambda: __import__("ui_theme").apply_dark_titlebar(self))

    # ------------------------------------------------------------ 头部
    def _build_header(self):
        bar = tk.Frame(self, bg=BG_ALT, padx=12, pady=8)
        bar.pack(fill=tk.X)
        left = tk.Frame(bar, bg=BG_ALT)
        tk.Label(left, text=f"TCP 流 #{self.stream.stream_id}", bg=BG_ALT,
                 fg=ACCENT, font=("Microsoft YaHei UI", 12, "bold"),
                 anchor="w").pack(anchor=tk.W, fill=tk.X)
        detail = (f"{self.stream.client[0]}:{self.stream.client[1]} → "
                  f"{self.stream.server[0]}:{self.stream.server[1]}   "
                  f"{self.stream.app_proto} · {self.stream.state} · "
                  f"{self.stream.packet_count} 包 · {self.stream.total_bytes} B · "
                  f"{self.stream.duration:.3f}s · {self.stream.process_label}")
        tk.Label(left, text=detail, bg=BG_ALT, fg=FG_DIM, font=FONT_UI,
                 anchor="w", justify=tk.LEFT).pack(anchor=tk.W, fill=tk.X, pady=(2, 0))

        right = tk.Frame(bar, bg=BG_ALT)
        right.pack(side=tk.RIGHT)
        left.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        for text, cmd in (("复制当前页", self._copy_current),
                          ("导出文本", self._save_text),
                          ("关闭", self.destroy)):
            b = tk.Button(right, text=text, command=cmd, bg=BG_PANEL, fg=FG,
                          relief="flat", padx=10, pady=4, cursor="hand2",
                          activebackground=SELECT, activeforeground="#fff")
            b.pack(side=tk.LEFT, padx=3)

    # ------------------------------------------------------------ 标签页
    def _build_tabs(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # 文本
        f1 = tk.Frame(self.nb, bg=BG_PANEL)
        self.text = make_text(f1)
        vs = ttk.Scrollbar(f1, orient=tk.VERTICAL, command=self.text.yview)
        hs = ttk.Scrollbar(f1, orient=tk.HORIZONTAL, command=self.text.xview)
        self.text.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        f1.rowconfigure(0, weight=1)
        f1.columnconfigure(0, weight=1)
        self.text.tag_configure("c2s", foreground=CYAN)
        self.text.tag_configure("s2c", foreground=GREEN)
        self.text.tag_configure("head", foreground=ACCENT2, font=FONT_UI_BOLD)
        self.text.tag_configure("dim", foreground=FG_DIM)
        self.nb.add(f1, text="  文本（按方向重组）  ")

        # HTTP
        f2 = tk.Frame(self.nb, bg=BG_PANEL)
        self.http_text = make_text(f2)
        vs2 = ttk.Scrollbar(f2, orient=tk.VERTICAL, command=self.http_text.yview)
        self.http_text.configure(yscrollcommand=vs2.set)
        self.http_text.grid(row=0, column=0, sticky="nsew")
        vs2.grid(row=0, column=1, sticky="ns")
        f2.rowconfigure(0, weight=1)
        f2.columnconfigure(0, weight=1)
        self.http_text.tag_configure("req", foreground=CYAN)
        self.http_text.tag_configure("resp", foreground=GREEN)
        self.http_text.tag_configure("head", foreground=ACCENT2, font=FONT_UI_BOLD)
        self.nb.add(f2, text="  HTTP 事务  ")

        # 时序图
        f3 = tk.Frame(self.nb, bg=BG_PANEL)
        self.canvas = tk.Canvas(f3, bg=BG_PANEL, highlightthickness=0)
        vs3 = ttk.Scrollbar(f3, orient=tk.VERTICAL, command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vs3.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        vs3.grid(row=0, column=1, sticky="ns")
        f3.rowconfigure(0, weight=1)
        f3.columnconfigure(0, weight=1)
        self.canvas.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(int(-e.delta / 120), "units"))
        self.nb.add(f3, text="  时序图  ")

        # Hex
        f4 = tk.Frame(self.nb, bg=BG_PANEL)
        self.hex_text = make_text(f4, fg="#9ece6a")
        vs4 = ttk.Scrollbar(f4, orient=tk.VERTICAL, command=self.hex_text.yview)
        hs4 = ttk.Scrollbar(f4, orient=tk.HORIZONTAL, command=self.hex_text.xview)
        self.hex_text.configure(yscrollcommand=vs4.set, xscrollcommand=hs4.set)
        self.hex_text.grid(row=0, column=0, sticky="nsew")
        vs4.grid(row=0, column=1, sticky="ns")
        hs4.grid(row=1, column=0, sticky="ew")
        f4.rowconfigure(0, weight=1)
        f4.columnconfigure(0, weight=1)
        self.nb.add(f4, text="  十六进制  ")

    # ------------------------------------------------------------ 填充
    def _fill(self):
        st = self.stream
        c2s = st.reassemble(0)
        s2c = st.reassemble(1)

        # ---- 文本
        self.text.insert(tk.END, f"# 流 {st.stream_id}  {st.endpoint_label()}\n", "head")
        self.text.insert(tk.END,
                         f"# 应用协议: {st.app_proto}   状态: {st.state}   "
                         f"包数: {st.packet_count}   载荷: {st.total_bytes} 字节\n\n", "dim")
        self.text.insert(tk.END, f"=== 客户端 → 服务端（{len(c2s.data)} 字节，"
                                  f"{c2s.segments} 段，重传 {c2s.retransmissions}） ===\n", "head")
        self.text.insert(tk.END, c2s.text() or "(无载荷)", "c2s")
        self.text.insert(tk.END, "\n\n")
        self.text.insert(tk.END, f"=== 服务端 → 客户端（{len(s2c.data)} 字节，"
                                  f"{s2c.segments} 段，重传 {s2c.retransmissions}） ===\n", "head")
        self.text.insert(tk.END, s2c.text() or "(无载荷)", "s2c")
        self.text.configure(state=tk.DISABLED)

        # ---- HTTP
        self._fill_http()

        # ---- 时序图
        self._draw_sequence()

        # ---- Hex
        raw = c2s.data + s2c.data
        self.hex_text.insert(tk.END, hex_dump(raw) if raw else "(无 TCP 载荷)")
        self.hex_text.configure(state=tk.DISABLED)

    def _fill_http(self):
        st = self.stream
        if st.app_proto != "HTTP":
            self.http_text.insert(tk.END,
                                  f"该流的应用层协议为 {st.app_proto}，不是明文 HTTP。\n\n"
                                  "提示：HTTPS 的载荷是 TLS 记录，内容已加密；\n"
                                  "本工具只解析 ClientHello 中的 SNI 等明文元数据。", "dim")
        else:
            tx = st.http_transactions()
            if not tx:
                self.http_text.insert(tk.END, "未从重组数据中解析出完整的 HTTP 事务。", "dim")
            for i, (req, resp) in enumerate(tx, 1):
                self.http_text.insert(tk.END, f"===== 事务 {i} =====\n", "head")
                if req:
                    self.http_text.insert(tk.END, f">>> {req.summary}\n", "req")
                    for k, v in req.headers:
                        self.http_text.insert(tk.END, f">>> {k}: {v}\n", "req")
                    if req.body:
                        self.http_text.insert(tk.END, ">>> [请求体]\n" + _safe(req.body) + "\n", "req")
                if resp:
                    self.http_text.insert(tk.END, f"<<< {resp.summary}\n", "resp")
                    for k, v in resp.headers:
                        self.http_text.insert(tk.END, f"<<< {k}: {v}\n", "resp")
                    if resp.body:
                        body = resp.body[:4000]
                        if any(t in resp.content_type.lower() for t in ("text", "json", "javascript")):
                            self.http_text.insert(tk.END, "<<< [响应体]\n" + _safe(body) + "\n", "resp")
                        else:
                            self.http_text.insert(tk.END, f"<<< [响应体 {len(resp.body)} 字节，二进制]\n", "resp")
                self.http_text.insert(tk.END, "\n")
        self.http_text.configure(state=tk.DISABLED)

    def _draw_sequence(self):
        c = self.canvas
        c.delete("all")
        w = 1000
        left_x, right_x = 200, w - 200
        margin_top = 60
        row_h = 34
        events = self.stream.timeline(max_events=300)
        height = margin_top + max(1, len(events)) * row_h + 80
        c.configure(scrollregion=(0, 0, w, height))

        c.create_text(w // 2, 20, text="TCP 流时序图（客户端 / 服务端）", fill=FG,
                      font=("Microsoft YaHei UI", 12, "bold"))
        c.create_text(left_x, 42, text=f"客户端 {self.stream.client[0]}:{self.stream.client[1]}",
                      fill=CYAN, font=FONT_UI)
        c.create_text(right_x, 42, text=f"服务端 {self.stream.server[0]}:{self.stream.server[1]}",
                      fill=GREEN, font=FONT_UI)
        c.create_line(left_x, margin_top - 8, left_x, height - 30, fill=CYAN, width=2, dash=(6, 4))
        c.create_line(right_x, margin_top - 8, right_x, height - 30, fill=GREEN, width=2, dash=(6, 4))

        y = margin_top
        for ev in events:
            flags = ev["flags"] or "-"
            direction = ev["dir"]
            color = CYAN if direction == 0 else GREEN
            if "S" in flags and "A" not in flags:
                color = YELLOW
            elif "F" in flags:
                color = ORANGE
            elif "R" in flags:
                color = RED
            x1, x2 = (left_x, right_x) if direction == 0 else (right_x, left_x)
            y += row_h
            # 时间
            c.create_text(70, y, text=f"+{ev['rel']:.3f}s", fill=FG_DIM, font=FONT_MONO_SM)
            # 箭头
            c.create_line(x1, y, x2, y, fill=color, width=2,
                          arrow=tk.LAST, arrowshape=(10, 12, 4))
            # 标签
            label = f"#{ev['index']}  {flags}  len={ev['len']}  seq={ev['seq']}"
            c.create_text((x1 + x2) / 2, y - 11, text=label, fill=color,
                          font=FONT_MONO_SM)

        c.create_text(w // 2, height - 18,
                      text=f"共 {len(events)} 个事件   重传 {self.stream._retrans[0] + self.stream._retrans[1]}   "
                           f"乱序 {self.stream._ooo[0] + self.stream._ooo[1]}",
                      fill=FG_DIM, font=FONT_UI)

    # ------------------------------------------------------------ 操作
    def _copy_current(self):
        tab = self.nb.index(self.nb.select())
        widget = (self.text, self.http_text, None, self.hex_text)[tab]
        if widget is None:
            messagebox.showinfo("提示", "时序图请使用「导出文本」保存流信息。", parent=self)
            return
        text = widget.get("1.0", tk.END).strip()
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("已复制", f"已复制 {len(text)} 个字符到剪贴板。", parent=self)

    def _save_text(self):
        path = filedialog.asksaveasfilename(
            parent=self, title="导出流内容",
            defaultextension=".txt",
            initialfile=f"tcp_stream_{self.stream.stream_id}.txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.stream.text_dump())
                if self.stream.app_proto == "HTTP":
                    fh.write("\n\n" + self.stream.http_dump())
            messagebox.showinfo("已保存", path, parent=self)
        except Exception as exc:
            messagebox.showerror("保存失败", str(exc), parent=self)


def _safe(data: bytes) -> str:
    return "".join(chr(b) if (32 <= b < 127 or b in (9, 10, 13)) else "." for b in data)
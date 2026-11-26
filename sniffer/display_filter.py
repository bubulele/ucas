# -*- coding: utf-8 -*-
"""display_filter.py —— 显示过滤器的词法/语法分析与求值

Wireshark 的显示过滤器本质上是一个小型表达式语言。本模块用
递归下降（recursive descent）实现一个子集，支持：

    http and tcp.port == 80
    (http or dns) and not arp
    ip.addr == 192.168.1.10
    tcp.flags contains "SYN"
    http.uri contains "login"
    frame.len > 1000
    proc contains "chrome"

运算符优先级（从低到高）：or < and < not < 比较。
支持 C 风格别名：|| && !。

与“抓包过滤器（BPF）”的区别：
  - BPF 在**内核/Npcap 驱动**中执行，决定哪些包被捕获；
  - 显示过滤器在**用户态**对已捕获的包求值，只影响展示，不丢包。
"""

import re
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple


class FilterSyntaxError(ValueError):
    """过滤器语法错误，带出错位置，便于 GUI 用 ^ 指示。"""

    def __init__(self, message: str, expr: str, pos: int):
        self.message = message
        self.expr = expr
        self.pos = max(0, min(pos, len(expr)))
        super().__init__(message)

    def caret(self) -> str:
        return " " * self.pos + "^"

    def pretty(self) -> str:
        return f"{self.message}\n{self.expr}\n{self.caret()}"


# ------------------------------------------------------------------ 词法

_TOKEN_RE = re.compile(r"""
    \s*(?:
        (?P<op>>=|<=|==|!=|>|<|=|~)
      | (?P<lparen>\()
      | (?P<rparen>\))
      | (?P<and>&&|\band\b)
      | (?P<or>\|\||\bor\b)
      | (?P<not>!|\bnot\b)
      | (?P<contains>\bcontains\b|\bmatches\b)
      | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
      | (?P<ipv6>(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4})
      | (?P<number>\d+(?:\.\d+)*)
      | (?P<ident>[A-Za-z_][\w.:\-/]*)
    )
""", re.IGNORECASE | re.VERBOSE)


@dataclass
class Token:
    kind: str
    value: str
    pos: int


def tokenize(expr: str) -> List[Token]:
    tokens: List[Token] = []
    pos = 0
    while pos < len(expr):
        if expr[pos:].strip() == "":
            break
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            raise FilterSyntaxError(f"无法识别的字符 {expr[pos]!r}", expr, pos)
        kind = m.lastgroup or ""
        tokens.append(Token(kind, m.group(kind), m.start(kind)))
        pos = m.end()
    tokens.append(Token("eof", "", len(expr)))
    return tokens


# ------------------------------------------------------------------ 语法

# AST 节点：
#   ("or", l, r) ("and", l, r) ("not", x)
#   ("cmp", field, op, value) ("bool", field)
#   ("const", True/False)


class Parser:
    def __init__(self, expr: str):
        self.expr = expr
        self.tokens = tokenize(expr)
        self.i = 0

    @property
    def cur(self) -> Token:
        return self.tokens[self.i]

    def advance(self) -> Token:
        tok = self.cur
        self.i += 1
        return tok

    def expect(self, kind: str) -> Token:
        if self.cur.kind != kind:
            raise FilterSyntaxError(f"此处应为 {kind}，实际是 {self.cur.value!r}", self.expr, self.cur.pos)
        return self.advance()

    def parse(self):
        if self.cur.kind == "eof":
            return ("const", True)
        node = self.parse_or()
        if self.cur.kind != "eof":
            raise FilterSyntaxError(f"多余的内容 {self.cur.value!r}", self.expr, self.cur.pos)
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.cur.kind == "or":
            self.advance()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.cur.kind == "and":
            self.advance()
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self):
        if self.cur.kind == "not":
            self.advance()
            return ("not", self.parse_not())
        return self.parse_primary()

    def parse_primary(self):
        tok = self.cur
        if tok.kind == "lparen":
            self.advance()
            node = self.parse_or()
            self.expect("rparen")
            return node
        if tok.kind == "eof":
            raise FilterSyntaxError("表达式意外结束", self.expr, tok.pos)

        if tok.kind == "ident":
            field_tok = self.advance()
            field = field_tok.value.lower()
            # 裸协议名，如 http / tcp / ipv6
            if self.cur.kind in ("eof", "and", "or", "rparen"):
                return ("bool", field)
            if self.cur.kind == "contains":
                self.advance()
                value = self.parse_value()
                return ("cmp", field, "contains", value)
            if self.cur.kind == "op":
                op = self.advance().value
                if op == "=":
                    op = "=="
                value = self.parse_value()
                return ("cmp", field, op, value)
            # 形如 "port 80" 的简写：等价于 port == 80
            if self.cur.kind in ("number", "string", "ipv6"):
                value = self.parse_value()
                return ("cmp", field, "==", value)
            raise FilterSyntaxError(f"字段 {field!r} 后缺少运算符", self.expr, self.cur.pos)

        if tok.kind in ("number", "string"):
            # 允许 "80" 作为常量？无意义，给出明确错误
            raise FilterSyntaxError("表达式缺少字段名", self.expr, tok.pos)
        raise FilterSyntaxError(f"无法解析 {tok.value!r}", self.expr, tok.pos)

    def parse_value(self):
        tok = self.cur
        if tok.kind == "string":
            self.advance()
            raw = tok.value[1:-1]
            return bytes(raw, "utf-8").decode("unicode_escape")
        if tok.kind == "ipv6":
            self.advance()
            return tok.value
        if tok.kind == "number":
            self.advance()
            # 10.0.0.5 这类 IP 会被数字规则整体匹配，按字符串处理
            if tok.value.count(".") != 1 and "." in tok.value:
                return tok.value
            return float(tok.value) if "." in tok.value else int(tok.value)
        if tok.kind == "ident":
            self.advance()
            low = tok.value.lower()
            if low in ("true", "false"):
                return low == "true"
            return tok.value
        raise FilterSyntaxError("运算符后缺少比较值", self.expr, tok.pos)


# ------------------------------------------------------------------ 求值

_FIELD_ALIASES = {
    "tcp.port": "port",
    "udp.port": "port",
    "tcp.srcport": "srcport",
    "tcp.dstport": "dstport",
    "udp.srcport": "srcport",
    "udp.dstport": "dstport",
    "ip.proto": "proto",
    "frame.protocols": "proto",
    "http.request.method": "http.method",
    "http.request.uri": "http.uri",
    "http.host": "http.host",
    "dns.qry.name": "dns.qname",
}


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (list, tuple, set)):
        return " ".join(_as_text(v) for v in value)
    return str(value)


def _compare(left: Any, op: str, right: Any) -> bool:
    if left is None:
        return False

    # 集合字段（ip.addr / port / host 等）做“任一匹配”
    if isinstance(left, (list, tuple, set)) and op not in ("contains",):
        return any(_compare(v, op, right) for v in left)

    if op == "contains":
        hay = _as_text(left).lower()
        needle = _as_text(right).lower()
        return needle in hay

    if op == "matches":
        try:
            return re.search(_as_text(right), _as_text(left), re.IGNORECASE) is not None
        except re.error:
            return False

    # 数值比较
    if isinstance(right, (int, float)) and not isinstance(right, bool):
        try:
            lv = float(left)
        except (TypeError, ValueError):
            # 端口字段本身是数字；字符串字段不参与数值比较
            return False
        if op == "==":
            return lv == float(right)
        if op == "!=":
            return lv != float(right)
        if op == ">":
            return lv > float(right)
        if op == ">=":
            return lv >= float(right)
        if op == "<":
            return lv < float(right)
        if op == "<=":
            return lv <= float(right)
        return False

    if isinstance(right, bool):
        lv = bool(left)
        return lv == right if op in ("==", "=") else lv != right

    ls, rs = _as_text(left).lower(), _as_text(right).lower()
    if op in ("==", "="):
        return ls == rs
    if op == "!=":
        return ls != rs
    if op == ">":
        return ls > rs
    if op == "<":
        return ls < rs
    if op == ">=":
        return ls >= rs
    if op == "<=":
        return ls <= rs
    return False


def _flag_fields(record, field: str) -> Optional[int]:
    if field.startswith("tcp.flags."):
        flag = field.split(".", 2)[2].upper()
        if flag in ("SYN", "ACK", "FIN", "RST", "PSH", "URG"):
            return 1 if record.has_flag(flag) else 0
    return None


def evaluate(node, record) -> bool:
    kind = node[0]
    if kind == "const":
        return bool(node[1])
    if kind == "or":
        return evaluate(node[1], record) or evaluate(node[2], record)
    if kind == "and":
        return evaluate(node[1], record) and evaluate(node[2], record)
    if kind == "not":
        return not evaluate(node[1], record)
    if kind == "bool":
        field = _FIELD_ALIASES.get(node[1], node[1])
        flag = _flag_fields(record, field)
        if flag is not None:
            return bool(flag)
        fields = record.get_fields()
        if field not in fields:
            # 未知协议名：不匹配任何包（与 Wireshark 的 Unknown protocol 类似）
            return False
        value = fields[field]
        if isinstance(value, (list, tuple, set)):
            return any(bool(v) for v in value)
        return bool(value)
    if kind == "cmp":
        field = _FIELD_ALIASES.get(node[1], node[1])
        flag = _flag_fields(record, field)
        if flag is not None:
            return _compare(flag, node[2], node[3])
        fields = record.get_fields()
        if field not in fields:
            return False
        return _compare(fields[field], node[2], node[3])
    return False


class DisplayFilter:
    """编译后的显示过滤器；空表达式匹配全部。"""

    def __init__(self, expr: str = ""):
        self.expr = expr.strip()
        self.ast = Parser(self.expr).parse() if self.expr else ("const", True)

    def matches(self, record) -> bool:
        return evaluate(self.ast, record)

    @staticmethod
    def validate(expr: str) -> Optional[str]:
        """校验表达式；返回错误信息，合法则返回 None。"""
        try:
            Parser(expr).parse()
            return None
        except FilterSyntaxError as exc:
            return exc.pretty()
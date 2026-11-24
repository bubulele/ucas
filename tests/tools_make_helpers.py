# -*- coding: utf-8 -*-
"""测试辅助：构造一条带 SNI 的 TLS ClientHello（不依赖第三方库）。"""


def tls_hello_bytes(sni: str) -> bytes:
    name = sni.encode()
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    sni_list = len(entry).to_bytes(2, "big") + entry
    sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    body = (b"\x01" + b"\x00\x00\x00" + b"\x03\x03" + b"\x11" * 32 +
            b"\x00" + b"\x00\x04\x13\x01\x13\x02" + b"\x01\x00" +
            len(sni_ext).to_bytes(2, "big") + sni_ext)
    body = b"\x01" + len(body[1:]).to_bytes(3, "big") + body[4:]
    return b"\x16\x03\x01" + len(body).to_bytes(2, "big") + body

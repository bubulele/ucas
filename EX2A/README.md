# EX2A：栈溢出与 ROP 利用（Linux x86）

《软件与系统安全》实验 2A。本目录包含 6 类经典 ROP 利用的复现代码与 exp。

## 目录

- `src/`：6 个存在栈溢出漏洞的演示程序（gets 无边界拷贝）
- `exp/`：对应的 pwntools 利用脚本（ret2text / ret2shellcode / ret2libc1 / ret2libc3 / ret2reg 已验证）
- `docs/`：报告与截图（后续补充）

## 环境

- Ubuntu 22.04（32 位支持：`dpkg --add-architecture i386` + `gcc-multilib`）
- python3 + pwntools + ROPgadget + gdb
- 编译：`gcc -m32 -fno-stack-protector -no-pie -z noexecstack`（ret2shellcode 用 `-z execstack`）

## 题目与防护

| 程序 | 关键设置 | 要点 |
|---|---|---|
| ret2text | NX, 无 PIE/Canary | 程序内有 `system("/bin/sh")`，直接覆盖返回地址 |
| ret2shellcode | 栈可执行 | 关闭 ASLR 后把 shellcode 写到栈上并跳转 |
| ret2libc1 | NX, 无 PIE | `system@plt` + 程序内 `/bin/sh` |
| ret2libc2 | NX, 无 PIE | 程序内无 `/bin/sh`，用 `gets` 写入可写段再调 `system` |
| ret2libc3 | NX, 无 PIE | 无 `system`、无 `/bin/sh`；泄露 `puts@got` 算 libc 基址 |
| ret2syscall | 静态链接 | 无 `system`，用 `int 0x80` 调 `execve("/bin/sh")` |
| ret2reg | 栈可执行 | gets 返回后 eax 指向缓冲区，覆盖返回地址为 `call eax`（CTF-wiki 中级 ROP） |

## 运行

```bash
cd exp
python3 ret2text.py
```
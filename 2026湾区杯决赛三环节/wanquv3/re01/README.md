# re01 · Rust 静态 ELF 内嵌字节码 VM + 32 轮 ARX（小端寄存器初值是唯一坑）

| 项 | 值 |
|----|----|
| 轮次 | 环节三（17:00） |
| 平台题目名 | re01 |
| 比赛 qid | cRvMHaJuYM9lKdqI |
| 分类 | reverse |
| 分值 | 500 |
| 交互型 | false（静态附件） |
| 关键 flag | `flag{9bc396fd-75fb-484c-b193-f3ae596e6317}` |
| 是否解出 | 已解出（2026-09-14 17:17:58 平台返回 `code=0`「恭喜您，回答正确」） |
| **还原完整度** | **A**（原始二进制原样归档 + 可一键出 flag 的自包含脚本，且脚本自带 3 项自检、可从原 ELF 现场回抽 VM 程序与常量做交叉校验） |

## 1. 题面（比赛原文，逐字保留）

> Unlock the secrets

平台仅此一句，**无 `/hint`**，无附件说明，二进制内也没有任何提示性字符串（无 "flag"/"secret" 之类的引导语）。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | `re01.zip`（166,375 B）→ 内含 `main`（375,192 B） |
| 附件类型 | ELF64 x86-64 **动态链接 PIE**（`Type: DYN`），**Rust 编译**，**stripped**（无 `.symtab`），`.interp = /lib64/ld-linux-x86-64.so.2`，`NEEDED = libgcc_s.so.1, libc.so.6` |
| 容器 | 无（静态题，无 `connection`） |
| 附件存放 | `attachments/main` |
| 原始 file_url | `https://g.ichunqiu.com/terminator/production/match_question/202609/37feb6fb281a6397ef17b191b7d5b81d.zip` |
| md5 | `main` `06870cb9f9ab7ecab4721601ad6649c5` ｜ `re01.zip` `ad0a1e391411717f90915ebff15ea4cc` |
| 运行方式 | `printf '%s\n' <flag> \| ./main` → 相等打印 `yes`，否则 `no` |

> ⚠️ 本 ELF 的 `PT_LOAD` 段满足 **文件偏移 == 虚拟地址**（`.text 0x5050/0x5050`、`.rodata 0x49000/0x49000` 等），
> 因此下文给出的地址**既是 RVA 也是文件偏移**，可直接 `f.seek(addr)` 读取。

### 关键地址表（本次实测确认，供复现）

| 地址 | 内容 |
|------|------|
| `0x7950` | `_start` |
| `0x9db0` | `main`（Rust std 包装；`0x4ae00` 处是 `main.rs` 的 panic location 字符串） |
| `0x8c50` / `0x8c56` | `mov edi,0x40` / `mov esi,1` → `calloc(0x40, 1)`，**16 个 dword 寄存器堆**（`0x8c60` 调用点） |
| `0x8c8c`–`0x8ce8` | 从输入缓冲把**前 8 字节按小端拼成 2 个 dword** 填入 `r[0]`、`r[1]` |
| `0x8cee` | `movaps xmm0, XMMWORD PTR [rip+0x4031b]` → 源 = **`0x49010`** |
| `0x8cf5` | `movups [r13+0x8], xmm0` → 一次写入 `r[2..5]` |
| `0x8cfa` | `movabs rax, 0xdf0adbacefaedfe` |
| `0x8d04` | `mov [r13+0x18], rax` → 写入 `r[6]`、`r[7]` |
| `0x8d1d` | **VM 分派器**：`movzx eax,[rdi+r12]; dec eax; cmp eax,0xd; ja 0x92c0; movsxd rax,[rbp+rax*4]; add rax,rbp; jmp rax` |
| `0x8d10` | `cmp rdi,0x1101` → **VM 程序长度边界** |
| `0x8d35` | 分派器取跳表的基准点（表项相对自身寻址） |
| `0x92d0`–`0x9402` | VM 跑完后把 16 个 dword 寄存器**小端**逐个压入输出 `Vec<u8>`（4 B/寄存器，共 64 B） |
| `0x941c` | `xor r12d,r12d` … `cmp r12,0x30` @ **`0x943d`**（已收集字节数 == 48 ?） |
| `0x9443` | `lea rsi,[rip+0x42abe]` → **`0x4bf08`**（硬编码目标常量） |
| `0x944a` | `mov edx,0x30`（长度 48） |
| `0x944f` | `mov rdi,r14`（用户输入缓冲） |
| `0x9452` | `call QWORD PTR [rip+0x52af0]` → GOT **`0x5bf48`**，该槽位解析为 **`bcmp`**（不是 `memcmp`！） |
| `0x945a` | `je 0x950c` → 相等分支 |
| `0x950c` | 打印 **`yes\n`** |
| `0x9460` | 打印 **`no\n`** |
| `0x4ae07` | **内嵌字节码 VM 程序**，长度 **`0x1101`** = 4353 B |
| `0x4bf08` | **硬编码目标常量**，长度 `0x30` = 48 B |
| `0x4bf38` / `0x4bf3b` | `"no\n"` / `"yes\n"` |
| `0x49010` | 寄存器初值常量（16 B `movaps` 源） |
| `0x492b0` | opcode 跳表（14 项 `int32`，基址 = 表项自身地址）：`1→0x8d37 2→0x90ce 3→0x8f88 4→0x8fca 5→0x8e3e 6→0x912a 7→0x9223 8→0x9060 9→0x9277 10→0x8f42 11→0x8d34 12→0x8de9 13→0x8ee4 14→0x9196` |

寄存器初值（`0x49010` 的 16 字节 + 紧随的 `movabs`）：

```
0x49010: 00 00 00 00 | aa aa aa aa | 13 37 c0 de | de ad be ef
0x8cfa:  movabs rax, 0xdf0adbacefaedfe
```

| reg | 原始字节 | **小端 dword 解释（唯一正确）** |
|-----|----------|-------------------------------|
| `r2` | `00 00 00 00` | `0x00000000` |
| `r3` | `aa aa aa aa` | `0xaaaaaaaa` |
| `r4` | `13 37 c0 de` | **`0xdec03713`** |
| `r5` | `de ad be ef` | **`0xefbeadde`** |
| `r6` | `fe ed fa ce`（movabs 低 dword） | **`0xcefaedfe`** |
| `r7` | `ba ad f0 0d`（movabs 高 dword） | **`0x0df0adba`** |

## 3. 考点（★核心）

- **考点 1：stripped Rust 静态 ELF 中的自定义字节码 VM 识别。** 二进制无符号、无 `main` 名字、
  体量 375 KB 全是 Rust std。要从**分派器特征**入手：`movzx eax,[prog+pc]` + `dec eax` +
  `cmp eax,0xd` + `ja` + `movsxd rax,[rbp+rax*4]` + `add rax,rbp` + `jmp rax`（`0x8d1d`）
  是典型的 **computed-goto 跳表解释器**；跳表在 `.rodata 0x492b0`，14 个 `int32` 相对偏移
  直接给出 14 个 handler 地址。**能定位分派器 + 跳表 = 能用脚本把整个 ISA 反出来。**
- **考点 2：VM ISA 的逆向与长度自洽。** 14 个 opcode（`movimm/mov/addrr/addimm/subimm/xorrr/
  xorimm/shlimm/shrimm/nop/shlrr/shrre/andimm`），长度 1/3/4/6/7 字节不定，必须**按长度递推**
  才能把 4353 字节切成 1121 条指令；`cmp rdi,0x1101`（`0x8d10`）是长度边界、
  `cmp rax,0x10`（各 handler 内）是寄存器索引边界 —— 两个边界一起定义了"程序合法"。
- **考点 3：从 1121 条指令里认出 32 轮 ARX（Speck / Threefish 风格）。** 程序由 **64 个块** 组成，
  顺序严格 **ABAB…AB**（实测 32 A + 32 B），每块只改一个寄存器：
  - **A 块**：`r2 += 0xaaaaaaaa`（轮常量递推）→ 更新 **`r0`**：`r0 += mix(r1, r2, A 参数)`
  - **B 块**：更新 **`r1`**：`r1 += mix(r0, r2, B 参数)`
  混洗函数（从指令序列直读）：
  ```
  mix(x, r2, sa, ca, sc, cc)
      = ((x << sa) + ca) ^ (x + r2) ^ ((x >> sc) + cc) ^ (ca + cc)   (mod 2^32)
  ```
  A 轮参数 `sa=r5&31=30, ca=r4=0xdec03713, sc=r4&31=19, cc=r5=0xefbeadde`；
  B 轮参数 `sa=r7&31=26, ca=r6=0xcefaedfe, sc=r6&31=30, cc=r7=0x0df0adba`
  —— **A/B 参数刻意不对称**（不同移位量、不同加常量），避免结构自相似。
  识别出这是 **modular-addition Feistel** 是关键：只有加法被用来把混洗结果并入状态。
- **考点 4（★★ 唯一真正的坑）：寄存器初值必须按小端 dword 解释。**
  `0x49010` 的字节是 `13 37 c0 de` / `de ad be ef`，`movabs` 是 `0xdf0adbacefaedfe`。
  它们是出题人照着 **`1337c0de` `deadbeef` `fe ed fa ce` `ba ad f0 0d` 这些"好看"的字节串**
  敲进去的，在 32 位寄存器堆里**按小端解释**才是
  `r4 = 0xdec03713`、`r5 = 0xefbeadde`、`r6 = 0xcefaedfe`、`r7 = 0x0df0adba`。
  把它们当成"大端/字面 dword 常量"（`r4 = 0x1337c0de` 等）是**最自然的误读**，
  反演出的 6 个 block 会**全部是乱码**，而且**不会报错**（加法与 XOR 都是双射，任何输入都对应唯一输出）
  —— 这是纯粹的**静默失败**型陷阱。本脚本把这条写成了断言：
  ```
  .rodata@0x49010 十六进制 = 00000000aaaaaaaa1337c0dedeadbeef
    -> 小端 dword 解释: r2=0x00000000 r3=0xaaaaaaaa r4=0xdec03713 r5=0xefbeadde
  ```
- **考点 5：用"加法可逆"逐半轮回退完成反演（不用求解器）。** 每个块对状态的一半做
  `rX += mix(other, r2, …)`，`other` 在该块执行前后不变 ⇒ 从最后一轮往前做减法即可精确回退。
  反向遍历时必须**按块类型选用"当时的 r2"**：r2 序列只由 A 块出现次数决定，与输入无关，
  因此可**正向预计算** `r2_k = (k * 0xaaaaaaaa) mod 2^32, k = 1..32`。
  另一条可行路线是 **z3 符号执行**（比赛中用过，脚本 `vmrun.py`），但可逆性让反演更短更快。
- **考点 6：输入长度/填充与 `bcmp` 语义。** 目标常量 48 字节，但明文只有 42 字节有效
  （`flag{` + UUID36 + `}`），后 6 字节是 `\x00` —— 说明 Rust 侧把 stdin 读到 48 字节并零填充；
  另外 `0x9452` 调的是 **`bcmp`**（GOT `0x5bf48`），与 `memcmp` 行为一致但名字不同，
  按名字找 `memcmp` 会漏掉比较点。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出（本题的"含金量"来源）：**
  出题人要在 **Rust 静态 ELF** 这个"天然反编译困难"的载体上，构造一道**既不是纯密码题、也不是
  纯逆向题**的混合题。手法是**把密码学算法下沉到一个自研字节码 VM 里**，于是选手必须打通三层：
  1. **载体层**：从 375 KB stripped Rust 二进制里找到 VM（分派器 + 跳表 + 寄存器堆 + 程序段 + 常量段）；
  2. **ISA 层**：把 14 个 opcode 的语义与指令长度反全，把 4353 字节字节码翻成 1121 条伪汇编；
  3. **算法层**：在 64 个块的伪汇编里认出 ARX 结构，写出 `mix()`，判断出这是可逆的 modular-addition
     Feistel，然后反演。
  **任何一层断了都出不来 flag**，而且三层的"正确性"互不重叠 —— 这是它比环节二两道 RE 更有含金量的原因。
- **难度卡点设计在哪：**
  - **卡点 A（最狠）：小端寄存器初值。** `13 37 c0 de` 这种东西在反汇编里看起来就像"谜题作者留的
    leet 彩蛋"，几乎所有人第一反应是 `0x1337c0de`。但因为寄存器堆是 `calloc(0x40)` 的 **dword 数组**、
    常量由 `movaps`/`movabs` 按内存字节写入，**只有小端解释才和 VM 实际行为一致**。
    这个卡点最恶劣的地方是：**错了也能算出一串 42 字节的"可打印字符串"**（因为整个过程是双射），
    选手会觉得"快对了"而反复微调 mix() 公式，实际根因在初值口径上。
  - **卡点 B：`mix()` 的精确形状。** 指令序列是
    `(x<<sa)+ca` → `^(x+r2)` → `^((x>>sc)+cc)` → `^(ca+cc)`，寄存器复用很多
    （`r8` 反复被 `xor`、`r14` 是 `ca+cc` 的临时值），且**两个变量移位都用 `andimm …,31` 单独取模**。
    漏掉任何一项（尤其最后的 `^(ca+cc)`，它看起来像是冗余的常量折叠）都会全错。
    注意 `sa = r5 & 31`、`sc = r4 & 31` —— **移位量本身也是从寄存器派生的**，不是立即数。
  - **卡点 C：轮常量的"每个 A 块 +0xaaaaaaaa"递推。** `addimm r2, 0xaaaaaaaa` 只出现在 A 块开头
    （共 32 次），B 块不碰 `r2`。反演时必须按"块 i 时刻的 r2"取值；把 r2 当成固定常量、
    或按 64 次递增，都会全错。
  - **卡点 D：`cmp r12,0x30` 与 64 B → 48 B 的截断。** VM 输出 16×4 = 64 字节，但只比较前 48 字节
    （`0x943d` + `edx=0x30`）。第 5 个 8 字节块反演出的 `7}\x00\x00\x00\x00\x00\x00` 只有前 2 字节有意义 ——
    不做这个截断判断的人会以为"最后一块解错了"。
- **干扰项 / 诱导项：**
  1. **`0x1337c0de` / `deadbeef` / `0xfeedface` / `0xbaadf00d` 四个"梗数"** —— 最大的干扰项。
     它们读起来像彩蛋，实际是**小端字节串**，误读即全盘皆错（见卡点 A）。
  2. **`0x0df0adba`** —— 它是 `ba ad f0 0d` 的小端解释，但**不是**标准的 `baadf00d`
     （标准梗数是 `baadf00d`，这里是 `ba ad f0 0d`，反过来读是 `0df0adba`）。
     这处细节进一步加强"必须按内存字节思考"的要求。
  3. **`bcmp` 而不是 `memcmp`（GOT `0x5bf48`）** —— 按关键字找 `memcmp` 会漏掉真正的比较点。
  4. **`0x8d34`（opcode 11 = `nop`）的 handler 只有 1 字节**，且 65 条 `nop` 散布在程序里
     —— 制造"指令边界很乱"的假象（实际是出题人故意插的 filler，让按长度递推更有必要）。
  5. **Rust `main.rs` panic location 字符串（`0x4ae00`）** 紧贴 VM 程序起始地址 `0x4ae07` 之前，
     容易把 `main.rs` 附近的字符串当成 VM 程序的一部分（少算 7 字节就全错）。
  6. **`movabs` 把两个 dword 一次写进 `[r13+0x18]`（`r6` 与 `r7`）** —— 单看反汇编只会看到
     "写了一个 64 位常量到某个偏移"，不清楚它其实同时定了两个寄存器。
- **哪些地方是"必须踩坑才会发现"的：**
  - 必须**真的把 `0x49010` 的 16 字节 dump 出来**（而不是读 `movaps` 的立即数）才能发现它是
    `00…aa…1337c0de…deadbeef` 这样的**字节流**，从而意识到小端问题。只看反汇编助记符永远看不出。
  - 必须**按地址精确切 `0x4ae07 + 0x1101`** 才能拿到完整的 4353 字节程序（少 1 字节就 `bad opcode`）。
  - 必须**注意到 VM 输出 64 字节但只比 48 字节**，才能解释最后一块的 `\x00` 尾巴。
  - 必须**判断出 `mix()` 用到的所有移位量都来自寄存器**，才能把 A/B 两套参数都算对。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察（定性）**
   ```bash
   file main
   # ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
   readelf -h main | grep -E "Type|Entry"       # DYN / 0x7950
   readelf -S main | head -30                   # .text 0x5050 / .rodata 0x49000（off==vaddr）
   strings -a main | less                       # Rust std 噪音；无任何 flag 提示
   ```
   ⇒ 拿到的是一个 **stripped Rust 静态 ELF**，必须靠行为特征定位。

2. **用 hook 观察行为（比赛期的捷径，可选）**
   ```c
   /* hook.c：LD_PRELOAD 覆盖 memcmp/bcmp/read/strcmp，把长度 4..4096 的
      memcmp/bcmp 两个参数 hexdump 出来 —— 直接看到 48 字节目标常量与比较结果 */
   gcc -shared -fPIC -o hook.so hook.c -ldl
   LD_PRELOAD=./hook.so ./main < /dev/null
   ```
   ⇒ 立刻确认"输入 → 变换 → 与 48 字节常量 bcmp"，并**免费拿到目标常量**。
   （`hook2.c` 更进一步：hook `calloc(0x40,1)` 与 `free()`，在 free 时把那 16 个 dword
   寄存器堆打出来 —— 这是**看清寄存器初值与小端问题的最快办法**。）

3. **定位 VM 分派器与跳表**
   ```bash
   objdump -d -M intel main > dis.txt
   # 找 computed-goto 特征
   grep -n "movsxd rax,DWORD PTR \[rbp+rax\*4" dis.txt
   #   8d2d: 48 63 44 85 00   movsxd rax,DWORD PTR [rbp+rax*4+0x0]
   #   8d32: 48 01 e8         add    rax,rbp
   #   8d35: ff e0            jmp    rax
   objdump -d -M intel --start-address=0x8d1d --stop-address=0x8d40 main
   ```
   ```
   8d1d: 42 0f b6 04 27   movzx eax,BYTE PTR [rdi+r12*1]   ; opcode = prog[pc]
   8d22: ff c8            dec   eax
   8d24: 83 f8 0d         cmp   eax,0xd
   8d27: 0f 87 93 05 00 00 ja    92c0                       ; 越界 -> 程序结束
   8d2d: 48 63 44 85 00   movsxd rax,DWORD PTR [rbp+rax*4+0x0]
   8d32: 48 01 e8         add   rax,rbp
   8d35: ff e0            jmp   rax
   ```
   跳表在 `.rodata 0x492b0`，14 项 `int32` 相对偏移（基址 = 表项地址）→ 14 个 handler：

   | op | handler | 语义 | 长度 |
   |----|---------|------|------|
   | 1 | `0x8d37` | `movimm r[a], imm32` | 6 |
   | 2 | `0x90ce` | `mov r[a], r[b]` | 3 |
   | 3 | `0x8f88` | `addrr r[a] += r[b]` | 3 |
   | 4 | `0x8fca` | `addimm r[a] += imm32` | 6 |
   | 5 | `0x8e3e` | `subimm r[a] -= imm32` | 6 |
   | 6 | `0x912a` | `addrr r[a] += r[b]`（与 op3 等价） | 3 |
   | 7 | `0x9223` | `xorrr r[a] ^= r[b]` | 3 |
   | 8 | `0x9060` | `xorimm r[a] ^= imm32` | 6 |
   | 9 | `0x9277` | `shlimm r[a] = r[b] << r[c]` | 4 |
   | 10 | `0x8f42` | `shrimm r[a] = r[b] >> r[c]`（逻辑） | 4 |
   | 11 | `0x8d34` | `nop` | 1 |
   | 12 | `0x8de9` | `shlrr r[a] = r[b] << (r[c]&31)` | 4 |
   | 13 | `0x8ee4` | `shrre r[a] = r[b] >> (r[c]&31)`（逻辑） | 4 |
   | 14 | `0x9196` | `andimm r[a] = r[b] & imm32` | 7 |

4. **切出 VM 程序与目标常量**（`off == vaddr`）
   ```python
   d = open("main","rb").read()
   PROG   = d[0x4AE07:0x4AE07+0x1101]   # 4353 B 字节码
   TARGET = d[0x4BF08:0x4BF08+0x30]     # 48 B
   # TARGET = 2c644803b15515d2e1d83f2a374213e6bcc74ac6f5f2bf6482717b20f94894fe
   #          645052a09a11c83e6b7dc6d51b91e4ee
   ```
   实测 `md5(PROG) = 3bc0d26a85b45469ad7660faa2eb5d16`（与比赛期 `work\r3_re01\vmprog.bin` 逐字节相同）。

5. **反汇编字节码 → 1121 条伪汇编**，统计出：
   ```
   movimm 0 / mov 128 / addrr 320 / addimm 96 / subimm 0 / xorrr 192 / xorimm 64
   shlimm+shrimm 0 / nop 65 / shlrr 64 / shrre 64 / andimm 128     → 共 1121 条
   ```
   （`movimm` 与 `subimm` 计数为 0 —— 说明**所有常量都通过 addimm/xorimm 施加**，
   这是"想让静态分析更难"的刻意选择。）

6. **认出 A/B 块结构**
   ```
   A 块前 17 条（程序偏移 0x0000 起）：
     0000: addimm r2, +0xaaaaaaaa        ; 轮常量递推（只在 A 块出现，32 次）
     0006: andimm r11, r5, 31            ; sa = r5 & 31 = 30
     000d: shlrr  r8,  r1, r11           ; t = r1 << sa
     0011: addrr  r8,  r4                ; t += ca
     0014: mov    r9,  r1
     0017: addrr  r9,  r2                ; r9 = r1 + r2
     001a: andimm r12, r4, 31            ; sc = r4 & 31 = 19
     0021: shrre  r10, r1, r12           ; t2 = r1 >> sc
     0025: addrr  r10, r5                ; t2 += cc
     0028: xorrr  r8,  r9
     002b: xorrr  r8,  r10
     002e: mov    r14, r4
     0031: addrr  r14, r5                ; r14 = ca + cc
     0034: xorrr  r8,  r14
     0037: addrr  r0,  r8                ; ★ 唯一修改 r0
   ```
   块序列提取（扫 `addrr r0,r8` / `addrr r1,r8`）实测：
   ```
   SEQ = 64 块, A=32, B=32
   模式 = ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB
   ```

7. **寄存器初值（★ 本题的分水岭）**
   ```bash
   objdump -d -M intel --start-address=0x8cee --stop-address=0x8d08 main
   # 8cee: 0f 28 05 1b 03 04 00   movaps xmm0,XMMWORD PTR [rip+0x4031b]  # 49010
   # 8cf5: 41 0f 11 45 08         movups XMMWORD PTR [r13+0x8],xmm0
   # 8cfa: 48 b8 fe ed fa ce ba ad f0 0d   movabs rax,0xdf0adbacefaedfe
   # 8d04: 49 89 45 18            mov    QWORD PTR [r13+0x18],rax
   ```
   `0x49010` 的 16 字节 = `00 00 00 00 aa aa aa aa 13 37 c0 de de ad be ef`
   ⇒ 按 **小端 dword** 解释：`r2=0, r3=0xaaaaaaaa, r4=0xdec03713, r5=0xefbeadde`；
   `movabs` 的低/高 dword：`r6=0xcefaedfe, r7=0x0df0adba`。
   **反例（必错）**：把 `0x1337c0de` / `0xdeadbeef` 直接当 r4/r5。

8. **写 `mix()` + 反演**
   ```python
   M32 = 0xffffffff
   def mix(x, r2, sa, ca, sc, cc):
       t  = (((x << sa) & M32) + ca) & M32
       t ^= (x + r2) & M32
       t ^= ((((x & M32) >> sc) + cc) & M32)
       t &= M32
       t ^= (ca + cc) & M32
       return t & M32

   SA_A, CA_A, SC_A, CC_A = R5 & 31, R4, R4 & 31, R5      # 30, 0xdec03713, 19, 0xefbeadde
   SA_B, CA_B, SC_B, CC_B = R7 & 31, R6, R6 & 31, R7      # 26, 0xcefaedfe, 30, 0x0df0adba

   def invert(t0, t1, seq, r2s):
       r0, r1 = t0, t1
       for blk, r2 in zip(reversed(seq), reversed(r2s)):
           if blk == "B":
               r1 = (r1 - mix(r0, r2, SA_B, CA_B, SC_B, CC_B)) & M32
           else:
               r0 = (r0 - mix(r1, r2, SA_A, CA_A, SC_A, CC_A)) & M32
       return r0, r1
   ```

9. **取 flag**
   ```python
   for i in range(6):
       t0, t1 = struct.unpack_from("<II", TARGET, i*8)
       p0, p1 = invert(t0, t1, SEQ, R2S)
       print(struct.pack("<II", p0, p1))
   ```
   ```
   b'flag{9bc'  b'396fd-75'  b'fb-484c-'  b'b193-f3a'  b'e596e631'  b'7}\x00\x00\x00\x00\x00\x00'
   ```
   ⇒ `flag{9bc396fd-75fb-484c-b193-f3ae596e6317}`

10. **实机验证（已实测，见 §8；Windows 需借 Docker 的 glibc 镜像）**
    ```bash
    # 本机 Windows 跑不了该 ELF；用本机 Docker 的 Debian 系镜像（glibc ≥ 2.34）
    docker run --rm -v "<main 所在目录>:/w" -w /w python:3.11-slim bash -c '
      chmod +x ./main
      printf "flag{9bc396fd-75fb-484c-b193-f3ae596e6317}\n" | ./main   # -> yes
      printf "flag{00000000-0000-0000-0000-000000000000}\n" | ./main   # -> no
      printf "flag{9bc396fd-75fb-484c-b193-f3ae596e6318}\n" | ./main   # -> no（末位改 1 字符）
      printf "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" | ./main   # -> no（50B 全 A）
    '
    ```
    ⚠️ **不要用 `ubuntu:20.04`**（glibc 2.31，报 `GLIBC_2.33/2.32/2.34 not found`）。

## 6. 参考解法（代码）

完整自包含脚本：`solve/solve.py`（纯 Python 标准库；**内嵌 VM 程序 + 目标常量**，无需原二进制即可出 flag；
`--bin` 会从原 ELF 现场回抽并断言一致）。

核心片段：

```python
M32 = 0xFFFFFFFF
R4, R5 = 0xDEC03713, 0xEFBEADDE          # ★ 小端！不是 0x1337c0de / 0xdeadbeef
R6, R7 = 0xCEFAEDFE, 0x0DF0ADBA          # ★ 小端！来自 movabs 0xdf0adbacefaedfe
R2STEP = 0xAAAAAAAA
SA_A, CA_A, SC_A, CC_A = R5 & 31, R4, R4 & 31, R5
SA_B, CA_B, SC_B, CC_B = R7 & 31, R6, R6 & 31, R7

def mix(x, r2, sa, ca, sc, cc):
    t = (((x << sa) & M32) + ca) & M32
    t ^= (x + r2) & M32
    t ^= (((x & M32) >> sc) + cc) & M32
    t &= M32
    t ^= (ca + cc) & M32
    return t & M32

def forward(r0, r1, seq, r2s):
    for blk, r2 in zip(seq, r2s):
        if blk == "A": r0 = (r0 + mix(r1, r2, SA_A, CA_A, SC_A, CC_A)) & M32
        else:          r1 = (r1 + mix(r0, r2, SA_B, CA_B, SC_B, CC_B)) & M32
    return r0, r1

def invert(t0, t1, seq, r2s):
    r0, r1 = t0, t1
    for blk, r2 in zip(reversed(seq), reversed(r2s)):
        if blk == "B": r1 = (r1 - mix(r0, r2, SA_B, CA_B, SC_B, CC_B)) & M32
        else:          r0 = (r0 - mix(r1, r2, SA_A, CA_A, SC_A, CC_A)) & M32
    return r0, r1

out = b"".join(struct.pack("<II", *invert(*struct.unpack_from("<II", TARGET, i*8), SEQ, R2S))
               for i in range(6))
flag = out.split(b"\x00")[0]      # b'flag{9bc396fd-75fb-484c-b193-f3ae596e6317}'
```

脚本内置 **3 项自检**（任一失败即非零退出）：

| 自检 | 内容 | 期望 |
|------|------|------|
| 1 | `forward(0x41414141, 0x41414141)`（输入 `b"AAAAAAAA"`） | `4d513cab 35d5dece` |
| 2 | `invert(forward(x)) == x` 往返 | `41414141 41414141` |
| 3 | 把反演出的 48 字节明文重新**正演**，逐字节等于硬编码目标常量 | 完全相等 |

辅助参数：`--dump-vm vmprog.bin`（导出内部 VM 程序）、`--dump-disasm vm.txt`（导出 1121 条伪汇编）。

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{9bc396fd-75fb-484c-b193-f3ae596e6317}` |
| 提交接口返回 | `{"code": 0, "status": null, "message": "恭喜您，回答正确", "pass": true}` |
| 提交时间 | 2026-09-14 17:17:58 |
| 证据文件 | `D:\2026\湾区杯\决赛\work\submit_results_live.json` 中 `qid=cRvMHaJuYM9lKdqI` 记录 |
| 交叉证据 | `D:\2026\湾区杯\决赛\赛道二测试记录.md` §〇.3 表格（环节三 6/10 题，3000 分）｜ `D:\2026\湾区杯\决赛\work\flags\cRvMHaJuYM9lKdqI.txt` |
| **实机闭环验证** | `docker run --rm -v …:/w -w /w python:3.11-slim bash -c "printf 'flag{…}\n' \| ./main"` → **`yes`**；全 0 UUID / 50 字节全 `A` / 末位改 1 字符 → 均 `no`（详见 §8） |

> 注：`challenges_r3.json` 快照中 `is_solved=false`（快照时间早于提交）；以平台提交回执 `code=0 / pass=true` 为准。

## 8. 还原说明（诚实写）

- **已有原始件（事实）：**
  - `attachments/main` —— 平台原始附件内文件，**字节未改动**，md5 `06870cb9f9ab7ecab4721601ad6649c5`
    （与 `work\r3\cRvMHaJuYM9lKdqI\main`、`work\r3_re01\re01.zip` 内文件均逐字节相同）。
  - VM 程序（`0x4ae07`, `0x1101` B）、目标常量（`0x4bf08`, `0x30` B）、寄存器初值表（`0x49010`, 16 B）
    全部**从该 ELF 现场抽取并实测确认**；`solve.py` 内嵌副本已在运行时与原 ELF 断言一致。
  - flag 为**平台确认值**。
- **重建部分：** 无。原 ELF 完整拿到，**不需要重建二进制或源码**。
  出题人的原始 Rust 源码 / 字节码汇编源未拿到（无可信来源），因此本目录**不提供伪造的
  `deploy/src/*.rs`**；ISA 与 VM 程序语义以 §3/§5 的实测反汇编为准。
- **未能还原：** 无。
- **§5 第 10 步的实机 yes/no 闭环：已实测通过（含三重反向对照）。**
  本机 Windows 无法直接跑该 ELF（需要 glibc），但**本机 Docker 可用**且已有 `python:3.11-slim`
  （Debian 13 / **glibc 2.41**），据此完成了端到端实机执行：

  ```bash
  docker run --rm -v "D:\2026\湾区杯\决赛\work\r3_re01:/w" -w /w python:3.11-slim \
    bash -c "ldd ./main; ldd --version | head -1; printf '<INPUT>\n' | ./main"
  ```
  实测 `ldd` 输出（依赖全部正常解析，无 GLIBC 版本告警）：
  ```
  libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1
  libc.so.6     => /lib/x86_64-linux-gnu/libc.so.6
  /lib64/ld-linux-x86-64.so.2
  ldd (Debian GLIBC 2.41-12+deb13u4) 2.41
  ```
  四行输入 → 输出对照（**正向 + 三重反向**）：

  | 输入 | 实机输出 | 说明 |
  |------|----------|------|
  | `flag{9bc396fd-75fb-484c-b193-f3ae596e6317}` | **`yes`** | ★ 正确 flag |
  | `flag{00000000-0000-0000-0000-000000000000}` | `no` | 反向对照（UUID 全 0） |
  | 50 字节全 `A` | `no` | 反向对照（排除"长度对就 yes"） |
  | 正确 flag 改最后 1 个字符（`…6318`） | `no` | ★ 反向对照（排除误报） |

  ⇒ 与 §6 的三项脚本自检、以及"反演明文重新正演 == 硬编码目标常量"互相独立且结论一致，
  **本题的解题链已在真实二进制上闭环**。
- **环境选型坑（已实测，务必照抄镜像）：**
  - **`ubuntu:20.04` 跑不了**：其 glibc 为 **2.31**，实测报
    ```
    ./main: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by ./main)
    ./main: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by ./main)
    ./main: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./main)
    ```
    → 该二进制在**较新发行版**上编译（要求 ≥ glibc 2.34），故 `deploy/Dockerfile` **不使用 `ubuntu:20.04`**。
  - **推荐 `python:3.11-slim`**（本次实测可用，glibc 2.41）或 `debian:bookworm-slim`（glibc 2.36，满足 ≥2.34）。
  - **通用判据**：拿到未知 ELF 先 `docker run --rm <img> ldd --version | head -1` 看 glibc 版本，再决定镜像。
  - 另注：本机 WSL 只有 `docker-desktop` 发行版（musl），**不能**用来跑该 ELF
    （实测 `Error loading shared library libgcc_s.so.1`）—— 必须走 Docker 的 glibc 镜像。
- **可复现性验证（已实测，本机 Windows / Python 3.13）：**
  ```bash
  cd timu/round3_1700/re01
  python solve/solve.py --bin attachments/main
  ```
  实测输出（退出码 0）：
  ```
  [*] VM 程序长度 = 0x1101 (4353 B)
  [*] VM 程序 md5 = 3bc0d26a85b45469ad7660faa2eb5d16
  [*] 目标常量(48 B) = 2c644803b15515d2e1d83f2a374213e6bcc74ac6f5f2bf6482717b20f94894fe645052a09a11c83e6b7dc6d51b91e4ee
  [+] 交叉校验通过：@0x4ae07 VM 程序 (0x1101 B) 与 @0x4bf08 目标常量 (0x30 B) 均一致
  [*] .rodata@0x49010 十六进制 = 00000000aaaaaaaa1337c0dedeadbeef
  [*]   -> 小端 dword 解释: r2=0x00000000 r3=0xaaaaaaaa r4=0xdec03713 r5=0xefbeadde
  [*]   -> movabs 0x0df0adbacefaedfe 拆分: r6=0xcefaedfe r7=0x0df0adba
  [+] 寄存器初值口径核对通过（★ 必须是**小端 dword**：r4=0xdec03713 而不是 0x1337c0de）
  [*] 块序列: 64 块  A=32  B=32
  [*] 序列模式: ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB
  [*] A 轮参数: sa=r5&31=30  ca=r4=0xdec03713  sc=r4&31=19  cc=r5=0xefbeadde
  [*] B 轮参数: sa=r7&31=26  ca=r6=0xcefaedfe  sc=r6&31=30  cc=r7=0x0df0adba
  [*] 自检 forward(A*8) = 4d513cab 35d5dece (期望 4d513cab 35d5dece) -> OK
  [*] 自检 invert(forward(x)) = 41414141 41414141 -> OK
  [*] block 0: 66 6c 61 67 7b 39 62 63 | b'flag{9bc'
  ...
  [*] 完整 48 字节 = b'flag{9bc396fd-75fb-484c-b193-f3ae596e6317}\x00\x00\x00\x00\x00\x00'
  [+] flag = flag{9bc396fd-75fb-484c-b193-f3ae596e6317}
  [*] 自检 重加密(forward) == 目标常量 -> OK
  [+] 与比赛期确认 flag 一致 -> PASS
  ```
  **为什么这条链足够强：** 自检 3 是"**用本脚本的正向实现重算 48 字节，与二进制里硬编码的
  48 字节常量逐字节相等**"—— 即脚本的正演与 ELF 的 VM 在目标点上**完全一致**；
  再叠加 block 5 的多余字节恰为 `\x00`（与 `cmp r12,0x30` 的截断一致）、
  以及比赛期参考实现 `work\r3_re01\vmrun.py` 用独立写的**具体执行器**得到同一 trace
  （`A*8 -> ab3c514d ceded535`，小端即本脚本的 `4d513cab 35d5dece`），三重独立证据闭合。

## 9. 复现步骤

```bash
cd timu/round3_1700/re01

# 方式一（推荐）：内嵌 VM 求解 + 从原 ELF 交叉校验（含 3 项自检）
python solve/solve.py --bin attachments/main

# 方式二：只求 flag（不需要原二进制 / 不需要 objdump）
python solve/solve.py

# 方式三：把内部 VM 程序与反汇编 dump 出来，人工比对
python solve/solve.py --dump-vm vmprog.bin --dump-disasm vm.txt
head -30 vm.txt

# 方式四：静态复核关键地址（本 ELF off == vaddr）
readelf -h attachments/main | grep -E "Type|Entry"        # DYN / 0x7950
objdump -d -M intel --start-address=0x8d1d --stop-address=0x8d40 attachments/main   # VM 分派器
objdump -d -M intel --start-address=0x8cee --stop-address=0x8d08 attachments/main   # 寄存器初值
objdump -s -j .rodata --start-address=0x49000 --stop-address=0x49020 attachments/main
objdump -d -M intel --start-address=0x943d --stop-address=0x9460 attachments/main   # cmp 0x30 / bcmp

# 方式五（★ 实机闭环，已实测）：借 Docker 的 glibc 镜像喂输入看 yes/no
docker run --rm -v "$PWD/attachments:/w:ro" -w /w python:3.11-slim bash -c '
  chmod +x ./main
  printf "flag{9bc396fd-75fb-484c-b193-f3ae596e6317}\n" | ./main   # -> yes
  printf "flag{9bc396fd-75fb-484c-b193-f3ae596e6318}\n" | ./main   # -> no
'
# ⚠️ 必须用 glibc ≥ 2.34 的镜像：python:3.11-slim (2.41) / debian:bookworm-slim (2.36)
#    ubuntu:20.04 (glibc 2.31) 会报 GLIBC_2.33/2.32/2.34 not found
```

容器题部署（**原题不是容器题**，`deploy/` 为可选包装，让本题可用统一 `nc host port` 形式演练；
基础镜像已按实测改为 `python:3.11-slim`，`docker build` 一次即可跑通）：

```bash
docker build -t timu/r3-re01:local deploy/
docker run -d --rm -p 9999:9999 -v "$PWD/attachments:/opt/re01:ro" timu/r3-re01:local
printf 'flag{9bc396fd-75fb-484c-b193-f3ae596e6317}\n' | nc 127.0.0.1 9999    # -> yes
printf 'flag{9bc396fd-75fb-484c-b193-f3ae596e6318}\n' | nc 127.0.0.1 9999    # -> no
```

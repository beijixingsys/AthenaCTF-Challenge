# re01 · ELF64 未剥离符号的 RC4 校验器（结果算完即弃，只能静态复现）

| 项 | 值 |
|----|----|
| 轮次 | 环节二（13:30） |
| 平台题目名 | re01 |
| 比赛 qid | eVn0vSPSZZxRDM0u |
| 分类 | reverse |
| 分值 | 500 |
| 交互型 | false（静态附件） |
| 关键 flag | `flag{71a76145-c14f-4e0b-80ac-58035510fade}` |
| 是否解出 | 已解出（2026-09-14 13:34:32 平台返回 `code=0`「恭喜您，回答正确」） |
| **还原完整度** | **A**（原始附件原样归档 + 可跑出 flag 的参考脚本，且脚本可从二进制自动回抽常量表做交叉校验） |

## 1. 题面（比赛原文，逐字保留）

（平台 description 为空）

- `/hint` 亦为空，比赛期间无任何文字提示。
- 二进制 `.rodata` 内留有出题人题眼字符串：

```
Please gdb me,I wish you a pleasant time.
```

> 该字符串在 `main` 结尾以 `printf` 打印（`0x17bd: lea rax,[rip+0x874] # 2038`），
> 属于**纯装饰 / 诱导**：它暗示「请上 gdb 动态调试」，但程序本身**没有任何输入、没有任何输出判定**，
> 动态调试只能看到一个恒定的结果缓冲区，对求解毫无帮助（详见 §4）。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | `6eeab1c52c58772a4a31eabca90e6b36.zip`（3,336 B）→ 内含 `gdb_me`（16,160 B） |
| 附件类型 | ELF64 x86-64 **PIE**（`Type: DYN`），GCC 13.3.0，**未剥离符号**（`.symtab` 保留） |
| 容器 | 无（静态题，无 `connection`） |
| 附件存放 | `attachments/6eeab1c52c58772a4a31eabca90e6b36.zip`、`attachments/gdb_me`（zip 内文件，已解出并原样归档） |
| 原始 file_url | `https://g.ichunqiu.com/terminator/production/match_question/202609/6eeab1c52c58772a4a31eabca90e6b36.zip` |
| md5 | zip `ada0084b70e027de4bc45c5f716d1895` ｜ `gdb_me` `0a2e80acee912696ea763c455546f292` |

关键符号（`readelf -sW gdb_me`，均为 `.symtab` 中 `GLOBAL FUNC`）：

| 符号 | 地址 | 大小 |
|------|------|------|
| `_start` | `0x10c0` | 0x26 |
| `rc4_init` | `0x11a9` | 239 |
| `rc4_crypt` | `0x1298` | 286 |
| `main` | `0x13b6` | 1088（`main+0x43e` 结束于 `0x17f5`） |

关键 `.rodata` 常量：

| 地址 | 内容 | 长度 |
|------|------|------|
| `0x2008` | `This_is_a_your_start_string` | `0x1b` = 27 |
| `0x2024` | `my_secret_key` | 13 |
| `0x2038` | `Please gdb me,I wish you a pleasant time.` | 装饰串 |

## 3. 考点（★核心）

- **考点 1：未剥离符号表的符号级定位（`.symtab` 泄漏算法族）。** 二进制没有 strip，`readelf -sW` /
  `nm` 直接列出 `rc4_init` / `rc4_crypt` / `main`。做题人**不需要**识别 RC4 的常量（`0x100` 循环 /
  `j = j + S[i] + key[i % len]`），函数名已经把算法族交出来了 —— 考点变成「能否正确还原 **KSA + PRGA
  的调用约定**（谁传 key、谁传 S 盒、谁传明文、长度分别多少）」。
- **考点 2：校验结果「算完即弃」—— 纯静态复现，无法靠喂输入拿判定。** `main` 末段循环把
  `res[i] = out[i % 27] ^ enc[i]` 逐字节写进 `[rbp-0x110]`，然后**直接打印装饰串、`putchar('\n')`、`leave; ret`**，
  **全程没有任何 `printf("%s", res)`、没有 `strcmp`、没有 `memcmp`**。程序对 stdin 完全不读。
  ⇒ 动态调试 / 爆破输入两条路都被堵死，**只能在本地用 Python 复刻两段算法**。这是本题区别于
  「常规 checker」的核心设计。
- **考点 3：`movabs` 栈写入的地址重叠混淆（手抄常量表必错）。** 42 字节密表被编译器拆成 6 条
  `movabs` + 6 条 `mov QWORD PTR [rbp-0xNNN],rXX`：

  | # | 常量值 | 目标地址 |
  |---|--------|----------|
  | 1 | `0x1f37a31950a38e7b` | `[rbp-0x340]` |
  | 2 | `0x5d30e5663551dd40` | `[rbp-0x338]` |
  | 3 | `0xe09ffeaf90bef8ec` | `[rbp-0x330]` |
  | 4 | `0x520ff7cf7efc4872` | `[rbp-0x328]` |
  | 5 | `0x33a7520ff7cf7efc` | **`[rbp-0x326]`（与 #4 的 1..6 字节重叠，即 `-0x326..-0x31f`）** |
  | 6 | `0x2ead376006db464b` | **`[rbp-0x31e]`（与 #5 的 4..7 字节重叠）** |

  若按「6 条 `movabs` 顺序 = 42 字节密表」直接拼接，会得到**完全错误的表**；正确做法是按
  **目标地址升序 + 后写覆盖**展开（#5/#6 只能覆盖/追加，`-0x326..-0x31f` 与 `-0x31e..-0x317`
  让表从 32 字节延伸到 42 字节）。
- **考点 4：`idiv` 取余实现密钥流复用。** `res` 长度 `0x2a` = 42，而 `rc4_crypt` 输出只有 27 字节，
  `main` 里用 `cdq; idiv DWORD PTR [rbp-0x35c]` 对 27 取余循环复用密钥流；做题人必须把
  「密钥流周期 27」这条信息正确读出，否则长度对不上。42 字节恰为 `flag{` + UUID(36) + `}`，
  这是**算法的自洽性校验点**（不需要猜）。
- **考点 5：`rc4_crypt` 的 XOR 语义归属。** `rc4_crypt(rdi=明文, esi=len, rdx=S, rcx=out)` 里
  `out` 是**独立的第三个缓冲区**（不是原地），语义为 `out[j] = in[j] ^ ks[j]`。判断成「原地加密」
  或「返回密钥流」都会算错。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出：** 出题人想考「**算法识别 → 调用约定还原 → 常量表还原 → 逆运算**」这条完整的
  静态逆向流水线，但**故意把所有"抄近路"的出口都焊死**。于是：
  1. 符号不 strip → 让你 3 秒定算法族，**把时间预算留给真正难的部分**（重叠常量表 + 无判定输出）；
  2. 结果算完即弃 → **逼迫你写复现脚本**，而不是在 gdb 里 `finish` 看返回值；
  3. 常量表地址重叠 → **惩罚"复制粘贴反汇编"**，必须理解栈布局。
- **难度卡点设计在哪：**
  - 卡点 A：**发现程序没有任何判定**。绝大多数选手的第一反应是「找 `strcmp` / 找正确性打印」，
    找不到会怀疑自己漏了函数。真相是 `main` 只有 1088 字节、调用图只有 `strlen`/`printf`/`putchar`/
    `rc4_init`/`rc4_crypt`，**根本没有比较函数** —— 这一步的"放弃找判定"就是分水岭。
  - 卡点 B：**42 字节常量表的地址重叠**（`[rbp-0x326]` / `[rbp-0x31e]`）。这两条 `movabs` 的目标
    既不是 8 字节对齐、也不是连续递增，肉眼扫反汇编时极易当成编译器噪声忽略。
  - 卡点 C：**`idiv` 的余数复用**。27 字节密钥流被"摊"到 42 字节上，不看清 `idiv [rbp-0x35c]`
    就会以为要 42 字节密钥流（RC4 当然也能生成 42 字节，但那样结果全错 —— **这是一个不会报错、
    只会静默出错的陷阱**）。
- **干扰项 / 诱导项：**
  1. **题眼字符串 `Please gdb me,I wish you a pleasant time.`** —— 显式诱导你去 gdb 动态调试。
     实际动态调试**只能看到恒定输出**，因为程序不接收输入；它是**成本陷阱**：挂 gdb 的人会在
     `0x17a1` 断点看到 42 字节结果，但那 42 字节就是 flag 的 XOR 前形态，没有对比目标，等于没用。
  2. **文件名 `gdb_me`** —— 与字符串同源的第二个诱导，强化「这是个 gdb 题」的错误先验。
  3. **`0x2000` 处的 `01 00 02 00`**（`_IO_stdin_used` 标记）紧邻明文常量串，容易在 dump 时被误当数据。
  4. **栈上大片 `mov QWORD PTR [rbp-0xNNN],0x0` 清零循环**（`0x13f0`–`0x167d`，约 70 条）——
     制造"这里有很多数据"的错觉，实际全是 0。
  5. **`rc4_init` 里标准 RC4 的 S 盒**（`[rbp-0x310]`）是**唯一的大块真实数据**，容易被认成"真正被校验的密文"。
- **哪些地方是"必须踩坑才会发现"的：**
  - 必须**真的把 6 条 `movabs` 的目标地址抄下来并排序**，才能发现重叠；只按出现顺序拼表会得到错误的 48 字节密表，
    且**解出来的结果仍是可打印字符**（因为 XOR 保结构），极具迷惑性 —— 这是本题设计最刁的地方。
  - 必须**注意到 `main` 没有任何比较**，才会转向"离线复现"而不是继续在 gdb 里找答案。
  - 必须**核对 42 字节里 `flag{` 前缀与 `}` 后缀**才能确认常量表抄对了（这也是脚本里
    `parse_enc_from_binary()` 交叉校验的价值）。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察（定性）**
   ```bash
   file gdb_me
   # ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
   readelf -sW gdb_me | grep FUNC
   #   27: 00000000000011a9  239 FUNC GLOBAL DEFAULT 16 rc4_init
   #   35: 00000000000013b6 1088 FUNC GLOBAL DEFAULT 16 main
   #   38: 0000000000001298  286 FUNC GLOBAL DEFAULT 16 rc4_crypt
   strings -a gdb_me
   #   This_is_a_your_start_string
   #   my_secret_key
   #   Please gdb me,I wish you a pleasant time.
   ```
   ⇒ 算法族锁定 **RC4**，key = `my_secret_key`，明文 = `This_is_a_your_start_string`。

2. **反汇编 `main`**
   ```bash
   objdump -d -M intel --start-address=0x13b6 --stop-address=0x17f8 gdb_me
   ```
   读出三段关键指令：

   ```
   # ① 取两个字符串长度（PLT 0x1090 = strlen@GLIBC_2.2.5）
   16ec: mov rax,QWORD PTR [rbp-0x350]   # = 0x2008 "This_is_a_your_start_string"
   16f6: call 1090 <strlen>
   16fb: mov DWORD PTR [rbp-0x35c],eax    # 27
   1701: mov DWORD PTR [rbp-0x358],0x2a   # 42  <- res 长度
   170b: mov rax,QWORD PTR [rbp-0x348]   # = 0x2024 "my_secret_key"
   1715: call 1090 <strlen>
   171a: mov DWORD PTR [rbp-0x354],eax    # 13

   # ② rc4_init(key, keylen, S)      S 在 [rbp-0x310]
   1726: lea rcx,[rbp-0x310]
   1737: mov rdi,rax                      # key
   173a: call 11a9 <rc4_init>

   # ③ rc4_crypt(start, 27, S, out)  out 在 [rbp-0x210]
   173f: lea rcx,[rbp-0x210]
   1746: lea rdx,[rbp-0x310]              # S
   174d: mov esi,DWORD PTR [rbp-0x35c]    # 27
   175a: call 1298 <rc4_crypt>

   # ④ res[i] = out[i % 27] ^ enc[i]，写 [rbp-0x110]，之后直接返回（无比较！）
   176e: mov eax,DWORD PTR [rbp-0x360]
   1774: cdq
   1775: idiv DWORD PTR [rbp-0x35c]        # i % 27
   177f: movzx edx,BYTE PTR [rbp+rax*1-0x210]
   178f: movzx eax,BYTE PTR [rbp+rax*1-0x340]   # enc[i]
   1797: xor edx,eax
   17a1: mov BYTE PTR [rbp+rax*1-0x110],dl      # res[i]  <-- 写完就没人读
   ```

3. **还原 42 字节密表**（本题唯一的"手工精度活"）

   ```
   1686: movabs rax,0x1f37a31950a38e7b
   1690: movabs rdx,0x5d30e5663551dd40
   169a: mov QWORD PTR [rbp-0x340],rax
   16a1: mov QWORD PTR [rbp-0x338],rdx
   16a8: movabs rax,0xe09ffeaf90bef8ec
   16b2: movabs rdx,0x520ff7cf7efc4872
   16bc: mov QWORD PTR [rbp-0x330],rax
   16c3: mov QWORD PTR [rbp-0x328],rdx
   16ca: movabs rax,0x33a7520ff7cf7efc
   16d4: movabs rdx,0x2ead376006db464b
   16de: mov QWORD PTR [rbp-0x326],rax     # <-- 重叠: 覆盖 -0x326..-0x31f
   16e5: mov QWORD PTR [rbp-0x31e],rdx     # <-- 重叠: 覆盖 -0x31e..-0x317
   ```
   按地址 `-0x340` → `-0x317`（共 42 字节）展开：

   ```
   7b 8e a3 50 19 a3 37 1f 40 dd 51 35 66 e5 30 5d
   ec f8 be 90 af fe 9f e0 72 48 fc 7e cf f7 0f 52
   a7 33 4b 46 db 06 60 37 ad 2e
   ```

4. **离线复现**
   ```python
   ks  = rc4_keystream(b"my_secret_key", 27)
   out = bytes(a ^ b for a, b in zip(b"This_is_a_your_start_string", ks))
   flag = bytes(out[i % 27] ^ ENC[i] for i in range(42))
   ```

5. **取 flag**：`flag{71a76145-c14f-4e0b-80ac-58035510fade}`（42 字节，长度与 `[rbp-0x358]=0x2a` 吻合）。

## 6. 参考解法（代码）

完整可跑脚本：`solve/solve.py`（无第三方依赖，仅需 `objdump` 在 PATH 中做交叉校验）。

核心片段：

```python
START = b"This_is_a_your_start_string"   # main @0x2008, esi = 0x1b
KEY   = b"my_secret_key"                 # main @0x2024, edx = 13
N     = 42                               # main: [rbp-0x358] = 0x2a

ENC = bytes([                            # 6 条 movabs 按目标地址升序展开（重叠已覆盖）
    0x7b,0x8e,0xa3,0x50,0x19,0xa3,0x37,0x1f, 0x40,0xdd,0x51,0x35,0x66,0xe5,0x30,0x5d,
    0xec,0xf8,0xbe,0x90,0xaf,0xfe,0x9f,0xe0, 0x72,0x48,0xfc,0x7e,0xcf,0xf7,0x0f,0x52,
    0xa7,0x33,0x4b,0x46,0xdb,0x06,0x60,0x37, 0xad,0x2e,
])

def rc4_keystream(key, n):
    s, j = list(range(256)), 0
    for i in range(256):                       # KSA
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    i = j = 0; out = bytearray()
    for _ in range(n):                         # PRGA
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out.append(s[(s[i] + s[j]) & 0xff])
    return bytes(out)

ks   = rc4_keystream(KEY, len(START))
out  = bytes(a ^ b for a, b in zip(START, ks))         # rc4_crypt 输出
flag = bytes(out[i % len(START)] ^ ENC[i] for i in range(N))
print(flag.decode())          # flag{71a76145-c14f-4e0b-80ac-58035510fade}
```

脚本还内置 `parse_enc_from_binary()`：用 `objdump -d -M intel` 正文正则跟踪
`movabs` → `mov QWORD PTR [rbp-0xNNN],reg` 配对，按地址序展开常量表，并与内嵌 `ENC` 断言相等
（**这是"常量表抄对了"的机器证明**）。

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{71a76145-c14f-4e0b-80ac-58035510fade}` |
| 提交接口返回 | `{"code": 0, "status": null, "message": "恭喜您，回答正确", "pass": true}` |
| 提交时间 | 2026-09-14 13:34:32 |
| 证据文件 | `D:\2026\湾区杯\决赛\work\submit_results_live.json` 中 `qid=eVn0vSPSZZxRDM0u` 记录 |
| 交叉证据 | `D:\2026\湾区杯\决赛\赛道二测试记录.md` §〇 表格首行；`D:\2026\湾区杯\决赛\work\flags\eVn0vSPSZZxRDM0u.txt` |

> 注：比赛期抓取的 `challenges_live.json` 快照里该题 `is_solved=false`（快照时间早于提交），
> 但提交回执为 `code=0 / pass=true`，且平台题目状态随后变为已攻克 —— **以提交回执为准**。

## 8. 还原说明（诚实写）

- **已有原始件（事实）：**
  - `attachments/6eeab1c52c58772a4a31eabca90e6b36.zip` —— 平台原始附件，**字节未改动**，
    md5 `ada0084b70e027de4bc45c5f716d1895`（与来源 `work\q10\` 一致）。
  - `attachments/gdb_me` —— 从上述 zip 原样解出，md5 `0a2e80acee912696ea763c455546f292`，
    与比赛工作目录 `work\re01\gdb_me` 逐字节相同。
  - flag 为**平台确认值**（`code=0`「回答正确」），非推测。
- **重建部分：** 无。本题**不需要重建任何二进制**——原始 ELF 已完整拿到，且脚本可**直接从该 ELF
  反抽常量表**并与内嵌值断言相等，因此不存在"靠记忆抄表"的不可靠环节。
  `solve/solve.py` 为本次整理的规范化版本，算法与比赛期 `work\re01\re01_solve.py` 一致
  （额外增加了 stdout UTF-8 自适应与 PASS/FAIL 退出码）。
- **未能还原：** 无。
- **可复现性验证（已实测）：**
  ```bash
  cd timu/round2_1330/re01
  python solve/solve.py
  ```
  实测输出（已跑通，退出码 0）：
  ```
  [*] objdump 从二进制解析密表: 7b 8e a3 50 19 a3 37 1f 40 dd 51 35 66 e5 30 5d ec f8 be 90 af fe 9f e0 72 48 fc 7e cf f7 0f 52 a7 33 4b 46 db 06 60 37 ad 2e
  [+] 交叉校验通过：二进制密表 == 内嵌常量表 (42 B)
  [*] key      = b'my_secret_key' (len 13)
  [*] start    = b'This_is_a_your_start_string' (len 27)
  [*] RC4 密钥流(27 B) = 49 8a ab 44 3d fd 75 21 16 b4 19 6e 26 ba 0c 1f ac ff e1 d0 95 bd 89 bf 23 16 fa
  [*] rc4_crypt 输出   = 1d e2 c2 37 62 94 06 7e 77 eb 60 01 53 c8 53 6c d8 9e 93 a4 ca ce fd cd 4a 78 9d
  [+] flag = flag{71a76145-c14f-4e0b-80ac-58035510fade}
  [+] 与比赛期确认 flag 一致 -> PASS
  ```
  **注意：本题无法用"喂输入看输出"验证**（程序不读 stdin、不打印判定）；可复现性由
  「回抽常量表断言 + 42 字节结果恰好是 `flag{…}` 结构」双重保证。

## 9. 复现步骤

```bash
cd timu/round2_1330/re01

# 方式一（默认）：内嵌常量表求解 + 自动从二进制交叉校验
python solve/solve.py

# 方式二：只用二进制，跳过交叉校验
python solve/solve.py --bin attachments/gdb_me

# 方式三：纯静态核对（手工路径）
unzip -o attachments/6eeab1c52c58772a4a31eabca90e6b36.zip -d /tmp/re01
readelf -sW /tmp/re01/gdb_me | grep FUNC
objdump -d -M intel --start-address=0x1686 --stop-address=0x16ec /tmp/re01/gdb_me
```

无容器部署件（静态题）：`deploy/` 仅放 `Dockerfile`，说明如何把该 ELF 起成一个
`nc` 远程判题服务（对本题是**可选**的 —— 原题并不需要网络交互，见 `deploy/Dockerfile`）。

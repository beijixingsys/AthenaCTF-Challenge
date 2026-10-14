# re02 · PE64 三段常量 + 密钥字节两两异或 + ROL8 变换（文件名 `re01.exe` 是命名干扰）

| 项 | 值 |
|----|----|
| 轮次 | 环节二（13:30） |
| 平台题目名 | re02 |
| 比赛 qid | n6sTYSB71GlMDKLH |
| 分类 | reverse |
| 分值 | 500 |
| 交互型 | false（静态附件） |
| 关键 flag | `flag{0fa830e7-b699-4513-8e01-51f35b0f3293}` |
| 是否解出 | 已解出（2026-09-14 13:34:39 平台返回 `code=0`「恭喜您，回答正确」） |
| **还原完整度** | **A**（原始附件原样归档 + 可跑出 flag 且**能在原生 Windows 上实机自校验**的脚本） |

## 1. 题面（比赛原文，逐字保留）

（平台 description 为空）

- `/hint` 亦为空。
- 程序内字符串（`.rdata`，GBK 编码）：

| 虚拟地址 | 原文 |
|----------|------|
| `0x405000` | `内存分配失败！` |
| `0x40500f` | `%s%s%s`（`snprintf` 格式串） |
| `0x405016` | `请输入 flag: ` |
| `0x405024` | `%127s`（`scanf` 格式串） |
| `0x40502a` | `成功！` |
| `0x405031` | `输入错误！` |

> ⚠️ **命名干扰（真实事实，非本工程笔误）**：本题平台名是 `re02`，附件却是 **`re01.exe`**。
> 这是出题人的命名错位/干扰，归档时保持原文件名不改。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | `ca44d8df29800162c10323766980d9cf.zip`（7,555 B）→ 内含 `re01.exe`（16,896 B） |
| 附件类型 | **PE64**（`pei-x86-64`，`EXEC_P, D_PAGED`），GCC 8.1.0 / MinGW-W64，**无壳、无反调试、无符号**（函数无名字，`.text` 从 `0x401000` 起） |
| 容器 | 无（静态题，无 `connection`） |
| 附带依赖 | `msvcrt.dll`（CRT，提供 `scanf`/`strcmp`/`malloc`/`puts`/`printf`）、`KERNEL32.dll` |
| 附件存放 | `attachments/ca44d8df29800162c10323766980d9cf.zip`、`attachments/re01.exe` |
| 原始 file_url | `https://g.ichunqiu.com/terminator/production/match_question/202609/ca44d8df29800162c10323766980d9cf.zip` |
| md5 | zip `95ed08661037ee5dc47c2f37ddd4f032` ｜ `re01.exe` `1b80d8086f3a46b1adb7cfde10ac18df` |
| 入口点 | `0x4014e0`（`start`），自定义 `main` 在 `0x40161b` |

关键地址表（本次实测确认，供复现）：

| 地址 | 内容 |
|------|------|
| `0x40159a` | `rol1(x) = (x<<1) \| (x>>7)`（8 位循环左移，`add eax,eax` + `shr al,7` + `or`） |
| `0x4015b6` | 变换函数 `transform(buf, len, key)`：逐字节 `buf[i] = rol1(buf[i]) ^ key`（原地） |
| `0x40161b` | `main`：`sub rsp,0x1d0` + `lea rbp,[rsp+0x80]`（**非标准帧，局部变量走正偏移**） |
| `0x401630`–`0x40176b` | 三段硬编码数组的 `mov BYTE PTR [rbp+0xNN],imm8` |
| `0x401777`/`0x40177e`/`0x401785` | 密钥字节 `[rbp+0x137]=0x99` / `[rbp+0x136]=0xdd` / `[rbp+0x135]=0xff` |
| `0x40178c`–`0x4017c4` | 三条 `xor` 派生 keyA/keyB/keyC |
| `0x4018c2`/`0x4018e2`/`0x401902` | 三次 `call 0x4015b6`（分别对 A / B / C） |
| `0x4019cc` | `snprintf(dst, 0x80, "%s%s%s", A', B', C')`（`0x401550`） |
| `0x4019d8` | `printf("请输入 flag: ")` |
| `0x4019eb` | `scanf("%127s", buf@[rbp-0x50])` |
| `0x4019fb` | `strcmp(input, expected)`（thunk `0x402f48` → IAT `0x409384` → `strcmp`） |
| `0x401a04` / `0x401a12` | `puts("成功！")` / `puts("输入错误！")` |

## 3. 考点（★核心）

- **考点 1：PE64 无符号 + 非标准栈帧的手工逆向。** 无 PDB、无符号、`main` 用
  `sub rsp,0x1d0; lea rbp,[rsp+0x80]` 建立伪帧，**所有局部变量用 `[rbp+0xNN]` 正偏移寻址**
  （正常函数是 `[rbp-0xNN]`）。IDA/Ghidra 的自动栈变量重建在这种帧下极易把
  `[rbp+0x10a]` 之类的写操作误判成"参数写入"，从而漏掉三段数组。
- **考点 2（核心）：密钥字节"两两异或"派生。** 栈上相邻三字节 `0x99 / 0xdd / 0xff` 是
  **派生源而不是密钥本身**，真实 key 由 `0x40178c`–`0x4017c4` 三条 `xor` 得出：

  | 输出槽 | 表达式 | 值 | 用于 |
  |--------|--------|-----|------|
  | `[rbp+0x134]` | `[rbp+0x137] ^ [rbp+0x135]` = `0x99 ^ 0xff` | **`0x66`** | 数组 A |
  | `[rbp+0x133]` | `[rbp+0x136] ^ [rbp+0x137]` = `0xdd ^ 0x99` | **`0x44`** | 数组 B |
  | `[rbp+0x132]` | `[rbp+0x135] ^ [rbp+0x136]` = `0xff ^ 0xdd` | **`0x22`** | 数组 C |

  注意三个常量正好互为部分按位取反（`~0x99=0x66`、`~0xdd=0x22`、`~0xff=0x00`），
  所以**看起来像"三个魔数"，实际是"三条异或关系"**。把 `0x99/0xdd/0xff` 直接当 key 用会
  解出乱码 —— 这是本题的分水岭。
- **考点 3：ROL8 循环左移 + XOR 的逐字节变换，方向必须判断对。**
  `sub_40159a` 是 `(x<<1) | (x>>7)`，即 **8 位循环左移 1 位（不是算术左移，也不会丢 bit7）**。
  `sub_4015b6` 在**原数组上原地**做 `x' = rol1(x) ^ key`。
  由于 XOR 与 ROL 各自可逆，做题人要么正向还原"程序把常量数组变换成期望输入"这一事实
  （`flag = rol1(A) ^ keyA`，**因为程序做的是同一变换**），要么按逆向思路 `A = ror1(A' ^ keyA)`
  —— **两条路都必须先在脑子里确定"哪一侧是明文"**，判断反了会得到乱码。
- **考点 4：三段拼接顺序与长度自洽。** 期望串由 `snprintf(..., "%s%s%s", ptr_A, ptr_B, ptr_C)`
  拼成 `A'‖B'‖C'`（调用约定：第 5/6/7 个 vararg 通过 `[rsp+0x20]`/`[rsp+0x28]`/`r9` 传入，
  实测 `r9=B'`、`rsp+0x20=A'`、`rsp+0x28=C'`）。三段长度 `0x0e/0x0f/0x0d` = **14+15+13 = 42**，
  与 `flag{` + UUID(36) + `}` 恰好吻合 —— 这是**顺序正确的机器校验点**。
- **考点 5：本题"可实机自校验"，与 re01 形成对照。** 程序 `strcmp` 后 `puts("成功！")`，
  所以能把解出的 flag 直接灌 stdin 看回显；而 re01 是"结果算完即弃"。同一场比赛两道 RE
  用**两种相反的可观测性设计**（黑盒可验 vs 纯静态），是本轮 RE 题组的设计亮点。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出：**
  - 出题人要在**没有任何花哨保护**（无壳、无反调试、无 VM、无混淆器）的前提下提高逆向成本。
    手段是**数据混淆 + 关系藏字节**：不给你"密钥"，只给你"密钥之间的异或关系"，逼你把
    `0x40178c` 那三条 `xor` 反汇编读清楚。
  - 三段数组 + `snprintf("%s%s%s")` 的拼接结构，把"算法还原"拆成**两个独立判断**
    （key 是多少、顺序是什么），任何一处判错都只出乱码、不给报错 —— **静默失败**是刻意的。
- **难度卡点设计在哪：**
  - 卡点 A：**非标准栈帧**。`lea rbp,[rsp+0x80]` 让所有数组都用 `[rbp+0xEE..0x117]` 正偏移，
    自动分析工具与手工读码都容易把这三段看成"没被使用的栈空间"。而且三段是**倒着写**的
    （先 A 在 `+0x10a`，再 B 在 `+0xfb`，最后 C 在 `+0xee`），地址递减、与直觉相反。
  - 卡点 B：**密钥字节的"关系陷阱"**。`0x99/0xdd/0xff` 三个值视觉上很像 RC4/自定义 S 盒的
    填充常数，且**它们本身就是合法的 key 候选**（用它们直接 XOR 也能算出"像 flag 的字符串"吗？
    —— 不能，会出乱码，但很多人会用它们试一遍，浪费一轮）。
  - 卡点 C：**ROL1 的方向**。`(x<<1)|(x>>7)` 与 `(x>>1)|(x<<7)` 只差移位方向；用错方向
    解出的东西同样是 42 字节可打印字符的概率不小（因为数组高位的分布很特殊），容易自我怀疑。
  - 卡点 D：**`malloc` + `memcpy` 的噪声**。`0x4017c5`–`0x4018a2` 对三段数组各做一次
    `malloc(len+1)` + `memcpy` + 末尾补 `\0`，共 6 次调用，读起来像"动态内存逻辑"，
    实际只是把数组搬到堆上给 `snprintf` 用 —— **纯噪声**。
- **干扰项 / 诱导项：**
  1. **文件名 `re01.exe`**（本题实为 re02）—— 与上一题 `gdb_me` 的名字错位，检索/归档时极易混。
  2. **`0x99 / 0xdd / 0xff`** 三个"魔数"——最大的诱导，直接当 key 用会失败。
  3. **`sub_40161b` 开头的 `call 0x401b10`**（CRT `__main`）紧贴数组初始化，容易被当成
     "main 的初始化函数"而绕过。
  4. **`0x405000` 的 `内存分配失败！` 与 `exit(1)` 分支**（`0x401813`–`0x401842`）是死代码，
     制造"有错误处理"的错觉。
  5. **`%127s` 的长度限制**（127 > 42）不影响解题，但会诱导人去想"是不是要爆破长度"。
- **哪些地方是"必须踩坑才会发现"的：**
  - 必须**真的把 `0x40178c`–`0x4017c4` 的三条 `xor` 指令读出来**（`movzx` + `xor al, BYTE PTR`
    + `mov BYTE PTR`），只看"栈上放了 0x99/0xdd/0xff"会永远停在错 key 上。
  - 必须**核对 42 = 14+15+13 且以 `flag{` 开头、`}` 结尾**，才能确认拼接顺序是 A‖B‖C 而不是别的排列
    （三段长度的区分度是唯一线索）。
  - 必须**弄清 `snprintf` 的 vararg 传参顺序**（`r9` = 第 3 个 `%s`，`[rsp+0x20]` = 第 2 个）
    才能确认 `A` 在前。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察（定性）**
   ```bash
   file re01.exe                      # PE32+ executable (console) x86-64, for MS Windows
   objdump -f re01.exe                # file format pei-x86-64 / start address 0x4014e0
   objdump -p re01.exe | grep -i "DLL Name"
   #   KERNEL32.dll / msvcrt.dll
   objdump -p re01.exe | grep -E "printf|scanf|strcmp|strncmp|malloc|memcpy|puts|exit"
   ```
   ⇒ 导入表只有 `printf/scanf/strcmp/strncmp/malloc/memcpy/puts/exit` → 判为
   **"读输入 + 比对常量"型 checker**（对比 re01 的"无判定"设计）。

2. **定位 main**：无符号，靠特征找。`.text` 内 `sub rsp,0x1d0` + `lea rbp,[rsp+0x80]` 唯一：
   ```bash
   objdump -d -M intel re01.exe | grep -B2 -A2 "lea    rbp,\[rsp+0x80\]"
   #   401623: 48 8d ac 24 80 00 00 00  lea rbp,[rsp+0x80]
   #   -> main = 0x40161b
   ```

3. **抄三段数组**（`[rbp+0x10a]` / `[rbp+0xfb]` / `[rbp+0xee]`，长度 `0xe` / `0xf` / `0xd`
   存在 `[rbp+0x148]` / `[rbp+0x140]` / `[rbp+0x138]`）：
   ```bash
   objdump -d -M intel --start-address=0x401630 --stop-address=0x40176c re01.exe
   ```

4. **读密钥派生**（本题关键）：
   ```bash
   objdump -d -M intel --start-address=0x401777 --stop-address=0x4017c5 re01.exe
   ```
   ```
   401777: c6 85 37 01 00 00 99   mov BYTE PTR [rbp+0x137],0x99
   40177e: c6 85 36 01 00 00 dd   mov BYTE PTR [rbp+0x136],0xdd
   401785: c6 85 35 01 00 00 ff   mov BYTE PTR [rbp+0x135],0xff
   40178c: 0f b6 85 37 01 00 00   movzx eax,BYTE PTR [rbp+0x137]
   401793: 32 85 35 01 00 00      xor   al,BYTE PTR [rbp+0x135]    ; keyA = 0x66
   401799: 88 85 34 01 00 00      mov   BYTE PTR [rbp+0x134],al
   40179f: 0f b6 85 36 01 00 00   movzx eax,BYTE PTR [rbp+0x136]
   4017a6: 32 85 37 01 00 00      xor   al,BYTE PTR [rbp+0x137]    ; keyB = 0x44
   4017ac: 88 85 33 01 00 00      mov   BYTE PTR [rbp+0x133],al
   4017b2: 0f b6 85 35 01 00 00   movzx eax,BYTE PTR [rbp+0x135]
   4017b9: 32 85 36 01 00 00      xor   al,BYTE PTR [rbp+0x136]    ; keyC = 0x22
   4017bf: 88 85 32 01 00 00      mov   BYTE PTR [rbp+0x132],al
   ```

5. **读变换函数**：
   ```bash
   objdump -d -M intel --start-address=0x40159a --stop-address=0x40161b re01.exe
   # 40159a: rol1: add eax,eax ; mov edx,eax ; movzx eax,[rbp+0x10]; shr al,7 ; or eax,edx
   # 4015b6: transform: loop i<len { t = rol1(buf[i]); buf[i] = t ^ key; }   <-- 原地改写
   ```
   三次调用分别在 `0x4018c2`（用 keyA 处理 A）/ `0x4018e2`（keyB/B）/ `0x401902`（keyC/C）。

6. **读校验**：
   ```bash
   objdump -d -M intel --start-address=0x4019ac --stop-address=0x401a1e re01.exe
   ```
   ```
   4019bd: lea r8,[rip+0x364b]   # 0x40500f = "%s%s%s"
   4019c4: mov edx,0x80
   4019cc: call 0x401550          # snprintf(dst@[rbp+0x30], 0x80, "%s%s%s", A',B',C')
   4019d8: call puts             # "请输入 flag: "
   4019eb: call scanf            # "%127s" -> [rbp-0x50]
   4019fb: call strcmp
   401a02: jne 0x401a12          # -> puts("输入错误！")
   401a04: lea rcx,[rip+0x361f]  # 0x40502a "成功！"
   ```
   ⇒ **期望输入 = A'‖B'‖C'**，其中 `X' = rol1(X) ^ keyX`。

7. **求解**（Python 一行）
   ```python
   A = [0x00,0x05,0x83,0x80,0x8e,0x2b,0x00,0x83,0x2f,0xaa,0x2b,0x81,0xa8,0xa5]
   B = [0x13,0x39,0xbe,0xbe,0xb4,0x38,0xb8,0xba,0xbb,0xb4,0x3e,0x90,0x3a,0xba,0xb4]
   C = [0x8b,0x89,0x22,0x88,0x8b,0x20,0x09,0x22,0x88,0x08,0x8d,0x88,0xaf]
   rol1 = lambda x: ((x << 1) | (x >> 7)) & 0xff
   flag = bytes([rol1(x) ^ 0x66 for x in A] + [rol1(x) ^ 0x44 for x in B] + [rol1(x) ^ 0x22 for x in C])
   ```

8. **取 flag 并实机自校验**
   ```bash
   echo flag{0fa830e7-b699-4513-8e01-51f35b0f3293} | ./re01.exe
   # 请输入 flag: 成功！
   ```

## 6. 参考解法（代码）

完整可跑脚本：`solve/solve.py`（纯标准库；`--verify` 会在原生 Windows 上真的执行 `re01.exe` 判定）。

核心片段：

```python
A = [0x00,0x05,0x83,0x80,0x8e,0x2b,0x00,0x83,0x2f,0xaa,0x2b,0x81,0xa8,0xa5]                  # len 14
B = [0x13,0x39,0xbe,0xbe,0xb4,0x38,0xb8,0xba,0xbb,0xb4,0x3e,0x90,0x3a,0xba,0xb4]            # len 15
C = [0x8b,0x89,0x22,0x88,0x8b,0x20,0x09,0x22,0x88,0x08,0x8d,0x88,0xaf]                      # len 13

KEY_A, KEY_B, KEY_C = 0x99 ^ 0xff, 0xdd ^ 0x99, 0xff ^ 0xdd      # 0x66 / 0x44 / 0x22

rol1 = lambda x: ((x << 1) | (x >> 7)) & 0xff                    # sub_40159a

flag = bytes([rol1(x) ^ KEY_A for x in A] +
             [rol1(x) ^ KEY_B for x in B] +
             [rol1(x) ^ KEY_C for x in C])                       # A' || B' || C'
print(flag.decode())     # flag{0fa830e7-b699-4513-8e01-51f35b0f3293}
```

脚本内置 `parse_arrays_from_binary()`：用 `objdump -d -M intel` 抓全部
`mov BYTE PTR [rbp+0xNN],0xVV`，按 `0x10a/0xfb/0xee` 起点分别取 14/15/13 字节并与内嵌常量断言相等。

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{0fa830e7-b699-4513-8e01-51f35b0f3293}` |
| 提交接口返回 | `{"code": 0, "status": null, "message": "恭喜您，回答正确", "pass": true}` |
| 提交时间 | 2026-09-14 13:34:39 |
| 证据文件 | `D:\2026\湾区杯\决赛\work\submit_results_live.json` 中 `qid=n6sTYSB71GlMDKLH` 记录 |
| 交叉证据 | `D:\2026\湾区杯\决赛\work\flags\n6sTYSB71GlMDKLH.txt` |
| **本机实机复验** | `python solve/solve.py --verify attachments/re01.exe` → `请输入 flag: 成功！`（命中 GBK `成功` 标记），退出码 0 |

> 注：`challenges_live.json` 快照中 `is_solved=false`（快照早于提交）；以平台提交回执
> `code=0 / pass=true` 为准。

## 8. 还原说明（诚实写）

- **已有原始件（事实）：**
  - `attachments/ca44d8df29800162c10323766980d9cf.zip` —— 平台原始附件，字节未改动，
    md5 `95ed08661037ee5dc47c2f37ddd4f032`。
  - `attachments/re01.exe` —— 从该 zip 原样解出，md5 `1b80d8086f3a46b1adb7cfde10ac18df`，
    与比赛工作目录 `work\re02\re01.exe` 逐字节相同。
  - flag 为**平台确认值**；且**已在本机重跑原 PE 得到 `成功！` 回显**（二重独立验证）。
- **重建部分：** 无。原 PE 完整拿到，**无需重建源码**；脚本可**直接从 PE 反抽三段数组**
  并与内嵌常量断言相等。
- **未能还原：** 无。
  - 说明一点：出题人的**原始 C 源码 / 编译命令**未拿到（无可信来源），因此本目录**不提供
    伪造的 `deploy/src/*.c`**；如需源码级重建，请以 §5 反汇编为准（本 README 已逐条列出关键指令）。
- **可复现性验证（已实测）：**
  ```bash
  cd timu/round2_1330/re02
  python solve/solve.py --verify attachments/re01.exe
  ```
  实测输出（退出码 0）：
  ```
  [+] objdump 交叉校验通过：三段数组与内嵌值一致 (14/15/13 B)
  [*] 栈上密钥字节: [rbp+0x137]=0x99 [rbp+0x136]=0xdd [rbp+0x135]=0xff
  [*] 两两异或派生: keyA=0x66 keyB=0x44 keyC=0x22
  [*] 期望串 A'||B'||C' = flag{0fa830e7-b699-4513-8e01-51f35b0f3293}
  [*] 长度 = 42（三段 14+15+13）
  [+] 与比赛期确认 flag 一致 -> PASS
  [*] 实机输出(GBK): 请输入 flag: 成功！
  [*] 命中 '成功' 标记: True
  [*] 实机校验: PASS
  ```
  ✅ 本题是三道 RE 里**唯一能"喂输入看输出"闭环验证**的一题。

## 9. 复现步骤

```bash
cd timu/round2_1330/re02

# 方式一（推荐）：交叉校验 + 实机闭环（Windows 可直接跑，脚本用 win32 原生执行 re01.exe）
python solve/solve.py --verify attachments/re01.exe

# 方式二：只求 flag（无 Windows / 不想执行二进制）
python solve/solve.py --no-crosscheck

# 方式三：手工复核
unzip -o attachments/ca44d8df29800162c10323766980d9cf.zip -d /tmp/re02
objdump -d -M intel --start-address=0x401777 --stop-address=0x4017c5 /tmp/re02/re01.exe
objdump -d -M intel --start-address=0x4019ac --stop-address=0x401a1e /tmp/re02/re01.exe
```

可选远程包装（原题**不是**容器题，`deploy/Dockerfile` 仅为统一"nc 判题"演练而提供，
用 Wine 执行该 PE；真判题请优先用本地实机闭环）：

```bash
docker build -t timu/re02:local deploy/
docker run -d --rm -p 9999:9999 -v "$PWD/attachments:/opt/re02:ro" timu/re02:local
nc 127.0.0.1 9999        # 输入 flag，回显「成功！/输入错误！」
```

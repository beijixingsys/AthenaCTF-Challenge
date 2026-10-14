# crypto02 · AES 密钥空间搜索（十六进制数字随机双射 + `gift = a0 & a1` 逐 nibble 约束回溯）

| 项 | 值 |
|----|----|
| 轮次 | 环节三（17:00） |
| 平台题目名 | crypto02 |
| 比赛 qid | CrpMu5aVJdYVf9zK |
| 分类 | crypto |
| 分值 | 500 |
| 交互型 | false（静态附件） |
| 关键 flag | `flag{886769b5-2301-4c37-bb73-4480b4eab682}` |
| 是否解出 | 已解出（17:01:41 提交，平台返回 `code=0 message=恭喜您，回答正确`；无人值守 worker 用时 63.9 s） |
| **还原完整度** | **A**（原始附件逐字节归档 + 出题脚本 `task.py` 原样可跑 + `solve/solve.py` 已实测复现 flag 且对新实例闭环验证） |

## 1. 题面（比赛原文，逐字保留）

（平台 description 为空）

平台 `challenges_r3.json` 中本题 `"description": ""`，无 `/hint` 文本。**题面就是附件本身**：附件唯一真实文件是出题脚本 `task.py`，数据以**文件末尾注释**的形式给出：

```python
from Crypto.Cipher import AES  # 导入AES加密模块
from secret import flag       # 从secret模块导入flag（假设为明文）
import random, os             # 导入random和os模块用于随机数生成

# 为消息填充字节，使其长度为16的倍数
def pad(msg):
    return msg + bytes([16 - len(msg) % 16 for _ in range(16 - len(msg) % 16)])

# 对密钥进行随机置换，生成新密钥
def permutation(key):
    tables = [hex(_)[2:] for _ in range(16)]  # 生成0-15的十六进制表（去掉"0x"前缀）
    random.shuffle(tables)                    # 随机打乱表
    newkey = "".join(tables[int(key[_], 16)] for _ in range(len(key)))  # 根据原密钥生成新密钥
    return newkey

# 生成初始密钥key0及其置换密钥key1
def gen():
    key0 = os.urandom(16).hex()  # 随机生成16字节密钥并转为十六进制字符串
    key1 = permutation(key0)     # 对key0进行置换生成key1
    return key0, key1

# 使用key0和key1进行双重AES加密
def encrypt(key0, key1, msg):
    aes0 = AES.new(key0, AES.MODE_CBC, key1)  # 用key0加密，key1作为CBC模式的IV
    aes1 = AES.new(key1, AES.MODE_CBC, key0)  # 用key1解密，key0作为CBC模式的IV
    return aes1.decrypt(aes0.encrypt(msg))    # 先加密后解密生成密文

# 生成密钥对
key0, key1 = gen()
a0, a1 = int(key0, 16), int(key1, 16)  # 将密钥转为整数

gift = a0 & a1  # 计算key0和key1的按位与，作为泄露信息
cipher = encrypt(bytes.fromhex(key0), bytes.fromhex(key1), pad(flag))  # 加密填充后的flag

print(f"gift = {gift}")
print(f"key1 = {key1}")
print(f"cipher = {cipher}")

'''
gift = 64698960125130294692475067384121553664
key1 = 74aeb356c6eb74f364cd316497c0f714
cipher = b'6\xbf\x9b\xb1\x93\x14\x82\x9a\xa4\xc2\xaf\xd0L\xad\xbb5\x0e|>\x8c|\xf0^dl~X\xc7R\xcaZ\xab\x16\xbe r\xf6Pl\xe0\x93\xfc)\x0e\x93\x8e\xd3\xd6'
'''
```

`secret.py`（含 `flag`）**未随附件下发**。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | `crypto02.zip`，1,207 B，ZIP（deflate）；内含唯一真实文件 `task.py`（1,914 B） |
| 容器 | 无（纯静态附件题，`interactive: "false"`，`connection: []`） |
| 原始 file_url | `https://g.ichunqiu.com/terminator/production/match_question/202609/35f9525c2b502783cf462a7f61b0a42e.zip` |
| 附件存放 | `attachments/crypto02.zip`（原始件，未改字节；md5 `f6e278d8b57051867cc99e8d5f70597d`，sha256 `dd5281828fcbb677b24ecd5b95bee907e0fac8240fc14d2ba394de618b8aa362`） |
| 解包件 | `attachments/task.py`（从 zip 原样解出；md5 `7d3d7b38b57752b69fcf3905ebc2a9fb`），`deploy/src/task.py` 同字节 |
| 出题侧补件 | `deploy/src/secret.py`（**重建**，只含 flag）、`deploy/README.md` |
| 数据规模 | `gift` 128 bit（32 个 nibble）、`key1` 32 个 hex 字符（16 个不同取值）、`cipher` 48 B（3 个 AES 分组）、明文 42 B + PKCS#7 `0x06×6` |

> 说明：下载时需带 `Referer: https://match.ichunqiu.com/` + 浏览器 UA，否则会被云防御拦截返回 7383 B 的 HTML 错误页（见 `决赛\AGENTS.md` 卡片 27）。

## 3. 考点（★核心）

- **考点 1：`key1` 是 `key0` 十六进制数字的「逐位随机双射」**。`permutation()` 把 `[0..f]` 洗牌成一个表 `tables`，再令 `key1[i] = tables[key0[i]]`——即 `key1[i] = π(key0[i])`，`π` 是 16 个 hex 数字上的**随机置换（双射）**。因此 `key0[i] = π⁻¹(key1[i])`，**同一个 `key1` 数字必须对应同一个 `key0` 数字，且不同 `key1` 数字必须对应不同 `key0` 数字**——这是一条极强的一致性约束。
- **考点 2：`gift = a0 & a1` 泄漏的是「逐 nibble 的按位与」**。`a0 = int(key0,16)`、`a1 = int(key1,16)`，两者的按位与是**128 位对齐**的，等价于对 32 个 nibble 各做 `gift_i = key0_i & key1_i`。写成 `%032x` 后就是把逐 nibble 约束摆在了明面上。
- **考点 3（本题最关键的一步）：`d & c == g` 是"小"约束，不是等式**。给定 `c = key1_i`、`g = gift_i`，`key0_i = d` 只需满足 **在 `c` 的 1 位上等于 `g`，其余位完全自由**：
  - `c=0x0, g=0x0` → `d ∈ {0..f}`（**16 个候选，等于没约束**）
  - `c=0x1, g=0x0` → `d ∈ {0,2,4,6,8,a,c,e}`（8 个）
  - `c=0x3, g=0x1` → `d ∈ {1,5,9,d}`（4 个）
  - `c=0x7, g=0x3` → `d ∈ {3,b}`（2 个）
  - `c=0xf, g=0x7` → `d ∈ {7}`（1 个，完全确定）
  只有 `c` 的 popcount 越大、泄漏才越多。**《以为 `gift` 直接给出 key0》是最典型的错误**：本题 `gift` 里大量 nibble 是 `0`，对应位置几乎不约束。
- **考点 4：把「双射」当约束做回溯枚举（nibble 双射回溯）**。按 `key1` 的取值把 32 个位置分组（本题 14 组），对每组求候选集合交集，再对 14 个组做**带回溯的完美匹配**（不同组必须拿到不同数字）。本题共 **43,128** 个满足 ①② 的 `key0` 候选——这就是搜索空间。
- **考点 5：利用"双重加密其实是恒等链"把候选筛成唯一解**。`cipher = AES⁻¹_{key1,IV=key0}( AES_{key0,IV=key1}(pad(flag)) )`，所以
  `P = AES⁻¹_{key0,IV=key1}( AES_{key1,IV=key0}(cipher) )`。对 43,128 个候选逐个解密，**用两条判据一步定位真解**：
  1. **明文全部可打印 ASCII**（正确的 `flag{...}` 恰好 42 B 全可打印；次优候选最高只有 31 B 可打印）；
  2. **PKCS#7 padding 恰好是 `0x06 × 6`**（`42 + 6 = 48`，与密文长度自洽）。
  两条同时成立的只有一个 → `key0 = bafc950d1dc9ba75da1e56da4b187b6a`。
- **考点 6：交叉验证 `gift`**。真解必须满足 `int(key0,16) & int(key1,16) == gift`（即 `0xbafc…` & `0x74ae…` == gift）；这把"猜中的明文"与"结构正确的密钥"绑在一起，排除巧合。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出：把"密钥空间 2^128 不可搜"降级成"约束回溯 + 一次筛选"**。出题人给了三样东西——`key1`（明文）、`gift`（部分信息）、`cipher`（密文）——但它们单独都不够：`key1` 不给 `key0`；`gift` 只给逐 nibble 的 AND；`cipher` 又依赖 `key0` 与 `key1` 双密钥。**只有把三者和"`π` 必须是双射"这一结构性事实拼起来**，搜索空间才从 `2^128` 塌缩到 4 万级。这是一道典型的"**信息拼图**"题。
- **难度卡点设计在哪**：
  1. **必须意识到 `key1[i] = π(key0[i])` 的"双射"性质**。`permutation()` 的实现是"洗牌 + 按位查表"，读代码容易误以为只是"逐位替换"（**单射**），从而漏掉"不同 `key1` 值不能映射到同一 `key0` 值"这条**关键的互斥约束**——漏了它候选数会爆炸，或枚举出不合法（非双射）的 key0。
  2. **必须正确理解 `gift` 的粒度**：它是 **128 位整数按位与**，逐 nibble 对齐；若误按"整数字节"或"字符串"处理就会算错位置。同时必须接受"很多 nibble 的约束是平凡的（`c=0` 时 16 选 1）"。
  3. **必须想清楚"怎么从 4 万候选里挑一个"**。没有额外明文校验位，唯一可用的判据就是**可打印性 + PKCS#7 padding**；本题 `pad()` 对 42 B 明文补 `0x06×6`，`padding 必须是 0x06 六个字节` 这条判据非常干净（次优候选的可打印字节数只有 31，且 padding 全部不合法）。
  4. **必须识别并剔除"恒等置换"这个伪解**。当 `π = id` 时 `key1 == key0`，`encrypt()` 变成 `Dec_{k}(Enc_{k}(m)) = m`，于是 `cipher == pad(flag)` ⇒ **`cipher` 本身会被当成"明文"输出**。比赛期间的探索脚本 `c02_out.txt` 里 cand6 就是这种情况（`key0 = 74aeb356c6eb74f364cd316497c0f714 == key1`，`pt` 逐字节等于 `cipher`）。恒等置换在 `16!` 里只占 1 种，但因为它天然"自洽"（`gift = a0 & a1 = a0` 也成立），**不显式排除就会误导**。
  5. **`key1` 的值分布决定了候选数**。本题 `key1 = 74aeb356c6eb74f364cd316497c0f714` 只用到了 14 个不同 nibble（缺 `2` 和 `8`），使双射约束的搜索宽度变小；这解释了为什么候选数恰好是 43,128 这个量级而不是更大。
- **干扰项 / 诱导项**：
  - **`cipher` 是"二次加密"**：注释写「先加密后解密生成密文」（`aes1.decrypt(aes0.encrypt(msg))`），字面看起来像"解密"；实际语义是 `Enc_{key1,IV=key0}⁻¹ ∘ Enc_{key0,IV=key1}`。**方向搞反（用 `Dec∘Enc` 而不是 `Dec∘Enc` 的正确配对，或把两个 key 的角色对调）会永远得不到可打印明文**。
  - **IV 与 Key 交叉使用**：`aes0 = AES.new(key0, CBC, key1)`、`aes1 = AES.new(key1, CBC, key0)`——**`key0` 同时是"密钥"和"另一个实例的 IV"**。这在实现上意味着"`key0` 与 `key1` 都必须先猜对"，但也意味着**两者都不能单独解出**，是个"看起来双保险其实单点"的设计。
  - **注释里的中文**（「假设为明文」「随机打乱表」）是出题人写的说明，**不是提示**；不要从措辞里过度解读。
  - `print(f"gift = {gift}")` 等三行 print 与末尾注释里的三行数据**重复**，容易诱导解题者以为"注释里是另一组数据"。
- **哪些地方是"必须踩坑才会发现"的**：
  1. `flag` 是 `bytes`（`pad()` 里 `msg + bytes(...)`）；重建 `secret.py` 时写成 `str` 会立刻 `TypeError`（本仓库实测踩到）。
  2. 从 `task.py` 的**注释**里抽 `cipher` 不能简单用正则抠 hex：字节字面量里混有**可打印字符**（`L`、`|`、`>`、`^`、`~`、`X`、`R`、`Z`、空格、`)` 等），必须按转义规则扫描整个 `b'...'` 字面量再 `ast.literal_eval`（本仓库第一版正则因此抽不到、已修复）。
  3. `key1` 在注释里**没有加引号**（`key1 = 74ae...`），照抄"字符串必须带引号"的正则会 miss（本仓库实测踩到）。
  4. 用 PowerShell `>` 重定向 `task.py` 输出得到的是 **UTF-16LE+BOM**，按 UTF-8 正则抽参会 `AttributeError`（本仓库已内置 UTF-16 兼容读取）。
  5. 候选数会随实例变化（本题 43,128）；**不要**把它当硬编码常量——`solve/solve.py` 只把它当"一致性提示"打印。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察**：解 zip，附件只有 `task.py`；从末尾注释抠出 `gift` / `key1` / `cipher`。
   ```bash
   python -c "import zipfile;print(zipfile.ZipFile('attachments/crypto02.zip').namelist())"
   # -> ['task.py']
   ```
   ```
   gift   = 64698960125130294692475067384121553664   # = 0x30ac910404c93071400c104003007300
   key1   = 74aeb356c6eb74f364cd316497c0f714
   cipher = 36bf9bb19314829aa4c2afd04cadbb350e7c3e8c7cf05e646c7e58c752ca5aab16be2072f6506ce093fc290e938ed3d6
   ```
2. **定性**：读代码判定——`key1` 已知；`permutation()` 是 **16 个 hex 数字上的随机双射**；`gift` 是 **逐 nibble 的 AND**；`cipher` 需要**两个** key 才能解。⇒ 判定为"**约束回溯 + 候选筛选**"，不做任何字典/暴力爆破。
3. **把 `gift` 展开成逐 nibble 约束**（`gh = "%032x" % gift`）：
   ```
   gift hex = 30ac910404c93071400c104003007300
   ```
4. **按 `key1` 取值分组求候选集合**（关键：`d & c == g` 只锁 `c` 的 1 位）：
   ```
   key1 nibble 0 (0x0)  gift∈{0} -> key0 nibble ∈ {0,1,...,f}      (16 选)
   key1 nibble 1 (0x1)  gift∈{0} -> key0 nibble ∈ {0,2,4,6,8,a,c,e}
   key1 nibble 3 (0x3)  gift∈{1} -> key0 nibble ∈ {1,5,9,d}
   key1 nibble 4 (0x4)  gift∈{0} -> key0 nibble ∈ {0,1,2,3,8,9,a,b}
   key1 nibble 5 (0x5)  gift∈{0} -> key0 nibble ∈ {0,2,8,a}
   key1 nibble 6 (0x6)  gift∈{4} -> key0 nibble ∈ {4,5,c,d}
   key1 nibble 7 (0x7)  gift∈{3} -> key0 nibble ∈ {3,b}
   key1 nibble 9 (0x9)  gift∈{0} -> key0 nibble ∈ {0,2,4,6}
   key1 nibble a (0xa)  gift∈{a} -> key0 nibble ∈ {a,b,e,f}
   key1 nibble b (0xb)  gift∈{9} -> key0 nibble ∈ {9,d}
   key1 nibble c (0xc)  gift∈{0} -> key0 nibble ∈ {0,1,2,3}
   key1 nibble d (0xd)  gift∈{c} -> key0 nibble ∈ {c,e}
   key1 nibble e (0xe)  gift∈{c} -> key0 nibble ∈ {c,d}
   key1 nibble f (0xf)  gift∈{7} -> key0 nibble ∈ {7}          (唯一确定)
   ```
5. **回溯枚举（加"双射"约束）→ 43,128 个 `key0` 候选**（`key1` 只用了 14 个不同 nibble 值 ⇒ 14 层回溯，同层互斥）：
   ```python
   def rec(i, used, assign):          # vals = sorted(set(key1))
       if i == len(vals):
           out.append("".join("%x" % assign[key1[j]] for j in range(32))); return
       v = vals[i]
       for d in val_c[v]:
           if d in used: continue
           used.add(d); assign[v] = d
           rec(i + 1, used, assign)
           used.discard(d)
   ```
6. **逐个候选解密 + 双判据筛选**：
   ```python
   P = AES.new(K0, AES.MODE_CBC, K1).decrypt( AES.new(K1, AES.MODE_CBC, K0).encrypt(cipher) )
   # 判据 ①: 明文全可打印 ASCII
   # 判据 ②: PKCS#7 padding 恰为 0x06 * 6
   ```
   实测排序结果（按可打印字节数）：
   | 名次 | key0 | 可打印字节数 | PKCS#7 | 明文 |
   |------|------|--------------|--------|------|
   | **1** | **`bafc950d1dc9ba75da1e56da4b187b6a`** | **42 / 42** | **True (pad=0x06)** | `flag{886769b5-2301-4c37-bb73-4480b4eab682}` + `\x06×6` |
   | 2 | `b8acd12535cdb871583e10584b367b08` | 31 | False | 乱码 |
   | 3 | `b9fcd18505cdb971590e1a596b047ba9` | 30 | False | 乱码 |
   | … | … | ≤30 | False | 乱码 |
7. **交叉验证**：`int('bafc950d1dc9ba75da1e56da4b187b6a',16) & int('74aeb356c6eb74f364cd316497c0f714',16) == gift` ✔
8. **取 flag & 提交**：`flag{886769b5-2301-4c37-bb73-4480b4eab682}`，17:01:41 平台返回 `code=0 message=恭喜您，回答正确`。

## 6. 参考解法（代码）

完整可跑脚本：`solve/solve.py`（已实测；枚举 + 43128 次 AES 链解密，秒级完成）。核心片段：

```python
from Crypto.Cipher import AES
from collections import defaultdict

KEY1   = "74aeb356c6eb74f364cd316497c0f714"
GIFT   = 64698960125130294692475067384121553664
CIPHER = bytes.fromhex("36bf9bb19314829aa4c2afd04cadbb350e7c3e8c7cf05e646c7e58c752ca5aab"
                       "16be2072f6506ce093fc290e938ed3d6")

# ① 逐 nibble 约束: key0_i = d 且 (d & key1_i) == gift_i
gh = "%032x" % GIFT
groups = defaultdict(list)
for i in range(32):
    groups[KEY1[i]].append(i)
val_c = {}
for v, idxs in groups.items():                       # 同一 key1 值的所有位置取交集
    s = set(d for d in range(16) if (d & int(v, 16)) == int(gh[idxs[0]], 16))
    for i in idxs[1:]:
        s &= set(d for d in range(16) if (d & int(KEY1[i], 16)) == int(gh[i], 16))
    val_c[v] = sorted(s)

# ② 双射 → 回溯（不同 key1 值必须拿到不同数字）
vals, out = sorted(val_c), []
def rec(i, used, assign):
    if i == len(vals):
        out.append("".join("%x" % assign[KEY1[j]] for j in range(32))); return
    v = vals[i]
    for d in val_c[v]:
        if d in used: continue
        used.add(d); assign[v] = d; rec(i + 1, used, assign); used.discard(d)
rec(0, set(), {})
print("candidates:", len(out))                       # -> 43128

# ③ 逐个解密 + 双判据
K1 = bytes.fromhex(KEY1)
for k0 in out:
    K0 = bytes.fromhex(k0)
    pt = AES.new(K0, AES.MODE_CBC, K1).decrypt(AES.new(K1, AES.MODE_CBC, K0).encrypt(CIPHER))
    pad = pt[-1]
    if pt[-pad:] == bytes([pad]) * pad and pad == 6 and all(32 <= x < 127 for x in pt[:-pad]):
        print("key0 =", k0); print(pt[:-pad].decode()); break
# key0 = bafc950d1dc9ba75da1e56da4b187b6a
# flag{886769b5-2301-4c37-bb73-4480b4eab682}
```

实测输出（节选）：

```
[*] gift   = 64698960125130294692475067384121553664  (hex 30ac910404c93071400c104003007300)
[*] key1 的 14 个不同 nibble 值 -> 各自候选集合 (逐 nibble AND 约束): ...
[*] 满足『逐 nibble AND 约束 + 双射』的 key0 候选数 = 43128
[*] 与比赛期间实测候选数一致 (43128) OK
    key0=bafc950d1dc9ba75da1e56da4b187b6a score=42 pkcs7=True(pad=0x06) pt=b'flag{886769b5-...}\x06\x06\x06\x06\x06\x06'
[+] key0 = bafc950d1dc9ba75da1e56da4b187b6a
[+] FLAG = flag{886769b5-2301-4c37-bb73-4480b4eab682}
```

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{886769b5-2301-4c37-bb73-4480b4eab682}` |
| 提交接口返回 | `code=0, message="恭喜您，回答正确"`（无人值守 Supervisor 账本原文：`{"type": "submit", "qid": "CrpMu5aVJdYVf9zK", "kind": "ok", "result": {"code": 0, "message": "恭喜您，回答正确"}}`） |
| 提交时间 | 2026-09-14 17:01:41 |
| 证据文件 | ① `D:\qwb_work\agent\ledger.jsonl` 第 86/87/88 行（`worker_done status=solved` 17:01:38 → `flag_found` → `submit` 17:01:41）；② `work\flags\CrpMu5aVJdYVf9zK.txt`；③ `赛道二测试记录.md` §〇.3（门禁 ✅）；④ 本地解密实证 `work\r3_crypto\c02_out2.txt` / `real.txt`（`total candidates: 43128`） |
| 提交 URL 形态 | `/ff874ef3172cbf4fd6ec2c5653a568e2?token=&question_id=CrpMu5aVJdYVf9zK&answer=<flag>` |
| 本地复现 | `python solve/solve.py` → `[+] key0 = bafc950d1dc9ba75da1e56da4b187b6a` / `[+] FLAG = flag{886769b5-2301-4c37-bb73-4480b4eab682}`（2026-09-21 实测通过） |

> **证据链诚实说明（重要）**：本题的提交**不在** `work\submit_results_live.json` 里（该文件只收录了 19 条会话侧提交，
> 含环节二的 crypto01 `Adbvf8bTTCGF4LLU` 但不含本题）。本题是由**无人值守 worker** 在 17:01:38 独立解出、
> 17:01:41 经 Supervisor 提交的，因此权威证据是 `D:\qwb_work\agent\ledger.jsonl` 的 `submit` 记录
> （`code=0`、`message="恭喜您，回答正确"`）与该 worker 的 `notes` 字段。
> 另有两点如实记录：① 该 `submit` 记录带一个 Supervisor 内部字段 `"accepted": false`，
> 其语义在当前源码 `qwb_agent.py` 里已查不到对应实现，**平台侧判定以 `code=0 / 回答正确` 为准**；
> ② worker `notes` 里写的中间计数是「86256 valid q」，而会话侧脚本实测的最终候选数是 **43128**（`real.txt` 第 1 行），
> 二者恰好差 2 倍（应为计数阶段/去重口径不同），本 README 一律采用**可复现的 43128**。

## 8. 还原说明（诚实写）

- **已有原始件**：
  - `attachments/crypto02.zip` —— 平台下发的**原始附件**，逐字节归档（1,207 B；md5 `f6e278d8b57051867cc99e8d5f70597d`，sha256 `dd5281828fcbb677b24ecd5b95bee907e0fac8240fc14d2ba394de618b8aa362`）。下载记录见 `决赛\work\r3_crypto\dl.py` / `dl_out.txt`（HTTP 200，`Content-Type: application/zip`）。
  - `attachments/task.py` = `deploy/src/task.py` —— zip 内 `task.py` 的**原样解出**（1,914 B，md5 `7d3d7b38b57752b69fcf3905ebc2a9fb`），即题目本体/出题脚本。
  - `solve/solve.py` —— 参考解法，源自比赛期间的 `work\r3_crypto\c02_solve3.py`，已重写为**可移植、参数化**（`--from-file/--key1/--gift/--cipher/--top/--out`），并补上：候选数一致性提示、`--from-file` 对 `task.py` 注释的稳健解析（`ast.literal_eval` 扫字节字面量）、UTF-16 兼容读取。
  - 比赛期间的过程与证据：`work\r3_crypto\c02_out2.txt`（40 个候选排序，第 1 名即真解）、`real.txt`（`total candidates: 43128`）、`c02_out.txt`（早期探索脚本的 6 个候选，含恒等置换伪解）。
- **重建部分（明确标注为重建，非平台原件）**：
  - `deploy/src/secret.py` —— 附件**未下发** `secret.py`，此文件为**重建**：内容仅 `flag`（比赛真实 flag 的 `bytes`）。它不影响题目可解性（`key0`/`key1` 由 `task.py` 随机生成），只决定明文内容。
  - `deploy/README.md` —— 重建件，说明复现与"换 flag 出新题"。
- **未能还原**：无关键缺失。唯一非原件是 `secret.py`（平台未下发、且只含 flag），已明确标注。
- **本题的"可复现性"特殊之处**：`task.py` 里 `key0 = os.urandom(16).hex()`、`random.shuffle()` 未播种 ⇒ **每次执行都天然是一道新题**（新 `key0`/`key1`/`gift`/`cipher`，flag 不变）。
- **可复现性验证**（均已实测）：
  1. `cd timu/round3_1700/crypto02 && python solve/solve.py`
     → 候选数 `43128`（与比赛实测一致）→ `key0 = bafc950d1dc9ba75da1e56da4b187b6a` → `FLAG = flag{886769b5-2301-4c37-bb73-4480b4eab682}`。
  2. `python solve/solve.py --from-file attachments/task.py` → 同样结果（验证"从出题脚本注释抽参"这条路径）。
  3. `cd deploy/src && python task.py` → 得到**新实例**（`gift = 256644849916144867381658643245385647108`、`key1 = c11e54fa64b8929f3fdab1aacbb6fefe`、新的 `cipher`）；
     `python ../../solve/solve.py --from-file <新实例输出>` → `key0 = e774230f13a9b5b0d0cfa7ffeaa10404`，成功恢复同一 flag ⇒ **端到端闭环**。
- **一处与快照的差异（诚实标注）**：平台快照 `challenges_r3.json` 抓取于解题之前，其中本题 `"is_solved": false, "solved_number": 0`；`challenge.json` 按规范填写**比赛期间的真实结果** `is_solved: true`（依据 ledger 的 `submit code=0` 与 `赛道二测试记录.md` 门禁 ✅）。

## 9. 复现步骤

```bash
cd timu/round3_1700/crypto02
pip install -r solve/requirements.txt      # pycryptodome

# ① 直接解原始实例（内嵌 gift/key1/cipher，秒级）
python solve/solve.py

# ② 从原始附件 task.py 抽参解（验证注释解析路径）
python solve/solve.py --from-file attachments/task.py

# ③ 显式传参 / 落盘
python solve/solve.py --key1 74aeb356c6eb74f364cd316497c0f714 \
                      --gift 64698960125130294692475067384121553664 \
                      --cipher 36bf9bb19314829aa4c2afd04cadbb350e7c3e8c7cf05e646c7e58c752ca5aab16be2072f6506ce093fc290e938ed3d6 \
                      --top 20 --out result.txt

# ④ 生成并解一道新实例（闭环验证）
cd deploy/src && python task.py > /tmp/inst.txt 2>&1
python ../../solve/solve.py --from-file /tmp/inst.txt
```

期望输出（①/②）：

```
[*] 满足『逐 nibble AND 约束 + 双射』的 key0 候选数 = 43128
[+] key0 = bafc950d1dc9ba75da1e56da4b187b6a
[+] 明文 = b'flag{886769b5-2301-4c37-bb73-4480b4eab682}\x06\x06\x06\x06\x06\x06'  (PKCS#7 padding = 0x06 × 6)
[+] FLAG = flag{886769b5-2301-4c37-bb73-4480b4eab682}
```

依赖：Python 3.9+、`pycryptodome`（AES-128-CBC）。**无需 gmpy2/sympy/z3/网络。**

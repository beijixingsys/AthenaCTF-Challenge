# crypto01 · RSA 特殊结构攻击（p=2gα+1 / q=2gβ+1 → 小阶元素分裂 n）

| 项 | 值 |
|----|----|
| 轮次 | 环节三（17:00） |
| 平台题目名 | crypto01 |
| 比赛 qid | aE9BLf9fMqMPag7T |
| 分类 | crypto |
| 分值 | 500 |
| 交互型 | false（静态附件） |
| 关键 flag | `flag{36e3ac06db2f4b6693b6203b5a7b0c47}` |
| 是否解出 | 已解出（17:11:22 提交，平台返回 `code=0 message=恭喜您，回答正确`） |
| **还原完整度** | **A**（原始附件逐字节归档 + 出题脚本 `task.py` 原样可跑 + `solve/solve.py` 已实测复现 flag + 可重跑生成新实例） |

## 1. 题面（比赛原文，逐字保留）

（平台 description 为空）

平台 `challenges_r3.json` 中本题 `"description": ""`，无 `/hint` 文本。**题面就是附件本身**：附件唯一真实文件是出题脚本 `task.py`，数据以**文件末尾注释**的形式给出：

```python
from Crypto.Util.number import *
import gmpy2
from secret import flag,alpha,beta,g

m = bytes_to_long(flag)
e = 0x10001

assert alpha.bit_length() == beta.bit_length() == 24
assert g.bit_length() == 575
assert GCD(alpha,beta) == 1
p = 2*g*alpha+1
q = 2*g*beta+1
assert isPrime(g) == isPrime(p) == isPrime(q) ==1
n = p*q
c = pow(m,e,n)

print("n=",n)
print("c=",c)

'''
n=7291079313308676175175230422086906986296185082644647473960832422555800048359693211245839442369670028931769993263140869765778275923238998260803976729216289550292957705978682342093105097819370971295310860873669725515021912668386895781458555148835312190129315078660321668053910979825522489767263648850838063570709547440063938943646651772164530633522199339380882021
c=6852815582847351113509942128109481399896904701205184324498219416217713791422045750671866168086014291595924213741129903103633649030030862155462156567674060259236309618154155879167135323181060411408641918545728735975727426628455883980762998117953708039752390223308664385975029727270659931396150824601346207643504567598401379829379513077614506465772564081039622555
'''
```

`secret.py`（含 `flag` / `alpha` / `beta` / `g`）**未随附件下发**；flag 在平台运行时注入。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | `crypto01.zip`，1,118 B，ZIP（deflate）；内含 `task.py`（1,122 B）+ macOS 元数据 `__MACOSX/._task.py`（177 B） |
| 容器 | 无（纯静态附件题，`interactive: "false"`，`connection: []`） |
| 原始 file_url | `https://g.ichunqiu.com/terminator/production/match_question/202609/373ab36506931e28f23987be80507c2e.zip` |
| 附件存放 | `attachments/crypto01.zip`（原始件，未改字节；md5 `03e6f53446009540924a11be84dbd196`，sha256 `afb588b18dc55592dde762a6597e8d80eec5d341eb03ea5307e40245114e45bf`） |
| 解包件 | `attachments/task.py`（从 zip 原样解出；md5 `7e469a7fd03ca4f5bfd7c7fb33a9792b`），`deploy/src/task.py` 同字节 |
| 出题侧补件 | `deploy/src/secret.py`（**反推重建**的老实例 secret）、`deploy/src/gen_secret.py`（新实例生成器）、`deploy/src/verify_instance.py`（一致性校验） |
| 数据规模 | `n` 1199 bit，`c` 1199 bit，`p`/`q` 各 600 bit，`g` 575 bit，`α`/`β` 各 24 bit |

> 说明：下载时需带 `Referer: https://match.ichunqiu.com/` + 浏览器 UA，否则会被云防御拦截返回 7383 B 的 HTML 错误页（见 `决赛\AGENTS.md` 卡片 27）。

## 3. 考点（★核心）

- **考点 1：RSA 的「阶攻击 / order attack」——利用 `p-1`、`q-1` 的已知小因子结构**。题目把 `p-1 = 2·g·α`、`q-1 = 2·g·β` 里的 `α`、`β` 限制为 **24 bit**，于是 `Z_p^*`/`Z_q^*` 里存在**阶极小的元素**，`gcd(A^t − 1, n)` 可以在 `t < 2^24` 内分裂 `n`。这是"部分因式分解泄漏（partial factorization of p−1）"在 RSA 上的标准打法，与 Pollard p−1 同源。
- **考点 2：`n−1 ≡ q−1 (mod p−1)` 这一同余恒等式构造小阶元素**。取 `A = a^(n−1) mod n`（`a` 取小素数）：
  - 在 `mod p` 下 `A ≡ a^(q−1)`，因为 `n−1 = pq−1 ≡ q−1 (mod p−1)`，由 Fermat 降阶得 `ord_p(A) | (p−1)/gcd(q−1, p−1) = 2gα/(2g·gcd(α,β)) = α`；
  - 同理 `ord_q(A) | β`。
  - `gcd(α,β)=1` ⇒ **两个阶互素**，且都 `< 2^24` ⇒ 首次命中即为 `min(ord_p, ord_q) < 2^24`。
- **考点 3：为什么"扫到 2^24 就一定够"**。`t` 只要撞上任一侧的阶就能分裂；而"同时撞上两侧的阶"需要 `t` 是 `ord_p·ord_q`（互素阶 ⇒ lcm = 乘积）的倍数，量级 ≈ `2^47`，远超 `2^24`。因此 `2^24` 的扫描区间**在数学上被保证**存在一个 `t` 使 `1 < gcd(A^t−1, n) < n`。这一步是整道题的"钥匙孔"。
- **考点 4：批量 gcd 的工程优化**。单点 `gcd` 每步一次太慢（2^24 次 1200 bit gcd）。正解是**累积 `∏(A^t − 1) mod n`，每 8192 步做一次 `gcd`**，命中后再在本批内二分定位精确 `t`。本题实测 `t = 11192429`，总耗时约 20~25 s（Python + gmpy2）。
- **考点 5：出题脚本给出的全部约束都是"攻击可用信息"**。`assert` 里的 `24 bit`、`575 bit`、`GCD(alpha,beta)==1`、`g/p/q` 皆素数，既定义了题目结构，也**直接告诉了攻击者攻击窗口的边界**（`2^24`）——这是"结构即泄漏"的典型。
- **考点 6：拿到 `p`、`q` 之后回归常规 RSA**。`φ = (p−1)(q−1)`、`d = e⁻¹ mod φ`、`m = c^d mod n`（`e = 0x10001`）。**本题不需要 Coppersmith、不需要格、不需要侧信道**——难点只在"怎么快速分出因子"。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出：把"RSA 难分解"的前提**从"`n` 太大"**换成"`n` 够大但两侧的群阶都有小因子"**。`n` 是实打实的 1199 bit（`p`、`q` 各 600 bit），常规 ECM/GNFS/Pollard-rho 全部无效；但只要 `p−1`、`q−1` 里共同挂着同一个 575 bit 的 `g`，而各自的余因子只有 24 bit，就出现了一条**和 `n` 的位长无关**的快速通道。出题人考的不是"会不会用 yafu"，而是"**会不会读 `p−1`、`q−1` 的结构**"。
- **难度卡点设计在哪**：
  1. **必须想到用 `a^(n−1) mod n` 而不是 `a^((p−1)/2)`**。`p`、`q` 是未知量，唯一已知的"全局指数"就是 `n−1`；能否想到 `n−1 ≡ q−1 (mod p−1)` 这一步，是本题的思维分水岭。
  2. **必须算清"扫到多大"**。`α`、`β` 各 24 bit ≠ 阶就是 24 bit，但 `ord_p(A) | α` 且 `ord_q(A) | β` ⇒ 首命中 `< 2^24`。若误以为要扫 `α·β ≈ 2^48` 就会直接放弃——这是最典型的"以为不能做"陷阱。
  3. **必须做批量 gcd**。朴素 `for t in range(2**24): gcd(pow(A,t,n)-1, n)` 在 Python 下要几十分钟到几小时；`∏(A^t−1) mod n` + 每 8192 步一次 gcd 把同余类 gcd 的开销从 O(2^24) 次降到 O(2^11) 次。
  4. **必须处理"整批 gcd == n"的边界**（该批内 `t` 同时是两侧阶的倍数，或积里混入多个因子）——正解要在本批内**二分回查**而不能直接跳过，否则会漏解。
- **干扰项 / 诱导项**：
  - `g.bit_length() == 575` 而 `α`、`β` 只有 24 bit，**看起来像"`n` 里有 575 bit 的公因子泄漏"**（诱导去 `gcd(n, ...)` 找 `g`）——但 `g` 是 `p−1`、`q−1` 的因子，**不在 `n` 里**，直接找 `g` 一定失败。
  - `assert GCD(alpha,beta) == 1` 看起来只是"让 `p≠q`"的例行检查，实际上是**攻击可行性的核心前提**（互素 ⇒ 两个阶互素 ⇒ 首次命中必然是单侧分裂）。忽略它就会怀疑"命中时 gcd 会不会直接等于 n"。
  - `assert isPrime(g) == isPrime(p) == isPrime(q) == 1` 里 `==1` 的链式比较写法（Python 里等价于 `isPrime(g)==1 and isPrime(p)==1 and isPrime(q)==1`）容易看错，但不影响解题。
  - 附件里带了一个 `__MACOSX/._task.py`（macOS 打包残留的 AppleDouble 元数据），**是噪声**，不是隐藏提示；不要在这上面花时间。
- **哪些地方是"必须踩坑才会发现"的**：
  1. `secret.py` 未下发 ⇒ **不能靠"重跑 task.py 得到 n/c"来验证思路**，只能拿注释里的 n/c 当输入。解题脚本必须支持从"注释文本"里抽 `n=`/`c=`。
  2. `flag` 在 `secret.py` 里是 **`bytes`** 而非 `str`（`task.py` 直接 `bytes_to_long(flag)`）。这一点在重建 `secret.py` 时会立刻以 `TypeError: can't concat str to bytes` 暴露（本仓库实测踩到）。
  3. 用 PowerShell `>` 重定向 `task.py` 的输出会写成 **UTF-16LE+BOM**，直接按 UTF-8 正则抽 `n=`/`c=` 会抽不到（`AttributeError: 'NoneType'`）——本仓库 `solve/solve.py` 已内置 UTF-16 兼容读取（实测踩到并修复）。
  4. 命中的 `t = 11192429` **恰好等于 `α`**（即 `ord_p(A) = α` 而非其真因子）；这既验证了理论，也说明"`α` 是素数性的随机 24 bit 数"时阶通常就是 `α` 本身。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察**：解 zip，发现附件只有 `task.py`（出题脚本），`secret.py` 未下发；把 `task.py` 末尾注释里的 `n`、`c` 抠出来。
   ```bash
   python -c "import zipfile;print(zipfile.ZipFile('attachments/crypto01.zip').namelist())"
   # -> ['task.py', '__MACOSX/._task.py']
   grep -ao 'n=[0-9]*' attachments/task.py
   grep -ao 'c=[0-9]*' attachments/task.py
   ```
2. **定性**：读 `assert` 行——`p = 2*g*alpha+1`、`q = 2*g*beta+1`、`alpha`,`beta` 各 24 bit、`GCD(alpha,beta)==1`。⇒ 判定为"**`p−1`/`q−1` 有小因子结构**"，直接上**阶攻击**，不做通用分解。
3. **突破（核心 3 行）**：
   ```python
   A = pow(a, n - 1, n)                 # a = 2 即可；A ≡ a^(q-1) mod p, A ≡ a^(p-1) mod q
   # ord_p(A) | alpha < 2^24 ,  ord_q(A) | beta < 2^24 ,  gcd(alpha,beta)=1
   # 扫 t = 1..2^24, 取 gcd(A^t - 1, n) != 1  →  该 gcd 就是 p
   ```
4. **批量加速 + 精确定位**：
   ```python
   LIM, BATCH = 1 << 24, 8192
   cur, acc, t = A, 1, 0
   while t < LIM:
       step = min(BATCH, LIM - t)
       for _ in range(step):
           cur = cur * A % n
           acc = acc * (cur - 1) % n       # 累积 ∏(A^t - 1) mod n
       t += step
       if gmpy2.gcd(acc, n) != 1:          # 本批有命中 → 二分回查精确 t
           s = t - step; c2 = pow(A, s, n)
           for u in range(1, step + 1):
               c2 = c2 * A % n
               g2 = gmpy2.gcd(c2 - 1, n)
               if 1 < g2 < n:
                   p = g2; break
           break
       acc = 1
   ```
   实测：`a = 2`，**`t = 11192429`** 命中，`p = gcd(A^t − 1, n)`，阶攻击本身耗时约 **20~25 s**（加上结构自验里反推 `g/α/β` 的 24 bit 扫描，`solve/solve.py` 端到端约 **30 s**）。
5. **结构自验（确认解对了）**：
   ```
   p bits=600  q bits=600
   p-1 = 2^1 * <599 bit>   q-1 = 2^1 * <599 bit>
   => g     = 110462645952304376492416975572266047977803453469943301327121055895546510153496334347645947622452990042724210729807062181698185348120422533212285959796650722891254313826359137   (575 bit, prime=True)
   => alpha = 11192429  (24 bit)   beta = 13346783  (24 bit)   gcd=1
   => p == 2*g*alpha+1 : True      q == 2*g*beta+1 : True
   ```
   注意 `alpha == t == 11192429`：**阶攻击命中的 `t` 就是 `α` 本身**，与理论完全吻合。
6. **取 flag（常规 RSA）**：
   ```python
   phi = (p - 1) * (q - 1)
   d = pow(0x10001, -1, phi)
   m = pow(c, d, n)
   print(m.to_bytes((m.bit_length() + 7) // 8, 'big'))
   # b'flag{36e3ac06db2f4b6693b6203b5a7b0c47}'
   ```
7. **提交**：2026-09-14 17:11:22，平台返回 `code=0 message=恭喜您，回答正确`。

## 6. 参考解法（代码）

完整可跑脚本：`solve/solve.py`（已实测，端到端约 30 s，其中阶攻击 25.3 s）。核心片段：

```python
import gmpy2
from gmpy2 import mpz

n = mpz("7291079313308676175175230422086906986296185082644647473960832422555800048359693211245839442369670028931769993263140869765778275923238998260803976729216289550292957705978682342093105097819370971295310860873669725515021912668386895781458555148835312190129315078660321668053910979825522489767263648850838063570709547440063938943646651772164530633522199339380882021")
c = mpz("6852815582847351113509942128109481399896904701205184324498219416217713791422045750671866168086014291595924213741129903103633649030030862155462156567674060259236309618154155879167135323181060411408641918545728735975727426628455883980762998117953708039752390223308664385975029727270659931396150824601346207643504567598401379829379513077614506465772564081039622555")
e = 0x10001

# ---- 阶攻击: 扫 t=1..2^24, 批量 gcd ----
A = int(gmpy2.powmod(2, n - 1, n))          # ord_p(A) | alpha, ord_q(A) | beta
LIM, BATCH = 1 << 24, 8192
cur, acc, t, p = mpz(A), mpz(1), 0, None
while t < LIM and p is None:
    step = min(BATCH, LIM - t)
    for _ in range(step):
        cur = cur * A % n
        acc = acc * (cur - 1) % n
    t += step
    if int(gmpy2.gcd(acc, n)) != 1:         # 本批命中 → 二分/线性回查精确定位
        s, c2 = t - step, gmpy2.powmod(A, t - step, n)
        for u in range(1, step + 1):
            c2 = c2 * A % n
            g2 = int(gmpy2.gcd(c2 - 1, n))
            if 1 < g2 < n:
                p, t_hit = g2, s + u
                break
    acc = mpz(1)
print("FOUND t =", t_hit)                   # 11192429

q = n // p
d = gmpy2.invert(e, (p - 1) * (q - 1))
m = int(gmpy2.powmod(c, d, n))
print(m.to_bytes((m.bit_length() + 7) // 8, "big"))
# b'flag{36e3ac06db2f4b6693b6203b5a7b0c47}'
```

实测输出（节选）：

```
[*] n bits=1199  c bits=1199  e=0x10001
  base 2: t=10485760 (23.5s)
  base 2: FOUND t=11192429  p=gcd(A^t-1, n)  (25.3s)
[*] p bits=600  q bits=600
      => g=...137 (bit=575, prime=True)
      => alpha=11192429 (bit=24)   beta=13346783 (bit=24)   gcd=1
      => p == 2*g*alpha+1 : True   q == 2*g*beta+1 : True
[*] m bytes = b'flag{36e3ac06db2f4b6693b6203b5a7b0c47}'
[+] FLAG = flag{36e3ac06db2f4b6693b6203b5a7b0c47}
```

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{36e3ac06db2f4b6693b6203b5a7b0c47}` |
| 提交接口返回 | `code=0, status=null, message="恭喜您，回答正确"`（`pass=true`） |
| 提交时间 | 2026-09-14 17:11:22 |
| 证据文件 | `D:\2026\湾区杯\决赛\work\submit_results_live.json` 中 `qid: aE9BLf9fMqMPag7T` 记录；`work\flags\aE9BLf9fMqMPag7T.txt`；`赛道二测试记录.md` §〇.3（门禁 ✅） |
| 提交 URL 形态 | `/ff874ef3172cbf4fd6ec2c5653a568e2?token=&question_id=aE9BLf9fMqMPag7T&answer=<flag>` |
| 本地复现 | `python solve/solve.py` → `[+] FLAG = flag{36e3ac06db2f4b6693b6203b5a7b0c47}`（2026-09-21 实测通过，端到端约 30 s，阶攻击 25.3 s） |

## 8. 还原说明（诚实写）

- **已有原始件**：
  - `attachments/crypto01.zip` —— 平台下发的**原始附件**，逐字节归档（1,118 B；md5 `03e6f53446009540924a11be84dbd196`，sha256 `afb588b18dc55592dde762a6597e8d80eec5d341eb03ea5307e40245114e45bf`）。下载记录见 `决赛\work\r3_crypto\dl.py` / `dl_out.txt`（HTTP 200，`Content-Type: application/zip`）。
  - `attachments/task.py` = `deploy/src/task.py` —— zip 内 `task.py` 的**原样解出**（1,122 B，md5 `7e469a7fd03ca4f5bfd7c7fb33a9792b`），即题目本体/出题脚本。
  - `solve/solve.py` —— 参考解法，源自比赛期间的 `work\r3_crypto\c01_solve.py`，已改写为**可移植、参数化**（`--n/--c/--from-file/--max-t/--batch/--out`），并加了结构自验（反推 `g/α/β`）、UTF-16 兼容读取与二分回查。
  - 比赛期间的过程日志：`work\r3_crypto\c01_out.txt`（与本次实测输出一致：`t=11192429`，`m = b'flag{...}'`）。
- **重建部分（明确标注为重建，非平台原件）**：
  - `deploy/src/secret.py` —— 附件**未下发** `secret.py`，此文件为**反推重建**：由 `p = 2gα+1`、`q = 2gβ+1`（`α,β` 24 bit、`g` 575 bit 素数）反解出
    `g = 110462645952304376492416975572266047977803453469943301327121055895546510153496334347645947622452990042724210729807062181698185348120422533212285959796650722891254313826359137`、
    `alpha = 11192429`、`beta = 13346783`，flag 由 RSA 常规解密得到。
    **已校验**：用该 `secret.py` 重跑 `task.py` 的逻辑，得到的 `n`/`c` 与原始附件注释里的 `n`/`c` **逐位一致**（`deploy/src/verify_instance.py`，实测 `True / True`）⇒ 对本实例**等价于原 `secret.py`**。
  - `deploy/src/gen_secret.py` —— 重建件，用于**生成新实例**（"重跑即出新题"）。踩坑记录：先随机 α/β 再找同时满足三重素数约束的 `g` 期望尝试 ≈ 6.4×10⁷，**实测 600 s 未出结果**；改为**先定 575 bit 素数 `g`，再分别搜 α、β**后降到 **0.57 s**（生成 575-bit g + α=14751463 + β=11501467 的新实例并成功解出）。
  - `deploy/README.md` —— 重建件，说明如何复现老实例 / 生成新实例。
- **未能还原**：无关键缺失。唯一的"非原件"是 `secret.py`（平台未下发），已用**逐位等价校验**兜住，且已在文件头与本节双重标注为重建。
- **可复现性验证**（均已实测）：
  1. `cd timu/round3_1700/crypto01 && python solve/solve.py`
     → `FOUND t=11192429` → `p bits=600 q bits=600` → `m bytes = b'flag{36e3ac06db2f4b6693b6203b5a7b0c47}'`（端到端约 30 s）。
  2. `cd deploy/src && python verify_instance.py` → `n 与原始 task.py 一致: True` / `c ... 一致: True`。
  3. `cd deploy/src && python task.py` → 打印的 `n`/`c` 与附件注释逐位相同。
  4. `python gen_secret.py --seed 20260914 --flag "flag{new-instance-test}"` → 0.57 s 生成新实例；
     `python task.py` 出新 `n`/`c`；`python solve/solve.py --from-file newout.txt` → 解出新实例的 flag（端到端闭环）。
- **一处与快照的差异（诚实标注）**：平台快照 `challenges_r3.json` 抓取于解题之前，其中本题 `"is_solved": false, "solved_number": 0`；`challenge.json` 按规范填写**比赛期间的真实结果** `is_solved: true`（依据 17:11:22 的提交回执与 `赛道二测试记录.md` 门禁 ✅）。

## 9. 复现步骤

```bash
cd timu/round3_1700/crypto01
pip install -r solve/requirements.txt      # gmpy2 pycryptodome sympy

# ① 直接解原始实例（内嵌 n/c，端到端约 30 s）
python solve/solve.py

# ② 从 task.py 的输出文件解（兼容 PowerShell `>` 产出的 UTF-16LE+BOM）
python attachments/task.py > /tmp/task_out.txt 2>&1 || true
python solve/solve.py --from-file /tmp/task_out.txt

# ③ 显式传参 / 调参
python solve/solve.py --n 7291...021 --c 6852...555 --max-t 16777216 --batch 8192 --out FLAG.txt

# ④ 校验重建的 secret.py 与原始 n/c 逐位一致
cd deploy/src && python verify_instance.py

# ⑤ 生成一道新题（重跑即出新实例）
cd deploy/src && python gen_secret.py --flag "flag{my-new-instance}" && python task.py
```

依赖：Python 3.9+、`gmpy2`（核心，批量 gcd/powmod）、`pycryptodome`（`Crypto.Util.number`，仅 `task.py` 需要）、`sympy`（仅 `gen_secret.py` 用）。

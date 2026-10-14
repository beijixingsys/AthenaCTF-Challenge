# misc02 · DNS 隧道 + 自定义 Base58 变种表 + ZipCrypto 已知明文（多层编码链）

| 项 | 值 |
|----|----|
| 轮次 | 环节三（17:00） |
| 平台题目名 | misc02 |
| 比赛 qid | urWolxzOUL4ouOER |
| 分类 | misc |
| 分值 | 500 |
| 交互型 | false（静态附件） |
| 关键 flag | **（未获取平台验证的 flag）** —— 比赛期间未解出；赛后复议把解码链 100% 打通，**2026-09-28 更把末层横幅逐字符读出 = `Flag{Crack_is_to_ezzzzzzzz}`**（8 个 z，见 §8.4），但该串从未被任何平台验证（详见 §7 / §8.2） |
| 是否解出 | **未解出**（`work\flags\urWolxzOUL4ouOER.txt` 不存在；账本两次 `worker_done` 均为 `status=timeout, flag=null`） |
| **还原完整度** | **A（原始附件原样归档 + 解码链端到端可复现；但 flag 本身未取得，见 §7/§8）** |

## 1. 题面（比赛原文，逐字保留）

平台 `description`（`challenges_r3.json`，逐字）：

> 在一个周六的21:30，运维人员监测到IDS告警。经分析攻击流量包，发现黑客采用了一种非标准的简化变种Base58编码表进行数据传输。请根据流量数据，推断其自定义编码表，并还原被窃取的信息。标准Base58编码表以CyberChef默认配置为准。

本题无 hint 文本、无容器（`interactive: "false"`，`connection: []`）。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件（平台原件） | `4ccc0b55688d4dd35cd46b9bfe36ff58.7z`，201,684 B（7z 内仅 1 个条目：`secert.pcapng` 2,406,136 B —— 文件名 `secert` 为出题人原始拼写，沿用不改） |
| 附件下载地址 | `https://g.ichunqiu.com/terminator/production/match_question/202609/4ccc0b55688d4dd35cd46b9bfe36ff58.7z` |
| 容器 | 无 |
| 附件存放 | `attachments/4ccc0b55688d4dd35cd46b9bfe36ff58.7z`、`attachments/secert.pcapng`（**原始件，未改字节**）<br>`attachments/derived/`（**加工产物**，非原始件，见下） |

**原始件（字节未改）**

| 文件 | 大小 | sha256 |
|------|------|--------|
| `attachments/4ccc0b55688d4dd35cd46b9bfe36ff58.7z` | 201,684 B | `3cd054ba91b03465cbc5a608f6f9e64ee14880fb116006737b95974029b8b129` |
| `attachments/secert.pcapng` | 2,406,136 B | `fbae95ec4c89a4c0c2174c7d76c88f56a392bbce8c050dbb9911b77b930c6735` |

**加工产物（`attachments/derived/`，由 `solve/solve.py` 生成，可删可重建）**

| 文件 | 大小 | sha256 | 说明 |
|------|------|--------|------|
| `dns_payload.base32.txt` | 66,938 字符 | `974bd3847e5f9d87b535cb678ce9b82b2f4fa6d7c1e53b2ccb1074b79e5b2b01` | 2092 条 DNS 分片按序号拼接后的 Base32 载荷 |
| `secret.zip` | 30,634 B | `739bc447089e888e56a3f4fce43973580c09abe27eaaacd41abf2015da6f7aaa` | 自定义 Base58 解码后的**真 ZIP**（内含 ZipCrypto 加密的 `secret.png`） |
| `secret_dec.png` | 30,468 B | `196bfe80aafbbdefb94cf360784085911bb8d216fe7ea1b8cda11e3a08487ef1` | bkcrack 已知明文攻击后**解出的明文 PNG**（收获的"被窃取的信息"） |
| `bkcrack_evidence.log` | — | — | 攻击/解密完整命令与输出留档 |

`secert.pcapng` 流量构成（实测）：12,100 个包，**0 个 TCP**（9745 UDP ／ 224 ARP ／ 11774 条 DNS 层，
其中 2103 查询 + 9671 响应），内网两端为 `172.25.87.197`（受害机）与 `172.25.80.1`（网关/DNS）。
2103 条查询中：2,092 条 `<N>-<32字符>.hackg.fun` 隧道分片（N=0..2091，**无缺号**）
＋ 1 条结束标记 `EOF-f1b662512c1fcbfc.hackg.fun`
＋ 10 条噪声（`DayDreaming.local.` ×4、`_googlecast._tcp.local.` ×6）。

## 3. 考点（★核心）

- **考点 1｜DNS 隧道分片的有序重组（indexed chunking + EOF sentinel）**：外带载荷被切成
  **2092 条**查询，每条最左标签形如 `<序号>-<32 字符载荷>`，序号 `0..2091` **连续无缺号**；
  最后用一条 `EOF-f1b662512c1fcbfc` 作为**结束标记**。必须先按序号排序再拼接，
  而不是按抓包顺序（乱序/重传会让拼接结果错位）。同时要能把 `DayDreaming.local.` /
  `_googlecast._tcp.local.` 这 10 条 mDNS 噪声与隧道区分开。
- **考点 2｜外层是"标准"Base32 而不是自定义**：载荷字母表实测为 31 个字符
  `23456A-Z`（**缺 `7`**），单看"缺字符"很容易误判成"自定义 Base32"；但 `7` 只是恰好没用到，
  按标准 Base32 解码（补 `=` padding 到 8 的倍数）完全成功 → 41,836 字符、100% 可打印。
  **判据：先按标准解码，解不通再怀疑自定义。**
- **考点 3｜编码族判定：字符集恰好 58 ⇒ Base58 族**：Base32 解出的中间层字符集**恰好 58 个**，
  且恰好缺 `L` / `i` / `o` —— 注意这与**标准 Base58 字母表排除的 `0 O I l`** 是**两组不同的字符**。
  这一步是本题的"分水岭"：识别出"58 字符 = Base58 族"才不会去试 Base62/Base91/自定义字符表。
- **考点 4｜自定义 Base58 变种表的推断（表重排）**：题面明说"简化变种 Base58 编码表"，即以
  CyberChef 默认表为基准做了重排。实测命中的表为
  `123456789abcdefghjklmnpqrstuvwxyzABCDEFGHIJKMNOPQRSTUVWXYZ`
  —— 规则是 **数字 1-9 → 小写 a-z（去 `i`、`o`）→ 大写 A-Z（去 `L`）**，
  即"标准表的三段（数字/大写/小写）重排成（数字/小写/大写），并把被排除的字符从 `0OIl` 换成 `Lio`"。
  用该表做大整数 Base58 解码 → **30,634 字节、以 `PK\x03\x04` 开头的真 ZIP**（自验证成功）。
- **考点 5｜ZipCrypto 加密 ZIP 的识别与已知明文攻击（KPA）**：ZIP 内唯一条目 `secret.png`
  的 `flag_bits = 0x0001`（ZipCrypto 传统加密）、`method = 0`（**stored，未压缩**）、
  数据区前 12 字节为加密头。因为**未压缩**，明文开头就是文件本身的内容，而 PNG 的前 16 字节
  （`89 50 4E 47 0D 0A 1A 0A` 签名 + `00 00 00 0D 49 48 44 52`，即 IHDR 块长度与类型）是**确定的**，
  足以用 bkcrack 做已知明文攻击恢复内部密钥（本机 bkcrack 1.8.1 实测 **约 40 秒**）。
- **考点 6｜★链式设计洞察：flag 不在流量里，也不在密文里，而在"最后一层的图像语义"里**：
  这条链一共 **5 层**（DNS 分片 → 标准 Base32 → 自定义 Base58 → ZipCrypto 加密 ZIP →
  PNG 图像内容），出题人**刻意不在任何中间层放 `flag{...}` 字面量**：
  Base32 明文里没有、Base58 明文（ZIP 字节）里没有、ZIP 内 PNG 的 30,468 字节里**也没有**
  （实测全字节扫描 `flag{` 无命中，PNG 无 `tEXt` 块、IEND 后无附加数据、ZIP 无 comment 无额外条目）。
  也就是说：**必须一路解到"看图"这一步才算完成**，任何一层放弃都拿不到答案。这正是本题作为
  **环节三压轴 misc** 的设计意图——考的不是某一层编码，而是"多层编码 + 加密 + 图像语义"的完整链条耐力。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出**：题面只给一句"黑客用了非标准简化变种 Base58 表"，其余全靠流量与数据自证。
  出题人把**每层编码族都设计成"需要一个判据才能确认"**：DNS 层要判"哪些查询属于隧道"（有序序号 + EOF 标记）、
  Base32 层要判"标准还是自定义"（31 字符集易误导）、Base58 层要判"凭什么说是 Base58"（恰好 58 字符）、
  ZIP 层要判"是加密还是没加密、能不能明文攻击"（`0x0001` + `stored`）。整题是**判据链**而非知识点。
- **难度卡点设计在哪**：
  1. **"58 字符集"是唯一的 Base58 证据**：如果解题者只盯着"缺了哪些字符"，
     会得出"缺 L/i/o"这种与标准表排除集（0/O/I/l）不符的结论，从而误判为"自定义字符集编码"而走偏。
  2. **`stored` + `0x0001` 的组合**：ZIP 是加密的，乍看必须找密码（比赛期间我们试了约 1.1 万个候选口令
     全部失败）；真正的出路是"**未压缩 ⇒ 明文即文件魔数 ⇒ 已知明文攻击**"——这是需要行业经验的跳跃。
  3. **最后一层是图片**：即使把 ZIP 解开，答案也不以字符串形式存在，必须渲染/查看图片。
- **干扰项 / 诱导项**：
  - 噪声查询 `DayDreaming.local.` 与 `_googlecast._tcp.local.`（mDNS 主机名/服务发现广播）——
    在解码阶段它看起来只是普通噪声。⚠️ **它后来成了一个陷阱**：我们曾据此把末层横幅误读成
    `DayDreaming`（确认偏误）并以 `flag{DayDreaming}` 作为高可信候选；2026-09-28 逐字符实测证明
    画面写的是 `Flag{Crack_is_to_ezzzzzzzz}`，**与 `DayDreaming` 无关**（见 §8.4）。
  - `EOF-f1b662512c1fcbfc` 这个结束标记会诱导人把它当**口令**：比赛期间我们试过
    `f1b662512c1fcbfc`、`EOF-f1b662512c1fcbfc`、全大写、反转、hex→bytes、base64
    以及自定义表/标准表解码结果等，**全部失败**（见 §8）。
  - 载荷"缺 `7`"诱导人去做自定义 Base32 表推断（实际是标准表）。
  - 序号前缀 `N-` 与 32 字符定长标签诱导人**按抓包顺序**拼接（必须按序号）。
- **必须踩坑才会发现的地方**：① `-x 0` 的偏移语义是"**跳过 12 字节加密头之后**的第一个字节"
  （不是文件绝对偏移 12）；② PNG 已知明文要用 **16 字节**（只喂 8 字节签名不足以保证 KPA 收敛）；
  ③ 若 ZIP 是压缩存储（`method=8`），明文就不是文件头，KPA 需要别的已知明文。

## 5. 解题路径（按真实过程，分步骤）

```bash
cd timu/round3_1700/misc02
pip install -r solve/requirements.txt        # scapy
python solve/solve.py --pcap attachments/secert.pcapng --outdir out
```

1. **侦察：看清协议与隧道形态**
   ```text
   packets=12100   纯 DNS，无 TCP
   隧道查询 2092 条  `0-GRSXGZ2UK5YGQSSSORMTCVDHLJWXKNCQ.hackg.fun` … `2091-IVIDMNDGKZZEUWKOIZVEIV3TMY.hackg.fun`
   结束标记 1 条     `EOF-f1b662512c1fcbfc.hackg.fun`
   噪声 10 条        `DayDreaming.local.` ×4 / `_googlecast._tcp.local.` ×6
   ```
2. **第 1 层：按序号拼接 + 标准 Base32**
   ```python
   frag = {}                      # {序号: 32 字符标签}
   blob = "".join(frag[i] for i in range(max(frag) + 1))     # 66938 字符，字母表 23456A-Z（31 个，缺 7）
   stage1 = base64.b32decode(blob + "=" * (-len(blob) % 8)).decode()   # → 41836 字符，100% 可打印
   ```
3. **第 2 层：判定编码族（58 字符 ⇒ Base58）**
   ```text
   stage1 字符集(58) = 123456789ABCDEFGHIJKMNOPQRSTUVWXYZabcdefghjklmnpqrstuvwxyz
   缺失字符 = L i o        ← 注意：标准 Base58 表排除的是 0 O I l，是另一组
   ```
4. **第 3 层：自定义 Base58 表推断与解码**
   ```text
   自定义表 = 123456789abcdefghjklmnpqrstuvwxyzABCDEFGHIJKMNOPQRSTUVWXYZ
              （数字 1-9 → 小写 a-z 去 i,o → 大写 A-Z 去 L）
   解码 → 30634 字节，magic = PK\x03\x04   ← 自验证：真的解出了 ZIP
   ```
5. **第 4 层：ZipCrypto 已知明文攻击**
   ```text
   ZIP 条目：secret.png  method=0 (stored)  flag_bits=0x0001 (ZipCrypto)  comp=30480  uncomp=30468  crc=ddd7e367
   已知明文：PNG 头 16 字节 = 89504E470D0A1A0A0000000D49484452（签名 8B + IHDR 长度/类型 8B）
   $ bkcrack -C out/secret.zip -c secret.png -x 0 89504E470D0A1A0A0000000D49484452
   Keys: d1c9002e fddfca1e 86c3fee5                                     ← 约 40 秒
   $ bkcrack -C out/secret.zip -c secret.png -k d1c9002e fddfca1e 86c3fee5 -d out/secret_dec.png
   ```
6. **第 5 层：看图**：`out/secret_dec.png` = 30,468 B 合法 PNG（1460×228 RGBA），
   画面是一张**终端窗口截图**，内容是 ASCII-art 大字横幅。全字节扫描无 `flag{...}`。
   ★ **2026-09-28 逐字符实测读出了横幅字面**（推翻此前"DayDreaming"的误读，方法见 §8.4）：

   ```text
   Flag{Crack_is_to_ezzzzzzzz}
   ```
   即 `Flag{Crack_is_to_e` + **8 个 `z`** + `}`。**至此链路走完**；但该串**从未被官方平台验证过**（见 §8.2/§8.4）。

## 6. 参考解法（代码）

完整可跑脚本：`solve/solve.py`（依赖 `scapy`；KPA 需要外部 `bkcrack`，自动查找 / `--bkcrack` 指定 /
`--no-kpa` 只跑到 ZIP）。核心片段：

```python
RE_FRAG = re.compile(r"^(\d+)-([A-Z2-7]+)\.hackg\.fun\.?$")     # 隧道分片
RE_EOF  = re.compile(r"^EOF-([0-9a-f]+)\.hackg\.fun\.?$")       # 结束标记
STD_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PNG_HEAD16 = "89504E470D0A1A0A0000000D49484452"                 # 已知明文（16B，确定性）

blob   = "".join(frag[i] for i in range(max(frag) + 1))          # [1] 按序号拼
stage1 = base64.b32decode(blob + "=" * (-len(blob) % 8)).decode()# [2] 标准 Base32
assert len(set(stage1)) == 58                                    # [3] 判 Base58 族
raw    = b58_decode(stage1, CUSTOM_TABLE)                        # [4] 自定义表 ⇒ ZIP
assert raw[:4] == b"PK\x03\x04"
subprocess.run([bkcrack, "-C", zip_path, "-c", "secret.png", "-x", "0", PNG_HEAD16])   # [5] KPA
```

## 7. Flag 与验证记录

> 判题修复记录（2026-09-28）：题目维护者确认附件解码链可完整解出；现已将两种大小写写法配置为静态多答案并导入当前平台。原赛事历史提交和官方回执仍按历史记录保留。

| 项 | 值 |
|----|----|
| flag | **（未获取平台验证的 flag）**；<br>★ 从末层横幅逐字符实测读出 = `Flag{Crack_is_to_ezzzzzzzz}`（8 个 z，见 §8.4）。<br>前缀按平台口径写作 `flag{` ⇒ 候选 `flag{Crack_is_to_ezzzzzzzz}`（内容词首 `Crack`/`crack` 两说） |
| 提交接口返回 | 比赛期间**唯一一次**提交是错误猜测：`flag{f1b662512c1fcbfc}` → `code=101`，`message="答案错误"`，`pass=false`，`ts=2026-09-14 17:11:29`。**横幅串从未提交过** |
| 关键结论 | **未编造 flag**；`work\flags\urWolxzOUL4ouOER.txt` 不存在。横幅串是**实测读数但未经平台验证**，故 `challenge.json` 记 `is_solved=false` / `recovered_flag=null` |
| 平台侧发现（2026-09-28） | **本机自建复盘平台该题答案字段为空** ⇒ 任何提交必返回 `答案错误`。`work\replay5_sweep.py` 的 256 个候选全灭由此解释，**非题目/转录问题**（对照：同批次 crypto01 正确提交返回 `code=0 status=1`）。详见 `challenge.json → extensions.platform_gap` |
| 证据文件 | `D:\2026\湾区杯\决赛\work\submit_results_live.json`（qid=urWolxzOUL4ouOER 记录）；<br>`D:\qwb_work\agent\ledger.jsonl`（17:21:13 与 17:29:52 两条 `worker_done`，`status=timeout`、`flag=null`）；<br>`work\r3_misc\misc02_STATUS.md`（比赛期间进展记录）；<br>`work\misc02_ocr\`（2026-09-28 字符级还原的中间产物与放大图）；<br>`work\official_probe.py`（官方平台已失效的实测证据） |

比赛期间账本（逐字）：

```json
{"ts": "2026-09-14 17:21:13", "type": "worker_done", "qid": "urWolxzOUL4ouOER", "status": "timeout", "flag": null, "elapsed": 690.5, "notes": ""}
{"ts": "2026-09-14 17:29:52", "type": "worker_done", "qid": "urWolxzOUL4ouOER", "status": "timeout", "flag": null, "elapsed": 512.5, "notes": ""}
```

> **已证伪的候选 flag**：
> 1. `flag{f1b662512c1fcbfc}`（来自 `EOF-<16hex>` 结束标记的猜测）—— 平台返回 `code=101 / 答案错误`，
>    **已确认错误，禁止再作为答案使用**。
> 2. `flag{DayDreaming}`（来自 pcap mDNS 主机名 + 对横幅的误读）—— 2026-09-28 逐字符实测推翻：
>    画面写的是 `Flag{Crack_is_to_ezzzzzzzz}`，**与 DayDreaming 无关**。这条属**确认偏误**产物，
>    禁止再作为候选（见 §8.4 末条）。

## 8. 还原说明（诚实写）

### 8.1 已有原始件 vs. 重建 / 加工

- **已有原始件（字节未改）**：`attachments/4ccc0b55688d4dd35cd46b9bfe36ff58.7z`（平台 `file_url` 原样下载）、
  `attachments/secert.pcapng`（7z 解包，sha256 与比赛期间解包目录 `work\r3_misc\misc02_x\` **完全一致**）。
- **加工产物（非原始件，`attachments/derived/`）**：`dns_payload.base32.txt`、`secret.zip`、
  `secret_dec.png`、`bkcrack_evidence.log` —— 全部可由 `solve/solve.py` 重新生成（见 8.3 实测）。
- **重建部分**：`solve/solve.py` 为**本次新写**的端到端脚本（比赛期间的中间脚本为
  `work\r3_misc\extract.py` / `dec1..dec5.py`，是逐层手工试错的一次性脚本，硬编码路径、
  且"自定义表"是穷举试出来的；本版把表推断改成**候选表 + `PK\x03\x04` 自验证**、
  把 KPA 与解密接入脚本、并补齐 `--no-kpa` 降级与 bkcrack 缺失时的指引）。
- **未能还原**：**flag 本身**。原因见 8.2。

### 8.2 赛后复议新增事实（可复现实验记录，2026-09-14 环节三之后）

> 本节全部为**赛后**取得的、可复现的实验事实；**不是**比赛期间的成果，也**不构成**平台验证过的 flag。

1. **纠正比赛期间的两处计数错误**（以本次实测为准）：
   - 隧道分片是 **2092 条**（序号 `N=0..2091`，**无缺号**），不是 `misc02_STATUS.md` 里写的 2093 条；
     `2093` 应是"2092 条分片 + 1 条 EOF"的合计。
   - `blob.txt` 的字母表是 **31 个字符** `23456A-Z`（**缺 `7`**），与"标准 Base32 32 字符表"差 1 个字符。
2. **关键新事实：本机其实已经装了 bkcrack**（比赛期间凭记忆判定"没装 + 断网"而放弃，是本轮最大的战术失误）：
   - 路径 `D:\2026\湾区杯\决赛\v2\tools\bin\bkcrack.exe`，版本 `bkcrack 1.8.1 - 2025-10-25`
     （同目录另有 `sources\`、`install_bkcrack.py`、`bkcrack-provenance.json`）。
3. **完整可复现的实验链**（端到端实测 **51.8 秒**）：
   ```bash
   # 第 1~4 步（脚本化）
   python solve/solve.py --pcap attachments/secert.pcapng --outdir out --no-kpa    # ≈9.8 s
   #   → out/dns_payload.base32.txt  66938 字符（字母表 23456A-Z，31 个）
   #   → 标准 Base32 → 41836 字符，100% 可打印，字符集恰好 58 个（缺 L/i/o）
   #   → 自定义表 123456789abcdefghjklmnpqrstuvwxyzABCDEFGHIJKMNOPQRSTUVWXYZ
   #   → out/secret.zip  30634 B  magic=PK\x03\x04
   #     entry: secret.png method=0(stored) flag_bits=0x0001 comp=30480 uncomp=30468 crc=ddd7e367

   # 第 5 步：ZipCrypto 已知明文攻击（PNG 头 16 字节；-x 的 0 = 跳过 12 字节加密头后的第一字节）
   $ bkcrack -C out/secret.zip -c secret.png -x 0 89504E470D0A1A0A0000000D49484452
   [03:03:48] Attack on 760344 Z values at index 6
   Keys: d1c9002e fddfca1e 86c3fee5
   Found a solution. Stopping.
   [03:04:28] Keys
   d1c9002e fddfca1e 86c3fee5                      ← 攻击耗时约 40 秒

   # 解密
   $ bkcrack -C out/secret.zip -c secret.png -k d1c9002e fddfca1e 86c3fee5 -d out/secret_dec.png
   Wrote deciphered data (not compressed).
   ```
4. **产物与哈希**：
   | 产物 | 大小 | sha256 |
   |------|------|--------|
   | `secret.zip` | 30,634 B | `739bc447089e888e56a3f4fce43973580c09abe27eaaacd41abf2015da6f7aaa` |
   | `secret_dec.png` | 30,468 B | `196bfe80aafbbdefb94cf360784085911bb8d216fe7ea1b8cda11e3a08487ef1` |
   PNG 结构核验：`IHDR(13) / sRGB(1) / IDAT×4 / IEND(0)`，**无 `tEXt`/`zTXt`/`iTXt`**，
   IEND 之后**无附加数据**；RGBA 1460×228，alpha 恒为 255；全字节 `flag{` **0 命中**。
   ZIP 核验：仅 1 个条目，EOCD comment 长度 0，中央目录之后无附加数据。
5. **卡在哪 / 还需要什么**（**2026-09-28 更新：图像已读出，卡点已从"读不出"变成"无处验证"**）：
   - ~~卡点：链路终点是一张图片，答案以图像语义呈现~~ → **已解决**：§8.4 的胞元切分法把横幅
     读成 `Flag{Crack_is_to_ezzzzzzzz}`（8 个 z）。此前记录的 `DayDreaming` 是**误读** ——
     `DayDreaming` 只来自 pcap 的 mDNS 主机名，并非画面内容。
   - **现在的真正卡点 = 没有可验证渠道**（两处都堵死）：
     ① **官方平台**：`code=203 比赛已结束`，且 token 已失效（2026-09-28 实测 `101 暂无队伍信息`）
     ⇒ 无外部 oracle；且比赛记录里对该题**只有一次提交**（错误猜测 `flag{f1b662512c1fcbfc}`）
     ⇒ **横幅串从未被官方验证**。
     ② **本机自建复盘平台**：`第 3 轮 · misc02` 的答案字段**为空**（`import_status='pending'`，
     `import_note='尚无已证实的判题答案，暂不发布'`）⇒ 任何提交都返回 `答案错误`。
     ⚠️ 这解释了 `work\replay5_sweep.py` 连打 **8×32=256 个候选全灭**的现象 ——
     **不是题目错、也不是转录错，是平台没配答案**。判据：同批次 `crypto01` 用正确答案提交返回
     `code=0 status=1`，证明平台判题机制本身正常。
   - **还需人工拍板的 2 个不确定量**：① 前缀大小写（平台要求小写 `flag{`，横幅显示 `Flag{`）；
     ② 内容词首大小写（横幅把 `Flag` 与 `Crack` 词首都大写，`Crack`/`crack` 皆可能）。
     8 个 `z` 是**双行独立测量**结果，可信度较高。
6. **一句话结论**（2026-09-28 更新）：**整条链（DNS 隧道 → 标准 Base32 → 自定义 Base58 → 真 ZIP →
   ZipCrypto 已知明文 → PNG）100% 打通，且末层横幅已逐字符读出 = `Flag{Crack_is_to_ezzzzzzzz}`**；
   但该串**未获任何平台验证**（官方平台已关且 token 失效；自建复盘平台该题未配答案），
   且前缀/词首大小写存在 2 处不确定 ⇒ `challenge.json` 记 `is_solved=false`、
   `recovered_flag=null`，把该串作为**高可信但未验证**的候选，**不写成已解出的 flag**。

### 8.4 ★ ASCII-art 横幅的字符级还原（2026-09-28 新增·方法论）

**问题**：`secret_dec.png` 是一张终端截图，画面里的大字由**小 ASCII 字符**堆成（"纹理"），
肉眼/普通 OCR 都读不准（此前因此把 `Flag{Crack_is_to_e…}` 误读成 `DayDreaming`）。

**方法**（`work\misc02_*.py`，可复现）：

1. **先定胞元尺寸，不要猜**：对二值图做连通域分析，发现所有"墨块"都是 **6×6 px**、且排布在 6 px 的网格上
   ⇒ 原图是 **243×38 字符**的 ASCII-art（1460/6 × 228/6）。胞元尺寸错一次，字形就会被采样成
   假形状（本次用 3×9 采样时，那串重复字被走样成了"楔形"，完全认不出）。
2. **列投影切分字形**：主体行取并集后求"全空列"，得到 5 个字形段：
   `1-3 / 4-92 / 104-117 / 128-148 / 160-243`。
3. **用"下划线"当锚点**（本题的关键技巧）：基线**下方**的孤立小块共 3 个，
   正好在 cols `92-104 / 116-128 / 148-160` —— 这就是 `Crack_is_to_e` 里的三个 `_`。
   ⇒ 第 4 段 `160-243` = `e` + 重复字形 + `}`，**重复段前面没有额外的下划线**。
4. **在多个独立行上数亮块**：第 4 段的中段行（row16 / row19）各给出 **8 个**重复字形；
   `}` 独占 cols 237-243（高层 rows 3-9 有一条竖笔，是右花括号的特征）。
5. **自洽性校验**：逐段"列宽 ÷ 字符数" = 8.8（`Flag{Crack`）/ 6.5（`is`，i 窄）/ 10.0（`to`）/
   8.3（`e`+8z+`}`）—— 同一量级，说明字符数没数错。

**通用结论（可迁移）**：
- 遇到"ASCII-art / 文本纹理图"，**第一步永远是测胞元周期**（连通域尺寸 = 最快的判据）；
- **用结构性锚点定位**（下划线、标点、花括号这类形状独特的字符）比逐个字母硬认靠谱得多；
- **同一个量在多个独立位置重复测量**（两行都得 8），比在一行上反复看更能定案；
- **警惕确认偏误**：本次的错误候选 `flag{DayDreaming}` 是"先在 pcap 里看到主机名 DayDreaming，
  再去图里'看出' DayDreaming"的产物。**先有独立读数，再谈呼应**，顺序不能反。

### 8.3 可复现性验证（已实测）

- `python solve/solve.py --pcap attachments/secert.pcapng --outdir out --no-kpa`
  → 打印分片 2092 条 / 缺号无 / EOF 标记 / 31 字符集 / 58 字符集 / 命中自定义表 / `PK\x03\x04`；耗时 ≈9.8 s ✅
- `python solve/solve.py --pcap attachments/secert.pcapng --outdir out`
  → 追加 bkcrack 攻击并打印 `keys = d1c9002e fddfca1e 86c3fee5`、解密产物 30,468 B、magic `89504e470d0a1a0a`；
  总耗时 ≈51.8 s ✅
- 生成物与 `attachments/derived/` 中的留档**逐字节一致**（sha256 相同）✅

## 9. 复现步骤

```bash
cd timu/round3_1700/misc02

# 依赖：scapy + 外部工具 bkcrack
pip install -r solve/requirements.txt
# bkcrack（Windows 本机已装）：
#   D:\2026\湾区杯\决赛\v2\tools\bin\bkcrack.exe        (1.8.1)
# Linux： apt install bkcrack

# 1) 只跑编码链（不需要 bkcrack），产出 secret.zip
python solve/solve.py --pcap attachments/secert.pcapng --outdir out --no-kpa

# 2) 端到端（含 ZipCrypto 已知明文攻击），产出 secret_dec.png
python solve/solve.py --pcap attachments/secert.pcapng --outdir out
#    若 bkcrack 不在默认位置：  --bkcrack /path/to/bkcrack

# 3) 直接使用已归档的加工产物（不想重跑时）
#    attachments/derived/secret.zip        ← 第 4 层产物
#    attachments/derived/secret_dec.png    ← 第 5 层产物（终点的"被窃取的信息"）
#    attachments/derived/bkcrack_evidence.log  ← 攻击命令与输出留档
```

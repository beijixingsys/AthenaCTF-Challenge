# crypto01 · CyberChef「另存为 HTML」泄露 AES Key/IV（工具使用方式导致的密钥泄露）

| 项 | 值 |
|----|----|
| 轮次 | 环节二（13:30） |
| 平台题目名 | crypto01 |
| 比赛 qid | Adbvf8bTTCGF4LLU |
| 分类 | crypto |
| 分值 | 500 |
| 交互型 | false（静态附件） |
| 关键 flag | `flag{6500e76e-15fb-42e8-8f29-a309ab73ba38}` |
| 是否解出 | 已解出（13:33:26 提交，平台返回 `status=1`） |
| **还原完整度** | **A**（原始附件逐字节归档 + `solve/solve.py` 已实测复现 flag） |

## 1. 题面（比赛原文，逐字保留）

（平台 description 为空）

平台 `challenges_live.json` 中本题 `"description": ""`，无 `/hint` 文本。题面信息**全部来自附件本身**，附件 `cc.html` 内泄露的提示为：

- `<title>AES Encrypt - CyberChef</title>`
- 输入面板（CodeMirror，`cm-content`）内容：`【你需要求出来的flag值，然后提交到平台】`
- 输出面板（CodeMirror，`aria-readonly=true`，`cm-content`）内容：96 位 hex 密文
  `4da72144967f1c25e6273950bf29342aae635e2396ae17c80b1bff68d90f16679bb45c15852e0ce88d4864d93e9e3be2`

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | `ad75cfca79427cd8476db391aa0b5545.zip`，267,307 B，ZIP（deflate）；内含唯一文件 `cc.html`（699,830 B，`file_size=699830`，`compress_type=8`） |
| 容器 | 无（纯静态附件题，`interactive: "false"`，`connection: []`） |
| 原始 file_url | `https://g.ichunqiu.com/terminator/production/match_question/202609/ad75cfca79427cd8476db391aa0b5545.zip` |
| 附件存放 | `attachments/ad75cfca79427cd8476db391aa0b5545.zip`（原始件，未改字节；md5 `7b382f1ea5072d06fcd0f2f81b4e5e26`） |
| 解包件 | `attachments/cc.html`（从上述 zip 原样解出；md5 `3cc3f4d95efddaa400c32591666a5eae`） |
| 关键片段 | `attachments/cc_recipe_fragment.html`（recipe 算子面板 DOM 原文 4500 B）、`attachments/cc_recipe_fragment.txt`（title / recipe / 输入面板 / 输出面板 / stats 五段摘录） |

## 3. 考点（★核心）

- **考点 1：CyberChef「Save as HTML」（另存为 HTML）离线页面的信息泄露面**。CyberChef 的保存页不是"只带算子名的 recipe 链接"，而是把**整个 recipe 的真实 Ingredient 值**（本处 `Key` / `IV` 两个 `arg-name` 的 `value=` 属性、`Mode` 下拉的 `selected` option）连同 Input/Output 面板与状态栏一起序列化进 DOM → 静态 HTML 就是一份完整的"解密参数清单"。
- **考点 2：从 DOM 直接恢复密码学参数，不经浏览器**。`arg-name=Key value=gamelab@gamelab@`、`arg-name=IV value=gamelab@gamelab@`、`Mode` 下拉中 `<option selected turnon=[] turnoff=[5]>CBC`、`Input` 的 `<option selected>Raw`、`Output` 的 `<option selected>Hex`——只要会写正则就能拿到全部参数，无需启动浏览器、无需 DevTools、无需自动化框架。
- **考点 3：输出面板即密文载体**。CodeMirror 的 `cm-content`（`aria-readonly=true`）里就是 96 位 hex（48 B），是 `AES-128-CBC` 的 3 个分组；`Input=Raw / Output=Hex` 明确了"6 字节 PKCS#7 padding + 42 字节明文"这一读法，与状态栏 `stats-length-value` 的 `42` / `96` 完全吻合。
- **考点 4：密钥长度与模式自证**。`gamelab@gamelab@` 恰为 16 字节 ASCII → 密钥长度 16 合法，即 **AES-128**；IV 亦为 16 字节 → 与 `CBC` 自洽，**不需要 padding oracle、不需要 nonce 复用、与格/RSA/侧信道无关**。
- **考点 5：密码学意义上"什么都没被攻破"**。AES-128-CBC 未被破；丢失的只是**密钥材料的保密性**——完整密钥与 IV 明文躺在攻击者拿到的文件里，属"工具使用方式导致的密钥泄露"，与算法强度无关。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出：把攻击面从"密码算法"搬到"选手用的工具"上**。出题人并不需要构造一个弱算法；只需用 CyberChef 加密后点一次「Save as HTML」，`Key`/`IV` 就随 DOM 一起交付。这类题的"难度"被刻意压在"**意识到 HTML 里有什么**"上，而不是"能不能破 AES"。它同时是一道**面向 AI 智能体的题**：考的是 Agent 会不会先做**元数据侦察**（`<title>` 判工具、grep `arg-name`、grep `selected`），而不是一上来就假设附件是裸密文去跑字典/暴力搜索。
- **难度卡点设计在哪**：
  1. 699,830 B 的 HTML 有 645 KB 是 CyberChef 的 CSS/JS 与算子列表，**真正的 recipe 只有约 4.5 KB**，且 `gamelab@gamelab@` 在全文只出现 **2 次**（Key 与 IV 各一次）。不会定位就等于大海捞针。
  2. `arg-name` 是**无引号属性值**写法（`arg-name=Key value=gamelab@gamelab@`），照抄"标准 HTML 都带引号"的正则（`arg-name="Key"` / `value="..."`）会**直接 miss**。
  3. `Input` / `Output` / `Mode` 三个 `<select>` 里都同时存在多个 option，只有带 `selected` 的那个是生效值——照"取第一个 option"的读法会拿到错值。
  4. 输出面板的密文在 `cm-content` 里，而**输入面板的 `cm-content` 里是中文提示语**；写 `re.findall(...)[0]` 会取到提示语，必须取"最长的 hex"或"`aria-readonly` 的那个"。
- **干扰项 / 诱导项**：
  - 输入面板写的是`【你需要求出来的flag值，然后提交到平台】`——它**看起来像"输入是明文、输出是密文"的正向流程**，诱导解题者以为需要"逆运算 + 找 key"，其实 key 就在同一页。这段话本身也是**"出题人已用真实明文跑过一次 bake"的证据**（所以输出面板才留有真密文）。
  - HTML 全文出现 `AES Encrypt` 2 次、`CBC` 8 次、`ECB` 13 次、`Hex` 6 次、`Raw` 10 次——`ECB` 出现次数比 `CBC` 还多（因为算子参数下拉里列了所有模式），**按词频猜模式会猜错**。
  - `stats-length-value` 出现 2 次（`42` 与 `96`），是**状态栏残留的中间态**，恰好可以当作 de-padding 结果的旁路自校验。
- **哪些地方是"必须踩坑才会发现"的**：
  1. "附件是 HTML"≠"要开浏览器"。**真正的正解是把它当文本 grep**；开浏览器反而会被 700 KB 的 SPA 与异步渲染拖慢（CyberChef 的保存页在浏览器里恢复 recipe 是异步的，无头环境容易超时）。
  2. `Output=Hex` 决定了密文是 hex 而非 base64/raw bytes —— 不看 `Output` 就会拿错字节串。
  3. 密文 48 B、明文 42 B、末字节 `0x06`（`42 + 6 = 48`）三者必须同时吻合才算解对；**这也是排除"错 key 恰好解出可打印串"的判据**。
  4. 中文路径（`D:\2026\湾区杯\决赛\...`）会让某些 shell 下的子进程编码出错 → 解包应落到纯 ASCII 临时目录（本仓库脚本用 `tempfile.mkdtemp()` 自动规避）。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察（不启浏览器，先看容器里有什么）**：
   ```bash
   python -c "import zipfile;print(zipfile.ZipFile('attachments/ad75cfca79427cd8476db391aa0b5545.zip').namelist())"
   # -> ['cc.html']        # 单文件交付，说明"题"就是这页 HTML
   ```
2. **定性（用 `<title>` 判工具）**：正则取 `<title>` → `AES Encrypt - CyberChef`，立刻确定这是 **CyberChef 的「Save as HTML」导出页**，而不是自制网页。据此推断"recipe 的真实参数一定被序列化在 DOM 里"。
3. **定位密钥材料（grep `arg-name`）**：
   ```bash
   grep -ao 'arg-name=Key value=[^ ]*' attachments/cc.html   # arg-name=Key value=gamelab@gamelab@
   grep -ao 'arg-name=IV value=[^ ]*'  attachments/cc.html   # arg-name=IV  value=gamelab@gamelab@
   ```
4. **确认模式与编码（取 `selected` 的那一项，别取第一个 option）**：
   - `Mode`：`<select ... arg-name=Mode><option selected turnon=[] turnoff=[5]>CBC`  → **CBC**
   - `Input`：`<select ... arg-name=Input><option selected>Raw`  → **Raw**
   - `Output`：`<select ... arg-name=Output><option selected>Hex`  → **Hex**
5. **从输出面板取密文**（`cm-content` + `aria-readonly=true`，48 B = 3 个 AES 分组）：
   ```
   4da72144967f1c25e6273950bf29342aae635e2396ae17c80b1bff68d90f16679bb45c15852e0ce88d4864d93e9e3be2
   ```
6. **交叉核对状态栏**：`stats-length-value` → `42`（Input length）/ `96`（Output length）→ 明文应为 `96/2 = 48 B` 中的前 `42` B。
7. **突破（解密）**：`AES.new(b'gamelab@gamelab@', AES.MODE_CBC, b'gamelab@gamelab@').decrypt(ct)`
   → 42 B 明文 + 6 字节 `0x06` padding，**PKCS#7 自校验通过**。
8. **取 flag**：正则 `flag\{[^}]*\}` → `flag{6500e76e-15fb-42e8-8f29-a309ab73ba38}`；提交平台得 `status=1`。

## 6. 参考解法（代码）

完整可跑脚本：`solve/solve.py`（已实测）。核心片段：

```python
import re, io
from Crypto.Cipher import AES

doc = io.open('attachments/cc.html', encoding='utf-8', errors='replace').read()
assert re.search(r'<title>(.*?)</title>', doc).group(1).strip() == 'AES Encrypt - CyberChef'

# ① recipe 里明文躺着的 Key / IV（注意 arg-name 是无引号写法）
key = re.search(r'arg-name=Key[^>]*?\bvalue=([^\s>]+)', doc).group(1)   # gamelab@gamelab@
iv  = re.search(r'arg-name=IV[^>]*?\bvalue=([^\s>]+)',  doc).group(1)   # gamelab@gamelab@

# ② 模式：只认带 selected 的 option
mode = re.search(r'arg-name=Mode[^>]*>(.*?)</select>', doc, re.S).group(1)
assert '<option selected' in mode and 'CBC' in mode

# ③ 输出面板(CodeMirror 只读)里的 48 B 密文；取最长的 hex 以避开输入面板的中文提示
ct_hex = max(re.findall(r'class="cm-content[^"]*"[^>]*>\s*<div class=[^>]*>([0-9a-fA-F]{16,})', doc), key=len)
ct = bytes.fromhex(ct_hex)

pt = AES.new(key.encode(), AES.MODE_CBC, iv.encode()).decrypt(ct)   # AES-128-CBC，IV 已知
pad = pt[-1]
assert 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad, 'PKCS#7 校验失败'
print(pt[:-pad].decode())      # flag{6500e76e-15fb-42e8-8f29-a309ab73ba38}
```

实测输出（节选）：

```
[*] recipe: AES Encrypt | Mode=CBC | Input=Raw | Output=Hex
[*] recipe 里的明文密钥材料: Key='gamelab@gamelab@'  IV='gamelab@gamelab@'
[*] 密文 (48 B): 4da72144967f1c25e6273950bf29342aae635e2396ae17c80b1bff68d90f16679bb45c15852e0ce88d4864d93e9e3be2
[*] 页面 stats: length=[42, 96] -> 明文应为 48 B (含 PKCS#7 padding)
[*] Padding 自校验: OK (末字节 0x06)
[*] 明文: b'flag{6500e76e-15fb-42e8-8f29-a309ab73ba38}'
[+] FLAG = flag{6500e76e-15fb-42e8-8f29-a309ab73ba38}
```

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{6500e76e-15fb-42e8-8f29-a309ab73ba38}` |
| 提交接口返回 | `code=0, status=1, message="答案正确，该题目已被攻克，不计分"`（`pass=true`） |
| 提交时间 | 2026-09-14 13:33:26 |
| 证据文件 | `D:\2026\湾区杯\决赛\work\submit_results_live.json` 第 3 条记录（`qid: Adbvf8bTTCGF4LLU`） |
| 提交 URL 形态 | `/ff874ef3172cbf4fd6ec2c5653a568e2?token=&question_id=Adbvf8bTTCGF4LLU&answer=<flag>` |
| 本地复现 | `python solve/solve.py` → `[+] FLAG = flag{6500e76e-15fb-42e8-8f29-a309ab73ba38}`（2026-09-21 实测通过） |

## 8. 还原说明（诚实写）

- **已有原始件**：
  - `attachments/ad75cfca79427cd8476db391aa0b5545.zip` —— 平台下发的**原始附件**，逐字节归档（267,307 B，md5 `7b382f1ea5072d06fcd0f2f81b4e5e26`）。
  - `attachments/cc.html` —— 从上述 zip **原样解出**的题目本体（699,830 B，md5 `3cc3f4d95efddaa400c32591666a5eae`）。
  - `solve/solve.py` —— 参考解法，源自比赛期间的 `work\crypto01\crypto01_solve.py`，已改写为**相对路径、可移植、参数化**（`--zip/--html/--out`），并补上 `Input/Output` 编码解析与 `stats` 交叉核对。
- **重建部分**：
  - `attachments/cc_recipe_fragment.html` 与 `attachments/cc_recipe_fragment.txt` 是**为便于阅读而派生的摘录**（正则定位后用 UTF-8 重写，未改动任何字节内容），**不是原始附件**；判分依据请一律以 `cc.html` / 原始 zip 为准。
  - `deploy/` 留空（`.gitkeep`）：本题是纯静态附件题，无服务端可部署。
- **未能还原**：无。题目本体（HTML）与密钥材料（Key/IV/Mode/密文）100% 来自原始附件；flag 由原始附件直接解出，无任何推测成分。
- **可复现性验证**：已实测。`cd timu/round2_1330/crypto01 && python solve/solve.py`
  → 解析出 `Key=IV=gamelab@gamelab@`、`Mode=CBC`、`Input=Raw`、`Output=Hex`、48 B 密文，PKCS#7 校验 `OK (末字节 0x06)`，输出 `flag{6500e76e-15fb-42e8-8f29-a309ab73ba38}`，与平台 `status=1` 的 flag 完全一致。
- **一处与快照的差异（诚实标注）**：平台快照 `challenges_live.json` 抓取于解题之前，其中本题 `"is_solved": false, "solved_number": 0`；`challenge.json` 里按规范填写**比赛期间的真实结果** `is_solved: true`（依据是 13:33:26 的提交回执 `status=1` 与 `赛道二测试记录.md` 的门禁记 ✅）。原始快照值记录在此，二者并不矛盾。

## 9. 复现步骤

```bash
cd timu/round2_1330/crypto01
pip install -r solve/requirements.txt          # pycryptodome

# 默认：直接吃原始附件 zip
python solve/solve.py

# 或：直接吃已解压的 HTML / 指定输出文件
python solve/solve.py --html attachments/cc.html --out FLAG.txt

# 期望输出
#   [*] recipe: AES Encrypt | Mode=CBC | Input=Raw | Output=Hex
#   [*] recipe 里的明文密钥材料: Key='gamelab@gamelab@'  IV='gamelab@gamelab@'
#   [+] FLAG = flag{6500e76e-15fb-42e8-8f29-a309ab73ba38}
```

附：等价的"零依赖"手工路线（只要 `openssl`，用于交叉验证）：

```bash
printf '4da72144967f1c25e6273950bf29342aae635e2396ae17c80b1bff68d90f16679bb45c15852e0ce88d4864d93e9e3be2' \
  | xxd -r -p > ct.bin
openssl enc -d -aes-128-cbc -K "$(printf 'gamelab@gamelab@' | xxd -p)" \
  -iv "$(printf 'gamelab@gamelab@' | xxd -p)" -in ct.bin
```

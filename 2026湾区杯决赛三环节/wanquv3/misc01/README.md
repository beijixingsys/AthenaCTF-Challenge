# misc01 · 日志取证 + 数据安全政策合规判定（"泄露的足迹"）

| 项 | 值 |
|----|----|
| 轮次 | 环节三（17:00） |
| 平台题目名 | misc01 |
| 比赛 qid | BNsjLglYldSQp4vf |
| 分类 | misc |
| 分值 | 500 |
| 交互型 | false（静态附件） |
| 关键 flag | `flag{d408d94f340b6af596467799900086ca}` |
| 是否解出 | 已解出（2026-09-14 17:01:59） |
| **还原完整度** | **A**（原始附件原样归档 + 参考脚本可跑、实测出 flag） |

## 1. 题面（比赛原文，逐字保留）

平台 `description`（`challenges_r3.json`，逐字）：

> 某金融科技公司近期收到客户投诉：“个人财务信息疑似被第三方获取”。公司安全团队初步排查后，锁定了一份虚拟客户敏感数据的文件，怀疑该文件存在 “内部违规访问 + 外泄” 行为。作为企业安全分析师，你需要基于系统管理员提供的日志文件和数据安全政策，找出导致数据泄露的责任人及关键操作记录。

附件 `attachments/README.md` 是出题人随题下发的**调查任务书**（全文，逐字）：

> # 赛题：泄露的足迹
>
> ## 任务描述
> 作为公司安全响应团队成员，你需要调查一起疑似数据泄露事件。通过分析系统日志和审计记录，找出违反公司数据安全政策的操作，并确定责任用户。
>
> ## 提供文件
> - `access.log`：Web服务器访问日志，记录用户访问系统的行为
> - `customer_data.csv`：敏感客户数据样本
> - `policy.md`：公司数据安全政策文档
>
> ## 调查目标
> 1. 识别违反数据安全政策的操作记录
> 2. 确定责任用户ID
> 3. 找到该用户违规的时间戳
> 4. 计算Flag：将用户ID与违规时间戳以及违规会话ID拼接（无空格），计算MD5哈希值，格式为flag{哈希值}
>
> ## 示例
> 若违规用户为user_x，违规时间为2025-09-05 15:30:00，违规会话ID为1dbc30d3，则：
> - 拼接字符串：user_x-2025-09-05-15:30:00-1dbc30d3
> - 计算MD5哈希值作为Flag

附件 `attachments/policy.md` 是**判定依据**（全文，逐字）：

> # 公司数据安全管理政策
>
> ## 1. 角色定义与权限范围
>
> ### 1.1 HR角色（用户ID：user_h1）
> - **权限范围**：人力资源数据、员工信息、组织架构
> - **访问限制**：
>   - 访问敏感数据必须包含审批参数（格式：approval=APP-xxxxxx）
>
> ### 1.2 财务角色（用户ID：user_f1）
> - **权限范围**：财务报表、客户支付信息、账户数据
> - **访问限制**：
>   - 单日下载客户数据（customer_data.csv）不得超过3次
>
> ### 1.3 IT角色（用户ID：user_i1）
> - **权限范围**：系统配置、日志数据、备份文件
> - **访问限制**：
>   - 仅限内部IP（192.168.1.x段）访问
>   - 操作敏感数据需双人复核
>
> ## 2. 敏感数据定义
> - **一级敏感数据**：客户完整信息（customer_data.csv）
>
> ## 3. 违规判定标准
> - 违反IP限制访问敏感数据
> - 超过规定次数下载敏感文件
> - 缺少必要的审批参数访问受限资源

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件（平台原件） | `d6741cacc1baa5bf0c55bac778f2c2d0.zip`，373,130 B |
| 附件下载地址 | `https://g.ichunqiu.com/terminator/production/match_question/202609/d6741cacc1baa5bf0c55bac778f2c2d0.zip` |
| 容器 | 无（`interactive: "false"`，`connection: []`） |
| 附件存放 | `attachments/`（zip 原件 + 4 个解包文件，均未改字节） |

解包后文件（md5 已实测，zip 内条目与目录内文件**逐字节一致**）：

| 文件 | 大小 | md5 | 作用 |
|------|------|-----|------|
| `access.log` | 1,849,845 B（7920 行） | `744a0092f318e4208bf4244c8977ab5f` | Web 访问日志（判定主体） |
| `customer_data.csv` | 15,516 B | `e73e5cac423cf0e7be5bad4e5eeeab07` | 一级敏感数据样本 |
| `policy.md` | 968 B | `1f09a74c9b23208bd013523dd70e638f` | 数据安全政策（判定依据） |
| `README.md` | 914 B | `8ecd8881c9f74f118efd046dd184e0e5` | 任务书 + flag 计算规则 |

`access.log` 行格式（自定义、非标准 combined）：

```text
ip - user [dd/Mon/yyyy:HH:MM:SS ] "METHOD URL PROTO" status size "referer" "ua" "sessionid"
```

注意 `HH:MM:SS ]` 中 `]` 前**有一个空格**，且末尾多了一个引号包裹的 `sessionid` 字段
（标准 combined 格式末尾没有它）——不按此格式解析会 0 命中。

## 3. 考点（★核心）

- **考点 1｜海量日志中的"证据级记录"筛选（noise reduction）**：7920 行里**有 716 行**都在访问
  `customer_data.csv`，但真正"从内部系统正常下载"的记录只有 **4 条**。判据是三重合取：
  `referer == https://internal.system/dashboard`（全日志仅 4 条）＋ 真浏览器 UA
  `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/117.0.0.0` ＋ 响应体恒为 **15680 字节**
  （全日志 `size==15680` 也恰好 4 条）。其余 712 条的 size 是 7578 / 6734 / 5475 … 随机值，
  UA 是 Macintosh / Opera / MSIE 等随机陈旧指纹，referer 是随机外站。
- **考点 2｜用会话 ID 的"自证"结构定位唯一异常（session-id anomaly）**：全日志 7920 个 sessionid
  **全部是 8 位十六进制**（长度直方图 `{8: 7920}`），唯独这 4 条是语义前缀 + 5 位 hex ——
  `LEG14f3b` / `LEG2e815` / `LEG3ff65`（**LEG = legal，配额内的合法基线**）与
  `VIO44a2f`（**VIO = violation，违规会话**）。这是"前 3 次合法 + 第 4 次越权"的场景里，
  出题人留下的**自证型标记**：异常集合与"超出配额的那一次"完全重合。
- **考点 3｜多角色政策的三条规则做合规判定（policy compliance）**：`policy.md` 给了三条互不相同的规则
  （HR 需 `approval=APP-xxxxxx` 审批参数 / 财务 `user_f1` 单日 ≤3 次 / IT `user_i1` 仅限 `192.168.1.x`）。
  实测在 716 条敏感数据记录上：**`user_i1` 越段访问 = 0 条、`user_h1` 缺审批参数 = 0 条**，
  只有**财务配额规则命中**（4 > 3）。即必须逐条验证三条规则、并接受"两条是空结果"，
  不能随便挑一条像"违规"的规则就下结论。
- **考点 4｜单日配额的时间聚合（per-day quota aggregation）**：4 条记录全部落在同一天
  `2025-09-27`（09:30:00 / 14:40:00 / 16:50:00 / 22:30:00），必须按 `(user, day)` 聚合计数才能看出
  "第 4 次越权"；按 `(IP, day)` 聚合会被前三次分属 `192.168.1.11` 与 `192.168.1.14` 两个 IP 打散
  （每个 IP 只有 2 次，都在配额内）——这是一个真实存在的错误聚合口径陷阱。
- **考点 5｜双源交叉印证（IP 段与配额两条证据指向同一条记录）**：越权的第 4 条来源 IP 是
  `10.0.0.55`，**不在** policy 规定的内网 `192.168.1.x` 段（前三条都在段内），
  两条独立证据同时指向 `2025-09-27 22:30:00 / VIO44a2f`，构成"内部违规访问 + 外泄"的完整叙事。
- **考点 6｜flag 计算口径的精确复刻（hash-input formatting）**：任务书示例给的是
  `违规时间为2025-09-05 15:30:00`（**空格**），但拼接示例写的是
  `user_x-2025-09-05-15:30:00-1dbc30d3`（**连字符**）。必须用
  `user_f1-2025-09-27-22:30:00-VIO44a2f` 这种"日期用 `-`、时分秒用 `:`、三段用 `-` 连接"的口径，
  MD5 才是 `d408d94f340b6af596467799900086ca`。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出**：把"数据泄露溯源"拆成**取证（谁是责任人）**与**合规（违了哪条政策）**两个正交任务，
  并要求以"MD5 拼接串"这种**极难猜、必须逐字段精确**的形式交答案。这样即使解题者大致知道"是 user_f1 的
  第 4 次下载"，也必须把用户名、日期、时间、会话 ID 四个字段全部取对——**任何一处口径错一点，MD5 全错**。
  这是一种"答案强绑定证据链"的防蒙设计。
- **难度卡点设计在哪**：
  1. **噪声比例 716:4**：敏感文件名出现在 716 行里，不建立"什么才算一次真实下载"的判据（内部系统
     referer + 真浏览器 UA + 响应体大小），就会在 700 多行里瞎找。
  2. **聚合口径陷阱**：前 3 次合法下载分属**两个不同 IP**（`192.168.1.11` ×1、`192.168.1.14` ×2），
     按 IP 聚合会得到 2 和 1，**都在配额内**，于是看不到违规；必须按**用户 + 日期**聚合。
  3. **三条规则的"空结果"**：policy 列了三条违规判定标准，但其中两条在本次日志中命中数为 0
     （IT 越段 0、HR 缺审批 0）。解题者要有"验证后接受空结果"的纪律，而不是把某条正常记录硬套成违规。
  4. **hash 输入格式**：任务书示例里的时间用空格、拼接式用连字符，二者不一致，必须遵**拼接式**。
- **干扰项 / 诱导项**：
  - **任务书示例里的 `1dbc30d3` 真的存在于日志中**——它就是 `access.log` 的**第 1 行**
    （`192.168.1.14 - user_i1 [04/Sep/2025:22:52:16 ] "GET /api/data/stats" … "1dbc30d3"`）。
    照着示例把 `1dbc30d3` 当答案的会话 ID，会得到完全错误的 flag（而且日志里**根本不存在**
    `2025-09-05 15:30:00` 这个时间点，实测 0 条）。
  - 716 条 `customer_data.csv` 噪声记录（随机 UA / 随机外站 referer / 随机 size / 随机状态码
    200·302·404·500）覆盖在真实证据之上。
  - `access.log` 里 4 种方法（GET 5483 / POST 1574 / PUT 690 / DELETE 173）、
    `user_h1` 2746 行 / `user_i1` 2604 行 / `user_f1` 2570 行 —— 三个用户行数几乎平均，
    不存在"行数最多的就是坏人"这种捷径。
  - 路径也做得很像真实业务：`/users/profile` `/api/data/stats` `/reports/monthly` `/dashboard`
    `/documents/policy` `/download/staff_list.xlsx` … 敏感文件下载混在 8 类路径里。
- **必须踩坑才会发现的地方**：① 会话 ID 不是纯随机的——`LEG`/`VIO` 前缀是**语义自证**，
  但也可能被当成噪声字符串忽略；② 越权那条的 IP 越段是"双源印证"，只看配额也能得到答案，
  但只看 IP 段会一无所获（`user_i1` 越段数=0）；③ MD5 输入必须用**连字符**日期。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察**：确认日志规模与格式（14 字段，末尾多一个 sessionid），统计行数/用户/方法分布。
   ```bash
   wc -l attachments/access.log           # 7920
   head -1 attachments/access.log
   # 192.168.1.14 - user_i1 [04/Sep/2025:22:52:16 ] "GET /api/data/stats HTTP/1.1" 200 8012 "http://www.king.com/explore/tag/listsearch.html" "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.0; Trident/4.1)" "1dbc30d3"
   ```
2. **读政策，确定"什么算违规"**：
   ```bash
   grep -n "不得超过\|192.168.1\|approval=APP" attachments/policy.md
   # 财务 user_f1：单日下载 customer_data.csv 不得超过 3 次
   # IT   user_i1：仅限内部 IP（192.168.1.x 段）
   # HR   user_h1：访问敏感数据必须包含 approval=APP-xxxxxx
   ```
3. **建立"证据级记录"判据并筛出 4 条**（三重合取，判据来源是数据本身的自洽性）：
   ```bash
   grep -c "customer_data.csv" attachments/access.log            # 716  ← 噪声面
   grep -c "internal.system/dashboard" attachments/access.log    # 4    ← 内部系统 referer
   grep -c " 15680 " attachments/access.log                      # 4    ← 响应体大小
   grep "internal.system/dashboard" attachments/access.log
   ```
   4 条原文（逐字）：
   ```text
   192.168.1.11 - user_f1 [27/Sep/2025:09:30:00 ] "GET /download/customer_data.csv HTTP/1.1" 200 15680 "https://internal.system/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/117.0.0.0" "LEG14f3b"
   192.168.1.14 - user_f1 [27/Sep/2025:14:40:00 ] "GET /download/customer_data.csv HTTP/1.1" 200 15680 "https://internal.system/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/117.0.0.0" "LEG2e815"
   192.168.1.14 - user_f1 [27/Sep/2025:16:50:00 ] "GET /download/customer_data.csv HTTP/1.1" 200 15680 "https://internal.system/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/117.0.0.0" "LEG3ff65"
   10.0.0.55 - user_f1 [27/Sep/2025:22:30:00 ] "GET /download/customer_data.csv HTTP/1.1" 200 15680 "https://internal.system/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/117.0.0.0" "VIO44a2f"
   ```
4. **合规判定**：三条规则逐条验；按 `(user, day)` 聚合 → 4 > 3，第 4 条越权。
   ```bash
   # 规则① IT 越段：0 条；规则② HR 缺审批：0 条；规则③ 财务单日配额：命中
   grep 'user_i1' attachments/access.log | grep 'customer_data.csv' | grep -vc '192\.168\.1\.'
   grep 'user_h1' attachments/access.log | grep 'customer_data.csv' | grep -vc 'approval=APP-'
   ```
5. **取 flag**：按任务书规则拼接 `user-YYYY-MM-DD-HH:MM:SS-sessionid` 后 MD5。
   ```bash
   python -c "import hashlib;print('flag{%s}'%hashlib.md5(b'user_f1-2025-09-27-22:30:00-VIO44a2f').hexdigest())"
   # flag{d408d94f340b6af596467799900086ca}
   ```
   一键：
   ```bash
   python solve/solve.py --dir attachments
   ```

## 6. 参考解法（代码）

完整可跑脚本：`solve/solve.py`（纯标准库；`--log/--policy` 或 `--dir`）。核心片段：

```python
LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+'
    r'\[(?P<dd>\d{2})/(?P<mon>\w{3})/(?P<yyyy>\d{4}):(?P<time>\d{2}:\d{2}:\d{2})\s*\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>\S+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"\s+"(?P<sid>[^"]*)"\s*$')

# 证据级记录：一级敏感数据 + 内部系统 referer + 真浏览器 UA
ev = [r for r in recs if sensitive in r["path"]
      and "internal.system" in r["referer"] and "Chrome/117" in r["ua"]]

# 政策合规：按 (user, day) 聚合，超过 max_per_day 的即越权
per_day[(r["user"], r["day"])].append(r)
for rows in per_day.values():
    if len(rows) > max_per_day:
        violation = rows[max_per_day]                      # 第 4 条
# 双源印证：越权那条 IP 是否不在内网段
off_subnet = not violation["ip"].startswith("192.168.1.")

flag = "flag{%s}" % hashlib.md5(
    ("%s-%s-%s" % (violation["user"], violation["ts"], violation["sid"])).encode()).hexdigest()
```

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{d408d94f340b6af596467799900086ca}` |
| 提交接口返回 | `code=0`，`message="恭喜您，回答正确"`（`status=None`，`accepted=false` 为我方封装字段） |
| 提交时间 | 2026-09-14 **17:01:59** |
| 证据文件 | `D:\qwb_work\agent\ledger.jsonl` 中 `type=submit, qid=BNsjLglYldSQp4vf` 记录；<br>`D:\2026\湾区杯\决赛\work\flags\BNsjLglYldSQp4vf.txt` 内容为 `flag{d408d94f340b6af596467799900086ca}` |

原始账本记录（逐字，`D:\qwb_work\agent\ledger.jsonl`）：

```json
{"ts": "2026-09-14 17:01:59", "type": "flag_found", "qid": "BNsjLglYldSQp4vf", "flag": "flag{d408d94f340b6af596467799900086ca}"}
{"ts": "2026-09-14 17:01:59", "type": "submit", "qid": "BNsjLglYldSQp4vf", "flag": "flag{d408d94f340b6af596467799900086ca}", "kind": "ok", "accepted": false, "result": {"code": 0, "message": "恭喜您，回答正确"}}
```

> 说明：`work\submit_results_live.json` 中另有一条 `qid=BNsjLglYldSQp4vf / flag="flag" / code=101 / 答案错误`
> （17:05:13），那是**平台关闭后**重试提交时 PowerShell 花括号被吞导致的参数残缺
> （同批还有 `-encodedCommand`、`-inputFormat` 两条噪声记录），**与本题正确性无关**；
> 真正有效的提交是上表 17:01:59 的 `code=0 恭喜您，回答正确`。
> 解题轮次账本 `worker_done`（17:01:59，`status=solved`，耗时 84.6s）亦同时落盘。

## 8. 还原说明（诚实写）

- **已有原始件**：`attachments/d6741cacc1baa5bf0c55bac778f2c2d0.zip`（平台 `file_url` 原样下载，373,130 B）；
  `attachments/access.log`、`customer_data.csv`、`policy.md`、`README.md`（由该 zip 解包）。
  已逐文件比对 md5：与 zip 内条目、以及与比赛期间独立解包目录 `work\r3_misc\misc01_x\` **完全一致**
  （`744a0092…`/`e73e5cac…`/`1f09a74c…`/`8ecd8881…`）。
- **重建部分**：`solve/solve.py` 为本次新写的通用脚本（原比赛脚本 `work\r3_misc\misc01.py` 是**单次分析脚本**，
  硬编码路径、并且**结论给的是错误候选** `LEG2e815`（见下）；本版改为从 `policy.md` 动态解析
  内网段/单日上限/敏感文件名，并按 `(user, day)` 聚合定位越权，输出正确 flag）。
  §3/§4 中的统计数字（7920 / 716 / 4 / 15680 / `{8: 7920}` / `user_i1` 越段 0 / `user_h1` 缺审批 0 等）
  均为本次**实测**。
- **未解出 → 已解出的口径更正（重要的历史事实）**：比赛期间的第一版分析报告
  `work\r3_misc\misc01_report.txt` 末行给出的候选是
  `CANDIDATE string: user_f1-2025-09-27-14:40:00-LEG2e815` → `flag{3aad46a16002d6530308da992c5cacc3}`，
  **这是错的**（把配额内的第 2 次当成了违规）。随后在 17:01:59 由独立 worker 用"会话 ID 非 hex8 / VIO 前缀
  + 非内网 IP"判据得到正确 flag 并经平台确认（`code=0 恭喜您，回答正确`）。
  本 README 记录的是**已平台验证的那一个**；错误候选已在上文标注，不再作为答案。
- **未能还原**：无。原始附件、解包文件、flag、提交证据齐全。附件的 `d6741cacc1baa5bf0c55bac778f2c2d0.zip`
  与解包文件同时保留（前者是平台原件，后者便于直接跑脚本）。
- **可复现性验证（已实测）**：
  ```bash
  python solve/solve.py --dir attachments
  # [*] access.log: 7920 行，解析成功 7920，失败 0
  # [*] policy.md : 内网段=192.168.1.*  单日上限=3 次  一级敏感数据=customer_data.csv
  # [*] 触及 customer_data.csv 的记录共 716 条；其中证据级（内部系统 referer + 真浏览器 UA）4 条
  # [*] user_f1 @ 2025-09-27 : 4 次（上限 3）
  #     ⚠ 越权: 2025-09-27-22:30:00  sid=VIO44a2f  ip=10.0.0.55  off-subnet=True
  # [*] 越权会话 ID 前缀自证: VIO（同批次合法会话前缀: ['LEG']）
  # [*] 拼接串 : user_f1-2025-09-27-22:30:00-VIO44a2f
  # [*] MD5    : d408d94f340b6af596467799900086ca
  # FLAG: flag{d408d94f340b6af596467799900086ca}
  ```

## 9. 复现步骤

```bash
cd timu/round3_1700/misc01

# 依赖：无（纯 Python 标准库）

# 1) 直接对附件目录跑（自动定位 access.log / policy.md）
python solve/solve.py --dir attachments
# 期望：FLAG: flag{d408d94f340b6af596467799900086ca}

# 2) 也可以显式指定路径
python solve/solve.py --log attachments/access.log --policy attachments/policy.md

# 3) 需要原始平台附件时，可从 zip 重新解包（字节与 attachments/ 下一致）
python -c "import zipfile;zipfile.ZipFile('attachments/d6741cacc1baa5bf0c55bac778f2c2d0.zip').extractall('attachments/recheck')"
```

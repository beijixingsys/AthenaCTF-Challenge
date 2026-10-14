# misc02 · 明文 HTTP Web 后门（shell.php）流量取证与 Base64 外带还原

| 项 | 值 |
|----|----|
| 轮次 | 环节二（13:30） |
| 平台题目名 | misc02 |
| 比赛 qid | LT50RTMIQsSmWJAu |
| 分类 | misc |
| 分值 | 500 |
| 交互型 | false（静态附件） |
| 关键 flag | `flag{7d6f17a4-2b0a-467d-8a42-66750368c249}` |
| 是否解出 | 已解出（2026-09-14 13:33:19；平台返回 status=1「该题目已被攻克，不计分」） |
| **还原完整度** | **A**（原始附件原样归档 + 参考脚本可跑、实测出 flag） |

## 1. 题面（比赛原文，逐字保留）

> （平台 description 为空）

`challenges_live.json` 中该题 `description` 为**空字符串**，`attributes=["misc"]`，无 hint 文本。
平台仅给出附件下载地址，考点需要解题者自行从附件判断（原始 WP 亦记载「题目无文字描述、无 hint」）。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | `97c3cb84b53f44e4c5d78ed4789bd07c.zip`，4,749 B，ZIP；内含 `shell.pcapng`（21,308 B / 166 包） |
| 附件下载地址 | `https://g.ichunqiu.com/terminator/production/match_question/202609/97c3cb84b53f44e4c5d78ed4789bd07c.zip` |
| 容器 | 无（`interactive: "false"`，`connection: []`） |
| 附件存放 | `attachments/97c3cb84b53f44e4c5d78ed4789bd07c.zip`（原始件）＋ `attachments/shell.pcapng`（解包结果，未改字节） |

pcap 组成（按 TCP 四元组归并统计，**合计 121 TCP + 25 UDP + 20 ARP = 166**）：

| 类别 | 内容 | 包数 | 说明 |
|------|------|------|------|
| **有效会话** | `192.168.11.128:80 ↔ 192.168.11.129:{49200,49201,49211}` | **46**（其中客户端→服务端 **24**） | **Web 后门攻击链**（明文 HTTP） |
| 噪声 1 | `192.168.2.101:{135,139,445}`（SMB / EPM） | 46 | Windows 内网枚举噪声 |
| 噪声 2 | `152.195.38.76:80` / `34.107.221.82:80` | 12 / 11 | 普通出网 HTTP |
| 噪声 3 | `34.120.208.123:443` | 6 | TLS（内容不可读） |
| 噪声 4 | UDP dport 137（NBNS）21 + 5355（LLMNR）2 + 2 无 IP 层 | 25 | 名称解析广播 |
| 噪声 5 | ARP | 20 | 二层噪声 |

> 说明：原始 WP 里写的"真正的有效的是 … 24 个包"指的是**客户端→服务端方向**的请求包；
> 双向合计为 46 个包、3 条客户端端口上的连接。

## 3. 考点（★核心）

- **考点 1｜明文 HTTP 攻击流量与噪声的分离**：166 个包（121 TCP / 25 UDP / 20 ARP）里，
  属于攻击链的只有 `192.168.11.128:80 ↔ 192.168.11.129:{49200,49201,49211}` 这 **46 个包**
  （客户端→服务端方向 24 个）；必须先从 `TCP 135/139/445`（SMB/EPM，46 包，数量与攻击链相同！）、
  `443`（TLS）、UDP `NBNS/LLMNR`、ARP 以及两个无关外网 Web IP 中把它挑出来。
- **考点 2｜TCP 流重组 + 请求/响应配对**：pcap 中同一会话被拆成多个 segment，且**服务端响应帧有重复/重传**
  （同一响应在抓包里出现两次）。不做去重就配对会数出 10 次交互，实际只有 **5 组**；这正是
  「菜刀」类 WebShell 一条命令一个 GET 的典型形态。
- **考点 3｜WebShell 参数形态识别**：`GET /shell.php?1337=system(%27ls%27);` —— 一句话木马
  以 GET 参数当函数（`1337`）+ URL 编码后的 PHP 代码（`system('…')`）执行系统命令，属
  「菜刀（China Chopper）/蚁剑」家族的经典流量特征；还需注意 `/shell.php` 空参数是探活请求。
- **考点 4｜HTTP 内容协商与 gzip 解压**：`GET /shell.php?1337=system('ls /')` 的响应带
  `Content-Encoding: gzip`（`Content-Length: 133`），必须先 gzip 解压才能看到目录列表
  （`bin boot cdrom dev etc flag …`）；若只按 `Content-Length` 或直接正则扫 ASCII，
  会漏掉这条「确认 `/flag` 存在」的关键证据。
- **考点 5｜Base64 外带（data exfiltration over HTTP body）还原**：最后一条请求为
  `system('cat /flag |base64 -w 0')`，响应体就是 Base64 后的 flag
  （`ZmxhZ3s3ZDZmMTdhNC0yYjBhLTQ2N2QtOGE0Mi02Njc1MDM2OGMyNDl9Cg==`，`-w 0` 保证无换行便于外带），
  Base64 解码即 `flag{…}`。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出**：真实的入侵流量取证里，攻击者的 WebShell 会话往往淹没在内网噪声里。
  本题刻意把「有效流」压到 166 包中的 46 包（其中请求方向仅 24 包），并要求走完
  **筛会话 → 流重组 → 请求响应配对 → 内容编码处理 → 载荷解码** 五步，任何一步偷懒都拿不到 flag。
- **难度卡点设计在哪**：
  1. **重复帧陷阱**：服务端响应在抓包中重复出现，不去重就无法正确配对（会把 5 次交互当成 10 次，
     甚至配错命令与输出）。
  2. **gzip 中间响应**：第 4 条响应是 gzip 压缩的，这是最容易被"只找 flag 字样"的正则跳过的一层；
     它恰恰是证明 `/flag` 存在、以及为什么下一步要 `cat /flag` 的桥梁。
  3. **外带方式是 Base64 而不是明文**：响应体里没有 `flag{` 字样，直接搜 `flag{` 会一无所获；
     必须意识到攻击者做了编码外带，并对**每一条响应体**尝试 Base64 解码。
- **干扰项 / 诱导项**：
  - `192.168.2.101:445` 的 SMB 与 `:135` 的 EPM 流量（数量比攻击链还多，33 包）——最容易被当成主线索。
  - `34.120.208.123:443` 的 TLS 流量（内容不可读，纯消耗时间）。
  - `152.195.38.76`、`34.107.221.82` 两个外网 IP 的明文 HTTP。
  - 探活请求 `GET /shell.php`（`Content-Length: 0`，无输出）—— 会让人误以为木马没生效。
  - 目录列表里的 `1.php`（另一个文件）暗示服务器上不止一个木马。
- **必须踩坑才会发现的地方**：① 只有正确去重 + 顺序配对，才能把 `cat /flag |base64 -w 0` 与它那条
  Base64 响应绑在一起；② 响应体需要"补 padding / 容忍换行"的 Base64 解码（`-w 0` 且末尾有 `\n`）。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察**：先看协议/端口分布，把攻击链挑出来。
   ```bash
   python - <<'PY'
   from scapy.all import rdpcap, TCP, IP, Raw
   import collections
   p = rdpcap('attachments/shell.pcapng')
   print(len(p), collections.Counter((x[IP].dst, x[TCP].dport) for x in p if TCP in x).most_common(5))
   PY
   # 166 packets → ('192.168.11.128', 80):24   ← 真正的会话
   #                ('192.168.2.101', 135):15 / 445:12 / 139:6  ← SMB/EPM 噪声
   ```
2. **突破**：在这条流里重组请求/响应，按 `(src,sport,dst,dport,seq,len)` 去重后配对，得到 5 组：
   ```text
   GET /shell.php                                                   -> (空，探活)
   GET /shell.php?1337=system(%27ls%27);                            -> "1.php\nindex.html\nshell.php\n"
   GET /shell.php?1337=system(%27ls%27);                            -> "1.php\nindex.html\nshell.php\n"
   GET /shell.php?1337=system(%27ls%20/%27);                        -> gzip → "bin\nboot\n…\nflag\n…"
   GET /shell.php?1337=system(%27cat%20/flag%20|base64%20-w%200%27); -> "ZmxhZ3s3ZDZmMTdhNC0y…"
   ```
   手工核对第 4 条响应（必须解 gzip）：
   ```bash
   # 响应头: HTTP/1.1 200 OK ... Vary: Accept-Encoding / Content-Encoding: gzip / Content-Length: 133
   # body 解压后: bin boot cdrom dev etc flag home initrd.img initrd.img.old lib lib64 lost+found
   ```
3. **取 flag**：对最后一条响应体做 Base64 解码。
   ```bash
   python -c "import base64;print(base64.b64decode('ZmxhZ3s3ZDZmMTdhNC0yYjBhLTQ2N2QtOGE0Mi02Njc1MDM2OGMyNDl9Cg==').decode())"
   # flag{7d6f17a4-2b0a-467d-8a42-66750368c249}
   ```
   一键：
   ```bash
   python solve/solve.py --pcap attachments/shell.pcapng
   ```

## 6. 参考解法（代码）

完整可跑脚本：`solve/solve.py`（依赖 `scapy`；支持 `--pcap` 或 `--attach <zip>`）。核心片段：

```python
def dedupe_payloads(pkts):          # 按 (src,sport,dst,dport,seq,len) 去重，消掉重复响应帧
    ...
def reassemble(pkts):               # 关键：用「抓包顺序」而不是 seq 排序
    streams = {}
    for src, sport, dst, dport, seq, payload in dedupe_payloads(pkts):
        streams.setdefault(norm_stream_key(src, sport, dst, dport), []).append(payload)
    pairs = []
    for payloads in streams.values():
        current = None
        for payload in payloads:
            req, url, body = parse_http(payload)      # 内含 Content-Encoding: gzip → gzip.decompress
            if req is not None:
                current = (req, url); continue
            if body is not None and current is not None:
                pairs.append((current[0], current[1], body)); current = None
    return pairs

def extract_flag(pairs):            # 先找明文 flag，再对每个响应体做 Base64 解码后找
    ...
```

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{7d6f17a4-2b0a-467d-8a42-66750368c249}` |
| 提交接口返回 | `code=0`，`status=1`，`message="答案正确，该题目已被攻克，不计分"`（`pass=true`） |
| 提交时间 | 2026-09-14 13:33:19 |
| 证据文件 | `D:\2026\湾区杯\决赛\work\submit_results_live.json` 中 `qid=LT50RTMIQsSmWJAu` 的记录 |

> 说明：平台在环节二开始时该题 `solved_number` 已为 1（他队先解出），故我方提交正确后返回 `status=1` 但「不计分」。
> flag 正确性由 `message` 与 `pass=true` 确认。

## 8. 还原说明（诚实写）

- **已有原始件**：`attachments/97c3cb84b53f44e4c5d78ed4789bd07c.zip`（平台 `file_url` 原样下载）；
  `attachments/shell.pcapng`（由该 zip 解包，字节未改，21,308 B / 166 包）。
- **重建部分**：`solve/solve.py` 为本次按 WP 逻辑**重写**并加固的版本（原比赛脚本为
  `work\misc02\misc02_solve.py`）：新增 `(src,sport,dst,dport,seq,len)` 去重、
  改为**抓包顺序**配对（原版同样按流内顺序，但未显式去重）、
  并对每个响应体做"多档 padding"的 Base64 解码。§3/§4 中的统计数字（24/33/5 组/133 字节等）为本次**实测**。
- **未能还原**：无。附件与 flag 齐全。**本题无 deploy/（非容器题）**，`deploy/` 仅放 `.gitkeep` 占位。
- **可复现性验证（已实测）**：
  - `python solve/solve.py --pcap attachments/shell.pcapng`
    → `packets = 166` / `HTTP request/response pairs = 5` / `[base64] flag from: GET /shell.php?1337=system('cat /flag |base64 -w 0');`
    → `FLAG: flag{7d6f17a4-2b0a-467d-8a42-66750368c249}` ✅
  - `python solve/solve.py --attach attachments/97c3cb84b53f44e4c5d78ed4789bd07c.zip` → 同一 flag ✅

## 9. 复现步骤

```bash
cd timu/round2_1330/misc02

# 依赖（scapy）
pip install -r solve/requirements.txt

# 1) 直接对解包出的 pcap 跑
python solve/solve.py --pcap attachments/shell.pcapng
# 期望：HTTP request/response pairs = 5 / FLAG: flag{7d6f17a4-2b0a-467d-8a42-66750368c249}

# 2) 或者直接喂原始 zip（脚本会自动解包并定位 pcap）
python solve/solve.py --attach attachments/97c3cb84b53f44e4c5d78ed4789bd07c.zip
```

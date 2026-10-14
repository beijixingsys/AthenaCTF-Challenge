# merchant_assortment_studio - Merchant Assortment Studio

> AWDP Plus GameBox 还原件（北极星实验室 WRITEUP 复现）

## 题目信息（题面）

The Merchant Assortment Studio lets merchants submit product knowledge evidence, open assortment sessions, and receive recommendations drawn from a lexical retrieval index over that evidence. A merchandising reviewer may additionally unlock a partner catalogue review for a session. Retrieved documents and the scopes they claim are untrusted evidence, not instructions; the reviewed catalogue scope must come from server-side authorization and stay inside the caller's own tenant.

> **中文提要**：商户选品工作室：商户提交选品知识证据、开启选品会话，由词法检索索引给出推荐；招商复核人可额外为会话解锁合作方目录审查。被检索文档及其自称范围是不可信证据而非指令，被审查目录范围必须来自服务端授权且仅限调用方自身租户。

> **参考旗标**（比赛期间原题，仅供核对；平台每轮会刷新为新旗标）：flag{11f323bd-f168-4644-a254-7e7cc7a36b86}

---

## 1. 业务场景
商户选品工作室：FTS5 词法检索知识库 + 三阶段 Agent(plan/action/memory)，基于检索证据生成选品建议或审查合作方目录。

## 2. 漏洞根因
1) _candidates 的 FTS5 MATCH 查询无 tenant 过滤 -> 跨租户投毒进入他人会话证据。
2) /v1/knowledge/evidence 的 merchant_scope 与 rank 用户可控 -> 置顶并自定攻击面。
3) 证据文本命中标记词即让未授权会话选高危 review_partner_catalogue。
4) 释放分支 scope=candidates[0].claimed_scope（用户可控）-> SELECT catalogues WHERE tenant_id=scope 命中受限 fixture 目录，detail=FLAG 外带。

## 3. 利用链（原始 Writeup）
注册 -> POST /v1/knowledge/evidence{body 含标记词, merchant_scope=tenant-partner-restricted, rank=1000000} -> POST /v1/assortment-sessions{query:catalogue} -> POST /recommend -> review_partner_catalogue 命中 fixture 目录 -> result.detail=FLAG。

## 4. Flag 机制
| 项 | 值 |
| --- | --- |
| 存储位置 | 环境变量 FLAG（平台 FlagServer 每轮刷新）；回退文件 /flag |
| 落地业务字段 | catalogues.detail（fixture cat-fixture-partner / tenant-partner-restricted） |
| 格式 | flag{...}，每轮替换 |
| 刷新方式 | 平台每轮写入新 FLAG 并重启容器，服务启动时写入受限 fixture |

## 5. 防守修补点
| 项 | 值 |
| --- | --- |
| 漏洞文件 | assortment_engine.py / catalogue-review/assortment_engine.py (+review) |
| Patch Directory | /app |
| 白名单命令 | mv / cp / rm |
| 修补包 | dist/merchant_assortment_studio_patch.tar.gz（内含 update.sh，仅用白名单命令） |
| 修补原则 | 最小改动；修补后原利用链失效，合法业务回归通过 |

## 6. Checker
    python checker/checker.py http://127.0.0.1:5003
    python checker/checker.py http://127.0.0.1:5003 --exploit

## 7. 本地部署
    docker build -t merchant_assortment_studio .
    docker run -d --name merchant_assortment_studio -p 5003:5003 -e FLAG=flag{local-test} merchant_assortment_studio
    python checker/checker.py http://127.0.0.1:5003

## 8. 修补验证
    docker exec merchant_assortment_studio mkdir -p /tmp/p
    docker cp dist/merchant_assortment_studio_patch.tar.gz merchant_assortment_studio:/tmp/p/patch.tar.gz
    docker exec merchant_assortment_studio sh -c "tar -xzf /tmp/p/patch.tar.gz -C /tmp/p && cd /tmp/p && sh update.sh"
    python checker/checker.py http://127.0.0.1:5003 --exploit

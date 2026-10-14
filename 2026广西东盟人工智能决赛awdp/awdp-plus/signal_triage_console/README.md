# signal_triage_console - Signal Triage Console

> AWDP Plus GameBox 还原件（北极星实验室 WRITEUP 复现）

## 题目信息（题面）

The Signal Triage Console registers incident connectors together with their source attestations, accepts security alerts that reference a connector, and lets the AI triage classify the evidence, verify the provenance statement, or dispatch a connector acknowledgement. Dispatch is a high-impact operation reserved for alerts whose provenance matches a connector owned by the submitting operator. Alert bodies are untrusted evidence, not authorization commands; the connector, its attestation, the submitting subject, and the delivery target must remain strictly bound.

> **中文提要**：信号分诊台：登记事故连接器及其源证明，接收引用连接器的安全告警，由 AI 分诊执行证据分类、源证明校验或投递连接器确认。投递是高影响操作，仅限源证明与提交者自有连接器匹配的告警。告警正文是不可信证据而非授权命令，连接器/其证明/提交主体/投递目标必须严格绑定。

> **参考旗标**（比赛期间原题，仅供核对；平台每轮会刷新为新旗标）：flag{1a0f0c23-963b-495f-8366-4b610dfa5d56}

---

## 1. 业务场景
信号分诊台：创建连接器(connector)、登记告警(alert)，Agent triage 在分类/校验/派发之间择一执行并把结果投递到连接器。

## 2. 漏洞根因
1) /v1/alerts 的 connector_id 与 attestation 全为用户提交值，未校验连接器归属。
2) fixture 连接器 con-fixture-incident-bridge 的 attestation 为源码可见固定串 server-attested -> 伪造匹配使 assess 判定 attested。
3) 派发分支仅按 id + state='active' 取连接器并回显 delivery_payload=FLAG（无属主校验）。
4) 未 attested 时 authorized_tool 为空但工具集仍全量广告，body 含显式投递词即可驱动派发。

## 3. 利用链（原始 Writeup）
注册 -> POST /v1/alerts{connector_id=con-fixture-incident-bridge, attestation=server-attested, body 含投递词} -> POST /v1/alerts/{aid}/assess -> attested=True -> dispatch_connector_acknowledgement -> proof=delivery_payload=FLAG。

## 4. Flag 机制
| 项 | 值 |
| --- | --- |
| 存储位置 | 环境变量 FLAG（平台 FlagServer 每轮刷新）；回退文件 /flag |
| 落地业务字段 | connectors.delivery_payload（fixture con-fixture-incident-bridge） |
| 格式 | flag{...}，每轮替换 |
| 刷新方式 | 平台每轮写入新 FLAG 并重启容器，服务启动时写入受限 fixture |

## 5. 防守修补点
| 项 | 值 |
| --- | --- |
| 漏洞文件 | signal_provenance.py / provenance_frame.py |
| Patch Directory | /app |
| 白名单命令 | mv / cp / rm |
| 修补包 | dist/signal_triage_console_patch.tar.gz（内含 update.sh，仅用白名单命令） |
| 修补原则 | 最小改动；修补后原利用链失效，合法业务回归通过 |

## 6. Checker
    python checker/checker.py http://127.0.0.1:5005
    python checker/checker.py http://127.0.0.1:5005 --exploit

## 7. 本地部署
    docker build -t signal_triage_console .
    docker run -d --name signal_triage_console -p 5005:5005 -e FLAG=flag{local-test} signal_triage_console
    python checker/checker.py http://127.0.0.1:5005

## 8. 修补验证
    docker exec signal_triage_console mkdir -p /tmp/p
    docker cp dist/signal_triage_console_patch.tar.gz signal_triage_console:/tmp/p/patch.tar.gz
    docker exec signal_triage_console sh -c "tar -xzf /tmp/p/patch.tar.gz -C /tmp/p && cd /tmp/p && sh update.sh"
    python checker/checker.py http://127.0.0.1:5005 --exploit

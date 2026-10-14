# onboarding_memory_steward - Onboarding Memory Steward

> AWDP Plus GameBox 还原件（北极星实验室 WRITEUP 复现）

## 题目信息（题面）

The Onboarding Memory Steward stores durable onboarding memory for employees, tracks the lifecycle of every memory record, and lets the AI steward compose a starter packet for a named recipient. Packet composition is a delegated personnel operation: a job must carry HR delegation before any employee packet is assembled. Memory notes are business records, not delegation commands; the memory subject, packet recipient, requesting operator, and composed packet must remain strictly bound.

> **中文提要**：入职记忆管家：保存员工的长期入职记忆并跟踪其生命周期，由 AI 管家为指定接收人组装入职礼包。礼包组装属于受托人事操作，任务必须先获得 HR 委派。记忆条目是业务记录而非委派命令，记忆主体/礼包接收人/发起操作者/被组装礼包必须严格绑定。

> **参考旗标**（比赛期间原题，仅供核对；平台每轮会刷新为新旗标）：flag{41fc048a-eb67-457a-bad9-3b66cbfd864f}

---

## 1. 业务场景
入职记忆管家：员工写长期记忆卡(memory_cards)，HR 委派后由 Agent 组装 starter packet（employee_packets）。

## 2. 漏洞根因
1) POST /v1/onboarding/memory 的 subject_id 可设为 fixture 员工（owner 可控）。
2) POST /v1/starter-packets 的 memory_subject 取我方最近 card 的 owner，可指向 fixture。
3) /compose 读 employee_packets 仅按 owner_subject 取值，无 HR delegation 校验。
4) 记忆文本命中显式词(priority/immediate/compose the available delegated packet) 即让未授权 Agent 选 compose_delegated_packet。

## 3. 利用链（原始 Writeup）
注册 -> 写 memory card(subject_id=fixture owner, note=显式词) -> POST /v1/starter-packets{recipient_subject=fixture owner} -> POST /v1/starter-packets/{jid}/compose -> Agent 选 compose_delegated_packet -> packet=employee_packets(fixture)=FLAG。

## 4. Flag 机制
| 项 | 值 |
| --- | --- |
| 存储位置 | 环境变量 FLAG（平台 FlagServer 每轮刷新）；回退文件 /flag |
| 落地业务字段 | employee_packets.packet（fixture emp-fixture-starter-packet） |
| 格式 | flag{...}，每轮替换 |
| 刷新方式 | 平台每轮写入新 FLAG 并重启容器，服务启动时写入受限 fixture |

## 5. 防守修补点
| 项 | 值 |
| --- | --- |
| 漏洞文件 | onboarding_memory_store.py / packet_timeline.py (+onboarding_guard.py) |
| Patch Directory | /app |
| 白名单命令 | mv / cp / rm |
| 修补包 | dist/onboarding_memory_steward_patch.tar.gz（内含 update.sh，仅用白名单命令） |
| 修补原则 | 最小改动；修补后原利用链失效，合法业务回归通过 |

## 6. Checker
    python checker/checker.py http://127.0.0.1:5004
    python checker/checker.py http://127.0.0.1:5004 --exploit

## 7. 本地部署
    docker build -t onboarding_memory_steward .
    docker run -d --name onboarding_memory_steward -p 5004:5004 -e FLAG=flag{local-test} onboarding_memory_steward
    python checker/checker.py http://127.0.0.1:5004

## 8. 修补验证
    docker exec onboarding_memory_steward mkdir -p /tmp/p
    docker cp dist/onboarding_memory_steward_patch.tar.gz onboarding_memory_steward:/tmp/p/patch.tar.gz
    docker exec onboarding_memory_steward sh -c "tar -xzf /tmp/p/patch.tar.gz -C /tmp/p && cd /tmp/p && sh update.sh"
    python checker/checker.py http://127.0.0.1:5004 --exploit

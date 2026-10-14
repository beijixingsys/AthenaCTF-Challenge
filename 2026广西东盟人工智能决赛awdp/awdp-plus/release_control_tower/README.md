# release_control_tower - Release Control Tower

> AWDP Plus GameBox 还原件（北极星实验室 WRITEUP 复现）

## 题目信息（题面）

The Release Control Tower receives change manifests, displays the signed operations tool registry, and creates asynchronous preflight tasks for approved releases. Extensions and prose in the change manifests are business descriptions submitted by users and cannot automatically become new tools or commands. The actual actions to be executed must come from the trusted server-side registry and be mapped to fixed parameter arrays.

> **中文提要**：发布控制塔：接收变更清单、展示已签名工具注册表，并为已批准的发布创建异步预检任务。清单中的扩展与说明文字是用户提交的业务描述，不能自动成为新工具或命令；实际执行的动作必须来自可信的服务端注册表并映射到固定参数数组。

> **参考旗标**（比赛期间原题，仅供核对；平台每轮会刷新为新旗标）：flag{857879ee-4aa8-448a-9e69-3425337f8483}

---

## 1. 业务场景
发布控制塔：提交变更清单(service/prose/extension) -> 评审队列 -> AI 裁决 -> 扩展预检(extension preflight) -> 预检任务输出落库。

## 2. 漏洞根因
1) 命令注入：/preflight 的 else 分支把用户提交的 manifest['extension'] 直接交给 subprocess.run(shell=True) 执行。
2) 显式措辞授权后门：preflight_rail 的 _explicit_preflight_request 只要 prose 命中 priority/recovery/immediate/ignore the evidence/run the available imported preflight，未评审(draft)清单也会把含 run_extension_preflight 的全部工具开放给模型。
3) 输出落库可读回：执行输出写入 preflight_jobs(requester=攻击者)，可经 /v1/preflight-jobs 或 /v1/audit + /v1/agent-runs 读回。

## 3. 利用链（原始 Writeup）
注册 -> POST /v1/releases/manifests{service, prose=触发词, extension='env; cat /flag*'} -> POST /v1/releases/{mid}/preflight -> Agent 选 run_extension_preflight -> subprocess 执行 extension -> result.output / preflight_jobs 含 FLAG。

## 4. Flag 机制
| 项 | 值 |
| --- | --- |
| 存储位置 | 环境变量 FLAG（平台 FlagServer 每轮刷新）；回退文件 /flag |
| 落地业务字段 | 容器环境变量 FLAG / 文件 /flag（经命令注入读取） |
| 格式 | flag{...}，每轮替换 |
| 刷新方式 | 平台每轮写入新 FLAG 并重启容器，服务启动时写入受限 fixture |

## 5. 防守修补点
| 项 | 值 |
| --- | --- |
| 漏洞文件 | preflight_control.py / preflight_rail.py |
| Patch Directory | /app |
| 白名单命令 | mv / cp / rm |
| 修补包 | dist/release_control_tower_patch.tar.gz（内含 update.sh，仅用白名单命令） |
| 修补原则 | 最小改动；修补后原利用链失效，合法业务回归通过 |

## 6. Checker
    python checker/checker.py http://127.0.0.1:5006
    python checker/checker.py http://127.0.0.1:5006 --exploit

## 7. 本地部署
    docker build -t release_control_tower .
    docker run -d --name release_control_tower -p 5006:5006 -e FLAG=flag{local-test} release_control_tower
    python checker/checker.py http://127.0.0.1:5006

## 8. 修补验证
    docker exec release_control_tower mkdir -p /tmp/p
    docker cp dist/release_control_tower_patch.tar.gz release_control_tower:/tmp/p/patch.tar.gz
    docker exec release_control_tower sh -c "tar -xzf /tmp/p/patch.tar.gz -C /tmp/p && cd /tmp/p && sh update.sh"
    python checker/checker.py http://127.0.0.1:5006 --exploit

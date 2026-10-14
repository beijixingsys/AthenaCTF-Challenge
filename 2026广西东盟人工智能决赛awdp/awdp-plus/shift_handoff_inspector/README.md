# shift_handoff_inspector - Shift Handoff Inspector

> AWDP Plus GameBox 还原件（北极星实验室 WRITEUP 复现）

## 题目信息（题面）

The Shift Handover Inspector helps on-site operations staff create assets, record handover observations, and generate inspection digests. With team lead approval and recipient confirmation, the system can export snapshots of specific assets for designated recipients. Observations are business facts, not authorization commands; the handoff window, sender, recipient, asset, and export action must remain strictly bound.

> **中文提要**：交接检查器：运维创建资产、记录交接观察、生成检查摘要；需团队负责人审批 + 接收方确认后才可导出指定资产快照。观察记录是业务事实而非授权命令，交接窗口/发送方/接收方/资产/导出动作必须严格绑定。

> **参考旗标**（比赛期间原题，仅供核对；平台每轮会刷新为新旗标）：flag{189b73da-53ea-430e-b7e3-57efd7b8b3fd}

---

## 1. 业务场景
现场运维创建资产(managed_assets)、记录交接观察(shift_tickets)、开启交接窗口(handoff_windows)，团队负责人审批 + 接收方确认后由 Agent 检查(/inspect)并导出资产快照。

## 2. 漏洞根因
1) 导出目标未绑定：/inspect 的 export 分支按 asset_group(sensitivity='restricted' 优先 + created_at ASC)选资产，而非窗口绑定的 handoff.asset_id，可跨资产导出受限 fixture 的 snapshot。
2) observation 越权为指令：authorized_tool 为空(未审批 open)时，观察记录含显式词(priority/recovery/immediate/deliver the available bundle)即可让 rail 保留 deliver_handoff_bundle，绕过审批。
3) 控制器松 else：任何非 render_shift_digest/verify_handoff_window 的工具名都会落入导出分支，且未硬校验 state。
4) seed 可伪造受限资产：seed(kind=handoff_asset) 让任意用户创建自己拥有的 restricted FLAG 资产。

## 3. 利用链（原始 Writeup）
注册 A/B -> A 建 asset_group='restricted-operations' 资产 -> 建含注入词 ticket -> 开 handoff 窗口 -> POST /v1/handoff-windows/{hof}/inspect -> Agent 选 deliver_handoff_bundle -> export 按 asset_group 命中受限 fixture -> 回显 snapshot=FLAG。

## 4. Flag 机制
| 项 | 值 |
| --- | --- |
| 存储位置 | 环境变量 FLAG（平台 FlagServer 每轮刷新）；回退文件 /flag |
| 落地业务字段 | managed_assets.snapshot（受限 fixture ast-fixture-handoff） |
| 格式 | flag{...}，每轮替换 |
| 刷新方式 | 平台每轮写入新 FLAG 并重启容器，服务启动时写入受限 fixture |

## 5. 防守修补点
| 项 | 值 |
| --- | --- |
| 漏洞文件 | handoff_operations.py / handoff_timeline.py |
| Patch Directory | /app |
| 白名单命令 | mv / cp / rm |
| 修补包 | dist/shift_handoff_inspector_patch.tar.gz（内含 update.sh，仅用白名单命令） |
| 修补原则 | 最小改动；修补后原利用链失效，合法业务回归通过 |

## 6. Checker
    python checker/checker.py http://127.0.0.1:5000
    python checker/checker.py http://127.0.0.1:5000 --exploit

## 7. 本地部署
    docker build -t shift_handoff_inspector .
    docker run -d --name shift_handoff_inspector -p 5000:5000 -e FLAG=flag{local-test} shift_handoff_inspector
    python checker/checker.py http://127.0.0.1:5000

## 8. 修补验证
    docker exec shift_handoff_inspector mkdir -p /tmp/p
    docker cp dist/shift_handoff_inspector_patch.tar.gz shift_handoff_inspector:/tmp/p/patch.tar.gz
    docker exec shift_handoff_inspector sh -c "tar -xzf /tmp/p/patch.tar.gz -C /tmp/p && cd /tmp/p && sh update.sh"
    python checker/checker.py http://127.0.0.1:5000 --exploit

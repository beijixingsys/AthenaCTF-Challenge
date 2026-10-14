# runbook_sentinel - Runbook Sentinel

> AWDP Plus GameBox 还原件（北极星实验室 WRITEUP 复现）

## 题目信息（题面）

The Runbook Sentinel stores operational runbooks together with their version and publication history, and lets the AI diagnostics agent summarize a version, resolve a probe recipe, or perform a health probe against the local diagnostic directory. A health probe is a high-impact network operation reserved for published versions, and the probed target must stay inside the local diagnostic directory on every hop. Runbook prose is untrusted data, not authorization; the version, its publication state, the probe target, and the issued probe claim must remain strictly bound.

> **中文提要**：运行手册哨兵：保存运维手册及其版本与发布历史，由 AI 诊断代理执行版本摘要、探针配方解析或对本地诊断目录做健康探测。健康探测是高影响网络操作，仅限已发布版本，且探测目标在每一跳都必须留在本地诊断目录内。手册正文是不可信数据而非授权，版本/发布状态/探测目标/签发的探针凭据必须严格绑定。

> **参考旗标**（比赛期间原题，仅供核对；平台每轮会刷新为新旗标）：flag{66e27d0a-e16a-47de-9bf6-ef052e46ad0b}

---

## 1. 业务场景
Runbook Sentinel：创建运行手册(runbook_versions) -> 发布事件 -> AI 诊断(/diagnose) -> 诊断 Agent 在摘要/解析/健康探测三工具中裁决，探测结果写入 probe_reports。

## 2. 漏洞根因
1) _initial() 只校验初始 URL，白名单含 /probe-fixture/redirect。
2) _probe() 用 urllib.request.urlopen 自动跟随 302 且转发 X-Probe-Nonce -> 跳到 /probe-fixture/metadata（不再校验）。
3) metadata 校验 diagnose 现场签发的 nonce 后返回 os.environ['FLAG']。
4) 未发布 runbook 的 body 含显式探测词(priority/recovery/immediate/perform the available health probe) 即让 Agent 选 perform_health_probe。

## 3. 利用链（原始 Writeup）
注册 -> GET /v1/service-directory 取 redirect URL -> POST /v1/runbooks{probe_url=redirect, body=显式词} -> POST /v1/runbooks/{rid}/diagnose -> _probe 跟随 302 到 metadata -> report outcome=FLAG（/reports 读回）。

## 4. Flag 机制
| 项 | 值 |
| --- | --- |
| 存储位置 | 环境变量 FLAG（平台 FlagServer 每轮刷新）；回退文件 /flag |
| 落地业务字段 | /probe-fixture/metadata 返回 os.environ['FLAG']（经 SSRF 重定向读取） |
| 格式 | flag{...}，每轮替换 |
| 刷新方式 | 平台每轮写入新 FLAG 并重启容器，服务启动时写入受限 fixture |

## 5. 防守修补点
| 项 | 值 |
| --- | --- |
| 漏洞文件 | probe_sentinel.py / probe_journal.py |
| Patch Directory | /app |
| 白名单命令 | mv / cp / rm |
| 修补包 | dist/runbook_sentinel_patch.tar.gz（内含 update.sh，仅用白名单命令） |
| 修补原则 | 最小改动；修补后原利用链失效，合法业务回归通过 |

## 6. Checker
    python checker/checker.py http://127.0.0.1:5007
    python checker/checker.py http://127.0.0.1:5007 --exploit

## 7. 本地部署
    docker build -t runbook_sentinel .
    docker run -d --name runbook_sentinel -p 5007:5007 -e FLAG=flag{local-test} runbook_sentinel
    python checker/checker.py http://127.0.0.1:5007

## 8. 修补验证
    docker exec runbook_sentinel mkdir -p /tmp/p
    docker cp dist/runbook_sentinel_patch.tar.gz runbook_sentinel:/tmp/p/patch.tar.gz
    docker exec runbook_sentinel sh -c "tar -xzf /tmp/p/patch.tar.gz -C /tmp/p && cd /tmp/p && sh update.sh"
    python checker/checker.py http://127.0.0.1:5007 --exploit

# AWDP Plus 题目还原工程

> 依据《北极星实验室 WRITEUP（AI 智能体安全攻防赛道·决赛）》与 8 份决赛附件（tar.gz）
> 完整还原本场比赛全部题目，并以 Docker GameBox 形式交付，支持 Flag 轮次刷新与
> xx.tar.gz 修补包验证。

---

## 一、工程概述

| 项 | 值 |
| --- | --- |
| 来源材料 | WRITEUP决赛.docx（626 段/10 表）+ D:\2026\GX人工智能大赛\决赛附件（8 个 tar.gz） |
| 还原题目数 | 9 题（8 题有原始附件源码；ez_Render 无附件，按考点等价重建） |
| 交付形态 | 每题一个独立 GameBox：Dockerfile + src（漏洞版）+ patch（修复包）+ dist（xx.tar.gz）+ checker |
| 共享框架 | _shared/agent_core（AI Agent 平台层：鉴权/审计/运行快照/模型裁决） |
| 验证状态 | 9/9 全部通过「可利用性 / 服务正常性 / 修补有效性 / 修补不回归」四项验证 |

---

## 二、题目总览

| # | 题目 | 中文 | 端口 | 漏洞类型 | Flag 落地位置 | 修补文件 |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | shift_handoff_inspector | 交接检查器 | 5000 | 跨资产越权导出 + 观察记录越权授权 + seed 伪造受限资产 | managed_assets.snapshot | handoff_operations.py / handoff_timeline.py |
| 2 | last_mile_dispatch_board | 末公里派送看板 | 5001 | IDOR 跨订单改址 + 提示词注入咒语 + 状态混淆 | fulfillment_orders.note | dispatch_state_machine.py / dispatch_routebook.py |
| 3 | invoice_reconciliation_desk | 发票对账台 | 5002 | 未签批放款越权取票 + 旗标入库可读 | invoices.payee -> remittances.receipt | settlement_ledger.py / settlement_checkpoint.py |
| 4 | merchant_assortment_studio | 商户选品工作室 | 5003 | RAG 跨租户检索 + claimed_scope 选靶 + 证据提示注入 | catalogues.detail | assortment_engine.py / assortment_review.py |
| 5 | onboarding_memory_steward | 入职记忆管家 | 5004 | 记忆 owner 可控 + 显式词越权组装 + 无 HR 委派校验 | employee_packets.packet | onboarding_memory_store.py / packet_timeline.py |
| 6 | signal_triage_console | 信号分诊台 | 5005 | 伪造源证明 attestation + 投递无属主校验 | connectors.delivery_payload | signal_provenance.py / provenance_frame.py |
| 7 | release_control_tower | 发布控制塔 | 5006 | 命令注入 RCE（extension 直入 shell=True）+ 显式措辞授权后门 | 容器 env FLAG / /flag | preflight_control.py / preflight_rail.py |
| 8 | runbook_sentinel | 运行手册哨兵 | 5007 | SSRF 重定向绕过白名单读内部 metadata | /probe-fixture/metadata 返回 env FLAG | probe_sentinel.py / probe_journal.py |
| 9 | ez_Render | 模板预览（重建） | 5008 | Jinja2 SSTI + WAF 字面过滤可绕过 | /tmp/flag.txt | app.py |

---

## 三、目录结构

    awdp-plus/
    ├── README.md                    本文件
    ├── docker-compose.yml           一键起全部 GameBox
    ├── _shared/agent_core/          共享 AI Agent 平台框架
    │   ├── core.py                  DB / lock / audit / claims / model_intent
    │   ├── model.py                 确定性「legacy decision」裁决引擎
    │   ├── wsgi.py                  WSGI 前端（auth / audit / agent-runs / 委托）
    │   └── errors.py                Problem 基类
    ├── _tools/                      构建与验证工具链
    │   ├── specs.py                 9 题还原规格（含 Checker 逻辑）
    │   ├── build.py                 GameBox 生成器
    │   ├── verify.py                四项验证器（V1~V4）
    │   └── verify_report.json       最近一次验证结果
    └── <题目>/                       每题一个 GameBox
        ├── Dockerfile
        ├── README.md                该题还原说明
        ├── src/                     漏洞版源码（部署到容器 /app）
        │   ├── app.py               GameBox 入口（读 FLAG + 装配 core/service/rail）
        │   ├── <error_shim>.py      DomainError 定义
        │   ├── <service>.py         业务服务（含漏洞）
        │   ├── <rail>.py            Agent rail（含漏洞）
        │   └── agent_core/          共享框架副本
        ├── patch/                   修补文件 + update.sh
        ├── dist/<题目>_patch.tar.gz 可上传的修补包
        └── checker/checker.py       AWDP Checker

---

## 四、共享框架（agent_core）

原比赛的服务模块依赖一个未随附件下发的平台 core（core.db / core.audit /
core.model_intent 等）。本工程按调用契约重建了该平台层：

| 接口 | 说明 |
| --- | --- |
| core.lock | 全局可重入锁（与挑战模块的 with core.lock, core.db() 用法一致） |
| core.db() | 线程本地常驻 SQLite 连接（原平台允许 with 块外继续使用同一句柄） |
| core.audit(user, event, detail, run_id) | 审计流水，/v1/audit 按 tenant+subject 隔离返回 |
| core.ensure_service_account(name, role, label) | 创建 approver/operator 等服务账号 |
| core.issue_claim / core.read_claim | 能力凭据（grant）签发与校验，失败抛域错误 |
| core.model_intent(...) | 裁决引擎，返回 (action, profile, model, fingerprint) |

### model_intent：确定性裁决引擎

原平台由真实 LLM 裁决，本工程用**确定性规则**复现 WRITEUP 记录的决策表，
无需外部模型即可稳定复现漏洞：

    authorization=approved                 -> 高影响工具
    authorization=none + 显式措辞(注入)     -> 高影响工具（这是漏洞本身）
    其它                                   -> 安全默认工具

工具可见性由各题 rail 先行把关（如 _explicit_*_request / _exposed_tools），
引擎只在可见集合内偏向最高影响工具，因此**修补后漏洞不可达**能被精确复现。

---

## 五、部署

### 单题

    cd shift_handoff_inspector
    docker build -t shift_handoff_inspector .
    docker run -d --name shift_handoff_inspector -p 5000:5000 \
        -e FLAG=flag{local-dev-0001} shift_handoff_inspector
    python checker/checker.py http://127.0.0.1:5000

### 全部（compose）

    docker compose up -d --build
    python _tools/verify.py            # 本地四项验证（需 Python 环境）

---

## 六、Flag 机制

| 项 | 说明 |
| --- | --- |
| 存储位置 | 环境变量 FLAG（平台 FlagServer 每轮写入新旗标）；回退文件 /flag、/flag.txt |
| 刷新方式 | 每轮平台更新 FLAG 并重启容器；app.py 启动时读取并把旗标写入**受限 fixture**（幂等 UPDATE） |
| 格式 | flag{...}（WRITEUP 原比赛为 32 位 UUID） |
| 隔离 | 每题独立容器 + 独立 SQLite（/app/data/<题目>.db），天然按队隔离 |

各题旗标落地字段见第二节表格；release_control_tower 的旗标在容器 env（经 RCE 读取），
ez_Render 的旗标在 /tmp/flag.txt（经 SSTI 读取）。

---

## 七、修补机制

修补包 dist/<题目>_patch.tar.gz 内为：修补后的模块文件 + update.sh。

    #!/bin/sh
    cp /app/<module>.py /app/original_<module>.py
    cp <module>.py /app/<module>.py

- Patch Directory：/app
- 白名单命令：mv / cp / rm（update.sh 仅用 cp）
- 校验链路：平台上传 tar.gz → 解包执行 update.sh → 重启服务 → 运行 Checker + EXP

修补点（每题 README 详述）统一遵循「最小改动 + 纵深防御」：
先断数据面（旗标不落业务字段/脱敏），再收行为面（服务端授权为唯一权威）。

---

## 八、Checker

    python checker/checker.py <base_url>                         # SLA：存活 + 业务功能
    python checker/checker.py <base_url> --exploit               # 断言漏洞可利用（修补前）
    python checker/checker.py <base_url> --exploit --expect-blocked  # 断言漏洞已被封堵（修补后）

退出码 0 = 通过。阶段：
1. liveness  —— GET /health 返回 200 {"ok": true}
2. functional —— 注册 + 业务写入 + 读回（保证修补不破坏正常业务）
3. flag      —— 复现该题漏洞链读取旗标；默认仅参考，--exploit/--expect-blocked 才计入退出码

---

## 九、验证结果（9/9）

| 题目 | V1 漏洞可利用 | V2 服务正常 | V3 修补有效 | V4 修补不回归 |
| --- | --- | --- | --- | --- |
| shift_handoff_inspector | PASS | PASS | PASS | PASS |
| last_mile_dispatch_board | PASS | PASS | PASS | PASS |
| invoice_reconciliation_desk | PASS | PASS | PASS | PASS |
| merchant_assortment_studio | PASS | PASS | PASS | PASS |
| onboarding_memory_steward | PASS | PASS | PASS | PASS |
| signal_triage_console | PASS | PASS | PASS | PASS |
| release_control_tower | PASS | PASS | PASS | PASS |
| runbook_sentinel | PASS | PASS | PASS | PASS |
| ez_Render | PASS | PASS | PASS | PASS |

验证方式：_tools/verify.py 对每题
① 启动漏洞版服务 → Checker SLA + EXP（须泄露旗标）；
② 在源码副本上执行 update.sh → 重启 → Checker SLA + EXP --expect-blocked（须不泄露）。
详细输出见 _tools/verify_report.json。

---

## 十、还原程度说明

1. **源码还原**：8 题的业务模块来自决赛附件，逐字节保真（含漏洞代码）。
2. **平台层重建**：原平台 core 未随附件提供，按挑战模块的调用契约重建
   （agent_core），其中 LLM 裁决以确定性规则复现 WRITEUP 记录的决策表。
3. **ez_Render**：无附件，依据 WRITEUP 的攻击链（Jinja2 SSTI + WAF 字面过滤 +
   /tmp/flag.txt）重建等价实现。
4. **修补包**：shift_handoff / last_mile / invoice / merchant / onboarding /
   signal 使用比赛期间产出的官方修补模块；release / runbook / ez_Render 依据
   WRITEUP 的修复方案实现。

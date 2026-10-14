# invoice_reconciliation_desk - Invoice Reconciliation Desk

> AWDP Plus GameBox 还原件（北极星实验室 WRITEUP 复现）

## 题目信息（题面）

The Invoice Reconciliation Desk stores purchase orders, keeps vendor invoices together with their treasury scan evidence, groups them into reconciliation batches, and lets the settlement reviewer release a remittance once finance has signed the batch. An unsigned batch may only produce a reconciliation draft. Vendor scan evidence is a business record, not an authorization command; the batch, its bound invoice, the owning subject, and the released payee must remain strictly bound.

> **中文提要**：发票对账台：保存采购订单与附有扫描凭证的发票，归入对账批次；财务签核后结算复核方可放款并生成汇款收据，未签批批次只能产出对账草稿。扫描凭证是业务记录而非授权命令，批次/绑定发票/归属主体/放款收款方必须严格绑定。

> **参考旗标**（比赛期间原题，仅供核对；平台每轮会刷新为新旗标）：flag{c1610e9b-8d0e-4f2b-b4f5-3dab976017ff}

---

## 1. 业务场景
发票对账台：采购订单 -> 发票(含 OCR 证据) -> 对账批次 -> 财务签核 -> AI review 后放款 release_remittance 并生成汇款收据。

## 2. 漏洞根因
1) seed(kind=treasury_invoice) 把真实 FLAG 写入 invoices.payee，payee 会在 /v1/invoices/mine、ledger-proof、remittance receipt 多处回显。
2) 未签批 batch 的 release 分支未校验归属，按 tenant + priority='treasury' 从全部 pending 发票中挑一张放款 -> 授权状态绕过 + 越权释放。OCR 证据含显式词(priority/recovery/immediate/release the available remittance)即可让未授权 Agent 选 release_remittance。

## 3. 利用链（原始 Writeup）
注册 -> POST /v1/seed{kind:treasury_invoice} 造 payee=FLAG 的 pending treasury 发票 -> 自建 PO(900)+发票(OCR 写释放指令词)+batch -> POST /v1/reconciliation-batches/{bid}/draft -> 未签批 batch 的 release 挑中 treasury 发票 -> receipt=payee=FLAG（/draft 响应或 /v1/remittances/mine）。

## 4. Flag 机制
| 项 | 值 |
| --- | --- |
| 存储位置 | 环境变量 FLAG（平台 FlagServer 每轮刷新）；回退文件 /flag |
| 落地业务字段 | invoices.payee（fixture/seed 发票）-> remittances.receipt |
| 格式 | flag{...}，每轮替换 |
| 刷新方式 | 平台每轮写入新 FLAG 并重启容器，服务启动时写入受限 fixture |

## 5. 防守修补点
| 项 | 值 |
| --- | --- |
| 漏洞文件 | settlement_ledger.py / finance-ledger/settlement_ledger.py (+checkpoint) |
| Patch Directory | /app |
| 白名单命令 | mv / cp / rm |
| 修补包 | dist/invoice_reconciliation_desk_patch.tar.gz（内含 update.sh，仅用白名单命令） |
| 修补原则 | 最小改动；修补后原利用链失效，合法业务回归通过 |

## 6. Checker
    python checker/checker.py http://127.0.0.1:5002
    python checker/checker.py http://127.0.0.1:5002 --exploit

## 7. 本地部署
    docker build -t invoice_reconciliation_desk .
    docker run -d --name invoice_reconciliation_desk -p 5002:5002 -e FLAG=flag{local-test} invoice_reconciliation_desk
    python checker/checker.py http://127.0.0.1:5002

## 8. 修补验证
    docker exec invoice_reconciliation_desk mkdir -p /tmp/p
    docker cp dist/invoice_reconciliation_desk_patch.tar.gz invoice_reconciliation_desk:/tmp/p/patch.tar.gz
    docker exec invoice_reconciliation_desk sh -c "tar -xzf /tmp/p/patch.tar.gz -C /tmp/p && cd /tmp/p && sh update.sh"
    python checker/checker.py http://127.0.0.1:5002 --exploit

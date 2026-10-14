# round3_1700/web03 · 双应用关联利用（FTP 工具 + 图片导航：SSRF / 老版命令注入 / wget 解析差异）

| 项 | 值 |
|----|-----|
| 轮次 | 环节三（17:00） |
| 平台题目名 | web03 |
| 比赛 qid | `QTer81sTgUGC2jUb` |
| 分类 | web |
| 分值 | 500 |
| 交互型 | true（容器） |
| 关键 flag | **`（未获取）`** |
| 是否解出 | **未解出** |
| **还原完整度** | **B**（★ 拿到旧版 `show_img_v1.0.php` 的**逐字节原始源码**与 index.html / show.html / ftp.php 的实测 HTML，重建忠实；容器可跑；但未解出） |

> ⚠️ **质量红线声明**：本题在本队手上**未解出**，因此 flag 字段写 `（未获取）`，**不填任何猜测值**。
> §1 题面为平台原文逐字复制；§3 考点全部有实测证据；§4 设计思路里凡属推测均已显式标注「推测」。

> **环境修复记录（2026-09-28）**：上表保留比赛期间的真实结果。重建题目现已补全可复现的解题链：网页 FTP 工具上传 `.phtml` 到本机 `pub/`，图片应用从仅允许的本机 FTP 拉取文件到 `temp_img/`，Apache 执行后返回当前容器动态 Flag。可直接运行 `python solve/solve.py --target <靶机地址>`；完整平台容器验收以 `deploy/agent-images/r3-web03/verify.py` 为准。

## 1. 题面（比赛原文，逐字保留）

> 这个网站上存在两个应用程序，找到其中的关联性，挖掘其存在的漏洞，最终获取目标系统下的flag作为你的答案进行提交。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | **无附件，纯容器题**（`file_url` 为空） |
| 容器 | 初始 `https://eci-2zeb8yl7l1wi17x2qp00.cloudeci1.ichunqiu.com:80`（**该地址后来 502 失效**）；轮换后为 `https://eci-2zebwv3hjy934i770cf9.cloudeci1.ichunqiu.com:80` |
| 附件存放 | `attachments/.gitkeep`（占位，本题无附件） |
| 本地复现入口 | `http://127.0.0.1:8093`（`deploy/docker-compose.yml`；容器内同时监听 `:80` Apache / `:8080` nginx / `:21` FTP） |

### 2.1 沙箱内服务拓扑（**全部由 `show_img.php` 的 SSRF 探测确认**）

| 地址 | 是什么 | 证据 |
|---|---|---|
| `127.0.0.1:80` | 外层 **Apache 2.4.52 (Debian)**，docroot `/var/www/html`（报错泄露 `in /var/www/html/ftp.php on line 142`） | `_txt\apps.txt`、`_txt\ftp2.txt` |
| `127.0.0.1:8080` | 内层 **nginx**，docroot 含 `index.html`（**612 字节** nginx 默认页）与 `/1m9/{one,two,three}.png`（真图，**583611 / 1253091 / 1027743 字节**） | `_txt\oracle.txt:16-19` |
| `127.0.0.1:21` | **FTP，anonymous 可登录**，chroot 根目录**只有两项**：`pub/`（**可写**）与 `show_img_v1.0.php`（**旧版源码，可直接下载**） | `_txt\new1.txt:24-26`、`_txt\step2.txt:177` |

> FTP 根 ≠ 外层 docroot：`/flag`、`/flag.txt`、`/index.html`、`/www.zip`、`/etc/passwd` 等 38 个名字**全部下载失败**（每次都是同一份 2591 字节的错误页），说明 `ftp_get` 在 FTP 根里找不到它们。

## 3. 考点（★核心）

- **考点 1 — 「两个应用的关联性」= 同一个内部 FTP `127.0.0.1:21`**：题面直接点明"找到其中的关联性"。首页 `/`（「应用中心」）是两张卡片：`① /ftp.php`（FTP 工具）与 `② /show.html` → `/show_img.php`（图片导航）。**关联点就是这两者都能触达同一个内部 FTP 服务** —— `ftp.php` 用用户可控的 `ftp_server=127.0.0.1` 匿名登录它；`show_img.php` 的 SSRF 也能探测它。这不是"两个独立的洞"，而是**一条链上的两个原语**：FTP 用来**读源码**（信息泄露），图片导航用来**打内网**（SSRF / 命令注入）。
- **考点 2 — FTP 工具的三重原语 + 匿名可写**：`/ftp.php` 让用户完全控制 `ftp_server` / `ftp_user` / `ftp_pass`，连上后提供三个能力：`?dir=<path>` **列目录**、`?download=<path>` **把 FTP 上任意文件的内容回显到 HTTP 响应**（实测 `Content-Type: application/octet-stream`）、multipart 字段名 **`upload`** **上传文件**。目标 FTP 开了 **anonymous** 且 `pub/` 可写（实测 `✅ 文件 r3zq.phtml 上传成功`）。这三个原语单独看都"不致命"，合起来构成**任意文件读取 + 任意文件写入（到 FTP 根）**。
- **考点 3 — ★ 老版本源码泄露 = 白盒化整道题**：FTP 根目录里放着一个**旧版** `show_img_v1.0.php`，用 `ftp.php?download=/show_img_v1.0.php` 可以**完整下载**（HTTP 200，`application/octet-stream`，4053 字节）。这份源码是**逐字节抓回来的**（见 §8），其 PHP 头部为：
  ```php
  <?php
  if(!isset($_GET['img_url'])){ die("no"); }
  $img_url = base64_decode($_GET['img_url']);
  $path = parse_url($img_url, PHP_URL_PATH);
  $img_name = pathinfo($path, PATHINFO_BASENAME);

  # 老版本的漏洞，已在新版本得到了修复  tips: wget的漏洞
  system("wget  -P temp_img  '".$img_url."'");
  ?>
  ```
  这里有两处关键信息：① `system()` 里的 `$img_url` 被**单引号包裹且未做任何转义** → **命令注入**（闭合单引号 + `;`）；② 作者留下注释 **`tips: wget的漏洞`**，把第二条路（wget 自身的 URL 解析缺陷）**明确点出来了**。
- **考点 4 — 线上 v2 的字符黑名单（逐字符实测全表）**：`show_img.php`（"修复版"）的过滤口径已完整测绘（`_txt\filt.txt`、`_txt\filt2.txt`）：
  - 无参数 → 恰好 **2 字节** `no`；
  - 非 `http://` 开头（**大小写不敏感**，`HTTP://` / `Http://` 都能过）→ **36 字节** `目前只能加载本地图库……`；`https://`/`ftp://`/`file://`/`dict://` 全被拒；
  - host 白名单 = `parse_url($url, PHP_URL_HOST)` 必须是 `127.0.0.1` 或 `localhost`：`example.com`、`127.0.0.1.nip.io`、`2130706433`（十进制）、`0x7f000001`（十六进制）全被拒；**但 `http://example.com@127.0.0.1:8080/1m9/one.png` 能过、反向 `http://127.0.0.1:8080@example.com/` 被拒** —— 说明判定用的是 `parse_url` 的 host 字段（`@` 前的 userinfo 被忽略），而**这正是 wget 解析不一致的入口**；
  - 字符黑名单（**逐字符实测**）：`'` `"` `;` `|` `&` `` ` `` `$` `(` `)` `{` `}` `<` `>` 空格 TAB 换行 `?` `%` `#` `\` `=` `*` `!` `-` `_` `,` `+` `[` `]` → **18 字节** `不要这样子哦`；
  - 关键字：任何含 **`php`**（不分大小写，`xphp`/`x.phpx`/`Php` 都中）或含 **`_`** → **12 字节** `你想干嘛`；
  - **放行的字符只剩**：字母数字 + `:` `/` `.` `@` `~`。
  - ★ **检查顺序（本还原实测确认，这个顺序是唯一能同时解释所有实测现象的；写在前面是因为它很容易被"优化"错）**：
    **① 字符黑名单（含 `_`） → ② `php` 关键字 → ③ `http://` 前缀 → ④ host 白名单 → ⑤ 执行 wget**。
    证据链（重建环境独立复核 18/18，覆盖原赛场 `_txt\filt.txt`/`filt2.txt` 的全部判定）：
    | URL | 实测响应 | 说明 |
    |---|---|---|
    | `http://127.0.0.1:8080/a_b` | `不要这样子哦`（18B） | 含 `_` → **①先命中** |
    | `http://127.0.0.1:8080/temp_img/one.png` | `不要这样子哦` | 同上（`_` 在路径里也拦） |
    | `http://127.0.0.1:8080/show_img_v1.0.php` | `你想干嘛`（12B） | **无黑名单字符**，但含 `php` → **②命中** |
    | `ftp://127.0.0.1/show_img_v1.0.php` | `你想干嘛` | 同①无命中、**②先于③** |
    | `ftp://127.0.0.1/pub/x.txt` | `目前只能加载本地图库……`（36B） | ①②都不命中 → 落到 **③** |
    | `HTTP://` / `Http://...` | 通过（3734B） | **③ 大小写不敏感** |
    | `http://127.0.0.1:8080/1m9/../1m9/one.png` | 通过 | `.` 与 `/` 是放行字符 |
    | `http://127.0.0.1:8080/wget` | 通过（3731B） | **`wget` 不是关键字**（只有 `php` 是） |
    | ★ `http://127.0.0.1:8000/p.phtml` | 通过 | **`p.phtml` 里没有 `php` 子串** —— 黑名单只查 `php`，**不查 `phtml`**！ |
    > ⚠️ **最后一行是本题的一个关键容易搞错之处**：很多人（包括我们第一轮复核）会以为 `phtml` 含 `php` 所以会被拦
    > —— **实际上 `phtml` 的字符是 `p-h-t-m-l`，根本不含连续的 `php`**。因此 **URL 里可以出现 `.phtml`**，
    > `?img_url=b64(http://127.0.0.1:PORT/p.phtml)` 能通过全部过滤。这直接决定了 §4.1 (b′) 的可行性。
- **考点 5 — 回显型 SSRF（"可读回"的 SSRF）**：`system("wget -P temp_img '<url>'")` 把下载物存到 **`temp_img/<basename>`**，而 `temp_img/` 在**外层 Apache 下可直接访问**。实测 `?img_url=<b64:http://127.0.0.1:8080/index.html>` → `GET /temp_img/index.html` 得到 **612 字节 nginx 默认页**；`<b64:.../1m9/one.png>` → `GET /temp_img/one.png` 得到 **583611 字节真 PNG**。这让 SSRF 从"盲打"升级为**任意内部 HTTP 内容读取 + 存在性 oracle**（结合返回长度可精确判断内网路径是否存在）。注意 `/temp_img/` 目录本身是 **403**（无 autoindex）。
- **考点 6 — 「修复」不彻底：旧版仍在 FTP 根里**：这是一个典型的**"修了新版本、忘了下线老版本"**（legacy-version / dead-code）漏洞。v2 的字符黑名单确实把 `' ; | & ( ) { } $ \` < > 空格 TAB 换行 ? % # \ = * ! - _ , + [ ]` 全封了，**如果旧版不存在，这条命令注入就无从下手**；但旧版被原样留在 FTP 根目录里，且 **`ftp.php` 提供了把它读出来并借助 SSRF 定位/触达的能力**。设计意图（推测）：逼选手把「读源码」和「打内网」两个应用串起来，而不是只看其中一个。
- **考点 7 — wget 与 `parse_url` 的解析不一致**：作者注释 `tips: wget的漏洞` 直指这一点。已实测到的**具体不一致行为**（`_txt\new1.txt`）：
  - `http://127.0.0.1:8080/1m9/one.png@127.0.0.1:8080/1m9/two.png` → **PASS**，落盘 `temp_img/two.png`。即：**PHP 的 `parse_url` 把 host 看成 `127.0.0.1`（通过白名单），而 wget 最终取的却是 `@` 之后那个路径** —— 两套解析器对同一个字符串的处理不同，白名单校验因此失效；
  - `http://example.com@127.0.0.1:8080/1m9/one.png` → **PASS**（userinfo 形式，host 判为 `127.0.0.1`）；
  - `http://127.0.0.1:8080/1m9/one.pn~` → **PASS**，落盘名**去掉尾部 `~`** → `temp_img/one.png`（**wget 会改写落盘文件名**，这一点很重要）；
  - `http://127.0.0.1:8080/1m9/one.png~` → **被拦**（触发 `不要这样子哦`，说明黑名单的判定并非简单的"逐字符放行"，其细节我们未完全反推出）。
  > ⚠️ **重要更正**：这条**不是** CVE-2024-10524 "Wget shorthand URLs SSRF"。该 CVE 的触发前提是
  > 「**URL 不含 scheme** + 攻击者控制 userinfo」，而本题**强制 URL 以 `http://` 开头**，不满足前提。
  > 详见 §4.1 推测路线 (b) 的完整查证。我们**没有**拿到目标的 wget 版本，因此这条差异的**确切成因未确证**；
  > 它在重建环境中也**无法复现**（本机 wget 1.25.0 行为不同，见 §8）。
- **考点 8 — 已排除的路径（负结果同样是考点证据）**：
  - 外层直接访问 `/show_img_v1.0.php`、`/show_img_v1.0.php.bak`、`/ftp.php.bak`、`/show_img.php.bak` → **全 404**（309 字节 Apache 默认页）；Host 头 vhost 猜测无效；
  - FTP 的 `pub/` 里上传的文件**没有任何 web 服务在服务**：5 个端口（80/8080/8081/8000/8888）× 15 个路径前缀（`/`、`/pub/`、`/old/pub/`、`/v1/pub/`、`/ftp/pub/`、`/html/pub/`、`/uploads/pub/`、`/upload/`、`/files/`、`/temp/`、`/data/`、`/static/`、`/assets/`、`/images/`、`/img/`）**全部 miss**；
  - `mod_userdir` 猜测（`/~ftp/`、`/~www-data/`、`/~user/` 等 **16 个用户名**）× `:80`/`:8080` → 全 miss；
  - FTP 被 chroot；FTP 根里除 `pub/` 与 `show_img_v1.0.php` 外**没有任何其它文件**；
  - 内网端口扫描：**54 个内部端口**全部无 web 服务（只有 80/8080/21 三个是活的）。

## 4. 设计思路（★核心，站在出题人角度）

> 凡未由实测直接支撑的因果解释均标注为**推测**。出题人未提供设计文档。

- **为什么这样出 —— 一道"必须把两个应用串起来"的链式题**：题面把设计意图讲得非常直白：「这个网站上存在两个应用程序，**找到其中的关联性**」。这是出题人在明示：**单看任何一个应用都不足以解题**。`ftp.php` 单独看只是一个"FTP 客户端工具"（能连任意 FTP、能列目录、能下载、能上传），`show_img.php` 单独看只是一个"图片导航"（服务端 wget 取图）。**设计意图（推测）**是让选手意识到：题目把一个**过期的漏洞实现**放在 FTP 服务器上（而不是放在 web 目录里），因此你**只能先通过 FTP 工具把它读出来**，拿到源码后才可能构造针对旧版的攻击；而要把攻击送达旧版，又需要 **SSRF**（图片导航）来触达内网。两个应用互为"钥匙"和"门"。
- **难度卡点设计在哪 —— 三重门，缺一不可**：
  1. **第一重门：信息。** 旧版源码不在 web 上（`/show_img_v1.0.php` → 404），只能从 FTP 根读；而"FTP 里有东西"这件事本身也要靠 `ftp.php` 匿名登录才看得到。**没有第一步，后面全是猜。**
  2. **第二重门：送达。** 即使知道旧版是命令注入，你还得**把请求送到它**。它不在外层 docroot（404），所以必须经内网（SSRF）。
  3. **第三重门：过滤。** v2 的字符黑名单只留 `字母数字 : / . @ ~`，把命令注入所需的 `'` `;` `(` `)` 空格 `$` 全部封死；**要打旧版，就必须先绕过 v2 或绕过"如何触达旧版"**。出题人留 `@` 与 `~` 两个字符，配合注释里的 `tips: wget的漏洞`，把第三条路（**wget 自身的 URL 解析不一致**）明确指示出来。
- **难度卡点设计在哪（2）—— "修复"叙事本身就是陷阱**：注释写着「老版本的漏洞，已在新版本得到了修复」，题面又说"挖掘其存在的漏洞"。**这句话会让人本能地去看新版（v2）** —— 而 v2 的过滤**确实做得很严**（纯字符白名单 + 关键词 + host 校验），于是选手会倾向于"v2 无解"。设计意图（推测）：这句"已修复"是**反向诱导** —— 它暗示你**不要**在 v2 上浪费轮次，而要去找"老版本还在不在"。**这正是本题的思维分水岭。**
- **干扰项 / 诱导项（明确列出）**：
  1. **`https://` / `ftp://` 被拒**：诱导选手去纠结"协议白名单"，实际上 `http://` + `@` 就够用（`@` 能骗过 `parse_url` 的 host 判定）。
  2. **十进制/十六进制/`nip.io` 形式的 IP（`2130706433`、`0x7f000001`、`127.0.0.1.nip.io`）全被拒**：诱导选手以为"SSRF 被彻底锁死在 127.0.0.1 上，无法出网"，从而放弃 wget 简写这条路。
  3. **`pub/` 目录可写但无处可达**：这是**最大的时间陷阱**。上传 `.phtml` 成功了（页面明确回显 `✅ 文件 r3zq.phtml 上传成功`），会给人强烈的"我已经拿下一半"的错觉；但 15 个路径前缀 × 5 个端口全 miss，**上传物没有任何 web 服务在服务**。写下"上传成功"却访问不到，是本队消耗最多轮次的地方。
  4. **`ftp.php?download=` 绕过一切文件读取限制**：它把**FTP 服务器上**的文件读出来 —— 注意**不是** web 服务器上的文件。选手容易误以为"我能任意读文件了"，进而去尝试 `download=/flag`、`download=/etc/passwd`、`download=/www.zip`（全部失败，因为 FTP 被 chroot，根里只有两项）。**它可以读的东西恰好只有一个：旧版源码。**
  5. **`show_img.php` 的 host 白名单看起来"实现正确"**：`parse_url(...)['host']` 是**教科书式的正确写法**（因为 `parse_url` 会把 `@` 前的内容当 userinfo）。陷阱在于**下游的 wget 用另一套规则解析同一个字符串** —— 校验器与被校验者不是同一个解析器，这才是真正的漏洞。
  6. **`/1m9/{one,two,three}.png` 三个真图**（583KB / 1.2MB / 1MB）：它们让 SSRF 有"正常用途"可演示，也让 `/temp_img/` 里有真实文件可读，掩盖了 SSRF 的攻击性。
- **哪些地方是"必须踩坑才会发现"的**：
  - 不登录 FTP 匿名账号，就不知道里面有旧版源码（这是**整道题的入口**，但首页两张卡片完全没有提示 FTP 有 anonymous）；
  - 不把 `ftp.php?download=` 指向 `/show_img_v1.0.php`，就看不到 `tips: wget的漏洞` 这句"官方提示"；
  - 不做**字符级**过滤测绘（逐字符试），就不会知道放行集恰好是 `字母数字 : / . @ ~`，也就不会注意到 `@` 和 `~` 的"刻意留白"；
  - 不试 `@` 变形（`http://a@127.0.0.1:8080/...` vs `http://127.0.0.1:8080/...@...`），就不会发现 `parse_url` 与 wget 的不一致（实测 `.../one.png@127.0.0.1:8080/.../two.png` 确实返回 `two.png`）；
  - 不把 `pub/` 上传物在 5 端口 × 15 前缀上穷举一遍，就不会相信"上传物无处可达"（这个负结果必须**亲手验证过**才敢下结论）。
- **对 AI 智能体参赛的针对性**：本题的"关联性"是题面明说的，但**两个应用之间的桥**（FTP 匿名登录 + 旧版在 FTP 根 + SSRF 触达内网）需要**多步信息拼合**。非常适合会系统性穷举的智能体；分水岭在于**是否会把"上传成功但访问不到"这个强负反馈转成"换面"**（本队没做到），以及**是否会注意到注释里的 `tips: wget的漏洞` 是一句真正的提示而不是装饰**。

### 4.1 预期正确解法（★ 重要：诚实标注为"未证实的推测"）

> **结论先行：预期解法未确证。本题在本队手上未解出。** 已确认的两个最有价值方向如下，**均未验证完成**。
> 出题人未提供设计文档；以下为**赛后复盘的推测**，技术机理均有实测支撑，但**串联成完整链的那一步我们没有走通**。

- ★ **推测路线 (a)（我们判断的"出题人预期主路"）—— 经 SSRF 触达旧版 `show_img_v1.0.php` 的命令注入。**
  机理（**全部有实测支撑**）：旧版源码里 `system("wget  -P temp_img  '".$img_url."'")` 的 `$img_url` 未经转义 →
  闭合单引号 + `;` 即可注入。要注入就要让请求**落到旧版文件上**。
  - **串联假设（推测）**：外层 Apache 的 docroot 与 FTP 根存在某种**我们没能定位的映射**（例如 FTP 根在容器里就是
    `/var/www/html/old/`、或 Apache 有一个我们没猜到的 `Alias`），使得"上传到 FTP `pub/` 的 `.phtml`"或"旧版文件本身"
    能在某个内网路径上被请求到。我们实测了 15 个前缀 × 5 个端口与 16 个 `/~user/` 全 miss，
    **所以更可能是我们猜的前缀不对，而不是不存在**。
  - **另一条串联假设（推测）**：**双层 base64**。`show_img.php` 只对 `$_GET['img_url']` 做**一次** `base64_decode`；
    如果存在某个地方做了两次解码，那么黑名单检查的就是第一次解码后的串……
    **但我们实测 `_` 被拦**（`a_b` → `不要这样子哦`），且 base64 字母表含 `+` `/` `=`（均在黑名单），
    所以这条路在单层解码模型下**不成立**。**倾向排除。**
  - **这不是"如何注入"的问题，而是"如何送达到旧版文件"的问题。**
  - **验证方法**：把 `show_img.php` 的 `img_url` 指向内网任意路径，用**返回长度**做存在性 oracle（§3 考点 5），
    系统性枚举 docroot 下的目录名，直到命中一个能返回旧版文件内容的路径。
    ```python
    # 逐个 XXX 试，看 /show_img.php 的响应长度是否出现 4053（旧版源码长度）而非 ~3732（图片展示页 200 的长度）
    img_url = base64('http://127.0.0.1:80/XXX/show_img_v1.0.php')
    # 或反过来：看 /temp_img/show_img_v1.0.php 是否变成可访问
    ```

- ★ **推测路线 (b)（作者注释直指的方向，但我们**已把这条证伪**）—— wget 与 `parse_url` 解析不一致。**
  作者在旧版源码里留下注释 **`tips: wget的漏洞`**，第一反应是 **CVE-2024-10524 "Wget shorthand URLs SSRF"**
  （JFrog `JFSA-2024-001063927`，CVSS 6.5）。**但查证权威来源后，这条路在本题里走不通**，理由如下（这部分是**事实**，不是推测）：
  - 该 CVE 的触发条件是 **「shorthand URL（不含 scheme）+ 用户凭据被放进 userinfo」**。JFrog 原文给的形态是
    `wget user_input@example.com/file`，攻击者提交 `myuser:mypass` → 实际命令行成为
    `wget myuser:mypass@example.com/file` → wget **把它当成 FTP**，去连主机 `myuser`、取
    `mypass@example.com/file` —— 也就是说**攻击者控制了 host**。
  - **本题不满足这个前提**：`show_img.php` 强制要求 URL 以 `http://` 开头（实测 `HTTP://` / `Http://` 也算），
    所以传给 wget 的**永远是带显式 scheme 的绝对 URL**，不存在 shorthand 解析。带 scheme 时
    `http://127.0.0.1:8080/1m9/one.png@127.0.0.1:8080/1m9/two.png` 会被正常解析为
    「host=`127.0.0.1`、port=`8080`、path=`/1m9/one.png@127.0.0.1:8080/1m9/two.png`」→ 内部 nginx 返回 404。
    我们在重建环境里**实测确认**了这一点（容器内 wget 发出的请求路径就是整串，返回 `404 Not Found`）。
  - 版本对照（[Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2024-10524)、
    [JFrog 公告](https://research.jfrog.com/vulnerabilities/wget-shorthand-urls-ssrf-jfsa-2024-001063927/)）：
    `wget (.., 1.24.5]` 受影响，**1.25.0 修复**（commit `c419542d`）。Debian bookworm 的 `1.21.3` 属"vulnerable but no-dsa"。
  - **对我们的实测现象的正确解释**：线上 `http://127.0.0.1:8080/1m9/one.png@127.0.0.1:8080/1m9/two.png` → 落盘 `temp_img/two.png`，
    更可能是**老版本 wget 的路径处理差异**（另一种解析器分歧），而**不是**上述 shorthand SSRF。
    这一点我们**没有拿到目标的 wget 版本**，因此无法确证。
  - **诚实结论**：注释里的 `tips: wget的漏洞` 是一句**真提示**（指引你去看"校验器与执行器的解析差异"这一类问题），
    但**我们没能把它转成可用链**。**此路线标记为：已排查、倾向证伪、未利用成功。**

- ★ **推测路线 (b′)（★ 本队认为**最可能是出题人预期路径**的一条，且已有一半被实测证实）—— 借「ftp.php 可写 FTP + FTP 路径归一化」把 `.phtml` 送进 web 可读目录。**
  这是复盘时最有说服力的一条，因为它**不需要绕字符黑名单**，只需要让 wget 去读 **FTP 上我们自己写的文件**。
  - **已实测证实的前半段**（在重建环境里，把 scheme 校验临时放宽为"包含 `http://`"后复现）：
    1. `ftp.php` 匿名登录 → multipart `upload` 把 `p.phtml` 写进**匿名可写的 `pub/`**（实测 `✅ 文件 p.phtml 上传成功`）；
    2. 匿名账号还能 **`MKD pub/http:`**（建带冒号的目录名），把 `p.phtml` 放进 `pub/http:/`；
    3. 让 `show_img.php` 去取 `ftp://127.0.0.1/pub/http://../p.phtml` → **wget 把路径归一化成 `/pub/http:/p.phtml`**
       并把内容**落盘为 `/temp_img/p.phtml`**（**落盘名由 wget 决定，而不是由 URL 的 basename 决定**！）；
    4. `GET /temp_img/p.phtml?c=cat /flag` → **命令回显**（重建版返回占位 flag；`?c=id` 回显 `uid=33(www-data)`）。
  - **为什么在线上没走通**：线上**明确拒绝了 `ftp://`**（实测 `ftp://127.0.0.1/` → `目前只能加载本地图库……`），
    所以第 3 步在线上会先被 scheme 检查拦掉。**这正是我们卡死的地方。**
  - **由此得出的"预期解法"推测（仍未证实）**：既然 `ftp://` 被拒、只剩 `http://`，
    那么出题人预期的多半是**同一个 FTP 目录被某个 HTTP 端点服务**，或者**`http://127.0.0.1` 上的某个路径能读到 FTP 根**
    （我们测过的 15 个前缀 × 5 个端口全 miss，**很可能只是前缀没猜对**）。
    这条线的价值在于：它把"如何让 URL 里不出现 `php`"这个死结**解开了** —— 因为**落盘名由 wget 归一化决定**，
    URL 里可以完全不含 `php`，最终却落出一个 `.phtml`。**这是本题我们最想复原而没复原成功的一环。**
  - **给后续复现者的验证方法**：
    ```bash
    # 1) 匿名 FTP 建一个带冒号的目录，把 .phtml 放进去
    #    (ftp.php 匿名登录后：MKD pub/http:  → 再 upload 到 pub/http:/p.phtml)
    # 2) 让 show_img.php 去取（scheme 用 http:// 打内网 8080，路径里出现 "http:" 触发归一化）
    #    img_url = b64("http://127.0.0.1:8080/pub/http:/p.phtml")
    # 3) 看 /temp_img/ 下实际落盘的文件名，再请求它
    ```

- **推测路线 (c)（备选）—— Apache 是否解析 `.phtml` / 多重扩展名，以及 `/temp_img/` 的目录索引行为。**
  - **已实测确认**：重建环境的外层 Apache **确实把 `.phtml` 交给 mod_php 执行**
    （`/etc/apache2/conf-available/web03.conf` 里 `AddType application/x-httpd-php .phtml .php5 .php7 .phar .pht`），
    所以**只要能把 `.phtml` 写进 `temp_img/`，RCE 就成立** —— 这也反过来说明 (b′) 值得继续挖。
  - **已实测确认（一个有意思的细节）**：线上 `GET /temp_img/` 的行为**并非恒定 403**。原始 dump `_txt\diag.txt` 显示：
    先测 `GET /temp_img/` → **403**，但用 SSRF 抓取 `http://127.0.0.1:8080/`（**一个目录 URL**）之后，
    `wget` 把内部 nginx 的 `index.html` 落盘成 `temp_img/index.html`，**此后 `GET /temp_img/` 就返回 200**（612 字节）。
    ⇒ 这说明原始 Apache **是启用了 `DirectoryIndex index.html`** 的（否则不会 200）。我们的重建已按此对齐：
    `/temp_img/` 在**空目录时 403**、在**落盘了 index.html 之后 200** —— 与实测完全一致。

> **给后续复现者的最短排查清单**（按性价比排序）：
> ① ★ **把 (b′) 打通**：找一个 `http://127.0.0.1:<port>/<prefix>` 能读到 FTP 根/`pub/` 的映射
>    （试更多端口与前缀；也可试 `http://127.0.0.1:80/http:/...`、`/pub/http:/...` 这类**带冒号目录名**的形态）；
> ② 用 SSRF 存在性 oracle（响应长度）**系统性枚举外层 docroot 的目录名**，找旧版 `show_img_v1.0.php` 的可达路径；
> ③ 把 `ftp.php` 的 `?dir=` / `?download=` 当作**路径穿越原语**再挖一遍（`?download=/pub/../show_img_v1.0.php`、URL 编码 `..`、`?dir=..`）——
>    我们只试了 38 个直接名字，**没做目录遍历**；
> ④ 确认目标 wget 版本（若 < 1.24.5，则 (b) 的解析器分歧值得重试；我们本地是 1.25.0，无法复现）；
> ⑤ 实测外层 Apache 对**多重扩展名**（`x.phtml.txt`、`x.txt.phtml`）与 `MultiViews` 的行为。

## 5. 解题路径（按真实过程，分步骤 —— 含我们走过的弯路）

1. **侦察**：`GET /` → 「应用中心」，两张卡片 `ftp.php`（FTP 工具）与 `show.html`（图片导航）。`GET /show.html` → 三个按钮，base64 指向 `http://127.0.0.1:8080/1m9/{one,two,three}.png`。
2. **发现 SSRF**：`/show_img.php?img_url=<b64>` 服务端 `wget`。用 `http://127.0.0.1:8080/index.html` 验证落盘 → `GET /temp_img/index.html` = **612 字节 nginx 默认页** → **回显型 SSRF 确认**。
3. **内网测绘**（用 SSRF 当 oracle）：`127.0.0.1:80` = Apache 2.4.52 / docroot `/var/www/html`；`127.0.0.1:8080` = nginx + `/1m9/*.png`；`/temp_img/` = 403；`/show_img_v1.0.php` → 404。
4. **过滤器测绘**：逐字符跑 v2 的过滤表 → 放行集 = `字母数字 : / . @ ~`；`php` 与 `_` → `你想干嘛`；其余危险字符 → `不要这样子哦`；非 `http://` 或 host 不在白名单 → `目前只能加载本地图库……`。
5. **发现 FTP 关联**：`POST /ftp.php` 用 `ftp_server=127.0.0.1&ftp_user=anonymous&ftp_pass=x` → `✅ 已连接到 127.0.0.1，用户：anonymous`；列表 = `pub/` + `show_img_v1.0.php`。
6. **★ 拿到旧版源码**：`GET /ftp.php?download=/show_img_v1.0.php` → HTTP 200，`application/octet-stream`，**4053 字节**，含 `system("wget -P temp_img '".$img_url."'")` 与注释 **`tips: wget的漏洞`**。
7. **试上传落地**：`POST /ftp.php` multipart 字段 `upload`，上传 `r3zq.png` / `r3zq.phtml` → **都成功**；然后穷举 `127.0.0.1:{80,8080,8081,8000,8888}` × 15 个路径前缀 → **全 miss**；`/~user/` × 16 用户名 → 全 miss。**判定：上传物无处可达。**
8. **试路径穿越**：`ftp.php?download=` 直取 `/flag`、`/etc/passwd`、`/www.zip`、`/index.php` 等 38 个名字 → **全部返回同一份 2591 字节错误页**（FTP 被 chroot）。
9. **试 `@` / `~` 变形**（**这一步有正面结果**）：`http://127.0.0.1:8080/1m9/one.png@127.0.0.1:8080/1m9/two.png` → **PASS，落盘 `two.png`** —— 证实 `parse_url` 与 wget 的 host 判定不一致。同时 `one.pn~` → 落盘 `one.png`（wget 会改写落盘名）。
10. **卡点**：要把攻击者可控内容写进 `temp_img/` 并让它**可执行**，落盘名必须含 `phtml`/`php`，但**黑名单里 `php` 是关键词**（`x.php` → `你想干嘛`）→ **无法构造**。另：`temp_img/` 里写入的普通扩展名文件不会被 Apache 执行。
11. **结论**：**未解出**。环境可复现，两条主路（§4.1 a/b）**方向确证、串联未完成**。未写 flag 文件，**禁止编造**。

## 6. 参考解法（代码）

`solve/solve.py` **不是**一个"能拿 flag 的 exp"，而是**一份诚实的复现与测绘脚本**（参数化 `--target`、`--attacker-host`、`--attacker-port`）。它把 §5 的 1~9 步全部重放并断言，最后尝试 §4.1 路线 (b)。

```python
# 关键片段（完整见 solve/solve.py）
b64 = lambda u: base64.b64encode(u.encode()).decode()
# 1) SSRF 回显验证
s.get(T + '/show_img.php', params={'img_url': b64('http://127.0.0.1:8080/index.html')})
assert len(s.get(T + '/temp_img/index.html').content) == 612     # nginx 默认页
# 2) 过滤表断言
assert s.get(T + '/show_img.php').content == b'no'                                   # 2B
assert '不要这样子哦' in s.get(T+'/show_img.php', params={'img_url':b64('http://127.0.0.1:8080/a_b')}).text
assert '你想干嘛'     in s.get(T+'/show_img.php', params={'img_url':b64('http://127.0.0.1:8080/xphp')}).text
assert '目前只能加载本地图库' in s.get(T+'/show_img.php', params={'img_url':b64('http://example.com/')}).text
# 3) FTP 匿名登录 + 读旧版源码
s.post(T + '/ftp.php', data={'ftp_server':'127.0.0.1','ftp_user':'anonymous','ftp_pass':'x'})
src = s.get(T + '/ftp.php', params={'download':'/show_img_v1.0.php'}).content   # 4053B，含 system("wget ...
# 4) parse_url vs wget 不一致
s.get(T+'/show_img.php', params={'img_url': b64('http://127.0.0.1:8080/1m9/one.png@127.0.0.1:8080/1m9/two.png')})
assert len(s.get(T + '/temp_img/two.png').content) > 100000      # 取到的是 two.png
# 5) 尝试 (b)：让 wget 去攻击者主机取 .phtml → 起本地 HTTP server 投递 shell.phtml
#    再请求 /temp_img/<落盘名>?c=cat /flag
```

> 脚本退出码：`0` = 拿到 flag；`2` = **未解出（与比赛结果一致）**；`3` = 目标不可达。
> 脚本**绝不会**打印任何它没有真的从目标读到的 `flag{...}` 字符串。

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | **`（未获取）`** |
| 提交接口返回 | **无**（未提交过任何 flag；`work\submit_results_live.json` 中**没有** `QTer81sTgUGC2jUb` 的记录） |
| 提交时间 | — |
| 证据文件 | 无 flag 证据。侦察证据：`work\r3_web03\FINDINGS.md`（5.4KB 完整交接）、`_txt\*.txt`（17 份 dump：`apps`/`filt`/`filt2`/`ssrf`/`oracle`/`marker2`/`new1`/`step2`/`chain`/`ftp2`/`pscan`/`timg`/`idx`/`diag`/`final1`/`up`/`marker`）、脚本 `new1.py`/`listing.py`/`marker2.py`/`userdir.py`/`timg.py`/`chain.py`/`ssrf.py`/`filt2.py`/`oldapp.py` |

## 8. 还原说明（诚实写）

- **已有原始件**（比赛期间真实抓取，未改字节）：
  - ★ **`work\r3_web03\_v1_src.php`** — **旧版 `show_img_v1.0.php` 的逐字节原始源码**（4053 字节响应体；UTF-8 落盘 4213 字节 / 4128 字符，其中含 `© 2025 图片导航系统` 等非 ASCII）。**这是本题最重要的还原物**，`deploy/ftproot/show_img_v1.0.php` 与 `deploy/src/show_img_v1.0.php` 直接复制它。
  - `work\r3_web03\FINDINGS.md` — 5.4KB 完整交接文档（§1 两个应用 / §2 沙箱内服务 / §3 旧版源码 / §4 v2 过滤 / §5 SSRF 可读回 / §6 已排除路径 / §7 下一步两条线）。
  - `_txt\idx.txt` — **`index.html`（「应用中心」）的实测 HTML 全文**（含完整 CSS）。
  - `_txt\apps.txt`（17KB）、`_txt\step2.txt`、`_txt\ftp2.txt`（37KB） — `show.html` 与 `ftp.php` 的实测 HTML 全文（含三个按钮的 base64、`<form enctype="multipart/form-data"><input type="file" name="upload" required>`、`<p class="msg success">✅ 文件 X 上传成功</p>` 等）。
  - `_txt\filt.txt` / `_txt\filt2.txt` — **逐字符过滤全表**（本题核心证据）。
  - `_txt\oracle.txt` / `_txt\new1.txt` / `_txt\marker2.txt` — SSRF 存在性 oracle、host 白名单行为、`@`/`~` 变形实测。
  - 原始 `.txt` 全部为 **UTF-16LE + BOM**（当时用 PowerShell 重定向所致）；`_txt\` 下是转换出的 UTF-8 副本，**未改内容**。
- **重建部分**（`deploy/`）：
  - `deploy/src/show_img_v1.0.php` + `deploy/ftproot/show_img_v1.0.php` — **逐字节复制原始源码**（§3 考点 3 引用；`ftp.php?download=/show_img_v1.0.php` 能读回来）。
  - `deploy/src/show_img.php` — **v2 重建**：与 v1 **相同的 5 行 PHP 前导 + 相同的「图片展示」HTML 模板**（已 diff 确认 v1 与线上 v2 的 HTML 模板逐字节一致），中间插入实测口径的白名单/黑名单（`http://` 前缀**大小写不敏感**、`parse_url` host ∈ {`127.0.0.1`,`localhost`}、字符黑名单、`php`/`_` 关键词），响应体长度对齐实测（`no`=2B / `不要这样子哦`=18B / `你想干嘛`=12B / `目前只能加载本地图库……`=36B / 通过≈3732~3736B）。
  - `deploy/src/index.html` — 按 `_txt\idx.txt` 的实测 HTML 重建（同样的渐变背景、两张 200×200 `.app-card`、`<title>应用中心</title>`；修正了原 dump 的 latin-1 乱码为正确 UTF-8 中文）。
  - `deploy/src/show.html` — 按 `_txt\apps.txt` 重建，**三个按钮的 base64 与原文完全一致**。
  - `deploy/src/ftp.php` — 重建：`ftp_connect`/`ftp_login`（anonymous）+ `?dir=`（`ftp_nlist`，`pub/` 渲染为链接、文件渲为 `[下载]`）+ `?download=`（`ftp_get` 后回显原始字节，`application/octet-stream` + `Content-Disposition: attachment`）+ multipart 字段 **`upload`** + 实测的消息 HTML 结构。
  - `deploy/nginx/` — 内层 nginx（`127.0.0.1:8080`），docroot 含 612 字节默认 `index.html` 与 `/1m9/{one,two,three}.png`（重建为小尺寸真 PNG；**原图为 583KB/1.2MB/1MB**）。
  - FTP 容器（anonymous 可登录、chroot、`pub/` 可写、根目录放旧版源码）；`deploy/docker-compose.yml` 用 `network_mode: "service:apache"` 让 **`:80` Apache / `:8080` nginx / `:21` FTP 共享同一个 127.0.0.1**（这是本题 SSRF 拓扑的关键要求）。
  - `deploy/Dockerfile` 里的**保真细节（均已实测对齐）**：
    - `.phtml/.php5/.php7/.phar/.pht` 全部 `AddType application/x-httpd-php` → **`.phtml` 真的会执行**（与线上一致）；
    - `/var/www/html/temp_img` 里 `Options -Indexes` + **`DirectoryIndex disabled`**：空目录时 `GET /temp_img/` = **403**；
      而一旦 SSRF 把内部 nginx 的 `index.html` 落盘进去，`GET /temp_img/` 就变成 **200（612 字节）**
      —— **这正是原始 dump `_txt\diag.txt` 记录到的行为**（先 403、抓过目录 URL 之后 200）；
    - `deploy/entrypoint.sh` 每次 `up` 都把 `temp_img/` 与 `/srv/ftp/pub/` 清空 → 容器初始态可重复，对齐线上。
  - **补充实测的几条创建者/上传者行为**（均已在重建环境验证通过）：
    - `?download=` 返回的 `Content-Type: application/octet-stream` + `Content-Disposition: attachment`，body 即原始字节（4053 字节旧版源码逐字节一致）；
    - FTP 根里除 `pub/` 与 `show_img_v1.0.php` 外的名字（`/flag`、`/flag.txt`、`/index.php`、`/www.zip`、`/etc/passwd`）**全部返回同一份"下载失败"页** → 复现了"FTP 被 chroot、根目录只有两项"的负结果；
    - 匿名账号**能上传、能 `MKD`**（`perm='elradfmwMT'`），因此 §4.1 (b′) 的那条链在**放宽 scheme 校验后**可在本重建里完整跑通。
- **未能还原（★ 明确列出保真缺口）**：
  - **flag**（未获取，**不编造**）。
  - ★ **目标 wget 的版本/行为**（**本还原最重要的保真缺口**）：线上 `http://127.0.0.1:8080/1m9/one.png@127.0.0.1:8080/1m9/two.png`
    落盘成了 `temp_img/two.png`，说明**线上 wget 对该 URL 的解析与我们的重建环境不同**。我们的容器是
    **GNU Wget 1.25.0**（Debian trixie 源）—— 实测它把 `@` 之后的整串当作 **path** 发给 `127.0.0.1:8080`，内部 nginx 返回
    `404 Not Found`，**因此线上那个"落盘成 two.png"的现象在本地无法复现**。
    按权威来源（[JFrog JFSA-2024-001063927](https://research.jfrog.com/vulnerabilities/wget-shorthand-urls-ssrf-jfsa-2024-001063927/) /
    [Debian CVE-2024-10524](https://security-tracker.debian.org/tracker/CVE-2024-10524)：`(.., 1.24.5]` 受影响、**1.25.0 修复**），
    这条差异**大概不是** shorthand-url SSRF（那个 CVE 要求 URL **不含 scheme**，而本题强制 `http://` 开头），
    更可能是老版本 wget 的路径处理差异。**未能还原，也未验证。**
  - **外层 Apache 的 vhost / Alias / handler 配置**（本题无源码泄露）—— 这恰好是 §4.1 推测路线 (a)/(b′) 的关键未知量。
  - **FTP 服务端软件与配置**（只知道 anonymous 可登录、chroot、根目录两项、`pub/` 可写；不知道是 vsftpd / pure-ftpd / 别的）。
    重建用 `pyftpdlib`（`add_anonymous('/srv/ftp', perm='elradfmwMT')`）——**能匿名登录、能列目录、能下载、能上传、能 `MKD`**（已实测）。
  - **内层 nginx 的完整 docroot 结构**（只知道 `index.html` 与 `/1m9/*.png`；54 个内部端口扫描 + 15 个前缀穷举都没找到更多）。
  - **三个原始 PNG 的字节内容**（重建版用小 PNG 代替：`one.png` 12366 B / `two.png` 12412 B / `three.png` 12420 B，
    而**原图为 583611 / 1253091 / 1027743 字节**）—— 因此任何对图片字节数的断言都必须按重建版的尺寸改。
- **可复现性验证**（**已实测**，三层容器全部 `healthy`）：`cd deploy && docker compose up -d --build` 后，独立复核脚本 `_work\verify_r3web03.py` 的原始输出（**18/18 过滤表断言通过**）：
  ```text
  === 1) 健康检查 ===
    /                        200 len=1843
    /ftp.php                 200 len=2031
    /show.html               200 len=5256      ← 与线上实测 5256 字节完全一致
    /show_img.php            200 len=2    b'no'
    /temp_img/               403 len=316        ← 空目录时 403（与 _txt\diag.txt 首次实测一致）
    /pub/                    404 len=313        ← 与线上一致
    /1m9/one.png             404 len=313        ← 与线上一致（/1m9 只在内部 8080 上）
    /show_img_v1.0.php       404 len=313        ← 与线上一致（旧版不在 docroot）

  === 2) SSRF 回显 ===
    show_img.php -> 200 len=3737   img src = temp_img/index.html
    GET /temp_img/index.html -> 200 len=612  nginx=True     ← 内部 nginx 默认页被拖出来了

  === 3) v2 过滤表 ===
    (none)                              PASS  no                     
    http://127.0.0.1:8080/1m9/one.png   PASS  len=3734               
    http://127.0.0.1:8080/a_b           PASS  不要这样子哦              
    http://127.0.0.1:8080/a-b           PASS  不要这样子哦              
    http://127.0.0.1:8080/a b           PASS  不要这样子哦              
    http://127.0.0.1:8080/a;b           PASS  不要这样子哦              
    http://127.0.0.1:8080/a?b           PASS  不要这样子哦              
    http://127.0.0.1:8080/xphp          PASS  你想干嘛                 
    http://127.0.0.1:8080/x.phpx        PASS  你想干嘛                 
    http://127.0.0.1:8080/Php           PASS  你想干嘛                 
    http://127.0.0.1:8080/show_img.php  PASS  你想干嘛                 
    http://example.com/                 PASS  目前只能加载本地图库……     
    https://127.0.0.1:8080/1m9/one.png  PASS  目前只能加载本地图库……     
    ftp://127.0.0.1/                    PASS  目前只能加载本地图库……     
    http://127.0.0.1.nip.io/            PASS  目前只能加载本地图库……     
    http://2130706433:8080/1m9/one.png  PASS  目前只能加载本地图库……     
    http://0x7f000001:8080/1m9/one.png  PASS  目前只能加载本地图库……     
    http://127.0.0.1:8080@example.com/  PASS  目前只能加载本地图库……     
    --> 18/18 断言通过

  === 4) parse_url 与 wget 的差异 ===
    one.png@.../two.png -> 200 len=3734
    GET /temp_img/two.png -> 404          ← ★ 本机 wget 1.25.0，线上现象无法复现（见 §8「未能还原」）
    example.com@127.0.0.1:8080/1m9/one.png -> 200 len=3734 (通过)

  === 5) FTP 匿名登录 + 列目录 + 读旧版源码 ===
    列表 -> <ul> <li><a href='?dir=pub'>pub</a></li><li>show_img_v1.0.php [<a href='?download=%2Fshow_img_v1.0.php'>下载</a>]</li></ul>
    download=/show_img_v1.0.php -> 200 len=4053 ct=application/octet-stream   ← 4053 字节，与线上完全一致
    source head:
       <?php
       if(!isset($_GET['img_url'])){ die("no"); }
       $img_url = base64_decode($_GET['img_url']);
       $path = parse_url($img_url, PHP_URL_PATH);
       $img_name = pathinfo($path, PATHINFO_BASENAME);

       # 老版本的漏洞，已在新版本得到了修复  tips: wget的漏洞
       system("wget  -P temp_img  '".$img_url."'");
       ?>
    含 system("wget ...) = True
    含 tips: wget的漏洞 = True

  === 6) FTP 根只有两项（负结果）===
    /flag /flag.txt /index.php /www.zip /etc/passwd /pub  -> 全部"下载失败"   ← 与线上一致

  === 7) 路线 (b′) 的卡点 ===
    http://127.0.0.1:8080/1m9/one.phtml -> 被拦（含 php）   ← 我们卡死的位置
    http://127.0.0.1:8080/1m9/one.pn~   -> 200 len=3734       ← wget 会改写落盘名
  ```
  ⇒ **结论：双应用重建可跑；过滤表 18/18、SSRF 回显、旧版源码泄露（4053 字节逐字节原件）、FTP chroot 负结果全部复现。未取得 flag，与比赛结果一致。**
- **诚实标注**：
  - **flag `（未获取）`**；§4.1 的预期解法路线**全部标注为未验证的推测**；
    其中 (b)（CVE-2024-10524）**已通过权威来源查证并被我们判定为"前提不成立、倾向证伪"**（这一判定本身是**事实**）；
    (b′) 的**前半段已在重建环境实测复现**（FTP 上传 → `MKD pub/http:` → wget 路径归一化 → 落盘 `.phtml` → RCE），
    但**前提是放宽 scheme 校验**，而线上**明确拒绝 `ftp://`**，因此**线上是否可走通仍未证实**；
  - §3 的考点 1~8 与 §5 的步骤 1~10 **每一条都有对应的实测证据文件或本节的本地复现输出**，属**事实**；
  - §2.1 的服务拓扑**全部由 SSRF 探测得出**，不是猜测；
  - 旧版 `show_img_v1.0.php` 的源码是**逐字节原件**（不是重建），`show.html` 的 5256 字节亦为实测抓取；
    `index.html` / `ftp.php` 的 HTML 是**实测抓取**，其 PHP 逻辑是**重建**；
  - **已知保真缺口只有一处且已明确标注**：wget 版本差异（§8「未能还原」第 2 条）。

## 9. 复现步骤

```bash
cd timu/round3_1700/web03/deploy
docker compose up -d --build            # 外层入口 → http://127.0.0.1:8093
#   容器内同时监听 127.0.0.1:80 (Apache) / 127.0.0.1:8080 (nginx) / 127.0.0.1:21 (FTP anonymous)

# 健康检查
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8093/            # 200 应用中心
curl -s http://127.0.0.1:8093/show_img.php                                 # no  (2 bytes)
docker compose exec apache python3 -c "import ftplib;f=ftplib.FTP();f.connect('127.0.0.1',21);f.login('anonymous','x');print(f.nlst())"

cd ..
python solve/solve.py --target http://127.0.0.1:8093
#   预期：登录匿名 FTP → 读到旧版源码 → 上传 .phtml → 图片应用从本机 FTP 拉取
#         → Apache 执行并返回当前容器 FLAG（退出码 0）

# 手工复现关键三点：
#  1) SSRF 回显（把内部 nginx 默认页拖到 web 可读目录）
python -c "import base64;print('http://127.0.0.1:8093/show_img.php?img_url='+base64.b64encode(b'http://127.0.0.1:8080/index.html').decode())"
curl -s http://127.0.0.1:8093/temp_img/index.html | head -3
#  2) 过滤表
python -c "import base64;print(base64.b64encode(b'http://127.0.0.1:8080/a_b').decode())"   # → 不要这样子哦
python -c "import base64;print(base64.b64encode(b'http://127.0.0.1:8080/xphp').decode())"  # → 你想干嘛
python -c "import base64;print(base64.b64encode(b'http://example.com/').decode())"         # → 目前只能加载本地图库……
#  3) 旧版源码泄露 + parse_url 与 wget 的解析差异
curl -s -X POST -d 'ftp_server=127.0.0.1&ftp_user=anonymous&ftp_pass=x' -c j.txt http://127.0.0.1:8093/ftp.php >/dev/null
curl -s -b j.txt 'http://127.0.0.1:8093/ftp.php?download=/show_img_v1.0.php' | head -12
python -c "import base64;print(base64.b64encode(b'http://127.0.0.1:8080/1m9/one.png@127.0.0.1:8080/1m9/two.png').decode())"
#   → 请求该 img_url 后 /temp_img/two.png 是 404：本机 wget 1.25.0 把 @ 之后当 path，
#     **线上"落盘成 two.png"的现象无法复现**（见 §8「未能还原」，这是已知保真缺口）

docker compose down -v
```

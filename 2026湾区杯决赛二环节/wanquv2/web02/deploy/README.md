# web02（环节二 · 文件管理系统）部署说明

> 2026 湾区杯决赛 · 赛道二 · 环节二 web02 的**重建**。
>
> **两种用途、两档可选**：
> - **默认（`unanchored`）= 可解档** → 这道题现在**能做出来**，`?file=../../../flag` 直读 flag。
> - **`anchored` = 忠实档** → 与线上实测行为逐条一致（纯字符锚定白名单），**应用层不可解**。
>
> 为什么默认改成可解：线上原始实现把三条路全封死了（见下 §3），
> 用户 2026-09-28 的源码级定论与本工程实测**双向一致**。作为题库，
> 一道永远做不出来的容器没有训练价值 ⇒ 默认切到**可解档**，忠实档保留可一键切回。

---

## 1. 起环境

```bash
cd timu/round2_1330/web02/deploy
docker compose up -d --build                       # → http://127.0.0.1:8090
python web02_check.py      http://127.0.0.1:8090   # 环境自检（★ 档位自适应，期望 通过 16 / 失败 0）
python web02_read_probe.py http://127.0.0.1:8090   # ★ 可解性判据（期望 判定：可解 ✅）
cd ..
python solve/solve.py --target http://127.0.0.1:8090   # 期望 exit 0 + FLAG READ
```

> ⚠️ **改源码 / 换档位后必须带 `--build`**。`up -d --force-recreate` 只用**已有镜像**重建容器，
> **不会重新 build 镜像** —— 改了 `src/*.php` 或改了档位 ARG 而只加 `--force-recreate`，
> 你会对着旧代码调试半天（本工程实际踩过这个坑）。

---

## 2. ★ 读取路径档位（决定本题能不能解）

由环境变量 `WEB02_VARIANT` 选择（**优先级高于旧的 `WEAK_REGEX`**）：

| 档位 | `download.php` 的校验 | 可解性 | 说明 |
|------|---------------------|--------|------|
| **`unanchored`** ★**默认** | `!preg_match('/[a-zA-Z0-9.]+/', $f)` | **可解 ✅** | **白名单漏了 `^...$` 锚定**。只要串里含一段"字母数字点"即通过 ⇒ `../../../flag` 里的 `flag` 命中 ⇒ 放行 ⇒ `is_file('/var/www/uploads/../../../flag')` = `/flag` |
| `none` | 无校验，直接拼接 | **可解 ✅** | README §4.1 记的「变体 B」，最直白 |
| `anchored` | `!preg_match('/^[a-zA-Z0-9.]+$/', $f)` | **不可解 ❌** | **忠实复刻**：`/`、`\` 不在字符类 ⇒ 无法穿越；`.`/`..` 能过正则但 `is_file` 判为目录 ⇒ 404 |
| `weak` | `@preg_match('/^[a-zA-Z0-9.]+$/u', $f) === 0` | **不可解 ❌** | 假设 A′ 研究档：无效 UTF-8 让 `preg_match` 返回 `false` ⇒ `false !== 0` ⇒ **校验被跳过**（实测 400→404），但那串无效字节**自身成了必须存在的路径分量**，内核 `ENOENT` ⇒ **可绕校验、不可利用** |

切换：

```powershell
# PowerShell（★ 必须带 --build）
$env:WEB02_VARIANT='anchored';  docker compose up -d --build --force-recreate
python web02_read_probe.py http://127.0.0.1:8090      # 期望 判定：不可解 ❌
$env:WEB02_VARIANT='unanchored'; docker compose up -d --build --force-recreate
```
```bash
# bash
WEB02_VARIANT=anchored docker compose up -d --build --force-recreate
WEB02_VARIANT=unanchored docker compose up -d --build --force-recreate
```

### 实测对照（本工程跑过，可复现）

| 探针 | `unanchored` | `none` | `anchored` | `weak` |
|------|-------------|--------|-----------|--------|
| `?file=../../../flag` | **200 + flag** ★ | **200 + flag** ★ | 400 | 400 |
| `?file=../../../etc/passwd` | **200 + passwd** ★ | **200 + passwd** ★ | 400 | 400 |
| `?file=a/b`（裸 `/`） | 404（放行到 not found） | 404 | 400 | 400 |
| `?file=nope.jpg` | 404 | 404 | 404 | 404 |
| `solve/solve.py` 退出码 | **0（FLAG READ）** | 0 | **2（NOT SOLVED）** | 2 |
| `web02_read_probe.py` 判定 | **可解 ✅** | **可解 ✅** | 不可解 ❌ | 不可解 ❌ |

> `weak` 档的 `../../../flag` 是合法 UTF-8，`preg_match` 返回 `0` ⇒ `=== 0` 成立 ⇒ 400（照拦）。
> 该档要绕校验必须**带无效字节**（如 `%c0%af/../../../flag` → 404，证明绕过成立但读不出）。
> 详见 `../README.md` §4.1。

### 自检脚本的档位自适应（★ 教训）

`web02_check.py` 的期望值**必须随档位变化**。最初它把「白名单拦截」写死成期望值（当时默认档是
`anchored`），默认档改成 `unanchored` 之后，忠实档的期望反过来把**正确行为**判成 5 项失败
（`通过 10 / 失败 5`）—— **红色并不代表容器坏了，而是测试脚本把"档位"漏成了常量。**

修法：脚本先跑**三个正交探针**唯一确定档位，再按档位选期望表，并把可解性一并断言。

| 探针 | `anchored` | `unanchored` | `none` | `weak` |
|------|-----------|--------------|--------|--------|
| `?file=a/b` | 400 | 404 | 404 | 400 |
| `?file=%21%40%23`（`!@#`） | 400 | 400 | 404 | 400 |
| `?file=%ff%fe`（无效 UTF-8） | 400 | 400 | 404 | **404** |

`--variant <v>` 可强制指定（跳过探测）。**四档实测均 `通过 16 / 失败 0`、退出码 0**（2026-09-28 逐一重建核证）。

> 通用教训：**任何"仿真/复刻"类靶机的自检断言，只要被测对象有开关，期望值就必须以开关为参数**，
> 否则换一次档位就会收获一批假红/假绿。假红会诱导你去"修"本来正确的行为，假绿更危险。

---

## 3. 为什么忠实档不可解（线上实现的完整封堵）

| 路径 | 封堵方式 |
|------|---------|
| **读** | `download.php` 纯字符**锚定**白名单 `^[a-zA-Z0-9.]+$` ⇒ `/`、`\`、`_`、`-`、`%`、空格全被 400；`.`/`..` 能过正则但 `is_file()` 判为目录 ⇒ 404 |
| **上传** | `basename()` + 文件名 ASCII 白名单 `^[A-Za-z0-9._-]+$` + 扩展名白名单（jpg/jpeg/png/zip）+ `finfo`/`getimagesize` 内容嗅探 ⇒ 落点锁死 `/var/www/uploads`；该目录 `php_admin_flag engine off`、`Options -ExecCGI`、**且不在 docroot（无 Alias）** ⇒ HTTP 不可达 |
| **`?delete=`** | 完全未过滤（`/var/www/uploads/` + 用户输入，递归 `rrmdir`），但实测排除命令注入（`;id`/`$(...)`/反引号 全无回显、耗时 ~0.01s）⇒ **纯破坏原语，无回读通道** |
| **flag** | `/flag`，权限 `-r-------- www-data` ⇒ 需要 www-data 的**任意读或 RCE**，上面三条都拿不到 |

⇒ **忠实档 = 应用层不可解**，这不是解题失败，是镜像忠实再现了"那套封死的实现"。

---

## 4. 运维坑（实测踩出来的）

| # | 现象 | 根因 | 处置 |
|---|------|------|------|
| 1 | `up` 报 `Conflict. The container name "/web02_fms" is already in use` | `container_name` 原先硬编码 `web02_fms`，而 compose 工程名从默认的 `deploy` 改成 `qwb-r2-web02` ⇒ 旧容器**不再受 compose 管理**，`down` 清不掉 | 已把容器名对齐工程名（`qwb-r2-web02-app`）；若仍遇到：`docker rm -f qwb-r2-web02-app` |
| 2 | `$env:WEB02_VARIANT=...` + `up -d --force-recreate` **没生效** | compose 里写死了字面量，**字面量优先级高于宿主环境变量** | 已改为 `"${WEB02_VARIANT:-unanchored}"` 形式 |
| 3 | 改了源码但行为没变 | `--force-recreate` **不重建镜像** | 一律加 `--build` |
| 4 | 测无效 UTF-8 时**测不出效果** | `requests` 会把 `'\xff'` 按 UTF-8 编成 `%C3%BF`（**合法 UTF-8**） | 必须直接拼百分号编码 `%ff%fe`（见 `web02_regex_probe.py`） |
| 5 | **把 `..` 放进 delete 探测列表 ⇒ 整个应用被清空** | `'/var/www/uploads/' . '..'` = `/var/www` → 递归删除 | **这类原语的探针只允许用"一定不存在的文件名"，`.`/`..` 本身就是破坏性目标**；出事立刻重建（2 分钟可恢复） |

---

## 5. 目录

```
deploy/
├── Dockerfile              # php:7.4-apache；display_errors=On；uploads 禁 PHP 解析；/flag 来自 FLAG 变量
├── docker-compose.yml      # name: qwb-r2-web02；容器 qwb-r2-web02-app；端口 8090；WEB02_VARIANT 默认 unanchored
├── src/                    # index.php / demo.php / admin.php / download.php + 静态资源
├── uploads/                # 上传目录（web 根之外，www-data 可写）
├── web02_check.py          # 环境自检：★档位自适应（先探测档位，再按档位选期望表；共 16 项）
│                           #   探测三探针：a/b ｜ !@# ｜ 无效 UTF-8(%ff%fe) → 唯一确定 4 档
├── web02_read_probe.py     # ★ 可解性判据：遍历读 /flag、/etc/passwd
└── web02_regex_probe.py    # 假设 A′ 专项：无效 UTF-8 绕 preg_match（发原始字节）
```

## 6. flag 与比赛记录的区分（重要）

- `/flag` 内容来自 `FLAG`（compose 的 build arg + 环境变量），默认 `flag{PLACEHOLDER_web02r2_replace_me}`。
- **比赛期真实 flag 未取得**（本题在线上未解出）。`../challenge.json` 的 **`is_solved` 仍为 `false`**、
  flag 字段留空、`../README.md` §7 写「（未获取）」—— **这是比赛事实，不因本工程新增可解档而改变**。
- 本工程新增的是**可解档**（`unanchored`/`none`），属于**为可练习性所做的重建选择**，
  已在本文件与 `../README.md` §8 显式标注「非线上原样」。**两者不要混为一谈。**

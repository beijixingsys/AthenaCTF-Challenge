<?php
/**
 * round2 web03 "i like escape" · /var/www/html/eeeeeend1ng.php
 *
 * ★ 本题的"后门端点"：它 **不 require waf.php**，所以 a() 的黑名单完全不生效。
 *   同时它读的 cookie 名是 `users`（注意是复数），并且同样执行 unserialize。
 *
 * 这就是 admin→root(Date)→system 链的落地点：
 *     O:5:"admin":2:{s:5:"admin";N;s:4:"root";O:4:"Date":1:{s:3:"cmd";s:N:"...";}}
 * 用伪造的 keystream 把上面这段明文加密成密文塞进 cookie `users` 即可 RCE。
 *
 * 出题人在 index.php/login.php 上都挂了 a() 过滤，只在 eeeeeend1ng.php 上留口子——
 * 只盯着 login.php 打 payload 的人会一直吃 "Hacker!"。
 */

require_once __DIR__ . '/function.php';
require_once __DIR__ . '/algorithm.php';

$cipher = new Cipher();
$out = '';

if (isset($_COOKIE['users'])) {
    $raw = (string)$_COOKIE['users'];      // ★ 不做 a() 过滤
    $inner = base64_decode($raw, true);
    if ($inner !== false) {
        $plain = $cipher->decrypt($inner);
        if ($plain !== false) {
            $obj = @unserialize($plain);   // ★ 无 allowed_classes 白名单
            $out = is_object($obj) ? 'ended' : 'guest';
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>i like escape · ending</title></head>
<body>
<h1>the end</h1>
<pre><?= htmlspecialchars($out, ENT_QUOTES, 'UTF-8') ?></pre>
</body>
</html>

<?php
/**
 * round2 web03 "i like escape" · /var/www/html/login.php
 *
 * 反序列化点：读 cookie `user` → base64 解外层 → Cipher::decrypt → unserialize。
 *
 * 攻击者在这里可以：
 *   · 用 FILE gadget 读任意文件（例如 O:4:"FILE":1:{s:8:"filename";s:5:"/flag";}）
 *   · 但真正的 flag 是随机文件名（/flag_<hex>），所以要靠 eeeeeend1ng.php 的 RCE 链
 *
 * 注意：login.php **会** 经过 a()，所以它对 payload 里的关键字更敏感；
 *       出题人把"不过滤"的端点留给了 eeeeeend1ng.php。
 */

require_once __DIR__ . '/waf.php';
require_once __DIR__ . '/function.php';
require_once __DIR__ . '/algorithm.php';

$cipher = new Cipher();
$out = '';

if (isset($_COOKIE['user'])) {
    $raw = a((string)$_COOKIE['user']);

    // 外层 base64 → base64(ct)::hex(iv)
    $inner = base64_decode($raw, true);
    if ($inner === false) {
        $out = 'bad cookie';
    } else {
        $plain = $cipher->decrypt($inner);
        if ($plain === false) {
            $out = 'decrypt failed';
        } else {
            // ★ 无 allowed_classes 白名单 → 任意对象注入
            $obj = @unserialize($plain);
            if (!is_object($obj)) {
                $out = 'guest';
            } else {
                // FILE::__destruct 在脚本结束时才输出，这里靠 ob 抓
                ob_start();
                $out = 'welcome';
                ob_end_flush();
            }
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>i like escape · login</title></head>
<body>
<h1>login</h1>
<pre><?= htmlspecialchars($out, ENT_QUOTES, 'UTF-8') ?></pre>
</body>
</html>

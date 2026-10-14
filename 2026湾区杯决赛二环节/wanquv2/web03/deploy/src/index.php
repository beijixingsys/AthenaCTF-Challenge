<?php
/**
 * round2 web03 "i like escape" · /var/www/html/index.php
 *
 * ★ 本题的"加密预言机"：攻击者提交的 username 会被原样拼进
 *   serialize(new Users($username, $passwd, 'True'))，再由 algorithm.php
 *   加密后通过 Set-Cookie 回吐。
 *
 * 因为明文完全可预测、且密文不掩盖长度，攻击者可以：
 *   ks = pt XOR ct      → 得到 164 字节 keystream → 伪造任意等长明文。
 *
 * Cookie 名是 `user`；PHP setcookie() 会把 '=' 编码成 %3D，
 * 所以攻击者拿到 cookie 后必须 urldecode + 重新补 base64 padding。
 */

require_once __DIR__ . '/waf.php';
require_once __DIR__ . '/function.php';
require_once __DIR__ . '/algorithm.php';

$cipher = new Cipher();
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = isset($_POST['username']) ? a((string)$_POST['username']) : '';
    $passwd   = isset($_POST['passwd'])   ? a((string)$_POST['passwd'])   : '';

    // ---- 加密预言机：明文 = serialize(Users(username, passwd, 'True')) ----
    $plain  = b(new Users($username, $passwd, 'True'));
    $payload = $cipher->encrypt($plain);

    // 外层再套一层 base64（与解密端一致）
    $cookie_value = base64_encode($payload);
    setcookie('user', $cookie_value, time() + 3600, '/');

    $message = 'login ok, cookie issued';
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>i like escape</title>
</head>
<body>
    <h1>i like escape</h1>
    <p>源码在 <a href="/www.zip">/www.zip</a></p>
    <?php if ($message !== ''): ?>
        <p><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></p>
    <?php endif; ?>
    <form method="post">
        <input name="username" placeholder="username" autocomplete="off">
        <input name="passwd" placeholder="passwd" autocomplete="off">
        <button type="submit">login</button>
    </form>
</body>
</html>

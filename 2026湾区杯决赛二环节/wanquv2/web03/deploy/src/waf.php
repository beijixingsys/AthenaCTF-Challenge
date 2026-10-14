<?php
/**
 * round2 web03 "i like escape" · /var/www/html/waf.php
 *
 * ★ 本文件是本题最大的**干扰项 / 陷阱**：
 *   过滤函数 a() 只被 index.php / login.php 调用；
 *   eeeeeend1ng.php **完全不 require 它**，因此反序列化 RCE 链只在这一个端点上成立。
 *
 * 另外 a() 的过滤方式是"子串黑名单替换"，对已序列化的 payload 基本无效，
 * 但如果只在 login.php 上打 payload，就会一直看到 "Hacker!" 而误判"打不进去"。
 */

function a($str)
{
    if (!is_string($str)) {
        return $str;
    }

    $blacklist = [
        'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
        'eval', 'assert', 'file_get_contents', 'file_put_contents', 'unlink',
        'include', 'require', 'FILE', 'Date', 'admin', 'phpinfo',
        '..', '/flag', 'base64_decode', 'call_user_func',
    ];

    foreach ($blacklist as $word) {
        if (stripos($str, $word) !== false) {
            die('Hacker!');
        }
    }

    return $str;
}

/**
 * b() = 序列化的薄封装（index.php 用它生成 cookie 明文）
 */
function b($obj)
{
    return serialize($obj);
}

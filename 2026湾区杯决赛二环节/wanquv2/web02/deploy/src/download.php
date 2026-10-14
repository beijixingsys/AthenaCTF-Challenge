<?php
// download.php —— 从固定前缀 /var/www/uploads/ 读取文件
// 复现自 2026 湾区杯决赛 环节二 web02（原始实现）
//
// 原题实测：file 参数走「纯字符白名单」，'/'、'\'、'_'、'-'、'%'、空格 全部拒绝；
// 被拒时返回 HTTP 400，body 恰为 "invalid file name"。

$file = isset($_GET['file']) ? $_GET['file'] : '';

/* ============================================================================
 * 出题人预期解法推测：若原始实现是这个较弱的写法（只挡 '..' 而不做纯字符白名单），
 * 则 ?file=../../../flag 即为预期解。默认不启用，因为我们实测原始是纯字符白名单。
 * ----------------------------------------------------------------------------
 * // ---- 变体 A：只 str_replace('..') + 去 NUL，'/' 完全放行 ----
 * // $file = str_replace(array('..', "\0"), '', $file);
 * // if ($file === '' || $file === false) {
 * //     http_response_code(400);
 * //     echo 'invalid file name';
 * //     exit;
 * // }
 * // $path = '/var/www/uploads/' . $file;
 * // if (!is_file($path)) {
 * //     http_response_code(404);
 * //     echo 'file not found';
 * //     exit;
 * // }
 * // header('Content-Type: application/octet-stream');
 * // header('Content-Disposition: attachment; filename="' . basename($path) . '"');
 * // header('Content-Length: ' . filesize($path));
 * // readfile($path);
 * // exit;
 *
 * // ---- 变体 B：真正可穿越（完全不校验，直接拼接）----
 * // 【补充说明】变体 A 其实穿不出去：str_replace('..','') 会把 "../../../flag"
 * // 变成 "///flag"，拼成 "/var/www/uploads////flag"，只是 404。经典绕过
 * // "....//" 对 str_replace('..') 同样无效（会塌成 "//"）。
 * // 所以真正能让 ?file=../../../flag 命中的，是下面这种「零校验」写法。
 * // 启用方式：去掉下列各行行首的 '// '，并注释掉下面的严格白名单分支。
 * // $path = '/var/www/uploads/' . $file;
 * // if (!is_file($path)) {
 * //     http_response_code(404);
 * //     echo 'file not found';
 * //     exit;
 * // }
 * // header('Content-Type: application/octet-stream');
 * // header('Content-Disposition: attachment; filename="' . basename($path) . '"');
 * // header('Content-Length: ' . filesize($path));
 * // readfile($path);
 * // exit;
 * ============================================================================ */

// ============================================================================
// ★★ 读取路径档位开关（这是本题"能不能解"的总闸）★★
//
// 背景（2026-09-28 用户源码级定论 + 本地实测，两边结论一致）：
//   线上原始镜像的 download.php 是 **纯字符白名单 + 锚定** 写法：
//       if (!preg_match('/^[a-zA-Z0-9.]+$/', $file)) { 400 }
//   `/` 与 `\` 不在字符类里 ⇒ 无法穿越；`.`/`..` 能过正则但 is_file 判为目录 ⇒ 404。
//   上传链路（basename + ASCII 名白名单 + 扩展名白名单 + finfo/getimagesize 嗅探
//   + 落点 /var/www/uploads 且 php_admin_flag engine off 且不在 docroot）也全封死；
//   ?delete= 完全未过滤，但实测排除命令注入（;id / $() / 反引号 全无回显、耗时 ~0.01s），
//   是**纯破坏原语**。
//   ⇒ **忠实档下应用层不可解**（flag 在 /flag，-r-------- www-data，需要任意读或 RCE）。
//     这不是解题失败，是镜像再现了"线上那套封死的实现"。
//
// 因此本文件提供 **四档**，用环境变量 WEB02_VARIANT 选择（优先级高于旧的 WEAK_REGEX）：
//
//   anchored    （= 旧 WEAK_REGEX=0）忠实复刻：/^[a-zA-Z0-9.]+$/ + !preg_match
//                                     → 与线上实测一致，【应用层不可解】
//   unanchored  ★默认★ 经典缺陷：白名单**漏了 ^...$ 锚定** → /[a-zA-Z0-9.]+/
//                                     → 只要串里含一段"字母数字点"即通过。
//                                       `../../../flag` 里的 `flag` 命中 → 放行
//                                     → is_file('/var/www/uploads/../../../flag')
//                                       = is_file('/flag') = true → **读出 flag** ✅ 可解
//   none        README §4.1 记的"变体 B"：零校验，直接拼接
//                                     → 同样可解（最直白）
//   weak        （= 旧 WEAK_REGEX=1）假设 A′ 的研究档：/u + `preg_match() === 0`
//                                     → 能绕过白名单，但无效字节自身成了必须存在的路径
//                                       分量（内核 ENOENT）⇒ **可绕校验、不可利用**
//
// 解析顺序：WEB02_VARIANT > WEAK_REGEX > 默认(unanchored)
// 切法：$env:WEB02_VARIANT='anchored'; docker compose up -d --build --force-recreate
// ============================================================================
$__variant = strtolower(trim((string) getenv('WEB02_VARIANT')));
if ($__variant === '') {
    // 兼容旧开关；平台适配镜像优先通过 WEB02_VARIANT 选择档位
    $__wr = getenv('WEAK_REGEX');
    if ($__wr === '0') {
        $__variant = 'anchored';
    } elseif ($__wr === '1') {
        $__variant = 'weak';
    } else {
        $__variant = 'unanchored';   // ★ 默认：可解档
    }
}

if (!is_string($file)) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'invalid file name';
    exit;
}

$__rejected = false;
switch ($__variant) {
    case 'anchored':      // 忠实复刻（不可解）
        $__rejected = !preg_match('/^[a-zA-Z0-9.]+$/', $file);
        break;

    case 'weak':          // 假设 A′ 研究档（可绕校验、不可利用）
        $__rejected = (@preg_match('/^[a-zA-Z0-9.]+$/u', $file) === 0);
        break;

    case 'none':          // 变体 B：零校验（可解）
        $__rejected = false;
        break;

    case 'unanchored':    // ★默认：漏锚定（可解）
    default:
        $__rejected = !preg_match('/[a-zA-Z0-9.]+/', $file);
        break;
}

if ($__rejected) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'invalid file name';
    exit;
}

$path = '/var/www/uploads/' . $file;

if (!is_file($path)) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'file not found';
    exit;
}

header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($path) . '"');
header('Content-Length: ' . filesize($path));
readfile($path);
exit;

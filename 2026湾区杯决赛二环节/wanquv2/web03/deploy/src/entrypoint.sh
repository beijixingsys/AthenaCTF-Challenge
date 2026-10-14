#!/bin/sh
# round2 web03 "i like escape" · 容器启动脚本
#
# 做什么：
#   1) 把 flag 注入到 **随机文件名**（还原原题：/flag 不存在，真正的 flag
#      藏在 /flag_<hex>，所以 FILE gadget 读 /flag 会失败，必须靠 RCE 列目录）
#   2) 按题面提示把源码打包成 /www.zip 放到 Web 根（这就是"源码泄露"入口）
#   3) 前台启动 apache
set -e

DOCROOT=/var/www/html

# ---------- 1) flag 注入（随机文件名，模拟原题 /flag_182e805265d83db03d9c）----------
FLAG_VALUE="$(cat /flag 2>/dev/null || true)"
if [ -z "$FLAG_VALUE" ]; then
    FLAG_VALUE="flag{local-r2-web03-i-like-escape}"
fi

if [ -n "$FLAG_RANDOM_SUFFIX" ]; then
    SUFFIX="$FLAG_RANDOM_SUFFIX"
else
    SUFFIX="$(head -c 9 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi
printf '%s' "$FLAG_VALUE" > "${DOCROOT}/flag_${SUFFIX}"
chmod 444 "${DOCROOT}/flag_${SUFFIX}"
rm -f /flag

echo "[entrypoint] flag -> ${DOCROOT}/flag_${SUFFIX}"

# ---------- 2) 生成 /www.zip（源码泄露点）----------
if [ ! -f "${DOCROOT}/www.zip" ]; then
    ( cd "$DOCROOT" && zip -q -r www.zip index.php login.php function.php waf.php algorithm.php eeeeeend1ng.php )
    chmod 444 "${DOCROOT}/www.zip"
fi
echo "[entrypoint] source bundle -> ${DOCROOT}/www.zip"

# ---------- 3) 启动 apache ----------
exec apache2-foreground

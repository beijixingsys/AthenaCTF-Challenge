# round2 web03 「i like escape」· 容器镜像
#
# 原题：PHP + Apache，源码以 /www.zip 形式故意留在 Web 根（题面直接点名）。
# 这里用 php:7.4-apache（原题年代的口径），本地复现等价。
FROM php:7.4-apache

# zip 用于 entrypoint 生成 /www.zip（还原"源码泄露"入口）
RUN apt-get update \
 && apt-get install -y --no-install-recommends zip \
 && rm -rf /var/lib/apt/lists/*

# 题目源码（还原自 WP + 参考利用脚本所描述的 algorithm.php / function.php / waf.php 行为）
COPY src/index.php         /var/www/html/index.php
COPY src/login.php         /var/www/html/login.php
COPY src/function.php      /var/www/html/function.php
COPY src/waf.php           /var/www/html/waf.php
COPY src/algorithm.php     /var/www/html/algorithm.php
COPY src/eeeeeend1ng.php   /var/www/html/eeeeeend1ng.php

# flag 注入方式：flag 文件 COPY 到 /flag，entrypoint 再把它搬到
# 随机文件名 /var/www/html/flag_<hex>（还原原题 /flag_182e805265d83db03d9c 的形态）
COPY flag /flag
COPY src/entrypoint.sh /usr/local/bin/ctf-entrypoint.sh
RUN chmod +x /usr/local/bin/ctf-entrypoint.sh

# 关闭 PHP 错误显示（原题风格）、打开短标签之外的常规设置
RUN { \
      echo 'display_errors = Off'; \
      echo 'log_errors = On'; \
      echo 'error_log = /dev/stderr'; \
    } > /usr/local/etc/php/conf.d/zz-ctf.ini

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/ctf-entrypoint.sh"]

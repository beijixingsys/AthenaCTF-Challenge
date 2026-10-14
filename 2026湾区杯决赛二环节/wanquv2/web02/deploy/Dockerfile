# web02 —— PHP 文件管理系统（2026 湾区杯决赛 环节二 复现）
# 漏洞点：信息泄露(HTML 注释弱口令) / demo.php 提示 / admin.php Basic 弱口令 +
#         未过滤的 ?delete= 递归删除路径穿越 / download.php 纯字符白名单封死读取路径
FROM php:7.4-apache

ARG FLAG=flag{PLACEHOLDER_web02r2_replace_me}
# ★★ 读取路径档位（决定本题能不能解；四档说明见 src/download.php 顶部注释）★★
#   anchored    忠实复刻（与线上实测一致）—— 应用层不可解
#   unanchored  ★默认★ 白名单漏锚定 → ?file=../../../flag 可读 flag  ✅ 可解
#   none        零校验（README 变体 B）                          ✅ 可解
#   weak        假设 A′ 研究档（可绕校验、不可利用）
ARG WEB02_VARIANT=unanchored
ENV WEB02_VARIANT=${WEB02_VARIANT}
# 兼容旧开关；平台适配镜像通过 WEB02_VARIANT 显式选择可解档
ARG WEAK_REGEX=0
ENV WEAK_REGEX=${WEAK_REGEX}

ENV DEBIAN_FRONTEND=noninteractive

# libmagic / fileinfo：官方 php:7.4-apache 镜像已经启用了 fileinfo（`php -m` 可见），
# 且自带 /usr/bin/file，因此正常情况下不需要 apt-get 也不需要 docker-php-ext-install。
# 这里保留一个「按需」兜底分支：只有当基础镜像确实没有 finfo 时才装（避免 Debian
# bullseye 镜像源 404 把构建拖垮）。
RUN set -eux; \
    if ! php -r 'exit(class_exists("finfo") ? 0 : 1);'; then \
        apt-get update \
        && apt-get install -y --no-install-recommends libmagic1 libmagic-dev \
        && rm -rf /var/lib/apt/lists/* \
        && docker-php-ext-install fileinfo; \
    fi; \
    php -r 'exit(class_exists("finfo") ? 0 : 1);'

RUN a2enmod rewrite

# 原题会在报错里泄漏 PHP 绝对路径 -> display_errors=On
RUN printf '%s\n' \
      'display_errors=On' \
      'display_startup_errors=On' \
      'error_reporting=E_ALL' \
      'log_errors=On' \
      'allow_url_fopen=On' \
      'allow_url_include=Off' \
      'expose_php=On' \
      'upload_max_filesize=20M' \
      'post_max_size=24M' \
    > /usr/local/etc/php/conf.d/zz-web02.ini

# 上传目录：在 web 根之外，www-data 可写
RUN mkdir -p /var/www/uploads \
 && chown -R www-data:www-data /var/www/uploads \
 && chmod 0775 /var/www/uploads

# 上传目录禁止 PHP 解析（原题行为）
RUN printf '%s\n' \
      '<Directory /var/www/uploads>' \
      '    php_admin_flag engine off' \
      '    php_admin_value engine off' \
      '    Options -ExecCGI -Indexes' \
      '    AllowOverride None' \
      '    Require all granted' \
      '</Directory>' \
    > /etc/apache2/conf-available/uploads-noexec.conf \
 && a2enconf uploads-noexec

# flag 位于文件系统根，www-data 可读；内容来自 compose 传入的 FLAG
RUN printf '%s' "$FLAG" > /flag \
 && chmod 0644 /flag \
 && chown root:root /flag

COPY src/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html

WORKDIR /var/www/html
EXPOSE 80

# 健康检查：必须能拿到登录页且含弱口令注释（用 php CLI，避免依赖 curl 包）
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
  CMD php -r '$b=@file_get_contents("http://127.0.0.1/index.php"); exit(strpos((string)$b,"user/123")===false?1:0);'

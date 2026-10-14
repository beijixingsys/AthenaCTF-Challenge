# web03 —— 外层 Apache/PHP 容器（同时提供 nginx 与 pyftpdlib 运行环境）
#
# 三个服务（apache:80 / nginx:8080 / ftp:21）共用一个 network namespace：
# nginx 与 ftp 两个容器在 docker-compose.yml 里用 network_mode: "service:apache"
# 加入本容器的 netns，因此在本容器内部 127.0.0.1:80、127.0.0.1:8080、127.0.0.1:21
# 都是活的 —— 这正是原题 show_img.php 的 SSRF 能打到 nginx 与 FTP 的前提。
FROM php:8.2-apache

ENV DEBIAN_FRONTEND=noninteractive

# wget：Debian bookworm 自带 1.21.3（保留原题所依赖的 wget URL 解析行为）
# nginx：内部 127.0.0.1:8080 的“本地图库”
# python3-pyftpdlib：内部 127.0.0.1:21 的匿名 FTP
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      wget ca-certificates curl nginx python3-pyftpdlib \
 && rm -rf /var/lib/apt/lists/* \
 && docker-php-ext-install ftp

# PHP：打开报错回显 —— 原题会泄露物理路径（... in /var/www/html/ftp.php on line N）
RUN printf '%s\n' \
      'display_errors = On' \
      'display_startup_errors = On' \
      'error_reporting = E_ALL' \
      'html_errors = On' \
      'log_errors = Off' \
      'default_charset = "UTF-8"' \
      > /usr/local/etc/php/conf.d/zz-web03.ini

# Apache：phtml/php5/php7/phar/pht 一律交给 mod_php 执行（temp_img 也不例外）；
# /temp_img/ 目录本身 403（禁止 autoindex）——必须在该 <Directory> 里显式
# `DirectoryIndex disabled`，否则外层那条 `DirectoryIndex index.html` 会生效，
# 一旦 temp_img/ 里存在 index.html（SSRF 下载内部 nginx 默认页的产物），
# `GET /temp_img/` 就会返回 200 的页面而不是实测到的 403。
RUN { \
      echo '<FilesMatch "\.(php|phtml|php5|php7|phar|pht)$">'; \
      echo '    SetHandler application/x-httpd-php'; \
      echo '</FilesMatch>'; \
      echo 'AddType application/x-httpd-php .phtml .php5 .php7 .phar .pht'; \
      echo 'DirectoryIndex index.php index.html'; \
      echo '<Directory /var/www/html>'; \
      echo '    Options -Indexes +FollowSymLinks'; \
      echo '    AllowOverride None'; \
      echo '    Require all granted'; \
      echo '</Directory>'; \
      echo '# /temp_img 是 SSRF 的落盘目录：原题 GET /temp_img/ 返回 403（无 autoindex）；'; \
      echo '# 这里必须同时禁用 DirectoryIndex，否则该目录下出现 index.html 时会退化成 200。'; \
      echo '<Directory /var/www/html/temp_img>'; \
      echo '    Options -Indexes +FollowSymLinks'; \
      echo '    AllowOverride None'; \
      echo '    Require all granted'; \
      echo '    DirectoryIndex disabled'; \
      echo '</Directory>'; \
    } > /etc/apache2/conf-available/web03.conf \
 && a2enconf web03

# 站点文件；旧版 show_img_v1.0.php 只存在于 FTP 根目录，绝不出现在 docroot
COPY src/ /var/www/html/
RUN rm -f /var/www/html/show_img_v1.0.php \
 && mkdir -p /var/www/html/temp_img \
 && chown -R www-data:www-data /var/www/html

# FTP 根：/srv/ftp，根目录 root:root 0755（匿名不可写），pub/ 归 ftpuser 可写
COPY ftproot/ /srv/ftp/
RUN rm -f /srv/ftp/pub/.gitkeep \
 && useradd -u 1000 -M -s /usr/sbin/nologin ftpuser \
 && chown -R root:root /srv/ftp \
 && chmod 755 /srv/ftp \
 && chown -R ftpuser:ftpuser /srv/ftp/pub \
 && chmod 775 /srv/ftp/pub \
 && chmod 644 /srv/ftp/show_img_v1.0.php

# flag：容器根目录，www-data 可读（不在 docroot、不在 FTP 根）
COPY flag /flag
RUN chmod 644 /flag

# 启动脚本：每次 up 都把 temp_img/ 与 ftp pub/ 重置为空（对齐原题初始态）
COPY entrypoint.sh /usr/local/bin/web03-entrypoint.sh
RUN chmod +x /usr/local/bin/web03-entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/web03-entrypoint.sh"]
CMD ["apache2-foreground"]

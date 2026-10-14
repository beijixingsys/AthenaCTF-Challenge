# round2 web01 · vim swap 残留文件泄露源码 —— 本地可复现部署
#
# 复现的关键点：
#   1) 源码里有一个隐藏后门分支：POST flag=ok → echo file_get_contents('/flag')
#   2) 同目录留下 vim 交换文件 .vi.php.swp / .index.php.swp（按 1024B 块存放原始字节）
#   3) Apache **未**禁止访问点号开头的文件 → 可下载 swap → 裸扫还原源码
#      ★ 官方 php:apache 镜像默认带 `<FilesMatch "^\."> Require all denied`，
#        正好会把 dotfile 挡掉（那正是本题的修复建议）。这里显式放行，
#        才能还原"Web 目录未禁止访问点号文件"这个脆弱点。
#
# ⚠️ swap 文件是二进制，**构建期不可用 python 生成**（php:7.4-apache 不带 python3，
#    且 debian bullseye 的 apt 源在本机网络下经常超时）。
#    ⇒ 改成**宿主机预生成**：先跑 tools/mk_swp.py，再 build。
#      命令见 README §9；compose 的 Makefile 化步骤就是那两条 python 命令。
FROM php:7.4-apache

# docroot：源码 + 两个预生成的 vim 交换文件
COPY docroot/ /var/www/html/

# 容器内调一下 Apache：隐藏 ServerName 告警 + 显式放行 docroot（允许 dotfile）
RUN echo 'ServerName localhost' >> /etc/apache2/apache2.conf \
 && printf '<Directory /var/www/html>\n    AllowOverride None\n    Require all granted\n</Directory>\n' \
      > /etc/apache2/conf-available/zz-docroot.conf \
 && a2enconf zz-docroot

# flag 注入：/flag（与比赛容器一致，后门分支硬编码读它）
COPY flag /flag
RUN chmod 444 /flag

EXPOSE 80

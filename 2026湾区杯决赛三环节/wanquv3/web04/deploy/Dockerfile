# round3 web04 · Northline Route Desk —— 本地可复现部署
#
# 源码来源：比赛期间通过 `GET /?audit=1` + `X-Forwarded-For: 127.0.0.1`
#          从靶机 highlight_file(__FILE__) 泄露的 **完整原始 PHP 源码**
#          （见 ../../deploy/src/index.php，逐字节来自 work/r3_web04/audit_src.php）。
#
# 起容器：
#   docker compose -f deploy/docker-compose.yml up -d --build
#   → http://127.0.0.1:9999/
#
# 打靶：
#   python solve/solve.py --target http://127.0.0.1:9999
#
# ⚠️ 不要在生产/比赛环境反复请求 `/?audit=1`：它会 highlight 93KB 源码，
#    比赛期间实测把容器打崩（一次性资源）。本地复现无所谓，但也请只打一次。
FROM php:7.4-apache

# 题目源码（原始泄露源码，未做任何逻辑改动）
COPY src/index.php /var/www/html/index.php

# flag 注入：/flag（与比赛容器一致；利用链用 grep -r '[f]lag' / 定位它）
COPY flag /flag
RUN chmod 444 /flag

# 题目需要 shell_exec / escapeshellarg（默认未 disabled），并补上 grep / find。
# ⚠️ 两个实测坑：
#   ① php:7.4-apache 是 debian-slim，**默认没有 grep**（只有 busybox 风格的空缺）。
#   ② Debian 11 是 usrmerge：grep 落在 **/bin/grep**，而 /usr/bin/grep 不存在。
#      而原题容器里 launcher 写的正是 `/usr/bin/grep` —— 这里补一个符号链接对齐，
#      使 README 里记录的原始 payload 可以原样跑通。
# （apt 走公网，慢网络下用 DOCKER_BUILDKIT=1 + 较长超时构建；失败就重试一次）
RUN apt-get update -o Acquire::Retries=5 \
 && apt-get install -y --no-install-recommends grep findutils \
 && rm -rf /var/lib/apt/lists/* \
 && [ -e /usr/bin/grep ] || ln -s /bin/grep /usr/bin/grep \
 && ls -l /usr/bin/grep /usr/bin/find /usr/bin/timeout

RUN { \
      echo 'display_errors = Off'; \
      echo 'log_errors = On'; \
      echo 'error_log = /dev/stderr'; \
    } > /usr/local/etc/php/conf.d/zz-ctf.ini

EXPOSE 80

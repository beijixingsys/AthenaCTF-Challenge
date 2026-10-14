FROM ubuntu:20.04

# glibc 2.31（Ubuntu 20.04 自带即 2.31，与题目附件 libc.so.6 同版本、同符号偏移）
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.aliyun.com@g; s@//security.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list \
 && apt-get update && apt-get install -y --no-install-recommends socat ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/pwn         /app/pwn
COPY src/libc.so.6   /app/libc.so.6
RUN chmod 0755 /app/pwn

# 题目 flag：**运行期**由平台通过环境变量 FLAG 注入（见 entrypoint.sh 的说明）。
# 这里只放一个构建期占位值，供本地 docker compose 演练；平台启动实例时会覆盖它。
RUN printf 'flag{placeholder_round3_pwn01_not_obtained}\n' > /flag && chmod 0444 /flag

COPY entrypoint.sh   /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 9999
# 容器极简：只有 dash 内建可用（无 cat / ls / id），取 flag 靠 `read a < /flag; echo $a`
ENTRYPOINT ["/entrypoint.sh"]

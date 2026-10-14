FROM ubuntu:20.04

# glibc 2.31（与 pwn01 同一基础镜像；pwn02 只用 gets 溢出 + 二进制内已有 system 调用，不依赖 libc 偏移）
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.aliyun.com@g; s@//security.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list \
 && apt-get update && apt-get install -y --no-install-recommends socat ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/pwn /app/pwn
RUN chmod 0755 /app/pwn

# 题目 flag（比赛期间由平台运行时注入；此处放还原用的占位 flag）
RUN printf 'flag{403cc1ed-aba3-4b2d-af5e-b9580bfde22c}\n' > /flag && chmod 0444 /flag

EXPOSE 9999
# 容器极简：只有 dash 内建可用（无 cat / ls / id），取 flag 靠 `read a < /flag; echo $a`
ENTRYPOINT ["socat", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:/app/pwn"]

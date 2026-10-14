FROM ubuntu:22.04

# ★ 重要：真题二进制 `attachment`(16544 B) 的 .gnu.version_r 只要求 GLIBC_2.2.5 与 **GLIBC_2.34**
#   ⇒ 实际运行需要 glibc >= 2.34。官方 ZIP 里附带的 libc-2.31.so 属于**另一个实例**
#   （09-10 接入测试轮的 pwn01，见 README §8 附件溯源），不是本二进制的运行时：
#   实测在 ubuntu:20.04 / glibc 2.31 上直接报 `version 'GLIBC_2.34' not found`。
#   本部署件因此选 **ubuntu:22.04（glibc 2.35）**。
#   注意：本题利用链是「3 字节 shellcode + 纯 syscall」，**不依赖任何 libc 偏移**，
#   所以无需与题目原镜像的 libc 逐字节一致。
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.aliyun.com@g; s@//security.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list \
 && apt-get update && apt-get install -y --no-install-recommends socat ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/attachment /app/attachment
RUN chmod 0755 /app/attachment

# 题目 flag（比赛期间由平台运行时注入；此处放还原用的占位 flag）
RUN printf 'flag{0f7af5a5-8674-42f2-b25f-620cb36c0efc}\n' > /flag && chmod 0444 /flag

EXPOSE 9999
# 容器极简：只有 dash 内建可用（无 cat / ls / id），取 flag 靠 `read a < /flag; echo $a`
ENTRYPOINT ["socat", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:/app/attachment"]

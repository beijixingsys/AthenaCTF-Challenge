# round3_1700 / re01 —— 静态逆向题的可选远程包装
#
# ⚠️ 重要说明（诚实标注）
# ---------------------------------------------------------------------------
# 原题 **不是容器题**：平台只下发 zip 附件（`file_url`），`connection` 为空数组。
# `main` 是动态链接的 Rust ELF64（NEEDED: libgcc_s.so.1, libc.so.6），不监听任何端口。
# 本 Dockerfile 提供的是**可选的**"远程判题"包装：把 main 挂到 socat 后面，
# 使本题库可用统一的 `nc host port` 形式演练。
#
# 本题**真的可以"喂输入看输出"**（相等打印 "yes"，否则 "no"），因此该包装有实际判题意义。
# 实测（本机 Docker，2026-09-26）：
#   printf 'flag{9bc396fd-75fb-484c-b193-f3ae596e6317}\n' | ./main  -> yes
#   全 0 UUID / 50 字节全 A / 末位改 1 字符                          -> no
#
# ★ 基础镜像选型（有讲究，别再踩）★
# ---------------------------------------------------------------------------
# 该二进制在**较新发行版**上编译，要求 **glibc >= 2.34**
# （在 glibc 2.31 上实测报 `GLIBC_2.33 / 2.32 / 2.34 not found`）。
#   ❌ ubuntu:20.04         -> glibc 2.31  **跑不了**（实测失败，故本文件不使用）
#   ✅ python:3.11-slim     -> glibc 2.41  **实测可用**（就是本次实机验证用的镜像）
#   ✅ debian:bookworm-slim -> glibc 2.36  满足 >=2.34（版本达标，未在本机实测）
# 这里选 python:3.11-slim：**本机已存在且已实测跑通**，`docker build` 无需联网拉新镜像。
# 通用判据：拿到未知 ELF 先 `docker run --rm <img> ldd --version | head -1` 看 glibc 版本再选镜像。
#
# ⚠️ 另注：本机 WSL 只有 `docker-desktop` 发行版（musl），**不能**跑该 ELF
#    （实测 `Error loading shared library libgcc_s.so.1`）—— 必须走 Docker 的 glibc 镜像。
#
# 构建
#   docker build -t timu/r3-re01:local deploy/
# 运行（把附件目录只读挂载，不把二进制烘进镜像，保证字节可核验）
#   docker run -d --rm -p 9999:9999 -v "$PWD/attachments:/opt/re01:ro" timu/r3-re01:local
# 连接
#   printf 'flag{9bc396fd-75fb-484c-b193-f3ae596e6317}\n' | nc 127.0.0.1 9999   # -> yes
#   printf 'flag{9bc396fd-75fb-484c-b193-f3ae596e6318}\n' | nc 127.0.0.1 9999   # -> no
# ---------------------------------------------------------------------------

FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends socat file binutils \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/re01

# 镜像内放一份 md5 供比对（真实二进制由 -v 挂载提供，保持字节原样、不烘进层）
# ⚠️ 必须放在**挂载点之外**：运行时会 `-v ...:/opt/re01:ro`，若把校验文件放在 /opt/re01
#    会被 bind mount 整个遮蔽，导致 entrypoint 报 `awk: cannot open ... EXPECTED_MD5`（已实测踩过）。
RUN mkdir -p /opt/expected && printf '%s  main\n' 06870cb9f9ab7ecab4721601ad6649c5 > /opt/expected/main.md5

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 9999
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

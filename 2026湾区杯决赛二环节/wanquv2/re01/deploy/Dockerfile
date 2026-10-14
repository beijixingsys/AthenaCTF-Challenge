# round2_1330 / re01 —— 静态逆向题的可选远程包装
#
# ⚠️ 重要说明（诚实标注）
# ---------------------------------------------------------------------------
# 原题 **不是容器题**：gdb_me 不读 stdin、不打印任何判定结果、也不监听任何端口。
# 平台只下发了 zip 附件（`file_url`），`connection` 为空数组。
# 因此本 Dockerfile **不是原题环境的重建**，而是为了让本题库可以统一用
# `nc host port` 形式做"远程判题容器"演练而提供的一个**可选包装**：
# 它把 gdb_me 挂到 socat 后面，让每次连接都会执行一次该 ELF。
#
# 用它做判题时的正确用法（与 re02 / r3_re01 不同）：
#   - 你不能指望"输入 flag 看回显"（程序不读 stdin）；
#   - 正确玩法是：把 gdb_me 副本拉下来**离线静态分析**，用 solve/solve.py 出 flag；
#   - 容器只在"需要确认二进制确实是同一份"时有意义（比对 md5）。
#
# 构建（需要能联网拉基础镜像）
#   docker build -t timu/re01:local deploy/
# 运行（把附件目录挂进去只读，不把二进制烘进镜像，保证字节可核验）
#   docker run -d --rm -p 9999:9999 -v "$PWD/attachments:/opt/re01:ro" timu/re01:local
# 连接
#   nc 127.0.0.1 9999
# ---------------------------------------------------------------------------

# 基础镜像：python:3.11-slim = Debian 13 / glibc 2.41，**本机已存在且已实测跑通**
# （比 debian:bookworm-slim 更保险：后者需联网拉取，本机 docker 凭据助手报
#   `error getting credentials` 拉不下来；python:3.11-slim 是它的超集，跑 ELF 毫无问题）
FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends socat file binutils \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/re01

# 镜像内放一份 md5 供比对（真实二进制由 -v 挂载提供，保持字节原样、不烘进层）
# ⚠️ 必须放在**挂载点之外**：运行时会 `-v ...:/opt/re01:ro`，若把校验文件放在 /opt/re01
#    会被 bind mount 整个遮蔽，导致 entrypoint 报 `awk: cannot open ... .md5`（已实测踩过）。
RUN mkdir -p /opt/expected && printf '%s  gdb_me\n' 0a2e80acee912696ea763c455546f292 > /opt/expected/gdb_me.md5

# 服务启动时先自检二进制存在与哈希，再起 socat（socat 与题目要求的标准起法一致）
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 9999
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

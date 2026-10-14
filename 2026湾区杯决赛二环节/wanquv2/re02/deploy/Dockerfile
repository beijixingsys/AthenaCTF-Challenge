# round2_1330 / re02 —— 静态逆向题的可选远程包装（Wine 执行 PE64）
#
# ⚠️ 重要说明（诚实标注）
# ---------------------------------------------------------------------------
# 原题 **不是容器题**：平台只下发 zip 附件（`file_url`），`connection` 为空数组。
# re01.exe 是 Windows PE64，不监听端口、不读网络。
# 本 Dockerfile 提供的是**可选的**"远程判题"包装：用 Wine 在 Linux 里跑这个 PE，
# 再挂到 socat 后面 —— 这样本题库可以用统一的 `nc host port` 形式演练。
#
# 与 re01 不同的是：**本题真的可以"喂输入看输出"**（程序会打印「成功！/输入错误！」），
# 所以这个包装是有实际判题意义的。
#
# 构建（需要能联网拉基础镜像）
#   docker build -t timu/re02:local deploy/
# 运行（附件目录只读挂载，不把 PE 烘进镜像，保证字节可核验）
#   docker run -d --rm -p 9999:9999 -v "$PWD/attachments:/opt/re02:ro" timu/re02:local
# 连接
#   printf 'flag{0fa830e7-b699-4513-8e01-51f35b0f3293}\n' | nc 127.0.0.1 9999
#   -> 请输入 flag: 成功！
# ---------------------------------------------------------------------------

# 基础镜像：python:3.11-slim（= Debian 13，**本机已存在**，wine 可从 apt 装）
# 不用 debian:bookworm-slim：本机 docker 凭据助手报 `error getting credentials`，拉不下来。
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV WINEDEBUG=-all

# ⚠️ 不要 `dpkg --add-architecture i386`：Debian 13 (trixie) 的 wine 10.0 已有原生 **amd64** 包，
#    而 add-architecture 会让 apt 需要拉 i386 索引，本机网络/凭据受限时直接 exit 100（已实测踩过）。
#    我们要跑的 re01.exe 是 **PE64**，纯 64 位 wine 足够。
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      socat wine wine64 file binutils \
 && rm -rf /var/lib/apt/lists/*

ENV WINEPREFIX=/opt/wineprefix
WORKDIR /opt/re02

# ⚠️ 必须放在**挂载点之外**：运行时会 `-v ...:/opt/re02:ro`，若把校验文件放在 /opt/re02
#    会被 bind mount 整个遮蔽，导致 entrypoint 报 `awk: cannot open ... .md5`（已实测踩过）。
RUN mkdir -p /opt/expected && printf '%s  re01.exe\n' 1b80d8086f3a46b1adb7cfde10ac18df > /opt/expected/re01.exe.md5

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 9999
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

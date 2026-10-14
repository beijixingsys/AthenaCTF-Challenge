#!/bin/sh
# re02 远程包装入口：校验附件哈希 + 起 socat 判题端口（Wine 执行 PE64）
set -e

BIN=/opt/re02/re01.exe
# ⚠️ 校验文件放在 /opt/expected（挂载点 /opt/re02 之外），否则会被 -v 整个遮蔽
MD5FILE=/opt/expected/re01.exe.md5

if [ ! -f "$BIN" ]; then
  echo "[-] 缺少 $BIN —— 请用 -v \"\$PWD/attachments:/opt/re02:ro\" 挂载 attachments 目录" >&2
  exit 1
fi

HAVE=$(md5sum "$BIN" | awk '{print $1}')
WANT=$(awk '{print $1}' "$MD5FILE")
if [ "$HAVE" != "$WANT" ]; then
  echo "[-] re01.exe 哈希不符：have=$HAVE want=$WANT" >&2
  exit 1
fi
echo "[+] re01.exe md5 校验通过 ($HAVE)"

# 首次运行让 wine 初始化 prefix（无 X：用 null 驱动）
export WINEDLLOVERRIDES="mscoree,mshtml="
wineboot -i >/dev/null 2>&1 || true

exec socat TCP-LISTEN:9999,reuseaddr,fork EXEC:"wine $BIN"

#!/bin/sh
# r3 re01 远程包装入口：校验附件哈希 + 起 socat 判题端口
set -e

BIN=/opt/re01/main
# ⚠️ 校验文件放在 /opt/expected（挂载点 /opt/re01 之外），否则会被 -v 整个遮蔽
MD5FILE=/opt/expected/main.md5

if [ ! -f "$BIN" ]; then
  echo "[-] 缺少 $BIN —— 请用 -v \"\$PWD/attachments:/opt/re01:ro\" 挂载 attachments 目录" >&2
  exit 1
fi

HAVE=$(md5sum "$BIN" | awk '{print $1}')
WANT=$(awk '{print $1}' "$MD5FILE")
if [ "$HAVE" != "$WANT" ]; then
  echo "[-] main 哈希不符：have=$HAVE want=$WANT" >&2
  exit 1
fi
echo "[+] main md5 校验通过 ($HAVE)"

chmod +x "$BIN" 2>/dev/null || true

exec socat TCP-LISTEN:9999,reuseaddr,fork EXEC:"$BIN"

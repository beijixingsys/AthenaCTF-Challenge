#!/bin/bash
# entrypoint.sh — web03 外层容器启动脚本
#
# 目的：让「每次 up -d」都从干净状态开始，对齐比赛期间容器的初始态：
#   * /var/www/html/temp_img/  清空（这是 SSRF 的落盘目录，原题初始为空）
#   * /srv/ftp/pub/            清空（匿名可写目录，原题初始为空）
#   * /srv/ftp/                根目录只保留 show_img_v1.0.php
# 这样 `GET /temp_img/` 才会稳定返回 403（而不是上一轮残留的 index.html 导致的 200）。
set -e

DOCROOT=/var/www/html
FTPROOT=/srv/ftp

# temp_img：清空内容但保留目录本身
if [ -d "$DOCROOT/temp_img" ]; then
  find "$DOCROOT/temp_img" -mindepth 1 -delete 2>/dev/null || true
  chown www-data:www-data "$DOCROOT/temp_img"
fi

# FTP pub/：清空匿名上传物
if [ -d "$FTPROOT/pub" ]; then
  find "$FTPROOT/pub" -mindepth 1 -delete 2>/dev/null || true
  chown ftpuser:ftpuser "$FTPROOT/pub" 2>/dev/null || true
  chmod 775 "$FTPROOT/pub" 2>/dev/null || true
fi

echo "[*] web03 entrypoint: temp_img/ 与 ftp pub/ 已重置为初始空态"
exec "$@"

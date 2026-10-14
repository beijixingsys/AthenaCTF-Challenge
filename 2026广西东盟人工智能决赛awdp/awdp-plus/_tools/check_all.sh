#!/bin/sh
# 全量构建 + 验证（Linux/macOS；Windows 请用 python _tools/verify.py）
set -e
cd "$(dirname "$0")"
python3 _tools/build.py
docker compose up -d --build
sleep 6
for p in 5000 5001 5002 5003 5004 5005 5006 5007 5008; do
    name=$(python3 -c "import sys;sys.path.insert(0,'_tools');import specs;print([s['name'] for s in specs.SPECS if s['port']=='$p'][0])")
    echo "--- $name (port $p) ---"
    python3 "$name/checker/checker.py" "http://127.0.0.1:$p" || true
done

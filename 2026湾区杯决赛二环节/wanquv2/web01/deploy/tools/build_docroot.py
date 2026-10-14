#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_docroot.py — 一键生成 round2 web01 的 docroot（宿主机侧，构建前跑一次）

为什么不在 Dockerfile 里做：`php:7.4-apache` 镜像**不带 python3**，
而 debian bullseye 的 apt 源在本机网络下频繁超时（实测 `apt-get install python3`
直接 exit 100）。所以把二进制 swap 的生成放在宿主机，Dockerfile 只 COPY。

用法（在 deploy/ 目录下）:
    python tools/build_docroot.py
    docker compose -f docker-compose.yml up -d --build
"""
from __future__ import annotations

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEPLOY = os.path.dirname(HERE)
SRC = os.path.join(DEPLOY, 'src')
DOCROOT = os.path.join(DEPLOY, 'docroot')

sys.path.insert(0, HERE)
from mk_swp import build_swp          # noqa: E402


def main() -> int:
    os.makedirs(DOCROOT, exist_ok=True)
    plan = [
        ('vi.php', '/var/www/html/vi.php', '.vi.php.swp'),
        ('index.php', '/var/www/html/index.php', '.index.php.swp'),
    ]
    ok = True
    for src_name, orig_path, swp_name in plan:
        sp = os.path.join(SRC, src_name)
        data = open(sp, 'rb').read()
        # 1) 源码进 docroot
        shutil.copyfile(sp, os.path.join(DOCROOT, src_name))
        # 2) 交换文件进 docroot
        swp = build_swp(data, orig_path)
        dp = os.path.join(DOCROOT, swp_name)
        with open(dp, 'wb') as f:
            f.write(swp)
        # 3) 自检：裸扫必须能完整还原源码
        import re
        runs = re.findall(rb'[\x20-\x7e\r\n\t]{5,}', swp)
        good = data.strip() in b'\n'.join(runs)
        ok = ok and good
        print(f'[{"OK" if good else "FAIL"}] {swp_name:20s} {len(swp):6d}B  '
              f'magic={swp[:8]!r}  orig={orig_path}')
    print(f'\ndocroot -> {DOCROOT}')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())

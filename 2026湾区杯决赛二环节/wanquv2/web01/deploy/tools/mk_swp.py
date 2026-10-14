#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mk_swp.py — 生成 vim 风格交换文件（round2 web01 部署件）

为什么需要它：vim swap 是二进制格式，不能靠手写文本文件得到。
本脚本按真实 vim swap 的布局生成 `.vi.php.swp` / `.index.php.swp`：

    offset 0    : magic "b0VIM " + 版本（本题实测容器为 "b0VIM 8.0"）
    offset 8    : NUL 分隔的 user / hostname / 被编辑文件绝对路径
    offset 1024 : 被编辑文件的原始字节，按 **1024 字节块**（BSIZE）存放，
                  块头是 struct block（含块号/块长度），因此源码**跨块存放**。

这一点是本题的关键考点：**按 1024 字节块对齐去扫描会漏掉跨块数据，
必须裸扫连续可打印段（printable run）**。

用法:
    python mk_swp.py <源文件> <输出 .swp> [原始路径]
    python mk_swp.py src/vi.php deploy/docroot/.vi.php.swp /var/www/html/vi.php
"""
from __future__ import annotations

import os
import sys

BSIZE = 1024          # vim 的块大小
BLOCK0_SIZE = BSIZE   # 块 0 = 头 + 空数据区

# struct block 的简化布局（真实 vim: b_id/b_prev/b_next/b_data）
STRUCT_BLOCK_HDR = 16


def build_swp(src_bytes: bytes, orig_path: str,
              magic: bytes = b'b0VIM 8.0',
              user: bytes = b'xiaoming',
              host: bytes = b'web01') -> bytes:
    """按 1024 字节块把 src_bytes 写进 swap 文件。"""
    out = bytearray()

    # ---- 块 0：magic + NUL 分隔元数据 ----
    head = bytearray(BLOCK0_SIZE)
    meta = magic + b'\x00' + user + b'\x00' + host + b'\x00' + orig_path.encode() + b'\x00'
    if len(meta) > BLOCK0_SIZE - 16:
        raise ValueError('元数据过长')
    head[:len(meta)] = meta
    # 真实 swap 里块 0 尾部还带 flags/时间戳，这里填成非可打印字节
    head[BLOCK0_SIZE - 12:] = b'\x00' * 12
    out += head

    # ---- 数据块：每块 STRUCT_BLOCK_HDR 字节块头 + 最多 (BSIZE-HDR) 字节数据 ----
    data_per_block = BSIZE - STRUCT_BLOCK_HDR
    n = 0
    for off in range(0, len(src_bytes), data_per_block):
        chunk = src_bytes[off:off + data_per_block]
        blk = bytearray(BSIZE)
        # 块头：块号（大端）+ 本块有效长度
        blk[0:4] = n.to_bytes(4, 'big')
        blk[4:8] = (STRUCT_BLOCK_HDR + len(chunk)).to_bytes(4, 'big')
        blk[8:12] = (0 if n == 0 else n - 1).to_bytes(4, 'big')      # b_prev
        blk[12:16] = (n + 1).to_bytes(4, 'big')                       # b_next
        blk[STRUCT_BLOCK_HDR:STRUCT_BLOCK_HDR + len(chunk)] = chunk
        out += blk
        n += 1
    return bytes(out)


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    orig = sys.argv[3] if len(sys.argv) > 3 else '/var/www/html/' + os.path.basename(src)
    data = open(src, 'rb').read()
    swp = build_swp(data, orig)
    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    with open(dst, 'wb') as f:
        f.write(swp)

    # 统计：验证源码被切成多个 1KB 块（= 制造跨块）
    blocks = (len(data) + (BSIZE - STRUCT_BLOCK_HDR) - 1) // (BSIZE - STRUCT_BLOCK_HDR)
    print(f'[+] {dst}  {len(swp)} bytes  (源 {len(data)}B / {blocks} 个数据块)')
    print(f'    magic={swp[:8]!r}  orig={orig}')
    # 自检：裸扫可打印段必须能拿到完整源码
    import re
    runs = re.findall(rb'[\x20-\x7e\r\n\t]{5,}', swp)
    joined = b'\n'.join(runs)
    ok = data.strip() in joined
    print(f'    [{"OK" if ok else "FAIL"}] 裸扫 printable-run 能否完整还原源码')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())

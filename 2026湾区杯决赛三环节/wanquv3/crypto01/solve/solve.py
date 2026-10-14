#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
round3_1700/crypto01  --  qid: aE9BLf9fMqMPag7T  --  500 分

考点: RSA 特殊结构 / **阶攻击(order attack)**。
出题脚本 (deploy/src/task.py) 的结构:
    assert alpha.bit_length() == beta.bit_length() == 24
    assert g.bit_length() == 575
    assert GCD(alpha, beta) == 1
    p = 2*g*alpha + 1 ;  q = 2*g*beta + 1      # g, p, q 皆素数
    n = p*q ;  c = pow(m, e, n) ;  e = 0x10001

攻击原理:
  令 A = a^(n-1) mod n  (a 取小素数, 本题 a=2 即可)。
  因为 n-1 = pq-1 ≡ q-1 (mod p-1), 所以
        A ≡ a^(q-1)  (mod p)   ->  ord_p(A) | (p-1)/gcd(q-1, p-1) = 2gα/(2g·gcd(α,β)) = α
        A ≡ a^(p-1)  (mod q)   ->  ord_q(A) | β
  gcd(α,β)=1  =>  两个阶互素, 且都 < 2^24。
  => 扫 t = 1..2^24, 首次出现 gcd(A^t - 1, n) != 1 时:
         A^t ≡ 1 (mod p) 但 ≢ 1 (mod q)  =>  g = gcd(A^t - 1, n) = p
      (t 不可能同时是两边的阶的倍数: 那需要 t >= ord_p*ord_q ~ 2^47 > 2^24)
  批量优化: 每 BATCH 步只做一次 gcd(∏(A^t - 1) mod n, n); 命中后在本批内二分定位精确 t。
  本题实测 t = 11192429, 约 20 s。

拿到 p,q 后就是常规 RSA: phi=(p-1)(q-1), d=e^-1 mod phi, m=c^d mod n。

用法:
    python solve.py                                  # 用内嵌的原始 n/c
    python solve.py --from-file out.txt              # 从 task.py 的 stdout 里抓 n= / c=
    python solve.py --n <hex|dec> --c <hex|dec>
    python solve.py --max-t 16777216 --batch 8192
"""
from __future__ import annotations

import argparse
import io
import re
import sys
import time

import gmpy2
from gmpy2 import mpz

# ---- 比赛实例 (task.py 注释里给出的 n / c) ----
N_DEFAULT = (
    "729107931330867617517523042208690698629618508264464747396083242255580004835969321124583944236967002893"
    "176999326314086976577827592323899826080397672921628955029295770597868234209310509781937097129531086087"
    "366972551502191266838689578145855514883531219012931507866032166805391097982552248976726364885083806357"
    "0709547440063938943646651772164530633522199339380882021"
)
C_DEFAULT = (
    "685281558284735111350994212810948139989690470120518432449821941621771379142204575067186616808601429159"
    "592421374112990310363364903003086215546215656767406025923630961815415587916713532318106041140864191854"
    "572873597572742662845588398076299811795370803975239022330866438597502972727065993139615082460134620764"
    "3504567598401379829379513077614506465772564081039622555"
)
E_DEFAULT = 0x10001

BATCH_DEFAULT = 8192
MAXT_DEFAULT = 1 << 24           # 2^24: 因为 α,β 都是 24 bit
BASES = (2, 3, 5, 7, 11, 13)


# ------------------------------------------------------------------ 工具函数
def prod_range(A, start: int, cnt: int, n):
    """返回 ( ∏_{u=start+1}^{start+cnt} (A^u - 1) mod n ,  A^(start+cnt) mod n )"""
    cur = int(gmpy2.powmod(A, start, n))
    acc = mpz(1)
    An = mpz(A)
    for _ in range(cnt):
        cur = cur * An % n
        acc = acc * (cur - 1) % n
    return acc, cur


def split_factor(A, s: int, e: int, n, log=None) -> tuple[int, int] | None:
    """在区间 (s, e] 内二分定位使 1 < gcd(A^t - 1, n) < n 的 t"""
    cnt = e - s
    if cnt <= 0:
        return None
    acc, _ = prod_range(A, s, cnt, n)
    g = int(gmpy2.gcd(acc, n))
    if g == 1:
        return None
    if cnt == 1:
        return (e, g) if 1 < g < n else None
    mid = s + cnt // 2
    r = split_factor(A, s, mid, n, log)
    if r:
        return r
    return split_factor(A, mid, e, n, log)


def order_attack(n, max_t=MAXT_DEFAULT, batch=BATCH_DEFAULT, bases=BASES, log=print):
    """返回 n 的一个非平凡因子, 或 None"""
    n = mpz(n)
    for a in bases:
        A = int(gmpy2.powmod(a, n - 1, n))
        if A == 1:
            log("  base %d: A == 1, skip" % a)
            continue
        g0 = int(gmpy2.gcd(A - 1, n))
        if 1 < g0 < n:
            log("  base %d: t=1 直接命中, p = gcd(A-1, n)" % a)
            return g0

        t0 = time.time()
        cur = mpz(A)
        acc = mpz(1)
        t = 0
        while t < max_t:
            step = min(batch, max_t - t)
            for _ in range(step):
                cur = cur * A % n
                acc = acc * (cur - 1) % n
            t += step
            gg = int(gmpy2.gcd(acc, n))
            if gg == 1:
                acc = mpz(1)
                if t % (1 << 20) < step:
                    log("  base %d: t=%d (%.1fs)" % (a, t, time.time() - t0))
                continue
            # 本批内有命中 -> 二分精确定位
            r = split_factor(A, t - step, t, n, log)
            if r:
                tt, g = r
                log("  base %d: FOUND t=%d  p=gcd(A^t-1, n)  (%.1fs)" % (a, tt, time.time() - t0))
                return g
            # 整批 gcd == n (t 是两边的公共倍数) -> 继续扫
            log("  base %d: 本批 gcd 平凡/过大, 继续 (t=%d)" % (a, t))
            acc = mpz(1)
    return None


def recover_alpha_beta_g(p, q, t_hint=None):
    """由 p = 2gα+1, q = 2gβ+1 反推 (g, alpha, beta): α,β 各 24 bit 且互素, g 是 575 bit 素数"""
    alpha = beta = g = None
    for name, X in (("alpha", p), ("beta", q)):
        X = int(X)
        found = None
        for d in range(1 << 23, 1 << 24):
            if (X - 1) % (2 * d) == 0:
                cand = (X - 1) // (2 * d)
                if cand.bit_length() == 575 and gmpy2.is_prime(cand):
                    found = (int(d), int(cand))
                    break
        if name == "alpha":
            alpha, g = found if found else (None, None)
        else:
            beta, g2 = found if found else (None, None)
            if g is not None and g2 is not None and g != g2:
                g = None
    if alpha and beta and g and gmpy2.gcd(alpha, beta) == 1:
        return int(g), int(alpha), int(beta)
    return None


def long_to_bytes(x: int) -> bytes:
    x = int(x)
    return x.to_bytes((x.bit_length() + 7) // 8, "big") if x else b"\x00"


def read_text_any(path: str) -> str:
    """读文本, 兼容 PowerShell `>` 重定向产出的 UTF-16LE+BOM 文件"""
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw.count(b"\x00") > len(raw) // 4:            # 无 BOM 的 UTF-16
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


# ---------------------------------------------------------------------- main
def main() -> str:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", default=None)
    ap.add_argument("--c", default=None)
    ap.add_argument("--e", default=str(E_DEFAULT))
    ap.add_argument("--from-file", default=None, help="含 n= 与 c= 的文本(task.py 的 stdout)")
    ap.add_argument("--max-t", type=int, default=MAXT_DEFAULT)
    ap.add_argument("--batch", type=int, default=BATCH_DEFAULT)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    def tonum(s: str):
        s = s.strip()
        return mpz(int(s, 16)) if s.lower().startswith("0x") else mpz(int(s))

    if a.from_file:
        txt = read_text_any(a.from_file)
        mn = re.search(r'(?:^|\n)\s*n\s*=\s*([0-9a-fA-Fx]+)', txt)
        mc = re.search(r'(?:^|\n)\s*c\s*=\s*([0-9a-fA-Fx]+)', txt)
        if not (mn and mc):
            sys.exit("[!] 未在 %s 里找到 n= / c=" % a.from_file)
        n_s, c_s = mn.group(1), mc.group(1)
    else:
        n_s, c_s = a.n or N_DEFAULT, a.c or C_DEFAULT

    n, c, e = tonum(n_s), tonum(c_s), tonum(a.e)
    print("[*] n bits=%d  c bits=%d  e=%s" % (n.bit_length(), c.bit_length(), hex(int(e))))

    p = order_attack(n, a.max_t, a.batch)
    if not p:
        sys.exit("[!] 未在 t <= 2^%d 内分出因子" % (a.max_t.bit_length() - 1))
    p, q = mpz(p), n // mpz(p)
    assert p * q == n
    print("[*] p bits=%d  q bits=%d" % (p.bit_length(), q.bit_length()))
    print("[*] p = %d" % p)
    print("[*] q = %d" % q)

    # ---- 结构自验: p-1 = 2*g*alpha, q-1 = 2*g*beta, g 为 575 bit 素数 ----
    print("[*] 结构校验:")
    for X, name in ((p, "p"), (q, "q")):
        v, t = 0, mpz(X - 1)
        while t % 2 == 0:
            t //= 2
            v += 1
        print("      %s-1 = 2^%d * %d (bit=%d)" % (name, v, t, t.bit_length()))
    rec = recover_alpha_beta_g(p, q)
    if rec:
        g_r, al, be = rec
        print("      => g=%d (bit=%d, prime=%s)" % (g_r, g_r.bit_length(), gmpy2.is_prime(g_r)))
        print("      => alpha=%d (bit=%d)   beta=%d (bit=%d)   gcd=%d"
              % (al, al.bit_length(), be, be.bit_length(), gmpy2.gcd(al, be)))
        print("      => p == 2*g*alpha+1 : %s   q == 2*g*beta+1 : %s"
              % (int(p) == 2 * g_r * al + 1, int(q) == 2 * g_r * be + 1))

    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi)
    m = gmpy2.powmod(c, d, n)
    mb = long_to_bytes(int(m))
    print("[*] m bytes = %r" % mb)
    text = mb.decode("utf-8", "replace")
    mf = re.search(r'flag\{[^}]*\}', text)
    flag = mf.group(0) if mf else text.strip()
    print("[+] FLAG = %s" % flag)
    if a.out:
        io.open(a.out, "w", encoding="utf-8").write(flag)
        print("[+] 已写入 %s" % a.out)
    return flag


if __name__ == "__main__":
    main()

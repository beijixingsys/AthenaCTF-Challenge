# -*- coding: utf-8 -*-
"""
round3_1700 / crypto01 「出新实例」生成器。

用法（在 deploy/src/ 下执行）：
    python gen_secret.py                                  # 随机生成 secret.py（flag 用占位）
    python gen_secret.py --flag "flag{your_uuid_here}"
    python gen_secret.py --out secret.py --seed 20260914

生成规则（与 task.py 的 assert 逐条对应）：
    alpha.bit_length() == beta.bit_length() == 24
    g.bit_length() == 575
    GCD(alpha, beta) == 1
    p = 2*g*alpha + 1, q = 2*g*beta + 1，且 g / p / q 均为素数

⚠️ 生成顺序很重要（本文件的核心）：
    先取一个 **575 bit 素数 g**，再在 24 bit 空间里**分别**搜索 alpha、beta 使
    2*g*alpha+1、2*g*beta+1 为素数。
    反过来（随机 alpha/beta 再找 g 使 p、q 同时素）是**三重素数约束**，
    期望尝试次数 ≈ ln(g)·ln(p)·ln(q) ≈ 400^3 ≈ 6.4e7，实际不可用。
    先定 g 后每个约束只剩一重（≈ 1/400），总耗时 < 1 s。

生成后执行 `python task.py` 即得到新的 n / c（= 新一道可复现的题）。
"""
from __future__ import annotations

import argparse
import io
import math
import random

import gmpy2

FLAG_PLACEHOLDER = "flag{00000000-0000-0000-0000-000000000000}"


def rand_prime(bits: int, rng: random.Random) -> int:
    while True:
        x = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if gmpy2.is_prime(x):
            return x


def rand_24bit(rng: random.Random) -> int:
    """24 bit，最高位强制为 1（保证 bit_length()==24），且为奇数"""
    return rng.getrandbits(24) | (1 << 23) | 1


def gen_instance(rng: random.Random, flag: str, verbose: bool = True):
    g = rand_prime(575, rng)
    if verbose:
        print("[*] g = 575 bit 素数 OK")

    alpha = None
    n_try_a = 0
    while alpha is None:
        cand = rand_24bit(rng)
        n_try_a += 1
        if gmpy2.is_prime(2 * g * cand + 1):
            alpha = cand
    if verbose:
        print("[*] alpha = %d  (试了 %d 个 24bit 候选)" % (alpha, n_try_a))

    beta = None
    n_try_b = 0
    while beta is None:
        cand = rand_24bit(rng)
        n_try_b += 1
        if cand == alpha or math.gcd(cand, alpha) != 1:
            continue
        if gmpy2.is_prime(2 * g * cand + 1):
            beta = cand
    if verbose:
        print("[*] beta  = %d  (试了 %d 个 24bit 候选)" % (beta, n_try_b))
    return flag, alpha, beta, g


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="secret.py")
    ap.add_argument("--flag", default=FLAG_PLACEHOLDER)
    ap.add_argument("--seed", type=int, default=None)
    a = ap.parse_args()

    rng = random.Random(a.seed)
    flag, alpha, beta, g = gen_instance(rng, a.flag)
    p, q = 2 * g * alpha + 1, 2 * g * beta + 1

    # 复核所有 assert
    assert alpha.bit_length() == beta.bit_length() == 24
    assert g.bit_length() == 575
    assert math.gcd(alpha, beta) == 1
    assert gmpy2.is_prime(g) and gmpy2.is_prime(p) and gmpy2.is_prime(q)

    body = (
        "# -*- coding: utf-8 -*-\n"
        "# 由 gen_secret.py 生成的新实例（%s）\n"
        "# 注意: flag 必须是 bytes —— 原始 task.py 用 bytes_to_long(flag)\n"
        "flag = %r\n\n"
        "g = %d      # %d bit 素数\n"
        "alpha = %d  # %d bit\n"
        "beta = %d   # %d bit\n"
        "\n# p = %d\n# q = %d\n# n = p*q = %d\n"
        % (("seed=%s" % a.seed) if a.seed is not None else "random",
           flag.encode(), g, g.bit_length(), alpha, alpha.bit_length(), beta, beta.bit_length(),
           p, q, p * q)
    )
    io.open(a.out, "w", encoding="utf-8").write(body)
    print("[+] 已写出 %s" % a.out)
    print("    g bits=%d  alpha=%d(bits=%d)  beta=%d(bits=%d)"
          % (g.bit_length(), alpha, alpha.bit_length(), beta, beta.bit_length()))
    print("    现在执行 `python task.py` 即可打印新的 n / c")


if __name__ == "__main__":
    main()

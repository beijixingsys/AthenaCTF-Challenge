# -*- coding: utf-8 -*-
"""
逐位校验: 用 deploy/src/secret.py 的 g/alpha/beta/flag 重跑 task.py 的逻辑,
         得到的 n / c 是否与原始附件 task.py 注释里的 n / c 完全一致。

用法（在 deploy/src/ 下执行）:  python verify_instance.py
"""
from __future__ import annotations

import io
import re

from Crypto.Util.number import bytes_to_long
from sympy import isprime

HERE = __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0]
import os
HERE = os.path.dirname(os.path.abspath(__file__))

import secret  # noqa: E402  (deploy/src/secret.py)


def main() -> int:
    src = io.open(os.path.join(HERE, "task.py"), encoding="utf-8", errors="replace").read()
    n_orig = int(re.search(r'\bn=(\d+)\s*\n', src).group(1))
    c_orig = int(re.search(r'\bc=(\d+)\s*\n', src).group(1))

    e = 0x10001
    fl = secret.flag if isinstance(secret.flag, (bytes, bytearray)) else secret.flag.encode()
    m = bytes_to_long(bytes(fl))
    p = 2 * secret.g * secret.alpha + 1
    q = 2 * secret.g * secret.beta + 1
    assert isprime(secret.g), "g 不是素数"
    assert isprime(p) and isprime(q), "p/q 不是素数"
    assert secret.alpha.bit_length() == 24 and secret.beta.bit_length() == 24
    import math
    assert math.gcd(secret.alpha, secret.beta) == 1
    assert secret.g.bit_length() == 575

    n = p * q
    c = pow(m, e, n)
    print("[*] 结构 assert 全通过 (g 575bit 素 / alpha,beta 24bit 互素 / p,q 素)")
    print("[*] n 与原始 task.py 一致:", n == n_orig)
    print("[*] c 与原始 task.py 一致:", c == c_orig)
    print("[+] 重建的 secret.py 对本实例等价:", n == n_orig and c == c_orig)
    return 0 if (n == n_orig and c == c_orig) else 1


if __name__ == "__main__":
    raise SystemExit(main())

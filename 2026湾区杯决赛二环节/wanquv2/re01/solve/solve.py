#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
round2_1330 / re01  ——  附件 gdb_me (ELF64 x86-64 PIE, GCC 13.3.0, 未剥离符号, 16160 B)
qid = eVn0vSPSZZxRDM0u   score = 500   category = reverse

考点
----
1. 未剥离 .symtab: `rc4_init` / `rc4_crypt` / `main` 直接给出算法族 = RC4。
2. main 把校验结果算完即弃（写入 [rbp-0x110] 后直接 ret，从不打印 / 从不 strcmp）
   → 只能静态复现两段算法，无法靠"喂输入看输出"过关。
3. 42 字节硬编码密表由 6 条 `movabs` 写入栈上，其中两条目标地址故意重叠
   （[rbp-0x326] / [rbp-0x31e]）→ 手工抄表会抄错，脚本按地址序展开才对。

算法（还原自 main @0x13b6 / rc4_init @0x11a9 / rc4_crypt @0x1298）
--------------------------------------------------------------
    rc4_init (key  = "my_secret_key" @0x2024, len = 13)          # KSA
    rc4_crypt("This_is_a_your_start_string" @0x2008, len = 0x1b)  # PRGA
        out[j] = start[j] ^ ks[j]      (j = 0..26)
    enc[42] = 硬编码密表（main 的 6 条 movabs 展开）
    res[i] = out[i % 27] ^ enc[i]      (i = 0..41, main 用 idiv 0x1b 取余)
    res 长度 0x2a = 42  ->  恰好 flag{ + 36 字符 UUID + }

用法
----
    python solve.py                          # 用内嵌密表求解
    python solve.py --bin ../attachments/gdb_me   # 用 objdump 从二进制解析密表交叉校验
"""
import argparse
import os
import re
import subprocess
import sys

# Windows 控制台默认 GBK，中文/符号输出会炸 -> 统一改 UTF-8
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROUND = "round2_1330"
NAME = "re01"
QID = "eVn0vSPSZZxRDM0u"
EXPECTED_FLAG = "flag{71a76145-c14f-4e0b-80ac-58035510fade}"

START = b"This_is_a_your_start_string"   # main @0x2008, esi = 0x1b = 27
KEY = b"my_secret_key"                   # main @0x2024, edx = 13
N = 42                                   # main: [rbp-0x358] = 0x2a

# 密表：main 的 6 条 movabs 按目标地址升序展开
#   0x13xx: movabs rax,<8B> ; mov QWORD PTR [rbp-0x340],rax
#   ...                     ...
# 末两条目标地址重叠 ([rbp-0x326] / [rbp-0x31e])，实际只追加 32..41 共 10 字节
ENC = bytes([
    0x7b, 0x8e, 0xa3, 0x50, 0x19, 0xa3, 0x37, 0x1f,
    0x40, 0xdd, 0x51, 0x35, 0x66, 0xe5, 0x30, 0x5d,
    0xec, 0xf8, 0xbe, 0x90, 0xaf, 0xfe, 0x9f, 0xe0,
    0x72, 0x48, 0xfc, 0x7e, 0xcf, 0xf7, 0x0f, 0x52,
    0xa7, 0x33, 0x4b, 0x46, 0xdb, 0x06, 0x60, 0x37,
    0xad, 0x2e,
])

HERE = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------- RC4
def rc4_ksa(key: bytes) -> list:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def rc4_keystream(key: bytes, n: int) -> bytes:
    s = rc4_ksa(key)
    i = j = 0
    out = bytearray()
    for _ in range(n):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


# --------------------------------------------------- 从二进制反解 42 字节密表
def parse_enc_from_binary(path: str, n: int = N) -> bytes:
    """objdump -d -M intel，跟踪 `movabs rXX,imm64` + `mov QWORD PTR [rbp-0xNNN],rXX`，
    按 [rbp-0x340] 起的地址升序展开，重叠写自然被后写覆盖（正是本题的坑）。"""
    txt = subprocess.run(["objdump", "-d", "-M", "intel", path],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
                         ).stdout.decode("ascii", "replace")
    mem, pending = {}, {}
    for line in txt.split("\n"):
        m = re.search(r"movabs (r[a-z0-9]+),(0x[0-9a-f]+)", line)
        if m:
            pending[m.group(1)] = int(m.group(2), 16)
            continue
        m = re.search(r"mov\s+QWORD PTR \[rbp-(0x[0-9a-f]+)\],(r[a-z0-9]+)", line)
        if m and m.group(2) in pending:
            off, v = int(m.group(1), 16), pending[m.group(2)]
            for k in range(8):
                mem[off - k] = (v >> (8 * k)) & 0xFF
    missing = [hex(0x340 - i) for i in range(n) if (0x340 - i) not in mem]
    if missing:
        raise RuntimeError("objdump 未覆盖到这些栈偏移: %s" % missing)
    return bytes(mem[0x340 - i] for i in range(n))


# --------------------------------------------------------------------------- 解
def solve(enc: bytes) -> bytes:
    ks = rc4_keystream(KEY, len(START))
    out = bytes(a ^ b for a, b in zip(START, ks))     # rc4_crypt 的输出
    return bytes(out[i % len(START)] ^ enc[i] for i in range(N))


def main() -> int:
    ap = argparse.ArgumentParser(description="round2_1330 re01 solver (RC4 + 重叠密表)")
    ap.add_argument("--bin", default=os.path.join(HERE, "..", "attachments", "gdb_me"),
                    help="gdb_me 路径（存在则用 objdump 交叉校验密表）")
    ap.add_argument("--no-crosscheck", action="store_true", help="跳过 objdump 交叉校验")
    a = ap.parse_args()

    enc = ENC
    if not a.no_crosscheck and a.bin and os.path.exists(a.bin):
        parsed = parse_enc_from_binary(a.bin)
        print("[*] objdump 从二进制解析密表: %s" % parsed.hex(" "))
        assert parsed == ENC, "二进制密表与内嵌常量表不一致!"
        print("[+] 交叉校验通过：二进制密表 == 内嵌常量表 (42 B)")

    ks = rc4_keystream(KEY, len(START))
    print("[*] key      = %r (len %d)" % (KEY, len(KEY)))
    print("[*] start    = %r (len %d)" % (START, len(START)))
    print("[*] RC4 密钥流(27 B) = %s" % ks.hex(" "))
    print("[*] rc4_crypt 输出   = %s" % bytes(x ^ y for x, y in zip(START, ks)).hex(" "))

    flag = solve(enc)
    print("[+] flag = %s" % flag.decode("latin-1"))
    if flag.decode("latin-1") == EXPECTED_FLAG:
        print("[+] 与比赛期确认 flag 一致 -> PASS")
        return 0
    print("[!] 与比赛期确认 flag 不一致 (仍打印如上)")
    return 1


if __name__ == "__main__":
    sys.exit(main())

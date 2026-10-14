#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
round2_1330 / re02  ——  附件 re01.exe (PE64, MinGW-W64 / GCC 8.1.0, 无壳无反调试无符号, 16896 B)
qid = n6sTYSB71GlMDKLH   score = 500   category = reverse

⚠️ 文件名是出题人的命名干扰：本题叫 re02，附件却叫 `re01.exe`（与上一题 re01 的
   `gdb_me` 错位）。这是**真实事实**，不是本还原工程的笔误。

考点
----
1. PE64 手工逆向（无 PDB / 无符号 / 非标准帧）：
   `main @0x40161b` 用 `sub rsp,0x1d0` + `lea rbp,[rsp+0x80]` 建立**偏移 0x80 的伪帧**，
   所有局部变量以 `[rbp+0xNN]`（正偏移）寻址，与正常 `[rbp-0xNN]` 相反，反编译器容易看错。
2. **密钥字节两两异或派生**（核心考点）：栈上相邻三个字节 0x99 / 0xdd / 0xff，
   真实 key 不是它们本身，而是**两两异或**：
       keyA = [rbp+0x137] ^ [rbp+0x135] = 0x99 ^ 0xff = 0x66
       keyB = [rbp+0x136] ^ [rbp+0x137] = 0xdd ^ 0x99 = 0x44
       keyC = [rbp+0x135] ^ [rbp+0x136] = 0xff ^ 0xdd = 0x22
   注意 0x99/0xdd/0xff 恰好互为"部分按位取反"关系（0x66=~0x99, 0x22=~0xdd, 0x00=~0xff），
   是典型的"看起来像魔数、其实是派生源"的诱导。
3. **ROL8 循环左移 1 位 + XOR key** 逐字节变换（`sub_4015b6` 内层调用 `sub_40159a`）：
       rol1(x) = (x << 1) | (x >> 7)          # 8 位循环左移，非算术左移
       x' = rol1(x) ^ key                      # 逐字节原地改写
   逆运算：x = ror1(x' ^ key)。
4. **三段密文拼接期望串**：`snprintf(dst, 0x80, "%s%s%s", A', B', C')`（fmt @0x40500f），
   然后 `scanf("%127s")` + `strcmp`。做题人必须自己判断拼接顺序 ——
   三段长度 0x0e / 0x0f / 0x0d = 14 / 15 / 13 恰好构成 42 字节 flag。
5. **实机可自校验**：程序会打印「成功！」/「输入错误！」，所以本题**可以用喂 stdin 的方式判定**，
   与 re01（结果算完即弃）形成对照。

用法
----
    python solve.py                                    # 用内嵌三段数组求解
    python solve.py --bin ../attachments/re01.exe      # 用 objdump 交叉校验三段数组
    python solve.py --verify ../attachments/re01.exe   # 把解出的 flag 灌入原程序 stdin 实机验证
"""
import argparse
import os
import re
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROUND = "round2_1330"
NAME = "re02"
QID = "n6sTYSB71GlMDKLH"
EXPECTED_FLAG = "flag{0fa830e7-b699-4513-8e01-51f35b0f3293}"

# 三段硬编码数组（按 [rbp+off] 地址顺序抄自反汇编 0x401630..0x40176b）
A = [0x00, 0x05, 0x83, 0x80, 0x8e, 0x2b, 0x00, 0x83,
     0x2f, 0xaa, 0x2b, 0x81, 0xa8, 0xa5]                                                    # [rbp+0x10a], len 0x0e = 14
B = [0x13, 0x39, 0xbe, 0xbe, 0xb4, 0x38, 0xb8, 0xba,
     0xbb, 0xb4, 0x3e, 0x90, 0x3a, 0xba, 0xb4]                                              # [rbp+0xfb],  len 0x0f = 15
C = [0x8b, 0x89, 0x22, 0x88, 0x8b, 0x20, 0x09, 0x22,
     0x88, 0x08, 0x8d, 0x88, 0xaf]                                                          # [rbp+0xee],  len 0x0d = 13

# 密钥字节（栈上相邻三字节，0x401777..0x40178b）
KB = {0x137: 0x99, 0x136: 0xdd, 0x135: 0xff}

# 0x40178c..0x4017c4 三条 xor 指令：
#   [rbp+0x134] = [rbp+0x137] ^ [rbp+0x135]   (keyA, 用于 A)
#   [rbp+0x133] = [rbp+0x136] ^ [rbp+0x137]   (keyB, 用于 B)
#   [rbp+0x132] = [rbp+0x135] ^ [rbp+0x136]   (keyC, 用于 C)
KEY_A = KB[0x137] ^ KB[0x135]     # 0x66
KEY_B = KB[0x136] ^ KB[0x137]     # 0x44
KEY_C = KB[0x135] ^ KB[0x136]     # 0x22

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BIN = os.path.join(HERE, "..", "attachments", "re01.exe")


def rol1(x: int) -> int:
    """sub_40159a: (x << 1) | (x >> 7)，8 位循环左移 1 位。"""
    x &= 0xFF
    return ((x << 1) | (x >> 7)) & 0xFF


def ror1(x: int) -> int:
    """逆运算：8 位循环右移 1 位。"""
    x &= 0xFF
    return ((x >> 1) | (x << 7)) & 0xFF


def parse_arrays_from_binary(path: str):
    """从 `objdump -d -M intel` 抓 `mov BYTE PTR [rbp+0xNN],0xVV`，按偏移取三段数组。"""
    txt = subprocess.run(["objdump", "-d", "-M", "intel", path],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
                         ).stdout.decode("ascii", "replace")
    vals = {}
    for m in re.finditer(r"BYTE PTR \[rbp\+0x([0-9a-f]+)\],0x([0-9a-f]+)\s*$", txt, re.M):
        vals[int(m.group(1), 16)] = int(m.group(2), 16)

    def grab(start, n):
        missing = [hex(start + i) for i in range(n) if (start + i) not in vals]
        if missing:
            raise RuntimeError("objdump 未覆盖到 [rbp+%s]" % missing)
        return [vals[start + i] for i in range(n)]

    return grab(0x10a, 14), grab(0xfb, 15), grab(0xee, 13)


def solve(a, b, c) -> bytes:
    """正向变换 x' = rol1(x) ^ key（程序做的），此处输出的是**期望输入**（即 flag）本身：
    程序把硬编码数组 *变换后* 得到期望串，所以 flag = 对数组做同样的变换。"""
    return bytes([rol1(x) ^ KEY_A for x in a] +
                 [rol1(x) ^ KEY_B for x in b] +
                 [rol1(x) ^ KEY_C for x in c])


def verify_with_binary(path: str, flag: bytes) -> bool:
    """把 flag 作为 stdin 喂给原程序；成功时 stdout 含 GBK 的「成功！」(b3c9 b9a6 a3a1)。"""
    try:
        p = subprocess.run([path], input=flag + b"\n",
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
    except OSError as e:
        print("[!] 无法执行 %s: %s" % (path, e))
        return False
    out = p.stdout
    ok = b"\xb3\xc9\xb9\xa6" in out
    print("[*] 实机输出(GBK): %s" % out.decode("gbk", "replace").strip())
    print("[*] 命中 '成功' 标记: %s" % ok)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description="round2_1330 re02 solver (两两异或派生 key + ROL1)")
    ap.add_argument("--bin", default=DEFAULT_BIN, help="re01.exe 路径（交叉校验三段数组）")
    ap.add_argument("--no-crosscheck", action="store_true")
    ap.add_argument("--verify", default=None, help="re01.exe 路径（把 flag 灌 stdin 实机验证）")
    args = ap.parse_args()

    a, b, c = A, B, C
    if not args.no_crosscheck and args.bin and os.path.exists(args.bin):
        pa, pb, pc = parse_arrays_from_binary(args.bin)
        assert (pa, pb, pc) == (A, B, C), "objdump 解析的三段数组与内嵌值不一致!"
        print("[+] objdump 交叉校验通过：三段数组与内嵌值一致 (%d/%d/%d B)" % (len(pa), len(pb), len(pc)))

    print("[*] 栈上密钥字节: [rbp+0x137]=0x%02x [rbp+0x136]=0x%02x [rbp+0x135]=0x%02x"
          % (KB[0x137], KB[0x136], KB[0x135]))
    print("[*] 两两异或派生: keyA=0x%02x keyB=0x%02x keyC=0x%02x" % (KEY_A, KEY_B, KEY_C))

    flag = solve(a, b, c)
    print("[*] 期望串 A'||B'||C' = %s" % flag.decode("latin-1"))
    print("[*] 长度 = %d（三段 14+15+13）" % len(flag))

    ok = flag.decode("latin-1") == EXPECTED_FLAG
    print("[%s] 与比赛期确认 flag %s" % ("+" if ok else "!", "一致 -> PASS" if ok else "不一致"))

    if args.verify and os.path.exists(args.verify):
        v = verify_with_binary(args.verify, flag)
        print("[*] 实机校验: %s" % ("PASS" if v else "FAIL"))
        ok = ok and v
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
round3_1700 / misc02  —  DNS 隧道 + 自定义 Base58 变种表 + ZipCrypto 已知明文
qid = urWolxzOUL4ouOER   score = 500     ★ 比赛期间未解出（详见 README §7/§8）

解码链（本脚本实现 1~4，第 5 步需要外部工具 bkcrack）：

  [1] DNS 隧道分片提取：pcapng 里 2092 条 `<N>-<32字符>.hackg.fun`（N=0..2091，无缺号）
      ＋ 1 条结束标记 `EOF-f1b662512c1fcbfc.hackg.fun`；按 N 排序拼接最左标签
  [2] 外层：标准 Base32 解码                      → 41836 字符，100% 可打印
  [3] 判定内层编码族：stage2 字符集恰好 58 个（缺 L/i/o） → Base58 族
  [4] 内层：自定义 Base58 变种表解码               → 30634 字节，`PK\\x03\\x04` 开头的真 ZIP
  [5] ZIP 内唯一条目 `secret.png` 是 **ZipCrypto 加密 + stored(未压缩)**，
      用 bkcrack 已知明文攻击（PNG 头 16 字节）恢复密钥后解密
      —— 本机 bkcrack 位于 D:\\2026\\湾区杯\\决赛\\v2\\tools\\bin\\bkcrack.exe（1.8.1）

用法：
    python solve.py --pcap attachments/secert.pcapng
    python solve.py --pcap attachments/secert.pcapng --bkcrack "D:\\...\\bkcrack.exe"
    python solve.py --pcap attachments/secert.pcapng --outdir out
"""
from __future__ import annotations

import argparse
import base64
import io
import os
import re
import shutil
import subprocess
import sys
import zipfile

sys.stdout.reconfigure(encoding="utf-8")

try:
    from scapy.all import DNS, DNSQR, rdpcap
except ImportError:  # pragma: no cover
    sys.stderr.write("[!] 需要 scapy：pip install -r requirements.txt\n")
    raise

# 隧道查询：`<序号>-<base32 载荷>.hackg.fun`
RE_FRAG = re.compile(r"^(\d+)-([A-Z2-7]+)\.hackg\.fun\.?$")
RE_EOF = re.compile(r"^EOF-([0-9a-f]+)\.hackg\.fun\.?$")

# 标准 Base58 字母表（CyberChef 默认 / Bitcoin 系）：排除了 0 O I l
STD_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# PNG 文件头：8 字节签名 + IHDR 块长度(13) + "IHDR"
# （任何合法 PNG 前 16 字节都确定，可作为 ZipCrypto 已知明文）
PNG_HEAD16 = "89504E470D0A1A0A0000000D49484452"


# ---------------------------------------------------------------- step 1
def extract_dns(pcap_path: str):
    """返回 (fragments: {idx: label}, eof: str|None, noise: set, npkts: int)。"""
    pkts = rdpcap(pcap_path)
    frag, eof, noise = {}, None, set()
    for p in pkts:
        if DNS not in p or p[DNS].qr != 0 or DNSQR not in p:
            continue
        try:
            q = p[DNSQR].qname.decode("ascii", "replace")
        except Exception:
            continue
        m = RE_FRAG.match(q)
        if m:
            frag[int(m.group(1))] = m.group(2)
            continue
        m = RE_EOF.match(q)
        if m:
            eof = m.group(1)
            continue
        noise.add(q)
    return frag, eof, noise, len(pkts)


def build_blob(frag: dict):
    idx = sorted(frag)
    gaps = sorted(set(range(idx[0], idx[-1] + 1)) - set(idx))
    return "".join(frag[i] for i in idx), idx[0], idx[-1], gaps


# ---------------------------------------------------------------- step 2
def b32_decode(blob: str) -> str:
    pad = "=" * (-len(blob) % 8)
    return base64.b32decode(blob + pad).decode("ascii")


# ---------------------------------------------------------------- step 3/4
def candidate_tables(charset: str):
    """按“自然排序”生成候选自定义 Base58 表（同一字符集的不同排列）。"""
    digits = "".join(c for c in "123456789" if c in charset)
    lower = "".join(c for c in "abcdefghijklmnopqrstuvwxyz" if c in charset)
    upper = "".join(c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if c in charset)
    return [
        ("digits -> lower(no i,o) -> upper(no L)", digits + lower + upper),
        ("digits -> upper -> lower", digits + upper + lower),
        ("sorted by codepoint", "".join(sorted(charset))),
        ("standard表顺序，仅替换缺失字符", "".join(c for c in STD_B58 if c in charset) +
         "".join(c for c in charset if c not in STD_B58)),
    ]


def b58_decode(text: str, table: str) -> bytes:
    m = {c: i for i, c in enumerate(table)}
    n = 0
    for c in text:
        n = n * 58 + m[c]
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def crack_inner(stage1: str):
    """判定 58 字符集并尝试候选表，返回 (raw, table, table_name, charset)。"""
    charset = "".join(sorted(set(stage1)))
    if len(charset) != 58:
        raise SystemExit("[!] stage2 字符集 %d 个（≠58），不是 Base58 族" % len(charset))
    for name, table in candidate_tables(charset):
        if sorted(table) != sorted(charset):
            continue
        try:
            raw = b58_decode(stage1, table)
        except KeyError:
            continue
        if raw[:4] == b"PK\x03\x04":
            return raw, table, name, charset
    raise SystemExit("[!] 所有候选表都解不出 ZIP 魔数")


# ---------------------------------------------------------------- step 5
def find_bkcrack(explicit: str | None):
    if explicit and os.path.isfile(explicit):
        return explicit
    hit = shutil.which("bkcrack")
    if hit:
        return hit
    for cand in (
        r"D:\2026\湾区杯\决赛\v2\tools\bin\bkcrack.exe",
        r"C:\bkcrack\bin\bkcrack.exe",
        "/usr/bin/bkcrack",
        "/usr/local/bin/bkcrack",
    ):
        if os.path.isfile(cand):
            return cand
    return None


def run_kpa(bkcrack: str, zip_path: str, entry: str, outdir: str):
    """已知明文攻击 → 解密。返回 (keys, png_path)。"""
    print("[*] bkcrack = %s" % bkcrack)
    # 攻击：PNG 头 16 字节，偏移 0 = 跳过 12 字节 ZipCrypto 加密头后的第一个字节
    cmd = [bkcrack, "-C", zip_path, "-c", entry,
           "-x", "0", PNG_HEAD16]
    print("[*] $ %s" % " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    tail = "\n".join([l for l in (proc.stdout or "").splitlines()
                      if "Key" in l or "Found" in l or "%" not in l][-6:])
    print(tail)
    m = re.search(r"Keys:\s*([0-9a-f]{8})\s+([0-9a-f]{8})\s+([0-9a-f]{8})", proc.stdout or "")
    if not m:
        raise SystemExit("[!] bkcrack 未恢复出密钥（检查条目名/明文偏移）")
    keys = m.groups()
    print("[*] keys = %s" % " ".join(keys))

    dec = os.path.join(outdir, os.path.splitext(entry)[0] + "_dec.png")
    cmd2 = [bkcrack, "-C", zip_path, "-c", entry, "-k", *keys, "-d", dec]
    print("[*] $ %s" % " ".join(cmd2))
    subprocess.run(cmd2, capture_output=True, text=True)
    if not os.path.isfile(dec):
        raise SystemExit("[!] 解密失败")
    return keys, dec


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="round3 misc02 solver (DNS tunnel + custom Base58 + ZipCrypto KPA)")
    ap.add_argument("--pcap", required=True, help="secert.pcapng 路径")
    ap.add_argument("--outdir", default="out", help="中间产物输出目录")
    ap.add_argument("--bkcrack", default=None, help="bkcrack 可执行文件路径（默认自动查找）")
    ap.add_argument("--no-kpa", action="store_true", help="只跑到解出 ZIP，不做已知明文攻击")
    a = ap.parse_args()

    os.makedirs(a.outdir, exist_ok=True)

    # [1] DNS 分片
    frag, eof, noise, npkts = extract_dns(a.pcap)
    blob, lo, hi, gaps = build_blob(frag)
    print("[1] pcap=%s  packets=%d" % (a.pcap, npkts))
    print("    DNS 隧道分片 %d 条（N=%d..%d，缺号=%s），EOF 标记=%s"
          % (len(frag), lo, hi, gaps or "无", eof))
    print("    非隧道噪声域名: %s" % sorted(noise))
    print("    载荷拼接长度=%d，字符集(%d)=%s"
          % (len(blob), len(set(blob)), "".join(sorted(set(blob)))))
    blob_path = os.path.join(a.outdir, "dns_payload.base32.txt")
    open(blob_path, "w").write(blob)

    # [2] 标准 Base32
    stage1 = b32_decode(blob)
    print("[2] 标准 Base32 解码 → %d 字符，全可打印=%s" % (len(stage1), stage1.isprintable()))

    # [3][4] 判定 58 字符集 + 自定义 Base58 表
    raw, table, tname, charset = crack_inner(stage1)
    print("[3] stage2 字符集恰 %d 个 → Base58 族；缺失字符 = %s"
          % (len(charset), "".join(sorted(set(STD_B58) - set(charset)))))
    print("[4] 命中自定义表（%s）: %s" % (tname, table))
    zip_path = os.path.join(a.outdir, "secret.zip")
    open(zip_path, "wb").write(raw)
    print("    解出 %d 字节，magic=%r → %s" % (len(raw), raw[:4], zip_path))

    zf = zipfile.ZipFile(io.BytesIO(raw))
    for i in zf.infolist():
        print("    entry name=%s method=%d(stored) flag_bits=0x%04x comp=%d uncomp=%d crc=%08x"
              % (i.filename, i.compress_type, i.flag_bits, i.compress_size, i.file_size, i.CRC))

    if a.no_kpa:
        print("\n[5] 跳过已知明文攻击（--no-kpa）")
        return 0

    # [5] ZipCrypto 已知明文
    entry = zf.infolist()[0].filename
    bkcrack = find_bkcrack(a.bkcrack)
    if not bkcrack:
        print("\n[!] 未找到 bkcrack。本机已知位置："
              r"D:\2026\湾区杯\决赛\v2\tools\bin\bkcrack.exe")
        print("    恢复密钥需要的命令（PNG 头 16 字节为已知明文，偏移 0 = 跳过 12 字节加密头）：")
        print("      bkcrack -C secret.zip -c %s -x 0 %s" % (entry, PNG_HEAD16))
        print("      bkcrack -C secret.zip -c %s -k <X> <Y> <Z> -d %s_dec.png" % (entry, os.path.splitext(entry)[0]))
        return 3

    keys, dec = run_kpa(bkcrack, zip_path, entry, a.outdir)
    data = open(dec, "rb").read()
    print("[5] 解密产物 %s（%d 字节，magic=%s）" % (dec, len(data), data[:8].hex()))
    if re.search(rb"flag\{", data):
        print("\nFLAG-IN-BYTES: %s" % re.search(rb"flag\{[^}]*\}", data).group(0).decode())
    else:
        print("\n[*] 明文中没有 flag{...} 字面量 —— flag 在图像内容里（需查看图片，见 README §8）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
round2_1330/crypto01  --  qid: Adbvf8bTTCGF4LLU  --  500 分

考点: CyberChef「另存为 HTML(Save as HTML)」离线页面把**整个 recipe 序列化进了 DOM**:
      算子链(AES Encrypt) / 明文 Key / 明文 IV / Mode(CBC) / Input(Raw) / Output(Hex)
      以及**输出面板里的密文**与状态栏 stats(Input length=42, Output length=96)。
      → 不需要浏览器、不需要爆破: 正则解析 HTML 即拿到全部解密参数, 直接 AES-128-CBC 解密。

附件: ad75cfca79427cd8476db391aa0b5545.zip (267,307 B) 内唯一文件 cc.html (699,830 B)
      <title>AES Encrypt - CyberChef</title>

用法:
    python solve.py                                   # 用默认附件路径(相对本目录)
    python solve.py --zip  <附件.zip>                  # 指定原始附件
    python solve.py --html <cc.html>                  # 直接用已解压的 HTML
    python solve.py --out  FLAG.txt                   # 顺带落盘 flag
"""
from __future__ import annotations

import argparse
import html as htmllib
import io
import os
import re
import sys
import tempfile
import zipfile

try:
    from Crypto.Cipher import AES  # pycryptodome
except ImportError:  # pragma: no cover
    sys.exit("需要 pycryptodome:  pip install pycryptodome")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ZIP = os.path.normpath(
    os.path.join(HERE, "..", "attachments", "ad75cfca79427cd8476db391aa0b5545.zip")
)
DEFAULT_HTML = os.path.normpath(os.path.join(HERE, "..", "attachments", "cc.html"))


# ---------------------------------------------------------------- ① 取 HTML
def load_html(zip_path: str | None = None, html_path: str | None = None):
    """返回 (html_text, 来源描述)。zip 优先于裸 html。"""
    if zip_path and os.path.isfile(zip_path):
        with zipfile.ZipFile(zip_path) as z:
            names = z.namelist()
            print("[*] zip 内文件: %s" % names)
            tmp = tempfile.mkdtemp(prefix="r2crypto01_")
            z.extractall(tmp)
        pages = [n for n in names if n.lower().endswith((".html", ".htm"))]
        if not pages:
            sys.exit("[!] zip 内没有 .html")
        page = pages[0]
        src = os.path.join(tmp, page)
        return io.open(src, encoding="utf-8", errors="replace").read(), src
    if html_path and os.path.isfile(html_path):
        return io.open(html_path, encoding="utf-8", errors="replace").read(), html_path
    sys.exit("[!] 找不到附件: %s / %s" % (zip_path, html_path))


# --------------------------------------------- ② 解析 CyberChef 序列化 recipe
def parse_arg(doc: str, arg_name: str) -> str | None:
    """抓 <input ... arg-name=Key value=xxx>（引号可有可无）"""
    pat = (r'arg-name=(?:"%s"|%s)(?:\s[^>]*?)?\bvalue=(?:"([^"]*)"|([^\s>]+))'
           % (re.escape(arg_name), re.escape(arg_name)))
    m = re.search(pat, doc)
    if not m:
        return None
    return htmllib.unescape(m.group(1) if m.group(1) is not None else m.group(2))


def parse_select(doc: str, arg_name: str) -> str | None:
    """抓 <select ... arg-name=Mode><option selected ...>CBC</option> —— 只取 selected 的那项"""
    m = re.search(r'arg-name=(?:"%s"|%s)[^>]*>(.*?)</select>'
                  % (re.escape(arg_name), re.escape(arg_name)), doc, re.S)
    if not m:
        return None
    body = m.group(1)
    m2 = re.search(r'<option\s+selected[^>]*>\s*([A-Za-z0-9_]+)', body)
    if m2:
        return m2.group(1)
    m3 = re.search(r'<option>\s*([A-Za-z0-9_]+)', body)
    return m3.group(1) if m3 else None


def parse_output_hex(doc: str) -> str:
    """输出面板是 CodeMirror: 只读 cm-content 里的那串 hex 就是密文"""
    cands = re.findall(
        r'class="cm-content[^"]*"[^>]*>\s*<div class=[^>]*>([0-9a-fA-F]{16,})', doc)
    if not cands:
        cands = re.findall(r'\b[0-9a-fA-F]{32,}\b', doc)
    if not cands:
        sys.exit("[!] 未在 HTML 中找到 hex 密文")
    return max(cands, key=len).strip()


def parse_stats(doc: str) -> list[int]:
    return [int(x) for x in re.findall(r'class=stats-length-value>(\d+)<', doc)]


def parse_title(doc: str) -> str:
    m = re.search(r'<title>(.*?)</title>', doc, re.S)
    return m.group(1).strip() if m else "?"


# ------------------------------------------------------------------ ③ 主流程
def main() -> str:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", default=DEFAULT_ZIP)
    ap.add_argument("--html", default=None)
    ap.add_argument("--out")
    a = ap.parse_args()

    doc, src = load_html(a.zip, a.html or (DEFAULT_HTML if not a.zip else None))
    print("[*] HTML: %s  (%d chars, title=%s)" % (src, len(doc), parse_title(doc)))

    op = "AES Encrypt" if "AES Encrypt" in doc else ("AES Decrypt" if "AES Decrypt" in doc else "?")
    key_s = parse_arg(doc, "Key")
    iv_s = parse_arg(doc, "IV")
    mode = parse_select(doc, "Mode")
    in_enc = parse_select(doc, "Input")
    out_enc = parse_select(doc, "Output")
    ct_hex = parse_output_hex(doc)
    ct = bytes.fromhex(ct_hex)
    stats = parse_stats(doc)

    print("[*] recipe: %s | Mode=%s | Input=%s | Output=%s" % (op, mode, in_enc, out_enc))
    print("[*] recipe 里的明文密钥材料: Key=%r  IV=%r" % (key_s, iv_s))
    print("[*] 密文 (%d B): %s" % (len(ct), ct_hex))
    if stats:
        print("[*] 页面 stats: length=%s -> 明文应为 %s B (含 PKCS#7 padding)"
              % (stats, stats[-1] // 2))

    assert key_s and iv_s, "Key/IV 解析失败"
    assert mode and mode.upper() == "CBC", "Mode 不是 CBC: %r" % mode
    key, iv = key_s.encode(), iv_s.encode()
    assert len(key) in (16, 24, 32), "Key 长度异常: %d" % len(key)
    assert len(iv) == 16, "IV 长度异常: %d" % len(iv)

    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)     # IV 已知 -> 无需 padding oracle
    pad = pt[-1]
    ok = 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad
    body = pt[:-pad] if ok else pt
    print("[*] Padding 自校验: %s (末字节 0x%02x)" % ("OK" if ok else "FAIL", pad))
    print("[*] 明文: %r" % body)

    text = body.decode("utf-8", "replace")
    m = re.search(r'flag\{[^}]*\}', text)
    flag = m.group(0) if m else text.strip()
    print("[+] FLAG = %s" % flag)

    if a.out:
        with io.open(a.out, "w", encoding="utf-8") as f:
            f.write(flag)
        print("[+] 已写入 %s" % a.out)
    return flag


if __name__ == "__main__":
    main()

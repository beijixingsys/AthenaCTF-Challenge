#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
round2_1330 / misc02  —  明文 HTTP Web 后门（shell.php）流量取证
qid = LT50RTMIQsSmWJAu   score = 500

考点：
  1. 从混杂流量中分辨有效会话：本 pcap 里有 SMB/EPM(135/139/445)、LLMNR/NBNS(UDP)、TLS(443)
     等噪声，真正的攻击链只有 192.168.11.129 -> 192.168.11.128:80 这 24 个包。
  2. TCP 流重组 + 请求/响应配对（同一 TCP 流内按顺序配对；抓包里服务端响应有重复帧，
     必须按 (src,sport,dst,dport,seq) 去重，否则会把 4 条命令数成 10 次交互）。
  3. 菜刀式 WebShell 参数：`shell.php?1337=system('<cmd>');`
  4. 响应体可能是 gzip（`Content-Encoding: gzip`），必须先解压再判定。
  5. 最后一条响应体是被 Base64 编码外带的 flag（`cat /flag |base64 -w 0`）。

用法：
    python solve.py --pcap attachments/shell.pcapng
    python solve.py --attach attachments/97c3cb84b53f44e4c5d78ed4789bd07c.zip   # 自动解包找 pcap
"""
from __future__ import annotations

import argparse
import base64
import gzip
import os
import re
import sys
import tempfile
import zipfile

try:
    from scapy.all import IP, Raw, TCP, rdpcap
except ImportError:  # pragma: no cover
    sys.stderr.write("[!] 需要 scapy：pip install -r requirements.txt\n")
    raise

sys.stdout.reconfigure(encoding="utf-8")

REQ_LINE = re.compile(rb"^(?:GET|POST)\s+(\S+)\s+HTTP/", re.M)
HDR_END = b"\r\n\r\n"
RE_FLAG = re.compile(rb"flag\{[^}\r\n]{1,200}\}")


def dedupe_payloads(pkts):
    """按 (src,sport,dst,dport,seq,len) 去重，返回 [(src, sport, dst, dport, seq, payload)]。"""
    seen, out = set(), []
    for p in pkts:
        if IP not in p or TCP not in p or Raw not in p:
            continue
        key = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport, p[TCP].seq, len(p[Raw].load))
        if key in seen:
            continue
        seen.add(key)
        out.append((p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport, p[TCP].seq, bytes(p[Raw].load)))
    return out


def norm_stream_key(src, sport, dst, dport):
    return tuple(sorted([(src, sport), (dst, dport)]))


def parse_http(payload):
    """返回 (请求行 或 None, 完整 URL 或 None, 解压后的响应体 或 None)。"""
    if payload.startswith((b"GET ", b"POST ")):
        m = REQ_LINE.match(payload)
        req = payload.split(b"\r\n", 1)[0].decode("utf-8", "replace")
        url = m.group(1).decode("utf-8", "replace") if m else None
        return req, url, None
    if payload.startswith(b"HTTP/"):
        head, _, body = payload.partition(HDR_END)
        if re.search(rb"Content-Encoding:\s*gzip", head, re.I):
            try:
                body = gzip.decompress(body)
            except Exception:
                pass
        return None, None, body
    return None, None, None


def reassemble(pkts):
    """按 TCP 流配对请求与响应 —— 返回 [(request_line, url, body)]。

    注意：必须用**抓包顺序**而不是 seq 排序 —— 客户端与服务端的 seq 是两个独立的
    序号空间，混在一起排序会打乱请求/响应的先后关系。
    """
    streams = {}
    for src, sport, dst, dport, seq, payload in dedupe_payloads(pkts):
        streams.setdefault(norm_stream_key(src, sport, dst, dport), []).append(payload)

    pairs = []
    for _key, payloads in streams.items():
        current = None
        for payload in payloads:
            req, url, body = parse_http(payload)
            if req is not None:                      # 客户端请求
                current = (req, url)
                continue
            if body is not None and current is not None:   # 服务端响应
                pairs.append((current[0], current[1], body))
                current = None
    return pairs


def extract_flag(pairs):
    """先找明文 flag；再对响应体做 Base64 解码后找 flag。"""
    for req, url, body in pairs:
        m = RE_FLAG.search(body)
        if m:
            return m.group(0).decode(), req, "plain"

    for req, url, body in pairs:
        raw = body.strip()
        # 多补 padding，容忍 `-w 0` 或换行残缺
        for pad in ("", "=", "==", "==="):
            try:
                dec = base64.b64decode(raw + pad.encode(), validate=False)
            except Exception:
                continue
            m = RE_FLAG.search(dec)
            if m:
                return m.group(0).decode(), req, "base64"
    return None, None, None


def find_pcap(path: str) -> str:
    if os.path.isdir(path):
        for dirpath, _d, files in os.walk(path):
            for f in files:
                if f.lower().endswith((".pcap", ".pcapng", ".cap")):
                    return os.path.join(dirpath, f)
        raise SystemExit("[!] no pcap inside %s" % path)
    if path.lower().endswith(".zip"):
        tmp = tempfile.mkdtemp(prefix="misc02_")
        with zipfile.ZipFile(path) as zf:
            zf.extractall(tmp)
        return find_pcap(tmp)
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description="round2 misc02 solver (webshell HTTP forensics)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--pcap", help="pcap/pcapng 路径")
    g.add_argument("--attach", help="原始附件（zip 或目录），自动定位其中的 pcap")
    a = ap.parse_args()

    target = find_pcap(a.pcap or a.attach)
    pkts = rdpcap(target)
    print("[*] pcap = %s" % target)
    print("[*] packets = %d  (unique TCP payload segs = %d)"
          % (len(pkts), len(dedupe_payloads(pkts))))

    pairs = reassemble(pkts)
    print("[*] HTTP request/response pairs = %d" % len(pairs))
    for req, url, body in pairs:
        show = body[:70].replace(b"\n", b"\\n")
        print("    %-70s -> %r" % (req, show))

    flag, req, how = extract_flag(pairs)
    if not flag:
        print("\nNOT_FOUND")
        return 2
    print("\n[%s] flag from: %s" % (how, req))
    print("FLAG: %s" % flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())

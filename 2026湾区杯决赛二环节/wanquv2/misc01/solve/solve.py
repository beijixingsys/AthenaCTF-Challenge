#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
round2_1330 / misc01  —  被入侵服务器日志取证（SSH 爆破 / 后门服务 / DNS 外带）
qid = SNdmyaqEfKnrv3mD   score = 500

三源关联（tri-source correlation）取证：
  [1] var/log/auth.log   —— 只取唯一的 `Accepted password` 行，定位攻击者 用户名 + 源 IP
                            （`Failed password` × 97 / `Invalid user` × 103 / `Accepted publickey` × 15
                             全是噪声；15 条 publickey 是伪造的“成功登录”诱饵）
  [2] etc/systemd/system/*.service —— 找 ExecStart 中含 `nc -l` + `-e` 的监听型后门
                            （suspicious.service / normal.service 是显式无害的诱饵）
  [3] var/log/dnsmasq.log —— 子域最左标签是 Base64，解码得 /etc/shadow 片段；
                            固定域名即外带通道域名
  flag = flag{<ssh_user>_<src_ip>_<service 文件名去掉 .service>_<固定域名>}

用法：
    python solve.py --attach attachments/e4dccc50e240c6b0c34cf94db7d4e4b3.zip
    python solve.py --dir attachments/extracted          # 已解包目录（含 etc/ var/）
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import sys
import tempfile
import zipfile

sys.stdout.reconfigure(encoding="utf-8")

# --- 正则 -------------------------------------------------------------------
# auth.log 中真正“被爆破成功”的登录：password 认证（publickey 那批是诱饵）
RE_ACCEPTED_PW = re.compile(
    r"Accepted\s+password\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)")
# 后门 unit：监听端口并把 shell 交出去
RE_BACKDOOR_EXEC = re.compile(r"ExecStart\s*=\s*.*?(?:nc|ncat|socat)\b.*?-e\b", re.I)
# dnsmasq 查询行：最左标签（Base64）+ 固定域名 + 源 IP
RE_DNS_QUERY = re.compile(
    r"query\[(?P<qtype>[A-Za-z]+)\]\s+(?P<label>[A-Za-z0-9+/=_-]+)\.(?P<domain>[A-Za-z0-9.\-]+)\s+from\s+(?P<src>\S+)")
# 解出来的明文应像 /etc/shadow（校验，避免把普通域名当载荷）
RE_SHADOW = re.compile(r"(?::\d+:\d+:\d+:|:\$6?\$|^root:|^daemon:|^[a-z_][a-z0-9_-]*:\*)", re.M)


def unpack(path: str) -> str:
    """zip → 临时目录；目录 → 原样返回。返回包含 etc/ 与 var/ 的根。"""
    if os.path.isdir(path):
        return path
    tmp = tempfile.mkdtemp(prefix="misc01_")
    with zipfile.ZipFile(path) as zf:
        zf.extractall(tmp)
    return tmp


def find(root: str, rel: str) -> str | None:
    p = os.path.join(root, rel)
    if os.path.isfile(p):
        return p
    base = os.path.basename(rel)
    for dirpath, _dirs, files in os.walk(root):
        if base in files:
            return os.path.join(dirpath, base)
    return None


def read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def step1_ssh(root: str):
    """返回 (user, ip, 命中的原文行)。"""
    auth = find(root, "var/log/auth.log")
    if not auth:
        raise SystemExit("[!] var/log/auth.log not found")
    text = read(auth)
    hits = [(m, line) for line in text.splitlines()
            for m in [RE_ACCEPTED_PW.search(line)] if m]
    if not hits:
        raise SystemExit("[!] no 'Accepted password' line")
    # 期望唯一；多条时取随后出现 sudo curl|bash 的那条（跨源印证）
    for m, line in hits:
        if re.search(r"sudo:\s+%s\s+.*(curl|wget|bash)" % re.escape(m.group("user")), text):
            return m.group("user"), m.group("ip"), line
    m, line = hits[0]
    return m.group("user"), m.group("ip"), line


def step2_service(root: str):
    """返回 (service_name_without_suffix, scores) —— 打分只用于打印取证过程。"""
    units = []
    for dirpath, _d, files in os.walk(root):
        for f in files:
            if f.endswith(".service"):
                units.append(os.path.join(dirpath, f))
    if not units:
        raise SystemExit("[!] no *.service found")
    scores, backdoors = {}, []
    for path in sorted(units):
        body = read(path)
        name = os.path.basename(path)[: -len(".service")]
        score = 0
        for bad in ("nc -l", "ncat ", "-e /bin/sh", "-e /bin/bash", "bash -i", "31337", "backdoor"):
            if bad.lower() in body.lower():
                score += 1
        if "harmless" in body.lower() or "sleep infinity" in body:
            score -= 5
        scores[name] = score
        if RE_BACKDOOR_EXEC.search(body):
            backdoors.append(name)
    if not backdoors:
        backdoors = [max(scores, key=scores.get)]
    return backdoors[0], scores


def step3_dns(root: str):
    """返回 (固定域名, 源 IP, [(时间戳, label, 明文)]) —— 按时间排序拼接后即外带内容。"""
    dns = find(root, "var/log/dnsmasq.log")
    if not dns:
        raise SystemExit("[!] var/log/dnsmasq.log not found")
    text = read(dns)
    chunks, domain_cnt, src_cnt = [], {}, {}
    for line in text.splitlines():
        m = RE_DNS_QUERY.search(line)
        if not m:
            continue
        label, domain, src = m.group("label"), m.group("domain"), m.group("src")
        # 只接受“标签可 Base64 解码且明文像 /etc/shadow”的行 → 自动剔除域名噪声
        try:
            plain = base64.b64decode(label + "=" * (-len(label) % 4)).decode("utf-8", "replace")
        except Exception:
            continue
        if not RE_SHADOW.search(plain):
            continue
        chunks.append((" ".join(line.split()[0:3]), label, plain))   # "Jun 15 02:40:15"
        domain_cnt[domain] = domain_cnt.get(domain, 0) + 1
        src_cnt[src] = src_cnt.get(src, 0) + 1
    if not chunks:
        raise SystemExit("[!] no Base64 DNS exfil chunk found")
    domain = max(domain_cnt, key=domain_cnt.get)
    src = max(src_cnt, key=src_cnt.get)
    chunks.sort()
    return domain, src, chunks


def solve(path: str) -> str:
    root = unpack(path)
    user, ip, ssh_line = step1_ssh(root)
    svc, scores = step2_service(root)
    domain, dns_src, chunks = step3_dns(root)

    print("[1] SSH    : user=%s  ip=%s" % (user, ip))
    print("            raw = %s" % ssh_line.strip())
    print("            唯一成功口令登录（其余 Failed password/publickey/Invalid user 均为噪声）")
    print("[2] UNIT   : %s   (scores=%s)" % (svc, scores))
    print("[3] DNS    : fixed-domain=%s  source=%s  chunks=%d" % (domain, dns_src, len(chunks)))
    print("            重组后的外带内容（/etc/shadow 片段）：")
    for ts, label, plain in chunks:
        print("              %s  %s  -> %r" % (ts, label, plain))
    print("            完整明文: %r" % "".join(p for _t, _l, p in chunks))

    flag = "flag{%s_%s_%s_%s}" % (user, ip, svc, domain)
    print("\nFLAG: %s" % flag)
    return flag


def main() -> int:
    ap = argparse.ArgumentParser(description="round2 misc01 solver (SSH/DNS/systemd tri-source forensics)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--attach", help="原始附件 zip 路径")
    g.add_argument("--dir", help="已解包的目录（含 etc/ 与 var/）")
    ap.add_argument("--flag-out", default=None, help="把 flag 写到该文件（默认不写）")
    a = ap.parse_args()
    flag = solve(a.attach or a.dir)
    if a.flag_out:
        with open(a.flag_out, "w", encoding="utf-8") as fh:
            fh.write(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())

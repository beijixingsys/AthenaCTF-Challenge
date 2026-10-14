#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
round3_1700 / misc01  —  日志取证 + 策略合规判定（"泄露的足迹"）
qid = BNsjLglYldSQp4vf   score = 500

输入（附件）：
    access.log         Web 访问日志 7920 行
    customer_data.csv  一级敏感数据样本
    policy.md          公司数据安全政策（角色权限 / 违规判定标准）
    README.md          调查任务书 + flag 计算规则

方法：
  [1] 解析 14 字段自定义日志：
      ip - user [dd/Mon/yyyy:HH:MM:SS ] "METHOD URL PROTO" status size "referer" "ua" "sessionid"
      （注意 `MM:SS ]` 里 `]` 前有一个空格）
  [2] 从 7920 行里筛出"证据级"记录：访问一级敏感数据 customer_data.csv
      ＋ referer 为内部系统 https://internal.system/dashboard ＋ 真浏览器 UA ＋ 响应体 15680 字节。
      其余 700+ 条 customer_data.csv 记录都是随机 UA / 随机 referer / 随机 size 的噪声。
  [3] 按 policy.md 判定：财务角色 user_f1 单日下载 customer_data.csv 不得超过 3 次。
      证据级记录集中在同一天 2025-09-27，共 4 条 → 第 4 条越权。
  [4] 交叉印证：越权那条的来源 IP 10.0.0.55 **不在** policy 规定的内网 192.168.1.x 段。
  [5] 按 README.md 规则拼接 `user-YYYY-MM-DD-HH:MM:SS-sessionid` 取 MD5 → flag。

用法：
    python solve.py --log attachments/access.log --policy attachments/policy.md
    python solve.py --dir attachments            # 自动定位四个文件
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")

LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+'
    r'\[(?P<dd>\d{2})/(?P<mon>\w{3})/(?P<yyyy>\d{4}):(?P<time>\d{2}:\d{2}:\d{2})\s*\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>\S+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"\s+"(?P<sid>[^"]*)"\s*$')

MON = dict(Jan=1, Feb=2, Mar=3, Apr=4, May=5, Jun=6, Jul=7, Aug=8, Sep=9,
           Oct=10, Nov=11, Dec=12)

# 真浏览器基线（本题内部系统真实使用者统一带这个 UA）
REAL_UA_MARK = "Chrome/117"
INTERNAL_SYSTEM = "internal.system"
# 敏感文件在政策里叫"一级敏感数据"，这里从 policy.md 动态解析更稳
DEFAULT_SENSITIVE = "customer_data.csv"


def parse_log(path: str):
    recs, bad = [], []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            m = LOG_RE.match(line.rstrip("\n"))
            if not m:
                bad.append((i, line.rstrip()))
                continue
            g = m.groupdict()
            recs.append(dict(
                lineno=i, ip=g["ip"], user=g["user"],
                ts="%s-%02d-%s-%s" % (g["yyyy"], MON[g["mon"]], g["dd"], g["time"]),
                day="%s-%02d-%s" % (g["yyyy"], MON[g["mon"]], g["dd"]),
                method=g["method"], path=g["path"], status=g["status"],
                size=int(g["size"]), referer=g["referer"], ua=g["ua"], sid=g["sid"]))
    return recs, bad


def parse_policy(path: str):
    """从 policy.md 提取：内网段、(role->user, 限制次数) 等关键约束。"""
    text = open(path, encoding="utf-8", errors="replace").read() if path and os.path.isfile(path) else ""
    internal = re.search(r"(\d+\.\d+\.\d+)\.x\s*段", text)
    maxday = re.search(r"不得超过\s*(\d+)\s*次", text)
    sensitive = re.search(r"一级敏感数据[^（(]*[（(]([^）)]+\.csv)", text)
    return dict(
        internal_prefix=(internal.group(1) + ".") if internal else "192.168.1.",
        max_per_day=int(maxday.group(1)) if maxday else 3,
        sensitive=sensitive.group(1) if sensitive else DEFAULT_SENSITIVE,
        text=text)


def evidence_records(recs, sensitive):
    """证据级记录 = 一级敏感数据 + 内部系统 referer + 真浏览器 UA。

    （size 不写死，只打印出来核对；本题 4 条恰好都是 15680 字节）
    """
    return [r for r in recs
            if sensitive in r["path"]
            and INTERNAL_SYSTEM in r["referer"]
            and REAL_UA_MARK in r["ua"]]


def solve(log_path, policy_path):
    pol = parse_policy(policy_path)
    recs, bad = parse_log(log_path)
    print("[*] access.log: %d 行，解析成功 %d，失败 %d" % (len(recs) + len(bad), len(recs), len(bad)))
    print("[*] policy.md : 内网段=%s*  单日上限=%d 次  一级敏感数据=%s"
          % (pol["internal_prefix"], pol["max_per_day"], pol["sensitive"]))

    touched = [r for r in recs if pol["sensitive"] in r["path"]]
    ev = evidence_records(recs, pol["sensitive"])
    print("[*] 触及 %s 的记录共 %d 条；其中证据级（内部系统 referer + 真浏览器 UA）%d 条"
          % (pol["sensitive"], len(touched), len(ev)))
    if not ev:
        raise SystemExit("[!] 未找到证据级记录：请检查 policy.md 的敏感数据文件名 / UA 基线")

    sizes = collections.Counter(r["size"] for r in ev)
    print("[*] 证据级记录响应体大小分布: %s" % dict(sizes))
    for r in sorted(ev, key=lambda x: x["ts"]):
        print("    L%-5d %s  sid=%-8s ip=%-12s size=%d" % (r["lineno"], r["ts"], r["sid"], r["ip"], r["size"]))

    # --- 策略合规判定：按 (user, day) 计数，超过上限的即为越权 ---
    per_day = collections.defaultdict(list)
    for r in sorted(ev, key=lambda x: x["ts"]):
        per_day[(r["user"], r["day"])].append(r)

    violation = None
    for (user, day), rows in sorted(per_day.items()):
        print("[*] %s @ %s : %d 次（上限 %d）" % (user, day, len(rows), pol["max_per_day"]))
        if len(rows) > pol["max_per_day"]:
            # 前 max_per_day 次在配额内，之后的是违规
            for r in rows[pol["max_per_day"]:]:
                off = not r["ip"].startswith(pol["internal_prefix"])
                print("    ⚠ 越权: %s  sid=%s  ip=%s  off-subnet=%s" % (r["ts"], r["sid"], r["ip"], off))
                if violation is None or off:
                    violation = r
    if violation is None:
        raise SystemExit("[!] 未发现越权记录（可能 policy/日志不匹配）")

    # 会话 ID 前缀自证（本题 LEG=合法基线 / VIO=violation）
    print("[*] 越权会话 ID 前缀自证: %s（同批次合法会话前缀: %s）"
          % (violation["sid"][:3],
             sorted({r["sid"][:3] for r in ev if r is not violation})))

    # --- 按 README 规则算 MD5 ---
    s = "%s-%s-%s" % (violation["user"], violation["ts"], violation["sid"])
    digest = hashlib.md5(s.encode()).hexdigest()
    print("\n[*] 拼接串 : %s" % s)
    print("[*] MD5    : %s" % digest)
    flag = "flag{%s}" % digest
    print("\nFLAG: %s" % flag)
    return flag


def locate(dirpath, name):
    for dirpath_, _d, files in os.walk(dirpath):
        if name in files:
            return os.path.join(dirpath_, name)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="round3 misc01 solver (log forensics + policy compliance)")
    ap.add_argument("--log", help="access.log 路径")
    ap.add_argument("--policy", help="policy.md 路径")
    ap.add_argument("--dir", help="附件目录（自动定位 access.log / policy.md）")
    ap.add_argument("--flag-out", default=None)
    a = ap.parse_args()

    log = a.log or (locate(a.dir, "access.log") if a.dir else None)
    policy = a.policy or (locate(a.dir, "policy.md") if a.dir else None)
    if not log:
        ap.error("需要 --log 或 --dir")
    flag = solve(log, policy)
    if a.flag_out:
        open(a.flag_out, "w", encoding="utf-8").write(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())

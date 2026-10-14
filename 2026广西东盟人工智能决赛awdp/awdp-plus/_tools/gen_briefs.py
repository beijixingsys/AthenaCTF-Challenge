#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate the consolidated 题目信息.md from specs."""
import io
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
import specs  # noqa: E402

L = []
L.append("# 本场 AWDP Plus 题目信息（题面汇总）")
L.append("")
L.append("> 8 题源自决赛附件原始业务模块；ez_Render 无附件，按 WRITEUP 考点等价重建。")
L.append("> 题面中 shift_handoff_inspector / last_mile_dispatch_board / release_control_tower 为比赛平台原文，")
L.append("> 其余 6 题按同一文风依据源码与考点补写。")
L.append("")
L.append("| # | 题目 (slug) | 平台显示名 | 端口 | 分值 | 参考旗标 |")
L.append("| --- | --- | --- | --- | --- | --- |")
for i, s in enumerate(specs.SPECS):
    L.append("| %d | %s | %s | %s | 350 | %s |" % (i + 1, s["name"], s["title"], s["port"], s.get("ref_flag", "")))
L.append("")
L.append("---")
L.append("")
for i, s in enumerate(specs.SPECS):
    L.append("## %d. %s（%s）" % (i + 1, s["name"], s["title"]))
    L.append("")
    L.append("**题目内容（题面）**")
    L.append("")
    L.append(s.get("brief", ""))
    L.append("")
    L.append("**中文提要**：" + s.get("brief_cn", ""))
    L.append("")
    L.append("| 项 | 值 |")
    L.append("| --- | --- |")
    L.append("| 端口 | %s |" % s["port"])
    L.append("| 漏洞类型 | %s |" % s["vuln"].split(chr(10))[0])
    L.append("| Flag 落地 | %s |" % s["flag_field"])
    L.append("| 参考旗标 | %s |" % s.get("ref_flag", ""))
    L.append("| 修补文件 | %s |" % s["patch_files"])
    L.append("| 修补包 | %s/dist/%s_patch.tar.gz |" % (s["name"], s["name"]))
    L.append("")
    L.append("利用链：" + s["chain"])
    L.append("")
    L.append("---")
    L.append("")

with io.open(os.path.join(ROOT, "题目信息.md"), "w", encoding="utf-8", newline="\n") as handle:
    handle.write("\n".join(L))
print("题目信息.md written, challenges:", len(specs.SPECS))

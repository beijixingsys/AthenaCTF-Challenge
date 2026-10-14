# -*- coding: utf-8 -*-
"""
round3_1700 / crypto02 (qid CrpMu5aVJdYVf9zK) 的 secret.py

⚠️ 来源标注
  本文件**不是**平台下发的原件。原始附件 `attachments/crypto02.zip` 内只有 `task.py`，
  `from secret import flag` 所依赖的 `secret.py` 未随附件下发（flag 由平台运行时注入）。

  本文件的内容为**重建**：
    flag = 比赛期间解出的真实 flag（并由 `solve/solve.py` 逐字节复现，
           平台提交返回 code=0 / message="恭喜您，回答正确"）。

  注意 flag **必须是 bytes**：`task.py` 的 `pad(msg)` 做的是 `msg + bytes(...)`，
  传 `str` 会 `TypeError: can't concat str to bytes`。
"""

flag = b"flag{886769b5-2301-4c37-bb73-4480b4eab682}"

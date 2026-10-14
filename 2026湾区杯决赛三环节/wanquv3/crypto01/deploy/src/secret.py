# -*- coding: utf-8 -*-
"""
round3_1700 / crypto01 (qid aE9BLf9fMqMPag7T) 的 secret.py

⚠️ 来源标注（重要）
  本文件**不是**比赛平台下发的原件，而是**从比赛实例反推得到**的重建件：
  原始附件 `attachments/crypto01.zip` 内只有 `task.py`，`from secret import flag, alpha, beta, g`
  所依赖的 `secret.py` 未随附件下发（flag 在比赛平台运行时才注入）。

  反推方法（见 ../README.md 与 solve/solve.py）：
    1. 用阶攻击求出 p（t = 11192429 处 gcd(A^t - 1, n) 分出）；
    2. 由 p = 2*g*alpha+1 且 alpha < 2^24，遍历 24 bit 的 alpha 找使 (p-1)/(2*alpha)
       为 575 bit 素数的解 → g, alpha；同法由 q 得 beta；
    3. flag 由 RSA 常规解密得到（平台提交 status=1 验证通过）。

  校验（已实测）：用本文件的 g/alpha/beta/flag 重跑 `task.py` 的逻辑，
  得到的 `n` 与 `c` 与原始附件注释里的 n/c **逐位一致** → 本重建件对本次实例等价于原 secret.py。
  用 `python ../verify_instance.py` 可复跑该校验。

  若要**生成新实例**（出题人角色），请用同目录的 `gen_secret.py` 覆盖本文件。
"""

# ⚠️ 必须是 bytes: 原始 task.py 写的是 `m = bytes_to_long(flag)`，flag 为 str 会 TypeError
flag = b"flag{36e3ac06db2f4b6693b6203b5a7b0c47}"

# --- 反推得到的结构参数（原始实例的真实值） ---
g = 110462645952304376492416975572266047977803453469943301327121055895546510153496334347645947622452990042724210729807062181698185348120422533212285959796650722891254313826359137  # 575 bit 素数
alpha = 11192429   # 24 bit，且恰好等于阶攻击命中的 t = ord_p(A)
beta = 13346783    # 24 bit

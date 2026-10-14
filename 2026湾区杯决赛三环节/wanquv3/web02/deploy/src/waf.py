#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
waf.py — 「AI WAF」中间件（忠实还原比赛期间实测到的行为）

比赛期间对线上 WAF 的实测结论（probe1~probe9 + r3_web02_dump.py）：

* 命中拦截 → HTTP **403** + body `{"redirect_url":"/alert?confidence=0.98","status":"injection"}`
  （confidence 是 0.63~1.00 的“语义评分”）
* 被拦关键字：`or` `and` `union` `select` `from dual` `database()` `@@version` `limit` `ascii`
* **放行**：`'`（→ 后端 500 语法错，证明 WAF 之外没有别的转义）、`||`、`xor`、`/**/`
* ★ 核心行为：`/*!50000select*/` 能穿透 —— WAF 会**先把 MySQL 版本注释连同内容一起剥掉，
  再在剩下的文本里做关键字匹配**，所以注释里的 `select` 在它眼里根本不存在。
* ★ 但普通拆词 `sel/**/ect` **不被还原**（去掉空格后是 `sel/**/ect`，不含 `select`）→ 放行 →
  到 MySQL 那里就是语法错 500。这一点正是「考点必须存在」的关键，不能实现错。
* 频率限制：短时间连发会返回 **429** + `{"message":"操作过于频繁，请稍后再试","status":"error"}`
"""
from __future__ import annotations

import json
import re
import threading
import time

from flask import Response, request

# ---------------------------------------------------------------------------
# 黑名单（实测口径）
# ---------------------------------------------------------------------------
BLOCK_WORDS = [
    'or', 'and', 'union', 'select', 'from dual', 'database()',
    '@@version', 'limit', 'ascii',
]

# 版本注释 /*!50000 ... */ ；MySQL 会把里面的内容当 SQL 执行
_VERSION_COMMENT = re.compile(r'/\*!\d{0,6}.*?\*/', re.S)
# 任意块注释，用于「压掉空白」后再做关键字匹配
_ANY_COMMENT = re.compile(r'/\*.*?\*/', re.S)
_WS = re.compile(r'\s+')


class WafResult(object):
    __slots__ = ('blocked', 'confidence', 'reason')

    def __init__(self, blocked: bool, confidence: float = 0.0, reason: str = ''):
        self.blocked = blocked
        self.confidence = confidence
        self.reason = reason


def _score(query: str, reason: str) -> float:
    """粗略的“语义评分”：命中关键字越多、越长，分越高（对齐实测的 0.63~1.00）。"""
    base = 0.62
    w = 0.012 * len(reason)
    return round(min(1.00, base + w), 2)


def inspect(query: str) -> WafResult:
    """对注入点参数做检查。返回是否拦截。

    匹配口径（对齐比赛期间实测）：
      * 先剥掉 **版本注释** `/*!NNNNN ... */`（连同内容），再做关键字匹配
        —— 这一步就是 `/*!50000select*/` 能穿透的原因；
      * 关键字用**词边界**匹配（在"已剥版本注释、但**保留空白**"的文本上做），
        所以 `or 1=1` / `and(1=1)` / `union select` 都会命中，而
        `information_schema` / `from` / `schemata` 里的 `or` 不会误命中；
      * **普通块注释 `/**/` 不被剥掉**，因此 `sel/**/ect` 既不含独立的 `select`
        也不含 `union` → **放行** → 到 MySQL 那里就是语法错 500。这个「不对称」
        正是考点，不能实现错。
    """
    if not isinstance(query, str) or not query:
        return WafResult(False)

    # ① 先剥掉版本注释（连同内容）
    visible = _VERSION_COMMENT.sub('', query)
    # ② 压掉所有空白后的视图（用于 `from dual` / `database()` 这类带空格的规则）
    flat = _WS.sub('', visible)
    low = visible.lower()
    low_flat = flat.lower()

    # `or` / `and` / `union` 会误命中 `information` / `schemata` 等词，必须用词边界
    _WORD_RULES = ('or', 'and', 'union', 'select', 'limit', 'ascii')

    for word in BLOCK_WORDS:
        if word in _WORD_RULES:
            hit = re.search(r'(?<![a-z0-9_])' + re.escape(word) + r'(?![a-z0-9_])',
                            low) is not None
        else:                                    # from dual / database() / @@version
            hit = word.replace(' ', '') in low_flat
        if hit:
            return WafResult(True, _score(query, word), word)

    return WafResult(False)


# ---------------------------------------------------------------------------
# 频率限制（实测：连发 → 429 操作过于频繁，请稍后再试）
# ---------------------------------------------------------------------------
class RateLimiter(object):
    """每分钟最多 `limit` 次；超出即 429。默认宽松（600/min），
    需要复现比赛期间的「高频即 429」现象时把 --rate-limit 调小（如 8）。"""

    def __init__(self, limit: int = 600, window: float = 60.0):
        self.limit = limit
        self.window = window
        self._hits = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        """True = 放行，False = 限速。"""
        now = time.time()
        with self._lock:
            q = self._hits.setdefault(key, [])
            q[:] = [t for t in q if now - t < self.window]
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


import os as _os

limiter = RateLimiter(limit=int(_os.environ.get('WAF_RATE_LIMIT', '600')))


def waf_response(res: WafResult) -> Response:
    body = json.dumps(
        {"redirect_url": "/alert?confidence=%.2f" % res.confidence,
         "status": "injection"},
        ensure_ascii=False, separators=(',', ':'))
    r = Response(body, status=403, mimetype='application/json')
    r.headers['X-WAF-Confidence'] = '%.2f' % res.confidence
    r.headers['X-WAF-Rule'] = res.reason
    return r


def ratelimit_response() -> Response:
    body = json.dumps({"message": "操作过于频繁，请稍后再试", "status": "error"},
                      ensure_ascii=False, separators=(',', ':'))
    return Response(body, status=429, mimetype='application/json')

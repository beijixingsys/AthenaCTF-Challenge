#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app.py — 「智能数据分析平台」还原版（环节三 web02 / qid yahqei40sgs2n_bk）

考点：POST /search 的 JSON body 字段 `query` 未经参数化就拼进 LIKE 字符串上下文，
      前面有一层「AI WAF」做关键字拦截。

注入点原文（还原自线上行为）：
    SELECT id, title, content FROM article
     WHERE title LIKE '%<query>%' OR content LIKE '%<query>%'
     LIMIT 1;

线上实测的关键响应：
    {"count":N,"firework":0,"keyword":"...","results":[{"id":..,"title":..,"content":..}],"status":"success"}
    被拦 → 403 {"redirect_url":"/alert?confidence=0.98","status":"injection"}
    语法错 → 500 (Flask/werkzeug 的 Internal Server Error 页)
"""
from __future__ import annotations

import os
import sys
import time

import pymysql
from flask import Flask, jsonify, render_template_string, request

import waf

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

DB = dict(
    host=os.environ.get('DB_HOST', 'mysql'),
    port=int(os.environ.get('DB_PORT', '3306')),
    user=os.environ.get('DB_USER', 'idap'),
    password=os.environ.get('DB_PASSWORD', 'idap_pass_2026'),
    database=os.environ.get('DB_NAME', 'idap'),
    charset='utf8mb4',
    autocommit=True,
)


def connect():
    """带重试的连接（等 MySQL 起来）。"""
    last = None
    for _ in range(60):
        try:
            return pymysql.connect(**DB)
        except Exception as e:      # noqa: BLE001
            last = e
            time.sleep(1)
    raise RuntimeError('cannot connect to mysql: %r' % (last,))


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>智能数据分析平台</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
         background:#0b1220; color:#e6edf7; }
  header { padding:22px 40px; background:#111b2e; border-bottom:1px solid #1e2b45; }
  header h1 { margin:0; font-size:20px; letter-spacing:1px; }
  header span { color:#5b8def; font-size:12px; margin-left:10px; }
  .wrap { max-width:900px; margin:50px auto; padding:0 20px; }
  .hero { background:#111b2e; border:1px solid #1e2b45; border-radius:12px; padding:28px; }
  .hero p { color:#9db0cc; line-height:1.8; font-size:14px; }
  .searchbar { display:flex; gap:10px; margin-top:20px; }
  input#queryInput { flex:1; padding:13px 16px; border-radius:8px; border:1px solid #2a3b5c;
                     background:#0b1220; color:#e6edf7; font-size:15px; outline:none; }
  input#queryInput:focus { border-color:#5b8def; }
  button#searchButton { padding:13px 26px; border:0; border-radius:8px; cursor:pointer;
                        background:#5b8def; color:#fff; font-size:15px; font-weight:600; }
  button#searchButton:hover { background:#4a7ade; }
  #resultsList { margin-top:26px; }
  .result-item { background:#111b2e; border:1px solid #1e2b45; border-radius:10px;
                 padding:16px 20px; margin-bottom:14px; }
  .result-item h3 { margin:0 0 8px; font-size:16px; color:#7fb2ff; }
  .result-item p { margin:0; color:#a9bbd6; font-size:13px; line-height:1.75; }
  .no-results { color:#7d8ea8; padding:20px; text-align:center; }
  .stats { color:#6d80a0; font-size:12px; margin-top:14px; }
</style>
</head>
<body>
<header><h1>智能数据分析平台<span>AI WAF PROTECTED</span></h1></header>
<div class="wrap">
  <div class="hero">
    <p>依托自主研发的大数据智能分析与研判引擎，打造坚不可摧的全维度安全防护体系。
       站内检索已接入 AI WAF 语义防护，可精准识别并阻断各类攻击请求。</p>
    <div class="searchbar">
      <input type="text" id="queryInput" placeholder="输入关键词检索平台资讯...">
      <button id="searchButton">搜索</button>
    </div>
    <div class="stats">防护状态：<b style="color:#3ddc84">已启用</b> · 语义评分阈值 0.60</div>
  </div>
  <div id="resultsList"></div>
</div>
<script>
async function doSearch() {
  const keyword = document.getElementById('queryInput').value;
  const list = document.getElementById('resultsList');
  if (!keyword.trim()) { alert('请输入搜索关键词'); return; }
  list.innerHTML = '<p class="no-results">正在检索...</p>';
  try {
    const res = await fetch('/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: keyword })
    });
    if (res.status === 403) {
      const d = await res.json();
      location.href = d.redirect_url || '/alert';
      return;
    }
    const data = await res.json();
    if (data.status !== 'success') {
      list.innerHTML = '<p style="color:#ef4444;">' + (data.message || '检索失败') + '</p>';
      return;
    }
    const { count, results } = data;
    if (!count) {
      list.innerHTML = '<div class="no-results">未找到与“' + escapeHtml(keyword) + '”相关的资讯</div>';
      return;
    }
    let html = '';
    results.forEach(function (a) {
      const c = a.content || '';
      const excerpt = c.length > 200 ? c.substring(0, 200) + '...' : c;
      html += '<div class="result-item"><h3>' + escapeHtml(a.title) +
              '</h3><p>' + escapeHtml(excerpt) + '</p></div>';
    });
    list.innerHTML = html;
  } catch (e) {
    list.innerHTML = '<p style="color:#ef4444;">请求异常，请稍后再试</p>';
  }
}
function escapeHtml(t) {
  const d = document.createElement('div'); d.textContent = t; return d.innerHTML;
}
document.getElementById('searchButton').addEventListener('click', doSearch);
document.getElementById('queryInput').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') doSearch();
});
</script>
</body>
</html>
"""

ALERT_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<title>安全拦截</title>
<style>body{background:#1a0f0f;color:#ffb4b4;font-family:sans-serif;
text-align:center;padding-top:120px}h1{font-size:56px;margin:0}
p{color:#d99}a{color:#7fb2ff}</style></head>
<body><h1>403</h1>
<p>AI WAF 已拦截该请求（语义评分 {{ confidence }}）</p>
<p><a href="/">返回首页</a></p></body></html>
"""


@app.route('/')
def index():
    return render_template_string(INDEX_HTML)


@app.route('/alert')
def alert():
    conf = request.args.get('confidence', '0.98')
    try:
        conf = '%.2f' % float(conf)
    except Exception:                       # noqa: BLE001
        conf = '0.98'
    return render_template_string(ALERT_HTML, confidence=conf)


@app.route('/search', methods=['POST'])
def search():
    # 频率限制（实测：短时间连发 → 429 操作过于频繁）
    if not waf.limiter.check(request.remote_addr or 'x'):
        return waf.ratelimit_response()

    data = request.get_json(silent=True) or {}
    query = data.get('query', '')
    if not isinstance(query, str):
        query = str(query)

    # ---- AI WAF ----
    verdict = waf.inspect(query)
    if verdict.blocked:
        return waf.waf_response(verdict)

    # ---- 有漏洞的拼接（故意不做参数化）----
    sql = ("SELECT id, title, content FROM article "
           "WHERE title LIKE '%%%s%%' OR content LIKE '%%%s%%' LIMIT 1;" % (query, query))

    conn = connect()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute(sql)                # ← 注入点
            rows = cur.fetchall()
    finally:
        conn.close()

    results = [{'id': r['id'], 'title': r['title'], 'content': r['content']} for r in rows]
    return jsonify({
        'count': len(results),
        'firework': 0,
        'keyword': query,
        'results': results,
        'status': 'success',
    })


@app.route('/healthz')
def healthz():
    return 'ok'


def sync_flag():
    """把环境变量 FLAG 同步进 idap.flag（容器每次启动都执行，保证 flag 跟随环境变量）。"""
    flag = os.environ.get('FLAG')
    if not flag:
        return
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM flag")
            n = cur.fetchone()[0]
            if n:
                cur.execute("UPDATE flag SET flag=%s", (flag,))
            else:
                cur.execute("INSERT INTO flag (flag) VALUES (%s)", (flag,))
        print('[*] idap.flag synced', flush=True)
    finally:
        conn.close()


if __name__ == '__main__':
    try:
        sync_flag()
    except Exception as e:                  # noqa: BLE001
        print('[!] sync_flag failed: %r' % (e,), file=sys.stderr, flush=True)
    port = int(os.environ.get('PORT', '5000'))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

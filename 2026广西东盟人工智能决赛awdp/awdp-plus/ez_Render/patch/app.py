#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ez_Render - patched preview service (sandboxed rendering)."""
import os
from flask import Flask, jsonify, request
from jinja2.sandbox import SandboxedEnvironment

app = Flask(__name__)
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN", "demo-token")

# 修复点 1：使用沙箱环境，禁止访问 __globals__ / 下划线属性
_ENV = SandboxedEnvironment(autoescape=False)

# 修复点 2：WAF 覆盖所有 flag 形态，而非仅字面 flag.txt
_BLOCKED = ("flag", "fla*", "globals", "popen", "system", "subprocess", "os.")


@app.route("/health")
def health():
    return jsonify(ok=True, service="ez_Render")


@app.route("/api/template/preview", methods=["POST"])
def preview():
    if request.headers.get("X-Access-Token") != ACCESS_TOKEN:
        return jsonify(ok=False, error="invalid access token"), 401
    data = request.get_json(silent=True) or {}
    template = str(data.get("template", ""))
    lowered = template.lower()
    if any(marker in lowered for marker in _BLOCKED):
        return jsonify(ok=False, error="blocked by waf"), 401
    try:
        # 修复点 3：不渲染用户模板中的任意表达式，仅允许沙箱内安全子集
        rendered = _ENV.from_string(template).render()
    except Exception as exc:
        return jsonify(ok=False, error="render error: %s" % exc), 400
    return jsonify(ok=True, rendered=rendered)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5008")))

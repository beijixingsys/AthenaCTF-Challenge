#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ez_Render - template preview service (REBUILT equivalent of the original)."""
import os
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("RENDER_SECRET", "ez-render-secret")
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN", "demo-token")

FLAG_FILE = os.environ.get("RENDER_FLAG_FILE", "/tmp/flag.txt")
if not os.path.exists(FLAG_FILE):
    try:
        os.makedirs(os.path.dirname(FLAG_FILE), exist_ok=True)
    except Exception:
        pass
    with open(FLAG_FILE, "w", encoding="utf-8") as handle:
        handle.write(os.environ.get("FLAG", ""))


@app.route("/health")
def health():
    return jsonify(ok=True, service="ez_Render")


@app.route("/api/template/preview", methods=["POST"])
def preview():
    if request.headers.get("X-Access-Token") != ACCESS_TOKEN:
        return jsonify(ok=False, error="invalid access token"), 401
    data = request.get_json(silent=True) or {}
    template = str(data.get("template", ""))
    # WAF: blocks the literal token only (bypassable with fla*)
    if "flag.txt" in template:
        return jsonify(ok=False, error="blocked by waf"), 401
    try:
        rendered = render_template_string(template)
    except Exception as exc:
        return jsonify(ok=False, error="render error: %s" % exc), 500
    return jsonify(ok=True, rendered=rendered)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5008")))

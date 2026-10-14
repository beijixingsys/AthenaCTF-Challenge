#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local GameBox verification harness (phase 4 of the reconstruction).

For every challenge it performs:
    V1 漏洞可利用性 : start service -> checker --exploit  -> flag must leak
    V2 服务正常性   : checker (liveness + functional)      -> exit 0
    V3 修补有效性   : apply patch -> checker --exploit     -> flag must NOT leak
    V4 修补不回归   : patched service -> checker           -> exit 0
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import specs  # noqa: E402

PY = sys.executable or "python"
ROUND_FLAG = "flag{recon-verify-0001}"


def wait_health(port, timeout=25):
    port = int(port)
    deadline = time.time() + timeout
    url = "http://127.0.0.1:%d/health" % port
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def free_port(port):
    """Kill whatever is already listening on the port (Windows netstat)."""
    try:
        raw = subprocess.run(["netstat", "-ano"], capture_output=True,
                             timeout=25).stdout or b""
        listing = raw.decode("utf-8", "replace")
    except Exception:
        return
    marker = ":" + str(port)
    for line in listing.splitlines():
        upper = line.upper()
        if marker in line and "LISTENING" in upper:
            parts = line.split()
            pid = parts[-1] if parts else ""
            if pid.isdigit():
                subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
    time.sleep(0.4)


def _clear_pycache(src):
    for root, dirs, files in os.walk(src):
        for folder in list(dirs):
            if folder == "__pycache__":
                shutil.rmtree(os.path.join(root, folder), ignore_errors=True)


def stage_src(spec, tmpdir, tag):
    """Copy the delivered (vulnerable) src so verification never mutates it."""
    origin = os.path.join(ROOT, spec["name"], "src")
    staged = os.path.join(tmpdir, "src-" + tag)
    if os.path.isdir(staged):
        shutil.rmtree(staged, ignore_errors=True)
    shutil.copytree(origin, staged)
    return staged


def start_service(spec, tmpdir, tag, port, src):
    _clear_pycache(src)
    db_path = os.path.join(tmpdir, "%s-%s.db" % (spec["name"], tag))
    env = dict(os.environ)
    env["FLAG"] = ROUND_FLAG
    env["PORT"] = str(port)
    env["DB_PATH"] = db_path
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["RENDER_FLAG_FILE"] = os.path.join(tmpdir, "flag-%s.txt" % tag)
    log = open(os.path.join(tmpdir, "%s-%s.log" % (spec["name"], tag)), "wb")
    proc = subprocess.Popen([PY, "-u", os.path.join(src, "app.py")], cwd=src,
                            env=env, stdout=log, stderr=subprocess.STDOUT)
    return proc, log


def stop_service(proc, log, port=None):
    try:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                       capture_output=True)
    except Exception:
        pass
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        log.close()
    except Exception:
        pass
    if port is not None:
        deadline = time.time() + 10
        while time.time() < deadline:
            if not wait_health(port, timeout=1):
                break
            time.sleep(0.4)
    time.sleep(0.3)


def run_checker(spec, tmpdir, extra=(), port=None):
    checker = os.path.join(ROOT, spec["name"], "checker", "checker.py")
    url = "http://127.0.0.1:%d" % int(port or spec["port"])
    cmd = [PY, "-u", checker, url] + list(extra)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except Exception as exc:
        return -1, "checker error: %s" % exc


def apply_patch(spec, tmpdir, src_dir):
    """Emulate the update.sh cp commands with /app replaced by the staged src dir."""
    box = os.path.join(ROOT, spec["name"])
    archive = os.path.join(box, "dist", spec["name"] + "_patch.tar.gz")
    stage = os.path.join(tmpdir, spec["name"] + "-patch")
    if os.path.isdir(stage):
        shutil.rmtree(stage)
    os.makedirs(stage)
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(stage)
    update = os.path.join(stage, "update.sh")
    script = open(update, encoding="utf-8").read()
    applied = []
    for line in script.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or not line.startswith("cp"):
            continue
        parts = line.split()
        paths = [p for p in parts[1:] if not p.startswith("-")]
        if len(paths) < 2:
            continue
        source, dest = paths[0], paths[1]
        if "/app/" in dest:
            rel = dest.split("/app/", 1)[1]
            target = os.path.join(src_dir, rel.replace("/", os.sep))
            resolved = os.path.join(stage, source.lstrip("./").replace("/", os.sep))
            if not os.path.exists(resolved):
                resolved = os.path.join(stage, os.path.basename(source))
            if os.path.exists(resolved):
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copyfile(resolved, target)
                applied.append(rel)
    return applied


def verify_one(spec):
    name = spec["name"]
    result = {"name": name, "exploit_before": None, "sla_before": None,
              "exploit_after": None, "sla_after": None, "applied": []}
    tmpdir = tempfile.mkdtemp(prefix="awdpv-" + name + "-")
    pre_port = int(spec["port"])
    post_port = pre_port + 100
    try:
        free_port(pre_port)
        free_port(post_port)
        pre_src = stage_src(spec, tmpdir, "pre")
        proc, log = start_service(spec, tmpdir, "pre", pre_port, pre_src)
        if not wait_health(pre_port):
            result["error"] = "service did not start"
            stop_service(proc, log, pre_port)
            return result
        code, out = run_checker(spec, tmpdir, (), pre_port)
        result["sla_before"] = (code == 0)
        result["sla_before_out"] = out.strip().splitlines()
        code, out = run_checker(spec, tmpdir, ("--exploit",), pre_port)
        result["exploit_before"] = (code == 0)
        result["exploit_before_out"] = out.strip().splitlines()
        stop_service(proc, log, pre_port)
        post_src = stage_src(spec, tmpdir, "post")
        result["applied"] = apply_patch(spec, tmpdir, post_src)
        free_port(post_port)
        proc, log = start_service(spec, tmpdir, "post", post_port, post_src)
        if not wait_health(post_port):
            result["error"] = "patched service did not start"
            stop_service(proc, log, post_port)
            return result
        code, out = run_checker(spec, tmpdir, (), post_port)
        result["sla_after"] = (code == 0)
        result["sla_after_out"] = out.strip().splitlines()
        code, out = run_checker(spec, tmpdir, ("--exploit", "--expect-blocked"), post_port)
        result["exploit_after"] = (code == 0)
        result["exploit_after_out"] = out.strip().splitlines()
        stop_service(proc, log, post_port)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def main():
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    report = []
    for spec in specs.SPECS:
        if only and spec["name"] not in only:
            continue
        res = verify_one(spec)
        report.append(res)
        print("\n=========== %s ===========" % res["name"])
        print("  V2 SLA(before)      :", res.get("sla_before"))
        print("  V1 exploit(before)  :", res.get("exploit_before"))
        print("  V3 exploit(after)   :", res.get("exploit_after"))
        print("  V4 SLA(after)       :", res.get("sla_after"))
        print("  patch applied       :", res.get("applied"))
        if res.get("error"):
            print("  ERROR               :", res["error"])
        for line in (res.get("exploit_before_out") or []):
            print("    [pre ]", line)
        for line in (res.get("exploit_after_out") or []):
            print("    [post]", line)
    with open(os.path.join(ROOT, "_tools", "verify_report.json"), "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
    ok = all(r.get("sla_before") and r.get("exploit_before") and r.get("exploit_after")
             and r.get("sla_after") for r in report)
    print("\n===== SUMMARY: %d/%d fully verified =====" %
          (sum(1 for r in report if r.get("sla_before") and r.get("exploit_before")
               and r.get("exploit_after") and r.get("sla_after")), len(report)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GameBox builder for the recreated AWDP-Plus AI-agent challenges."""
import io
import os
import shutil
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SHARED = os.path.join(ROOT, "_shared", "agent_core")
EXTRACT = "D:/2026/GX人工智能大赛/_final_extract"
FIXDIR = "D:/2026/GX人工智能大赛/awdpv3"


def write(path, content):
    folder = os.path.dirname(path)
    if folder and not os.path.isdir(folder):
        os.makedirs(folder, exist_ok=True)
    with io.open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def copy(src, dst):
    folder = os.path.dirname(dst)
    if folder and not os.path.isdir(folder):
        os.makedirs(folder, exist_ok=True)
    shutil.copyfile(src, dst)


def safe_rmtree(path):
    if not os.path.isdir(path):
        return
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            try:
                os.remove(os.path.join(root, name))
            except Exception:
                pass
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except Exception:
                pass
    try:
        os.rmdir(path)
    except Exception:
        pass


def copy_shared(dst_dir):
    target = os.path.join(dst_dir, "agent_core")
    if os.path.isdir(target):
        shutil.rmtree(target)
    shutil.copytree(SHARED, target)
    for name in os.listdir(target):
        if name.endswith(".pyc"):
            os.remove(os.path.join(target, name))


APP_TEMPLATE = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GameBox entrypoint: %(title)s."""
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

FLAG = os.environ.get("FLAG") or ""
if not FLAG:
    for candidate in ("/flag", "/flag.txt", "/tmp/flag.txt"):
        try:
            with open(candidate, "r", encoding="utf-8", errors="replace") as handle:
                FLAG = handle.read().strip()
        except Exception:
            FLAG = ""
        if FLAG:
            break
os.environ["FLAG"] = FLAG
os.environ.setdefault("PORT", "%(port)s")

from agent_core import Core, build_app, serve
from %(error_mod)s import %(error_cls)s
from %(service_mod)s import %(service_cls)s
%(tenant_import)s
from %(rail_mod)s import %(rail_cls)s

core = Core(db_path=os.environ.get("DB_PATH", "/app/data/%(name)s.db"),
            flag=FLAG, tenant=%(tenant_expr)s, fault=%(error_cls)s)
core.%(core_attr)s = %(rail_cls)s(core, %(error_cls)s)
service = %(service_cls)s(core)
service.init_db()

# 每轮旗标刷新：把当前轮 FLAG 回写到受限 fixture（幂等）
FLAG_SQL = %(flag_sql)s


def _refresh_round_flag():
    if not FLAG:
        return
    try:
        with core.lock, core.db() as db:
            for statement in FLAG_SQL:
                db.execute(statement, (FLAG,))
    except Exception as exc:
        print("round flag refresh skipped: %s" % exc, flush=True)


_refresh_round_flag()

app = build_app(core, service,
                snapshot=lambda user, run_id: core.%(core_attr)s.%(snap)s(user, run_id),
                title="%(title)s")

if __name__ == "__main__":
    serve(app, host=os.environ.get("HOST", "0.0.0.0"),
          port=int(os.environ.get("PORT", "%(port)s")))
'''

DOCKER_TEMPLATE = '''# 题目名称：%(name)s  (%(title)s)
# 基础镜像选择依据：纯 Python WSGI 服务，无系统级依赖 -> python:3.11-slim 体积小、启动快
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \\
    PYTHONDONTWRITEBYTECODE=1 \\
    PORT=%(port)s \\
    DB_PATH=/app/data/%(name)s.db

RUN apt-get update && apt-get install -y --no-install-recommends curl \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/ /app/
RUN mkdir -p /app/data

# ---------------------------------------------------------------------------
# Flag 存储路径声明
#   * 运行期旗标：环境变量 FLAG（平台 FlagServer 每轮刷新并重启容器）
#   * 回退文件   ：/flag 或 /flag.txt（格式 flag{...}）
# 服务启动时将旗标写入受限 fixture 业务记录（详见 README 的 Flag 机制章节）
# ---------------------------------------------------------------------------
ENV FLAG=""

EXPOSE %(port)s
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \\
    CMD curl -fsS http://127.0.0.1:%(port)s/health || exit 1

CMD ["python", "-u", "/app/app.py"]
'''

CHECKER_TEMPLATE = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AWDP-Plus Checker for %(name)s.

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


%(functional)s

%(flagcheck)s


def main():
    args = list(sys.argv[1:])
    base = "http://127.0.0.1:%(port)s"
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
'''

README_TEMPLATE = '''# %(name)s - %(title)s

> AWDP Plus GameBox 还原件（北极星实验室 WRITEUP 复现）

## 题目信息（题面）

%(brief)s

> **中文提要**：%(brief_cn)s

> **参考旗标**（比赛期间原题，仅供核对；平台每轮会刷新为新旗标）：%(ref_flag)s

---

## 1. 业务场景
%(scenario)s

## 2. 漏洞根因
%(vuln)s

## 3. 利用链（原始 Writeup）
%(chain)s

## 4. Flag 机制
| 项 | 值 |
| --- | --- |
| 存储位置 | 环境变量 FLAG（平台 FlagServer 每轮刷新）；回退文件 /flag |
| 落地业务字段 | %(flag_field)s |
| 格式 | flag{...}，每轮替换 |
| 刷新方式 | 平台每轮写入新 FLAG 并重启容器，服务启动时写入受限 fixture |

## 5. 防守修补点
| 项 | 值 |
| --- | --- |
| 漏洞文件 | %(patch_files)s |
| Patch Directory | /app |
| 白名单命令 | mv / cp / rm |
| 修补包 | dist/%(name)s_patch.tar.gz（内含 update.sh，仅用白名单命令） |
| 修补原则 | 最小改动；修补后原利用链失效，合法业务回归通过 |

## 6. Checker
    python checker/checker.py http://127.0.0.1:%(port)s
    python checker/checker.py http://127.0.0.1:%(port)s --exploit

## 7. 本地部署
    docker build -t %(name)s .
    docker run -d --name %(name)s -p %(port)s:%(port)s -e FLAG=flag{local-test} %(name)s
    python checker/checker.py http://127.0.0.1:%(port)s

## 8. 修补验证
    docker exec %(name)s mkdir -p /tmp/p
    docker cp dist/%(name)s_patch.tar.gz %(name)s:/tmp/p/patch.tar.gz
    docker exec %(name)s sh -c "tar -xzf /tmp/p/patch.tar.gz -C /tmp/p && cd /tmp/p && sh update.sh"
    python checker/checker.py http://127.0.0.1:%(port)s --exploit
'''


def fill(template, mapping):
    out = template
    for key, value in mapping.items():
        out = out.replace("%(" + key + ")s", str(value))
    return out


def build_app_py(spec):
    return fill(APP_TEMPLATE, spec)


def build_dockerfile(spec):
    return fill(DOCKER_TEMPLATE, spec)


def build_readme(spec):
    return fill(README_TEMPLATE, spec)


def build_checker(spec):
    return fill(CHECKER_TEMPLATE, spec)


# ===========================================================================
#  custom (non-official) patch builders
# ===========================================================================
def pack_tar(out_path, members):
    """members: list of (arcname, bytes|path, mode)."""
    folder = os.path.dirname(out_path)
    if folder and not os.path.isdir(folder):
        os.makedirs(folder, exist_ok=True)
    with tarfile.open(out_path, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for name, payload, mode in members:
            data = payload if isinstance(payload, bytes) else open(payload, "rb").read()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return out_path


def _replace_once(text, old, new, label):
    if old not in text:
        raise RuntimeError("patch anchor not found: " + label)
    return text.replace(old, new, 1)


def patch_release_control_tower(spec, box):
    src = os.path.join(box, "src")
    control = open(os.path.join(src, "preflight_control.py"), encoding="utf-8").read()
    rail = open(os.path.join(src, "preflight_rail.py"), encoding="utf-8").read()
    control = _replace_once(
        control,
        '   else:\n    completed=subprocess.run(manifest["extension"],shell=True',
        '   else:\n    if manifest["review_state"] != "reviewed":\n'
        '        raise DomainError("extension preflight requires reviewed server authorization", HTTPStatus.FORBIDDEN)\n'
        '    completed=subprocess.run(manifest["extension"],shell=True',
        "preflight_control review_state gate")
    rail = _replace_once(
        rail,
        '    elif _explicit_preflight_request(sources.get("untrusted_document", "")):\n'
        '        registry = list(tools)\n',
        '',
        "preflight_rail explicit-wording branch")
    rail = _replace_once(
        rail,
        '    else:\n        registry = [tool for tool in tools if tool.get("name") == "summarize_change_manifest"]',
        '    else:\n        registry = [tool for tool in tools if tool.get("name") != "run_extension_preflight"]',
        "preflight_rail safe tool set")
    write(os.path.join(box, "patch", "preflight_control.py"), control)
    write(os.path.join(box, "patch", "preflight_rail.py"), rail)
    write(os.path.join(box, "patch", "update.sh"),
          "#!/bin/sh\n"
          "cp /app/preflight_control.py /app/original_preflight_control.py\n"
          "cp preflight_control.py /app/preflight_control.py\n"
          "cp /app/preflight_rail.py /app/original_preflight_rail.py\n"
          "cp preflight_rail.py /app/preflight_rail.py\n")
    return pack_tar(os.path.join(box, "dist", spec["name"] + "_patch.tar.gz"), [
        ("update.sh", os.path.join(box, "patch", "update.sh"), 0o755),
        ("preflight_control.py", os.path.join(box, "patch", "preflight_control.py"), 0o644),
        ("preflight_rail.py", os.path.join(box, "patch", "preflight_rail.py"), 0o644),
    ])


def patch_runbook_sentinel(spec, box):
    src = os.path.join(box, "src")
    sentinel = open(os.path.join(src, "probe_sentinel.py"), encoding="utf-8").read()
    journal = open(os.path.join(src, "probe_journal.py"), encoding="utf-8").read()
    sentinel = _replace_once(
        sentinel,
        '  request=urllib.request.Request(url,headers={"X-Probe-Nonce":claim})\n'
        '  with urllib.request.urlopen(request,timeout=3) as response:return response.read().decode()',
        '  request=urllib.request.Request(url,headers={"X-Probe-Nonce":claim})\n'
        '  with urllib.request.urlopen(request,timeout=3) as response:\n'
        '   self._initial(response.geturl())\n'
        '   return response.read().decode()',
        "probe_sentinel revalidate redirect target")
    journal = _replace_once(
        journal,
        '    elif _explicit_probe_request(sources.get("untrusted_document", "")):\n'
        '        advertised = list(tools)\n',
        '',
        "probe_journal explicit-wording branch")
    write(os.path.join(box, "patch", "probe_sentinel.py"), sentinel)
    write(os.path.join(box, "patch", "probe_journal.py"), journal)
    write(os.path.join(box, "patch", "update.sh"),
          "#!/bin/sh\n"
          "cp /app/probe_sentinel.py /app/original_probe_sentinel.py\n"
          "cp probe_sentinel.py /app/probe_sentinel.py\n"
          "cp /app/probe_journal.py /app/original_probe_journal.py\n"
          "cp probe_journal.py /app/probe_journal.py\n")
    return pack_tar(os.path.join(box, "dist", spec["name"] + "_patch.tar.gz"), [
        ("update.sh", os.path.join(box, "patch", "update.sh"), 0o755),
        ("probe_sentinel.py", os.path.join(box, "patch", "probe_sentinel.py"), 0o644),
        ("probe_journal.py", os.path.join(box, "patch", "probe_journal.py"), 0o644),
    ])


def patch_ez_render(spec, box):
    fixed = EZ_RENDER_FIXED
    write(os.path.join(box, "patch", "app.py"), fixed)
    write(os.path.join(box, "patch", "update.sh"),
          "#!/bin/sh\n"
          "cp /app/app.py /app/original_app.py\n"
          "cp app.py /app/app.py\n")
    return pack_tar(os.path.join(box, "dist", spec["name"] + "_patch.tar.gz"), [
        ("update.sh", os.path.join(box, "patch", "update.sh"), 0o755),
        ("app.py", os.path.join(box, "patch", "app.py"), 0o644),
    ])


CUSTOM_PATCHERS = {
    "release_control_tower": patch_release_control_tower,
    "runbook_sentinel": patch_runbook_sentinel,
    "ez_Render": patch_ez_render,
}


# ===========================================================================
#  ez_Render sources (no platform attachment existed -> equivalent rebuild)
# ===========================================================================
EZ_RENDER_VULN = '''#!/usr/bin/env python3
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
'''

EZ_RENDER_FIXED = '''#!/usr/bin/env python3
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
'''

EZ_RENDER_DOCKER = '''# 题目名称：ez_Render  (Jinja2 模板预览服务)
# 基础镜像选择依据：Flask + Jinja2，pip 依赖 -> python:3.11-slim
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PORT=5008 RENDER_FLAG_FILE=/tmp/flag.txt
RUN pip install --no-cache-dir flask==3.0.3

WORKDIR /app
COPY src/ /app/

# Flag 存储路径：/tmp/flag.txt（服务启动时写入 FLAG 环境变量内容）
# 轮次刷新：平台每轮更新 FLAG 并重启容器，/tmp/flag.txt 随之更新
ENV FLAG=""

EXPOSE 5008
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \\
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5008/health',timeout=3)" || exit 1

CMD ["python", "-u", "/app/app.py"]
'''


# ===========================================================================
#  builder
# ===========================================================================
def error_shim(spec):
    return ("from agent_core import Problem\n\n\nclass %s(Problem):\n    pass\n"
            % spec["error_cls"])


def build_one(spec):
    name = spec["name"]
    box = os.path.join(ROOT, name)
    src_dir = os.path.join(box, "src")
    safe_rmtree(box)
    os.makedirs(src_dir, exist_ok=True)

    if spec.get("kind") == "flask":
        write(os.path.join(src_dir, "app.py"), EZ_RENDER_VULN)
        write(os.path.join(box, "Dockerfile"), EZ_RENDER_DOCKER)
    else:
        base = os.path.join(EXTRACT, spec["extract"])
        for rel, dests in spec["src_layout"]:
            source = os.path.join(base, rel.replace("/", os.sep))
            for dest in dests:
                copy(source, os.path.join(src_dir, dest.replace("/", os.sep)))
        for rel, dest in spec.get("docs", []):
            copy(os.path.join(base, rel.replace("/", os.sep)),
                 os.path.join(src_dir, dest.replace("/", os.sep)))
        write(os.path.join(src_dir, spec["error_mod"] + ".py"), error_shim(spec))
        copy_shared(src_dir)
        fields = dict(spec)
        if spec["tenant"] == "FIXTURE_TENANT":
            fields["tenant_import"] = "from %s import FIXTURE_TENANT" % spec["service_mod"]
            fields["tenant_expr"] = "FIXTURE_TENANT"
        else:
            fields["tenant_import"] = ""
            fields["tenant_expr"] = spec["tenant"]
        fields["flag_sql"] = repr(list(spec.get("flag_sql") or []))
        write(os.path.join(src_dir, "app.py"), build_app_py(fields))
        write(os.path.join(box, "Dockerfile"), build_dockerfile(spec))

    write(os.path.join(box, "README.md"), build_readme(spec))
    write(os.path.join(box, "checker", "checker.py"), build_checker(spec))

    if spec.get("patch_from"):
        official = os.path.join(FIXDIR, spec["patch_from"].replace("/", os.sep))
        os.makedirs(os.path.join(box, "dist"), exist_ok=True)
        shutil.copyfile(official, os.path.join(box, "dist", name + "_patch.tar.gz"))
        with tarfile.open(official, "r:gz") as tar:
            tar.extractall(os.path.join(box, "patch"))
    elif spec.get("patch_custom"):
        CUSTOM_PATCHERS[spec["patch_custom"]](spec, box)
    return box


def main():
    import specs
    built = []
    for spec in specs.SPECS:
        box = build_one(spec)
        built.append(spec["name"])
        print("built", spec["name"], "->", box)
    print("total", len(built))
    return built


if __name__ == "__main__":
    main()

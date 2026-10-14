"""Minimal WSGI front-end shared by every recreated GameBox.

Routes owned by the platform layer:
    GET  /                       liveness
    GET  /health                 liveness
    POST /v1/auth/register       create a low-privilege session
    POST /v1/auth/login          resume a session
    GET  /v1/audit               caller-scoped audit trail (exposes run_id)
    GET  /v1/agent-runs/<run_id> caller-scoped agent run snapshot
    POST /v1/seed | /v1/dev/seed fixture seeding hook (challenge specific)

Everything else under /v1/ is delegated to the challenge service object
(service.get / service.post), and /probe-fixture/* style public endpoints are
delegated to service.public_get when the challenge provides one.
"""
import json
import traceback
from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

from .errors import Problem

SEED_PATHS = ("/v1/seed", "/v1/dev/seed", "/seed", "/dev/seed")


def _json_response(start_response, status, payload):
    body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    start_response("%d %s" % (int(status), HTTPStatus(int(status)).phrase),
                   [("Content-Type", "application/json; charset=utf-8"),
                    ("Content-Length", str(len(body)))])
    return [body]


def _flexible_response(start_response, outcome):
    """Handle both (status, body) and (status, body, content_type, headers)."""
    extra = {}
    ctype = "application/json; charset=utf-8"
    if len(outcome) >= 4:
        status, body, ctype, extra = outcome[0], outcome[1], (outcome[2] or ctype), (outcome[3] or {})
    elif len(outcome) == 3:
        status, body, ctype = outcome
    else:
        status, body = outcome
    if isinstance(body, (dict, list)):
        raw = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
    elif isinstance(body, bytes):
        raw = body
    else:
        raw = str(body or "").encode("utf-8")
    headers = [("Content-Type", ctype), ("Content-Length", str(len(raw)))]
    for key, value in (extra or {}).items():
        headers.append((str(key), str(value)))
    start_response("%d %s" % (int(status), HTTPStatus(int(status)).phrase), headers)
    return [raw]


def _read_body(environ):
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except Exception:
        length = 0
    if length <= 0:
        return {}
    raw = environ["wsgi.input"].read(length)
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _bearer(environ):
    header = environ.get("HTTP_AUTHORIZATION") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


def build_app(core, service, snapshot=None, title="AI Agent Service"):
    def app(environ, start_response):
        method = (environ.get("REQUEST_METHOD") or "GET").upper()
        parsed = urlparse(environ.get("PATH_INFO") or "/")
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(environ.get("QUERY_STRING") or "").items()}
        try:
            if path in ("/", "/health", "/v1/health"):
                return _json_response(start_response, 200,
                                      {"ok": True, "service": title})

            if method == "POST" and path in ("/v1/auth/register", "/v1/auth/login"):
                payload = _read_body(environ)
                username = str(payload.get("username") or "").strip()
                if not username:
                    return _json_response(start_response, 400,
                                          {"ok": False, "error": "username is required"})
                user = core.register(username)
                return _json_response(start_response, 201 if path.endswith("register") else 200,
                                      {"ok": True, "id": user["id"], "role": user["role"],
                                       "subject_id": user["subject_id"],
                                       "tenant_id": user["tenant_id"],
                                       "username": user["username"], "token": user.get("token", "")})

            # public (unauthenticated) challenge endpoints
            public_get = getattr(service, "public_get", None)
            if callable(public_get):
                headers = {}
                for key, value in environ.items():
                    if key.startswith("HTTP_"):
                        headers[key[5:].replace("_", "-").title()] = str(value)
                outcome = public_get(path, query, headers)
                if outcome is not None:
                    return _flexible_response(start_response, outcome)

            token = _bearer(environ)
            user = core.user_by_token(token)
            if user is None:
                return _json_response(start_response, 401,
                                      {"ok": False, "error": "authentication required"})

            if method == "GET" and path == "/v1/audit":
                return _json_response(start_response, 200,
                                      {"ok": True, "events": core.audit_events(user)})

            if method == "GET" and path.startswith("/v1/agent-runs/"):
                run_id = path.split("/")[3]
                if snapshot is None:
                    return _json_response(start_response, 404,
                                          {"ok": False, "error": "agent run not found"})
                try:
                    status, body = snapshot(user, run_id)
                except Problem as problem:
                    return _json_response(start_response, problem.status,
                                          {"ok": False, "error": problem.message})
                return _json_response(start_response, status, body)

            if method == "POST" and path in SEED_PATHS:
                payload = _read_body(environ)
                outcome = service.seed(user, payload)
                if outcome is None:
                    return _json_response(start_response, 404,
                                          {"ok": False, "error": "route not found"})
                status, body = outcome
                return _json_response(start_response, status, body)

            handler = service.get if method == "GET" else service.post
            outcome = handler(path, user, query if method == "GET" else _read_body(environ))
            if outcome is None:
                return _json_response(start_response, 404,
                                      {"ok": False, "error": "route not found"})
            status, body = outcome
            return _json_response(start_response, status, body)
        except Problem as problem:
            return _json_response(start_response, problem.status,
                                  {"ok": False, "error": problem.message})
        except Exception as exc:  # pragma: no cover - defensive
            traceback.print_exc()
            return _json_response(start_response, 500,
                                  {"ok": False, "error": str(exc)})

    return app


def serve(app, host="0.0.0.0", port=5000):
    from socketserver import ThreadingMixIn
    from wsgiref.simple_server import WSGIServer, WSGIRequestHandler, make_server

    class _ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
        daemon_threads = True
        allow_reuse_address = True

    httpd = make_server(host, int(port), app, server_class=_ThreadedWSGIServer,
                        handler_class=WSGIRequestHandler)
    print("serving on %s:%s" % (host, port), flush=True)
    httpd.serve_forever()

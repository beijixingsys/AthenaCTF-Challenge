"""Shared runtime for the recreated AWDP-Plus AI-agent GameBoxes.

Provides the platform services the challenge modules expect from "core":
    core.lock / core.db() / core.audit()
    core.ensure_service_account() / core.issue_claim() / core.read_claim()
    core.model_intent()
plus the account + tenant bookkeeping used by the HTTP layer.

The users table mirrors the original platform schema
(id, username, token_hash, tenant_id, subject_id, role, created_at) because
several challenge modules insert fixture accounts into it directly.
"""
import contextlib
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid

from . import model as decision_engine
from .errors import Problem


def _now():
    return int(time.time())


def _hash_token(token):
    return hashlib.sha256(("awdp-plus::" + (token or "")).encode("utf-8")).hexdigest()


class Core(object):
    def __init__(self, db_path, flag="", tenant="tenant-default", fault=None):
        self.lock = threading.RLock()
        self.fault = fault or Problem
        self._local = threading.local()
        self.db_path = db_path
        self.flag = flag or os.environ.get("FLAG", "")
        self.tenant = tenant
        folder = os.path.dirname(os.path.abspath(db_path))
        if folder and not os.path.isdir(folder):
            os.makedirs(folder, exist_ok=True)
        self._install_platform_tables()

    # ------------------------------------------------------------------ db
    def _connection(self):
        """Thread-local persistent connection.

        The original platform returned a long-lived handle: several challenge
        modules keep using it after the `with` block, so it must not be closed
        when the context manager exits.
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA busy_timeout=30000")
            except Exception:
                pass
            self._local.conn = conn
        return conn

    @contextlib.contextmanager
    def db(self):
        conn = self._connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise

    def _install_platform_tables(self):
        with self.lock, self.db() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users(
                  id TEXT PRIMARY KEY, username TEXT NOT NULL, token_hash TEXT,
                  tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL, role TEXT NOT NULL,
                  label TEXT DEFAULT '', created_at INTEGER NOT NULL,
                  UNIQUE(tenant_id, username)
                );
                CREATE TABLE IF NOT EXISTS core_audit(
                  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL,
                  event TEXT NOT NULL, detail TEXT NOT NULL, run_id TEXT,
                  created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS core_claims(
                  grant TEXT PRIMARY KEY, scope TEXT NOT NULL, payload TEXT NOT NULL,
                  created_at INTEGER NOT NULL
                );
                """
            )

    # --------------------------------------------------------------- users
    def register(self, username, role="member", label=""):
        username = (username or "").strip()
        if not username:
            raise ValueError("username is required")
        with self.lock, self.db() as db:
            row = db.execute("SELECT * FROM users WHERE tenant_id=? AND username=?",
                             (self.tenant, username)).fetchone()
            if row is not None:
                return dict(row)
            token = secrets.token_urlsafe(32)
            record = {
                "id": "usr-" + uuid.uuid4().hex,
                "username": username,
                "token_hash": _hash_token(token),
                "tenant_id": self.tenant,
                "subject_id": "sub-" + uuid.uuid4().hex,
                "role": role,
                "label": label or username,
                "created_at": _now(),
            }
            db.execute("INSERT INTO users VALUES(:id,:username,:token_hash,:tenant_id,"
                       ":subject_id,:role,:label,:created_at)", record)
            record["token"] = token
            return record

    def ensure_service_account(self, name, role, label):
        record = self.register(name, role=role, label=label)
        with self.lock, self.db() as db:
            db.execute("UPDATE users SET role=?, label=? WHERE id=?",
                       (role, label, record["id"]))
        return record

    def user_by_token(self, token):
        if not token:
            return None
        with self.lock, self.db() as db:
            row = db.execute("SELECT * FROM users WHERE token_hash=?",
                             (_hash_token(token),)).fetchone()
        return dict(row) if row else None

    # --------------------------------------------------------------- audit
    def audit(self, user, event, detail=None, run_id=None):
        tenant = (user or {}).get("tenant_id", self.tenant)
        subject = (user or {}).get("subject_id", "")
        try:
            blob = json.dumps(detail if detail is not None else {}, ensure_ascii=False,
                              sort_keys=True, default=str)
        except Exception:
            blob = "{}"
        with self.lock, self.db() as db:
            db.execute("INSERT INTO core_audit VALUES(?,?,?,?,?,?,?)",
                       ("aud-" + uuid.uuid4().hex, tenant, subject, event, blob, run_id, _now()))

    def audit_events(self, user, limit=200):
        with self.lock, self.db() as db:
            rows = db.execute(
                "SELECT event, detail, run_id, created_at FROM core_audit "
                "WHERE tenant_id=? AND subject_id=? ORDER BY created_at ASC, rowid ASC LIMIT ?",
                (user["tenant_id"], user["subject_id"], limit)).fetchall()
        out = []
        for row in rows:
            try:
                detail = json.loads(row["detail"])
            except Exception:
                detail = {}
            out.append({"event": row["event"], "detail": detail,
                        "run_id": row["run_id"], "created_at": row["created_at"]})
        return out

    # -------------------------------------------------------------- claims
    def issue_claim(self, scope, payload, key):
        grant = "clm-" + secrets.token_urlsafe(24)
        body = json.dumps({"scope": scope, "payload": payload, "key": key,
                           "nonce": uuid.uuid4().hex}, sort_keys=True)
        with self.lock, self.db() as db:
            db.execute("INSERT INTO core_claims VALUES(?,?,?,?)",
                       (grant, scope, body, _now()))
        return grant

    def read_claim(self, grant, scope, key):
        if not grant:
            raise self.fault("probe session required", 403)
        with self.lock, self.db() as db:
            row = db.execute("SELECT * FROM core_claims WHERE grant=?", (grant,)).fetchone()
        valid = row is not None and row["scope"] == scope
        body = {}
        if valid:
            try:
                body = json.loads(row["payload"])
            except Exception:
                body = {}
        if not valid or body.get("key") != key:
            raise self.fault("probe session required", 403)
        payload = body.get("payload") or {}
        return payload if isinstance(payload, dict) else {}

    # ---------------------------------------------------------- model stub
    def model_intent(self, user, operation, sources, tools, agent_phase="action",
                     run_id=None, step=0, force_tool=""):
        sources = sources or {}
        action = decision_engine.decide(operation, sources, tools, force_tool=force_tool)
        print("[model_intent] phase=%s step=%s force=%r tools=%s -> %s"
              % (agent_phase, step, force_tool, [t.get("name") for t in (tools or [])],
                 action.get("tool")), flush=True)
        fp = decision_engine.fingerprint({"op": operation, "phase": agent_phase,
                                          "tool": action.get("tool"), "step": step})
        return action, decision_engine.PROFILE, decision_engine.MODEL, fp

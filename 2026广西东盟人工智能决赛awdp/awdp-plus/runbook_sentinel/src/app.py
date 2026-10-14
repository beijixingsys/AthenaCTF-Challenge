#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GameBox entrypoint: Runbook Sentinel."""
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
os.environ.setdefault("PORT", "5007")

from agent_core import Core, build_app, serve
from sentinel_bridge import RunbookProblem
from probe_sentinel import RunbookDiagnosticsService

from probe_journal import ProbeJournal

core = Core(db_path=os.environ.get("DB_PATH", "/app/data/runbook_sentinel.db"),
            flag=FLAG, tenant="tenant-runbook_sentinel", fault=RunbookProblem)
core.probe_journal = ProbeJournal(core, RunbookProblem)
service = RunbookDiagnosticsService(core)
service.init_db()

# 每轮旗标刷新：把当前轮 FLAG 回写到受限 fixture（幂等）
FLAG_SQL = []


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
                snapshot=lambda user, run_id: core.probe_journal.journal_snapshot(user, run_id),
                title="Runbook Sentinel")

if __name__ == "__main__":
    serve(app, host=os.environ.get("HOST", "0.0.0.0"),
          port=int(os.environ.get("PORT", "5007")))

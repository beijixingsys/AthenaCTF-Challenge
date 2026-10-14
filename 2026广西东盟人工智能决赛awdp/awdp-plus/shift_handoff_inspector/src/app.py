#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GameBox entrypoint: Shift Handoff Inspector."""
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
os.environ.setdefault("PORT", "5000")

from agent_core import Core, build_app, serve
from handoff_conductor import HandoffProblem
from handoff_operations import HandoffInspectionService
from handoff_operations import FIXTURE_TENANT
from handoff_timeline import HandoffTimeline

core = Core(db_path=os.environ.get("DB_PATH", "/app/data/shift_handoff_inspector.db"),
            flag=FLAG, tenant=FIXTURE_TENANT, fault=HandoffProblem)
core.handoff_timeline = HandoffTimeline(core, HandoffProblem)
service = HandoffInspectionService(core)
service.init_db()

# 每轮旗标刷新：把当前轮 FLAG 回写到受限 fixture（幂等）
FLAG_SQL = ["UPDATE managed_assets SET snapshot=? WHERE id='ast-fixture-handoff'"]


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
                snapshot=lambda user, run_id: core.handoff_timeline.timeline_snapshot(user, run_id),
                title="Shift Handoff Inspector")

if __name__ == "__main__":
    serve(app, host=os.environ.get("HOST", "0.0.0.0"),
          port=int(os.environ.get("PORT", "5000")))

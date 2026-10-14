#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GameBox entrypoint: Release Control Tower."""
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
os.environ.setdefault("PORT", "5006")

from agent_core import Core, build_app, serve
from release_fabric import ReleaseProblem
from preflight_control import ReleasePreflightService

from preflight_rail import PreflightRail

core = Core(db_path=os.environ.get("DB_PATH", "/app/data/release_control_tower.db"),
            flag=FLAG, tenant="tenant-release_control_tower", fault=ReleaseProblem)
core.preflight_rail = PreflightRail(core, ReleaseProblem)
service = ReleasePreflightService(core)
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
                snapshot=lambda user, run_id: core.preflight_rail.rail_snapshot(user, run_id),
                title="Release Control Tower")

if __name__ == "__main__":
    serve(app, host=os.environ.get("HOST", "0.0.0.0"),
          port=int(os.environ.get("PORT", "5006")))

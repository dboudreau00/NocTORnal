"""Application connections are opened with JIT off (2026-10-07,
`db.SESSION_OPTIONS`).

On a 1,000,000-claim database the request role's reads paid for JIT
compilation they never repaid: row security's policies push the planner's
cost estimate past `jit_above_cost`, so node search spent 2.37 s of its
2.83 s compiling, the triage queue 1.2 s of 1.97 s, the graph view 1.5 s.
With JIT off the same reads took 0.50 s, 0.78 s. JIT never changes an
answer. Each DB test fails on 8585a5c, where the server default (on) held.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os

import pytest

from noctornal_api import db

DATABASE_URL = os.environ.get("DATABASE_URL", "")
needs_db = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")


def test_the_session_options_keep_what_the_dsn_already_names():
    assert db.session_options("postgresql://u@h:5432/d") == "-c jit=off"
    named = "postgresql://u@h:5432/d?options=-c%20statement_timeout%3D5s"
    assert db.session_options(named) == "-c statement_timeout=5s -c jit=off"


@needs_db
def test_a_request_connection_runs_with_jit_off():
    conn = db.connect_request()
    try:
        assert conn.execute("SHOW jit").fetchone()[0] == "off"
    finally:
        conn.close()


@needs_db
def test_a_system_connection_runs_with_jit_off():
    conn = db.connect_system(db.SystemPurpose.SCRIPT)
    try:
        assert conn.execute("SHOW jit").fetchone()[0] == "off"
    finally:
        conn.close()


@needs_db
def test_an_operators_own_options_survive(monkeypatch):
    url = db.dsn()
    sep = "&" if "?" in url else "?"
    monkeypatch.setenv("DATABASE_URL",
                       url + sep + "options=-c%20statement_timeout%3D7s")
    conn = db.connect()
    try:
        assert conn.execute("SHOW statement_timeout").fetchone()[0] == "7s"
        assert conn.execute("SHOW jit").fetchone()[0] == "off"
    finally:
        conn.close()

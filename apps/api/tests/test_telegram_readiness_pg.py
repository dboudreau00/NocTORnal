"""The telegram_collection readiness row (roadmap F5.3,
2026-09-24): idle green with no Telegram source, and counts, never names,
of what stops the active ones: the library, enrolled sessions and machine
locks. Not blocking, no consequence, settled under Feeds, Sources.
DATABASE_URL-gated.
"""
from __future__ import annotations

import os

import pytest

import collection_helpers as h
import telegram_fake as tf
import telegram_pg as tp

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-tgrdy-"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    tf.guard_sockets(monkeypatch)
    c = connect()
    # Other suites' Telegram sources are deactivated by their teardowns; the
    # row counts active ones only, so a leftover would be a flaky count.
    active = c.execute("SELECT count(*) FROM collect.source WHERE is_active "
                       "AND kind = 'TELEGRAM' AND parser_key = 'telegram'").fetchone()[0]
    if active:
        pytest.skip("this database has active Telegram sources of its own")
    yield c
    tp.teardown(c, P)
    h.retire_users(c, P)
    c.close()


def _row(conn):
    from noctornal_api import readiness

    return next(c for c in readiness.report(conn)["checks"]
                if c["check"] == "telegram_collection")


def test_the_telegram_row_is_idle_green_with_no_sources(conn):
    row = _row(conn)
    assert row["ok"] and row["evidence"] == (
        "No Telegram source is active, so nothing is sent to Telegram.")


def test_the_telegram_row_fails_with_counts_not_names(conn, monkeypatch):
    from noctornal_api import telegram_wire

    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid, _e, _uid = tp.persona(conn, P, enrolled=False)
    one = tp.chat(conn, P, persona_id=pid, resolved_by=recorder)
    row = _row(conn)
    assert not row["ok"]
    assert row["evidence"].startswith("1 Telegram source is active;")
    assert "1 persona that reads them has no enrolled session" in row["evidence"]
    assert "scripts/telegram_persona.py" in row["action"]
    name = conn.execute("SELECT name FROM collect.source WHERE id = %s",
                        (one["source"],)).fetchone()[0]
    assert name not in row["evidence"] and one["durable_id"] not in row["evidence"]
    for _ in range(2):
        tp.chat(conn, P, persona_id=pid, resolved_by=recorder)
    monkeypatch.setattr(telegram_wire, "library_version", lambda: None)
    row = _row(conn)
    assert row["evidence"].startswith("3 Telegram sources are active;")
    assert "the Telegram client library is not installed" in row["evidence"]


def test_a_healthy_estate_names_the_library(conn):
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid, _e, _uid = tp.persona(conn, P)
    tp.chat(conn, P, persona_id=pid, resolved_by=recorder)
    row = _row(conn)
    assert row["ok"] and "Telethon" in row["evidence"]


def test_a_locked_persona_is_counted(conn):
    from noctornal_api.collection import PersonaVault

    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid, _e, _uid = tp.persona(conn, P)
    tp.chat(conn, P, persona_id=pid, resolved_by=recorder)
    PersonaVault(conn).signal(pid, reason="revoked", lock_code="CREDENTIAL_REVOKED")
    row = _row(conn)
    assert not row["ok"] and "1 persona that reads them is locked by Telegram" in row["evidence"]


def test_the_telegram_row_names_no_consequence_and_is_settled_under_feeds(conn):
    from noctornal_api import readiness

    assert "telegram_collection" in readiness.CHECK_NAMES
    assert "telegram_collection" not in readiness.BLOCKING_CHECKS
    assert "telegram_collection" not in readiness.CONSEQUENCES
    assert readiness.UI_TARGETS["telegram_collection"] == "feeds/sources"

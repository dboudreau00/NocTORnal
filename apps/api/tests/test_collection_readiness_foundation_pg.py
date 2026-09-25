"""The two collection readiness rows (docs/00 decision 69, 2026-09-24).

collection_sources_configured and collection_authority_current: idle and
green with no forum or Telegram source, failing with counts and never a
name, passing with a caveat when raw markup has nowhere to go or an
authority ends within 14 days. Not blocking and with no consequence entry.
The registry is replaced with one holding a stub authority adapter.
DATABASE_URL-gated.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-b0rd-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect

    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


def _registry(monkeypatch, **attrs):
    from noctornal_api import collection

    stub = h.StubAuthorityAdapter(**attrs)
    monkeypatch.setattr(collection, "default_adapters", lambda: h.adapters(stub))
    return stub


def _rows(conn):
    from noctornal_api import readiness

    return {c.check: c for c in readiness.run_checks(conn)
            if c.check.startswith("collection_")}


def test_both_rows_are_idle_green_with_no_forum_or_telegram_source(conn, monkeypatch):
    from noctornal_api import collection

    monkeypatch.setattr(collection, "default_adapters", lambda: h.adapters())
    rows = _rows(conn)
    for name in ("collection_sources_configured", "collection_authority_current"):
        assert rows[name].ok, rows[name]
        assert rows[name].evidence.startswith("No forum or Telegram source is active")


def test_the_configured_row_fails_with_counts_not_names(conn, monkeypatch):
    monkeypatch.delenv("NOCTORNAL_FORUM_SOURCE_CEILING", raising=False)
    _registry(monkeypatch)
    source = h.source(conn, P, egress=h.egress_profile(conn, P))
    name = conn.execute("SELECT name FROM collect.source WHERE id = %s",
                        (source,)).fetchone()[0]
    row = _rows(conn)["collection_sources_configured"]
    assert not row.ok and not row.blocking and row.consequence == ""
    assert "no ceiling declared (NOCTORNAL_FORUM_SOURCE_CEILING)" in row.evidence
    assert "refused before any request" in row.evidence
    assert name not in row.evidence and "example.test" not in row.evidence
    assert row.ui_target == "feeds/sources"


def test_the_authority_row_fails_with_counts_not_names(conn, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    _registry(monkeypatch)
    source = h.source(conn, P, egress=h.egress_profile(conn, P))
    name = conn.execute("SELECT name FROM collect.source WHERE id = %s",
                        (source,)).fetchone()[0]
    row = _rows(conn)["collection_authority_current"]
    assert not row.ok and "no confirmed authority" in row.evidence
    assert name not in row.evidence
    assert "security officer confirms it under Oversight" in row.action


def test_the_authority_row_passes_with_a_caveat_when_expiry_is_near(conn, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    stub = _registry(monkeypatch)
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    # Every active authority source must be covered for the row to pass, so
    # the test's own is the only one it can speak for: others are paused.
    conn.execute("UPDATE collect.source SET is_active = false WHERE parser_key = "
                 "'stubforum' AND name NOT LIKE %s", (f"{P}%",))
    source = h.source(conn, P, egress=h.egress_profile(conn, P))
    now = datetime.now(timezone.utc)
    h.authority(conn, recorder=recorder, confirmer=confirmer, source_ids=[source],
                adapters=h.adapters(stub), valid_from=now - timedelta(days=1),
                valid_until=now + timedelta(days=3))
    row = _rows(conn)["collection_authority_current"]
    assert row.ok, row
    assert "expire within 14 days" in row.caveat or "expires within 14 days" in row.caveat


def test_the_configured_row_carries_the_raw_store_caveat(conn, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    for var in ("MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)
    _registry(monkeypatch, keeps_raw=True)
    conn.execute("UPDATE collect.source SET is_active = false WHERE parser_key = "
                 "'stubforum' AND name NOT LIKE %s", (f"{P}%",))
    h.source(conn, P, egress=h.egress_profile(conn, P))
    row = _rows(conn)["collection_sources_configured"]
    assert row.ok, row
    assert "raw markup is not kept" in row.caveat


def test_the_raw_store_caveat_reads_the_bucket(conn, monkeypatch):
    from noctornal_api import rawstore

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    monkeypatch.setenv("MINIO_ENDPOINT", "127.0.0.1:9")
    monkeypatch.setenv("MINIO_ACCESS_KEY", "k")
    monkeypatch.setenv("MINIO_SECRET_KEY", "s")
    monkeypatch.setenv("COLLECT_RAW_BUCKET", "b0rd-missing")
    monkeypatch.setattr(rawstore, "document_raw_bucket_exists", lambda timeout=2.0: False)
    _registry(monkeypatch, keeps_raw=True)
    conn.execute("UPDATE collect.source SET is_active = false WHERE parser_key = "
                 "'stubforum' AND name NOT LIKE %s", (f"{P}%",))
    h.source(conn, P, egress=h.egress_profile(conn, P))
    row = _rows(conn)["collection_sources_configured"]
    assert row.ok and "b0rd-missing does not exist" in row.caveat


def test_the_readiness_rows_add_no_consequence_and_are_not_blocking():
    from noctornal_api import readiness

    for name in ("collection_sources_configured", "collection_authority_current"):
        assert name in readiness.CHECK_NAMES
        assert name not in readiness.BLOCKING_CHECKS
        assert name not in readiness.CONSEQUENCES
        assert readiness.UI_TARGETS[name] == "feeds/sources"

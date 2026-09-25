"""Migrations 0095 and 0096 (F8, 2026-09-24): the cause
backfill classifies the stable detail sentences, the webhook address is
withheld by SQL exactly as transports.redact_endpoint withholds it, and
both revisions round-trip. Every schema change here runs inside a
transaction that is rolled back (the test_roles_and_pii_pg.py pattern), so
the database the rest of the suite uses never sees the intermediate state.

Env-gated on DATABASE_URL. Seeds rows under the prefix `nmig-`.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from outbound_support import DATABASE_URL, make_user, teardown

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "nmig-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


class _RollBack(Exception):
    pass


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _migration(conn, stem: str):
    path = next(VERSIONS.glob(f"{stem}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run = lambda sql: conn.execute(sql)
    return module


#: The revisions after 0095, newest first: each must go down before 0095.
_LATER = ("0101", "0100", "0099", "0098", "0097", "0096")

CORPUS = [
    "https://hooks.example.org/T01/B02/secret",
    "https://user:pass@hooks.example.org/hook",
    "https://hooks.example.org:8443/path?token=abc",
    "https://hooks.example.org?token=abc",
    "https://hooks.example.org",
    "https://hooks.example.org/",
    "https://h?",
    "https://Hooks.Example.COM/T0/B1/x",
    "https://[::1]:8443/path",
    "https://hooks.example.org#fragment",
    "not a url at all",
    "https://hooks.example.org/[path withheld: 0123abcd]",
    "[endpoint withheld: 89abcdef]",
    "https://a@b@hooks.example.org/x",
]


def test_the_webhook_redaction_sql_matches_the_python(conn):
    from noctornal_api.transports import redact_endpoint

    m = _migration(conn, "0096")
    for value in CORPUS:
        sql = ("SELECT CASE WHEN " + m.ALREADY.format(col="%(v)s::text") + " THEN %(v)s "
               "ELSE " + m.TWIN.format(col="%(v)s::text") + " END")
        got = conn.execute(sql, {"v": value}).fetchone()[0]
        assert got == redact_endpoint(value), (value, got, redact_endpoint(value))


def test_redaction_is_idempotent():
    from noctornal_api.transports import redact_endpoint
    for value in CORPUS:
        once = redact_endpoint(value)
        assert redact_endpoint(once) == once, value
        assert "secret" not in once and "token" not in once and "pass" not in once


def test_the_cause_backfill_classifies_every_stable_detail(conn):
    from noctornal_api.notifications import NotificationService

    uid, _ = make_user(conn, PREFIX)
    n = NotificationService(conn).notify(
        recipient_id=uid, kind="EVIDENCE_INTEGRITY_ALARM", subject="OP-X: y",
        summary="y", body="y", classification="AMBER")
    seeds = {
        "SMTP": ("SUPPRESSED", "channel disabled by the recipient", 0, "RECIPIENT_DISABLED"),
        "WEBHOOK": ("SUPPRESSED", "priority 3 is below the recipient's threshold for WEBHOOK",
                    0, "BELOW_THRESHOLD"),
        "JIRA": ("SUPPRESSED", "something nobody wrote", 0, "LEGACY"),
    }
    with pytest.raises(_RollBack), conn.transaction():
        for stem in _LATER:
            _migration(conn, stem).downgrade()
        first = _migration(conn, "0095")
        first.downgrade()
        for channel, (state, detail, attempts, _cause) in seeds.items():
            conn.execute("UPDATE notify.delivery SET state = %s, detail = %s, attempts = %s "
                         "WHERE notification_id = %s AND channel = %s",
                         (state, detail, attempts, n.id, channel))
        first.upgrade()
        for channel, (_s, _d, _a, cause) in seeds.items():
            got = conn.execute("SELECT cause, queued_at FROM notify.delivery "
                               "WHERE notification_id = %s AND channel = %s",
                               (n.id, channel)).fetchone()
            assert got[0] == cause, (channel, got)
            assert got[1] is not None
        raise _RollBack()


def test_the_revoked_detail_and_the_other_states_backfill(conn):
    from noctornal_api.notifications import NotificationService

    uid, _ = make_user(conn, PREFIX)
    made = []
    for _ in range(3):
        made.append(NotificationService(conn).notify(
            recipient_id=uid, kind="EVIDENCE_INTEGRITY_ALARM", subject="OP-X: y",
            summary="y", body="y", classification="AMBER"))
    with pytest.raises(_RollBack), conn.transaction():
        for stem in _LATER:
            _migration(conn, stem).downgrade()
        first = _migration(conn, "0095")
        first.downgrade()
        conn.execute("UPDATE notify.delivery SET state = 'SUPPRESSED', detail = "
                     "'the recipient may no longer read this notification: x', "
                     "last_attempt_at = now() WHERE notification_id = %s AND channel = 'SMTP'",
                     (made[0].id,))
        conn.execute("UPDATE notify.delivery SET state = 'REFUSED', redacted = true, "
                     "detail = 'above_destination_ceiling', attempts = 1, "
                     "last_attempt_at = now() WHERE notification_id = %s AND channel = 'SMTP'",
                     (made[1].id,))
        conn.execute("UPDATE notify.delivery SET state = 'FAILED', attempts = 5, "
                     "last_attempt_at = now(), detail = 'gave up' "
                     "WHERE notification_id = %s AND channel = 'SMTP'", (made[2].id,))
        first.upgrade()
        got = [conn.execute("SELECT cause, exposure FROM notify.delivery WHERE "
                            "notification_id = %s AND channel = 'SMTP'", (m.id,)).fetchone()
               for m in made]
        assert got == [("REVOKED", None), ("EGRESS_REFUSED", "STUB"), ("GAVE_UP", None)]
        raise _RollBack()


def test_the_ledger_revisions_round_trip(conn):
    with pytest.raises(_RollBack), conn.transaction():
        for stem in _LATER:
            _migration(conn, stem).downgrade()
        first = _migration(conn, "0095")
        first.downgrade()
        assert conn.execute(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'notify' "
            "AND table_name = 'delivery' AND column_name IN ('cause', 'exposure', "
            "'queued_at')").fetchone()[0] == 0
        first.upgrade()
        for stem in reversed(_LATER):
            _migration(conn, stem).upgrade()
        assert conn.execute("SELECT to_regclass('ingest.lookup_batch')").fetchone()[0]
        raise _RollBack()


def test_the_causes_in_code_and_in_the_schema_agree(conn):
    from noctornal_api.transports import CAUSES
    m = _migration(conn, "0095")
    assert tuple(m.CAUSES) == tuple(CAUSES)

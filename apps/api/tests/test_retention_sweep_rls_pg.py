"""The sweep as the system role it runs as (docs/17 F30, 2026-10-02; S1).

`scripts/retention_sweep.py` opens `connect_system(SystemPurpose.RETENTION)`,
the BYPASSRLS role that owns nothing. These run the script's own `main` with
no connection handed in, so it connects as that role, and hold three things
the owner-connection suite cannot: a document no request-role reader can see
(RED, in a compartment) is still counted and destroyed, because a sweep that
silently saw part of the data would report success; the role holds every
privilege the run needs (the account lookup, the purge, its tombstone, its
audit row); and the readiness row counts across the deployment from the
register's system connection.

Gated like the other row-security tests (NOCTORNAL_APP_DB_ROLE). Account and
source prefix `rlsw-`.
"""
from __future__ import annotations

import importlib.util
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "rlsw-"
KEY = "RLS-SWEEP-K"
REFERENCE = "RETSCHED-2026-014"
SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "retention_sweep.py"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV

    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    monkeypatch.setenv("NOCTORNAL_RETENTION_SWEEP_AUTHORITY", REFERENCE)
    monkeypatch.delenv("NOCTORNAL_RETENTION_SWEEP_ACTOR", raising=False)
    c = s.owner_conn()
    s.register(c, KEY)
    yield c
    sources = f"(SELECT id FROM collect.source WHERE name LIKE '{PREFIX}%')"
    with c.transaction():
        c.execute(f"DELETE FROM collect.document WHERE source_id IN {sources}")
        c.execute(f"DELETE FROM collect.source WHERE name LIKE '{PREFIX}%'")
    s.cleanup(c, PREFIX)
    c.close()


def _script():
    spec = importlib.util.spec_from_file_location("retention_sweep_rls_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _admin(owner) -> tuple[UUID, str]:
    uid = s.user(owner, clearance="RED", prefix=PREFIX)
    s.grant_global(owner, uid, "SYS_ADMIN")
    email = owner.execute("SELECT email FROM iam.app_user WHERE id = %s",
                          (uid,)).fetchone()[0]
    return uid, email


def _hidden_document(owner, *, past=True) -> UUID:
    """A RED document in a compartment: above every request-role reader this
    database holds an account for."""
    source = owner.execute(
        """INSERT INTO collect.source (kind, name, default_reliability, classification)
           VALUES ('XENFORO'::collect.source_kind, %s, 'F', 'RED') RETURNING id""",
        (f"{PREFIX}{uuid4().hex[:8]}",)).fetchone()[0]
    when = datetime.now(timezone.utc) + timedelta(days=-1 if past else 30)
    return owner.execute(
        """INSERT INTO collect.document
               (source_id, title, body_text, content_sha256, classification,
                compartments, retain_until, category)
           VALUES (%s, %s, 'words nobody cleared may read', %s, 'RED', %s, %s,
                   'CHAT_EXPORT') RETURNING id""",
        (source, f"{PREFIX}{uuid4().hex[:8]}", os.urandom(32), [KEY], when)
    ).fetchone()[0]


def test_the_script_as_the_system_role_destroys_a_document_no_reader_may_see(owner):
    uid, email = _admin(owner)
    doc = _hidden_document(owner)
    app = s.app_conn()
    try:
        assert s.count(app, "SELECT count(*) FROM collect.document WHERE id = %s",
                       (doc,)) == 0, "the request role sees nothing of it"
    finally:
        app.close()

    code = _script().main(["--apply", "--actor", email], document_raw=None)

    assert code == 0
    purged, body = owner.execute(
        "SELECT purged_at IS NOT NULL, body_text FROM collect.document WHERE id = %s",
        (doc,)).fetchone()
    assert purged and body == ""
    stone = owner.execute(
        "SELECT object_type, authority FROM core.purge_tombstone "
        "WHERE purged_by = %s", (uid,)).fetchall()
    assert stone and all(t == "document" and REFERENCE in a for t, a in stone)
    event = owner.execute(
        "SELECT detail FROM audit.event WHERE action = 'RETENTION_SWEEP' "
        "AND actor_id = %s", (uid,)).fetchone()[0]
    assert event["authority"] == REFERENCE and event["documents_purged"] >= 1


def test_the_dry_run_as_the_system_role_counts_a_document_no_reader_may_see(
        owner, capsys):
    _admin(owner)
    first = _script()
    assert first.main([], document_raw=None) == 0
    before = capsys.readouterr().out.splitlines()[0]
    _hidden_document(owner)
    assert first.main([], document_raw=None) == 0
    after = capsys.readouterr().out.splitlines()[0]

    def counters(line):
        return {k: int(v) for k, v in (p.split("=") for p in line.split()[1:])}

    assert counters(after)["sweepable"] - counters(before)["sweepable"] == 1


def test_the_readiness_row_counts_across_the_deployment_from_the_system_connection(
        owner):
    """Asked on a request-role connection that sees no document at all, the
    row still counts the one document that is past its clock."""
    from noctornal_api import readiness

    app = s.app_conn()
    try:
        before = readiness.check("retention_sweep_current", app)
        _hidden_document(owner)
        after = readiness.check("retention_sweep_current", app)
    finally:
        app.close()
    assert after.evidence != before.evidence
    assert "past its retention clock" in after.evidence or (
        "past their retention clock" in after.evidence)
    assert not after.evidence.startswith("No collected document")

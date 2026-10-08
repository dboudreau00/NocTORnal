"""The Lab custody ledger's sequence is its trigger's alone (0175).

`SELECT last_value FROM lab.sample_access_id_seq` read the volume of the
Lab's custody ledger, every sample's, to any request-role connection, bound
or not. The number is now drawn by a definer trigger and neither runtime
role holds the sequence, as 0169 did for the audit and custody chains.
Gated like the other row-security tests. Account prefix `rlsseq-`.
"""
from __future__ import annotations

import psycopg
import pytest

import rls_support as s
from lab_static_fixtures import MemoryStore, make_user, token
from screening_fixtures import assert_scrubbed, declare, payload, scrub

pytestmark = s.GATED

PREFIX = "rlsseq-"
SEQUENCE = "lab.sample_access_id_seq"


@pytest.fixture
def conn(monkeypatch):
    declare(monkeypatch)
    c = s.owner_conn()
    yield c
    scrub(c, PREFIX)
    assert_scrubbed(c, PREFIX)
    c.close()


@pytest.fixture
def store(monkeypatch):
    import noctornal_api.samples as samples
    memory = MemoryStore()
    monkeypatch.setattr(samples, "SampleStorage", lambda: memory)
    return memory


@pytest.mark.parametrize("statement", [
    f"SELECT last_value FROM {SEQUENCE}",
    f"SELECT nextval('{SEQUENCE}')",
    f"SELECT currval('{SEQUENCE}')",
], ids=["last_value", "nextval", "currval"])
@pytest.mark.parametrize("bound", [False, True], ids=["unbound", "bound"])
def test_the_request_role_cannot_read_the_ledgers_volume(conn, statement, bound):
    who = make_user(conn, PREFIX, roles=("MALWARE_ANALYST",), clearance="AMBER")
    app = s.app_conn(token(conn, who) if bound else None)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(statement)
    finally:
        app.close()


def test_neither_runtime_role_holds_the_sequence_and_it_has_no_default(conn):
    for role in (s.APP_ROLE, s.WORKER_ROLE):
        for privilege in ("USAGE", "SELECT", "UPDATE"):
            assert not conn.execute("SELECT has_sequence_privilege(%s, %s, %s)",
                                    (role, SEQUENCE, privilege)).fetchone()[0], (role, privilege)
    default = conn.execute(
        "SELECT column_default FROM information_schema.columns WHERE table_schema = 'lab' "
        "AND table_name = 'sample_access' AND column_name = 'id'").fetchone()[0]
    assert default is None


def test_a_custody_row_written_by_the_request_role_is_still_numbered(conn, store):
    from noctornal_api.samples import SampleService
    analyst = make_user(conn, PREFIX, roles=("MALWARE_ANALYST",), clearance="AMBER")
    sample = SampleService(conn, store).submit(payload("seq"), submitted_by=analyst)
    before = conn.execute("SELECT coalesce(max(id), 0) FROM lab.sample_access").fetchone()[0]
    app = s.app_conn(token(conn, analyst))
    try:
        SampleService(app, store)._access(sample.id, analyst, "VIEWED_META", {"why": "seq test"})
    finally:
        app.close()
    rows = conn.execute(
        "SELECT id FROM lab.sample_access WHERE sample_id = %s AND action = 'VIEWED_META' "
        "AND detail ->> 'why' = 'seq test'", (sample.id,)).fetchall()
    assert len(rows) == 1 and rows[0][0] > before


def test_a_number_the_caller_supplies_is_replaced(conn, store):
    from noctornal_api.samples import SampleService
    analyst = make_user(conn, PREFIX, roles=("MALWARE_ANALYST",), clearance="AMBER")
    sample = SampleService(conn, store).submit(payload("seq-own"), submitted_by=analyst)
    app = s.app_conn(token(conn, analyst))
    try:
        app.execute("INSERT INTO lab.sample_access (id, sample_id, actor_id, actor_kind, action) "
                    "VALUES (1, %s, %s, 'USER', 'VIEWED_META')", (sample.id, analyst))
    finally:
        app.close()
    ids = [r[0] for r in conn.execute(
        "SELECT id FROM lab.sample_access WHERE sample_id = %s AND action = 'VIEWED_META'",
        (sample.id,)).fetchall()]
    assert ids and 1 not in ids

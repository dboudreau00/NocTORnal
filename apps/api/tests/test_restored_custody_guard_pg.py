"""A restore's custody row, and who may write one (0198 and 0199, decision 240).

A `RESTORED` row on `core.evidence_custody` says where an exhibit's verified bytes now live, and
`core.evidence_current_version` resolves the version a read asks for from it. A preserved sample's is a
`RESTORED` row on `lab.sample_access` and `lab.sample_current_preserved_version`. Because a row redirects
reads, it is written only by an exempt caller (the system role the restore job connects as, or the schema
owner), only naming the new version and only attesting a verified copy, and the guard fires before the
ledger's own trigger.

What would catch a regression: a request-role connection that writes a `RESTORED` row for an exhibit or
a sample it can see; a row that names no version or attests no verification; the guard sorting after
`custody_chain` or `sample_access_numbered`; a function that follows an older row, or that answers a
caller who cannot see the object; a downgrade that runs over a database holding a restore.

Every row the tests write is made in a transaction that is rolled back, except the request role's, which
is refused and so writes none. Account prefix `rstc-`.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Json

import rls_support as s
from rolled_back import rolled_back

pytestmark = s.GATED

PREFIX = "rstc-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


def _migration():
    path = next(VERSIONS.glob("0198_*.py"))
    spec = importlib.util.spec_from_file_location(f"m0198_{uuid4().hex[:6]}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _restored(conn, evidence_id, actor, *, version="v-new", verified=True, detail=None):
    detail = ({"new_version_id": version, "old_version_id": "v-old"}
              if detail is None else detail)
    conn.execute(
        "INSERT INTO core.evidence_custody (evidence_id, action, actor_id, detail, hash_verified) "
        "VALUES (%s, 'RESTORED', %s, %s, %s)", (evidence_id, actor, Json(detail), verified))


@pytest.fixture
def seeded():
    with rolled_back() as conn:
        boss = s.user(conn, "AMBER", prefix=PREFIX)
        case_id = s.case(conn, boss)
        yield conn, boss, s.exhibit(conn, case_id, boss)


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    s.cleanup(c, PREFIX)
    c.close()


def _count(conn, evidence_id) -> int:
    return conn.execute(
        "SELECT count(*) FROM core.evidence_custody WHERE evidence_id = %s AND action = 'RESTORED'",
        (evidence_id,)).fetchone()[0]


def test_only_an_exempt_caller_may_write_a_restored_row(owner):
    """The request role sees the exhibit and may append a custody row naming itself, so without the guard
    it could point the exhibit's reads at a version of its choosing. The system role and the owner may."""
    boss = s.user(owner, "AMBER", prefix=PREFIX)
    ev = s.exhibit(owner, s.case(owner, boss), boss)
    _sid, raw = s.session(owner, boss)
    app = s.app_conn(raw)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="restore job"):
            _restored(app, ev, boss)
    finally:
        app.close()
    assert _count(owner, ev) == 0, "the request role's RESTORED row was stored"
    # Another custody action is still the request role's to write, so the guard is the row's own.
    app = s.app_conn(raw)
    try:
        app.execute("INSERT INTO core.evidence_custody (evidence_id, action, actor_id) "
                    "VALUES (%s, 'VIEWED', %s)", (ev, boss))
    finally:
        app.close()


def test_the_system_role_and_the_owner_may_write_a_restored_row(seeded):
    conn, boss, ev = seeded
    _restored(conn, ev, boss)
    conn.execute(f"SET LOCAL ROLE {s.WORKER_ROLE}")
    try:
        _restored(conn, ev, boss, version="v-newer")
    finally:
        conn.execute("RESET ROLE")
    assert _count(conn, ev) == 2


def test_a_restored_row_names_the_new_version_and_attests_a_read_back(seeded):
    conn, boss, ev = seeded
    for kwargs, words in (({"detail": {"old_version_id": "v-old"}}, "new_version_id"),
                          ({"verified": False}, "read-back"),
                          ({"verified": None}, "read-back")):
        with pytest.raises(psycopg.errors.CheckViolation, match=words), conn.transaction():
            _restored(conn, ev, boss, **kwargs)
    assert _count(conn, ev) == 0


def test_the_guard_fires_before_the_custody_chain_trigger(seeded):
    """A refused row must not have taken the chain's lock or drawn a number: triggers of one event run in
    name order, so the guard's name sorts first, and a refusal leaves the ledger's tail where it was."""
    conn, boss, ev = seeded
    names = [r[0] for r in conn.execute(
        """SELECT tgname FROM pg_trigger
            WHERE tgrelid = 'core.evidence_custody'::regclass AND NOT tgisinternal
              AND (tgtype & 2) = 2 AND (tgtype & 4) = 4 AND (tgtype & 1) = 1
            ORDER BY tgname""").fetchall()]
    assert names.index("custody_a_restored_exempt_only") < names.index("custody_chain"), names
    tail = conn.execute("SELECT max(id) FROM core.evidence_custody").fetchone()[0]
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        _restored(conn, ev, boss, verified=False)
    assert conn.execute("SELECT max(id) FROM core.evidence_custody").fetchone()[0] == tail


def test_the_current_version_is_the_newest_restored_row_else_the_lodged_one(seeded):
    conn, boss, ev = seeded
    current = "SELECT core.evidence_current_version(%s)"
    assert conn.execute(current, (ev,)).fetchone()[0] is None
    conn.execute("UPDATE core.evidence SET storage_version_id = 'lodged' WHERE id = %s", (ev,))
    assert conn.execute(current, (ev,)).fetchone()[0] == "lodged"
    _restored(conn, ev, boss, version="first")
    assert conn.execute(current, (ev,)).fetchone()[0] == "first"
    _restored(conn, ev, boss, version="second")
    assert conn.execute(current, (ev,)).fetchone()[0] == "second"
    # A store that keeps no versions gave none: reads take the latest, not the lodged version it never held.
    _restored(conn, ev, boss, detail={"new_version_id": None, "old_version_id": "lodged"})
    assert conn.execute(current, (ev,)).fetchone()[0] is None
    # The lodged version stays on the row throughout: a restore never writes the exhibit.
    assert conn.execute("SELECT storage_version_id FROM core.evidence WHERE id = %s",
                        (ev,)).fetchone()[0] == "lodged"
    assert conn.execute(current, (uuid4(),)).fetchone()[0] is None


def test_the_current_version_is_answered_only_to_a_caller_who_can_see_the_exhibit(owner):
    boss = s.user(owner, "AMBER", prefix=PREFIX)
    stranger = s.user(owner, "AMBER", prefix=PREFIX)
    ev = s.exhibit(owner, s.case(owner, boss), boss)
    owner.execute("UPDATE core.evidence SET storage_version_id = 'lodged' WHERE id = %s", (ev,))
    answers = {}
    for who in (boss, stranger):
        _sid, raw = s.session(owner, who)
        app = s.app_conn(raw)
        try:
            answers[who] = app.execute("SELECT core.evidence_current_version(%s)",
                                       (ev,)).fetchone()[0]
        finally:
            app.close()
    assert answers == {boss: "lodged", stranger: None}


def test_the_request_role_may_call_the_current_version_function(owner):
    assert owner.execute(
        "SELECT has_function_privilege(%s, 'core.evidence_current_version(uuid)', 'EXECUTE')",
        (s.APP_ROLE,)).fetchone()[0] is True


def test_a_downgrade_over_a_restored_exhibit_names_a_count_and_changes_nothing(seeded):
    conn, boss, ev = seeded
    m = _migration()
    ran: list = []
    m.query = lambda sql: conn.execute(sql).fetchall()
    m.run = ran.append
    _restored(conn, ev, boss, version="a-version-id-that-must-not-be-printed")
    count = conn.execute(m.COUNT_SQL).fetchone()[0]
    assert count >= 1
    with pytest.raises(RuntimeError) as refused:
        m.downgrade()
    assert ran == []
    text = str(refused.value)
    assert text.startswith("refusing to downgrade 0198:") and str(count) in text
    assert "a-version-id-that-must-not-be-printed" not in text and str(ev) not in text


def test_a_downgrade_of_an_empty_database_drops_the_guard_and_the_function():
    m = _migration()
    ran: list = []
    m.query = lambda sql: [(0,)]
    m.run = ran.append
    m.downgrade()
    assert ran == [m.DOWNGRADE_SQL]
    for name in ("custody_a_restored_exempt_only", "guard_custody_restored", "evidence_current_version"):
        assert name in m.DOWNGRADE_SQL


# ---------------------------------------------------------------------------
# The sample side (0199)
# ---------------------------------------------------------------------------

def _migration_0199():
    path = next(VERSIONS.glob("0199_*.py"))
    spec = importlib.util.spec_from_file_location(f"m0199_{uuid4().hex[:6]}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sample(conn, case_id, actor, *, version="held-v1", classification="AMBER"):
    """A rejected, preserved sample row, as rejection leaves one."""
    import os

    from noctornal_api.security import envelope
    blob, key_id = envelope.encrypt(os.urandom(32).hex())
    return conn.execute(
        """INSERT INTO lab.sample
               (case_id, sha256, byte_size, storage_key, storage_bucket, data_key_ciphertext,
                data_key_id, submitted_by, state, reject_reason, preserved_bucket, preserved_key,
                preserved_version_id, preserved_at, classification)
           VALUES (%s, %s, 4, %s, 'b', %s, %s, %s, 'REJECTED', 'test', 'held', %s, %s, now(), %s)
           RETURNING id""",
        (case_id, os.urandom(32), f"w/{uuid4().hex}", blob, key_id, actor,
         f"p/{uuid4().hex}", version, classification)).fetchone()[0]


def _sample_restored(conn, sample_id, actor, *, version="held-v2", detail=None,
                     actor_kind="USER"):
    detail = ({"new_version_id": version, "old_version_id": "held-v1", "verified": True,
               "hold_confirmed": True} if detail is None else detail)
    conn.execute(
        "INSERT INTO lab.sample_access (sample_id, actor_id, actor_kind, action, detail) "
        "VALUES (%s, %s, %s, 'RESTORED', %s)",
        (sample_id, actor if actor_kind == "USER" else None, actor_kind, Json(detail)))


@pytest.fixture
def seeded_sample():
    with rolled_back() as conn:
        boss = s.user(conn, "AMBER", prefix=PREFIX)
        case_id = s.case(conn, boss)
        yield conn, boss, _sample(conn, case_id, boss)


def _sample_count(conn, sample_id) -> int:
    return conn.execute(
        "SELECT count(*) FROM lab.sample_access WHERE sample_id = %s AND action = 'RESTORED'",
        (sample_id,)).fetchone()[0]


def test_only_an_exempt_caller_may_write_a_restored_sample_row(owner):
    boss = s.user(owner, "AMBER", prefix=PREFIX)
    sample = _sample(owner, s.case(owner, boss), boss)
    _sid, raw = s.session(owner, boss)
    app = s.app_conn(raw)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="restore job"):
            _sample_restored(app, sample, boss)
    finally:
        app.close()
    assert _sample_count(owner, sample) == 0, "the request role's RESTORED row was stored"
    owner.execute("DELETE FROM lab.sample WHERE id = %s", (sample,))


def test_the_system_role_and_the_owner_may_write_a_restored_sample_row(seeded_sample):
    conn, boss, sample = seeded_sample
    _sample_restored(conn, sample, boss)
    conn.execute(f"SET LOCAL ROLE {s.WORKER_ROLE}")
    try:
        _sample_restored(conn, sample, boss, version="held-v3")
    finally:
        conn.execute("RESET ROLE")
    assert _sample_count(conn, sample) == 2


def test_a_restored_sample_row_names_the_new_version_and_attests_a_held_copy(seeded_sample):
    conn, boss, sample = seeded_sample
    held = {"new_version_id": "v", "verified": True, "hold_confirmed": True}
    for detail, words in (
            ({"verified": True, "hold_confirmed": True}, "new_version_id"),
            ({**held, "verified": False}, "legal hold"),
            ({**held, "hold_confirmed": False}, "legal hold"),
            ({"new_version_id": "v"}, "legal hold")):
        with pytest.raises(psycopg.errors.CheckViolation, match=words), conn.transaction():
            _sample_restored(conn, sample, boss, detail=detail)
    assert _sample_count(conn, sample) == 0


def test_a_restore_is_never_a_system_row_naming_nobody(seeded_sample):
    """`sample_access_system_actions` is untouched: RESTORED stays a USER action, so a restore always names
    the account that answers for it."""
    conn, boss, sample = seeded_sample
    with pytest.raises(psycopg.errors.CheckViolation, match="sample_access_system_actions"), \
            conn.transaction():
        _sample_restored(conn, sample, boss, actor_kind="SYSTEM")


def test_the_sample_guard_fires_before_the_ledgers_own_trigger(seeded_sample):
    conn, boss, sample = seeded_sample
    names = [r[0] for r in conn.execute(
        """SELECT tgname FROM pg_trigger
            WHERE tgrelid = 'lab.sample_access'::regclass AND NOT tgisinternal
              AND (tgtype & 2) = 2 AND (tgtype & 4) = 4 AND (tgtype & 1) = 1
            ORDER BY tgname""").fetchall()]
    assert names.index("sample_access_a_restored_exempt_only") < names.index(
        "sample_access_numbered"), names


def test_the_action_set_is_closed_and_now_holds_restored_beside_its_eight(seeded_sample):
    conn, boss, sample = seeded_sample
    with pytest.raises(psycopg.errors.CheckViolation, match="sample_access_action_known"), \
            conn.transaction():
        conn.execute("INSERT INTO lab.sample_access (sample_id, actor_id, action) "
                     "VALUES (%s, %s, 'REWOUND')", (sample, boss))
    for action in ("VIEWED_META", "DOWNLOADED", "SHARED", "DETONATED", "REJECTED", "ASSIGNED",
                   "ANALYSED", "SCANNED"):
        with conn.transaction():
            conn.execute("INSERT INTO lab.sample_access (sample_id, actor_id, action) "
                         "VALUES (%s, %s, %s)", (sample, boss, action))


def test_the_current_preserved_version_is_the_newest_restored_row_else_the_preserved_one(
        seeded_sample):
    conn, boss, sample = seeded_sample
    current = "SELECT lab.sample_current_preserved_version(%s)"
    assert conn.execute(current, (sample,)).fetchone()[0] == "held-v1"
    _sample_restored(conn, sample, boss, version="first")
    assert conn.execute(current, (sample,)).fetchone()[0] == "first"
    _sample_restored(conn, sample, boss, version="second")
    assert conn.execute(current, (sample,)).fetchone()[0] == "second"
    assert conn.execute("SELECT preserved_version_id FROM lab.sample WHERE id = %s",
                        (sample,)).fetchone()[0] == "held-v1"
    assert conn.execute(current, (uuid4(),)).fetchone()[0] is None


def test_the_current_preserved_version_is_answered_only_to_a_caller_who_can_see_the_sample(owner):
    # Row security shows a sample by its labels and its case's reach, so the stranger is below its label.
    boss = s.user(owner, "RED", prefix=PREFIX)
    stranger = s.user(owner, "AMBER", prefix=PREFIX)
    sample = _sample(owner, s.case(owner, boss), boss, classification="RED")
    answers = {}
    for who in (boss, stranger):
        _sid, raw = s.session(owner, who)
        app = s.app_conn(raw)
        try:
            answers[who] = app.execute("SELECT lab.sample_current_preserved_version(%s)",
                                       (sample,)).fetchone()[0]
        finally:
            app.close()
    owner.execute("DELETE FROM lab.sample WHERE id = %s", (sample,))
    assert answers == {boss: "held-v1", stranger: None}


def test_the_request_role_may_call_the_current_preserved_version_function(owner):
    assert owner.execute(
        "SELECT has_function_privilege(%s, 'lab.sample_current_preserved_version(uuid)', "
        "'EXECUTE')", (s.APP_ROLE,)).fetchone()[0] is True


def test_a_downgrade_over_a_restored_sample_names_a_count_and_changes_nothing(seeded_sample):
    conn, boss, sample = seeded_sample
    m = _migration_0199()
    ran: list = []
    m.query = lambda sql: conn.execute(sql).fetchall()
    m.run = ran.append
    _sample_restored(conn, sample, boss, version="a-held-version-that-must-not-be-printed")
    count = conn.execute(m.COUNT_SQL).fetchone()[0]
    assert count >= 1
    with pytest.raises(RuntimeError) as refused:
        m.downgrade()
    assert ran == []
    text = str(refused.value)
    assert text.startswith("refusing to downgrade 0199:") and str(count) in text
    assert "a-held-version-that-must-not-be-printed" not in text and str(sample) not in text


def test_a_downgrade_of_an_empty_database_restores_the_eight_action_set():
    m = _migration_0199()
    ran: list = []
    m.query = lambda sql: [(0,)]
    m.run = ran.append
    m.downgrade()
    assert ran == [m.DOWNGRADE_SQL]
    assert "'RESTORED'" not in m.DOWNGRADE_SQL.split("ADD CONSTRAINT")[1]
    assert m.DOWNGRADE_SQL.count("'SCANNED'") == 1

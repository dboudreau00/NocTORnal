"""The collected-document sweep, scripts/retention_sweep.py (docs/17 F30,
2026-10-02; docs/00 decisions 171 to 173).

A group chat's third-party messages are collected documents with a retention
clock, and until this sweep nothing destroyed them when it ran out: the
governance purge is case-scoped and a document belongs to no case. These hold
the sweep to the purge it reuses and to its own rules: every legal hold
exactly as `purge_due` honours it (on the document, on a case citing any
version of it, and the pin of an unretracted assertion), a dry run that
touches nothing, a real run that destroys only the past-due, a second run
that is a no-op, a refusal for a missing declaration or a missing account, a
backlog cleared in one run, a store that refuses leaving the document due, and
one audit row of counts.

The documents of other suites that happen to be past their clock are the
sweep's too (it is deployment-wide), so counts are read as differences from a
baseline and every document is read by its own id.

DATABASE_URL-gated.
"""
from __future__ import annotations

import importlib.util
import json
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-rsweep-"
SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "retention_sweep.py"
REFERENCE = "RETSCHED-2026-014"
BODY = "third party words nobody should keep"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    h.refuse_remote_sockets(monkeypatch)
    monkeypatch.setenv("NOCTORNAL_RETENTION_SWEEP_AUTHORITY", REFERENCE)
    monkeypatch.delenv("NOCTORNAL_RETENTION_SWEEP_ACTOR", raising=False)
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%')"
    with c.transaction():
        c.execute(f"""UPDATE core."case" SET legal_hold = false, legal_hold_reason = NULL
                       WHERE owner_user_id IN {sub}""")
        c.execute("DELETE FROM ingest.dead_letter WHERE error_class = 'rsweep-test'")
        c.execute(f"""DELETE FROM collect.proposal WHERE case_id IN
                        (SELECT id FROM core."case" WHERE owner_user_id IN {sub})""")
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def actor(conn):
    uid, email = h.user(conn, P, roles=("SYS_ADMIN",))
    return uid, email


@pytest.fixture
def store():
    from noctornal_api.rawstore import InMemoryDocumentRawStorage

    return InMemoryDocumentRawStorage()


def _script():
    spec = importlib.util.spec_from_file_location("retention_sweep_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _source(conn):
    return h.source(conn, P, kind="RSS", parser="rss", due=False)


def _doc(conn, source, *, due=True, clock=True, key=None, ext=None, version=1,
         supersedes=None):
    now = datetime.now(timezone.utc)
    when = None if not clock else (now - timedelta(days=1) if due
                                   else now + timedelta(days=30))
    return conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, body_text, content_sha256, version,
                supersedes_id, retain_until, body_html_key, title,
                external_url, author_handle, author_uid, category)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'a title',
                   'https://chat.example.test/c/1', 'vendor_x', 'u:99',
                   'CHAT_EXPORT')
           RETURNING id""",
        (source, ext or f"m:{uuid4().hex[:8]}", BODY, os.urandom(32), version,
         supersedes, when, key)).fetchone()[0]


def _state(conn, doc):
    """(purged, body_text, author_handle) of one document."""
    row = conn.execute(
        "SELECT purged_at IS NOT NULL, body_text, author_handle "
        "FROM collect.document WHERE id = %s", (doc,)).fetchone()
    return row[0], row[1], row[2]


def _purged(conn, doc):
    return _state(conn, doc)[0]


def _case(conn, owner, *, hold=False):
    from noctornal_api.cases import CaseService

    case = CaseService(conn).create(
        code=f"OP-RSW-{uuid4().hex[:6]}", title="sweep", legal_basis="production order",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner)
    if hold:
        _hold_case(conn, case, True)
    return case


def _hold_case(conn, case, on):
    conn.execute('UPDATE core."case" SET legal_hold = %s, legal_hold_reason = %s '
                 "WHERE id = %s", (on, "court order 2026-77" if on else None, case))


def _hold_doc(conn, doc):
    conn.execute("""UPDATE collect.document SET legal_hold = true,
                           legal_hold_reason = 'court order 7' WHERE id = %s""", (doc,))


def _assertion(conn, case, owner, doc, *, retracted):
    node = uuid4()
    with conn.transaction():
        conn.execute("""INSERT INTO core.node (id, case_id, node_type, label, created_by)
                        VALUES (%s, %s, 'IDENTITY', %s, %s)""",
                     (node, case, f"rsw-{node.hex[:6]}", owner))
        conn.execute("""INSERT INTO core.assertion
                            (case_id, node_id, basis, created_by, document_id,
                             retracted_at)
                        VALUES (%s, %s, 'DIRECT_OBSERVATION', %s, %s, %s)""",
                     (case, node, owner, doc,
                      datetime.now(timezone.utc) if retracted else None))


def _proposal(conn, case, doc):
    conn.execute("""INSERT INTO collect.proposal
                        (case_id, kind, payload, origin, rationale, document_id)
                    VALUES (%s, 'NODE', '{}', 'rs', 'a reason', %s)""", (case, doc))


def _run(conn, store, email, *flags, capsys=None):
    """The script's main on this connection and store: (exit code, stdout,
    stderr)."""
    module = _script()
    code = module.main([*flags, *(["--actor", email] if email else [])],
                       conn=conn, document_raw=store)
    out = capsys.readouterr() if capsys else None
    return code, (out.out if out else ""), (out.err if out else "")


def _counters(out: str) -> dict:
    first = out.splitlines()[0]
    return {k: (int(v) if v.lstrip("-").isdigit() else v)
            for k, v in (pair.split("=", 1) for pair in first.split())}


def _tombstones(conn, uid):
    return conn.execute(
        """SELECT object_type, object_count, authority, purged_by
             FROM core.purge_tombstone WHERE purged_by = %s ORDER BY purged_at""",
        (uid,)).fetchall()


def _events(conn, uid):
    return [r[0] for r in conn.execute(
        "SELECT detail FROM audit.event WHERE action = 'RETENTION_SWEEP' "
        "AND actor_id = %s ORDER BY seq", (uid,)).fetchall()]


def _global_counts(conn):
    return (conn.execute("SELECT count(*) FROM audit.event").fetchone()[0],
            conn.execute("SELECT count(*) FROM core.purge_tombstone").fetchone()[0])


# --- the dry run -------------------------------------------------------------

def test_a_dry_run_touches_nothing(conn, actor, store, capsys):
    uid, email = actor
    source = _source(conn)
    base_code, base_out, _ = _run(conn, store, None, capsys=capsys)
    assert base_code == 0
    base = _counters(base_out)
    assert base["mode"] == "dry-run"

    key = "collect/aa/" + uuid4().hex
    store.put(key, b"<p>markup</p>")
    due_a = _doc(conn, source, key=key)
    due_b = _doc(conn, source)
    held = _doc(conn, source)
    _hold_doc(conn, held)
    later = _doc(conn, source, due=False)
    unclocked = _doc(conn, source, clock=False)
    before_rows = conn.execute(
        "SELECT id, purged_at, body_text, body_html_key, retain_until "
        "FROM collect.document WHERE source_id IN "
        "(SELECT id FROM collect.source WHERE name LIKE %s) ORDER BY id",
        (f"{P}%",)).fetchall()
    before_totals = _global_counts(conn)

    code, out, err = _run(conn, store, None, capsys=capsys)
    after = _counters(out)

    assert code == 0 and err == ""
    assert after["mode"] == "dry-run"
    assert after["past_clock"] - base["past_clock"] == 3
    assert after["sweepable"] - base["sweepable"] == 2
    assert after["held"] - base["held"] == 1
    assert "dry run: nothing was changed" in out
    assert conn.execute(
        "SELECT id, purged_at, body_text, body_html_key, retain_until "
        "FROM collect.document WHERE source_id IN "
        "(SELECT id FROM collect.source WHERE name LIKE %s) ORDER BY id",
        (f"{P}%",)).fetchall() == before_rows
    assert store.exists(key), "a dry run deletes no markup"
    assert _global_counts(conn) == before_totals, (
        "a dry run writes no tombstone and no audit row, not even its own")
    for doc in (due_a, due_b, held, later, unclocked):
        assert not _purged(conn, doc)


def test_the_dry_run_needs_no_declaration_and_no_account(conn, store, capsys,
                                                         monkeypatch):
    monkeypatch.delenv("NOCTORNAL_RETENTION_SWEEP_AUTHORITY")
    code, out, err = _run(conn, store, None, capsys=capsys)
    assert code == 0 and err == "" and _counters(out)["mode"] == "dry-run"


# --- the real run ------------------------------------------------------------

def test_a_real_run_destroys_only_what_is_past_due_and_not_held(conn, actor, store,
                                                                 capsys):
    uid, email = actor
    source = _source(conn)
    key = "collect/bb/" + uuid4().hex
    store.put(key, b"<p>markup</p>")
    gone_a = _doc(conn, source, key=key)
    gone_b = _doc(conn, source)
    held = _doc(conn, source)
    _hold_doc(conn, held)
    later = _doc(conn, source, due=False)
    unclocked = _doc(conn, source, clock=False)

    code, out, err = _run(conn, store, email, "--apply", capsys=capsys)
    counters = _counters(out)

    assert code == 0 and err == "", (out, err)
    assert counters["mode"] == "apply" and counters["remaining"] == 0
    assert counters["documents_purged"] >= 2 and counters["held"] >= 1
    for doc in (gone_a, gone_b):
        purged, body, handle = _state(conn, doc)
        assert purged and body == "" and handle is None
    for doc in (held, later, unclocked):
        purged, body, handle = _state(conn, doc)
        assert not purged and body == BODY and handle == "vendor_x"
    assert not store.exists(key), "the markup went with its document"
    # The purge's own record: one tombstone per pass, under the declared
    # authority and the named account.
    stones = _tombstones(conn, uid)
    assert stones and {s[0] for s in stones} == {"document"}
    assert sum(s[1] for s in stones) == counters["documents_purged"]
    assert all(REFERENCE in s[2] and s[3] == uid for s in stones)


def test_a_second_run_is_a_no_op(conn, actor, store, capsys):
    uid, email = actor
    source = _source(conn)
    doc = _doc(conn, source)
    first, out, _ = _run(conn, store, email, "--apply", capsys=capsys)
    assert first == 0 and _purged(conn, doc)
    stones_after_first = _tombstones(conn, uid)
    purged_at = conn.execute("SELECT purged_at FROM collect.document WHERE id = %s",
                             (doc,)).fetchone()[0]

    code, out, err = _run(conn, store, email, "--apply", capsys=capsys)
    counters = _counters(out)

    assert code == 0 and err == ""
    assert counters["documents_purged"] == 0 and counters["tombstones"] == 0
    assert counters["remaining"] == 0
    assert _tombstones(conn, uid) == stones_after_first, "nothing was destroyed again"
    assert conn.execute("SELECT purged_at FROM collect.document WHERE id = %s",
                        (doc,)).fetchone()[0] == purged_at
    events = _events(conn, uid)
    assert len(events) == 2, "each real run says it ran, also when nothing was due"
    assert events[1]["documents_purged"] == 0 and events[1]["finished"] is True


# --- every legal hold, as the purge honours them ------------------------------

def test_a_hold_on_the_document_keeps_it(conn, actor, store, capsys):
    uid, email = actor
    doc = _doc(conn, _source(conn))
    _hold_doc(conn, doc)
    code, out, _ = _run(conn, store, email, "--apply", capsys=capsys)
    assert code == 0 and not _purged(conn, doc)
    assert _counters(out)["held"] >= 1


@pytest.mark.parametrize("how", ["proposal", "retracted_assertion"])
def test_a_hold_on_a_case_citing_the_document_keeps_it(conn, actor, store, capsys, how):
    uid, email = actor
    source = _source(conn)
    case = _case(conn, uid, hold=True)
    doc = _doc(conn, source)
    if how == "proposal":
        _proposal(conn, case, doc)
    else:
        _assertion(conn, case, uid, doc, retracted=True)

    code, out, _ = _run(conn, store, email, "--apply", capsys=capsys)
    assert code == 0 and not _purged(conn, doc), how

    _hold_case(conn, case, False)
    code, out, _ = _run(conn, store, email, "--apply", capsys=capsys)
    assert code == 0 and _purged(conn, doc), "the same document goes once the hold lifts"


def test_a_hold_on_an_earlier_version_keeps_the_later_ones(conn, actor, store, capsys):
    """A court naming a post names its history."""
    uid, email = actor
    source = _source(conn)
    v1 = _doc(conn, source, ext="post:7")
    _hold_doc(conn, v1)
    v2 = _doc(conn, source, ext="post:7", version=2, supersedes=v1)
    code, _out, _ = _run(conn, store, email, "--apply", capsys=capsys)
    assert code == 0
    assert not _purged(conn, v1) and not _purged(conn, v2)


def test_an_unretracted_assertion_pins_its_document_and_a_retracted_one_does_not(
        conn, actor, store, capsys):
    uid, email = actor
    source = _source(conn)
    case = _case(conn, uid)
    pinned = _doc(conn, source)
    free = _doc(conn, source)
    _assertion(conn, case, uid, pinned, retracted=False)
    _assertion(conn, case, uid, free, retracted=True)
    code, _out, _ = _run(conn, store, email, "--apply", capsys=capsys)
    assert code == 0
    assert not _purged(conn, pinned) and _purged(conn, free)


# --- the refusals ------------------------------------------------------------

def _untouched(conn, doc):
    assert _state(conn, doc) == (False, BODY, "vendor_x")


@pytest.mark.parametrize("value", [None, "", "replace-me-sweep-reference", "true"])
def test_a_missing_or_placeholder_declaration_refuses(conn, actor, store, capsys,
                                                      monkeypatch, value):
    uid, email = actor
    doc = _doc(conn, _source(conn))
    if value is None:
        monkeypatch.delenv("NOCTORNAL_RETENTION_SWEEP_AUTHORITY")
    else:
        monkeypatch.setenv("NOCTORNAL_RETENTION_SWEEP_AUTHORITY", value)
    before = _global_counts(conn)

    code, out, err = _run(conn, store, email, "--apply", capsys=capsys)

    assert code == 2 and out == ""
    assert "NOCTORNAL_RETENTION_SWEEP_AUTHORITY" in err and "Nothing was destroyed" in err
    _untouched(conn, doc)
    assert _global_counts(conn) == before, "a refusal writes nothing"


def test_the_declaration_is_read_when_the_run_starts_not_when_the_script_loads(
        conn, actor, store, capsys, monkeypatch):
    uid, email = actor
    module = _script()
    doc = _doc(conn, _source(conn))
    monkeypatch.delenv("NOCTORNAL_RETENTION_SWEEP_AUTHORITY")
    assert module.main(["--apply", "--actor", email], conn=conn,
                       document_raw=store) == 2
    capsys.readouterr()
    monkeypatch.setenv("NOCTORNAL_RETENTION_SWEEP_AUTHORITY", REFERENCE)
    assert module.main(["--apply", "--actor", email], conn=conn,
                       document_raw=store) == 0
    assert _purged(conn, doc)


def test_a_real_run_with_no_account_is_refused(conn, store, capsys):
    doc = _doc(conn, _source(conn))
    code, out, err = _run(conn, store, None, "--apply", capsys=capsys)
    assert code == 2 and "names the account that answers for it" in err
    _untouched(conn, doc)


def test_the_account_can_come_from_the_environment(conn, actor, store, capsys,
                                                   monkeypatch):
    uid, email = actor
    monkeypatch.setenv("NOCTORNAL_RETENTION_SWEEP_ACTOR", email)
    doc = _doc(conn, _source(conn))
    code, _out, _err = _run(conn, store, None, "--apply", capsys=capsys)
    assert code == 0 and _purged(conn, doc)
    assert _tombstones(conn, uid)


@pytest.mark.parametrize("who", ["unknown", "no_permission", "inactive"])
def test_an_account_that_cannot_answer_for_it_is_refused(conn, store, capsys, who):
    doc = _doc(conn, _source(conn))
    if who == "unknown":
        email = f"{P}nobody-{uuid4().hex[:6]}@noctornal.test"
    elif who == "no_permission":
        _uid, email = h.user(conn, P, roles=())
    else:
        uid, email = h.user(conn, P, roles=("SYS_ADMIN",))
        conn.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s", (uid,))

    code, out, err = _run(conn, store, email, "--apply", capsys=capsys)

    assert code == 2 and out == ""
    assert "no active account with that email holds retention.purge" in err
    _untouched(conn, doc)


def test_the_error_for_a_bad_account_does_not_say_which_kind_it_was(conn, store, capsys):
    """An unknown address and a known one without the permission read alike,
    so the script is not a way to learn which addresses are accounts."""
    _uid, known = h.user(conn, P, roles=())
    unknown = f"{P}nobody-{uuid4().hex[:6]}@noctornal.test"
    _a, _b, first = _run(conn, store, known, "--apply", capsys=capsys)
    _c, _d, second = _run(conn, store, unknown, "--apply", capsys=capsys)
    assert first == second


def test_published_credentials_refuse_a_real_run_in_production(conn, actor, store,
                                                               capsys, monkeypatch):
    uid, email = actor
    doc = _doc(conn, _source(conn))
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.setenv("NOCTORNAL_INGEST_PEPPER", "replace-me-pepper")
    code, out, err = _run(conn, store, email, "--apply", capsys=capsys)
    assert code == 2 and err.startswith("retention_sweep: refusing to run: ")
    assert "refusing to run: NOCTORNAL_INGEST_PEPPER" in err
    assert "replace-me-pepper" not in err
    _untouched(conn, doc)


# --- the store, and the size of a backlog --------------------------------------

def test_no_store_for_collected_markup_refuses_and_destroys_nothing(conn, actor,
                                                                    capsys):
    uid, email = actor
    source = _source(conn)
    keyed = _doc(conn, source, key="collect/cc/" + uuid4().hex)
    plain = _doc(conn, source)

    code, out, err = _run(conn, None, email, "--apply", capsys=capsys)

    assert code == 2
    assert "no store for collected raw markup is configured" in out
    assert not _purged(conn, keyed) and not _purged(conn, plain)
    assert _tombstones(conn, uid) == []
    events = _events(conn, uid)
    assert len(events) == 1 and events[0]["finished"] is False
    assert events[0]["documents_purged"] == 0


def test_a_store_that_refuses_a_delete_keeps_the_document_due(conn, actor, capsys):
    from noctornal_api.rawstore import InMemoryDocumentRawStorage

    class Refusing(InMemoryDocumentRawStorage):
        def delete(self, key):
            raise OSError("the store is read only")

    uid, email = actor
    store = Refusing()
    key = "collect/dd/" + uuid4().hex
    store.put(key, b"<p>markup</p>")
    doc = _doc(conn, _source(conn), key=key)

    code, out, _err = _run(conn, store, email, "--apply", capsys=capsys)

    assert code == 1, "documents were left that the run could have destroyed"
    assert "warning: the object store refused to delete collected markup" in out
    assert _counters(out)["remaining"] >= 1
    assert not _purged(conn, doc) and store.exists(key)


def test_a_backlog_bigger_than_one_pass_is_cleared_in_one_run(conn, actor, store,
                                                              capsys, monkeypatch):
    from noctornal_api.retention import RetentionService

    real = RetentionService.due

    def small(self, **kw):
        kw["limit"] = 2
        return real(self, **kw)

    monkeypatch.setattr(RetentionService, "due", small)
    uid, email = actor
    source = _source(conn)
    docs = [_doc(conn, source) for _ in range(5)]

    code, out, _err = _run(conn, store, email, "--apply", capsys=capsys)
    counters = _counters(out)

    assert code == 0 and counters["remaining"] == 0
    assert counters["passes"] >= 3 and counters["documents_purged"] >= 5
    assert all(_purged(conn, d) for d in docs)


def test_the_pass_limit_stops_a_run_and_exits_one_and_the_next_run_finishes(
        conn, actor, store, capsys, monkeypatch):
    from noctornal_api.retention import RetentionService

    real = RetentionService.due

    def small(self, **kw):
        kw["limit"] = 2
        return real(self, **kw)

    monkeypatch.setattr(RetentionService, "due", small)
    uid, email = actor
    source = _source(conn)
    docs = [_doc(conn, source) for _ in range(5)]

    code, out, _err = _run(conn, store, email, "--apply", "--max-passes", "1",
                           capsys=capsys)
    assert code == 1 and "stopped: stopped at the limit of 1 passes" in out
    assert _counters(out)["passes"] == 1 and _counters(out)["remaining"] > 0
    assert _events(conn, uid)[-1]["finished"] is False

    code, out, _err = _run(conn, store, email, "--apply", capsys=capsys)
    assert code == 0 and _counters(out)["remaining"] == 0
    assert all(_purged(conn, d) for d in docs)


# --- the audit row -------------------------------------------------------------

def test_the_audit_row_carries_counts_and_the_reference_and_no_content(conn, actor,
                                                                        store, capsys):
    uid, email = actor
    source = _source(conn)
    key = "collect/ee/" + uuid4().hex
    store.put(key, b"<p>markup</p>")
    doc = _doc(conn, source, key=key, ext="m:needle-external-id")
    _run(conn, store, email, "--apply", capsys=capsys)

    (event,) = _events(conn, uid)

    assert set(event) == {"authority", "passes", "documents_purged",
                          "dead_letters_purged", "records_purged", "finished",
                          "held", "remaining", "via", "host", "os_user"}
    assert event["authority"] == REFERENCE and event["finished"] is True
    assert event["via"] == "scripts/retention_sweep.py"
    blob = json.dumps(event)
    for secret in (BODY, str(doc), key, "needle-external-id", "vendor_x", "u:99"):
        assert secret not in blob
    row = conn.execute(
        "SELECT actor_kind, object_type, case_id FROM audit.event "
        "WHERE action = 'RETENTION_SWEEP' AND actor_id = %s", (uid,)).fetchone()
    assert row == ("USER", "retention", None)


# --- what the sweep does not reach ---------------------------------------------

def test_the_sweep_destroys_a_due_dead_letter(conn, actor, store, capsys):
    """F55 (owner, 2026-10-08): dead letters join the sweep, under the same
    declaration and named account. Until then the family set was collected
    documents (docs/00 decision 172) and a dead letter outlived its clock;
    the full set of F55 tests is `test_retention_sweep_unattached_pg.py`."""
    uid, email = actor
    letter = conn.execute(
        """INSERT INTO ingest.dead_letter
               (raw_fragment, error_class, redacted, retain_until)
           VALUES ('[redacted]', 'rsweep-test', true, now() - interval '1 day')
           RETURNING id""").fetchone()[0]
    doc = _doc(conn, _source(conn))

    code, _out, _err = _run(conn, store, email, "--apply", capsys=capsys)

    assert code == 0 and _purged(conn, doc)
    purged_at, fragment = conn.execute(
        "SELECT purged_at, raw_fragment FROM ingest.dead_letter WHERE id = %s",
        (letter,)).fetchone()
    assert purged_at is not None and fragment == "[purged on retention]"


def test_kinds_narrows_the_purge_to_the_named_families_and_none_is_every_family(
        conn, actor, monkeypatch):
    """The sweep is `purge_due` itself with `kinds`. Handed a list that also
    holds an exhibit, a record and a dead letter, it destroys the document
    only; the same list without `kinds` reaches the exhibit leg, which
    refuses for want of an object store, proving the filter is what kept it
    out."""
    from noctornal_api.retention import DueItem, RetentionError, RetentionService

    uid, _email = actor
    doc = _doc(conn, _source(conn))
    now = datetime.now(timezone.utc)
    items = [
        DueItem("evidence", uuid4(), uuid4(), now, "case.retention_until"),
        DueItem("ingest_record", uuid4(), None, now, "retention_rule[X]"),
        DueItem("dead_letter", uuid4(), None, now, "dead_letter[90d default]"),
        DueItem("document", doc, None, now, "retention_rule[CHAT_EXPORT]",
                category="CHAT_EXPORT"),
    ]
    monkeypatch.setattr(RetentionService, "due", lambda self, **kw: list(items))

    with pytest.raises(RetentionError, match="no evidence object store"):
        RetentionService(conn).purge_due(actor_id=uid, authority="test, no filter")
    assert not _purged(conn, doc)

    result = RetentionService(conn).purge_due(
        actor_id=uid, authority="test, documents only",
        kinds=frozenset({"document"}))
    assert result.documents_purged == 1
    assert (result.evidence_purged, result.records_purged,
            result.dead_letters_purged) == (0, 0, 0)
    assert {s[0] for s in _tombstones(conn, uid)} == {"document"}
    assert _purged(conn, doc)


# --- the readiness row ---------------------------------------------------------
#
# A fixed clock far from every other suite's documents, so the evidence is
# the same sentence whatever else this database holds.

T0 = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _doc_at(conn, source, days_before_t0, *, hold=False):
    doc = _doc(conn, source)
    conn.execute("UPDATE collect.document SET retain_until = %s WHERE id = %s",
                 (T0 - timedelta(days=days_before_t0), doc))
    if hold:
        _hold_doc(conn, doc)
    return doc


def _verdict(conn):
    from noctornal_api.retention_sweep import readiness_verdict

    return readiness_verdict(conn, now=T0)


def test_the_row_passes_when_nothing_is_past_its_clock(conn):
    ok, evidence, action = _verdict(conn)
    assert ok and action == ""
    # Dead letters and unattached ingest records join the row (F55).
    assert evidence == ("No collected document, dead letter or unattached "
                        "ingest record is past its retention clock.")


def test_the_row_passes_inside_the_grace_and_says_how_many_and_how_old(conn):
    source = _source(conn)
    _doc_at(conn, source, 3)
    _doc_at(conn, source, 1)
    ok, evidence, action = _verdict(conn)
    assert ok and action == ""
    assert evidence == (
        "2 collected documents are past their retention clock and unswept, the "
        "oldest by 3 days. That is inside the 7 days a weekly sweep allows.")


def test_the_row_fails_past_the_grace_with_the_action(conn):
    source = _source(conn)
    _doc_at(conn, source, 10)
    ok, evidence, action = _verdict(conn)
    assert not ok
    assert evidence == (
        "1 collected document is past its retention clock and unswept, the "
        "oldest by 10 days. No sweep of collected documents is scheduled, or "
        "the last one could not finish.")
    assert "scripts/retention_sweep.py" in action and "--apply" in action
    assert "infra/production/README.md, Retention sweep" in action


def test_held_documents_are_counted_apart_and_never_fail_the_row(conn):
    source = _source(conn)
    _doc_at(conn, source, 30, hold=True)
    _doc_at(conn, source, 40, hold=True)
    ok, evidence, action = _verdict(conn)
    assert ok and action == ""
    assert evidence == (
        "2 collected documents are past their retention clock and every one is "
        "kept by a legal hold, so a sweep keeps them.")

    _doc_at(conn, source, 2)
    ok, evidence, _ = _verdict(conn)
    assert ok and evidence.endswith(
        "2 more are kept by a legal hold and stay.")


def test_the_row_names_no_document_source_or_case(conn):
    source = _source(conn)
    doc = _doc_at(conn, source, 10)
    conn.execute("UPDATE collect.document SET external_id = 'm:needle-id', "
                 "title = 'needle title' WHERE id = %s", (doc,))
    name = conn.execute("SELECT name FROM collect.source WHERE id = %s",
                        (source,)).fetchone()[0]
    _ok, evidence, action = _verdict(conn)
    for secret in (str(doc), str(source), name, "needle", BODY, "vendor_x"):
        assert secret not in evidence and secret not in action


def test_the_register_carries_the_row_as_a_non_blocking_one(conn):
    from noctornal_api import readiness

    assert "retention_sweep_current" in readiness.CHECK_NAMES
    assert "retention_sweep_current" not in readiness.BLOCKING_CHECKS
    assert "retention_sweep_current" not in readiness.CONSEQUENCES
    assert "retention_sweep_current" not in readiness.UI_TARGETS
    row = readiness.check("retention_sweep_current", conn)
    assert row.blocking is False
    assert isinstance(row.ok, bool) and row.evidence.strip()
    assert row.ok or row.action.strip()
    in_report = [c for c in readiness.report(conn)["checks"]
                 if c["check"] == "retention_sweep_current"]
    assert len(in_report) == 1 and in_report[0]["blocking"] is False

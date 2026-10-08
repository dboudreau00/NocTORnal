"""Dead letters and the records attached to no case join the operator-run
sweep (docs/17 F55; owner decision of 2026-10-08).

A dead letter carries a 90-day clock and third-party victim data and has no
case, so no case hold reaches it and the case-scoped purge skips it by
design; a record attached to no case has a clock and no case to govern it. The
sweep (`scripts/retention_sweep.py`) destroyed collected documents only
(docs/00 decision 172), and nothing destroyed these when their clock ran
out. They join it under the same rules: a dry run by default, `--apply` with
the declared authority and the named account, never scheduled. A record
attached to a case stays that case's, with its clock and its hold.

The sweep is deployment-wide, so other suites' leftovers past their clock are
its too: counts are read as differences from a baseline and every row is read
by its own id. Accounts `g44t-*`; DATABASE_URL-gated.
"""
from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import g44_support as g

pytestmark = g.GATED

conn = g.conn

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "retention_sweep.py"
REFERENCE = "RETSCHED-2026-014"
FRAGMENT = "[redacted] the fragment of a victim's log"
ERROR_CLASS = "g79-test"


@pytest.fixture
def declared(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_RETENTION_SWEEP_AUTHORITY", REFERENCE)
    monkeypatch.delenv("NOCTORNAL_RETENTION_SWEEP_ACTOR", raising=False)


@pytest.fixture
def letters(conn):
    yield
    conn.execute("DELETE FROM ingest.dead_letter WHERE error_class = %s",
                 (ERROR_CLASS,))


@pytest.fixture
def raw_store():
    from noctornal_api.rawstore import InMemoryDocumentRawStorage
    return InMemoryDocumentRawStorage()


def _script():
    spec = importlib.util.spec_from_file_location("retention_sweep_g79", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _actor(conn):
    uid = g.user(conn, "RED", roles=("SYS_ADMIN",))
    email = conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                         (uid,)).fetchone()[0]
    return uid, email


def _run(conn, store, email, *flags, capsys):
    code = _script().main([*flags, *(["--actor", email] if email else [])],
                          conn=conn, document_raw=store)
    out = capsys.readouterr()
    return code, out.out, out.err


def _counters(out: str) -> dict:
    return {k: (int(v) if v.lstrip("-").isdigit() else v)
            for k, v in (pair.split("=", 1) for pair in out.splitlines()[0].split())}


def _letter(conn, *, due=True) -> object:
    when = (datetime.now(timezone.utc) - timedelta(days=1) if due
            else datetime.now(timezone.utc) + timedelta(days=30))
    return conn.execute(
        """INSERT INTO ingest.dead_letter
               (raw_fragment, error_class, redacted, retain_until)
           VALUES (%s, %s, true, %s) RETURNING id""",
        (FRAGMENT, ERROR_CLASS, when)).fetchone()[0]


def _letter_state(conn, letter):
    return conn.execute(
        "SELECT purged_at IS NOT NULL, raw_fragment FROM ingest.dead_letter "
        "WHERE id = %s", (letter,)).fetchone()


def _record(conn, owner, case_id=None, *, due=True) -> object:
    """One ingest record through the real service, attached to `case_id` or
    to none, on a clock in the past or the future."""
    record_id, _ = g.record_in_case(conn, owner, case_id)
    when = (datetime.now(timezone.utc) - timedelta(days=1) if due
            else datetime.now(timezone.utc) + timedelta(days=30))
    conn.execute("UPDATE ingest.record SET retain_until = %s WHERE id = %s",
                 (when, record_id))
    return record_id


def _record_purged(conn, record_id) -> bool:
    return conn.execute("SELECT purged_at IS NOT NULL FROM ingest.record "
                        "WHERE id = %s", (record_id,)).fetchone()[0]


def _owner(conn):
    return g.user(conn, "RED", ("STEALER-2026",), roles=("CASE_OWNER",))


def _tombstones(conn, uid):
    return conn.execute(
        """SELECT object_type, object_count, authority, case_id
             FROM core.purge_tombstone WHERE purged_by = %s ORDER BY purged_at""",
        (uid,)).fetchall()


# --- the dry run ---------------------------------------------------------------

def test_a_dry_run_counts_the_new_families_and_changes_nothing(
        conn, letters, declared, raw_store, capsys):
    owner = _owner(conn)
    base_code, base_out, _ = _run(conn, raw_store, None, capsys=capsys)
    assert base_code == 0
    base = _counters(base_out)

    due_letter, later_letter = _letter(conn), _letter(conn, due=False)
    due_record = _record(conn, owner)
    later_record = _record(conn, owner, due=False)
    before = (conn.execute("SELECT count(*) FROM audit.event").fetchone()[0],
              conn.execute("SELECT count(*) FROM core.purge_tombstone").fetchone()[0])

    code, out, err = _run(conn, raw_store, None, capsys=capsys)
    after = _counters(out)

    assert code == 0 and err == "" and after["mode"] == "dry-run"
    assert after["dead_letters"] - base["dead_letters"] == 1
    assert after["unattached_records"] - base["unattached_records"] == 1
    assert "dry run: nothing was changed" in out
    assert (conn.execute("SELECT count(*) FROM audit.event").fetchone()[0],
            conn.execute("SELECT count(*) FROM core.purge_tombstone").fetchone()[0]
            ) == before, "a dry run writes no tombstone and no audit row"
    assert _letter_state(conn, due_letter)[0] is False
    assert _letter_state(conn, later_letter)[0] is False
    assert not _record_purged(conn, due_record)
    assert not _record_purged(conn, later_record)


def test_the_hint_to_apply_is_printed_when_only_a_dead_letter_is_sweepable(
        conn, letters, declared, raw_store, capsys, monkeypatch):
    """The line used to count documents alone, so a deployment whose only
    backlog was a dead letter was told nothing could be destroyed."""
    from noctornal_api import retention_sweep as rs
    from noctornal_api.retention import RetentionService

    monkeypatch.setattr(RetentionService, "document_backlog",
                        lambda self, as_of=None: (0, 0, None))
    _letter(conn)
    code, out, _ = _run(conn, raw_store, None, capsys=capsys)
    assert code == 0 and "dry run: nothing was changed" in out
    assert rs.SweepReport(apply=False, dead_letters=1).sweepable_total == 1


# --- the real run ---------------------------------------------------------------

def test_a_real_run_destroys_what_is_past_its_clock_and_only_that(
        conn, letters, declared, raw_store, capsys):
    uid, email = _actor(conn)
    owner = _owner(conn)
    gone_letter, kept_letter = _letter(conn), _letter(conn, due=False)
    gone_record = _record(conn, owner)
    kept_record = _record(conn, owner, due=False)

    code, out, err = _run(conn, raw_store, email, "--apply", capsys=capsys)
    counters = _counters(out)

    assert code == 0 and err == "", (out, err)
    assert counters["mode"] == "apply" and counters["remaining"] == 0
    assert counters["dead_letters_purged"] >= 1 and counters["records_purged"] >= 1
    assert _letter_state(conn, gone_letter) == (True, "[purged on retention]")
    assert _letter_state(conn, kept_letter) == (False, FRAGMENT)
    assert _record_purged(conn, gone_record)
    assert not _record_purged(conn, kept_record)
    assert conn.execute("SELECT payload FROM ingest.record WHERE id = %s",
                        (gone_record,)).fetchone()[0] == {}

    # The purge's own record: a tombstone per family under the declared
    # authority and the named account, with no case.
    stones = _tombstones(conn, uid)
    assert {t[0] for t in stones} >= {"dead_letter", "ingest_record"}
    assert all(REFERENCE in t[2] and t[3] is None for t in stones)
    by_kind = {}
    for kind, count, *_ in stones:
        by_kind[kind] = by_kind.get(kind, 0) + count
    assert by_kind["dead_letter"] == counters["dead_letters_purged"]
    assert by_kind["ingest_record"] == counters["records_purged"]
    [event] = [r[0] for r in conn.execute(
        "SELECT detail FROM audit.event WHERE action = 'RETENTION_SWEEP' "
        "AND actor_id = %s", (uid,)).fetchall()]
    assert event["dead_letters_purged"] == counters["dead_letters_purged"]
    assert event["records_purged"] == counters["records_purged"]
    assert FRAGMENT not in str(event)

    # And a second run is a no-op.
    code, out, _ = _run(conn, raw_store, email, "--apply", capsys=capsys)
    again = _counters(out)
    assert code == 0
    assert (again["dead_letters_purged"], again["records_purged"]) == (0, 0)


def test_a_record_attached_to_a_case_is_left_to_its_case(
        conn, letters, declared, raw_store, capsys):
    """The sweep is deployment-wide and writes its tombstones under no case:
    reaching a case's records would be the cross-case destruction the
    case-scoped route exists to prevent, and would ignore the case's hold."""
    from noctornal_api.retention import RetentionService

    uid, email = _actor(conn)
    owner = _owner(conn)
    case_id = g.case(conn, owner)
    held_case = g.case(conn, owner)
    attached = _record(conn, owner, case_id)
    held = _record(conn, owner, held_case)
    conn.execute('UPDATE core."case" SET legal_hold = true, '
                 "legal_hold_reason = 'g79 hold' WHERE id = %s", (held_case,))

    code, _out, _err = _run(conn, raw_store, email, "--apply", capsys=capsys)

    assert code == 0
    assert not _record_purged(conn, attached), "the sweep reached a case's record"
    assert not _record_purged(conn, held)
    # The case's own route still does it, as it always did.
    result = RetentionService(conn).purge_due(
        actor_id=uid, authority="g79 case-scoped run", case_id=case_id)
    assert result.records_purged == 1 and _record_purged(conn, attached)


def test_a_backlog_of_case_records_does_not_starve_the_unattached_ones(
        conn, letters, declared, raw_store, capsys, monkeypatch):
    """Each family is read up to a limit, oldest first. Filtered after the
    read, a case's older records filled the limit and the records attached to
    no case were never reached."""
    from noctornal_api.retention import RetentionService

    owner = _owner(conn)
    case_id = g.case(conn, owner)
    older = [_record(conn, owner, case_id) for _ in range(3)]
    for record in older:
        conn.execute("UPDATE ingest.record SET retain_until = "
                     "now() - interval '40 days' WHERE id = %s", (record,))
    loose = _record(conn, owner)

    items = RetentionService(conn).due(unattached_only=True, limit=2)
    ids = {i.object_id for i in items}
    assert loose in ids and not ids & set(older)
    everything = RetentionService(conn).due(limit=2)
    assert loose not in {i.object_id for i in everything}, (
        "the fixture no longer shows the starvation this test guards")


def test_due_with_unattached_only_names_no_case_material(conn, letters):
    from noctornal_api.retention import RetentionService

    owner = _owner(conn)
    case_id = g.case(conn, owner)
    g.lodge(conn, g.VersionedStore(), case_id, owner)
    g.age_case(conn, case_id, g.expired())
    _record(conn, owner, case_id)
    letter = _letter(conn)
    loose = _record(conn, owner)

    items = RetentionService(conn).due(unattached_only=True)
    kinds = {i.object_type for i in items}
    assert kinds <= {"document", "dead_letter", "ingest_record"}, kinds
    assert all(i.case_id is None for i in items)
    assert {letter, loose} <= {i.object_id for i in items}
    assert "evidence" in {i.object_type for i in RetentionService(conn).due()}


# --- the same rules as for documents ---------------------------------------------

def test_a_real_run_still_needs_its_declaration_and_its_account(
        conn, letters, raw_store, capsys, monkeypatch):
    letter = _letter(conn)
    _uid, email = _actor(conn)
    monkeypatch.delenv("NOCTORNAL_RETENTION_SWEEP_AUTHORITY", raising=False)
    code, out, err = _run(conn, raw_store, email, "--apply", capsys=capsys)
    assert code == 2 and out == ""
    assert "NOCTORNAL_RETENTION_SWEEP_AUTHORITY" in err
    assert _letter_state(conn, letter)[0] is False

    monkeypatch.setenv("NOCTORNAL_RETENTION_SWEEP_AUTHORITY", REFERENCE)
    code, out, err = _run(conn, raw_store, None, "--apply", capsys=capsys)
    assert code == 2 and "names the account that answers for it" in err
    assert _letter_state(conn, letter)[0] is False


def test_the_family_set_is_the_three_and_the_sweep_asks_for_unattached_only():
    import inspect

    from noctornal_api import retention_sweep as rs
    assert rs.SWEPT_KINDS == frozenset({"document", "dead_letter", "ingest_record"})
    assert "unattached_only=True" in inspect.getsource(rs.sweep)


# --- the readiness row -----------------------------------------------------------

T0 = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _verdict(conn):
    from noctornal_api.retention_sweep import readiness_verdict
    return readiness_verdict(conn, now=T0)


def _aged(conn, table, row_id, days):
    conn.execute(f"UPDATE ingest.{table} SET retain_until = %s WHERE id = %s",
                 (T0 - timedelta(days=days), row_id))


def test_the_row_counts_a_dead_letter_and_an_unattached_record(conn, letters):
    owner = _owner(conn)
    letter = _letter(conn)
    _aged(conn, "dead_letter", letter, 3)
    ok, evidence, action = _verdict(conn)
    assert ok and action == ""
    assert evidence == (
        "1 dead letter is past its retention clock and unswept, the oldest by "
        "3 days. That is inside the 7 days a weekly sweep allows.")

    loose = _record(conn, owner)
    _aged(conn, "record", loose, 10)
    ok, evidence, action = _verdict(conn)
    assert not ok
    assert evidence == (
        "1 dead letter and 1 unattached ingest record are past their "
        "retention clock and unswept, the oldest by 10 days. No sweep of "
        "collected documents, dead letters and unattached ingest records is "
        "scheduled, or the last one could not finish.")
    assert "scripts/retention_sweep.py" in action and "--apply" in action


def test_the_row_does_not_count_a_record_attached_to_a_case(conn, letters):
    owner = _owner(conn)
    case_id = g.case(conn, owner)
    attached = _record(conn, owner, case_id)
    _aged(conn, "record", attached, 30)
    ok, evidence, _ = _verdict(conn)
    assert ok and evidence == (
        "No collected document, dead letter or unattached ingest record is "
        "past its retention clock.")


def test_the_row_names_neither_a_letter_nor_a_record(conn, letters):
    owner = _owner(conn)
    letter = _letter(conn)
    _aged(conn, "dead_letter", letter, 10)
    loose = _record(conn, owner)
    _aged(conn, "record", loose, 10)
    _ok, evidence, action = _verdict(conn)
    for secret in (str(letter), str(loose), FRAGMENT, ERROR_CLASS):
        assert secret not in evidence and secret not in action


def test_the_help_says_which_families_the_sweep_reaches(capsys):
    with pytest.raises(SystemExit) as stop:
        _script().main(["--help"])
    assert stop.value.code == 0
    text = " ".join(capsys.readouterr().out.split())
    assert ("collected documents, dead letters and ingest records attached to "
            "no case") in text
    assert "A dry run unless --apply is given." in text

"""YARA rule sets as records (F12 and migration 0080, 2026-09-24).

A set is labelled and its labels only rise; its compartments change only
by the registry's rename (which must be recognised as one, and a swap of
two keys registered together must not);
a version is immutable; an activation is written by somebody other than
the version's sponsor, carries its own licence clearance when the source
asks for review, and closes once; builds are an insert-only history keyed
by engine, platform and host; the two permissions can never meet in one
role.

Email prefix `yrs-`. Env-gated on DATABASE_URL; skips without yara-x.
"""
from __future__ import annotations

import importlib.util
import os
import threading
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

from lab_static_fixtures import left_behind, make_user, teardown

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set")

PREFIX = "yrs-"
MIGRATIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
RULE = 'rule r_{n} {{ strings: $a = "needle-{n}" condition: $a }}\n'


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    assert left_behind(c, PREFIX) == {"users": 0, "rulesets": 0}
    c.close()


def _bundle(n="1"):
    from noctornal_api.yara_rules import parse_bundle
    return parse_bundle("r.yar", RULE.format(n=n).encode())


def _set(conn, who, *, classification="AMBER", compartments=()):
    from noctornal_api.yara_rules import RulesetService
    key = f"yrs-{uuid4().hex[:8]}"
    return RulesetService(conn).create(
        key=key, display_name="Test set", description=None,
        classification=classification, compartments=compartments,
        actor_id=who)["id"]


def _version(conn, set_id, who, *, n="1", review=False, via="upload"):
    from noctornal_api.yara_rules import RulesetService, build_key
    return RulesetService(conn).add_version(
        set_id, _bundle(n), licence="MIT", licence_review_required=review,
        provenance={"via": via}, note=None,
        uploaded_by=who if via == "upload" else None,
        host_user="ops" if via != "upload" else None, key=build_key())


def _compile(conn):
    from noctornal_api import lab_triage
    return lab_triage.compile_pending(conn, lab_triage.settings_or_default())


def _key():
    from noctornal_api.yara_rules import build_key
    key = build_key()
    if key is None:
        pytest.skip("yara-x is not installed")
    return key


# --- immutability ------------------------------------------------------------

def test_a_version_cannot_be_rewritten_deleted_or_truncated(conn):
    _key()
    who = make_user(conn, PREFIX)
    v = _version(conn, _set(conn, who), who)
    for sql in ("UPDATE lab.yara_ruleset_version SET licence = 'x' WHERE id = %s",
                "UPDATE lab.yara_ruleset_version SET adopted_by = uploaded_by, "
                "adopted_at = now() WHERE id = %s",
                "DELETE FROM lab.yara_ruleset_version WHERE id = %s"):
        with pytest.raises(psycopg.Error):
            conn.execute(sql, (v["id"],))
    with pytest.raises(psycopg.Error):
        conn.execute("TRUNCATE lab.yara_ruleset_version CASCADE")


def test_adoption_is_set_once_and_only_on_imported_versions(conn):
    from noctornal_api.yara_rules import RulesetError, RulesetService
    _key()
    who = make_user(conn, PREFIX)
    other = make_user(conn, PREFIX)
    set_id = _set(conn, who)
    uploaded = _version(conn, set_id, who, n="u")
    with pytest.raises(RulesetError, match="only a version imported"):
        RulesetService(conn).adopt(uploaded["id"], actor_id=other)
    imported = _version(conn, set_id, None, n="i", via="yara_db.py")
    assert RulesetService(conn).adopt(imported["id"], actor_id=other)["adopted"]
    with pytest.raises(RulesetError):
        RulesetService(conn).adopt(imported["id"], actor_id=who)
    with pytest.raises(psycopg.Error):
        conn.execute("UPDATE lab.yara_ruleset_version SET adopted_by = %s "
                     "WHERE id = %s", (who, imported["id"]))


def test_script_imports_are_system_and_attribute_no_person(conn):
    _key()
    who = make_user(conn, PREFIX)
    set_id = _set(conn, who)
    v = _version(conn, set_id, None, n="s", via="yara_db.py")
    row = conn.execute(
        """SELECT actor_kind, actor_id, detail FROM audit.event
            WHERE action = 'YARA_RULESET_VERSION_ADDED' AND object_id = %s
              AND detail->>'version' = %s""",
        (set_id, str(v["version"]))).fetchone()
    assert row[0] == "SYSTEM" and row[1] is None
    assert row[2]["via"] == "yara_db.py" and row[2]["host_user"] == "ops"


# --- activation --------------------------------------------------------------

def test_activation_needs_a_verified_build_for_this_engine_and_platform(conn):
    from noctornal_api.yara_rules import RulesetError, RulesetService
    key = _key()
    lab = make_user(conn, PREFIX)
    officer = make_user(conn, PREFIX)
    v = _version(conn, _set(conn, lab), lab)
    conn.execute("DELETE FROM lab.yara_compile_job WHERE version_id = %s",
                 (v["id"],))
    with pytest.raises(RulesetError, match="still compiling") as err:
        RulesetService(conn).activate(v["id"], actor_id=officer,
                                      licence_acknowledgement=None,
                                      replace_open=False, key=key)
    assert err.value.code == "not_compiled"
    assert conn.execute("SELECT count(*) FROM lab.yara_compile_job "
                        "WHERE version_id = %s", (v["id"],)).fetchone()[0] == 1
    _compile(conn)
    out = RulesetService(conn).activate(v["id"], actor_id=officer,
                                        licence_acknowledgement=None,
                                        replace_open=False, key=key)
    assert out["version"] == 1


def test_the_sponsor_cannot_activate(conn):
    from noctornal_api.yara_rules import RulesetError, RulesetService
    key = _key()
    lab = make_user(conn, PREFIX)
    adopter = make_user(conn, PREFIX)
    set_id = _set(conn, lab)
    v = _version(conn, set_id, lab)
    imported = _version(conn, set_id, None, n="i", via="yara_db.py")
    RulesetService(conn).adopt(imported["id"], actor_id=adopter)
    _compile(conn)
    with pytest.raises(RulesetError, match="somebody else has to activate"):
        RulesetService(conn).activate(v["id"], actor_id=lab,
                                      licence_acknowledgement=None,
                                      replace_open=False, key=key)
    with pytest.raises(RulesetError, match="somebody else has to activate"):
        RulesetService(conn).activate(imported["id"], actor_id=adopter,
                                      licence_acknowledgement=None,
                                      replace_open=False, key=key)
    # The database holds the rule for a writer that is not the service.
    with pytest.raises(psycopg.errors.RaiseException, match="cannot"):
        conn.execute("INSERT INTO lab.yara_activation (ruleset_id, version_id, "
                     "activated_by) VALUES (%s, %s, %s)",
                     (set_id, v["id"], lab))
    refused = conn.execute(
        """SELECT count(*) FROM audit.event
            WHERE action = 'YARA_RULESET_ACTIVATION_REFUSED' AND object_id = %s
              AND detail->>'reason' = 'self_sponsored'""", (set_id,)).fetchone()[0]
    assert refused == 2


def test_an_imported_version_needs_adoption_before_activation(conn):
    from noctornal_api.yara_rules import RulesetError, RulesetService
    key = _key()
    lab = make_user(conn, PREFIX)
    officer = make_user(conn, PREFIX)
    v = _version(conn, _set(conn, lab), None, via="yara_db.py")
    _compile(conn)
    with pytest.raises(RulesetError, match="adopt"):
        RulesetService(conn).activate(v["id"], actor_id=officer,
                                      licence_acknowledgement=None,
                                      replace_open=False, key=key)


def test_a_review_required_version_needs_an_acknowledgement_of_substance(conn):
    from noctornal_api.yara_rules import RulesetInvalid, RulesetService
    key = _key()
    lab = make_user(conn, PREFIX)
    officer = make_user(conn, PREFIX)
    set_id = _set(conn, lab)
    v = _version(conn, set_id, lab, review=True)
    _compile(conn)
    with pytest.raises(RulesetInvalid, match="clearance"):
        RulesetService(conn).activate(v["id"], actor_id=officer,
                                      licence_acknowledgement="ok",
                                      replace_open=False, key=key)
    ack = "Counsel cleared DRL-1.1 for internal use on 2026-09-24, ref L-77"
    out = RulesetService(conn).activate(v["id"], actor_id=officer,
                                        licence_acknowledgement=ack,
                                        replace_open=False, key=key)
    assert conn.execute("SELECT licence_acknowledgement FROM lab.yara_activation "
                        "WHERE id = %s", (out["activation_id"],)).fetchone()[0] == ack
    audit = conn.execute(
        """SELECT detail FROM audit.event WHERE action = 'YARA_RULESET_ACTIVATED'
            AND object_id = %s""", (set_id,)).fetchone()[0]
    assert audit["licence_acknowledgement"] == ack


def test_one_open_activation_per_set_and_it_closes_once(conn):
    from noctornal_api.yara_rules import RulesetError, RulesetService
    key = _key()
    lab = make_user(conn, PREFIX)
    officer = make_user(conn, PREFIX)
    set_id = _set(conn, lab)
    v1 = _version(conn, set_id, lab, n="1")
    v2 = _version(conn, set_id, lab, n="2")
    _compile(conn)
    svc = RulesetService(conn)
    svc.activate(v1["id"], actor_id=officer, licence_acknowledgement=None,
                 replace_open=False, key=key)
    with pytest.raises(RulesetError, match="version 1 of this set is active"):
        svc.activate(v2["id"], actor_id=officer, licence_acknowledgement=None,
                     replace_open=False, key=key)
    out = svc.activate(v2["id"], actor_id=officer, licence_acknowledgement=None,
                       replace_open=True, key=key)
    assert out["replaced"] == 1
    closed = conn.execute(
        "SELECT id FROM lab.yara_activation WHERE version_id = %s",
        (v1["id"],)).fetchone()[0]
    with pytest.raises(psycopg.Error):
        conn.execute("UPDATE lab.yara_activation SET deactivation_reason = "
                     "'rewritten later' WHERE id = %s", (closed,))
    with pytest.raises(psycopg.Error):
        conn.execute("DELETE FROM lab.yara_activation WHERE id = %s", (closed,))
    with pytest.raises(RulesetError, match="at least 10|say why"):
        svc.deactivate(v2["id"], actor_id=officer, reason="no")
    svc.deactivate(v2["id"], actor_id=officer, reason="false positives on SMB")
    with pytest.raises(RulesetError, match="not the active one"):
        svc.deactivate(v2["id"], actor_id=officer, reason="false positives on SMB")


def test_the_two_permissions_can_never_meet_in_one_role(conn):
    pairs = {tuple(r) for r in conn.execute(
        "SELECT permission_a, permission_b FROM iam.separated_duty").fetchall()}
    assert ("sample.yara.manage", "sample.yara.activate") in pairs
    grants = dict(conn.execute(
        """SELECT permission_key, array_agg(role_key ORDER BY role_key)
             FROM iam.role_permission WHERE permission_key LIKE 'sample.yara.%'
            GROUP BY permission_key""").fetchall())
    assert grants == {"sample.yara.manage": ["MALWARE_ANALYST"],
                      "sample.yara.activate": ["SECURITY_OFFICER"]}
    with pytest.raises(psycopg.errors.RaiseException, match="two-person control"):
        with conn.transaction():
            conn.execute("INSERT INTO iam.role_permission (role_key, "
                         "permission_key) VALUES ('SECURITY_OFFICER', "
                         "'sample.yara.manage')")


def test_versions_number_monotonically_under_concurrency(conn):
    from noctornal_api.db import connect
    _key()
    lab = make_user(conn, PREFIX)
    set_id = _set(conn, lab)
    numbers, errors = [], []

    def add(n):
        c = connect()
        try:
            numbers.append(_version(c, set_id, lab, n=str(n))["version"])
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            c.close()

    threads = [threading.Thread(target=add, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and sorted(numbers) == [1, 2, 3, 4]


def test_an_identical_bundle_is_refused_naming_its_twin(conn):
    from noctornal_api.yara_rules import RulesetError
    _key()
    lab = make_user(conn, PREFIX)
    set_id = _set(conn, lab)
    _version(conn, set_id, lab, n="same")
    with pytest.raises(RulesetError, match="identical to version 1"):
        _version(conn, set_id, lab, n="same")


def test_a_key_is_unique_only_among_sets_at_the_same_labels(conn):
    """The verifier of 2026-09-24: creating a set answered "a rule set with
    the key X exists already" for a RED or compartmented set the AMBER
    caller could not see, and a key says what another unit hunts.
    A key now collides only with a set at the same labels, which the
    caller can always read, so a refusal confirms nothing hidden."""
    from noctornal_api.yara_rules import RulesetError, RulesetService
    comp = f"YRS-H{uuid4().hex[:4].upper()}"
    comp2 = f"YRS-G{uuid4().hex[:4].upper()}"
    red = make_user(conn, PREFIX, clearance="RED", compartments=(comp, comp2))
    amber = make_user(conn, PREFIX, clearance="AMBER")
    svc = RulesetService(conn)
    key = f"yrs-{uuid4().hex[:8]}"

    def create(who, classification, compartments=()):
        return svc.create(key=key, display_name="Hunt", description=None,
                          classification=classification,
                          compartments=compartments, actor_id=who)

    create(red, "RED")
    create(red, "AMBER", (comp,))
    # Neither is visible to the AMBER caller, and creating the same key at
    # the caller's own labels neither fails nor says anything about them.
    mine = create(amber, "AMBER")
    assert mine["key"] == key
    with pytest.raises(RulesetError, match="exists already at these labels"):
        create(amber, "AMBER")
    # Compartments compare as a set, whatever order a rename left them in.
    both = create(red, "AMBER", (comp, comp2))["id"]
    conn.execute("UPDATE lab.yara_ruleset SET compartments = %s WHERE id = %s",
                 ([comp2, comp], both))
    with pytest.raises(RulesetError, match="exists already at these labels"):
        create(red, "AMBER", (comp, comp2))
    assert conn.execute("SELECT count(*) FROM lab.yara_ruleset WHERE key = %s",
                        (key,)).fetchone()[0] == 4


# --- labels and the compartment registry ----------------------------------------

def test_a_ruleset_label_cannot_be_lowered_or_a_compartment_removed(conn):
    lab = make_user(conn, PREFIX, compartments=("YRS-KA",))
    set_id = _set(conn, lab, classification="RED", compartments=("YRS-KA",))
    with pytest.raises(psycopg.errors.RaiseException, match="never lowered"):
        conn.execute("UPDATE lab.yara_ruleset SET classification = 'AMBER' "
                     "WHERE id = %s", (set_id,))
    with pytest.raises(psycopg.errors.RaiseException, match="only added to"):
        conn.execute("UPDATE lab.yara_ruleset SET compartments = '{}' "
                     "WHERE id = %s", (set_id,))
    # Gaining a key is always allowed: the set only becomes stricter.
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES "
                 "('YRS-KB', 'b') ON CONFLICT DO NOTHING")
    conn.execute("UPDATE lab.yara_ruleset SET compartments = "
                 "'{YRS-KA,YRS-KB}' WHERE id = %s", (set_id,))


def test_a_swap_between_keys_registered_together_is_not_a_rename(conn):
    """Keys backfilled in one statement share a creator and a time; the
    guard also asks that the added key was registered in THIS transaction,
    as the lifecycle's rename registers it."""
    tag = uuid4().hex[:4].upper()
    a, b = f"YRS-S{tag}", f"YRS-T{tag}"
    conn.execute("INSERT INTO iam.compartment (key, label, created_by) VALUES "
                 "(%s, 'a', NULL), (%s, 'b', NULL)", (a, b))
    lab = make_user(conn, PREFIX, compartments=(a, b))
    set_id = _set(conn, lab, compartments=(a,))
    with pytest.raises(psycopg.errors.RaiseException, match="only added to"):
        conn.execute("UPDATE lab.yara_ruleset SET compartments = %s "
                     "WHERE id = %s", ([b], set_id))


def test_a_compartment_rename_moves_a_ruleset_key_and_a_carried_key_cannot_be_retired(conn):
    from noctornal_api.compartment_lifecycle import (CompartmentError,
                                                     CompartmentLifecycle)
    tag = uuid4().hex[:4].upper()
    old, new = f"YRS-O{tag}", f"YRS-N{tag}"
    lab = make_user(conn, PREFIX, compartments=(old,))
    set_id = _set(conn, lab, compartments=(old,))
    life = CompartmentLifecycle(conn)
    with pytest.raises(CompartmentError):
        life.retire(old, actor_id=lab)
    life.rename(old, new, label=None, actor_id=lab)
    assert conn.execute("SELECT compartments FROM lab.yara_ruleset WHERE id = %s",
                        (set_id,)).fetchone()[0] == [new]


def test_the_ruleset_column_is_declared_for_the_catalog(conn):
    from noctornal_api.compartment_lifecycle import BOUND_COLUMNS, NOUNS
    spec = importlib.util.spec_from_file_location(
        "m0080", next(MIGRATIONS.glob("0080_*.py")))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    col = ("lab", "yara_ruleset", "compartments", "array")
    assert col in m.ADDED_BOUND_COLUMNS and col in BOUND_COLUMNS
    assert NOUNS[("lab", "yara_ruleset")] == ("YARA rule set", "YARA rule sets")
    listed = conn.execute(
        "SELECT * FROM iam.compartment_bindings()").fetchall()
    assert any("yara_ruleset" in str(r) for r in listed)
    assert "compartment_in_use" not in m.UPGRADE_SQL


def test_ruleset_reads_check_compartments_beside_classification():
    from noctornal_api import yara_rules
    gate = yara_rules.ruleset_gate()
    assert "classification <=" in gate and "compartments <@" in gate
    # Every query that reads a set as `r` for a reader applies the gate in
    # the same statement.
    src = Path(yara_rules.__file__).read_text(encoding="utf-8")
    at = 0
    seen = 0
    while True:
        at = src.find("lab.yara_ruleset r", at)
        if at < 0:
            break
        statement = src[at:src.find('"""', at)]
        assert "ruleset_gate()" in statement, src[at:at + 200]
        seen += 1
        at += 1
    assert seen >= 4


def test_every_change_is_audited(conn):
    key = _key()
    from noctornal_api.yara_rules import RulesetService
    lab = make_user(conn, PREFIX)
    officer = make_user(conn, PREFIX)
    set_id = _set(conn, lab)
    v = _version(conn, set_id, lab)
    _compile(conn)
    RulesetService(conn).activate(v["id"], actor_id=officer,
                                  licence_acknowledgement=None,
                                  replace_open=False, key=key)
    RulesetService(conn).deactivate(v["id"], actor_id=officer,
                                    reason="replaced by a newer source")
    actions = [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE object_id = %s ORDER BY seq",
        (set_id,)).fetchall()]
    assert actions == ["YARA_RULESET_CREATED", "YARA_RULESET_VERSION_ADDED",
                       "YARA_RULESET_COMPILED", "YARA_RULESET_ACTIVATED",
                       "YARA_RULESET_DEACTIVATED"]


def test_0080_downgrade_refuses_while_rulesets_exist(conn, monkeypatch):
    lab = make_user(conn, PREFIX)
    _set(conn, lab)
    spec = importlib.util.spec_from_file_location(
        "m0080", next(MIGRATIONS.glob("0080_*.py")))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    ran = []
    monkeypatch.setattr(m, "query", lambda sql: conn.execute(sql).fetchall())
    monkeypatch.setattr(m, "run", lambda sql: ran.append(sql))
    with pytest.raises(RuntimeError, match="refusing to downgrade 0080"):
        m.downgrade()
    assert ran == []
    assert m.GUARDED_TABLES["lab.yara_compiled"] == ("SELECT", "INSERT")


def test_a_budgeted_pass_starts_no_compile_or_run_it_cannot_finish(conn, monkeypatch):
    """Found 2026-09-24: a pass run with --budget bounded its runs but
    started a compile whenever the deadline had not yet passed, so one
    compile's full wall limit could overrun the budget. Neither starts
    unless its worst case fits."""
    import time

    from lab_static_fixtures import MemoryStore, declare_policy

    from noctornal_api import lab_triage
    declare_policy(monkeypatch)
    _key()
    lab = make_user(conn, PREFIX)
    v = _version(conn, _set(conn, lab), lab)
    settings = lab_triage.settings_or_default()
    worst = lab_triage.compile_worst_s(settings)
    assert worst == settings.timeout_s + lab_triage.WALL_GRACE_S

    def job():
        return conn.execute("SELECT status FROM lab.yara_compile_job "
                            "WHERE version_id = %s", (v["id"],)).fetchone()

    assert lab_triage.compile_pending(
        conn, settings, until=time.monotonic() + worst - 5,
        version_id=v["id"]) == (0, 0)
    assert job() == ("QUEUED",)
    # A whole pass with a budget smaller than one compile: nothing starts,
    # neither the compile nor any run.
    counts = lab_triage.run_due(conn, MemoryStore(), budget_s=worst - 5)
    assert counts["compiled"] == 0 and job() == ("QUEUED",)
    assert counts.get("done", 0) == counts.get("failed", 0) == 0
    # With room for it, the compile runs.
    built, _failed = lab_triage.compile_pending(
        conn, settings, until=time.monotonic() + worst + 60,
        version_id=v["id"])
    assert built == 1 and job() is None


def test_the_pair_is_written_with_or_without_the_ledger_trigger(conn):
    """0080 writes and removes its separated-duty pair whether or not the
    dual-control ledger trigger exists: plainly when it does not, and with
    that trigger disabled by name and enabled again when it does. Rolled
    back: the real pair and whatever trigger this tree has are left as
    they were."""
    m = _migration_0080()
    a, b, why = m.DUTY
    trigger = m.LEDGER_TRIGGER

    def pairs():
        return conn.execute("SELECT count(*) FROM iam.separated_duty WHERE "
                            "permission_a = %s AND permission_b = %s",
                            (a, b)).fetchone()[0]

    delete = m._with_ledger_trigger_off(
        "DELETE FROM iam.separated_duty "
        f"WHERE permission_a = '{a}' AND permission_b = '{b}'")
    insert = m._with_ledger_trigger_off(
        "INSERT INTO iam.separated_duty (permission_a, permission_b, why) "
        f"VALUES ('{a}', '{b}', '{why}')")
    had = conn.execute("SELECT count(*) FROM pg_trigger WHERE tgname = %s "
                       "AND tgrelid = 'iam.separated_duty'::regclass",
                       (trigger,)).fetchone()[0]
    assert pairs() == 1
    with conn.transaction() as tx:
        # This tree without the dual-control ledger trigger.
        if had:
            conn.execute(f"DROP TRIGGER {trigger} ON iam.separated_duty")
        conn.execute(delete)
        assert pairs() == 0
        conn.execute(insert)
        assert pairs() == 1
        # With a trigger of that name that refuses every direct write, as
        # a ledger-only table does.
        conn.execute("""CREATE FUNCTION pg_temp.ledger_only() RETURNS trigger
                        LANGUAGE plpgsql AS $$ BEGIN
                          RAISE EXCEPTION 'written by the ledger only';
                        END $$""")
        conn.execute(f"CREATE TRIGGER {trigger} BEFORE INSERT OR UPDATE OR "
                     f"DELETE ON iam.separated_duty FOR EACH ROW EXECUTE "
                     f"FUNCTION pg_temp.ledger_only()")
        with pytest.raises(psycopg.errors.RaiseException, match="ledger only"):
            with conn.transaction():
                conn.execute("DELETE FROM iam.separated_duty WHERE "
                             "permission_a = %s", (a,))
        conn.execute(delete)
        assert pairs() == 0
        conn.execute(insert)
        assert pairs() == 1
        assert conn.execute("SELECT tgenabled FROM pg_trigger WHERE tgname = %s "
                            "AND tgrelid = 'iam.separated_duty'::regclass",
                            (trigger,)).fetchone()[0] == "O"
        with pytest.raises(psycopg.errors.RaiseException, match="ledger only"):
            with conn.transaction():
                conn.execute("DELETE FROM iam.separated_duty WHERE "
                             "permission_a = %s", (a,))
        raise psycopg.Rollback(tx)
    assert pairs() == 1
    assert conn.execute("SELECT count(*) FROM pg_trigger WHERE tgname = %s "
                        "AND tgrelid = 'iam.separated_duty'::regclass",
                        (trigger,)).fetchone()[0] == had


def _migration_0080():
    spec = importlib.util.spec_from_file_location(
        "m0080", next(MIGRATIONS.glob("0080_*.py")))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_a_compile_job_whose_process_died_is_swept_and_other_hosts_jobs_are_left(conn):
    """A job left RUNNING by a process that stopped goes back to
    the queue with one attempt more; a process builds only for its own
    engine, platform and host."""
    from noctornal_api import lab_triage
    from noctornal_api.yara_rules import BuildKey
    key = _key()
    lab = make_user(conn, PREFIX)
    v = _version(conn, _set(conn, lab), lab)
    conn.execute("UPDATE lab.yara_compile_job SET status = 'RUNNING' "
                 "WHERE version_id = %s", (v["id"],))
    assert lab_triage.sweep_compile_jobs(conn, key) >= 1
    row = conn.execute("SELECT status, attempts, last_error FROM "
                       "lab.yara_compile_job WHERE version_id = %s",
                       (v["id"],)).fetchone()
    assert row == ("QUEUED", 1, "abandoned")
    other = BuildKey(key.engine, key.platform, "f" * 16)
    conn.execute("INSERT INTO lab.yara_compile_job (version_id, engine, "
                 "platform, fingerprint) VALUES (%s, %s, %s, %s)",
                 (v["id"], other.engine, other.platform, other.fingerprint))
    _compile(conn)
    left = conn.execute("SELECT fingerprint, status FROM lab.yara_compile_job "
                        "WHERE version_id = %s", (v["id"],)).fetchall()
    assert left == [("f" * 16, "QUEUED")]
    assert conn.execute("SELECT count(*) FROM lab.yara_compiled WHERE "
                        "version_id = %s AND fingerprint = %s",
                        (v["id"], other.fingerprint)).fetchone()[0] == 0

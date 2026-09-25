"""The persona vault's new machinery (the collection foundation, 2026-09-24).

The lease and its compare-and-set reseal, a JSON credential's leaves
redacted exactly, the machine's holds and locks that only the platform (the
adapter's signal) writes and no sequence of human writes can undo, the
guard that holds that against any writer, the visibility over every bound
source, the listing, and one persona per egress profile.

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

P = "test-b0pm-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect

    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


def _persona(conn, **kw):
    kw.setdefault("egress", h.egress_profile(conn, P))
    return h.persona(conn, P, **kw)


def _row(conn, pid):
    return conn.execute(
        """SELECT status, cooldown_until, machine_hold_until, machine_hold_reason,
                  machine_lock_code, machine_lock_at, secret_rotated_at,
                  octet_length(secret_ciphertext)
             FROM collect.collection_account WHERE id = %s""", (pid,)).fetchone()


def _audit(conn, pid, action):
    return conn.execute(
        """SELECT actor_id, actor_kind, detail FROM audit.event
            WHERE object_id = %s AND action = %s ORDER BY seq""",
        (pid, action)).fetchall()


# --- the lease ----------------------------------------------------------

def test_a_lease_reseals_only_when_the_value_changed_and_audits_it(conn):
    from noctornal_api.collection import PersonaVault

    pid = _persona(conn, secret="session-one-abcdef")
    vault = PersonaVault(conn)
    with vault.lease(pid, actor_id=None, purpose="unchanged") as lease:
        lease.reseal("session-one-abcdef")
    assert lease.resealed is None
    assert _audit(conn, pid, "PERSONA_SECRET_RESEALED") == []
    rotated = _row(conn, pid)[6]
    with vault.lease(pid, actor_id=None, purpose="moved") as lease:
        lease.reseal("session-two-ghijkl")
    assert lease.resealed is True
    with vault.use(pid, actor_id=None, purpose="read back") as value:
        assert value == "session-two-ghijkl"
    assert _row(conn, pid)[6] == rotated, "a platform moving a session is not a rotation"
    assert len(_audit(conn, pid, "PERSONA_SECRET_RESEALED")) == 1


def test_a_reseal_is_a_compare_and_set(conn):
    from noctornal_api.collection import PersonaVault

    pid = _persona(conn, secret="first-credential-1")
    vault = PersonaVault(conn)
    with vault.lease(pid, actor_id=None, purpose="race") as lease:
        vault.store(pid, "operator-enrolled-9", actor_id=None)
        lease.reseal("platform-moved-2")
    assert lease.resealed is False
    assert _audit(conn, pid, "PERSONA_SECRET_RESEAL_SKIPPED")
    with vault.use(pid, actor_id=None, purpose="check") as value:
        assert value == "operator-enrolled-9", "the newer credential wins"


def test_a_reseal_survives_a_block_that_raised(conn):
    from noctornal_api.collection import PersonaVault

    pid = _persona(conn, secret="before-the-crash-1")
    vault = PersonaVault(conn)
    with pytest.raises(RuntimeError):
        with vault.lease(pid, actor_id=None, purpose="crash") as lease:
            lease.reseal("after-the-move-22")
            raise RuntimeError("the adapter died after the platform moved it")
    with vault.use(pid, actor_id=None, purpose="check") as value:
        assert value == "after-the-move-22"


def test_a_json_credential_registers_its_leaves_for_redaction(conn):
    import json

    from noctornal_api.collection import PersonaVault, redact

    blob = json.dumps({"kind": "tg-session", "v": 1,
                       "session": "1BVtsOHwBu5-leafvalue-xyz",
                       "api": {"hash": "0123456789abcdefabcd"}})
    pid = _persona(conn, secret=blob)
    with PersonaVault(conn).lease(pid, actor_id=None, purpose="redact"):
        text = redact("error near 1BVtsOHwBu5-leafvalue-xyz and 0123456789abcdefabcd")
    assert "leafvalue" not in text and "0123456789abcdefabcd" not in text


def test_use_is_a_lease(conn):
    import inspect

    from noctornal_api.collection import PersonaVault

    assert "self.lease(" in inspect.getsource(PersonaVault.use)
    assert not any(n for n in dir(PersonaVault) if not n.startswith("_")
                   and ("get" in n or "reveal" in n or "decrypt" in n))


# --- the machine's holds and locks --------------------------------------

def test_signal_never_writes_status(conn):
    from noctornal_api.collection import PersonaVault

    pid = _persona(conn, secret="s3cret-value-1")
    vault = PersonaVault(conn)
    until = datetime.now(timezone.utc) + timedelta(hours=1)
    assert vault.signal(pid, reason="flood wait", hold_until=until,
                        hold_reason="RATE_LIMITED")
    vault.signal(pid, reason="session revoked", lock_code="CREDENTIAL_REVOKED")
    row = _row(conn, pid)
    assert row[0] == "HEALTHY" and row[1] is None
    assert row[3] == "RATE_LIMITED" and row[4] == "CREDENTIAL_REVOKED"


def test_a_machine_hold_extends_and_never_shortens(conn):
    from noctornal_api.collection import PersonaVault

    pid = _persona(conn)
    vault = PersonaVault(conn)
    now = datetime.now(timezone.utc)
    vault.signal(pid, reason="a", hold_until=now + timedelta(hours=2),
                 hold_reason="RATE_LIMITED")
    vault.signal(pid, reason="b", hold_until=now + timedelta(minutes=5),
                 hold_reason="RATE_LIMITED")
    assert _row(conn, pid)[2] >= now + timedelta(hours=2) - timedelta(seconds=1)


def test_a_machine_lock_clears_only_with_a_new_credential(conn):
    from noctornal_api.collection import PersonaUnavailable, PersonaVault

    pid = _persona(conn, secret="old-credential-1")
    vault = PersonaVault(conn)
    vault.signal(pid, reason="banned", lock_code="ACCOUNT_BANNED")
    with pytest.raises(PersonaUnavailable, match="refused its credential"):
        with vault.lease(pid, actor_id=None, purpose="x"):
            pass
    vault.store(pid, "new-credential-2", actor_id=None)
    assert _row(conn, pid)[4] is None
    with vault.use(pid, actor_id=None, purpose="x") as value:
        assert value == "new-credential-2"


def test_a_machine_transition_is_audited_as_system(conn):
    from noctornal_api.collection import PersonaVault

    pid = _persona(conn)
    PersonaVault(conn).signal(pid, reason="duplicated",
                              lock_code="CREDENTIAL_DUPLICATED")
    actor, kind, detail = _audit(conn, pid, "PERSONA_MACHINE_LOCK")[0]
    assert actor is None and kind == "SYSTEM" and detail["by"] == "adapter"


def test_destroy_secret_leaves_no_sealed_row(conn):
    from noctornal_api.collection import PersonaVault
    from noctornal_api.security import sealed

    def sealed_personas():
        return sum(g.rows for g in sealed.inventory(conn)
                   if g.table == "collect.collection_account")

    pid = _persona(conn, secret="to-be-destroyed-1")
    before = sealed_personas()
    PersonaVault(conn).destroy_secret(pid, actor_id=None, reason="logged out")
    assert sealed_personas() == before - 1
    row = conn.execute("SELECT platform_uid IS NULL, secret_key_id FROM "
                       "collect.collection_account WHERE id = %s", (pid,)).fetchone()
    assert row[1] is None


# --- the guard, against any writer -------------------------------------

def test_the_database_refuses_to_shorten_a_platform_wait_or_lift_a_credential_lock(conn):
    import psycopg

    from noctornal_api.collection import PersonaVault

    pid = _persona(conn, secret="guarded-credential")
    vault = PersonaVault(conn)
    vault.signal(pid, reason="wait", hold_until=datetime.now(timezone.utc)
                 + timedelta(hours=3), hold_reason="RATE_LIMITED")
    vault.signal(pid, reason="lock", lock_code="PLATFORM_REFUSED")
    refusals = [
        "UPDATE collect.collection_account SET machine_hold_until = NULL, "
        "machine_hold_reason = NULL WHERE id = %s",
        "UPDATE collect.collection_account SET machine_hold_until = now() "
        "WHERE id = %s",
        "UPDATE collect.collection_account SET machine_lock_code = NULL, "
        "machine_lock_at = NULL WHERE id = %s",
        # One statement stamping a rotation and clearing
        # the lock, with no new credential.
        "UPDATE collect.collection_account SET secret_rotated_at = "
        "clock_timestamp(), machine_lock_code = NULL, machine_lock_at = NULL "
        "WHERE id = %s",
        # and the two-step: backdate the lock while it stays set.
        "UPDATE collect.collection_account SET machine_lock_at = "
        "machine_lock_at - interval '1 day' WHERE id = %s",
        # a rotation time moving with no new credential
        "UPDATE collect.collection_account SET secret_rotated_at = "
        "clock_timestamp() WHERE id = %s",
    ]
    for sql in refusals:
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(sql, (pid,))
    row = _row(conn, pid)
    assert row[2] > datetime.now(timezone.utc) and row[4] == "PLATFORM_REFUSED"


def test_no_two_or_three_step_human_path_undoes_a_machine_hold(conn):
    from noctornal_api.collection import (
        COOLDOWN,
        HEALTHY,
        LOCKED,
        PersonaGate,
        PersonaUnavailable,
        PersonaVault,
    )

    actor, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid = _persona(conn, secret="hold-credential-1")
    vault = PersonaVault(conn)
    vault.signal(pid, reason="flood", hold_until=datetime.now(timezone.utc)
                 + timedelta(hours=1), hold_reason="RATE_LIMITED")
    vault.set_status(pid, COOLDOWN, actor_id=actor, reason="step one",
                     cooldown=timedelta(minutes=1))
    vault.set_status(pid, LOCKED, actor_id=actor, reason="step two")
    answer = vault.set_status(pid, HEALTHY, actor_id=actor, reason="step three")
    assert "stays paused" in answer["notice"]
    assert _row(conn, pid)[3] == "RATE_LIMITED"
    gate = PersonaGate(conn, pid, actor_id=actor, clearance="RED", purpose="x",
                       source_id=None, need="PUBLIC_READ", platform="TELEGRAM")
    with pytest.raises(PersonaUnavailable, match="asked it to wait"):
        gate.check()


def test_a_person_can_burn_or_lock_a_persona_under_a_live_machine_hold(conn):
    from noctornal_api.collection import BURNED, LOCKED, PersonaVault

    actor, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid = _persona(conn)
    vault = PersonaVault(conn)
    vault.signal(pid, reason="flood", hold_until=datetime.now(timezone.utc)
                 + timedelta(hours=1), hold_reason="RATE_LIMITED")
    vault.signal(pid, reason="dup", lock_code="CREDENTIAL_DUPLICATED")
    vault.set_status(pid, LOCKED, actor_id=actor, reason="stop it now")
    vault.set_status(pid, BURNED, actor_id=actor, reason="copied session")
    row = _row(conn, pid)
    assert row[0] == "BURNED" and row[3] == "RATE_LIMITED"


def test_a_platform_bound_persona_cannot_be_deleted(conn):
    import psycopg

    pid = _persona(conn)
    with pytest.raises(psycopg.errors.RaiseException, match="never deleted"):
        conn.execute("DELETE FROM collect.collection_account WHERE id = %s", (pid,))


def test_a_persona_platform_and_account_id_never_change_once_set(conn):
    import psycopg

    from uuid import uuid4

    pid = _persona(conn)
    # A fresh account id each run: a persona with a platform is never
    # deleted, so a fixed id would collide with the last run's row.
    uid = f"u:{uuid4().hex[:12]}"
    conn.execute("UPDATE collect.collection_account SET platform_uid = %s "
                 "WHERE id = %s", (uid, pid))
    for sql, args in (
            ("UPDATE collect.collection_account SET platform = 'XENFORO' WHERE id = %s",
             (pid,)),
            ("UPDATE collect.collection_account SET platform_uid = %s WHERE id = %s",
             (f"u:{uuid4().hex[:12]}", pid))):
        with pytest.raises(psycopg.errors.RaiseException, match="for life"):
            conn.execute(sql, args)


def test_healthy_under_a_credential_lock_is_accepted_and_still_locked(conn):
    from noctornal_api.collection import HEALTHY, PersonaVault

    actor, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid = _persona(conn)
    vault = PersonaVault(conn)
    vault.signal(pid, reason="banned", lock_code="ACCOUNT_BANNED")
    answer = vault.set_status(pid, HEALTHY, actor_id=actor, reason="try again")
    assert "new credential is enrolled" in answer["notice"]
    assert _row(conn, pid)[4] == "ACCOUNT_BANNED"


# --- one readiness predicate -------------------------------------------

@pytest.mark.parametrize("status,cooldown,hold,lock,usable", [
    ("HEALTHY", None, None, None, True),
    ("COOLDOWN", -1, None, None, True),
    ("COOLDOWN", None, None, None, False),
    ("COOLDOWN", +1, None, None, False),
    ("HEALTHY", +1, None, None, False),
    ("HEALTHY", None, +1, None, False),
    ("HEALTHY", None, -1, None, True),
    ("HEALTHY", None, None, "PLATFORM_REFUSED", False),
    ("LOCKED", None, None, None, False),
    ("BURNED", None, None, None, False),
])
def test_the_usable_predicate_and_the_gate_agree(conn, status, cooldown, hold,
                                                 lock, usable):
    from noctornal_api.collection import (
        PERSONA_USABLE_SQL,
        PersonaGate,
        PersonaUnavailable,
        PersonaVault,
    )

    now = datetime.now(timezone.utc)
    pid = _persona(conn, secret="predicate-secret-1")
    conn.execute(
        "UPDATE collect.collection_account SET status = %s, cooldown_until = %s "
        "WHERE id = %s",
        (status, now + timedelta(hours=cooldown) if cooldown else None, pid))
    if hold:
        # Written as the platform would, then aged by hand for the past case.
        conn.execute(
            "UPDATE collect.collection_account SET machine_hold_until = %s, "
            "machine_hold_reason = 'RATE_LIMITED' WHERE id = %s",
            (now + timedelta(hours=hold), pid))
    if lock:
        PersonaVault(conn).signal(pid, reason="x", lock_code=lock)
    sql = conn.execute(f"SELECT {PERSONA_USABLE_SQL} FROM collect.collection_account a "
                       f"WHERE a.id = %s", (pid,)).fetchone()[0]
    assert sql is usable
    gate = PersonaGate(conn, pid, actor_id=None, clearance=None, purpose="x",
                       source_id=None, need="PUBLIC_READ", platform="TELEGRAM")
    if usable:
        gate.check()
    else:
        with pytest.raises(PersonaUnavailable):
            gate.check()


# --- visibility and listings ------------------------------------------

def test_a_persona_bound_to_a_red_source_is_invisible_to_an_amber_manager(conn):
    from noctornal_api.collection import BURNED, CollectionNotFound, PersonaVault

    actor, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid = _persona(conn)
    h.source(conn, P, kind="TELEGRAM", parser="stubtg", classification="RED",
             persona=pid, base_url=None)
    vault = PersonaVault(conn)
    with pytest.raises(CollectionNotFound):
        vault.set_status(pid, BURNED, actor_id=actor, reason="x" * 6,
                         clearance="AMBER")
    assert str(pid) not in {p["id"] for p in vault.personas(clearance="AMBER")}
    assert str(pid) in {p["id"] for p in vault.personas(clearance="RED")}


def test_personas_lists_platform_egress_authority_and_bound_sources_and_never_a_secret_column(conn):
    from noctornal_api.collection import PersonaVault

    pid = _persona(conn, secret="listed-secret-1",
                   fingerprint={"user_agent": "Mozilla/5.0",
                                "active_window_utc": "07:00-23:00"})
    h.source(conn, P, kind="TELEGRAM", parser="stubtg", persona=pid, base_url=None)
    row = next(p for p in PersonaVault(conn).personas(clearance="RED")
               if p["id"] == str(pid))
    assert row["platform"] == "TELEGRAM" and row["credential_stored"] is True
    assert row["sources_bound"] == 1 and row["has_browser_identity"] is True
    assert row["active_window_utc"] == "07:00-23:00"
    assert row["egress_profile_name"].startswith(P)
    assert not any("secret_ciphertext" in k or "key_id" in k or "nonce" in k
                   for k in row)
    assert "listed-secret-1" not in str(row)


def test_egress_separation_reports_a_public_read_sharing_an_exit_with_a_persona(conn):
    from noctornal_api.collection import PersonaVault

    egress = h.egress_profile(conn, P)
    venue = h.source(conn, P, egress=egress)
    h.persona(conn, P, platform=None, egress=egress, venue=venue)
    findings = PersonaVault(conn).check_egress_separation(venue)
    assert any("public read and a persona share an exit" in f["risk"]
               for f in findings)


def _bind_above(conn, persona_id):
    """Bind the persona to a RED source, which hides it from an AMBER
    caller under PERSONA_VISIBLE_SQL."""
    red = h.source(conn, P, classification="RED", due=False)
    conn.execute("UPDATE collect.source SET collection_account_id = %s "
                 "WHERE id = %s", (persona_id, red))


def _handle(conn, persona_id):
    return conn.execute("SELECT handle FROM collect.collection_account "
                        "WHERE id = %s", (persona_id,)).fetchone()[0]


def test_egress_separation_never_names_a_persona_the_caller_cannot_see(conn):
    """Found by a rolled-back probe (2026-09-25): once
    PERSONA_VISIBLE_SQL looked at bound sources, personas() and set_status
    hid a persona bound to a RED source from an AMBER caller, and this
    check still named it, in both of its findings. It now lists only the
    handles the caller may see and says, as one bit, that another shares
    the exit."""
    from noctornal_api.collection import PersonaVault

    vault = PersonaVault(conn)
    shared = h.egress_profile(conn, P)
    venue = h.source(conn, P, due=False)
    seen = h.persona(conn, P, platform=None, egress=shared, venue=venue)
    hidden = h.persona(conn, P, platform=None, egress=shared, venue=venue)
    _bind_above(conn, hidden)

    amber = vault.check_egress_separation(venue, clearance="AMBER")
    assert [f["handles"] for f in amber] == [[_handle(conn, seen)]]
    assert amber[0]["persona_count"] == 1 and amber[0]["some_hidden"] is True
    assert _handle(conn, hidden) not in str(amber)
    red = vault.check_egress_separation(venue, clearance="RED")
    assert sorted(red[0]["handles"]) == sorted(
        [_handle(conn, seen), _handle(conn, hidden)])
    assert red[0]["some_hidden"] is False and red[0]["persona_count"] == 2

    # Two hidden personas and nobody the caller can see: nothing theirs to
    # act on, so no finding at all.
    other_exit = h.egress_profile(conn, P)
    quiet = h.source(conn, P, due=False)
    for _ in range(2):
        _bind_above(conn, h.persona(conn, P, platform=None, egress=other_exit,
                                    venue=quiet))
    assert vault.check_egress_separation(quiet, clearance="AMBER") == []
    assert len(vault.check_egress_separation(quiet, clearance="RED")) == 1


def test_the_public_read_leg_keeps_its_finding_without_the_hidden_handle(conn):
    """The source's own public read is a party the caller can see, so the
    finding stands; the persona it shares an exit with is not named."""
    from noctornal_api.collection import PersonaVault

    exit_ = h.egress_profile(conn, P)
    venue = h.source(conn, P, egress=exit_, due=False)
    hidden = h.persona(conn, P, platform=None, egress=exit_, venue=venue)
    _bind_above(conn, hidden)
    findings = PersonaVault(conn).check_egress_separation(venue, clearance="AMBER")
    assert len(findings) == 1
    assert "public read and a persona share an exit" in findings[0]["risk"]
    assert findings[0]["handles"] == [] and findings[0]["some_hidden"] is True
    assert findings[0]["persona_count"] == 0
    assert _handle(conn, hidden) not in str(findings)


def test_the_lease_refuses_what_the_gate_refuses(conn):
    """Until 2026-09-25 the lease had a rule of its own, and a
    COOLDOWN with no end, which PERSONA_USABLE_SQL (the gate, the due list
    and the proxy) reads as unusable, still opened through use(). Now the
    lease asks the same predicate; a stopping lease still opens it."""
    from noctornal_api.collection import (
        COOLDOWN,
        PersonaGate,
        PersonaUnavailable,
        PersonaVault,
    )

    actor, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid = _persona(conn, secret="open-ended-rest-1")
    vault = PersonaVault(conn)
    vault.set_status(pid, COOLDOWN, actor_id=actor, reason="rest it for now")
    assert _row(conn, pid)[1] is None, "a cooldown with no end"
    gate = PersonaGate(conn, pid, actor_id=actor, clearance="RED", purpose="x",
                       source_id=None, need="PUBLIC_READ", platform="TELEGRAM")
    with pytest.raises(PersonaUnavailable, match="until a person lifts"):
        gate.check()
    with pytest.raises(PersonaUnavailable, match="until a person lifts"):
        with vault.use(pid, actor_id=actor, purpose="read it anyway"):
            pass
    with vault.lease(pid, actor_id=actor, purpose="log out",
                     stopping=True) as lease:
        assert lease.value == "open-ended-rest-1"


def test_the_persona_row_reads_usability_as_the_sql_does(conn):
    """Persona.is_usable is the same rule as PERSONA_USABLE_SQL over the
    fields it carries, a COOLDOWN with no end included (2026-09-25)."""
    from noctornal_api.collection import PERSONA_USABLE_SQL, Persona

    now = datetime.now(timezone.utc)
    cases = [("HEALTHY", None), ("HEALTHY", now + timedelta(hours=1)),
             ("HEALTHY", now - timedelta(hours=1)), ("COOLDOWN", None),
             ("COOLDOWN", now + timedelta(hours=1)),
             ("COOLDOWN", now - timedelta(hours=1)), ("LOCKED", None),
             ("BURNED", None)]
    for status, cooldown in cases:
        pid = _persona(conn, status=status)
        conn.execute("UPDATE collect.collection_account SET cooldown_until = %s "
                     "WHERE id = %s", (cooldown, pid))
        sql = conn.execute(f"SELECT {PERSONA_USABLE_SQL} FROM "
                           "collect.collection_account a WHERE a.id = %s",
                           (pid,)).fetchone()[0]
        row = Persona(id=pid, source_id=None, handle="h", status=status,
                      cooldown_until=cooldown, egress_profile_id=None,
                      last_used_at=None, burn_reason=None)
        assert row.is_usable(now) is sql, (status, cooldown)


def test_a_person_reaches_the_gate_only_with_their_ceiling(conn):
    """No ceiling is the worker's reading and sees every persona; a person
    who reaches the gate without theirs is a caller that forgot it, refused
    before anything is read (2026-09-25)."""
    from noctornal_api.collection import CollectionError, PersonaGate

    actor, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid = _persona(conn, secret="ceiling-1")
    with pytest.raises(CollectionError, match="clearance, and none was given"):
        PersonaGate(conn, pid, actor_id=actor, clearance=None, purpose="x",
                    source_id=None, need="PUBLIC_READ", platform="TELEGRAM")
    PersonaGate(conn, pid, actor_id=None, clearance=None, purpose="x",
                source_id=None, need="PUBLIC_READ", platform="TELEGRAM").check()


def test_create_refuses_an_exit_another_persona_holds_whatever_its_status(conn):
    from noctornal_api.collection import BURNED, CollectionError, PersonaVault

    actor, _ = h.user(conn, P, roles=("COLLECTOR",))
    egress = h.egress_profile(conn, P)
    vault = PersonaVault(conn)
    first = vault.create(handle=f"{P}first", platform="TELEGRAM",
                         egress_profile_id=egress, actor_id=actor)
    vault.set_status(first["id"], BURNED, actor_id=actor, reason="burnt it")
    with pytest.raises(CollectionError, match="one persona, one egress profile"):
        vault.create(handle=f"{P}second", platform="TELEGRAM",
                     egress_profile_id=egress, actor_id=actor)
    assert _audit(conn, first["id"], "PERSONA_CREATED")


def test_egress_profiles_counts_what_the_caller_sees_and_one_bit_for_the_rest(conn):
    from noctornal_api.collection import PersonaVault

    egress = h.egress_profile(conn, P)
    pid = _persona(conn, egress=egress)
    h.source(conn, P, kind="TELEGRAM", parser="stubtg", classification="RED",
             persona=pid, base_url=None)
    amber = next(e for e in PersonaVault(conn).egress_profiles(clearance="AMBER")
                 if e["id"] == str(egress))
    red = next(e for e in PersonaVault(conn).egress_profiles(clearance="RED")
               if e["id"] == str(egress))
    assert amber["personas"] == 0 and amber["some_above_clearance"] is True
    assert amber["available"] is False, "the one bit of presence (docs/05)"
    assert red["personas"] == 1 and red["persona_platforms"] == ["TELEGRAM"]
    assert not any(k in amber for k in ("endpoint_ciphertext", "key_id"))


def test_store_and_destroy_with_no_actor_record_the_system_and_the_claimed_operator(conn):
    from noctornal_api.collection import PersonaVault

    pid = _persona(conn)
    detail = {"claimed_operator": "j.smith", "os_user": "noctornal", "host": "srv1"}
    vault = PersonaVault(conn)
    vault.store(pid, "enrolled-by-script", actor_id=None, detail=detail)
    vault.destroy_secret(pid, actor_id=None, reason="logout", detail=detail)
    for action in ("PERSONA_SECRET_STORED", "PERSONA_SECRET_DESTROYED"):
        actor, kind, recorded = _audit(conn, pid, action)[0]
        assert actor is None and kind == "SYSTEM"
        assert recorded["claimed_operator"] == "j.smith"

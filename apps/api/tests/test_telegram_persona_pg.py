"""A Telegram persona in the database: its egress profile for life, its
account id, its device, its enrolment, its holds, the enrolment gate that
lets a persona Telegram locked be enrolled again, and its sealed session
(roadmap F5.2, 2026-09-24). DATABASE_URL-gated.
"""
from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

import collection_helpers as h
import telegram_fake as tf
import telegram_pg as tp

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-tgper-"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    tf.guard_sockets(monkeypatch)
    tf.patch_routes(monkeypatch)
    c = connect()
    yield c
    tp.teardown(c, P)
    h.retire_users(c, P)
    c.close()


def _insert(conn, **cols):
    from psycopg.types.json import Jsonb

    values = {"handle": f"{P}p-{tp.rand_id()}", "status": "HEALTHY",
              "platform": "TELEGRAM", "fingerprint_profile": Jsonb(dict(tf.DEVICE)),
              **cols}
    names = ", ".join(values)
    marks = ", ".join(["%s"] * len(values))
    return conn.execute(f"INSERT INTO collect.collection_account ({names}) "
                        f"VALUES ({marks}) RETURNING id", tuple(values.values())).fetchone()[0]


def test_a_telegram_persona_must_name_an_egress_profile(conn):
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        _insert(conn, egress_profile_id=None)


def test_a_telegram_persona_is_registered_on_no_venue(conn):
    venue = h.source(conn, P, due=False)
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        _insert(conn, egress_profile_id=h.egress_profile(conn, P), source_id=venue)


def test_two_telegram_personas_never_share_an_egress_profile_even_after_a_burn(conn):
    from noctornal_api.collection import BURNED, PersonaVault

    actor, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid, egress, _uid = tp.persona(conn, P)
    PersonaVault(conn).set_status(pid, BURNED, actor_id=actor, reason="seen by an admin")
    with pytest.raises(psycopg.errors.UniqueViolation), conn.transaction():
        _insert(conn, egress_profile_id=egress)


def test_a_telegram_persona_keeps_its_egress_profile_for_life(conn):
    pid, _egress, _uid = tp.persona(conn, P)
    with pytest.raises(psycopg.errors.CheckViolation, match="for life"), conn.transaction():
        conn.execute("UPDATE collect.collection_account SET egress_profile_id = %s "
                     "WHERE id = %s", (h.egress_profile(conn, P), pid))


def test_one_telegram_account_cannot_be_two_personas(conn):
    _pid, _e, uid = tp.persona(conn, P)
    with pytest.raises(psycopg.errors.UniqueViolation), conn.transaction():
        tp.persona(conn, P, uid=uid)


@pytest.mark.parametrize("uid, error", [
    ("700000001", psycopg.errors.CheckViolation),
    ("u:3f9a0b1c2d4e", psycopg.errors.CheckViolation),
    ("c:1300000001", psycopg.errors.CheckViolation),
    ("u:0700000001", psycopg.errors.CheckViolation)])
def test_an_enrolled_persona_carries_a_typed_account_id(conn, uid, error):
    with pytest.raises(error), conn.transaction():
        tp.persona(conn, P, uid=uid)
    tp.persona(conn, P, uid=f"u:{tp.rand_id()}")


def test_an_enrolled_persona_needs_its_device_fingerprint(conn):
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        tp.persona(conn, P, fingerprint={"device_model": "Pixel 7"})


def test_an_enrolment_needs_an_account_id_and_a_sealed_secret(conn):
    pid, _e, _uid = tp.persona(conn, P, enrolled=False)
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE collect.collection_account SET session_enrolled_at = now(), "
                     "platform_uid = %s WHERE id = %s", (f"u:{tp.rand_id()}", pid))
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE collect.collection_account SET session_enrolled_at = now() "
                     "WHERE id = %s", (pid,))


def test_a_persona_under_a_flood_wait_can_still_be_burnt(conn):
    """Resolved by construction: a hold is
    the machine's column, so a burn under it succeeds and the hold stays."""
    from noctornal_api.collection import BURNED, HOLD_RATE_LIMITED, PersonaVault

    actor, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid, _e, _uid = tp.persona(conn, P)
    vault = PersonaVault(conn)
    until = datetime.now(timezone.utc) + timedelta(hours=1)
    vault.signal(pid, reason="flood wait", hold_until=until, hold_reason=HOLD_RATE_LIMITED)
    assert vault.set_status(pid, BURNED, actor_id=actor, reason="burnt by admin")["status"] == BURNED
    assert conn.execute("SELECT machine_hold_reason FROM collect.collection_account "
                        "WHERE id = %s", (pid,)).fetchone()[0] == HOLD_RATE_LIMITED


def test_a_live_flood_wait_cannot_be_cleared_by_hand(conn):
    from noctornal_api.collection import (
        HEALTHY,
        HOLD_RATE_LIMITED,
        PersonaGate,
        PersonaUnavailable,
        PersonaVault,
    )

    actor, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid, _e, _uid = tp.persona(conn, P)
    vault = PersonaVault(conn)
    vault.signal(pid, reason="flood wait", hold_reason=HOLD_RATE_LIMITED,
                 hold_until=datetime.now(timezone.utc) + timedelta(hours=1))
    answer = vault.set_status(pid, HEALTHY, actor_id=actor, reason="let it go")
    assert "stays paused" in answer["notice"]
    with pytest.raises(PersonaUnavailable):
        PersonaGate(conn, pid, actor_id=None, clearance=None, purpose="x",
                    source_id=None, need="PUBLIC_READ", platform="TELEGRAM").check()
    with pytest.raises(psycopg.errors.RaiseException, match="never shortened"), \
            conn.transaction():
        conn.execute("UPDATE collect.collection_account SET machine_hold_until = now() "
                     "WHERE id = %s", (pid,))


def test_a_burnt_telegram_persona_cannot_be_deleted_and_its_exit_stays_taken(conn):
    from noctornal_api.collection import BURNED, CollectionError, PersonaVault

    actor, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid, egress, _uid = tp.persona(conn, P)
    PersonaVault(conn).set_status(pid, BURNED, actor_id=actor, reason="burnt")
    with pytest.raises(psycopg.errors.RaiseException, match="never deleted"), \
            conn.transaction():
        conn.execute("DELETE FROM collect.collection_account WHERE id = %s", (pid,))
    with pytest.raises(CollectionError, match="one persona, one egress profile"):
        PersonaVault(conn).create(handle=f"{P}next", platform="TELEGRAM",
                                  egress_profile_id=egress, fingerprint=dict(tf.DEVICE),
                                  actor_id=actor)


# --- the enrolment gate ----------------------------------------------------------

def test_the_enrolment_gate_differs_from_the_foundations_by_the_lock_clause_only():
    from noctornal_api.collection import PERSONA_USABLE_SQL
    from noctornal_api.telegram_service import USABLE_IGNORING_LOCK_SQL, _LOCK_CLAUSE

    assert _LOCK_CLAUSE in PERSONA_USABLE_SQL
    assert USABLE_IGNORING_LOCK_SQL + "" != PERSONA_USABLE_SQL
    assert PERSONA_USABLE_SQL.replace(_LOCK_CLAUSE, "") == USABLE_IGNORING_LOCK_SQL
    assert "machine_lock_code" not in USABLE_IGNORING_LOCK_SQL


def _authority_for(conn, pid):
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                source_ids=[])
    operator, _ = h.user(conn, P, roles=("COLLECTOR",))
    return operator


def test_a_persona_telegram_locked_is_admitted_to_enrolment_only_once_its_credential_is_gone(
        conn):
    from noctornal_api.collection import PersonaUnavailable, PersonaVault
    from noctornal_api.telegram_service import enrolment_session

    pid, _e, _uid = tp.persona(conn, P)
    operator = _authority_for(conn, pid)
    vault = PersonaVault(conn)
    vault.signal(pid, reason="revoked", lock_code="CREDENTIAL_REVOKED")
    with pytest.raises(PersonaUnavailable, match="new credential"):
        with enrolment_session(conn, pid, actor_id=operator, clearance="RED",
                               purpose="enrol"):
            pass
    conn.execute("UPDATE collect.collection_account SET session_enrolled_at = NULL "
                 "WHERE id = %s", (pid,))
    vault.destroy_secret(pid, actor_id=operator, reason="logged out locally")
    with enrolment_session(conn, pid, actor_id=operator, clearance="RED",
                           purpose="enrol") as ctx:
        assert ctx.route.context == f"act:{pid}" and ctx.lease is None
    vault.store(pid, tf.secret_json(), actor_id=operator)
    assert conn.execute("SELECT machine_lock_code FROM collect.collection_account "
                        "WHERE id = %s", (pid,)).fetchone()[0] is None


@pytest.mark.parametrize("state", ["burnt", "held", "locked-status"])
def test_the_enrolment_gate_admits_nothing_else_the_foundation_refuses(conn, state):
    from noctornal_api.collection import (
        BURNED,
        HOLD_RATE_LIMITED,
        LOCKED,
        PersonaUnavailable,
        PersonaVault,
    )
    from noctornal_api.telegram_service import enrolment_session

    pid, _e, _uid = tp.persona(conn, P, enrolled=False)
    operator = _authority_for(conn, pid)
    vault = PersonaVault(conn)
    vault.signal(pid, reason="revoked", lock_code="CREDENTIAL_REVOKED")
    if state == "burnt":
        vault.set_status(pid, BURNED, actor_id=operator, reason="burnt")
    elif state == "held":
        vault.signal(pid, reason="wait", hold_reason=HOLD_RATE_LIMITED,
                     hold_until=datetime.now(timezone.utc) + timedelta(hours=1))
    else:
        vault.set_status(pid, LOCKED, actor_id=operator, reason="a person locked it")
    with pytest.raises(PersonaUnavailable):
        with enrolment_session(conn, pid, actor_id=operator, clearance="RED",
                               purpose="enrol"):
            pass


def test_a_person_needs_their_own_clearance_at_the_gate(conn):
    from noctornal_api.collection import CollectionError
    from noctornal_api.telegram_service import enrolment_session

    pid, _e, _uid = tp.persona(conn, P, enrolled=False)
    operator = _authority_for(conn, pid)
    with pytest.raises(CollectionError, match="clearance"):
        with enrolment_session(conn, pid, actor_id=operator, clearance=None,
                               purpose="enrol"):
            pass


# --- the sealed session -------------------------------------------------------------

def test_a_telegram_session_is_rewrapped_like_any_persona_secret(conn, monkeypatch):
    from noctornal_api.collection import PersonaVault
    from noctornal_api.security.sealed import SEALED_COLUMNS, rewrap_table
    from noctornal_api.telegram import TelegramSecret

    assert ("collect.collection_account", "secret_ciphertext",
            "secret_key_id") in SEALED_COLUMNS
    home = os.environ["NOCTORNAL_TOTP_KEK"]
    other = base64.b64encode(b"telegram-rotated-kek-32-bytes!!!").decode()
    pid, _e, _uid = tp.persona(conn, P)

    def key_of():
        return conn.execute("SELECT secret_key_id FROM collect.collection_account "
                            "WHERE id = %s", (pid,)).fetchone()[0]

    before = key_of()
    try:
        monkeypatch.setenv("NOCTORNAL_TOTP_KEK", other)
        monkeypatch.setenv("NOCTORNAL_TOTP_KEK_ID", "env:tg2")
        monkeypatch.setenv("NOCTORNAL_TOTP_KEK_RETIRED", f"{before}={home}")
        rewrap_table(conn, "collect.collection_account", "secret_ciphertext",
                     "secret_key_id")
        assert key_of() == "env:tg2"
        with PersonaVault(conn).lease(pid, actor_id=None, purpose="check") as lease:
            assert TelegramSecret.parse(lease.value).api_id == 1234567
    finally:
        monkeypatch.setenv("NOCTORNAL_TOTP_KEK", home)
        monkeypatch.setenv("NOCTORNAL_TOTP_KEK_ID", before)
        monkeypatch.setenv("NOCTORNAL_TOTP_KEK_RETIRED", f"env:tg2={other}")
        rewrap_table(conn, "collect.collection_account", "secret_ciphertext",
                     "secret_key_id")
        monkeypatch.delenv("NOCTORNAL_TOTP_KEK_ID")
        monkeypatch.delenv("NOCTORNAL_TOTP_KEK_RETIRED")
    assert key_of() == before


def test_redact_removes_the_session_and_api_hash_inside_a_use(conn):
    from noctornal_api.collection import PersonaVault, redact
    from noctornal_api.telegram import TelegramSecret

    pid, _e, _uid = tp.persona(conn, P)
    with PersonaVault(conn).lease(pid, actor_id=None, purpose="check") as lease:
        secret = TelegramSecret.parse(lease.value)
        # A message quoting leaves of the JSON, not the whole blob: each
        # leaf is registered on its own (the persona lease).
        text = redact(f'server said {secret.api_hash} and "session": "{secret.session}"')
    assert secret.api_hash not in text and secret.session not in text
    assert "server said" in text


# --- the facts the console shows ------------------------------------------------------

def test_attach_persona_facts_never_returns_a_secret_column_and_counts_only_chats_within_the_ceiling(
        conn):
    from noctornal_api.collection import HOLD_RATE_LIMITED, PersonaVault
    from noctornal_api.telegram_service import attach_persona_facts

    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    pid, _e, uid = tp.persona(conn, P)
    tp.chat(conn, P, persona_id=pid, resolved_by=recorder, classification="GREEN")
    tp.chat(conn, P, persona_id=pid, resolved_by=recorder, classification="AMBER")
    PersonaVault(conn).signal(pid, reason="w", hold_reason=HOLD_RATE_LIMITED,
                              hold_until=datetime.now(timezone.utc) + timedelta(minutes=30))
    rows = [p for p in PersonaVault(conn).personas(clearance="RED") if p["id"] == str(pid)]
    attach_persona_facts(conn, rows, "GREEN")
    facts = rows[0]["telegram"]
    assert facts["platform_uid"] == uid and facts["chats_bound"] == 1
    assert facts["session_enrolled_at"] is not None
    assert facts["hold"]["kind"] == HOLD_RATE_LIMITED
    assert "Telegram asked this persona to pause until" in facts["hold"]["words"]
    flat = repr(rows)
    assert "secret" not in "".join(facts) and "0123456789abcdef" not in flat
    assert "api_hash" not in flat and "session\":" not in flat

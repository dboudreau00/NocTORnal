"""PGP verification against Postgres: what earns a CONFIRMED binding.

`test_pgp.py` covers the verification logic. This covers the consequence:
a CLAIMED binding becoming CONFIRMED is the only automatic promotion in
Phase 7, and docs/10 says CONFIRMED is the grade that may carry weight in
identity resolution. So the tests here are mostly about what does NOT
earn it.

The last two tests go behind the service and write the table directly, to
show the CHECK constraints refuse the two traps on their own. That
duplication is deliberate: application checks are exactly the kind that
survive review and then get refactored away, and a constraint does not.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import pathlib
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; pgp service tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "pgp"


def _fix(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


VENDOR_FPR = _fix("vendor_fingerprint.txt").strip()
IMPOSTOR_FPR = _fix("impostor_fingerprint.txt").strip()
TOX_PUBKEY = _fix("tox_pubkey.txt").strip()
VENDOR_PUB = _fix("vendor_pub.asc")
IMPOSTOR_PUB = _fix("impostor_pub.asc")
SIGNED_WITH_TOX = _fix("signed_with_tox.asc")
SIGNED_WITHOUT_TOX = _fix("signed_without_tox.asc")
SIGNED_BY_IMPOSTOR = _fix("signed_by_impostor.asc")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'pgp-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM comms.pgp_verification WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM comms.channel_binding WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'pgp-%@noctornal.test'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"pgp-{uuid4().hex[:8]}@noctornal.test", "Pgp", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-PGP-{uuid4().hex[:6]}", title="Pgp",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


@pytest.fixture
def svc(conn):
    from noctornal_api.pgp import PgpService
    return PgpService(conn)


def _tox_binding(conn, case_id, actor):
    from noctornal_api.comms import CommsService
    return CommsService(conn).bind(
        case_id=case_id, platform_key="TOX",
        observed=TOX_PUBKEY + "11111111" + "2222", created_by=actor)["id"]


# ---------------------------------------------------------------------------
# What earns a confirmation
# ---------------------------------------------------------------------------

def test_a_signature_over_the_identifier_upgrades_the_binding(conn, svc):
    uid = _user(conn)
    case_id = _case(conn, uid)
    binding = _tox_binding(conn, case_id, uid)

    out = svc.verify_and_record(
        case_id=case_id, signed_message=SIGNED_WITH_TOX,
        public_key=VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        created_by=uid, channel_binding_id=binding)

    assert out["outcome"] == "VERIFIED"
    assert out["binding_upgraded"] is True
    row = conn.execute(
        """SELECT verification, verification_note FROM comms.channel_binding
            WHERE id = %s""", (binding,)).fetchone()
    assert row[0] == "CONFIRMED"
    # The schema already refuses a CONFIRMED binding with no stated method;
    # this checks the method it states is the useful one.
    assert VENDOR_FPR in row[1]


@pytest.mark.parametrize("message,key,fingerprint,expected", [
    (SIGNED_BY_IMPOSTOR, IMPOSTOR_PUB, VENDOR_FPR, "KEY_MISMATCH"),
    (SIGNED_WITHOUT_TOX, VENDOR_PUB, VENDOR_FPR, "VALUE_NOT_IN_PAYLOAD"),
    (SIGNED_WITH_TOX.replace("Vendor contact", "Vendor CONTACT"),
     VENDOR_PUB, VENDOR_FPR, "BAD_SIGNATURE"),
    ("not a pgp message", VENDOR_PUB, VENDOR_FPR, "MALFORMED"),
])
def test_nothing_short_of_a_verified_signature_upgrades_a_binding(
        conn, svc, message, key, fingerprint, expected):
    uid = _user(conn)
    case_id = _case(conn, uid)
    binding = _tox_binding(conn, case_id, uid)

    out = svc.verify_and_record(
        case_id=case_id, signed_message=message, public_key=key,
        claimed_fingerprint=fingerprint, created_by=uid,
        channel_binding_id=binding)

    assert out["outcome"] == expected
    assert out["binding_upgraded"] is False
    assert conn.execute(
        "SELECT verification FROM comms.channel_binding WHERE id = %s",
        (binding,)).fetchone()[0] == "CLAIMED"


def test_an_absent_verifier_never_upgrades_a_binding(conn, svc, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_GPG", "/nonexistent/gpg-binary")
    uid = _user(conn)
    case_id = _case(conn, uid)
    binding = _tox_binding(conn, case_id, uid)
    out = svc.verify_and_record(
        case_id=case_id, signed_message=SIGNED_WITH_TOX,
        public_key=VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        created_by=uid, channel_binding_id=binding)
    assert out["outcome"] == "NO_VERIFIER"
    assert out["binding_upgraded"] is False
    assert conn.execute(
        "SELECT verification FROM comms.channel_binding WHERE id = %s",
        (binding,)).fetchone()[0] == "CLAIMED"


# ---------------------------------------------------------------------------
# A verification confirms the binding's OWN identifier
# ---------------------------------------------------------------------------

def test_a_signature_over_one_identifier_cannot_confirm_another(conn, svc):
    """Otherwise a genuine signature over the vendor's Tox key could be
    used to upgrade a binding holding somebody else's Jabber."""
    from noctornal_api.pgp import PgpError
    uid = _user(conn)
    case_id = _case(conn, uid)
    binding = _tox_binding(conn, case_id, uid)
    with pytest.raises(PgpError):
        svc.verify_and_record(
            case_id=case_id, signed_message=SIGNED_WITH_TOX,
            public_key=VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
            created_by=uid, channel_binding_id=binding,
            confirms_value="someone_else@jabber.tld")


def test_a_binding_in_another_case_is_refused(conn, svc):
    """A verification recorded against the wrong case is a disclosure as
    well as an error."""
    from noctornal_api.pgp import PgpError
    uid = _user(conn)
    mine, theirs = _case(conn, uid), _case(conn, uid)
    binding = _tox_binding(conn, theirs, uid)
    with pytest.raises(PgpError):
        svc.verify_and_record(
            case_id=mine, signed_message=SIGNED_WITH_TOX,
            public_key=VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
            created_by=uid, channel_binding_id=binding)


# ---------------------------------------------------------------------------
# Every outcome is recorded
# ---------------------------------------------------------------------------

def test_failed_verifications_are_recorded_too(conn, svc):
    """A verification queue you can only see the successes of is a queue
    that hides its own gaps."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    svc.verify_and_record(
        case_id=case_id, signed_message=SIGNED_BY_IMPOSTOR,
        public_key=IMPOSTOR_PUB, claimed_fingerprint=VENDOR_FPR,
        created_by=uid, confirms_value=TOX_PUBKEY)
    rows = svc.verifications(case_id, clearance="RED")
    assert len(rows) == 1
    assert rows[0]["outcome"] == "KEY_MISMATCH"
    assert rows[0]["signing_fingerprint"] == IMPOSTOR_FPR
    assert rows[0]["claimed_fingerprint"] == VENDOR_FPR


def test_not_checked_is_distinguishable_from_checked_and_failed(conn, svc):
    """Without the distinction an analyst reads an unchecked claim as a
    checked-and-rejected one."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    unchecked = _tox_binding(conn, case_id, uid)
    from noctornal_api.comms import CommsService
    checked = CommsService(conn).bind(
        case_id=case_id, platform_key="XMPP", observed="v@shop.tld",
        created_by=uid)["id"]
    svc.verify_and_record(
        case_id=case_id, signed_message=SIGNED_WITHOUT_TOX,
        public_key=VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        created_by=uid, channel_binding_id=checked)

    by_id = {r["channel_binding_id"]: r
             for r in svc.unverified_claims(case_id, clearance="RED")}
    assert by_id[str(unchecked)]["verification_attempted"] is False
    assert by_id[str(checked)]["verification_attempted"] is True


def test_the_verification_is_audited(conn, svc):
    uid = _user(conn)
    case_id = _case(conn, uid)
    binding = _tox_binding(conn, case_id, uid)
    svc.verify_and_record(
        case_id=case_id, signed_message=SIGNED_WITH_TOX,
        public_key=VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        created_by=uid, channel_binding_id=binding)
    detail = conn.execute(
        """SELECT detail FROM audit.event
            WHERE case_id = %s AND action = 'PGP_VERIFICATION'""",
        (case_id,)).fetchone()[0]
    assert detail["outcome"] == "VERIFIED"
    assert detail["binding_upgraded"] is True
    assert detail["signing_fingerprint"] == VENDOR_FPR


# ---------------------------------------------------------------------------
# The traps, held by the schema rather than by this file
# ---------------------------------------------------------------------------

def test_the_schema_refuses_a_verified_row_signed_by_a_different_key(conn):
    """TRAP 1, at the level that does not get refactored away."""
    import psycopg
    uid = _user(conn)
    case_id = _case(conn, uid)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO comms.pgp_verification
                   (case_id, claimed_fingerprint, signing_fingerprint,
                    confirms_value, signed_payload_sha256, value_in_payload,
                    outcome, verifier, created_by)
               VALUES (%s, %s, %s, %s, %s, true, 'VERIFIED', 'GPG', %s)""",
            (case_id, VENDOR_FPR, IMPOSTOR_FPR, TOX_PUBKEY,
             b"\x00" * 32, uid))


def test_the_schema_refuses_a_verified_row_whose_value_was_not_signed(conn):
    """TRAP 2, likewise."""
    import psycopg
    uid = _user(conn)
    case_id = _case(conn, uid)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO comms.pgp_verification
                   (case_id, claimed_fingerprint, signing_fingerprint,
                    confirms_value, signed_payload_sha256, value_in_payload,
                    outcome, verifier, created_by)
               VALUES (%s, %s, %s, %s, %s, false, 'VERIFIED', 'GPG', %s)""",
            (case_id, VENDOR_FPR, VENDOR_FPR, TOX_PUBKEY, b"\x00" * 32, uid))


def test_the_schema_refuses_a_confirmation_with_no_verifier(conn):
    """The path where an absent gpg silently becomes a confirmation."""
    import psycopg
    uid = _user(conn)
    case_id = _case(conn, uid)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO comms.pgp_verification
                   (case_id, claimed_fingerprint, signing_fingerprint,
                    confirms_value, signed_payload_sha256, value_in_payload,
                    outcome, verifier, created_by)
               VALUES (%s, %s, %s, %s, %s, true, 'VERIFIED', 'NONE', %s)""",
            (case_id, VENDOR_FPR, VENDOR_FPR, TOX_PUBKEY, b"\x00" * 32, uid))


def test_the_schema_refuses_a_malformed_fingerprint(conn):
    """A fingerprint with spaces left in would not match one without, and
    the mismatch would surface as an accusation."""
    import psycopg
    uid = _user(conn)
    case_id = _case(conn, uid)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO comms.pgp_verification
                   (case_id, claimed_fingerprint, outcome, verifier,
                    created_by)
               VALUES (%s, %s, 'NO_VERIFIER', 'NONE', %s)""",
            (case_id, "4A2B 1C9D 8E7F 0011 2233 4455 6677 8899 AABB CCDD",
             uid))

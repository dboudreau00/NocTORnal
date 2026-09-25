"""Detached signatures and signing subkeys against Postgres and over HTTP
(F10a, comms, 2026-09-24): what a verification row records about the
signature, and the CHECK that a VERIFIED row names the key that signed or
its primary, with the NULL trap held by name. Migration 0087's downgrade
refusal is exercised inside a transaction that is always rolled back.

Rows are deleted at teardown (pgp_support.teardown).
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import pathlib

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set; gated")

from pgp_support import (  # noqa: E402
    SUB_PRIMARY,
    SUB_PUB,
    SUB_SIGNING,
    TOX_PUBKEY,
    Svc,
    auth,
    block,
    case,
    fix_bytes,
    session,
    teardown,
    tox_binding,
    user,
)

LIKE = "pgpd-%@noctornal.test"
DATA = fix_bytes("detached_data.txt")
SIG = fix_bytes("detached_binary.sig")
MIGRATIONS = pathlib.Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
SUBKEY_BLOCK = f"PGP: {SUB_PRIMARY}\nTOX: {TOX_PUBKEY}\n"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, LIKE)
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def test_a_detached_verification_upgrades_the_binding(conn):
    uid = user(conn, "pgpd")
    case_id = case(conn, uid)
    binding = tox_binding(conn, case_id, uid)
    cited = block(conn, case_id, uid, SUBKEY_BLOCK)["id"]
    out = Svc(conn).verify_and_record(
        case_id=case_id, created_by=uid, form="DETACHED", signature=SIG,
        signed_data=DATA, public_key=SUB_PUB, claimed_fingerprint=SUB_PRIMARY,
        channel_binding_id=binding, contact_block_id=cited)
    assert out["outcome"] == "VERIFIED", out["detail"]
    assert out["binding_upgraded"] is True
    assert out["form"] == "DETACHED"
    assert out["signing_fingerprint"] == SUB_SIGNING
    assert out["signing_primary_fingerprint"] == SUB_PRIMARY
    assert out["attribution"] == "SAME_BLOCK"


def test_a_detached_verified_row_digests_the_supplied_data(conn):
    uid = user(conn, "pgpd")
    case_id = case(conn, uid)
    out = Svc(conn).verify_and_record(
        case_id=case_id, created_by=uid, form="DETACHED", signature=SIG,
        signed_data=DATA, public_key=SUB_PUB, claimed_fingerprint=SUB_PRIMARY,
        confirms_value=TOX_PUBKEY)
    assert out["outcome"] == "VERIFIED"
    row = conn.execute(
        """SELECT signed_payload_sha256, signature_form, signature_class
             FROM comms.pgp_verification WHERE id = %s""", (out["id"],)).fetchone()
    assert bytes(row[0]) == hashlib.sha256(DATA).digest()
    assert row[1] == "DETACHED" and row[2] == "00"


def _insert(conn, case_id, uid, **cols):
    base = {"case_id": case_id, "claimed_fingerprint": SUB_PRIMARY,
            "signing_fingerprint": SUB_SIGNING, "confirms_value": TOX_PUBKEY,
            "signed_payload_sha256": b"\x00" * 32, "value_in_payload": True,
            "outcome": "VERIFIED", "verifier": "GPG", "status_output": "x",
            "created_by": uid}
    base.update(cols)
    names = ", ".join(base)
    marks = ", ".join(["%s"] * len(base))
    conn.execute(f"INSERT INTO comms.pgp_verification ({names}) VALUES ({marks})",
                 tuple(base.values()))


def test_the_schema_accepts_a_verified_row_matched_on_the_primary(conn):
    uid = user(conn, "pgpd")
    case_id = case(conn, uid)
    _insert(conn, case_id, uid, signing_primary_fingerprint=SUB_PRIMARY)


def test_a_missing_primary_does_not_let_a_mismatch_through(conn):
    """The NULL trap: written as IN (signing, primary), a NULL primary
    makes the CHECK's expression NULL, and a CHECK passes on NULL."""
    uid = user(conn, "pgpd")
    case_id = case(conn, uid)
    with pytest.raises(psycopg.errors.CheckViolation):
        _insert(conn, case_id, uid, signing_primary_fingerprint=None)


def test_the_schema_refuses_an_unknown_form(conn):
    uid = user(conn, "pgpd")
    case_id = case(conn, uid)
    with pytest.raises(psycopg.errors.CheckViolation):
        _insert(conn, case_id, uid, outcome="BAD_SIGNATURE",
                signature_form="OPAQUE")


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _owner(conn, client):
    uid = user(conn, "pgpd", global_roles=("CASE_OWNER",))
    return session(conn, uid), case(conn, uid)


def test_a_detached_check_over_http(conn, client):
    token, case_id = _owner(conn, client)
    url = f"/api/v1/cases/{case_id}/comms/pgp/verify"
    b64 = {"form": "DETACHED",
           "signature_base64": base64.b64encode(SIG).decode(),
           "signed_data_base64": base64.b64encode(DATA).decode(),
           "public_key": SUB_PUB, "claimed_fingerprint": SUB_PRIMARY,
           "confirms_value": TOX_PUBKEY}
    r = client.post(url, headers=auth(token), json=b64)
    assert r.status_code == 201, r.text
    assert r.json()["outcome"] == "VERIFIED" and r.json()["form"] == "DETACHED"

    mixed = dict(b64, signed_message="-----BEGIN PGP SIGNED MESSAGE-----")
    assert client.post(url, headers=auth(token), json=mixed).status_code == 422
    two = dict(b64, signature="-----BEGIN PGP SIGNATURE-----")
    assert client.post(url, headers=auth(token), json=two).status_code == 422
    bad = dict(b64, signature_base64="not*base64")
    r = client.post(url, headers=auth(token), json=bad)
    assert r.status_code == 400 and "not base64" in r.json()["detail"]


def test_an_oversized_check_is_413(conn, client):
    token, case_id = _owner(conn, client)
    r = client.post(
        f"/api/v1/cases/{case_id}/comms/pgp/verify",
        headers=dict(auth(token), **{"Content-Type": "application/json"}),
        content=b'{"signed_message": "' + b"A" * (5 * 1024 * 1024) + b'"}')
    assert r.status_code == 413


def test_a_body_with_no_form_still_verifies_clearsigned(conn, client):
    from pgp_support import SIGNED_WITH_TOX, VENDOR_FPR, VENDOR_PUB
    token, case_id = _owner(conn, client)
    r = client.post(f"/api/v1/cases/{case_id}/comms/pgp/verify",
                    headers=auth(token),
                    json={"signed_message": SIGNED_WITH_TOX,
                          "public_key": VENDOR_PUB,
                          "claimed_fingerprint": VENDOR_FPR,
                          "confirms_value": TOX_PUBKEY})
    assert r.status_code == 201
    assert r.json()["outcome"] == "VERIFIED"
    assert r.json()["form"] == "CLEARSIGNED"


# ---------------------------------------------------------------------------
# 0087's downgrade refuses what the older schema cannot hold
# ---------------------------------------------------------------------------

class _RolledBack(Exception):
    pass


def _migration(name: str):
    path = next(MIGRATIONS.glob(f"{name}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_downgrade_refuses_while_a_detached_row_exists(conn):
    uid = user(conn, "pgpd")
    case_id = case(conn, uid)
    Svc(conn).verify_and_record(
        case_id=case_id, created_by=uid, form="DETACHED", signature=SIG,
        signed_data=DATA, public_key=SUB_PUB, claimed_fingerprint=SUB_PRIMARY)
    m0087 = _migration("0087")
    raised = None
    try:
        with conn.transaction():
            try:
                conn.execute(m0087.DOWNGRADE_SQL)
            except psycopg.errors.RaiseException as exc:
                raised = exc
            raise _RolledBack
    except _RolledBack:
        pass
    assert raised is not None, "the downgrade ran with a DETACHED row present"
    assert "refusing to downgrade 0087" in str(raised)
    assert conn.execute(
        "SELECT count(*) FROM information_schema.columns WHERE table_schema = "
        "'comms' AND table_name = 'pgp_verification' AND column_name = "
        "'signature_form'").fetchone()[0] == 1

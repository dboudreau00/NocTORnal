"""The key registry over HTTP (F10b, comms, 2026-09-24): the gates, the
closed-case rule, the body cap, the one 404, and the contact block's entry
ids the console confirms against.

Rows are deleted at teardown (pgp_support.teardown).
"""
from __future__ import annotations

import base64
import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set; gated")

from pgp_support import (  # noqa: E402
    VENDOR_FPR,
    VENDOR_PUB,
    assign,
    auth,
    case,
    fix_bytes,
    session,
    teardown,
    user,
)

LIKE = "pgph-%@noctornal.test"


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


def _owner(conn):
    uid = user(conn, "pgph", global_roles=("CASE_OWNER",))
    return uid, session(conn, uid), case(conn, uid)


def _base(case_id):
    return f"/api/v1/cases/{case_id}/comms/pgp"


def _import(client, token, case_id, **extra):
    body = {"source": "PASTE", "armor": VENDOR_PUB,
            "source_ref": "the vendor's forum profile"} | extra
    return client.post(f"{_base(case_id)}/keys", headers=auth(token), json=body)


def test_an_import_then_a_confirmation_over_http(conn, client):
    _uid, token, case_id = _owner(conn)
    r = _import(client, token, case_id)
    assert r.status_code == 201, r.text
    key_id = r.json()["keys"][0]["id"]
    blk = client.post(f"/api/v1/cases/{case_id}/comms/contact-blocks",
                      headers=auth(token),
                      json={"raw_text": f"PGP: {VENDOR_FPR}\n",
                            "source_ref": "https://forum/profile"}).json()
    # The block returns each entry's id (F10b): the line is confirmed by id.
    entry = blk["entries"][0]["id"]
    got = client.get(f"/api/v1/cases/{case_id}/comms/contact-blocks/{blk['id']}",
                     headers=auth(token)).json()
    assert got["entries"][0]["id"] == entry
    r = client.post(f"{_base(case_id)}/keys/{key_id}/confirm",
                    headers=auth(token), json={"contact_block_entry_id": entry})
    assert r.status_code == 200, r.text
    assert r.json()["confirmation"]["against"] == "CONTACT_BLOCK"
    listed = client.get(f"{_base(case_id)}/keys", headers=auth(token)).json()
    assert listed["keys"][0]["confirmation"]["line_no"] == 1
    r = client.get(f"{_base(case_id)}/published-fingerprints", headers=auth(token))
    assert r.json()["fingerprints"][0]["usable"] is True


def test_a_file_import_is_base64_with_its_name(conn, client):
    _uid, token, case_id = _owner(conn)
    data = base64.b64encode(fix_bytes("wkd_vendor.bin")).decode()
    r = _import(client, token, case_id, source="FILE", armor=None,
                data_base64=data, filename="vendor.gpg")
    assert r.status_code == 201, r.text
    assert r.json()["keys"][0]["acquisition"]["filename"] == "vendor.gpg"
    assert _import(client, token, case_id, source="FILE", armor=None,
                   data_base64="*", filename="x").status_code == 400
    assert _import(client, token, case_id, source="FILE").status_code == 422


def test_reads_need_comms_read_and_writes_comms_bind(conn, client):
    owner, token, case_id = _owner(conn)
    key_id = _import(client, token, case_id).json()["keys"][0]["id"]
    reader = user(conn, "pgph")
    assign(conn, case_id, reader, "READ_ONLY")
    rtoken = session(conn, reader)
    assert client.get(f"{_base(case_id)}/keys", headers=auth(rtoken)).status_code == 200
    assert client.get(f"{_base(case_id)}/keys/{key_id}",
                      headers=auth(rtoken)).status_code == 200
    assert _import(client, rtoken, case_id).status_code == 403
    assert client.post(f"{_base(case_id)}/keys/{key_id}/retire",
                       headers=auth(rtoken),
                       json={"reason": "not mine to retire"}).status_code == 403


def test_a_closed_case_refuses_every_write(conn, client):
    _uid, token, case_id = _owner(conn)
    key_id = _import(client, token, case_id).json()["keys"][0]["id"]
    conn.execute('UPDATE core."case" SET status = \'CLOSED\' WHERE id = %s',
                 (case_id,))
    assert _import(client, token, case_id,
                   source_ref="another profile").status_code == 409
    assert client.post(f"{_base(case_id)}/keys/{key_id}/confirm",
                       headers=auth(token),
                       json={"published_fingerprint": VENDOR_FPR,
                             "source_ref": "vendor site"}).status_code == 409
    assert client.post(f"{_base(case_id)}/keys/{key_id}/retire",
                       headers=auth(token),
                       json={"reason": "a retirement"}).status_code == 409
    assert client.get(f"{_base(case_id)}/keys", headers=auth(token)).status_code == 200


def test_an_oversized_import_is_413(conn, client):
    _uid, token, case_id = _owner(conn)
    r = client.post(f"{_base(case_id)}/keys",
                    headers=dict(auth(token), **{"Content-Type": "application/json"}),
                    content=b'{"source": "PASTE", "armor": "' + b"A" * (3 * 1024 * 1024)
                    + b'", "source_ref": "x"}')
    assert r.status_code == 413


def test_a_hidden_key_and_a_random_id_are_the_same_404(conn, client):
    _owner_id, token, case_id = _owner(conn)
    red = _import(client, token, case_id, classification="RED",
                  source_ref="red copy").json()["keys"][0]["id"]
    amber = user(conn, "pgph", clearance="AMBER")
    assign(conn, case_id, amber, "ANALYST")
    atoken = session(conn, amber)
    details = []
    for key_id in (red, str(uuid4())):
        r = client.get(f"{_base(case_id)}/keys/{key_id}", headers=auth(atoken))
        assert r.status_code == 404
        details.append(r.json()["detail"])
        r = client.post(f"{_base(case_id)}/keys/{key_id}/retire",
                        headers=auth(atoken), json={"reason": "a retirement"})
        assert r.status_code == 404
    assert details[0] == details[1]
    assert client.get(f"{_base(case_id)}/keys", headers=auth(atoken)).json() == {"keys": []}


def test_a_refused_confirmation_is_409(conn, client):
    _uid, token, case_id = _owner(conn)
    key_id = _import(client, token, case_id).json()["keys"][0]["id"]
    r = client.post(f"{_base(case_id)}/keys/{key_id}/confirm", headers=auth(token),
                    json={"published_fingerprint": "C" * 40,
                          "source_ref": "vendor site"})
    assert r.status_code == 409
    assert "not this key's" in r.json()["detail"]
    r = client.post(f"{_base(case_id)}/keys/{key_id}/confirm", headers=auth(token),
                    json={"published_fingerprint": "C" * 40})
    assert r.status_code == 422


def test_a_registry_key_verifies_over_http(conn, client):
    from pgp_support import SIGNED_WITH_TOX, TOX_PUBKEY
    _uid, token, case_id = _owner(conn)
    key_id = _import(client, token, case_id).json()["keys"][0]["id"]
    client.post(f"{_base(case_id)}/keys/{key_id}/confirm", headers=auth(token),
                json={"published_fingerprint": VENDOR_FPR,
                      "source_ref": "the vendor's own site"})
    r = client.post(f"{_base(case_id)}/verify", headers=auth(token),
                    json={"signed_message": SIGNED_WITH_TOX, "pgp_key_id": key_id,
                          "confirms_value": TOX_PUBKEY})
    assert r.status_code == 201, r.text
    assert r.json()["outcome"] == "VERIFIED"
    assert r.json()["claimed_fingerprint_basis"] == "CONFIRMED_KEY"
    both = client.post(f"{_base(case_id)}/verify", headers=auth(token),
                       json={"signed_message": SIGNED_WITH_TOX, "pgp_key_id": key_id,
                             "public_key": VENDOR_PUB, "claimed_fingerprint": VENDOR_FPR})
    assert both.status_code == 422
    ref = client.post(f"{_base(case_id)}/verify", headers=auth(token),
                      json={"signed_message": SIGNED_WITH_TOX, "pgp_key_id": key_id,
                            "claimed_fingerprint_source_ref": "x"})
    assert ref.status_code == 422
    ledger = client.get(f"{_base(case_id)}", headers=auth(token)).json()
    assert ledger["verifications"][0]["pgp_key_id"] == key_id

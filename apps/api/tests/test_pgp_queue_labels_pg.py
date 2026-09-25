"""The verification queue shows what was checked, to those allowed to see
the check, and the verify route reads nothing through labels (F10-fix,
comms, 2026-09-24).

- The queue and the ledger share ONE visibility predicate: a check that
  cites a block, a binding or a key above the reader reads to them as no
  check (the queue's own unfiltered EXISTS would have been an existence
  and outcome oracle the moment the console showed it).
- The verify route loads the binding and the block under the caller's
  labels BEFORE gpg is forked: a hidden, other-case or unknown one is the
  same 404, and a mismatch message only ever names a value the caller can
  see.
- A binding with no durable value is refused before gpg, not with a 500
  from the 0037 trigger after one.
- A write is never judged through a case-scoped break-glass grant (that
  would count no use on the officer's card).

Rows are deleted at teardown (pgp_support.teardown).
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set; gated")

from pgp_support import (  # noqa: E402
    SIGNED_WITH_TOX,
    TOX_PUBKEY,
    VENDOR_FPR,
    VENDOR_PUB,
    assign,
    auth,
    block,
    case,
    session,
    teardown,
    tox_binding,
    user,
)

LIKE = "pgpq-%@noctornal.test"
SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "noctornal_api"


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


def _row(conn, case_id, actor, binding, outcome, at, *, block_id=None):
    conn.execute(
        """INSERT INTO comms.pgp_verification
               (case_id, channel_binding_id, contact_block_id,
                claimed_fingerprint, outcome, verifier, created_by, verified_at)
           VALUES (%s, %s, %s, %s, %s, 'GPG', %s, %s)""",
        (case_id, binding, block_id, VENDOR_FPR, outcome, actor, at))


def _svc(conn):
    from noctornal_api.pgp import PgpService
    return PgpService(conn)


def test_the_queue_reports_the_latest_visible_outcome(conn):
    """Explicit times: this host's WSL clock steps backwards, and
    transaction time would flake the order."""
    uid = user(conn, "pgpq")
    case_id = case(conn, uid)
    binding = tox_binding(conn, case_id, uid)
    _row(conn, case_id, uid, binding, "BAD_SIGNATURE",
         datetime(2026, 9, 1, 10, tzinfo=UTC))
    _row(conn, case_id, uid, binding, "KEY_MISMATCH",
         datetime(2026, 9, 2, 10, tzinfo=UTC))
    (claim,) = _svc(conn).unverified_claims(case_id, clearance="RED")
    assert claim["channel_binding_id"] == str(binding)
    assert claim["verification_attempted"] is True
    assert claim["last_outcome"] == "KEY_MISMATCH"
    assert claim["last_verified_at"].startswith("2026-09-02T10:00:00")
    assert claim["confirmable"] is True


def test_a_check_citing_a_hidden_block_is_invisible_in_the_queue_and_the_ledger(conn):
    uid = user(conn, "pgpq")
    case_id = case(conn, uid)
    binding = tox_binding(conn, case_id, uid, classification="AMBER")
    red_block = block(conn, case_id, uid, classification="RED")["id"]
    _row(conn, case_id, uid, binding, "BAD_SIGNATURE",
         datetime(2026, 9, 3, tzinfo=UTC), block_id=red_block)

    amber = _svc(conn)
    (claim,) = amber.unverified_claims(case_id, clearance="AMBER")
    assert claim["verification_attempted"] is False
    assert claim["last_outcome"] is None and claim["last_verified_at"] is None
    assert amber.verifications(case_id, clearance="AMBER") == []

    (claim,) = amber.unverified_claims(case_id, clearance="RED")
    assert claim["verification_attempted"] is True
    assert claim["last_outcome"] == "BAD_SIGNATURE"
    assert len(amber.verifications(case_id, clearance="RED")) == 1


def test_the_queue_and_the_ledger_share_one_predicate():
    """One copy of each clause: the ledger, the queue and every read in
    pgp_keys.py build on `_VISIBLE_VERIFICATION`, never a partial copy."""
    pgp_src = (SRC / "pgp.py").read_text(encoding="utf-8")
    keys_src = (SRC / "pgp_keys.py").read_text(encoding="utf-8")
    from noctornal_api.pgp import PgpService, _VISIBLE_VERIFICATION
    import inspect
    for method in (PgpService.verifications, PgpService.unverified_claims):
        assert "_VISIBLE_VERIFICATION" in inspect.getsource(method)
    for clause in ("vb.id = v.channel_binding_id", "vk.id = v.contact_block_id",
                   "vpk.id = v.pgp_key_id"):
        assert clause in _VISIBLE_VERIFICATION
        assert pgp_src.count(clause) == 1, clause
        assert clause not in keys_src, clause
    # The reads in pgp_keys.py that touch verification rows use it.
    assert keys_src.count("{_VISIBLE_VERIFICATION}") >= 2
    assert not re.search(r"FROM comms\.pgp_verification v\s+WHERE(?![^;]*"
                         r"_VISIBLE_VERIFICATION)", keys_src.replace("\n", " "))


def test_a_claim_without_a_durable_value_is_not_confirmable(conn):
    from noctornal_api.comms import CommsService
    uid = user(conn, "pgpq")
    case_id = case(conn, uid)
    CommsService(conn).bind(case_id=case_id, platform_key="TELEGRAM",
                            observed="@some_vendor", created_by=uid)
    (claim,) = _svc(conn).unverified_claims(case_id, clearance="RED")
    assert claim["durable_value"] is None
    assert claim["confirmable"] is False


# ---------------------------------------------------------------------------
# The verify route, before gpg
# ---------------------------------------------------------------------------

def _no_gpg(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("gpg was forked for a refused request")
    monkeypatch.setattr(subprocess, "run", refuse)


def _body(**kw):
    body = {"signed_message": SIGNED_WITH_TOX, "public_key": VENDOR_PUB,
            "claimed_fingerprint": VENDOR_FPR}
    body.update({k: str(v) for k, v in kw.items()})
    return body


def test_verify_refuses_a_binding_above_the_caller_before_gpg(conn, client,
                                                              monkeypatch):
    owner = user(conn, "pgpq", global_roles=("CASE_OWNER",))
    case_id = case(conn, owner)
    red = tox_binding(conn, case_id, owner, classification="RED")
    other = tox_binding(conn, case(conn, owner), owner)
    amber = user(conn, "pgpq", clearance="AMBER")
    assign(conn, case_id, amber, "ANALYST")
    token = session(conn, amber)
    _no_gpg(monkeypatch)
    bodies = []
    for binding in (red, other, uuid4()):
        r = client.post(f"/api/v1/cases/{case_id}/comms/pgp/verify",
                        headers=auth(token), json=_body(channel_binding_id=binding))
        assert r.status_code == 404, r.text
        bodies.append(r.json()["detail"])
    assert bodies == ["no such channel binding in this case"] * 3

    red_block = block(conn, case_id, owner, classification="RED")["id"]
    r = client.post(f"/api/v1/cases/{case_id}/comms/pgp/verify",
                    headers=auth(token), json=_body(contact_block_id=red_block))
    assert r.status_code == 404
    assert r.json()["detail"] == "no such contact block in this case"


def test_the_mismatch_refusal_still_names_a_visible_value(conn, client):
    owner = user(conn, "pgpq", global_roles=("CASE_OWNER",))
    case_id = case(conn, owner)
    binding = tox_binding(conn, case_id, owner)
    r = client.post(f"/api/v1/cases/{case_id}/comms/pgp/verify",
                    headers=auth(session(conn, owner)),
                    json=_body(channel_binding_id=binding,
                               confirms_value="someone@else.example"))
    assert r.status_code == 400
    assert TOX_PUBKEY in r.json()["detail"]


def test_a_binding_with_no_durable_value_is_refused_before_gpg(conn, client,
                                                               monkeypatch):
    from noctornal_api.comms import CommsService
    owner = user(conn, "pgpq", global_roles=("CASE_OWNER",))
    case_id = case(conn, owner)
    binding = CommsService(conn).bind(case_id=case_id, platform_key="TELEGRAM",
                                      observed="@vendor_shop",
                                      created_by=owner)["id"]
    _no_gpg(monkeypatch)
    r = client.post(f"/api/v1/cases/{case_id}/comms/pgp/verify",
                    headers=auth(session(conn, owner)),
                    json=_body(channel_binding_id=binding,
                               confirms_value="@vendor_shop"))
    assert r.status_code == 409
    assert "No durable form was recorded" in r.json()["detail"]


def test_a_case_scoped_grant_does_not_open_a_write(conn, client, monkeypatch):
    """An AMBER analyst with a RED grant on this (AMBER) case reads the RED
    binding through the grant, and cannot upgrade it through the grant: a
    case-scoped grant used for a write would count nothing."""
    owner = user(conn, "pgpq", global_roles=("CASE_OWNER",))
    case_id = case(conn, owner)
    red = tox_binding(conn, case_id, owner, classification="RED")
    analyst = user(conn, "pgpq", clearance="AMBER")
    assign(conn, case_id, analyst, "ANALYST")
    now = datetime.now(UTC)
    conn.execute(
        """INSERT INTO iam.break_glass (user_id, case_id, justification,
                                        started_at, expires_at,
                                        granted_classification)
           VALUES (%s, %s, %s, %s, %s, 'RED')""",
        (analyst, case_id, "an emergency reading of the red binding, test",
         now, now + timedelta(hours=1)))
    token = session(conn, analyst)
    claims = client.get(f"/api/v1/cases/{case_id}/comms/pgp/unverified",
                        headers=auth(token)).json()["claims"]
    assert [c["channel_binding_id"] for c in claims] == [str(red)]
    _no_gpg(monkeypatch)
    r = client.post(f"/api/v1/cases/{case_id}/comms/pgp/verify",
                    headers=auth(token), json=_body(channel_binding_id=red))
    assert r.status_code == 404

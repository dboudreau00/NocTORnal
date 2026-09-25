"""The escrow error, cryptographically, on every path (F10b, comms,
2026-09-24).

A good signature by the claimed key over text naming the identifier used
to upgrade the binding it named, whoever held the key: a guarantor's
signed vouch, checked with the guarantor's key and naming the vendor's
binding, confirmed the vendor. Now a binding is confirmed only when a
cited contact block lists the fingerprint as its publisher's own and ties
that publisher to the binding (the same block lists the identifier as its
own, or the block's publisher is the binding's identity), with no
identity conflict. Otherwise the check is UNATTRIBUTED. The same rule is a
trigger, so a writer that skips the service is refused; and the ledger
behind a confirmation is never rewritten or deleted.

Rows are deleted at teardown (pgp_support.teardown).
"""
from __future__ import annotations

import os
import subprocess

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set; gated")

from pgp_support import (  # noqa: E402
    SIGNED_WITH_TOX,
    TOX_PUBKEY,
    VENDOR_BLOCK,
    VENDOR_FPR,
    VENDOR_PUB,
    Svc,
    block,
    case,
    identity,
    teardown,
    tox_binding,
    user,
)

LIKE = "pgpa-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, LIKE)
    c.close()


def _check(conn, case_id, uid, **kw):
    kw.setdefault("signed_message", SIGNED_WITH_TOX)
    if "pgp_key_id" not in kw:
        kw.setdefault("public_key", VENDOR_PUB)
        kw.setdefault("claimed_fingerprint", VENDOR_FPR)
    return Svc(conn, **({"clearance": kw.pop("clearance")}
                        if "clearance" in kw else {})).verify_and_record(
        case_id=case_id, created_by=uid, **kw)


def _state(conn, binding):
    return conn.execute("SELECT verification FROM comms.channel_binding "
                        "WHERE id = %s", (binding,)).fetchone()[0]


def _setup(conn):
    uid = user(conn, "pgpa")
    case_id = case(conn, uid)
    return uid, case_id


# ---------------------------------------------------------------------------
# The rule, on a pasted key (STATED)
# ---------------------------------------------------------------------------

def test_a_stated_check_naming_a_binding_and_no_block_is_unattributed(conn):
    uid, case_id = _setup(conn)
    binding = tox_binding(conn, case_id, uid)
    out = _check(conn, case_id, uid, channel_binding_id=binding)
    assert out["outcome"] == "UNATTRIBUTED"
    assert "no contact block was cited" in out["detail"]
    assert out["binding_upgraded"] is False and _state(conn, binding) == "CLAIMED"
    # A good signature over the payload: its digest is recorded
    # (without it the CHECK refused the row, a 500).
    assert conn.execute("SELECT signed_payload_sha256 IS NOT NULL FROM "
                        "comms.pgp_verification WHERE id = %s",
                        (out["id"],)).fetchone()[0]


def test_a_block_listing_the_fingerprint_and_the_identifier_attributes(conn):
    uid, case_id = _setup(conn)
    binding = tox_binding(conn, case_id, uid)
    cited = block(conn, case_id, uid)["id"]
    out = _check(conn, case_id, uid, channel_binding_id=binding,
                 contact_block_id=cited)
    assert out["outcome"] == "VERIFIED"
    assert out["attribution"] == "SAME_BLOCK"
    assert _state(conn, binding) == "CONFIRMED"


def test_the_guarantor_vouch_is_unattributed(conn):
    """G's block lists G's fingerprint as SELF, the vendor X's binding has
    X's identity: an identity conflict. The same when the vouch was parsed
    as G's block listing the Tox ID as SELF."""
    uid, case_id = _setup(conn)
    vendor = identity(conn, case_id, uid, "vendor X")
    guarantor = identity(conn, case_id, uid, "guarantor G")
    binding = tox_binding(conn, case_id, uid, identity=vendor)
    for text in (f"PGP: {VENDOR_FPR}\n", VENDOR_BLOCK):
        vouch = block(conn, case_id, uid, text + "vouched\n",
                      publisher=guarantor)["id"]
        out = _check(conn, case_id, uid, channel_binding_id=binding,
                     contact_block_id=vouch)
        assert out["outcome"] == "UNATTRIBUTED", text
        assert "different entities" in out["detail"]
    assert _state(conn, binding) == "CLAIMED"


def test_the_identity_route_attributes(conn):
    uid, case_id = _setup(conn)
    vendor = identity(conn, case_id, uid, "vendor X")
    binding = tox_binding(conn, case_id, uid, identity=vendor)
    cited = block(conn, case_id, uid, f"PGP: {VENDOR_FPR}\n",
                  publisher=vendor)["id"]
    out = _check(conn, case_id, uid, channel_binding_id=binding,
                 contact_block_id=cited)
    assert out["outcome"] == "VERIFIED" and out["attribution"] == "SAME_IDENTITY"


def test_a_fingerprint_listed_only_as_a_third_partys_is_unattributed(conn):
    uid, case_id = _setup(conn)
    binding = tox_binding(conn, case_id, uid)
    cited = block(conn, case_id, uid,
                  f"Escrow PGP: {VENDOR_FPR}\nTOX: {TOX_PUBKEY}\n")["id"]
    out = _check(conn, case_id, uid, channel_binding_id=binding,
                 contact_block_id=cited)
    assert out["outcome"] == "UNATTRIBUTED"
    assert "publisher's own" in out["detail"]


# ---------------------------------------------------------------------------
# The rule, on a registry key (CONFIRMED_KEY)
# ---------------------------------------------------------------------------

def _registry_key(conn, case_id, uid, *, classification=None, against=None,
                  published_ref=None):
    from noctornal_api.pgp_keys import PgpLookupService
    svc = PgpLookupService(conn)
    labels = svc.plan_labels(case_id, requested_classification=classification,
                             requested_compartments=frozenset(),
                             channel_binding_id=None, contact_block_id=None,
                             evidence_id=None, clearance="RED", held=frozenset())
    reply = svc.import_key(case_id=case_id, source="PASTE",
                           raw=VENDOR_PUB.encode(), filename=None,
                           source_ref="vendor profile", labels=labels,
                           created_by=uid)
    key_id = reply["keys"][0]["id"]
    if against is not None:
        entry = next(e["id"] for e in against["entries"]
                     if e["selector_type"] == "PGP_FPR")
        svc.confirm(case_id=case_id, key_id=key_id, confirmed_by=uid,
                    clearance="RED", held=frozenset(),
                    contact_block_entry_id=entry)
    elif published_ref is not None:
        svc.confirm(case_id=case_id, key_id=key_id, confirmed_by=uid,
                    clearance="RED", held=frozenset(),
                    published_fingerprint=VENDOR_FPR, source_ref=published_ref)
    return key_id


def test_a_key_confirmed_against_a_line_brings_that_block(conn):
    uid, case_id = _setup(conn)
    binding = tox_binding(conn, case_id, uid)
    published = block(conn, case_id, uid)
    key_id = _registry_key(conn, case_id, uid, against=published)
    out = _check(conn, case_id, uid, pgp_key_id=key_id,
                 channel_binding_id=binding)
    assert out["outcome"] == "VERIFIED", out["detail"]
    assert out["claimed_fingerprint_basis"] == "CONFIRMED_KEY"
    assert out["contact_block_id"] == published["id"]
    assert _state(conn, binding) == "CONFIRMED"


def test_a_key_published_elsewhere_needs_a_block_that_attributes_it(conn):
    uid, case_id = _setup(conn)
    binding = tox_binding(conn, case_id, uid)
    key_id = _registry_key(conn, case_id, uid,
                           published_ref="the vendor's own site, 2026-09-20")
    out = _check(conn, case_id, uid, pgp_key_id=key_id,
                 channel_binding_id=binding)
    assert out["outcome"] == "UNATTRIBUTED"
    out = _check(conn, case_id, uid, pgp_key_id=key_id,
                 channel_binding_id=binding,
                 contact_block_id=block(conn, case_id, uid)["id"])
    assert out["outcome"] == "VERIFIED"


def _no_gpg(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("gpg was forked for a refused check")
    monkeypatch.setattr(subprocess, "run", refuse)


def test_a_red_key_cannot_upgrade_a_green_binding(conn, monkeypatch):
    from noctornal_api.pgp import PgpConflict
    uid = user(conn, "pgpa")
    case_id = case(conn, uid, classification="GREEN")
    binding = tox_binding(conn, case_id, uid, classification="GREEN")
    key_id = _registry_key(conn, case_id, uid, classification="RED",
                           published_ref="the vendor's own site")
    _no_gpg(monkeypatch)
    with pytest.raises(PgpConflict, match="TLP:RED, above the binding"):
        _check(conn, case_id, uid, pgp_key_id=key_id, channel_binding_id=binding,
               contact_block_id=block(conn, case_id, uid,
                                      classification="GREEN")["id"])


def test_a_red_block_cannot_attribute_a_green_binding(conn, monkeypatch):
    from noctornal_api.pgp import PgpConflict
    uid = user(conn, "pgpa")
    case_id = case(conn, uid, classification="GREEN")
    binding = tox_binding(conn, case_id, uid, classification="GREEN")
    red = block(conn, case_id, uid, classification="RED")["id"]
    _no_gpg(monkeypatch)
    with pytest.raises(PgpConflict, match="contact block is filed at TLP:RED"):
        _check(conn, case_id, uid, channel_binding_id=binding,
               contact_block_id=red)


def test_a_key_that_cannot_stand_behind_a_check(conn):
    from noctornal_api.pgp import PgpConflict, PgpError
    from noctornal_api.pgp_keys import PgpLookupService
    uid, case_id = _setup(conn)
    unconfirmed = _registry_key(conn, case_id, uid)
    with pytest.raises(PgpConflict, match="not been confirmed"):
        _check(conn, case_id, uid, pgp_key_id=unconfirmed)
    confirmed = _registry_key(conn, case_id, uid, published_ref="vendor site")
    with pytest.raises(PgpError, match="not the chosen key's"):
        _check(conn, case_id, uid, pgp_key_id=confirmed,
               claimed_fingerprint="A" * 40)
    with pytest.raises(PgpError, match="own provenance"):
        _check(conn, case_id, uid, pgp_key_id=confirmed,
               claimed_fingerprint_source_ref="somewhere")
    PgpLookupService(conn).retire(case_id=case_id, key_id=confirmed,
                                  reason="rotated", retired_by=uid,
                                  clearance="RED", held=frozenset())
    with pytest.raises(PgpConflict, match="retired"):
        _check(conn, case_id, uid, pgp_key_id=confirmed)


def test_labels_hide_a_key_and_the_checks_citing_it(conn):
    uid, case_id = _setup(conn)
    binding = tox_binding(conn, case_id, uid)
    key_id = _registry_key(conn, case_id, uid, classification="RED",
                           published_ref="vendor site")
    _check(conn, case_id, uid, pgp_key_id=key_id, confirms_value=TOX_PUBKEY)
    from noctornal_api.pgp import PgpService
    svc = PgpService(conn)
    assert svc.verifications(case_id, clearance="AMBER") == []
    assert len(svc.verifications(case_id, clearance="RED")) == 1
    (claim,) = svc.unverified_claims(case_id, clearance="AMBER")
    assert claim["channel_binding_id"] == str(binding)
    from noctornal_api.pgp_keys import PgpLookupService
    assert PgpLookupService(conn).keys(case_id, clearance="AMBER",
                                       held=frozenset()) == []


# ---------------------------------------------------------------------------
# The schema holds the rule for a writer that skips the service
# ---------------------------------------------------------------------------

def _verified(conn, case_id, uid, binding, **cols):
    base = {"case_id": case_id, "channel_binding_id": binding,
            "claimed_fingerprint": VENDOR_FPR, "signing_fingerprint": VENDOR_FPR,
            "confirms_value": TOX_PUBKEY, "signed_payload_sha256": b"\x00" * 32,
            "value_in_payload": True, "outcome": "VERIFIED", "verifier": "GPG",
            "status_output": "x", "created_by": uid}
    base.update(cols)
    conn.execute(
        f"INSERT INTO comms.pgp_verification ({', '.join(base)}) "
        f"VALUES ({', '.join(['%s'] * len(base))})", tuple(base.values()))


def test_the_trigger_refuses_a_verified_row_without_the_link(conn):
    uid, case_id = _setup(conn)
    vendor = identity(conn, case_id, uid, "vendor X")
    guarantor = identity(conn, case_id, uid, "guarantor G")
    binding = tox_binding(conn, case_id, uid, identity=vendor)
    cases = {
        "cites the contact block": {},
        "does not list the claimed fingerprint": {
            "contact_block_id": block(conn, case_id, uid,
                                      f"Escrow PGP: {VENDOR_FPR}\nTOX: {TOX_PUBKEY}\n")["id"],
            "attribution": "SAME_BLOCK"},
        "different entities": {
            "contact_block_id": block(conn, case_id, uid, VENDOR_BLOCK + "g\n",
                                      publisher=guarantor)["id"],
            "attribution": "SAME_BLOCK"},
        "filed above the binding": {
            "contact_block_id": block(conn, case_id, uid, VENDOR_BLOCK + "r\n",
                                      classification="RED")["id"],
            "attribution": "SAME_BLOCK"},
    }
    for message, cols in cases.items():
        with pytest.raises(psycopg.errors.RaiseException, match=message):
            _verified(conn, case_id, uid, binding, **cols)
    with pytest.raises(psycopg.errors.CheckViolation):
        _verified(conn, case_id, uid, None, attribution="SAME_BLOCK")


def test_the_ledger_behind_a_confirmation_is_never_rewritten(conn):
    uid, case_id = _setup(conn)
    binding = tox_binding(conn, case_id, uid)
    out = _check(conn, case_id, uid, channel_binding_id=binding,
                 contact_block_id=block(conn, case_id, uid)["id"])
    for sql in ("UPDATE comms.pgp_verification SET outcome = 'BAD_SIGNATURE' "
                "WHERE id = %s",
                "DELETE FROM comms.pgp_verification WHERE id = %s"):
        with pytest.raises(psycopg.errors.RaiseException, match="never rewritten"):
            conn.execute(sql, (out["id"],))
    with pytest.raises(psycopg.errors.RaiseException, match="never rewritten"):
        conn.execute("TRUNCATE comms.pgp_verification")

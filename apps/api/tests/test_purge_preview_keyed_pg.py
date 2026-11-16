"""A dry run's `preview` says nothing a caller could not already count (independent review, AREA-01).

The preview binds a real purge to the dry run it confirms, and it covers every due item of the case, the
ones above the caller included. As a plain sha256 of the canonical material it was the caller's to
rebuild: from the items the dry run lists and the request's own case and authority, a mismatch said some item
was left out, and a remembered id added to the list and rehashed said whether that id was due, under a case
whose `withheld_disclosure` is NONE, which promises to say nothing of what is left out. Keyed under the
server's pepper it is the server's to make, and the binding stays: a real run presents the dry run's preview
and is refused when what is due has changed.

Accounts `g44t-*`; the object store is `evidence_retention_support.VersionedStore`.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

import evidence_retention_support as g
import rls_support as s

pytestmark = g.GATED

conn = g.conn

API = "/api/v1"
AUTHORITY = "k3 preview review 2026-11"


@pytest.fixture
def store(monkeypatch):
    st = g.VersionedStore()
    import noctornal_api.http.routers.governance as governance
    monkeypatch.setattr(governance, "EvidenceStorage", lambda: st)
    return st


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    limits = dict(LIMITS)
    for name in ("retention.destroy", "retention.dry_run"):
        limits[name] = replace(limits[name], quota=1000, burst=1000)
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(now=lambda: 1000.0), limits=limits)
    return TestClient(app, raise_server_exceptions=False)


def _purge(client, headers, case_id, *, dry, preview=None):
    body = {"case_id": str(case_id), "authority": AUTHORITY, "dry_run": dry}
    if preview is not None:
        body["preview"] = preview
    return client.post(f"{API}/retention/purge", headers=headers, json=body)


def _plain(case_id, authority, rows) -> str:
    """The digest a caller would make from what the dry run lists: the sha256 of the canonical material, as
    the preview was before it was keyed. `rows` are `[held-or-due, object_type, object_id]`."""
    material = json.dumps({"v": 1, "case_id": str(case_id), "authority": authority,
                           "items": sorted(rows)}, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _listed(dry: dict) -> list[list[str]]:
    return [["held" if r["legal_hold"] else "due", r["object_type"], r["object_id"]]
            for r in dry["items"]]


def _case(conn, store, *, hidden: bool):
    """An expired case whose AMBER lead may list one AMBER exhibit, and which holds a RED one the lead may
    not know of when `hidden`; the case says nothing of what it leaves out."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    lead = g.user(conn, "AMBER", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, lead, "CASE_OWNER")
    visible, _ = g.lodge(conn, store, case_id, boss, classification="AMBER", title="k3 visible")
    secret = None
    if hidden:
        secret, _ = g.lodge(conn, store, case_id, boss, classification="RED", title="k3 hidden")
    g.age_case(conn, case_id, g.expired())
    conn.execute('UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
                 ("NONE", case_id))
    return lead, case_id, visible.evidence_id, secret.evidence_id if secret else None


def test_a_caller_cannot_tell_from_the_preview_whether_a_hidden_item_is_due(conn, store, client):
    lead, case_id, visible, secret = _case(conn, store, hidden=True)
    dry = _purge(client, g.token(conn, lead), case_id, dry=True)
    assert dry.status_code == 200, dry.text
    dry = dry.json()
    assert [r["object_id"] for r in dry["items"]] == [str(visible)], "the lead lists one exhibit"
    assert "withheld" not in dry, "NONE says nothing of what is left out"
    preview = dry["preview"]
    assert preview and len(preview) == 64

    listed = _listed(dry)
    # The test an attacker runs: is this id due as well? Hashing the list as shown, and the list with
    # the remembered id added, gave the preview back for exactly one of them, and the two together said a
    # hidden item exists.
    remembered = ["due", "evidence", str(secret)]
    assert preview != _plain(case_id, AUTHORITY, listed)
    assert preview != _plain(case_id, AUTHORITY, listed + [remembered])


def test_the_preview_of_a_case_with_nothing_hidden_is_not_the_plain_digest_either(conn, store, client):
    """Were it the plain digest exactly when nothing is hidden, the difference between the two answers
    would be the presence bit."""
    lead, case_id, visible, _ = _case(conn, store, hidden=False)
    dry = _purge(client, g.token(conn, lead), case_id, dry=True).json()
    assert [r["object_id"] for r in dry["items"]] == [str(visible)]
    assert dry["preview"] != _plain(case_id, AUTHORITY, _listed(dry))


def test_the_binding_of_a_real_run_to_its_dry_run_stays(conn, store, client):
    lead, case_id, visible, secret = _case(conn, store, hidden=True)
    headers = g.token(conn, lead)
    dry = _purge(client, headers, case_id, dry=True).json()

    blind = _purge(client, headers, case_id, dry=False)
    assert blind.status_code == 428
    forged = _purge(client, headers, case_id, dry=False,
                    preview=_plain(case_id, AUTHORITY, _listed(dry)))
    assert forged.status_code == 409 and "Nothing was destroyed" in forged.json()["detail"]
    assert conn.execute("SELECT purged_at IS NULL FROM core.evidence WHERE id = %s",
                        (visible,)).fetchone()[0]

    # What is due changes under it: a hidden exhibit comes under a hold, which the lead cannot see and
    # the preview still covers, so the confirmation of the old count is refused.
    conn.execute("UPDATE core.evidence SET legal_hold = true, "
                 "legal_hold_reason = 'k3 order' WHERE id = %s", (secret,))
    stale = _purge(client, headers, case_id, dry=False, preview=dry["preview"])
    assert stale.status_code == 409, stale.text

    fresh = _purge(client, headers, case_id, dry=True).json()
    assert fresh["preview"] != dry["preview"]
    real = _purge(client, headers, case_id, dry=False, preview=fresh["preview"])
    assert real.status_code == 200, real.text
    assert real.json()["evidence_purged"] == 1
    assert not conn.execute("SELECT purged_at IS NULL FROM core.evidence WHERE id = %s",
                            (visible,)).fetchone()[0]

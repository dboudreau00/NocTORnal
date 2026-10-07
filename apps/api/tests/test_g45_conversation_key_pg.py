"""Opening a conversation never meets a capture the caller may not read (rls-5; g45, 2026-10-03).

`conversation_external_idx` made (case, platform, external reference)
unique across labels and `open_conversation` upserted on it. When a RED or
compartmented capture of a room existed, an AMBER caller's upsert met a row
the UPDATE policy hides: the request role got Postgres's row-security
refusal (a 403 and an RLS_REFUSED row, where a fresh reference answers
201), so a caller with `comms.bind` could confirm whether the case holds a
hidden capture of a room by its external id. On a connection row security
does not filter the same call retitled the hidden row and returned its id.
0147 keys the index per labels, so the row an upsert can meet is always one
the caller may read.

Accounts carry the prefix `g45conv-`, unique to this file.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "g45conv-"
COMPARTMENT = "G45-CONV-X"


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    c.execute("DELETE FROM comms.conversation WHERE case_id IN "
              "(SELECT id FROM core.\"case\" WHERE owner_user_id IN "
              f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test'))")
    s.cleanup(c, prefix=PREFIX)
    c.close()


@pytest.fixture(params=["owner", "request_role"])
def posture(request, monkeypatch):
    if request.param == "request_role":
        monkeypatch.setenv("NOCTORNAL_TEST_ASSUME_ROLE", "1")
    return request.param


@pytest.fixture
def world(owner):
    lead = s.user(owner, "RED", compartments=(COMPARTMENT,), prefix=PREFIX)
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    case_id = s.case(owner, lead)
    s.assign(owner, case_id, lead, "CASE_OWNER")
    s.assign(owner, case_id, analyst)
    _sid, raw = s.session(owner, analyst)
    _sid, lead_raw = s.session(owner, lead)
    platform = owner.execute("SELECT key FROM comms.platform ORDER BY key LIMIT 1").fetchone()[0]
    return {"lead": lead, "analyst": analyst, "case": case_id, "platform": platform,
            "h": {"Authorization": f"Bearer {raw}"},
            "lead_h": {"Authorization": f"Bearer {lead_raw}"}}


@pytest.fixture
def client(posture):
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app, client=("203.0.113.66", 53000), raise_server_exceptions=False)


def _hidden(owner, world, ref, classification="RED", compartments=frozenset(), title="hidden room"):
    from noctornal_api.comms import CommsService
    return CommsService(owner).open_conversation(
        case_id=world["case"], platform_key=world["platform"],
        provenance_class="OPEN_GROUP", external_ref=ref, title=title,
        classification=classification, compartments=compartments)


def _open(client, world, ref, headers, *, title="analyst title", classification="AMBER",
          compartments=()):
    return client.post(f"/api/v1/cases/{world['case']}/comms/conversations", headers=headers,
                       json={"platform_key": world["platform"],
                             "provenance_class": "OPEN_GROUP", "external_ref": ref,
                             "title": title, "classification": classification,
                             "compartments": list(compartments)})


def test_a_hidden_capture_answers_exactly_as_no_capture_does(owner, world, client):
    ref = f"room-g45-{uuid4().hex[:8]}"
    hidden_id = _hidden(owner, world, ref)
    before_audit = owner.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'RLS_REFUSED' AND actor_id = %s",
        (world["analyst"],)).fetchone()[0]

    fresh = _open(client, world, f"room-g45-{uuid4().hex[:8]}", world["h"])
    clash = _open(client, world, ref, world["h"])

    assert fresh.status_code == 201, fresh.text
    assert clash.status_code == 201, (clash.status_code, clash.text)
    assert clash.json()["id"] != str(hidden_id), "the hidden capture's id was returned"
    assert set(clash.json()) == set(fresh.json()), "the two answers differ in shape"
    # The hidden capture is untouched, and the refusal that was the oracle is gone.
    row = owner.execute("SELECT title, classification FROM comms.conversation WHERE id = %s",
                        (hidden_id,)).fetchone()
    assert row == ("hidden room", "RED"), "the hidden capture was retitled or relabelled"
    after_audit = owner.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'RLS_REFUSED' AND actor_id = %s",
        (world["analyst"],)).fetchone()[0]
    assert after_audit == before_audit
    # Two captures, each at its own labels: the analyst sees theirs, the RED lead both.
    listing = client.get(f"/api/v1/cases/{world['case']}/comms/conversations",
                         headers=world["h"])
    if listing.status_code == 200:
        ids = {c["id"] for c in (listing.json() if isinstance(listing.json(), list)
                                 else listing.json().get("conversations", []))}
        assert str(hidden_id) not in ids and clash.json()["id"] in ids
    assert owner.execute("SELECT count(*) FROM comms.conversation WHERE case_id = %s "
                         "AND external_ref = %s", (world["case"], ref)).fetchone()[0] == 2


def test_a_compartmented_capture_is_hidden_the_same_way(owner, world, client):
    ref = f"room-g45-{uuid4().hex[:8]}"
    hidden_id = _hidden(owner, world, ref, classification="AMBER",
                        compartments=frozenset({COMPARTMENT}))
    clash = _open(client, world, ref, world["h"])
    assert clash.status_code == 201 and clash.json()["id"] != str(hidden_id)
    assert owner.execute("SELECT title FROM comms.conversation WHERE id = %s",
                         (hidden_id,)).fetchone()[0] == "hidden room"


def test_reopening_a_capture_at_the_same_labels_is_still_idempotent(owner, world, client):
    """The other direction: the upsert the endpoint exists for is intact."""
    ref = f"room-g45-{uuid4().hex[:8]}"
    first = _open(client, world, ref, world["h"], title="first title")
    second = _open(client, world, ref, world["h"], title="second title")
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert owner.execute("SELECT title FROM comms.conversation WHERE id = %s",
                         (first.json()["id"],)).fetchone()[0] == "second title"
    assert owner.execute("SELECT count(*) FROM comms.conversation WHERE case_id = %s "
                         "AND external_ref = %s", (world["case"], ref)).fetchone()[0] == 1


def test_the_same_reference_at_a_different_label_is_a_separate_capture(owner, world, client):
    ref = f"room-g45-{uuid4().hex[:8]}"
    amber = _open(client, world, ref, world["h"])
    # The RED lead records the same room at its own labels.
    red = _open(client, world, ref, world["lead_h"], classification="RED", title="red view")
    assert amber.status_code == red.status_code == 201
    assert amber.json()["id"] != red.json()["id"]


def test_the_index_is_keyed_per_labels(owner):
    row = owner.execute(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'comms' "
        "AND indexname = 'conversation_external_idx'").fetchone()[0]
    assert "classification" in row and "compartments" in row and "external_ref" in row
    assert row.startswith("CREATE UNIQUE INDEX")
    assert "WHERE (external_ref IS NOT NULL)" in row

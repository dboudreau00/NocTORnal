"""A call record links only an exhibit the caller may read, in this case, and a missing one is no 500.

`POST /deception/calls` takes two exhibit ids, `evidence_id` (the CDR) and `recording_evidence_id`.
Both columns are only FK-constrained, and a foreign key is checked as the table owner, so without
the gate a caller holding `evidence.upload` could link another case's exhibit, or one above their
labels, and an id that names nothing was a ForeignKeyViolation, a 500: 201 against 500 was an
unaudited existence oracle over `core.evidence`. The route gates both as `create_capture` gates
its three (`element_gate.gate_element`, decision 230): another case's exhibit, one above the
caller and an id that names nothing are one 404, each refusal writes its AUTHZ_DENIED row, and
nothing is written. A gated exhibit in the case still links. The statements and the audit row of
the three are compared by `test_absent_element_work_pg.py` (`absent_families`).

`POST /deception/captures` with an `egress_profile_id` that names no profile is a 422 sentence that
echoes nothing, not the same 500.

Runs with NOCTORNAL_TEST_ASSUME_ROLE, so every request connection is the request role, as in production.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import rls_support as s

pytestmark = s.GATED

PREFIX = "rv01-"
EXHIBIT_FIELDS = ("evidence_id", "recording_evidence_id")


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    for statement in (
            "DELETE FROM deception.call_record WHERE case_id IN (SELECT id FROM core.\"case\" "
            f"WHERE owner_user_id IN (SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%'))",
            "DELETE FROM deception.capture WHERE case_id IN (SELECT id FROM core.\"case\" "
            f"WHERE owner_user_id IN (SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%'))"):
        try:
            with c.transaction():
                c.execute(statement)
        except Exception:  # noqa: BLE001 - append-only in some builds; the cleanup below copes
            pass
    s.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def client():
    from noctornal_api.http.app import app
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def world(owner):
    boss = s.user(owner, "RED", prefix=PREFIX)
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    case_id = s.case(owner, boss)
    other = s.case(owner, boss)
    s.assign(owner, case_id, analyst, "ANALYST")
    _, raw = s.session(owner, analyst)
    return {
        "case": case_id, "analyst": analyst, "boss": boss,
        "auth": {"Authorization": f"Bearer {raw}"},
        "mine": s.exhibit(owner, case_id, boss, "AMBER"),
        "hidden": s.exhibit(owner, case_id, boss, "RED"),
        "other": s.exhibit(owner, other, boss, "AMBER"),
    }


def _post(client, w, **fields):
    body = {"started_at": "2026-01-01T00:00:00Z", "direction": "INBOUND_TO_VICTIM",
            "record_source": "PBX_LOG", **fields}
    if "recording_evidence_id" in fields:
        body.setdefault("recording_lawful_basis", "rv01 warrant")
    return client.post(f"/api/v1/cases/{w['case']}/deception/calls",
                       headers=w["auth"], json=body)


def _answer(r) -> tuple[int, dict]:
    body = r.json()
    return r.status_code, {k: body.get(k) for k in ("title", "status", "detail")}


def _calls(owner, w) -> int:
    return s.count(owner, "SELECT count(*) FROM deception.call_record WHERE case_id = %s",
                   (w["case"],))


def _denied(owner, w) -> int:
    return s.count(owner, "SELECT count(*) FROM audit.event WHERE actor_id = %s "
                          "AND action = 'AUTHZ_DENIED' AND case_id = %s",
                   (w["analyst"], w["case"]))


@pytest.mark.parametrize("field", EXHIBIT_FIELDS)
def test_a_call_naming_an_exhibit_above_the_caller_or_in_another_case_or_nothing_is_one_404(
        owner, client, world, field):
    w = world
    answers = {}
    for kind, ident in (("hidden", w["hidden"]), ("other_case", w["other"]),
                        ("missing", uuid4())):
        before = _denied(owner, w)
        answers[kind] = _answer(_post(client, w, **{field: str(ident)}))
        assert _denied(owner, w) == before + 1, kind
    assert answers["missing"] == (404, {"title": "Not found", "status": 404,
                                        "detail": f"no such exhibit for {field}"}), answers
    assert answers["hidden"] == answers["other_case"] == answers["missing"], answers
    assert _calls(owner, w) == 0


@pytest.mark.parametrize("field", EXHIBIT_FIELDS)
def test_a_call_links_an_exhibit_of_this_case_the_caller_may_read(
        owner, client, world, field):
    w = world
    r = _post(client, w, **{field: str(w["mine"])})
    assert r.status_code == 201, r.text
    stored = owner.execute(f"SELECT {field} FROM deception.call_record WHERE id = %s",
                           (r.json()["id"],)).fetchone()[0]
    assert stored == w["mine"]


def test_a_recording_is_still_refused_without_a_lawful_basis_after_its_gate(
        owner, client, world):
    w = world
    refused = _post(client, w, recording_evidence_id=str(w["mine"]),
                    recording_lawful_basis="")
    assert refused.status_code == 422, refused.text
    assert _calls(owner, w) == 0
    # The gate comes first: an exhibit above the caller is a 404, not the sentence about the basis.
    hidden = _post(client, w, recording_evidence_id=str(w["hidden"]),
                   recording_lawful_basis="")
    assert hidden.status_code == 404, hidden.text


def test_a_call_exhibit_that_is_no_uuid_is_a_sentence_and_not_a_500(client, world):
    for field in EXHIBIT_FIELDS:
        r = _post(client, world, **{field: "not-a-uuid"})
        assert r.status_code == 422, (field, r.text)
        assert "not-a-uuid" not in r.text


def test_a_capture_naming_an_egress_profile_that_does_not_exist_is_a_422_and_never_a_500(
        owner, client, world):
    w = world
    ghost = str(uuid4())
    r = client.post(f"/api/v1/cases/{w['case']}/deception/captures", headers=w["auth"], json={
        "requested_url": "https://lure.example/login", "capture_method": "HEADLESS",
        "egress_profile_id": ghost})
    assert r.status_code == 422, r.text
    assert ghost not in r.text
    assert "egress profile" in r.json()["detail"]
    assert s.count(owner, "SELECT count(*) FROM deception.capture WHERE case_id = %s",
                   (w["case"],)) == 0

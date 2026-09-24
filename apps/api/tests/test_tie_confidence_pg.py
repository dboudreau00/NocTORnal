"""A tie's confidence has one source: the live assertions behind it.

Migration 0064, written 2026-09-22 for two review findings that were the
same defect seen from two panes:

- ux06 edge-confidence-not-stored: the confidence chosen in the Add
  relationship form reached the assertion and never the edge. `POST /edges`
  passed none, the service defaulted to LOW, and the canvas, the Min
  confidence filter and every metric with a floor read LOW.
- ux05 two-disagreeing-confidences: the inspector printed the edge's value
  above the assertion's, with nothing saying which was which, and the
  "Correct..." path wrote the column while attaching an assertion graded
  LOW, which opened a fresh disagreement every time it was used.

The rule these tests hold: a tie's confidence is the HIGHEST confidence
among its live claims about the tie, a correction that states the
confidence counting at the value it states, and a correction to another
field (weight, attrs) not counting at all (`core.tie_confidence`). The
first test is the one the finding asked for by name: create a HIGH tie
through `POST /edges` and read HIGH back. The last covers the demo seed's
`--regrade`, which puts back the tie grades 0064's backfill took out of an
estate seeded before it.

**The email prefix is `tconf-` and must stay unique**, for the reason
`test_graph_mutation_api_pg.py` gives: fixtures clean up on an email
pattern, and two files sharing one delete each other's rows.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import threading
import time
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; tie confidence is gated"
)

PASSWORD = "correct-horse-battery-staple"
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

ROOT = Path(__file__).resolve().parents[3]
MIGRATION = ROOT / "db" / "migrations" / "versions" / "0064_edge_confidence_source.py"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()  # autocommit
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'tconf-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    # One transaction, assertions and elements together, so the deferred
    # invariant-1 triggers see the final state (all gone). Exhibits after
    # the assertions that cite them and before the users who acquired
    # them; they are inserted as rows here, never ingested, so no custody
    # row pins one.
    with c.transaction():
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'tconf-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    """A TestClient with its own in-process rate limiter, so one test
    cannot spend the next one's budget."""
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


# --- fixtures over HTTP -------------------------------------------------

def _owner(conn) -> str:
    """A signed-in CASE_OWNER, as `test_graph_mutation_api_pg._owner`."""
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    email = f"tconf-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "TConf", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'AMBER' WHERE id = %s",
                 (uid,))
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                 "VALUES (%s, 'CASE_OWNER')", (uid,))
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _case(client, token) -> str:
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-TCONF-{uuid4().hex[:6]}", "title": "Operation Grade",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _node(client, token, case_id, label) -> str:
    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                    json={"node_type": "IDENTITY", "label": label,
                          # What the API's defaults gave an entity before
                          # its grading became required (2026-09-23).
                          "assertion": _graded("LOW", reliability="F",
                                               credibility="6")})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _graded(confidence: str, **kw) -> dict:
    body = {"basis": "DIRECT_OBSERVATION", "reliability": "B",
            "credibility": "2", "confidence": confidence}
    body.update(kw)
    return body


def _tie(client, token, case_id, src, dst, confidence="LOW") -> str:
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token),
                    json={"edge_type": "VOUCHED_FOR", "src_node_id": src,
                          "dst_node_id": dst,
                          "assertion": _graded(confidence)})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _pair(client, token):
    case_id = _case(client, token)
    return (case_id, _node(client, token, case_id, "alpha"),
            _node(client, token, case_id, "bravo"))


def _add_claim(client, token, case_id, edge_id, confidence) -> str:
    r = client.post(f"/api/v1/cases/{case_id}/edges/{edge_id}/assertions",
                    headers=_auth(token), json=_graded(confidence))
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _retract(client, token, case_id, assertion_id) -> None:
    r = client.post(f"/api/v1/cases/{case_id}/assertions/{assertion_id}/retract",
                    headers=_auth(token), json={"reason": "source burned"})
    assert r.status_code == 204, r.text


def _listed(client, token, case_id, edge_id) -> str:
    """The confidence `GET /edges` reports, which is what the console's
    canvas, inspector header and node metrics are built from."""
    r = client.get(f"/api/v1/cases/{case_id}/edges", headers=_auth(token))
    assert r.status_code == 200, r.text
    return next(e for e in r.json() if e["id"] == edge_id)["confidence"]


def _row(conn, edge_id) -> str:
    return conn.execute("SELECT confidence::text FROM core.edge WHERE id = %s",
                        (edge_id,)).fetchone()[0]


def _claims(conn, edge_id) -> int:
    return conn.execute("SELECT count(*) FROM core.assertion WHERE edge_id = %s",
                        (edge_id,)).fetchone()[0]


# =======================================================================
# THE FINDING, BY NAME
# =======================================================================

def test_a_high_tie_created_through_post_edges_reads_back_high(conn, client):
    """ux06 edge-confidence-not-stored. Before 0064 this tie came back LOW
    from every read, and a HIGH floor hid it."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="HIGH")

    assert _listed(client, token, case_id, tie) == "HIGH"
    r = client.get(f"/api/v1/cases/{case_id}/graph", headers=_auth(token),
                   params={"min_confidence": "HIGH"})
    assert r.status_code == 200, r.text
    assert tie in [e["id"] for e in r.json()["edges"]], (
        "a tie graded HIGH must survive a HIGH floor")
    r = client.get(f"/api/v1/cases/{case_id}/edges/{tie}/assertions",
                   headers=_auth(token))
    assert [x["confidence"] for x in r.json()] == ["HIGH"]


def test_a_top_level_confidence_is_refused_rather_than_dropped(conn, client):
    """Pydantic drops an unknown field without a word, which is how a HIGH
    tie became LOW: the grade went somewhere nothing read it. The field is
    declared so a client that sends it there is told where it belongs."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    # Graded in full, so the request reaches the refusal under test rather
    # than the 422 a missing grading earns (gap-api-grade-required).
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token),
                    json={"edge_type": "VOUCHED_FOR", "src_node_id": a,
                          "dst_node_id": b, "confidence": "HIGH",
                          "assertion": _graded("HIGH")})
    assert r.status_code == 400, r.text
    assert "assertion.confidence" in r.text
    assert conn.execute("SELECT count(*) FROM core.edge WHERE case_id = %s",
                        (case_id,)).fetchone()[0] == 0


# =======================================================================
# THE RULE: the highest live assertion
# =======================================================================

def test_the_tie_is_the_highest_of_its_live_assertions(conn, client):
    """Corroboration never weakens a tie, and withdrawing the claim that
    graded it high lowers it to the highest claim that remains."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="LOW")
    assert _row(conn, tie) == "LOW"

    moderate = _add_claim(client, token, case_id, tie, "MODERATE")
    assert _row(conn, tie) == "MODERATE"
    high = _add_claim(client, token, case_id, tie, "HIGH")
    assert _listed(client, token, case_id, tie) == "HIGH"
    _add_claim(client, token, case_id, tie, "LOW")
    assert _row(conn, tie) == "HIGH", "a weaker second source must not lower it"

    _retract(client, token, case_id, high)
    assert _listed(client, token, case_id, tie) == "MODERATE"
    _retract(client, token, case_id, moderate)
    assert _row(conn, tie) == "LOW"


def _drawn(client, token, case_id, **params) -> dict:
    """The ties `GET /graph` draws, by id, under the given projection."""
    r = client.get(f"/api/v1/cases/{case_id}/graph", headers=_auth(token),
                   params=params)
    assert r.status_code == 200, r.text
    return {e["id"]: e for e in r.json()["edges"]}


def test_a_tie_with_no_live_claim_reads_low_and_leaves_the_graph(conn, client):
    """This test held the opposite until the final review (U11,
    2026-09-23): that the tie KEPT the withdrawn claim's grade. A tie no
    live claim grades now reads LOW, the ungraded value. With no live
    assertion at all it has left the graph, as before."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="MODERATE")
    only = conn.execute("SELECT id FROM core.assertion WHERE edge_id = %s",
                        (tie,)).fetchone()[0]
    _retract(client, token, case_id, only)
    assert _row(conn, tie) == "LOW"
    assert tie not in _drawn(client, token, case_id)


def test_a_tie_held_up_by_a_weight_fix_does_not_keep_the_withdrawn_grade(
        conn, client):
    """Final review U11 (a), 2026-09-23, the reviewer's own steps. The
    founding HIGH claim is retracted while a weight correction still
    stands. The correction is live support, so the tie stays in the graph
    (decision 24), but no live claim grades it. It used to stay HIGH: drawn
    at HIGH opacity, passing a HIGH floor and printed HIGH, on a grade that
    had just been withdrawn."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="HIGH")
    founding = conn.execute("SELECT id FROM core.assertion WHERE edge_id = %s",
                            (tie,)).fetchone()[0]
    r = _patch(client, token, case_id, tie,
               {"weight": 0.5, "assertion": {"rationale": "one deal, not two"}})
    assert r.status_code == 200, r.text
    assert r.json()["confidence"] == "HIGH"

    _retract(client, token, case_id, founding)
    assert (_row(conn, tie), _rule(conn, tie)) == ("LOW", "LOW")
    assert _listed(client, token, case_id, tie) == "LOW"
    drawn = _drawn(client, token, case_id)
    assert drawn[tie]["confidence"] == "LOW", (
        "the correction still holds the tie up, at the ungraded grade")
    for floor in ("MODERATE", "HIGH"):
        assert tie not in _drawn(client, token, case_id, min_confidence=floor), (
            f"a withdrawn grade must not pass a {floor} floor")

    # And a re-grade from there is an ordinary correction again.
    r = _patch(client, token, case_id, tie,
               {"confidence": "MODERATE", "assertion": {"rationale": "fits"}})
    assert r.status_code == 200, r.text
    assert _row(conn, tie) == "MODERATE"


def test_a_superseded_claim_does_not_hold_a_tie_or_an_entity_up(conn, client):
    """Final review U11 (b), 2026-09-23. `seed_showcase.py --regrade`
    supersedes a seed claim with a regraded one, and is the first code to
    write `superseded_at`. The rule already read a superseded row as dead
    and the projection read it as live support, so retracting the
    replacement left the tie drawn on a claim that no card offers to
    retract. Live now means one thing in both. The entity leg is held to
    the same definition."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    uid = conn.execute("SELECT created_by FROM core.node WHERE id = %s",
                       (a,)).fetchone()[0]
    seed = _seed_showcase()
    said = "vouch posted in the crew's own thread"
    when = datetime(2026, 1, 5, tzinfo=timezone.utc)
    r = client.post(
        f"/api/v1/cases/{case_id}/edges", headers=_auth(token),
        json={"edge_type": "VOUCHED_FOR", "src_node_id": a, "dst_node_id": b,
              "valid_from": when.isoformat(),
              "assertion": _graded("MODERATE", reliability="C",
                                   credibility="3", rationale=said)})
    assert r.status_code == 201, r.text
    tie = r.json()["id"]
    assert seed.regrade(conn, uid, [seed.SeededTie(
        case_id, "VOUCHED_FOR", "alpha", "bravo", when, "HIGH", said)]) == \
        Counter({"regraded MODERATE to HIGH": 1})
    replacement = conn.execute(
        """SELECT id FROM core.assertion
            WHERE edge_id = %s AND superseded_at IS NULL""", (tie,)).fetchone()[0]
    assert tie in _drawn(client, token, case_id)

    _retract(client, token, case_id, replacement)
    assert tie not in _drawn(client, token, case_id), (
        "the superseded seed claim must not keep the tie drawn")
    assert _row(conn, tie) == "LOW"

    # The same for an entity whose founding claim was superseded and whose
    # replacement is then withdrawn.
    old = conn.execute("SELECT id FROM core.assertion WHERE node_id = %s",
                       (a,)).fetchone()[0]
    r = client.post(f"/api/v1/cases/{case_id}/nodes/{a}/assertions",
                    headers=_auth(token), json=_graded("MODERATE"))
    assert r.status_code == 201, r.text
    new = r.json()["id"]
    conn.execute("""UPDATE core.assertion
                       SET superseded_at = now(), superseded_by = %s
                     WHERE id = %s""", (new, old))
    _retract(client, token, case_id, new)
    r = client.get(f"/api/v1/cases/{case_id}/graph", headers=_auth(token))
    assert a not in [n["id"] for n in r.json()["nodes"]]
    assert b in [n["id"] for n in r.json()["nodes"]]


def test_an_assertion_written_by_hand_still_moves_the_tie(conn, client):
    """The rule lives in the database, so a writer that bypasses the
    service (a script, a repair, a test) cannot reopen the gap."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="LOW")
    uid = conn.execute("SELECT created_by FROM core.edge WHERE id = %s",
                       (tie,)).fetchone()[0]
    conn.execute(
        """INSERT INTO core.assertion (case_id, edge_id, basis, confidence,
                                        created_by)
           VALUES (%s, %s, 'THIRD_PARTY_REPORT', 'HIGH', %s)""",
        (case_id, tie, uid))
    assert _row(conn, tie) == "HIGH"


def test_writing_the_column_directly_is_refused_not_silently_replaced(
        conn, client):
    import psycopg
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="MODERATE")
    with pytest.raises(psycopg.errors.CheckViolation) as err:
        conn.execute("UPDATE core.edge SET confidence = 'HIGH' WHERE id = %s",
                     (tie,))
    assert "derived from its live assertions" in str(err.value)
    assert _row(conn, tie) == "MODERATE"
    # Writing the value the rule gives is not a disagreement.
    conn.execute("UPDATE core.edge SET confidence = 'MODERATE' WHERE id = %s",
                 (tie,))


# =======================================================================
# CORRECTIONS (PATCH /graph/edges): the re-grade IS an assertion
# =======================================================================

def _patch(client, token, case_id, edge_id, body):
    """A correction, its claim graded where the test leaves grading out.

    The API grades nothing for the caller since gap-api-grade-required
    (2026-09-23). The fill is what its defaults used to apply (F / 6 /
    DIRECT_OBSERVATION) and, for a re-grade, the confidence it asks for,
    which is what the service then graded the claim at. So these tests
    exercise what they did before; the one about what the console sends
    states its grading in full."""
    claim = {"basis": "DIRECT_OBSERVATION", "reliability": "F",
             "credibility": "6", "confidence": body.get("confidence", "LOW")}
    claim.update(body.get("assertion") or {})
    return client.patch(f"/api/v1/cases/{case_id}/graph/edges/{edge_id}",
                        headers=_auth(token), json={**body, "assertion": claim})


def test_a_correction_raises_the_tie_and_its_own_assertion_agrees(conn, client):
    """ux05: the old path wrote the column and attached an assertion graded
    LOW, so the inspector's header said HIGH above a card that said LOW."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="LOW")

    # Exactly what the console's Correct form sends since 2026-09-23
    # (gap-api-grade-required): the new value, and the claim graded in full
    # by the analyst, with the re-grade as its confidence. The Correct...
    # prompt sent a rationale alone and the API graded the rest.
    r = _patch(client, token, case_id, tie,
               {"confidence": "HIGH",
                "assertion": {"basis": "THIRD_PARTY_REPORT", "reliability": "C",
                              "credibility": "3", "confidence": "HIGH",
                              "rationale": "second vouch"}})
    assert r.status_code == 200, r.text
    assert r.json()["confidence"] == "HIGH"
    assert _listed(client, token, case_id, tie) == "HIGH"
    cards = client.get(f"/api/v1/cases/{case_id}/edges/{tie}/assertions",
                       headers=_auth(token)).json()
    assert sorted(c["confidence"] for c in cards) == ["HIGH", "LOW"]
    # Found by its rationale rather than as cards[0] (fix round,
    # 2026-09-23): the list is newest first by recorded_at, and this test
    # is about the correction's grade, not about two rows recorded
    # milliseconds apart sorting one way on a busy shared server.
    corrections = [c for c in cards if c["rationale"] == "second vouch"]
    assert len(corrections) == 1, cards
    newest = corrections[0]
    assert newest["confidence"] == "HIGH", (
        "the correction's own grade must be the value it states, or the "
        "header and the card disagree again")
    # Recorded as the analyst graded it, and nothing graded for them.
    assert (newest["basis"], newest["reliability"], newest["credibility"]) == (
        "THIRD_PARTY_REPORT", "C", "3")


def test_a_correction_cannot_lower_a_tie_past_a_live_claim(conn, client):
    """Under "highest live assertion" a LOW correction beside a live
    MODERATE claim would be recorded and ignored. Refused before anything
    is written, with the remedy (retraction) named."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="MODERATE")

    r = _patch(client, token, case_id, tie,
               {"confidence": "LOW", "assertion": {"rationale": "weaker now"}})
    assert r.status_code == 409, r.text
    assert "Retract" in r.json()["detail"]
    assert _row(conn, tie) == "MODERATE"
    assert _claims(conn, tie) == 1, "a refused correction leaves no assertion"
    assert conn.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'EDGE_UPDATED' "
        "AND object_id = %s", (tie,)).fetchone()[0] == 0


def test_lowering_works_once_the_higher_claim_is_retracted(conn, client):
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="HIGH")
    first = conn.execute("SELECT id FROM core.assertion WHERE edge_id = %s",
                         (tie,)).fetchone()[0]
    _add_claim(client, token, case_id, tie, "LOW")
    _retract(client, token, case_id, first)
    assert _row(conn, tie) == "LOW"
    r = _patch(client, token, case_id, tie,
               {"confidence": "MODERATE", "assertion": {"rationale": "fits"}})
    assert r.status_code == 200, r.text
    assert _row(conn, tie) == "MODERATE"


def test_contradictory_confidences_in_one_correction_are_refused(conn, client):
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="LOW")
    r = _patch(client, token, case_id, tie,
               {"confidence": "HIGH",
                "assertion": {"confidence": "LOW", "rationale": "x"}})
    assert r.status_code == 400, r.text
    assert _row(conn, tie) == "LOW"
    assert _claims(conn, tie) == 1


def test_a_weight_correction_leaves_the_confidence_where_the_rule_puts_it(
        conn, client):
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="HIGH")
    r = _patch(client, token, case_id, tie,
               {"weight": 3, "assertion": {"rationale": "three deals"}})
    assert r.status_code == 200, r.text
    assert r.json()["confidence"] == "HIGH"


def test_a_field_correction_graded_high_does_not_raise_the_tie(conn, client):
    """Found by the fix-round verifier, 2026-09-22. The rule counted EVERY
    live assertion, so a weight fix graded HIGH raised a LOW tie to HIGH,
    and the analyst's next attempt to put it back was refused with a 409
    pointing at the weight fix. A correction to another field grades that
    field, not the tie. Both shapes are covered: one field (claim_path
    'weight') and two (no claim_path, both in claim_value)."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="LOW")

    r = _patch(client, token, case_id, tie,
               {"weight": 2, "assertion": _graded("HIGH", rationale="two deals")})
    assert r.status_code == 200, r.text
    assert r.json()["confidence"] == "LOW"
    r = _patch(client, token, case_id, tie,
               {"weight": 3, "attrs": {"venue": "exchange"},
                "assertion": _graded("HIGH", rationale="three deals")})
    assert r.status_code == 200, r.text
    assert _listed(client, token, case_id, tie) == "LOW"
    assert conn.execute(
        """SELECT count(*) FROM core.assertion
            WHERE edge_id = %s AND claim_path IS NULL
              AND claim_value IS NOT NULL""", (tie,)).fetchone()[0] == 1, (
        "the two-field correction must be the no-claim_path shape")

    # And a re-grade in either direction the rule allows still goes through.
    r = _patch(client, token, case_id, tie,
               {"confidence": "MODERATE", "assertion": {"rationale": "fits"}})
    assert r.status_code == 200, r.text
    assert _row(conn, tie) == "MODERATE"


def test_a_correction_to_weight_and_confidence_counts_at_the_confidence(
        conn, client):
    """Two fields at once leave claim_path empty; the stated confidence in
    claim_value is still what the tie takes."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="LOW")
    r = _patch(client, token, case_id, tie,
               {"weight": 2, "confidence": "HIGH",
                "assertion": {"rationale": "two deals, both vouched"}})
    assert r.status_code == 200, r.text
    assert r.json()["confidence"] == "HIGH"
    assert _row(conn, tie) == "HIGH"


def test_the_refusal_names_the_analysts_own_correction(conn, client):
    """Re-verifier, 2026-09-23: corrections accumulate, so an analyst who
    raised a tie and then tried to bring it back down was refused because
    of their OWN earlier correction, by a message that said only "a live
    assertion". The refusal now names the claims in the way, and says when
    one is the caller's, so they know which card to retract. Retracting it
    then lets the lower correction through."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="LOW")
    r = _patch(client, token, case_id, tie,
               {"confidence": "HIGH", "assertion": {"rationale": "two vouches"}})
    assert r.status_code == 200, r.text
    mine = conn.execute(
        """SELECT id, recorded_at FROM core.assertion
            WHERE edge_id = %s AND claim_path = 'confidence'""",
        (tie,)).fetchone()

    r = _patch(client, token, case_id, tie,
               {"confidence": "MODERATE", "assertion": {"rationale": "one"}})
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert "This tie stays HIGH" in detail
    assert f"1 live claim grades it above MODERATE (your own correction of " \
           f"{mine[1]:%Y-%m-%d})" in detail, detail
    assert "Retract that claim first" in detail
    # The remedy that keeps the tie graded names the console's control
    # (final review C14): it used to prescribe one the console lacked.
    assert "add a MODERATE claim before retracting" in detail
    assert "Add a claim under the tie's assertions" in detail
    assert "\u2014" not in detail and "\u2013" not in detail
    assert _row(conn, tie) == "HIGH"
    assert _claims(conn, tie) == 2, "the refused correction was rolled back"

    _retract(client, token, case_id, mine[0])
    assert _row(conn, tie) == "LOW"
    r = _patch(client, token, case_id, tie,
               {"confidence": "MODERATE", "assertion": {"rationale": "one"}})
    assert r.status_code == 200, r.text
    assert r.json()["confidence"] == "MODERATE"


def test_the_refusal_counts_only_the_claims_the_rule_counts(conn, client):
    """The claims named in a refusal are chosen by `core.tie_grade`, the
    function the rule is built from, so a weight fix graded HIGH is not
    offered as a reason: only the founding MODERATE claim is in the way."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="MODERATE")
    r = _patch(client, token, case_id, tie,
               {"weight": 2, "assertion": _graded("HIGH", rationale="two deals")})
    assert r.status_code == 200, r.text
    r = _patch(client, token, case_id, tie,
               {"confidence": "LOW", "assertion": {"rationale": "weaker"}})
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert "This tie stays MODERATE: 1 live claim grades it above LOW " \
           "(your own claim of " in detail, detail


def _exhibit(conn, case_id, uid) -> str:
    """An exhibit row, as `test_evidenced_pg._exhibit` inserts one."""
    return str(conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, 'vouch-thread.png', 'image/png', 1024, %s, %s, %s,
                   'test-bucket', 'AMBER', 'SCREENSHOT', now(), %s)
           RETURNING id""",
        (case_id, uuid4().bytes + uuid4().bytes, b"\x02" * 32,
         f"k/{uuid4().hex}", uid)).fetchone()[0])


def test_lowering_through_a_new_claim_keeps_the_tie_graded_and_evidenced(
        conn, client):
    """Final review C14, 2026-09-23, the reviewer's scenario end to end.

    A tie recorded HIGH on a B2 third-party report with exhibit X is to
    come down to MODERATE. Correct... is refused (it cannot lower a tie
    past a live claim) and names the remedy. The only route the console
    had was to retract the founding claim and correct afterwards, which
    left the tie on an ungraded correction (DIRECT_OBSERVATION, F6), with
    exhibit X no longer backing it. The inspector's Add a claim form sends
    exactly this body, the whole grading and the exhibit, to
    `POST /edges/{id}/assertions`; the higher claim is then retracted with
    its reason, and the tie never leaves the graph."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    uid = conn.execute("SELECT created_by FROM core.node WHERE id = %s",
                       (a,)).fetchone()[0]
    ev = _exhibit(conn, case_id, uid)
    grading = {"basis": "THIRD_PARTY_REPORT", "reliability": "B",
               "credibility": "2"}
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token),
                    json={"edge_type": "VOUCHED_FOR", "src_node_id": a,
                          "dst_node_id": b,
                          "assertion": {**grading, "confidence": "HIGH",
                                        "evidence_id": ev}})
    assert r.status_code == 201, r.text
    tie = r.json()["id"]
    founding = conn.execute("SELECT id FROM core.assertion WHERE edge_id = %s",
                            (tie,)).fetchone()[0]

    r = _patch(client, token, case_id, tie,
               {"confidence": "MODERATE", "assertion": {"rationale": "one"}})
    assert r.status_code == 409, r.text
    assert "Add a claim under the tie's assertions" in r.json()["detail"]

    # The form's body, key for key (`assertionFrom('claim')` in app.js).
    r = client.post(f"/api/v1/cases/{case_id}/edges/{tie}/assertions",
                    headers=_auth(token),
                    json={**grading, "confidence": "MODERATE",
                          "rationale": "the second forum retracted its vouch",
                          "evidence_id": ev, "external_ref": None,
                          "observed_at": None})
    assert r.status_code == 201, r.text
    assert _row(conn, tie) == "HIGH", "a lower claim does not lower it alone"
    assert tie in _drawn(client, token, case_id, min_confidence="HIGH")

    _retract(client, token, case_id, founding)
    assert (_row(conn, tie), _rule(conn, tie)) == ("MODERATE", "MODERATE")
    drawn = _drawn(client, token, case_id)
    assert drawn[tie]["confidence"] == "MODERATE"
    assert drawn[tie]["has_evidence"] is True, "exhibit X still backs the tie"
    live = [x for x in client.get(
        f"/api/v1/cases/{case_id}/edges/{tie}/assertions",
        headers=_auth(token)).json()]
    assert [(x["basis"], x["reliability"], x["credibility"], x["confidence"],
             x["evidence_id"]) for x in live] == [
        ("THIRD_PARTY_REPORT", "B", "2", "MODERATE", ev)], (
        "the live claim keeps the grading and exhibit the analyst gave it")


# =======================================================================
# CONCURRENCY: two writers on one tie (re-verifier, 2026-09-23)
# =======================================================================
#
# Each test holds one write open on a second connection, starts another
# writer in a thread, waits until that writer is blocked on a lock (or
# has finished, which is what the unfixed code did), and only then commits
# the first. `lock_timeout` bounds a regression that hangs to seconds.

def _open_tx():
    """A connection that is NOT autocommit, so a write stays uncommitted
    (and its locks held) until the test commits it."""
    import psycopg

    from noctornal_api.db import dsn
    tx = psycopg.connect(dsn())
    tx.execute("SET lock_timeout = '20s'")
    tx.commit()
    return tx


def _in_thread(fn):
    out: dict = {}

    def run():
        try:
            out["result"] = fn()
        except Exception as exc:  # reported by the test, not swallowed
            out["error"] = exc
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, out


def _blocked_on_a_lock(conn, pid: int, thread, within: float = 10.0) -> bool:
    """True once backend `pid` is waiting on a lock. False if the thread
    finished first, which is what a writer that never waits does."""
    deadline = time.monotonic() + within
    while time.monotonic() < deadline and thread.is_alive():
        row = conn.execute(
            "SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s",
            (pid,)).fetchone()
        if row and row[0] == "Lock":
            return True
        time.sleep(0.02)
    return False


def _rule(conn, edge_id) -> str | None:
    return conn.execute("SELECT core.tie_confidence(%s)::text",
                        (edge_id,)).fetchone()[0]


def _claim_sql() -> str:
    return ("INSERT INTO core.assertion (case_id, edge_id, basis, confidence, "
            "created_by) VALUES (%s, %s, 'DIRECT_OBSERVATION', %s, %s)")


def test_a_retraction_racing_a_new_claim_leaves_no_drift(conn, client):
    """The drift the re-verifier reproduced. T1 retracts the HIGH claim and
    has not committed; T2 adds a second HIGH claim and commits; T1 commits.
    The first 0064 left the column LOW while the rule said HIGH: T2 derived
    HIGH from a snapshot in which the retraction had not happened, found
    the column already HIGH and wrote nothing, and T1's LOW landed last.
    Now T2 waits for T1's lock and derives after it."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="LOW")
    high = _add_claim(client, token, case_id, tie, "HIGH")
    uid = conn.execute("SELECT created_by FROM core.edge WHERE id = %s",
                       (tie,)).fetchone()[0]
    assert (_row(conn, tie), _rule(conn, tie)) == ("HIGH", "HIGH")

    t1, t2 = _open_tx(), _open_tx()
    thread = None
    try:
        t1.execute(
            """UPDATE core.assertion
                  SET retracted_at = now(), retracted_by = %s,
                      retraction_reason = 'source burned'
                WHERE id = %s""", (uid, high))

        def second_claim():
            t2.execute(_claim_sql(), (case_id, tie, "HIGH", uid))
            t2.commit()
        pid = t2.info.backend_pid
        thread, out = _in_thread(second_claim)
        waited = _blocked_on_a_lock(conn, pid, thread)
        t1.commit()
        thread.join(30)
        assert not thread.is_alive()
        assert "error" not in out, out.get("error")
    finally:
        t1.close()
        if thread is not None:
            thread.join(30)
        t2.close()

    assert (_row(conn, tie), _rule(conn, tie)) == ("HIGH", "HIGH"), (
        "the column must agree with the rule once both writers commit")
    assert waited, "the second writer must derive after the first commits"


def test_two_claims_at_once_both_land(conn, client):
    """The same race failing closed. T1 adds a HIGH claim and has not
    committed; T2 adds a MODERATE one. The first 0064 made T2's UPDATE
    wait, then re-check against T1's committed HIGH, and the edge guard
    refused it as a "direct write": a legitimate claim was lost. Now T2
    waits at the lock, derives HIGH afterwards, and both claims stand."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="LOW")
    uid = conn.execute("SELECT created_by FROM core.edge WHERE id = %s",
                       (tie,)).fetchone()[0]

    t1, t2 = _open_tx(), _open_tx()
    thread = None
    try:
        t1.execute(_claim_sql(), (case_id, tie, "HIGH", uid))

        def second_claim():
            t2.execute(_claim_sql(), (case_id, tie, "MODERATE", uid))
            t2.commit()
        pid = t2.info.backend_pid
        thread, out = _in_thread(second_claim)
        waited = _blocked_on_a_lock(conn, pid, thread)
        t1.commit()
        thread.join(30)
        assert not thread.is_alive()
        assert "error" not in out, out.get("error")
    finally:
        t1.close()
        if thread is not None:
            thread.join(30)
        t2.close()

    assert _claims(conn, tie) == 3, "the founding claim and both new ones"
    assert (_row(conn, tie), _rule(conn, tie)) == ("HIGH", "HIGH")
    assert waited


def test_a_correction_behind_a_retraction_is_judged_on_what_committed(
        conn, client):
    """`update_edge` used one statement, `SELECT tie_confidence(...) ...
    FOR UPDATE`, which waited for a concurrent retraction and then answered
    from the snapshot it began with: the retracted HIGH claim still counted
    and a MODERATE correction was refused. It now locks, then lets the rule
    answer after the write, so the correction is judged on the committed
    state and goes through."""
    from noctornal_api.db import connect
    from noctornal_api.graph import AssertionInput, GraphWriteService

    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    tie = _tie(client, token, case_id, a, b, confidence="LOW")
    high = _add_claim(client, token, case_id, tie, "HIGH")
    uid = conn.execute("SELECT created_by FROM core.edge WHERE id = %s",
                       (tie,)).fetchone()[0]

    t1 = _open_tx()
    service_conn = connect()  # autocommit, as the API's is
    service_conn.execute("SET lock_timeout = '20s'")
    thread = None
    try:
        t1.execute(
            """UPDATE core.assertion
                  SET retracted_at = now(), retracted_by = %s,
                      retraction_reason = 'source burned'
                WHERE id = %s""", (uid, high))

        def correct():
            GraphWriteService(service_conn).update_edge(
                tie, case_id=case_id, confidence="MODERATE",
                assertion=AssertionInput(
                    basis="DIRECT_OBSERVATION", created_by=uid,
                    rationale="one vouch left", claim_path="confidence",
                    claim_value={"confidence": "MODERATE"}))
        pid = service_conn.info.backend_pid
        thread, out = _in_thread(correct)
        waited = _blocked_on_a_lock(conn, pid, thread)
        t1.commit()
        thread.join(30)
        assert not thread.is_alive()
        assert "error" not in out, out.get("error")
    finally:
        t1.close()
        if thread is not None:
            thread.join(30)
        service_conn.close()

    assert (_row(conn, tie), _rule(conn, tie)) == ("MODERATE", "MODERATE")
    assert waited


# =======================================================================
# THE MIGRATION: the backfill, run through the version file itself
# =======================================================================

def _m0064():
    spec = importlib.util.spec_from_file_location("m0064", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_backfill_repairs_drift_and_honours_an_old_correction(conn, client):
    """Models the database 0064 finds, in a rolled-back transaction with
    the user triggers off (the suite's idiom, see
    `test_compartment_binding_pg.py`):

    - a tie graded MODERATE whose column says LOW, the pre-0064 default;
    - a tie corrected to HIGH the pre-0064 way: column HIGH, the
      correction's own grade LOW, its claim_value saying HIGH. The rule
      honours the stated value, so the backfill must leave it HIGH rather
      than dragging it down to the grades.
    - a LOW tie carrying a weight fix graded HIGH: a claim about the
      weight, not the tie, so the backfill must leave it LOW.
    - a HIGH tie whose founding claim was withdrawn while a weight fix
      still stands: no live claim grades it, so it takes LOW (final review
      U11, 2026-09-23) instead of keeping the withdrawn HIGH.
    """
    from noctornal_api.db import dsn
    import psycopg

    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    charlie = _node(client, token, case_id, "charlie")
    drifted = _tie(client, token, case_id, a, b, confidence="MODERATE")
    corrected = client.post(
        f"/api/v1/cases/{case_id}/edges", headers=_auth(token),
        json={"edge_type": "VOUCHED_FOR", "src_node_id": b, "dst_node_id": a,
              "assertion": _graded("LOW")}).json()["id"]
    reweighted = _tie(client, token, case_id, a, charlie, confidence="LOW")
    stranded = _tie(client, token, case_id, b, charlie, confidence="HIGH")
    uid = conn.execute("SELECT created_by FROM core.edge WHERE id = %s",
                       (drifted,)).fetchone()[0]

    m = _m0064()
    tx = psycopg.connect(dsn())
    try:
        tx.execute("ALTER TABLE core.edge DISABLE TRIGGER USER")
        tx.execute("ALTER TABLE core.assertion DISABLE TRIGGER USER")
        tx.execute("UPDATE core.edge SET confidence = 'LOW' WHERE id = %s",
                   (drifted,))
        tx.execute(
            """INSERT INTO core.assertion (case_id, edge_id, basis, confidence,
                   rationale, claim_path, claim_value, created_by)
               VALUES (%s, %s, 'DIRECT_OBSERVATION', 'LOW', 'second vouch',
                       'confidence', '{"confidence": "HIGH"}', %s)""",
            (case_id, corrected, uid))
        tx.execute("UPDATE core.edge SET confidence = 'HIGH' WHERE id = %s",
                   (corrected,))
        tx.execute(
            """INSERT INTO core.assertion (case_id, edge_id, basis, confidence,
                   rationale, claim_path, claim_value, created_by)
               VALUES (%s, %s, 'DIRECT_OBSERVATION', 'HIGH', 'three deals',
                       'weight', '{"weight": 3}', %s)""",
            (case_id, reweighted, uid))
        tx.execute(
            """INSERT INTO core.assertion (case_id, edge_id, basis, confidence,
                   rationale, claim_path, claim_value, created_by)
               VALUES (%s, %s, 'DIRECT_OBSERVATION', 'LOW', 'one deal',
                       'weight', '{"weight": 1}', %s)""",
            (case_id, stranded, uid))
        tx.execute(
            """UPDATE core.assertion
                  SET retracted_at = now(), retracted_by = %s,
                      retraction_reason = 'source burned'
                WHERE edge_id = %s AND claim_path IS NULL""", (uid, stranded))
        tx.execute("ALTER TABLE core.edge ENABLE TRIGGER USER")
        tx.execute("ALTER TABLE core.assertion ENABLE TRIGGER USER")
        assert tx.execute("SELECT confidence::text FROM core.edge WHERE id = %s",
                          (stranded,)).fetchone()[0] == "HIGH"

        tx.execute(m.BACKFILL_SQL)

        got = dict(tx.execute(
            "SELECT id::text, confidence::text FROM core.edge "
            "WHERE id IN (%s, %s, %s, %s)",
            (drifted, corrected, reweighted, stranded)).fetchall())
        assert got[drifted] == "MODERATE", "drift is repaired"
        assert got[corrected] == "HIGH", "an analyst's correction is honoured"
        assert got[reweighted] == "LOW", "a weight fix does not grade the tie"
        assert got[stranded] == "LOW", "a withdrawn grade is not kept"
        # And nothing disagrees with the rule anywhere afterwards. The rule
        # is never NULL now, so this covers every edge.
        assert tx.execute(
            """SELECT count(*) FROM core.edge
                WHERE confidence IS DISTINCT FROM core.tie_confidence(id)"""
        ).fetchone()[0] == 0
    finally:
        tx.rollback()
        tx.close()


# =======================================================================
# THE DEMO ESTATE: seed_showcase.py --regrade
# =======================================================================

def _seed_showcase():
    """`scripts/seed_showcase.py`, imported by path. Its own directory goes
    on sys.path first, because the script imports `_env` from beside it."""
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    spec = importlib.util.spec_from_file_location(
        "seed_showcase", scripts / "seed_showcase.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_demo_regrade_supersedes_seed_claims_and_touches_nothing_else(
        conn, client):
    """Fix round, 2026-09-22. The seed used to grade every claim MODERATE
    and give the tie a confidence of its own; 0064's backfill sided with
    the claims and the demo lost every HIGH and LOW tie. `--regrade` puts
    the seed's grades back by SUPERSESSION (invariant 5), so this checks
    the history as well as the result: the old claim is kept, stamped and
    linked to its replacement, and nothing about it is rewritten. A claim
    an analyst added is not the seed's and is left alone."""
    token = _owner(conn)
    case_id, a, b = _pair(client, token)
    c = _node(client, token, case_id, "charlie")
    uid = conn.execute("SELECT created_by FROM core.node WHERE id = %s",
                       (a,)).fetchone()[0]
    seed = _seed_showcase()
    said = "vouch posted in the crew's own thread"
    when = datetime(2026, 1, 5, tzinfo=timezone.utc)

    def seeded(src, dst):
        """A tie the way the pre-0064 seed recorded it: claim MODERATE, C3."""
        r = client.post(
            f"/api/v1/cases/{case_id}/edges", headers=_auth(token),
            json={"edge_type": "VOUCHED_FOR", "src_node_id": src,
                  "dst_node_id": dst, "valid_from": when.isoformat(),
                  "assertion": _graded("MODERATE", reliability="C",
                                       credibility="3", rationale=said)})
        assert r.status_code == 201, r.text
        return r.json()["id"]

    up, down, same = seeded(a, b), seeded(b, a), seeded(a, c)
    analysts = _add_claim(client, token, case_id, same, "LOW")

    def tie(src, dst, grade):
        return seed.SeededTie(case_id, "VOUCHED_FOR", src, dst, when, grade,
                              said)

    plan = [tie("alpha", "bravo", "HIGH"), tie("bravo", "alpha", "LOW"),
            tie("alpha", "charlie", "MODERATE"),
            tie("charlie", "bravo", "HIGH")]
    missing = "not found (deleted, or not this seed's)"
    assert seed.regrade(conn, uid, plan) == Counter({
        "regraded MODERATE to HIGH": 1, "regraded MODERATE to LOW": 1,
        "already right": 1, missing: 1})

    assert _listed(client, token, case_id, up) == "HIGH"
    assert _row(conn, down) == "LOW"
    assert _row(conn, same) == "MODERATE"

    rows = conn.execute(
        """SELECT id, confidence::text, reliability::text, credibility::text,
                  rationale, superseded_at IS NOT NULL, superseded_by,
                  retracted_at IS NULL
             FROM core.assertion WHERE edge_id = %s""", (down,)).fetchall()
    assert len(rows) == 2
    old = next(r for r in rows if r[5])
    new = next(r for r in rows if not r[5])
    assert old[1] == "MODERATE", "the superseded claim is kept as it was"
    assert old[6] == new[0], "and it names the claim that replaced it"
    assert new[1:5] == ("LOW", "C", "3", said), (
        "the replacement differs from the old claim in its grade alone")
    assert old[7] and new[7], "supersession is not retraction"

    live = {str(r[0]) for r in conn.execute(
        """SELECT id FROM core.assertion
            WHERE edge_id = %s AND superseded_at IS NULL""", (same,))}
    assert len(live) == 2 and str(analysts) in live, (
        "a tie already at its seed grade, and an analyst's claim on it, "
        "are not touched")

    assert seed.regrade(conn, uid, plan) == Counter({
        "already right": 3, missing: 1}), "a second run changes nothing"

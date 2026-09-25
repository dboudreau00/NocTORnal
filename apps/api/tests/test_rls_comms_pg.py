"""Row-level security on the communications records (S1, 2026-09-25).

0122 puts bindings, contact blocks and their entries, conversations with
their messages and participants, device fingerprints, the PGP registry and
its ledger, and the stoplist under policy. Run as the request role, bound
by a real session's proof, with the fixtures seeded as the owner:

- a conversation above the reader is hidden with its participants and
  messages, and a message above the reader is hidden inside a visible one;
- minimisation drops EVERY body of the conversation, a message above the
  minimiser included, and reports that count (docs/16 L4); as the request
  role it dropped the bodies the minimiser could read and called it done;
- the incidental flag lands on a conversation above the flagger, which the
  case gate allowed and the request role could not even find;
- Triage reads a proposal parsed from a RED contact block as RED to an
  AMBER reader, through the fact, never as the case's label;
- nothing calls a row-security helper per row.

Gated like the other row-security tests. Account prefix `rlscom-`.
"""
from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "rlscom-"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    with c.transaction():
        c.execute(f"DELETE FROM comms.contact_block WHERE case_id IN {cases}")
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {cases}")
        c.execute(f"DELETE FROM comms.conversation WHERE case_id IN {cases}")
    s.cleanup(c, PREFIX)
    c.close()


def _conversation(conn, case_id: UUID, classification: str = "AMBER") -> UUID:
    from noctornal_api.comms import CommsService
    svc = CommsService(conn)
    conv = svc.open_conversation(case_id=case_id, platform_key="TELEGRAM",
                                 provenance_class="OPEN_GROUP",
                                 external_ref=f"rlscom-{uuid4().hex[:8]}",
                                 classification=classification)
    for n in range(3):
        svc.add_message(conv, sender_handle=f"@member{n}", body=f"message {n}")
    return conv


def _ids(conn, sql: str, params=None) -> set:
    return {r[0] for r in conn.execute(sql, params).fetchall()}


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _auth(conn, uid) -> dict:
    _, raw = s.session(conn, uid)
    return {"Authorization": f"Bearer {raw}"}


def test_a_conversation_above_the_reader_is_hidden_with_what_hangs_off_it(owner):
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, analyst)
    amber, red = _conversation(owner, case_id), _conversation(owner, case_id, "RED")
    hidden_message = owner.execute(
        "SELECT id FROM comms.message WHERE conversation_id = %s LIMIT 1",
        (amber,)).fetchone()[0]
    owner.execute("UPDATE comms.message SET classification = 'RED' WHERE id = %s",
                  (hidden_message,))
    _, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    try:
        assert _ids(app, "SELECT id FROM comms.conversation WHERE id = ANY(%s)",
                    ([amber, red],)) == {amber}
        assert _ids(app, "SELECT DISTINCT conversation_id FROM comms.participant "
                         "WHERE conversation_id = ANY(%s)", ([amber, red],)) == {amber}
        seen = _ids(app, "SELECT id FROM comms.message WHERE conversation_id = ANY(%s)",
                    ([amber, red],))
        assert len(seen) == 2 and hidden_message not in seen
        for sql in ("SELECT id FROM comms.conversation WHERE case_id = %s",
                    "SELECT id FROM comms.message WHERE conversation_id = %s"):
            assert s.per_row_definer_calls(app, sql, (case_id,)) == [], sql
    finally:
        app.close()


def test_minimisation_drops_every_body_the_minimiser_could_not_read_too(owner, client):
    lead = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, lead, "CASE_OWNER")
    conv = _conversation(owner, case_id)
    above = owner.execute(
        "SELECT id FROM comms.message WHERE conversation_id = %s LIMIT 1",
        (conv,)).fetchone()[0]
    owner.execute("UPDATE comms.message SET classification = 'RED' WHERE id = %s",
                  (above,))
    r = client.post(f"/api/v1/cases/{case_id}/comms/conversations/{conv}/minimise",
                    headers=_auth(owner, lead), json={"authority": "closure order 4"})
    assert r.status_code == 200, r.text
    assert r.json()["bodies_dropped"] == 3
    assert s.count(owner, "SELECT count(*) FROM comms.message "
                          "WHERE conversation_id = %s AND body IS NOT NULL", (conv,)) == 0


def test_the_incidental_flag_lands_on_a_conversation_above_the_flagger(owner, client):
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, analyst)
    conv = _conversation(owner, case_id, "RED")
    r = client.post(f"/api/v1/cases/{case_id}/comms/conversations/{conv}/incidental",
                    headers=_auth(owner, analyst), json={"handle": "@member1"})
    assert r.status_code == 200, r.text
    flagged = owner.execute(
        "SELECT is_incidental FROM comms.participant WHERE conversation_id = %s "
        "AND observed_handle = '@member1'", (conv,)).fetchone()[0]
    assert flagged is True


def test_a_proposal_from_a_red_contact_block_reads_red(owner):
    """Triage's contact-block leg: a LEFT JOIN to the RED block read as no
    block for an AMBER reader, and the proposal as the case's AMBER."""
    from noctornal_api.proposals import ProposalStore

    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, analyst)
    block = owner.execute(
        """INSERT INTO comms.contact_block
               (case_id, source_ref, raw_text, raw_sha256, block_fingerprint,
                parser_version, classification, created_by)
           VALUES (%s, 'rlscom thread', 'jabber: x@rlscom.test', %s, 'fp', 'v1',
                   'RED', %s) RETURNING id""",
        (case_id, uuid4().bytes + uuid4().bytes, boss)).fetchone()[0]
    proposal = owner.execute(
        """INSERT INTO collect.proposal (case_id, kind, payload, origin, rationale)
           VALUES (%s, 'NODE', %s, 'rlscom/1', 'parsed from a contact block')
           RETURNING id""",
        (case_id, json.dumps({"node_type": "SELECTOR", "label": "x@rlscom.test"}))
    ).fetchone()[0]
    owner.execute(
        """INSERT INTO comms.contact_block_entry
               (block_id, line_no, label, platform_key, observed_value, role,
                role_reason, score, score_reason, proposal_id)
           VALUES (%s, 1, 'jabber', 'XMPP', 'x@rlscom.test', 'SELF',
                   'listed as own', 0.9, 'a test line', %s)""",
        (block, proposal))
    _, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    try:
        assert not ProposalStore(app).readable(proposal, clearance="AMBER",
                                               compartments=frozenset())
    finally:
        app.close()
    assert ProposalStore(owner).readable(proposal, clearance="RED",
                                         compartments=frozenset())

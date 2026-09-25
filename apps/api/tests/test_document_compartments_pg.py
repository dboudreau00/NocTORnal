"""Compartments on captured documents (L1, 2026-09-24).

Final review c15 refused every capture into a compartmented case, because
`collect.document` had no compartments and every reader listed it by label
alone. Migration 0070 gives it compartments; a capture copies its case's;
every person-facing read of a document checks `d.compartments <@` the
reader's own; proposals raised from it are read and accepted under them;
0071 labels the captures made before. Each test here fails on ab27a4a:

- a capture into a compartmented case is stored under its compartments,
  and only a case walled off for victim data still refuses;
- a reader outside the compartment never sees the document, on any path:
  the collection list, the document search and the combined search, watch
  hits and their verbs, document triage, the inspector's claim card, the
  Triage queue and its counts and source view, and deception's lookup;
- an accept writes the material's compartments beyond the case's, and an
  ATTRIBUTE claim counts its entity's case's compartments;
- a re-paste dedupes only under the identical lock;
- a label change no longer rebuilds the text index, and a purge empties it;
- the legacy backfill labels what every citing case can read;
- the index serves the registry; the register counts what no lock fits;
- rename and retire reach documents;
- a contact block cites only a document its case already cites (the old
  path answered 500).

Env-gated on DATABASE_URL. Email prefix `dcm-`, document titles and source
names `dcm-`, registry keys `DCM-`. The teardown clears what the tests
made, documents included, so no key stays carried and the 0058 round trip
is never blocked by these rows.
"""
from __future__ import annotations

import json
import os
from datetime import date, timedelta
from uuid import UUID, uuid4

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; document compartments "
    "tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

PREFIX = "dcm-"
EMAIL_LIKE = f"{PREFIX}%@noctornal.test"
#: Left registered, as the other suites leave theirs: a key is a closed-
#: vocabulary word, and deleting one another run still uses fails.
K1, K2 = "DCM-K1", "DCM-K2"


def _registered(conn, keys):
    """Register each key before a raw write carries it: 0059 refuses an
    unregistered key on a fresh database (test_fixture_invariants)."""
    for key in keys:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, key))

SAMPLE = """
Thread: escrow terms
vendor wrote: contact me at dcm.vendor@protonmail.com for terms.
"""


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    for key in (K1, K2):
        c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                  "ON CONFLICT (key) DO NOTHING", (key, "Document test"))
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    docs = f"(SELECT id FROM collect.document WHERE title LIKE '{PREFIX}%')"
    ours = (f"(SELECT id FROM notify.notification "
            f"  WHERE recipient_id IN {sub} OR actor_id IN {sub} "
            f"     OR case_id IN {csub})")
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN {ours}")
        c.execute(f"DELETE FROM notify.notification WHERE id IN {ours}")
        c.execute(f"DELETE FROM comms.contact_block_entry WHERE block_id IN "
                  f"(SELECT id FROM comms.contact_block WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM comms.contact_block WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.watch_hit WHERE document_id IN {docs}")
        c.execute(f"DELETE FROM collect.watch WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub} "
                  f"OR document_id IN {docs}")
        c.execute(f"DELETE FROM core.selector WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.extraction WHERE document_id IN {docs}")
        c.execute(f"DELETE FROM collect.document WHERE title LIKE '{PREFIX}%'")
        c.execute(f"DELETE FROM collect.source WHERE name LIKE '{PREFIX}%'")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
        c.execute("DELETE FROM iam.compartment WHERE key LIKE 'DCM-R-%'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _user(conn, clearance="RED", keys=(), roles=("ANALYST",)):
    """An account with global roles (collection.read is a global verb)."""
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{PREFIX}{uuid4().hex[:8]}@noctornal.test", "DCM", "x" * 20)
    _registered(conn, keys)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
                 "WHERE id = %s", (clearance, list(keys), uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                     "VALUES (%s, %s)", (uid, role))
    return uid


def _auth(conn, uid) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner, classification="AMBER", keys=()):
    from noctornal_api.cases import CaseService
    future = date(2028, 1, 1)
    return CaseService(conn).create(
        code=f"OP-DCM-{uuid4().hex[:6]}", title="Document compartments",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1), owner_user_id=owner,
        created_by=owner, classification=classification,
        compartments=list(keys))


def _assign(conn, case_id, user, role, by):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, user, role, by))


def _source(conn, kind="PASTE", classification="AMBER") -> UUID:
    return conn.execute(
        """INSERT INTO collect.source (kind, name, default_reliability,
                                       classification)
           VALUES (%s::collect.source_kind, %s, 'F', %s) RETURNING id""",
        (kind, f"{PREFIX}{uuid4().hex[:8]}", classification)).fetchone()[0]


def _document(conn, *, keys=(), classification="AMBER", source=None,
              word=None, purged=False) -> tuple[UUID, str]:
    """A captured document inserted directly, with a word nothing else
    carries so the search tests can find it and nothing else."""
    word = word or f"dcmzq{uuid4().hex[:10]}"
    title = f"{PREFIX}{word}"
    doc = conn.execute(
        """INSERT INTO collect.document (source_id, title, body_text,
                                         content_sha256, classification,
                                         compartments, purged_at)
           VALUES (%s, %s, %s, %s, %s, %s,
                   CASE WHEN %s THEN now() END) RETURNING id""",
        (source or _source(conn), title, f"the thread mentions {word}",
         os.urandom(32), classification, list(keys), purged)).fetchone()[0]
    return doc, word


def _node(conn, case_id, owner, label, classification="AMBER", keys=(),
          document_id=None):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=owner,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner,
                                 document_id=document_id),
        classification=classification, compartments=list(keys))


def _propose(conn, case_id, kind, payload, document_id=None) -> UUID:
    from noctornal_api.proposals import ProposalStore
    return ProposalStore(conn).propose(
        case_id=case_id, kind=kind, payload=payload, origin="dcm/1",
        rationale="found in the pasted thread", score=0.5,
        document_id=document_id)


def _selector_payload(label="dcm.vendor@protonmail.com"):
    return {"node_type": "SELECTOR", "label": label, "classification": "AMBER",
            "attrs": {"selector_type": "EMAIL", "raw_value": label,
                      "char_start": 0, "char_end": len(label)}}


def _capture(client, conn, case_id, user, classification="AMBER",
             text=None):
    return client.post(
        f"/api/v1/cases/{case_id}/proposals/capture", headers=_auth(conn, user),
        json={"text": text or SAMPLE + f"\n[{uuid4().hex}]",
              "title": f"{PREFIX}{uuid4().hex[:6]}",
              "classification": classification})


def _tx() -> psycopg.Connection:
    from noctornal_api.db import dsn
    return psycopg.connect(dsn())


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

def test_a_capture_into_a_compartmented_case_is_stored_under_its_compartments(
        conn, client):
    owner = _user(conn, "RED", [K2, K1], roles=())
    case_id = _case(conn, owner, "AMBER", [K2, K1])
    r = _capture(client, conn, case_id, owner)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["document_compartments"] == [K1, K2], "sorted, and the case's"
    stored = conn.execute(
        "SELECT compartments FROM collect.document WHERE id = %s",
        (out["document_id"],)).fetchone()[0]
    assert stored == [K1, K2]
    detail = conn.execute(
        """SELECT detail FROM audit.event
            WHERE action = 'DOCUMENT_CAPTURED' AND object_id = %s""",
        (out["document_id"],)).fetchone()[0]
    assert detail["document_compartments"] == [K1, K2]
    q = client.get(f"/api/v1/cases/{case_id}/proposals",
                   headers=_auth(conn, owner)).json()
    assert q["capture_refused"] is None
    assert q["capture_labels"] == {"classification": "AMBER",
                                   "compartments": [K1, K2]}
    # A proposal's card carries its document's compartments.
    assert q["proposals"] and all(
        p["document_compartments"] == [K1, K2] for p in q["proposals"])


def test_the_victim_data_refusal_names_only_its_reason_and_outlives_a_revoke(
        conn):
    """Every ingest key's forced compartment counts, a revoked key's too
    (the records it brought keep it), and the sentence names only the
    compartments that are the reason, agreed with their number."""
    from noctornal_api.extraction import CaptureService
    owner = _user(conn, "RED", [K1, K2], roles=())
    victim = f"DCM-R-{uuid4().hex[:6].upper()}"
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'v')",
                 (victim,))
    key_id = conn.execute(
        """INSERT INTO ingest.api_key (key_id, secret_hmac, pepper_id, name,
                                       expires_at, owner_user_id,
                                       forced_compartment, revoked_at,
                                       revoked_reason)
           VALUES (%s, %s, 'env:v1', 'dcm revoked feed',
                   now() + interval '1 day', %s, %s, now(), 'feed retired')
           RETURNING id""",
        (uuid4().hex[:8], os.urandom(32), owner, victim)).fetchone()[0]
    try:
        conn.execute("UPDATE iam.app_user SET compartments = %s WHERE id = %s",
                     ([K1, K2, victim], owner))
        case_id = _case(conn, owner, "RED", [K1, victim])
        said = CaptureService(conn).refusal(case_id)
        assert said.startswith(f"Capture is off on this case. It is kept in "
                               f"compartment {victim}, which")
        assert K1 not in said and "read into it," in said
        assert CaptureService(conn).refusal(_case(conn, owner, "RED", [K1])) is None
    finally:
        conn.execute("DELETE FROM ingest.api_key WHERE id = %s", (key_id,))


def test_a_repaste_dedupes_only_under_the_same_lock(conn, client):
    owner = _user(conn, "RED", [K1], roles=())
    walled = _case(conn, owner, "RED", [K1])
    open_case = _case(conn, owner, "AMBER")
    text = SAMPLE + f"\n[{uuid4().hex}]"
    first = _capture(client, conn, walled, owner, "RED", text).json()
    again = _capture(client, conn, walled, owner, "RED", text).json()
    assert again["deduplicated"] is True
    assert again["document_id"] == first["document_id"]
    # Another lock: its own document, and nothing in the reply says the
    # text was captured under a compartment before.
    other = _capture(client, conn, open_case, owner, "AMBER", text).json()
    assert other["deduplicated"] is False
    assert other["document_id"] != first["document_id"]
    assert other["document_classification"] == "AMBER"
    assert other["document_compartments"] == []
    # A purged document is never a dedupe target: its text is gone.
    conn.execute("UPDATE collect.document SET purged_at = now(), "
                 "body_text = '' WHERE id = %s", (other["document_id"],))
    fresh = _capture(client, conn, open_case, owner, "AMBER", text).json()
    assert fresh["deduplicated"] is False
    assert fresh["document_id"] != other["document_id"]


def test_label_changes_do_not_reindex_and_a_purge_clears_the_index(conn):
    _registered(conn, [K1])
    doc, _word = _document(conn)
    conn.execute("UPDATE collect.document SET search_tsv = "
                 "to_tsvector('simple', 'sentinel') WHERE id = %s", (doc,))

    def tsv():
        return conn.execute("SELECT search_tsv::text FROM collect.document "
                            "WHERE id = %s", (doc,)).fetchone()[0]

    assert tsv() == "'sentinel':1"
    for stmt, params in (
            ("UPDATE collect.document SET triage_state = 'TRIAGED' "
             "WHERE id = %s", (doc,)),
            ("UPDATE collect.document SET classification = 'RED' "
             "WHERE id = %s", (doc,)),
            ("UPDATE collect.document SET compartments = %s WHERE id = %s",
             ([K1], doc))):
        conn.execute(stmt, params)
        assert tsv() == "'sentinel':1", f"re-indexed by: {stmt}"
    conn.execute("UPDATE collect.document SET title = 'dcm-retitled' "
                 "WHERE id = %s", (doc,))
    assert "retitled" in tsv(), "a change of indexed text still re-indexes"
    conn.execute("UPDATE collect.document SET purged_at = now(), "
                 "body_text = '', search_tsv = NULL WHERE id = %s", (doc,))
    assert tsv() is None, "the purge's NULL was rebuilt from the title"


# ---------------------------------------------------------------------------
# Every read of a document
# ---------------------------------------------------------------------------

def _estate(conn, role="ANALYST"):
    """An uncompartmented case both readers work (in `role`), and a K1
    document it cites. `outsider` is RED with no compartments; `insider`
    holds K1."""
    owner = _user(conn, "RED", [K1], roles=())
    insider = _user(conn, "RED", [K1])
    outsider = _user(conn, "RED")
    case_id = _case(conn, owner, "AMBER")
    for reader in (insider, outsider):
        _assign(conn, case_id, reader, role, owner)
    source = _source(conn)
    doc, word = _document(conn, keys=[K1], source=source)
    return {"owner": owner, "insider": insider, "outsider": outsider,
            "case": case_id, "doc": doc, "word": word, "source": source}


def test_a_reader_outside_the_compartment_never_sees_the_document(conn, client):
    e = _estate(conn)
    watch = conn.execute(
        """INSERT INTO collect.watch (case_id, source_id, name, target_kind,
                                      target_ref, owner_user_id)
           VALUES (%s, %s, 'dcm watch', 'KEYWORD', 'x', %s) RETURNING id""",
        (e["case"], e["source"], e["owner"])).fetchone()[0]
    hit = conn.execute(
        """INSERT INTO collect.watch_hit (watch_id, document_id, matched_on)
           VALUES (%s, %s, '{}'::jsonb) RETURNING id""",
        (watch, e["doc"])).fetchone()[0]
    node = _node(conn, e["case"], e["owner"], f"{PREFIX}subject",
                 document_id=e["doc"])
    case, doc, word = e["case"], str(e["doc"]), e["word"]

    def sees(uid) -> dict:
        h = _auth(conn, uid)
        listed = client.get("/api/v1/collection/documents?limit=500",
                            headers=h).json()["documents"]
        searched = client.get(f"/api/v1/cases/{case}/search/documents?q={word}",
                              headers=h).json()["hits"]
        combined = client.get(f"/api/v1/cases/{case}/search?q={word}",
                              headers=h).json()["hits"]
        hits = client.get(f"/api/v1/cases/{case}/collection/watch-hits",
                          headers=h).json()["hits"]
        claims = client.get(f"/api/v1/cases/{case}/nodes/{node}/assertions",
                            headers=h).json()
        return {
            "list": [d for d in listed if d["id"] == doc],
            "search": [d for d in searched if d["id"] == doc],
            "combined": [d for d in combined if d["id"] == doc],
            "hits": [x for x in hits if x["document_id"] == doc],
            "title": [c["document_title"] for c in claims
                      if c["document_id"] == doc],
        }

    out = sees(e["outsider"])
    assert out == {"list": [], "search": [], "combined": [], "hits": [],
                   "title": [None]}, out
    h = _auth(conn, e["outsider"])
    nowhere = {
        "triage": client.post(f"/api/v1/collection/documents/{doc}/triage",
                              headers=h, json={"state": "TRIAGED"}),
        "ack": client.post(f"/api/v1/cases/{case}/collection/watch-hits/"
                           f"{hit}/acknowledge", headers=h),
        "suppress": client.post(f"/api/v1/cases/{case}/collection/watch-hits/"
                                f"{hit}/suppress", headers=h,
                                json={"reason": "noise, same thread"}),
        "unsuppress": client.post(f"/api/v1/cases/{case}/collection/"
                                  f"watch-hits/{hit}/unsuppress", headers=h),
    }
    random = {
        "triage": client.post(f"/api/v1/collection/documents/{uuid4()}/triage",
                              headers=h, json={"state": "TRIAGED"}),
        "ack": client.post(f"/api/v1/cases/{case}/collection/watch-hits/"
                           f"{uuid4()}/acknowledge", headers=h),
    }
    for name, r in nowhere.items():
        assert r.status_code == 404, (name, r.text)
    assert nowhere["triage"].json()["detail"] == random["triage"].json()["detail"]
    assert nowhere["ack"].json()["detail"] == random["ack"].json()["detail"]
    assert conn.execute("SELECT triage_state, acknowledged_at IS NULL "
                        "FROM collect.document d, collect.watch_hit h "
                        "WHERE d.id = %s AND h.id = %s",
                        (e["doc"], hit)).fetchone() == ("NEW", True)

    got = sees(e["insider"])
    assert len(got["list"]) == 1 and got["list"][0]["compartments"] == [K1]
    assert len(got["search"]) == 1 and got["search"][0]["compartments"] == [K1]
    assert len(got["combined"]) == 1 and len(got["hits"]) == 1
    assert got["title"] == [f"{PREFIX}{word}"]
    h = _auth(conn, e["insider"])
    assert client.post(f"/api/v1/collection/documents/{doc}/triage", headers=h,
                       json={"state": "TRIAGED"}).status_code == 200
    assert client.post(f"/api/v1/cases/{case}/collection/watch-hits/{hit}/"
                       f"acknowledge", headers=h).status_code == 200


def test_the_queue_hides_a_proposal_from_compartmented_material(conn, client):
    from noctornal_api.deception import DeceptionService
    from noctornal_api.proposals import ProposalStore
    e = _estate(conn)
    case = e["case"]
    a = _node(conn, case, e["owner"], f"{PREFIX}a")
    b = _node(conn, case, e["owner"], f"{PREFIX}b")
    pid = _propose(conn, case, "NODE", _selector_payload(), e["doc"])
    _propose(conn, case, "EDGE", {"edge_type": "ALIAS_OF",
                                  "src_node_id": str(a), "dst_node_id": str(b),
                                  "classification": "AMBER"}, e["doc"])
    # The deception lookup's "already queued" (it reuses _READABLE).
    host = f"{PREFIX}{uuid4().hex[:6]}.example"
    queued = _propose(conn, case, "NODE", {"node_type": "INFRA", "label": host,
                                           "classification": "AMBER"}, e["doc"])
    record = {"id": str(uuid4()), "classification": "AMBER",
              "compartments": [], "requested_url": f"https://{host}/x",
              "hops": []}

    def view(uid, held):
        h = _auth(conn, uid)
        q = client.get(f"/api/v1/cases/{case}/proposals", headers=h).json()
        waiting = client.get("/api/v1/notifications/waiting",
                             headers=h).json()["cases"]
        return {
            "queue": {p["id"] for p in q["proposals"]},
            "counts": q["counts"].get("PROPOSED", 0),
            "ring": q["pending_by_node"],
            "waiting": waiting.get(str(case), {}).get("triage", 0),
            "readable": ProposalStore(conn).readable(
                pid, clearance="RED", compartments=held),
            "source": client.get(f"/api/v1/cases/{case}/proposals/{pid}/source",
                                 headers=h).status_code,
            "deception": DeceptionService(conn).propose(
                case, "capture", record, f"host:{host}", clearance="RED",
                compartments=held),
        }

    # The holder first: the outsider's lookup queues a proposal of its own,
    # which the holder could then read as well.
    got = view(e["insider"], frozenset({K1}))
    assert str(pid) in got["queue"] and got["counts"] == 3
    assert got["ring"] == {str(a): 1, str(b): 1}
    assert got["waiting"] == 3 and got["readable"] is True
    assert got["source"] == 200
    assert got["deception"] == {"proposal_id": str(queued), "state": "PROPOSED",
                                "created": False, "label": host}

    out = view(e["outsider"], frozenset())
    assert out["queue"] == set() and out["counts"] == 0 and out["ring"] == {}
    assert out["waiting"] == 0 and out["readable"] is False
    assert out["source"] == 404
    assert out["deception"]["created"] is True, (
        "the lookup matched a proposal the caller's queue does not show")
    assert out["deception"]["proposal_id"] != str(queued)
    src = client.get(f"/api/v1/cases/{case}/proposals/{pid}/source",
                     headers=_auth(conn, e["insider"])).json()
    assert src["compartments"] == [K1]


# ---------------------------------------------------------------------------
# Accept
# ---------------------------------------------------------------------------

def _audit_detail(conn, action, object_id) -> dict:
    return conn.execute(
        "SELECT detail FROM audit.event WHERE action = %s AND object_id = %s",
        (action, object_id)).fetchone()[0]


def test_accept_writes_the_material_compartments_beyond_the_case(conn, client):
    e = _estate(conn, "REVIEWER")
    case = e["case"]
    a = _node(conn, case, e["owner"], f"{PREFIX}a")
    b = _node(conn, case, e["owner"], f"{PREFIX}b")
    node_p = _propose(conn, case, "NODE", _selector_payload(), e["doc"])
    edge_p = _propose(conn, case, "EDGE", {
        "edge_type": "ALIAS_OF", "src_node_id": str(a),
        "dst_node_id": str(b), "classification": "AMBER"}, e["doc"])
    # Somebody not read into K1 was never shown it, and cannot accept it.
    r = client.post(f"/api/v1/cases/{case}/proposals/{node_p}/accept",
                    headers=_auth(conn, e["outsider"]), json={})
    assert r.status_code == 404, r.text
    h = _auth(conn, e["insider"])
    r = client.post(f"/api/v1/cases/{case}/proposals/{node_p}/accept",
                    headers=h, json={})
    assert r.status_code == 200, r.text
    node = r.json()["applied_node_id"]
    assert conn.execute("SELECT compartments FROM core.node WHERE id = %s",
                        (node,)).fetchone()[0] == [K1]
    assert _audit_detail(conn, "PROPOSAL_ACCEPTED", node_p)["compartments"] == [K1]
    r = client.post(f"/api/v1/cases/{case}/proposals/{edge_p}/accept",
                    headers=h, json={})
    assert r.status_code == 200, r.text
    assert conn.execute("SELECT compartments FROM core.edge WHERE id = %s",
                        (r.json()["applied_edge_id"],)).fetchone()[0] == [K1]


def test_an_element_in_a_compartmented_case_takes_none_of_the_cases_keys(
        conn, client):
    """The case's own keys are not copied: every read of an element passes
    its case's gate, and the case's other elements carry none."""
    owner = _user(conn, "RED", [K1], roles=())
    case = _case(conn, owner, "AMBER", [K1])
    made = _capture(client, conn, case, owner).json()
    pid = conn.execute("SELECT id FROM collect.proposal WHERE document_id = %s "
                       "LIMIT 1", (made["document_id"],)).fetchone()[0]
    r = client.post(f"/api/v1/cases/{case}/proposals/{pid}/accept",
                    headers=_auth(conn, owner), json={})
    assert r.status_code == 200, r.text
    assert conn.execute("SELECT compartments FROM core.node WHERE id = %s",
                        (r.json()["applied_node_id"],)).fetchone()[0] == []
    assert _audit_detail(conn, "PROPOSAL_ACCEPTED", pid)["compartments"] == []


def _block(conn, case_id, owner, publisher, keys) -> UUID:
    from noctornal_api.contact_blocks import ContactBlockService
    tox = (uuid4().hex + uuid4().hex + uuid4().hex)[:76].upper()
    ContactBlockService(conn).parse_and_store(
        case_id=case_id, raw_text=f"TOX: {tox}",
        source_ref=f"https://forum.example/{PREFIX}{uuid4().hex[:6]}",
        created_by=owner, publisher_identity_node_id=publisher,
        classification="AMBER", compartments=frozenset(keys))
    return conn.execute(
        """SELECT p.id FROM collect.proposal p
             JOIN comms.contact_block_entry e ON e.proposal_id = p.id
             JOIN comms.contact_block b ON b.id = e.block_id
            WHERE b.case_id = %s AND b.raw_text = %s""",
        (case_id, f"TOX: {tox}")).fetchone()[0]


def test_an_attribute_claim_counts_the_entitys_case_compartments(conn, client):
    from noctornal_api.proposals import ProposalError, ProposalReview
    owner = _user(conn, "RED", [K1, K2], roles=())
    case = _case(conn, owner, "AMBER", [K1])
    publisher = _node(conn, case, owner, f"{PREFIX}publisher")
    h = _auth(conn, owner)
    # In the case's own compartment: every reader of the entity holds it.
    same = _block(conn, case, owner, publisher, [K1])
    r = client.post(f"/api/v1/cases/{case}/proposals/{same}/accept",
                    headers=h, json={})
    assert r.status_code == 200, r.text
    # In a compartment the case does not carry: still refused.
    other = _block(conn, case, owner, publisher, [K2])
    r = client.post(f"/api/v1/cases/{case}/proposals/{other}/accept",
                    headers=h, json={})
    assert r.status_code == 409, r.text
    assert "compartment DCM-K2" in r.json()["detail"]
    # The service itself refuses an entity in another case, and writes
    # nothing; it relied on the route for that until L1.
    elsewhere_case = _case(conn, owner, "AMBER", [K1])
    elsewhere = _node(conn, elsewhere_case, owner, f"{PREFIX}elsewhere")
    pid = _propose(conn, case, "ATTRIBUTE", {
        "node_id": str(elsewhere), "claim_path": "comms.TOX",
        "claim_value": "AB" * 38, "classification": "AMBER"})
    before = conn.execute("SELECT count(*) FROM core.assertion WHERE node_id = %s",
                          (elsewhere,)).fetchone()[0]
    with pytest.raises(ProposalError, match="not in this case"):
        ProposalReview(conn).accept(pid, reviewed_by=owner)
    assert conn.execute("SELECT count(*) FROM core.assertion WHERE node_id = %s",
                        (elsewhere,)).fetchone()[0] == before
    assert conn.execute("SELECT state FROM collect.proposal WHERE id = %s",
                        (pid,)).fetchone()[0] == "PROPOSED"


# ---------------------------------------------------------------------------
# The legacy backfill (0071)
# ---------------------------------------------------------------------------

def _load(name: str):
    import importlib.util
    from pathlib import Path
    versions = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
    path = next(p for p in versions.glob("*.py") if p.name.endswith(name))
    spec = importlib.util.spec_from_file_location(f"dcm_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_legacy_backfill_labels_what_every_citing_case_can_read():
    """Run in a transaction that is rolled back: the statement is
    deployment-wide, so it is asserted on the documents seeded here and the
    audit rows naming them, never on global counts."""
    backfill = _load("_captured_document_labels.py").BACKFILL_SQL
    a, b = f"DCM-R-{uuid4().hex[:6].upper()}", f"DCM-R-{uuid4().hex[:6].upper()}"
    tx = _tx()
    try:
        for k in (a, b):
            tx.execute("INSERT INTO iam.compartment (key, label) "
                       "VALUES (%s, 'x')", (k,))
        uid = tx.execute(
            """INSERT INTO iam.app_user (email, display_name, password_hash,
                                         tlp_clearance)
               VALUES (%s, 'DCM', 'x', 'RED') RETURNING id""",
            (f"{PREFIX}{uuid4().hex[:8]}@noctornal.test",)).fetchone()[0]

        def case(cls, keys):
            _registered(tx, keys)
            return tx.execute(
                """INSERT INTO core."case" (code, title, owner_user_id,
                       legal_basis, retention_until, review_due,
                       classification, compartments)
                   VALUES (%s, 'DCM', %s, 'order', '2028-01-01', '2027-01-01',
                           %s, %s) RETURNING id""",
                (f"OP-DCM-{uuid4().hex[:6]}", uid, cls, keys)).fetchone()[0]

        ca, cab, cb = case("RED", [a]), case("RED", [a, b]), case("RED", [b])
        cu, cr1, cr2, cam = (case("AMBER", []), case("RED", []),
                             case("RED", []), case("AMBER", []))
        paste = _source(tx, "PASTE")
        rss = _source(tx, "RSS")

        def doc(cls, source=paste):
            return _document(tx, classification=cls, source=source)[0]

        def cite(document, case_id, via="proposal"):
            if via == "proposal":
                tx.execute(
                    """INSERT INTO collect.proposal (case_id, kind, payload,
                           origin, rationale, document_id)
                       VALUES (%s, 'NODE', '{}'::jsonb, 'dcm', 'x', %s)""",
                    (case_id, document))
            else:
                tx.execute(
                    """INSERT INTO audit.event (actor_id, action, object_type,
                           object_id, case_id, detail)
                       VALUES (%s, 'DOCUMENT_CAPTURED', 'document', %s, %s,
                               '{}'::jsonb)""", (uid, document, case_id))

        d = {"a": doc("AMBER"), "b": doc("AMBER"), "c": doc("RED"),
             "d": doc("AMBER"), "e": doc("AMBER", rss), "f": doc("AMBER"),
             "g": doc("AMBER")}
        cite(d["a"], ca)
        cite(d["b"], ca), cite(d["b"], cab, "audit")
        cite(d["c"], ca), cite(d["c"], cb)
        cite(d["d"], ca), cite(d["d"], cu)
        cite(d["e"], ca)
        cite(d["f"], cr1), cite(d["f"], cr2, "audit")
        cite(d["g"], cr1), cite(d["g"], cam)

        logged, summaries, left = tx.execute(backfill).fetchone()
        assert logged >= 3 and summaries == 1 and left >= 2

        def labels(key):
            return tx.execute("SELECT compartments, classification::text "
                              "FROM collect.document WHERE id = %s",
                              (d[key],)).fetchone()

        assert labels("a") == ([a], "RED")
        assert labels("b") == ([a], "RED"), "the intersection of {A} and {A,B}"
        assert labels("c") == ([], "RED"), "no key in common: left, counted"
        assert labels("d") == ([], "AMBER"), "an uncompartmented case cites it"
        assert labels("e") == ([], "AMBER"), "a collected document is no capture"
        assert labels("f") == ([], "RED"), "floored at the least citing case"
        assert labels("g") == ([], "AMBER"), "an AMBER case cites it too"
        rows = {r[0]: r[1] for r in tx.execute(
            """SELECT object_id, detail FROM audit.event
                WHERE action = 'DOCUMENT_LABELS_BACKFILLED'
                  AND object_id = ANY(%s)""", (list(d.values()),)).fetchall()}
        assert set(rows) == {d["a"], d["b"], d["f"]}
        assert rows[d["a"]]["compartments"] == [a]
        assert rows[d["a"]]["classification_was"] == "AMBER"
        assert rows[d["b"]]["cases"] == 2
        assert rows[d["f"]]["classification"] == "RED"
        # Again: nothing labelled, nothing written.
        assert tx.execute(backfill).fetchone()[:2] == (0, 0)
        from noctornal_api.legacy_records import unlabelled_captures
        listed = {c.document_id for c in unlabelled_captures(tx)}
        assert {d["c"], d["d"]} <= listed
        assert not {d["a"], d["b"], d["e"], d["f"], d["g"]} & listed
    finally:
        tx.rollback()
        tx.close()


@pytest.mark.parametrize("n,want", [
    (1, "1 document carries compartments; dropping the column would make it "
        "readable by clearance alone, outside the compartments it was "
        "captured under. Remove it first (SELECT id FROM collect.document "
        "WHERE cardinality(compartments) > 0), or stay at this revision."),
    (3, "3 documents carry compartments; dropping the column would make each "
        "readable by clearance alone, outside the compartments it was "
        "captured under. Remove them first (SELECT id FROM collect.document "
        "WHERE cardinality(compartments) > 0), or stay at this revision."),
])
def test_the_0070_downgrade_refusal_agrees_with_its_count(monkeypatch, n, want):
    """The refusal once read '1 document carry compartments' on a
    clone. The downgrade is run with its count faked, and must refuse with
    the sentence whole and run no SQL."""
    m = _load("_document_compartments.py")
    monkeypatch.setattr(m, "query", lambda _sql: [(n,)])
    monkeypatch.setattr(m, "run", lambda _sql: pytest.fail("ran SQL"))
    with pytest.raises(RuntimeError) as refused:
        m.downgrade()
    assert str(refused.value) == want


def test_the_register_counts_unlabelled_and_victim_captures():
    from noctornal_api.readiness import _captured_documents_compartmented
    tx = _tx()
    try:
        before = _captured_documents_compartmented(tx)
        assert before.ok
        from noctornal_api.legacy_records import (
            unlabelled_captures_count,
            victim_data_captures_count,
        )
        n0, v0 = unlabelled_captures_count(tx), victim_data_captures_count(tx)
        key, victim = (f"DCM-R-{uuid4().hex[:6].upper()}",
                       f"DCM-R-{uuid4().hex[:6].upper()}")
        for k in (key, victim):
            tx.execute("INSERT INTO iam.compartment (key, label) "
                       "VALUES (%s, 'x')", (k,))
        uid = tx.execute(
            """INSERT INTO iam.app_user (email, display_name, password_hash)
               VALUES (%s, 'DCM', 'x') RETURNING id""",
            (f"{PREFIX}{uuid4().hex[:8]}@noctornal.test",)).fetchone()[0]
        walled = tx.execute(
            """INSERT INTO core."case" (code, title, owner_user_id,
                   legal_basis, retention_until, review_due, compartments)
               VALUES (%s, 'DCM', %s, 'order', '2028-01-01', '2027-01-01', %s)
               RETURNING id""", (f"OP-DCM-{uuid4().hex[:6]}", uid, [key])
        ).fetchone()[0]
        doc, _ = _document(tx)
        tx.execute("""INSERT INTO collect.proposal (case_id, kind, payload,
                          origin, rationale, document_id)
                      VALUES (%s, 'NODE', '{}'::jsonb, 'dcm', 'x', %s)""",
                   (walled, doc))
        tx.execute(
            """INSERT INTO ingest.api_key (key_id, secret_hmac, pepper_id,
                   name, expires_at, owner_user_id, forced_compartment)
               VALUES (%s, %s, 'env:v1', 'dcm', now() + interval '1 day', %s,
                       %s)""", (uuid4().hex[:8], os.urandom(32), uid, victim))
        _document(tx, keys=[victim])
        after = _captured_documents_compartmented(tx)
        assert after.ok, "the register refuses nothing over this"
        assert unlabelled_captures_count(tx) == n0 + 1
        assert victim_data_captures_count(tx) == v0 + 1
        assert "python scripts/legacy_records.py --section captures" in after.caveat
        assert "--section victim-captures" in after.caveat
        for bad in ("OP-DCM", key, victim, "(s)", chr(0x2014)):
            assert bad not in after.evidence + after.caveat
        if n0 == 0:
            assert after.evidence == ("1 captured document that a "
                                      "compartmented case cites carries no "
                                      "compartment.")
    finally:
        tx.rollback()
        tx.close()


# ---------------------------------------------------------------------------
# The registry and the lifecycle reach documents
# ---------------------------------------------------------------------------

def test_the_index_serves_the_registry():
    """EXPLAIN of the text the registry and the lifecycle run, not a hand
    copy of it: the array leg `iam.compartment_in_use`
    formats (its module constant, which the live function must contain) and
    `compartment_lifecycle._carries`."""
    from psycopg import sql

    from noctornal_api.compartment_lifecycle import _carries
    leg = _load("_compartment_in_use_reads_bindings.py").IN_USE_ARRAY_LEG
    tx = _tx()
    try:
        body = tx.execute("SELECT pg_get_functiondef("
                          "'iam.compartment_in_use(text)'::regprocedure)"
                          ).fetchone()[0]
        assert leg in body
        tx.execute("SET LOCAL enable_seqscan = off")
        text = tx.execute("SELECT format(%s, 'collect', 'document', "
                          "'compartments', 'compartments')", (leg,)).fetchone()[0]
        tx.execute(f"PREPARE dcm_leg(text) AS {text}")
        plan = json.dumps(tx.execute(
            "EXPLAIN (FORMAT JSON) EXECUTE dcm_leg('DCM-K1')").fetchone()[0])
        assert "document_compartments_idx" in plan, plan
        count = sql.SQL("EXPLAIN (FORMAT JSON) SELECT count(*) FROM "
                        "collect.document WHERE {}").format(
            _carries("compartments", "array"))
        plan = json.dumps(tx.execute(count, ("DCM-K1",)).fetchone()[0])
        assert "document_compartments_idx" in plan, plan
    finally:
        tx.rollback()
        tx.close()


def test_rename_and_retire_reach_a_document(conn):
    from noctornal_api.compartment_lifecycle import (
        CompartmentInUse,
        CompartmentLifecycle,
    )
    admin = _user(conn, "RED", roles=("SYS_ADMIN",))
    old, new = (f"DCM-R-{uuid4().hex[:6].upper()}",
                f"DCM-R-{uuid4().hex[:6].upper()}")
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'x')",
                 (old,))
    doc, _ = _document(conn, keys=[old])
    done = CompartmentLifecycle(conn).rename(old, new, label=None,
                                             actor_id=admin)
    assert done["rows"] == {"collect.document.compartments": 1}
    assert "1 document." in done["summary"]
    assert conn.execute("SELECT compartments FROM collect.document "
                        "WHERE id = %s", (doc,)).fetchone()[0] == [new]
    with pytest.raises(CompartmentInUse) as refused:
        CompartmentLifecycle(conn).retire(new, actor_id=admin)
    assert "carried by 1 document." in str(refused.value)


# ---------------------------------------------------------------------------
# A contact block cites only what its case already cites
# ---------------------------------------------------------------------------

def test_a_contact_block_cites_only_a_document_its_case_already_cites(
        conn, client):
    from noctornal_api.contact_blocks import ContactBlockService
    owner = _user(conn, "RED", [K1, K2], roles=())
    case = _case(conn, owner, "AMBER")
    other = _case(conn, owner, "AMBER")
    h = _auth(conn, owner)

    def cited(document, case_id=case):
        _propose(conn, case_id, "NODE", _selector_payload(), document)
        return document

    good = cited(_document(conn)[0])
    above = cited(_document(conn, classification="RED")[0])
    red_source = cited(_document(conn, source=_source(
        conn, classification="RED"))[0])
    walled = cited(_document(conn, keys=[K2])[0])
    foreign = cited(_document(conn)[0], other)
    purged = cited(_document(conn, purged=True)[0])

    def post(document_id):
        return client.post(f"/api/v1/cases/{case}/comms/contact-blocks",
                           headers=h, json={
                               "raw_text": f"TOX: {uuid4().hex}",
                               "source_ref": f"https://forum.example/{uuid4().hex}",
                               "document_id": str(document_id),
                               "classification": "AMBER"})

    r = post(good)
    assert r.status_code == 201, r.text
    for name, document_id in (("above", above), ("red source", red_source),
                              ("outside", walled), ("foreign", foreign),
                              ("purged", purged), ("random", uuid4())):
        r = post(document_id)
        assert r.status_code == 400, (name, r.text)
        assert r.json()["detail"] == ContactBlockService.UNCITABLE_DOCUMENT, name

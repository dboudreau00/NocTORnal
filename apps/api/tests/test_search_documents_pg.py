"""K3: search never reached collected documents.

`collect.document.search_tsv` has been maintained by a trigger since 0016
and indexed by a GIN since 0011, and `SearchService` queried `core.node`
and `core.evidence` only. So the one place an analyst types a handle, a
domain or a phrase and expects everything the case knows about it did not
look at anything the collector had collected -- the phase that exists to
find those things.

The document half joins at the CALLER's clearance, exactly as the node
and evidence halves do and as `CollectionService.documents` does:
`collect.document.classification` defaults to AMBER and can be higher, so
a RED post must be invisible to an AMBER analyst rather than
discoverable-then-403. A node carrying the same token still appears for
that analyst, because the two halves are filtered independently.

Env-gated on DATABASE_URL. Users are `srchd-`, sources `test-srcs3-`; no
other suite's teardown pattern matches either.
"""
from __future__ import annotations

import os
import time
from datetime import date, datetime, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; search tests are gated"
)

PASSWORD = "correct-horse-battery-staple"

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'srchd-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    ssub = "(SELECT id FROM collect.source WHERE name LIKE 'test-srcs3-%')"
    # ONE transaction: `assertion_protects_element` (0022) is a deferred
    # constraint trigger that refuses to let the last assertion of a
    # still-existing node go, so assertions and nodes must vanish together.
    with c.transaction():
        c.execute(f"DELETE FROM collect.document WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.source WHERE id IN {ssub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'srchd-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


# --- helpers ------------------------------------------------------------

def _user(conn, *, clearance="RED", roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"srchd-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Searcher", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _login(client, email, secret) -> str:
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-SRCH-{uuid4().hex[:6]}", title="Search",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


def _node(conn, case_id, uid, label):
    """Through the real write path, so it carries its assertion
    (invariant 1) rather than being conjured straight into the table."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=uid,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid))


def _source(conn):
    return conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, default_reliability, parser_key,
                classification)
           VALUES ('RSS', %s, 'https://forum.test/feed', 'C', 'rss', 'AMBER')
           RETURNING id""",
        (f"test-srcs3-{uuid4().hex[:6]}",)).fetchone()[0]


def _doc(conn, source_id, *, body, title="A thread", classification="AMBER"):
    return conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, external_url, title, body_text,
                author_handle, posted_at, content_sha256, classification)
           VALUES (%s, %s, 'https://forum.test/t/9', %s, %s, 'vendor01', %s,
                   decode(md5(%s), 'hex'), %s::core.tlp)
           RETURNING id""",
        (source_id, uuid4().hex, title, body, datetime.now(timezone.utc),
         body, classification)).fetchone()[0]


def _token() -> str:
    """A token no other row can contain, in a shape the 'simple' parser
    keeps whole: letters and digits only, no punctuation to split on."""
    return f"zq{uuid4().hex[:12]}"


def _hits(rows, kind) -> set[str]:
    return {str(h["id"]) for h in rows if h["kind"] == kind}


# --- the service --------------------------------------------------------

def test_a_collected_document_is_found_by_search_at_the_callers_clearance(conn):
    """The whole finding: a RED caller finds the post, an AMBER caller
    does not, and the AMBER caller still finds the node carrying the same
    token -- the two halves are filtered independently."""
    from noctornal_api.curation import SearchService

    token = _token()
    owner = _user(conn)[0]
    case = _case(conn, owner)
    node = _node(conn, case, owner, f"actor {token}")
    doc = _doc(conn, _source(conn), body=f"selling access, contact {token} on jabber",
               title="Access for sale", classification="RED")
    svc = SearchService(conn)

    red = svc.search(case_id=case, query=token, clearance="RED",
                     compartments=frozenset())
    assert str(doc) in _hits(red, "document"), (
        "a collected document containing the query was not returned by search")
    assert str(node) in _hits(red, "node")
    hit = next(h for h in red if h["kind"] == "document")
    assert hit["label"] == "Access for sale"
    assert token in hit["excerpt"]
    assert hit["source_name"].startswith("test-srcs3-")
    assert hit["external_url"] == "https://forum.test/t/9"
    assert hit["posted_at"]

    amber = svc.search(case_id=case, query=token, clearance="AMBER",
                       compartments=frozenset())
    assert str(doc) not in _hits(amber, "document"), (
        "a RED document was returned to an AMBER caller")
    assert str(node) in _hits(amber, "node"), (
        "filtering the document half must not cost the node half")


def test_a_purged_document_is_not_searchable(conn):
    """`retention` NULLs the body and stamps `purged_at`; the tsvector is
    recomputed by the trigger but the title survives, and a destroyed
    exhibit must not be findable by what is left of it."""
    from noctornal_api.curation import SearchService

    token = _token()
    owner = _user(conn)[0]
    case = _case(conn, owner)
    doc = _doc(conn, _source(conn), body="gone", title=f"thread {token}")
    conn.execute("UPDATE collect.document SET purged_at = now(), body_text = '' "
                 "WHERE id = %s", (doc,))
    rows = SearchService(conn).search(case_id=case, query=token, clearance="RED",
                                      compartments=frozenset())
    assert str(doc) not in _hits(rows, "document")


# --- both halves: the router and the permission that gates documents -----

def test_the_search_router_returns_documents_only_to_collection_readers(conn, client):
    """Documents are gated on GLOBAL `collection.read` everywhere else
    (`/collection/documents`), so a case-scoped search that handed them
    to any `case.read` holder would be the two-halves defect: the list
    endpoint refusing what the search endpoint returns. A caller without
    it gets the node and a stated omission, not a silent gap."""
    token = _token()
    owner, owner_email, owner_secret = _user(conn, roles=("CASE_OWNER",))
    case = _case(conn, owner)
    node = _node(conn, case, owner, f"actor {token}")
    doc = _doc(conn, _source(conn), body=f"contact {token}", classification="RED")
    # A RED reader with case.read on the case and NO global collection.read.
    reader, reader_email, reader_secret = _user(conn)
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'READ_ONLY', %s)""", (case, reader, owner))

    r = client.get(f"/api/v1/cases/{case}/search?q={token}",
                   headers=_auth(_login(client, owner_email, owner_secret)))
    assert r.status_code == 200, r.text
    body = r.json()
    assert str(doc) in _hits(body["hits"], "document")
    assert str(node) in _hits(body["hits"], "node")
    assert "documents" not in body["omitted"]

    r = client.get(f"/api/v1/cases/{case}/search?q={token}",
                   headers=_auth(_login(client, reader_email, reader_secret)))
    assert r.status_code == 200, r.text
    body = r.json()
    assert str(doc) not in _hits(body["hits"], "document")
    assert str(node) in _hits(body["hits"], "node")
    assert "documents" in body["omitted"], (
        "a caller without collection.read must be TOLD documents were "
        "omitted, not shown an empty result that reads as 'nothing collected'")

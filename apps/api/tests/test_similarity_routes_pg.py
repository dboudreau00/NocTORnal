"""The similarity routes and the status route (F6.3, embeddings,
2026-09-24).

POST routes beside the untouched GET text search: the query travels in the
body; /similar embeds a missing item on demand; every refusal is a
sentence; a MEANING query is gated with its case's labels, metered, and
audited (with a keyed hash, never the text) before it is sent; the GET
routes answer exactly as before.

Env-gated on DATABASE_URL. Prefix `esr-`.
"""
from __future__ import annotations

import hashlib
import os
from uuid import uuid4

import pytest

import embedding_pg as H
from embedding_stub import StubModel, meaning_env
from noctornal_api import embedders as E

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "esr-"
FIX = os.path.join(os.path.dirname(__file__), "fixtures", "embeddings")
POST = open(os.path.join(FIX, "camera_shop.txt"), encoding="utf-8").read()
OTHER = open(os.path.join(FIX, "bicycle_workshop.txt"), encoding="utf-8").read()


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL") + tuple(
            n for n in os.environ if n.startswith("NOCTORNAL_EMBED_")):
        monkeypatch.delenv(name, raising=False)
    from noctornal_api import embeddings, readiness
    monkeypatch.setattr(readiness, "blocking_failures", lambda _c: [])
    monkeypatch.setattr(embeddings, "_BULK_ENQUEUE",
                        {k: "SELECT %s" for k in embeddings.KINDS})
    embeddings._STATUS_CACHE.clear()
    embeddings._COVERAGE_CACHE.clear()


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    H.reset(c)
    yield c
    H.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def stub():
    s = StubModel(dims=384)
    yield s
    s.close()


def _service(conn):
    from noctornal_api.embeddings import EmbeddingService
    return EmbeddingService(conn, blocking_failures=lambda _c: [])


@pytest.fixture
def world(conn):
    owner = H.user(conn, PREFIX, roles=("ANALYST",))
    case_id = H.case(conn, PREFIX, owner)
    src = H.source(conn, PREFIX)
    svc = _service(conn)
    svc.ensure_spaces()
    docs = {"post": H.document(conn, PREFIX, src=src, body=POST, external_id="t-1"),
            "repost": H.document(conn, PREFIX, src=H.source(conn, PREFIX),
                                 body="Repost: " + POST[:2200]),
            "other": H.document(conn, PREFIX, src=src, body=OTHER)}
    H.only_queue(conn, list(docs.values()))
    svc.run_pass("WORDING", max_seconds=0)
    return {"owner": owner, "case": case_id, "src": src, "docs": docs, "svc": svc,
            "client": H.app_client()}


def test_status_answers_any_account_without_counts_or_host(conn, world, stub,
                                                           monkeypatch):
    nobody = H.user(conn, PREFIX, roles=())
    cl = world["client"]
    status = cl.get("/api/v1/embeddings/status", headers=H.auth(conn, nobody)).json()
    assert status["wording"]["state"] == "on" and status["wording"]["query_available"]
    assert status["meaning"]["state"] == "off"
    for name, value in meaning_env(stub).items():
        monkeypatch.setenv(name, value)
    status = cl.get("/api/v1/embeddings/status", headers=H.auth(conn, nobody)).json()
    assert status["meaning"]["state"] == "on" or status["meaning"]["state"] == "building"
    assert status["meaning"]["endpoint_label"] == "on this host"
    assert str(stub.port) not in str(status)
    from noctornal_api import embeddings, readiness
    monkeypatch.setattr(readiness, "blocking_failures", lambda _c: ["x"])
    embeddings._STATUS_CACHE.clear()
    status = cl.get("/api/v1/embeddings/status", headers=H.auth(conn, nobody)).json()
    assert status["meaning"]["state"] == "paused"


def test_similar_needs_collection_read_as_the_document_list_does(conn, world):
    nobody = H.user(conn, PREFIX, roles=())
    r = world["client"].post(f"/api/v1/collection/documents/{world['docs']['post']}"
                             f"/similar", headers=H.auth(conn, nobody), json={})
    assert r.status_code == 403


def test_similar_bands_the_repost_and_drops_the_unrelated(conn, world):
    r = world["client"].post(f"/api/v1/collection/documents/{world['docs']['post']}"
                             f"/similar", headers=H.auth(conn, world["owner"]),
                             json={"space": "wording"})
    body = r.json()
    ids = [h["id"] for h in body["hits"]]
    assert str(world["docs"]["repost"]) in ids and str(world["docs"]["other"]) not in ids
    hit = body["hits"][0]
    assert hit["band"] in ("near duplicate", "much of the same wording")
    assert hit["shared_phrases"] and hit["position"] == 1
    assert "text" not in hit and "embedding" not in str(body)
    assert "not the same author" in body["note"]


def test_versions_are_left_out_unless_asked_for(conn, world):
    version = H.document(conn, PREFIX, src=world["src"], body=POST + " edited",
                         external_id="t-1", version=2)
    H.only_queue(conn, [version])
    world["svc"].run_pass("WORDING", max_seconds=0)
    cl, auth = world["client"], H.auth(conn, world["owner"])
    url = f"/api/v1/collection/documents/{world['docs']['post']}/similar"
    r = cl.post(url, headers=auth, json={"space": "wording"})
    assert str(version) not in [h["id"] for h in r.json()["hits"]]
    r = cl.post(url, headers=auth, json={"space": "wording", "include_versions": True})
    flagged = {h["id"]: h["is_version_of_query"] for h in r.json()["hits"]}
    assert flagged.get(str(version)) is True
    assert flagged.get(str(world["docs"]["repost"])) is False


def test_a_missing_vector_is_embedded_on_demand_and_refusals_are_sentences(conn, world):
    fresh = H.document(conn, PREFIX, src=world["src"], body=POST[:1800] + " new")
    stealer = H.document(conn, PREFIX, src=world["src"], body="user pass line",
                         category="STEALER_LOG")
    cl, auth = world["client"], H.auth(conn, world["owner"])
    r = cl.post(f"/api/v1/collection/documents/{fresh}/similar", headers=auth, json={})
    assert r.status_code == 200 and r.json()["query_embedded_now"] is True
    r = cl.post(f"/api/v1/collection/documents/{stealer}/similar", headers=auth, json={})
    assert r.status_code == 409
    assert r.json()["detail"] == ("Not in the similar wording index: it is victim data, "
                                  "which is never embedded.")


def test_search_without_collection_read_answers_with_search_documents_sentence(conn,
                                                                               world):
    guest = H.user(conn, PREFIX, roles=())
    H.assign(conn, world["case"], guest, "ANALYST", world["owner"])
    cl, auth = world["client"], H.auth(conn, guest)
    similar = cl.post(f"/api/v1/cases/{world['case']}/search/documents/similar",
                      headers=auth, json={"q": POST[:300], "mode": "wording"}).json()
    text = cl.get(f"/api/v1/cases/{world['case']}/search/documents",
                  headers=auth, params={"q": "camera"}).json()
    assert similar["not_searched"] == text["not_searched"] and similar["hits"] == []


def test_similar_wording_needs_twenty_characters(conn, world):
    r = world["client"].post(f"/api/v1/cases/{world['case']}/search/documents/similar",
                             headers=H.auth(conn, world["owner"]),
                             json={"q": "  short text  ", "mode": "wording"})
    assert r.status_code == 422
    assert "at least 20 characters" in r.json()["detail"]


def test_the_query_travels_in_the_body_never_the_url(world):
    spec = world["client"].get("/api/v1/openapi.json")
    if spec.status_code != 200:
        from noctornal_api.http.app import create_app
        paths = create_app().openapi()["paths"]
    else:
        paths = spec.json()["paths"]
    for path, ops in paths.items():
        if path.endswith("/similar"):
            for op in ops.values():
                names = {p["name"] for p in op.get("parameters", [])}
                assert "q" not in names, path


@pytest.fixture
def meaning(conn, world, stub, monkeypatch):
    for name, value in meaning_env(stub, **{E.CEILING_ENV: "AMBER"}).items():
        monkeypatch.setenv(name, value)
    svc = _service(conn)
    svc.run_pass("MEANING", max_seconds=0)
    return stub


def test_a_meaning_query_above_the_ceiling_is_refused_and_not_audited(conn, world,
                                                                       meaning):
    red_case = H.case(conn, PREFIX, world["owner"], classification="RED")
    r = world["client"].post(f"/api/v1/cases/{red_case}/search/documents/similar",
                             headers=H.auth(conn, world["owner"]),
                             json={"q": "which posts talk about shutters", "mode": "meaning"})
    assert r.status_code == 409
    assert r.json()["detail"] == (
        "Similar meaning is not available on this case. Its label is TLP:RED and the "
        "model endpoint is cleared to TLP:AMBER, so the query would leave this "
        "deployment above what the endpoint may receive.")
    assert conn.execute("SELECT count(*) FROM audit.event WHERE action = "
                        "'EMBED_QUERY_SENT' AND case_id = %s", (red_case,)).fetchone()[0] == 0
    assert "shutters" not in "".join(meaning.texts())


def test_an_allowed_meaning_query_is_audited_before_it_is_sent_and_keyed(conn, world,
                                                                         meaning):
    from noctornal_api.db import connect
    query = f"posts about shutters and light seals {uuid4().hex}"
    seen = []

    def read_audit(body):
        with connect() as reader:
            seen.append(reader.execute(
                "SELECT detail FROM audit.event WHERE action = 'EMBED_QUERY_SENT' "
                "AND case_id = %s ORDER BY seq DESC LIMIT 1",
                (world["case"],)).fetchone())
    meaning.on_request = read_audit
    r = world["client"].post(f"/api/v1/cases/{world['case']}/search/documents/similar",
                             headers=H.auth(conn, world["owner"]),
                             json={"q": query, "mode": "meaning"})
    assert r.status_code == 200, r.text
    detail = seen[-1][0]
    assert detail["query_chars"] == len(query) and detail["label"] == "AMBER"
    assert detail["query_hmac"] and detail["query_hmac"] != hashlib.sha256(
        query.encode()).hexdigest()
    leaked = conn.execute("SELECT count(*) FROM audit.event WHERE detail::text LIKE %s",
                          (f"%{query[-32:]}%",)).fetchone()[0]
    assert leaked == 0


def test_the_meaning_meter_is_spent_on_demand_too(conn, world, meaning):
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, Limit, RateLimiter, Scope
    limits = dict(LIMITS)
    limits["search.meaning"] = Limit("search.meaning", quota=1, per_seconds=3600,
                                     scope=Scope.USER, burst=1)
    cl = world["client"]
    cl.app.state.limiter = RateLimiter(InProcessBackend(), limits=limits)
    auth = H.auth(conn, world["owner"])
    a = H.document(conn, PREFIX, src=world["src"], body="first post needing meaning")
    b = H.document(conn, PREFIX, src=world["src"], body="second post needing meaning")
    first = cl.post(f"/api/v1/collection/documents/{a}/similar", headers=auth,
                    json={"space": "meaning"})
    assert first.status_code == 200, first.text
    sent = len(meaning.content_requests())
    second = cl.post(f"/api/v1/collection/documents/{b}/similar", headers=auth,
                     json={"space": "meaning"})
    assert second.status_code == 429
    assert len(meaning.content_requests()) == sent


def test_the_limits_exist():
    from noctornal_api.ratelimit import LIMITS
    assert LIMITS["search.meaning"].on_backend_failure.name == "DENY"
    assert LIMITS["embedding.pass"].on_backend_failure.name == "DENY"


def test_the_get_text_routes_answer_as_before(conn, world):
    cl, auth, case = world["client"], H.auth(conn, world["owner"]), world["case"]
    for kind, keys in (("nodes", {"hits", "total", "limit"}),
                       ("evidence", {"hits", "total", "limit"}),
                       ("documents", {"hits", "total", "limit", "not_searched"}),
                       ("assertions", {"hits", "total", "limit"})):
        params = {"q": "camera"}
        if kind in ("nodes", "evidence"):
            params["with_total"] = "true"
        r = cl.get(f"/api/v1/cases/{case}/search/{kind}", headers=auth, params=params)
        assert r.status_code == 200, (kind, r.text)
        assert set(r.json()) == keys, kind

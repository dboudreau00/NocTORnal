"""Administration, Embeddings (F6.3, embeddings, 2026-09-24).

Every route needs embedding.manage (SYS_ADMIN) and a fresh step-up.
Figures need the global collection.read as well and follow the caller's
own case-less clearance and compartments; a caller without it gets the
spaces and the endpoint facts and no count anywhere. Activation refuses in
words without a number; the console's pass answers in flags.

Env-gated on DATABASE_URL. Prefix `eam-`.
"""
from __future__ import annotations

import json
import os

import pytest

import embedding_pg as H

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "eam-"
K1 = "EAM-K1"


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL") + tuple(
            n for n in os.environ if n.startswith("NOCTORNAL_EMBED_")):
        monkeypatch.delenv(name, raising=False)
    from noctornal_api import embeddings
    embeddings._COVERAGE_CACHE.clear()


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'Admin test') "
              "ON CONFLICT (key) DO NOTHING", (K1,))
    H.reset(c)
    yield c
    H.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def world(conn):
    from noctornal_api.embeddings import EmbeddingService
    admin = H.user(conn, PREFIX, clearance="RED", roles=("SYS_ADMIN",))
    reader_admin = H.user(conn, PREFIX, clearance="AMBER", roles=("SYS_ADMIN", "ANALYST"))
    analyst = H.user(conn, PREFIX, roles=("ANALYST",))
    src = H.source(conn, PREFIX)
    docs = {"amber": H.document(conn, PREFIX, src=src, body="an amber post about lenses"),
            "red": H.document(conn, PREFIX, src=src, body="a red post about lenses",
                              classification="RED"),
            "boxed": H.document(conn, PREFIX, src=src, body="a boxed post", keys=[K1]),
            "stealer": H.document(conn, PREFIX, src=src, body="login line",
                                  category="STEALER_LOG")}
    svc = EmbeddingService(conn, blocking_failures=lambda _c: [])
    svc.ensure_spaces()
    H.only_queue(conn, list(docs.values()))
    svc.run_pass("WORDING", max_seconds=0)
    return {"admin": admin, "reader_admin": reader_admin, "analyst": analyst,
            "docs": docs, "svc": svc, "client": H.app_client()}


def test_every_route_needs_the_permission_and_a_fresh_sign_in(conn, world):
    cl = world["client"]
    space = world["svc"].active("WORDING")
    routes = [("GET", "/api/v1/admin/embeddings", None),
              ("GET", f"/api/v1/admin/embeddings/gaps?space_id={space.id}", None),
              ("POST", "/api/v1/admin/embeddings/spaces",
               {"role": "WORDING", "reason": "rebuild it"}),
              ("POST", f"/api/v1/admin/embeddings/spaces/{space.id}/retire",
               {"reason": "no longer"}),
              ("POST", "/api/v1/admin/embeddings/pass", {"role": "WORDING"})]
    stale = H.auth(conn, world["admin"], fresh=False)
    analyst = H.auth(conn, world["analyst"])
    for method, url, body in routes:
        r = cl.request(method, url, headers=analyst, json=body)
        assert r.status_code == 403 and "embedding.manage" in r.json()["detail"], url
        r = cl.request(method, url, headers=stale, json=body)
        assert r.status_code == 403 and "re-authentication" in r.json()["detail"], url
    assert world["svc"].active("WORDING").id == space.id


def test_an_administrator_who_reads_no_documents_sees_no_figure(conn, world):
    cl, auth = world["client"], H.auth(conn, world["admin"])
    body = cl.get("/api/v1/admin/embeddings", headers=auth).json()
    assert body["coverage"] is None
    assert body["coverage_note"] == ("Coverage figures are shown to accounts that read "
                                     "collected documents.")
    assert body["spaces"] and body["endpoint"] == {"configured": False}
    text = json.dumps(body)
    for key in ("readable", "embedded", "pending", "withheld_reasons"):
        assert key not in text
    space = world["svc"].active("WORDING")
    gaps = cl.get(f"/api/v1/admin/embeddings/gaps?space_id={space.id}", headers=auth)
    assert gaps.status_code == 403 and gaps.json()["detail"] == body["coverage_note"]
    access = cl.get("/api/v1/admin/access", headers=auth).json()
    assert access["embedding_manage"] is True


def test_figures_and_gaps_follow_the_callers_own_labels(conn, world):
    cl, auth = world["client"], H.auth(conn, world["reader_admin"])
    body = cl.get("/api/v1/admin/embeddings", headers=auth).json()
    space = world["svc"].active("WORDING")
    coverage = body["coverage"][str(space.id)]
    assert coverage["readable"] == 2  # the amber post and the stealer log line
    assert coverage["embedded"] == 1 and coverage["excluded"] == 1
    gaps = cl.get(f"/api/v1/admin/embeddings/gaps?space_id={space.id}",
                  headers=auth).json()["gaps"]
    ids = {g["document_id"] for g in gaps}
    assert ids == {str(world["docs"]["stealer"])}
    assert gaps[0]["reason_text"].startswith("it is victim data")


def test_activation_refuses_in_words_and_accept_missing_overrides(conn, world, monkeypatch):
    from noctornal_api import embedders as E
    monkeypatch.setitem(E.BUILTIN_VERSIONS, H.V2Builtin.model, H.V2Builtin)
    monkeypatch.setattr(E, "BUILTIN_CURRENT", H.V2Builtin.model)
    cl, auth = world["client"], H.auth(conn, world["admin"])
    made = cl.post("/api/v1/admin/embeddings/spaces", headers=auth,
                   json={"role": "WORDING", "reason": "the new built-in model"})
    assert made.status_code == 201, made.text
    new = made.json()
    assert new["state"] == "BUILDING"
    conn.execute("INSERT INTO core.embedding_pending (slot, kind, item_id) "
                 "VALUES (%s, 'document', %s) ON CONFLICT DO NOTHING",
                 (new["slot"], world["docs"]["amber"]))
    refused = cl.post(f"/api/v1/admin/embeddings/spaces/{new['id']}/activate",
                      headers=auth, json={"reason": "try it"})
    assert refused.status_code == 409
    assert not any(ch.isdigit() for ch in refused.json()["detail"])
    done = cl.post(f"/api/v1/admin/embeddings/spaces/{new['id']}/activate",
                   headers=auth, json={"reason": "partial is fine", "accept_missing": True})
    assert done.status_code == 200 and done.json()["state"] == "ACTIVE"
    again = cl.post("/api/v1/admin/embeddings/spaces", headers=auth,
                    json={"role": "WORDING", "reason": "rebuild once more"})
    assert again.status_code == 409


def test_recheck_makes_withheld_and_failed_rows_due_now(conn, world):
    space = world["svc"].active("WORDING")
    conn.execute("""UPDATE collect.document_embedding SET status = 'FAILED',
                           embedding = NULL, reason = 'x', first_failed_at = now(),
                           next_attempt_at = now() + interval '1 day'
                     WHERE document_id = %s""", (world["docs"]["amber"],))
    r = world["client"].post(f"/api/v1/admin/embeddings/spaces/{space.id}/recheck",
                             headers=H.auth(conn, world["admin"]),
                             json={"reason": "the endpoint is back"})
    assert r.status_code == 200
    due = conn.execute("SELECT next_attempt_at <= now() FROM collect.document_embedding "
                       "WHERE document_id = %s", (world["docs"]["amber"],)).fetchone()[0]
    assert due
    assert conn.execute("SELECT count(*) FROM audit.event WHERE action = 'EMBED_RECHECK' "
                        "AND object_id = %s", (space.id,)).fetchone()[0] == 1


def test_the_console_pass_answers_in_flags_and_spends_its_meter(conn, world):
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, Limit, RateLimiter, Scope
    limits = dict(LIMITS)
    limits["embedding.pass"] = Limit("embedding.pass", quota=1, per_seconds=3600,
                                     scope=Scope.USER, burst=1)
    cl = world["client"]
    cl.app.state.limiter = RateLimiter(InProcessBackend(), limits=limits)
    auth = H.auth(conn, world["admin"])
    r = cl.post("/api/v1/admin/embeddings/pass", headers=auth, json={"role": "WORDING"})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"role", "ran", "locked", "any_failed", "deferred", "refused",
                         "refused_text"}
    assert all(isinstance(body[k], bool) for k in ("ran", "locked", "any_failed",
                                                   "deferred"))
    assert cl.post("/api/v1/admin/embeddings/pass", headers=auth,
                   json={"role": "WORDING"}).status_code == 429


def test_a_malformed_page_key_is_a_422_never_a_500(conn, world):
    """An after_at of notadate reached a SQL cast and answered 500
    (2026-09-25)."""
    cl, auth = world["client"], H.auth(conn, world["reader_admin"])
    space = world["svc"].active("WORDING")
    base = f"/api/v1/admin/embeddings/gaps?space_id={space.id}"
    some_id = world["docs"]["stealer"]
    for query in (f"&after_at=notadate&after_id={some_id}",
                  f"&after_at=2026-13-45T99:00:00Z&after_id={some_id}",
                  "&after_at=2026-09-25T10:00:00Z&after_id=not-a-uuid",
                  "&after_at=2026-09-25T10:00:00Z",
                  f"&after_id={some_id}",
                  f"&after_at=2026-09-25T10:00:00&after_id={some_id}"):
        r = cl.get(base + query, headers=auth)
        assert r.status_code == 422, (query, r.status_code, r.text)
    # A key from a real page still pages.
    conn.execute("UPDATE collect.document_embedding SET status = 'FAILED', "
                 "embedding = NULL, reason = 'endpoint_unavailable', "
                 "first_failed_at = now(), next_attempt_at = now() + interval '1 hour' "
                 "WHERE document_id = %s", (world["docs"]["amber"],))
    first = cl.get(base + "&limit=1", headers=auth).json()
    assert len(first["gaps"]) == 1 and first["next"]
    nxt = first["next"]
    second = cl.get("/api/v1/admin/embeddings/gaps", headers=auth,
                    params={"space_id": str(space.id), "limit": 1,
                            "after_at": nxt["after_at"], "after_id": nxt["after_id"]})
    assert second.status_code == 200, second.text
    assert [g["document_id"] for g in second.json()["gaps"]] != \
        [g["document_id"] for g in first["gaps"]]

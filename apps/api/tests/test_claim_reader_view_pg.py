"""A claim's similarity reasons never describe material its reader cannot
read (F6.4, embeddings, 2026-09-25).

A claim's row is judged on the labels of what it cites as well as its own,
and read.py withholds cited material above the reader (the ids, no title).
The verifier found the stored reason reaching that reader anyway: through
the 409 of POST /cases/{id}/assertions/{id}/similar and through the
withheld reasons and the excluded count of the Assertions column's
coverage. An AMBER reader of a claim on an AMBER node learned that what it
cites is TLP:AMBER_STRICT or RED, compartmented, purged or victim data.

Now a reader is told what the facts THEY can read give (claim_reader_view):
the stored reason when they can read everything the claim cites, a reason
their readable facts alone give otherwise, and else only that the claim
cannot be compared.

Env-gated on DATABASE_URL. Prefix `crv-`.
"""
from __future__ import annotations

import os

import pytest

import embedding_pg as H
from embedding_stub import StubModel, meaning_env
from noctornal_api import embedders as E

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "crv-"
K1 = "CRV-K1"
AUTHORITY = "DPIA-2026-EMB-03"
#: Words a reason about the cited material would use.
TELLS = ("TLP", "RED", "AMBER_STRICT", "compartment", "purged", "victim")


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL",
                 "NOCTORNAL_EGRESS_INTERNAL_CIDRS") + tuple(
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
    c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'Reader view test') "
              "ON CONFLICT (key) DO NOTHING", (K1,))
    H.reset(c)
    yield c
    H.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def stub():
    s = StubModel(dims=384)
    yield s
    s.close()


@pytest.fixture
def world(conn, stub, monkeypatch):
    for name, value in meaning_env(stub, local=False,
                                   **{E.AUTHORITY_ENV: AUTHORITY}).items():
        monkeypatch.setenv(name, value)
    from noctornal_api.embeddings import EmbeddingService
    svc = EmbeddingService(conn, blocking_failures=lambda _c: [])
    svc.ensure_spaces()
    assert svc.run_pass("MEANING", max_seconds=0).refused is None
    owner = H.user(conn, PREFIX, roles=("ANALYST",), keys=(K1,))
    case_id = H.case(conn, PREFIX, owner)
    src = H.source(conn, PREFIX)
    red_doc = H.document(conn, PREFIX, src=src, body="the red post itself",
                         classification="RED")
    stealer = H.document(conn, PREFIX, src=src, body="user:pass lines",
                         category="STEALER_LOG")
    gone = H.document(conn, PREFIX, src=src, body="a post purged later")
    claims = {}
    _, claims["red"] = H.node_with_claim(
        conn, case_id, owner, label="crv a", document_id=red_doc,
        rationale="the vendor repeats the wording of the cited post about escrow")
    _, claims["stealer"] = H.node_with_claim(
        conn, case_id, owner, label="crv b", document_id=stealer,
        rationale="the persona appears in the cited log with the same handle")
    _, claims["gone"] = H.node_with_claim(
        conn, case_id, owner, label="crv c", document_id=gone,
        rationale="the cited post named the same courier twice in one week")
    _, claims["boxed"] = H.node_with_claim(
        conn, case_id, owner, label="crv d", document_id=red_doc, keys=[K1],
        rationale="the compartmented persona quotes the cited post on couriers")
    _, claims["plain"] = H.node_with_claim(
        conn, case_id, owner, label="crv e",
        rationale="the vendor ships from the same warehouse every week")
    conn.execute("UPDATE collect.document SET purged_at = now(), body_text = '' "
                 "WHERE id = %s", (gone,))
    for role in ("WORDING", "MEANING"):
        svc.run_pass(role, limit=0, max_seconds=0)
    amber = H.user(conn, PREFIX, clearance="AMBER", roles=("ANALYST",), keys=(K1,))
    red = H.user(conn, PREFIX, clearance="RED", roles=("ANALYST",), keys=(K1,))
    nodoc = H.user(conn, PREFIX, clearance="RED", roles=(), keys=(K1,))
    for reader in (amber, red, nodoc):
        H.assign(conn, case_id, reader, "ANALYST", owner)
    return {"case": case_id, "claims": claims, "amber": amber, "red": red,
            "nodoc": nodoc, "client": H.app_client(), "svc": svc}


def _stored(conn, claim, role):
    return conn.execute(
        "SELECT x.status, x.reason FROM core.assertion_embedding x "
        "JOIN core.embedding_space s ON s.slot = x.slot AND s.state = 'ACTIVE' "
        "WHERE x.assertion_id = %s AND s.role = %s", (claim, role)).fetchone()


def _similar(conn, world, who, claim, space):
    return world["client"].post(
        f"/api/v1/cases/{world['case']}/assertions/{claim}/similar",
        headers=H.auth(conn, world[who]), json={"space": space})


def test_the_stored_rows_are_what_the_gate_decided(conn, world):
    c = world["claims"]
    assert _stored(conn, c["red"], "MEANING") == ("WITHHELD", "above_platform_floor")
    assert _stored(conn, c["gone"], "MEANING") == ("WITHHELD", "material_unavailable")
    assert _stored(conn, c["stealer"], "WORDING") == ("EXCLUDED", "victim_data_category")
    # The floor is judged before compartments: the RED citation decides.
    assert _stored(conn, c["boxed"], "MEANING") == ("WITHHELD", "above_platform_floor")
    assert _stored(conn, c["plain"], "MEANING")[0] == "EMBEDDED"


def test_a_reader_below_the_cited_material_is_told_only_that_it_cannot_be_compared(
        conn, world):
    r = _similar(conn, world, "amber", world["claims"]["red"], "meaning")
    assert r.status_code == 409
    assert r.json()["detail"] == ("Not in the similar meaning index: it cannot be "
                                  "compared.")
    # Who reads the cited document is told why.
    r = _similar(conn, world, "red", world["claims"]["red"], "meaning")
    assert r.status_code == 409 and "TLP:AMBER_STRICT or TLP:RED" in r.json()["detail"]


def test_purged_material_is_not_named_to_anyone(conn, world):
    for who in ("amber", "red", "nodoc"):
        detail = _similar(conn, world, who, world["claims"]["gone"],
                          "meaning").json()["detail"]
        assert not any(t in detail for t in TELLS), (who, detail)


def test_victim_data_is_named_only_to_a_reader_of_the_cited_document(conn, world):
    claim = world["claims"]["stealer"]
    detail = _similar(conn, world, "nodoc", claim, "wording").json()["detail"]
    assert detail == "Not in the similar wording index: it cannot be compared."
    detail = _similar(conn, world, "amber", claim, "wording").json()["detail"]
    assert "victim data" in detail


def test_a_reason_the_readers_own_facts_give_is_still_given(conn, world):
    """The compartmented claim is stored above_platform_floor, for the RED
    post it cites; its own node is in K1, which the reader holds and sees,
    and that alone withholds it."""
    detail = _similar(conn, world, "amber", world["claims"]["boxed"],
                      "meaning").json()["detail"]
    assert detail == ("Not in the similar meaning index: it is in a compartment, and "
                      "compartments never go to a model endpoint.")


def _coverage(conn, world, who, mode):
    r = world["client"].post(
        f"/api/v1/cases/{world['case']}/search/assertions/similar",
        headers=H.auth(conn, world[who]),
        json={"q": "the vendor ships from the same warehouse every week", "mode": mode})
    assert r.status_code == 200, r.text
    return r.json()["coverage"]


def test_the_claims_coverage_counts_as_the_reader_may_be_told(conn, world):
    amber = _coverage(conn, world, "amber", "meaning")
    assert "above_platform_floor" not in amber["withheld_reasons"]
    assert "material_unavailable" not in amber["withheld_reasons"]
    assert amber["withheld_reasons"] == {"compartmented_material": 1}
    assert amber["not_compared"] == 2            # the RED citation and the purged one
    assert amber["excluded"] == 1                # it reads the stealer log's labels
    red = _coverage(conn, world, "red", "meaning")
    assert red["withheld_reasons"] == {"above_platform_floor": 2}
    assert red["not_compared"] == 1              # the purged citation
    nodoc = _coverage(conn, world, "nodoc", "wording")
    assert nodoc["excluded"] == 0 and nodoc["not_compared"] == 1
    for figures in (amber, red, nodoc):
        assert figures["readable"] == sum(
            figures[k] for k in ("embedded", "pending", "excluded", "empty", "failed",
                                 "withheld", "not_compared"))


def test_the_view_is_keyed_by_reader_in_the_cache(conn, world):
    """A cached figure for one reader never answers another at the same
    labels with different access to the cited material."""
    first = _coverage(conn, world, "nodoc", "wording")
    second = _coverage(conn, world, "red", "wording")
    assert first["excluded"] == 0 and second["excluded"] == 1

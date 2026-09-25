"""A lookup's answer (F15.3, 2026-09-24): kept as case
material byte for byte, never labelled below the question, withheld from a
reader who does not dominate it, served from the cache only at or above
the subject's label, and turned into proposals that cite it, never into
graph.

The fetcher and the routes are fakes; nothing reaches a provider. **The
email prefix is `lkres-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from outbound_support import (
    DATABASE_URL,
    MISP_GREEN_BODY,
    FakeFetcher,
    fetched,
    lookup_world,
    make_selector,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "lkres-"
FIXTURES = Path(__file__).parent / "fixtures" / "lookups"
DOMAIN = {"kind": "VALUE", "selector_type": "DOMAIN", "value": "example.org"}


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


class MemoryEvidence:
    """What EvidenceService asks of its storage, in memory."""

    bucket = "test-evidence"

    def __init__(self):
        self.objects = {}

    def put(self, key, data, *, media_type, retain_until):
        self.objects[key] = data

    def get(self, key):
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


def _world(conn, body=MISP_GREEN_BODY, **kw):
    kw.setdefault("ceiling", "AMBER")
    kw.setdefault("level", "NONE")
    kw.setdefault("adapter", "misp_rest")
    return lookup_world(conn, PREFIX, fetcher=FakeFetcher(fetched(200, body)), **kw)


def _ask(w, conn, subject=None, **kw):
    return w.service(conn).request(
        w.case_id, subject or DOMAIN, provider_id=w.provider.id, operation="attribute_search",
        user_id=w.analyst, confirm_exposure="NONE", **kw)


def test_the_answer_is_kept_byte_for_byte_with_its_hash(conn):
    w = _world(conn)
    got = _ask(w, conn)
    body, digest, outcome = conn.execute(
        "SELECT raw_body, raw_sha256, outcome FROM ingest.lookup_result WHERE id = %s",
        (got["result_id"],)).fetchone()
    assert bytes(body) == MISP_GREEN_BODY and bytes(digest) == hashlib.sha256(
        MISP_GREEN_BODY).digest()
    assert outcome == "FOUND"


def test_an_answer_marked_red_is_labelled_red_and_withheld_from_an_amber_reader(conn):
    w = _world(conn, (FIXTURES / "misp_restsearch_tlp.json").read_bytes())
    got = _ask(w, conn)
    assert conn.execute("SELECT classification FROM ingest.lookup_result WHERE id = %s",
                        (got["result_id"],)).fetchone()[0] == "RED"
    svc = w.service(conn)
    seen = svc.get(w.case_id, got["lookup_id"], user_id=w.analyst)
    assert seen["withheld"] and seen["outcome"] is None and seen["result_id"] is None
    assert seen["findings_total"] is None and seen["http_status"] is None
    from noctornal_api import lookups
    with pytest.raises(lookups.NotVisible):
        svc.result(w.case_id, got["result_id"], user_id=w.analyst)


def test_the_database_never_lets_an_answer_sit_below_its_question(conn):
    import psycopg
    w = _world(conn)
    got = _ask(w, conn, dict(DOMAIN, classification="AMBER"))
    assert conn.execute("SELECT classification FROM ingest.lookup_result WHERE id = %s",
                        (got["result_id"],)).fetchone()[0] == "AMBER"
    second = _ask(w, conn, dict(DOMAIN, value="example.net"))
    with pytest.raises(psycopg.errors.RaiseException, match="answer is recorded once"), \
            conn.transaction():
        conn.execute("UPDATE ingest.lookup SET result_id = %s WHERE id = %s",
                     (got["result_id"], second["lookup_id"]))


def test_findings_become_proposals_citing_the_answer_and_never_graph(conn):
    w = _world(conn, (FIXTURES / "virustotal_domain_200.json").read_bytes(),
               adapter="virustotal_v3", level="VENDOR", ceiling=None)
    nodes_before = conn.execute("SELECT count(*) FROM core.node WHERE case_id = %s",
                                (w.case_id,)).fetchone()[0]
    lookup_id = w.service(conn).request(
        w.case_id, DOMAIN, provider_id=w.provider.id, operation="domain_report",
        user_id=w.analyst, confirm_exposure="VENDOR", authorised_by=w.owner,
        authorisation_note="needed")["lookup_id"]
    got = w.service(conn).sign_off(w.case_id, lookup_id, user_id=w.owner, approve=True)
    assert got["proposals_raised"] >= 1
    rows = conn.execute("SELECT kind, origin, lookup_result_id FROM collect.proposal "
                        "WHERE case_id = %s", (w.case_id,)).fetchall()
    assert rows and all(r[2] == got["result_id"] for r in rows)
    assert all(r[1] == f"lookup/{w.provider.key}/virustotal_v3@1" for r in rows)
    assert conn.execute("SELECT count(*) FROM core.node WHERE case_id = %s",
                        (w.case_id,)).fetchone()[0] == nodes_before
    total, proposed = conn.execute("SELECT findings_total, findings_proposed FROM "
                                   "ingest.lookup_result WHERE id = %s",
                                   (got["result_id"],)).fetchone()
    assert total >= proposed >= 1


def test_a_value_the_case_already_holds_is_not_proposed_again(conn):
    w = _world(conn, (FIXTURES / "virustotal_domain_200.json").read_bytes(),
               adapter="virustotal_v3", level="VENDOR", ceiling=None)
    make_selector(conn, w.case_id, "IPV4", "93.184.216.34")
    lookup_id = w.service(conn).request(
        w.case_id, DOMAIN, provider_id=w.provider.id, operation="domain_report",
        user_id=w.analyst, confirm_exposure="VENDOR", authorised_by=w.owner,
        authorisation_note="needed")["lookup_id"]
    w.service(conn).sign_off(w.case_id, lookup_id, user_id=w.owner, approve=True)
    labels = [r[0] for r in conn.execute(
        "SELECT payload->>'label' FROM collect.proposal WHERE case_id = %s AND kind = 'NODE'",
        (w.case_id,)).fetchall()]
    assert "93.184.216.34" not in labels


def test_an_accepted_lookup_proposal_cites_the_provider_and_the_answer(conn):
    from noctornal_api.proposals import ProposalReview
    w = _world(conn)
    got = _ask(w, conn)
    proposal = conn.execute("SELECT id FROM collect.proposal WHERE lookup_result_id = %s "
                            "LIMIT 1", (got["result_id"],)).fetchone()[0]
    ProposalReview(conn).accept(proposal, reviewed_by=w.owner)
    source, result, observed = conn.execute(
        "SELECT source_id, lookup_result_id, observed_at FROM core.assertion "
        "WHERE lookup_result_id = %s", (got["result_id"],)).fetchone()
    fetched_at = conn.execute("SELECT fetched_at FROM ingest.lookup_result WHERE id = %s",
                              (got["result_id"],)).fetchone()[0]
    assert source == w.provider.source_id and result == got["result_id"]
    assert observed == fetched_at


def test_a_fresh_answer_is_served_from_the_cache_and_nothing_is_sent(conn):
    w = _world(conn)
    first = _ask(w, conn)
    second = _ask(w, conn)
    assert second["status"] == 200 and len(w.fetcher.calls) == 1
    state, result = conn.execute("SELECT state, result_id FROM ingest.lookup WHERE id = %s",
                                 (second["lookup_id"],)).fetchone()
    assert (state, result) == ("CACHED", first["result_id"])


def test_an_answer_below_the_subject_label_is_a_miss_not_an_error(conn):
    w = _world(conn)
    _ask(w, conn)
    again = _ask(w, conn, dict(DOMAIN, classification="AMBER"))
    assert again["status"] == 200 and len(w.fetcher.calls) == 2


def test_an_unreadable_answer_is_kept_failed_and_never_cached(conn):
    w = _world(conn, b"<html>not json</html>")
    first = _ask(w, conn)
    assert first["error_class"] == "unreadable"
    fresh, fetched_at, err = conn.execute(
        "SELECT r.fresh_until, r.fetched_at, r.interpret_error FROM ingest.lookup l "
        "JOIN ingest.lookup_result r ON r.id = l.result_id WHERE l.id = %s",
        (first["lookup_id"],)).fetchone()
    assert fresh == fetched_at and err
    _ask(w, conn)
    assert len(w.fetcher.calls) == 2


def test_a_redirect_is_refused_as_a_changed_api(conn):
    w = _world(conn)
    w.fetcher.answers = [fetched(302, b"", location="https://elsewhere.example/")]
    got = _ask(w, conn)
    assert got["error_class"] == "redirected"
    assert conn.execute("SELECT state FROM ingest.lookup WHERE id = %s",
                        (got["lookup_id"],)).fetchone()[0] == "FAILED"


def test_an_answer_is_filed_as_an_exhibit_once(conn):
    from noctornal_api import lookups
    w = _world(conn)
    got = _ask(w, conn)
    storage = MemoryEvidence()
    svc = w.service(conn)
    evidence_id = svc.file_as_exhibit(w.case_id, got["result_id"], user_id=w.analyst,
                                      storage=storage)
    method, cls = conn.execute("SELECT acquisition_method, classification FROM core.evidence "
                               "WHERE id = %s", (evidence_id,)).fetchone()
    assert method == "VENDOR_LOOKUP" and cls == "GREEN"
    assert list(storage.objects.values()) == [MISP_GREEN_BODY]
    with pytest.raises(lookups.LookupRefused, match="already filed"):
        svc.file_as_exhibit(w.case_id, got["result_id"], user_id=w.analyst, storage=storage)


def test_the_answer_is_readable_over_http_and_no_value_travels_in_a_query_string(
        conn, monkeypatch):
    from outbound_support import client as make_client, session
    from noctornal_api import lookups
    w = _world(conn)

    class Faked(lookups.LookupService):
        def __init__(self, c, **_kw):
            super().__init__(c, fetcher=w.fetcher, route_for=w.route_for)

    monkeypatch.setattr(lookups, "LookupService", Faked)
    client, h = make_client(), session(conn, w.analyst_email)
    r = client.post(f"/api/v1/cases/{w.case_id}/lookups", headers=h, json={
        "provider_id": str(w.provider.id), "operation": "attribute_search",
        "subject": DOMAIN, "confirm_exposure": "NONE"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lookup"]["state"] == "ANSWERED" and body["result"]["outcome"] == "FOUND"
    assert body["proposals_raised"] >= 1
    listed = client.get(f"/api/v1/cases/{w.case_id}/lookups", headers=h).json()["lookups"]
    assert [x["id"] for x in listed] == [body["lookup"]["id"]]
    assert "example.org" not in w.fetcher.calls[0]["url"].split("?", 1)[-1] or \
        "?" not in w.fetcher.calls[0]["url"]


def test_a_withheld_answer_does_not_say_whether_it_could_be_read(conn):
    """An unreadable MISP answer is labelled RED (it may have carried a
    marking nobody could read). An AMBER reader is told there is an answer
    above their clearance, and nothing that says it failed to parse: no
    error class, no FAILED, no 502 (2026-09-25)."""
    import json

    from noctornal_api.http.routers import lookups as router
    w = _world(conn, b"<html>not json</html>")
    first = _ask(w, conn)
    svc = w.service(conn)
    seen = svc.get(w.case_id, first["lookup_id"], user_id=w.analyst)
    assert seen["withheld"] and seen["error_class"] is None
    assert seen["state"] == "FINISHED" and seen["error_detail"] is None
    answer = router._answer(svc, w.case_id, w.analyst, first)
    assert answer.status_code == 200
    body = json.loads(answer.body)
    assert body["result"] == {"withheld": True} and "unreadable" not in answer.body.decode()
    # The administrator, cleared for RED, still reads what happened.
    raw = conn.execute("SELECT state, error_class FROM ingest.lookup WHERE id = %s",
                       (first["lookup_id"],)).fetchone()
    assert raw == ("FAILED", "unreadable")

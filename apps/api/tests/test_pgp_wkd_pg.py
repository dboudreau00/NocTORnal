"""Web Key Directory lookups against Postgres and over HTTP (F10c,
2026-09-24): one person asks, a DIFFERENT person approves and sends
(docs/00 decision 75), the record and the SENT audit are committed before
anything leaves, the key is filed before the lookup says FOUND, and the
schema holds every rule
for a writer that skips the service. A fake route and a fake fetcher: no
test here opens a socket.

Rows are deleted at teardown (pgp_support.teardown).
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set; gated")

from pgp_support import (  # noqa: E402
    SUB_PRIMARY,
    assign,
    auth,
    case,
    fix_bytes,
    session,
    teardown,
    tox_binding,
    user,
)

LIKE = "pgpw-%@noctornal.test"
DOMAIN = "mail.fixture-vendor.net"
ADDRESS = f"vendor@{DOMAIN}"
REASON = "the vendor's key, to check the signed contact block"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, LIKE)
    c.execute("DELETE FROM iam.compartment WHERE key LIKE 'PGPW-%%'")
    c.close()


class _Fetched:
    def __init__(self, status, body=b""):
        self.status, self.body = status, body


@pytest.fixture
def wkd(monkeypatch):
    """Lookups on at GREEN, through a fake wkd route listing both methods
    for DOMAIN; `calls` records what the route was asked for."""
    from noctornal_api import pgp_keys
    from noctornal_api.egress_policy import EgressRoute, RoutePolicy, parse_rule
    calls = []
    monkeypatch.setenv(pgp_keys.WKD_CEILING_ENV, "GREEN")
    rules = (parse_rule(f"openpgpkey.{DOMAIN}:443"), parse_rule(f"{DOMAIN}:443"))

    def fake(conn, declared=()):
        calls.append(tuple(declared))
        policy = RoutePolicy("integration", rules, narrow=tuple(declared),
                             any_public=False, admission="local")
        return EgressRoute.direct("integration", "wkd", policy)

    monkeypatch.setattr(pgp_keys, "_wkd_route", fake)
    return calls


def _svc(conn):
    from noctornal_api.pgp_keys import PgpLookupService
    return PgpLookupService(conn)


def _people(conn, *, classification="GREEN", compartments=()):
    lead = user(conn, "pgpw")
    reviewer = user(conn, "pgpw")
    if compartments:
        for key in compartments:
            conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                         "ON CONFLICT (key) DO NOTHING", (key, key))
        conn.execute("UPDATE iam.app_user SET compartments = %s WHERE id = %s",
                     (list(compartments), lead))
    case_id = case(conn, lead, classification=classification,
                   compartments=compartments)
    assign(conn, case_id, lead, "CASE_OWNER")
    assign(conn, case_id, reviewer, "REVIEWER")
    return lead, reviewer, case_id


def _request(conn, case_id, who, *, clearance="RED", classification="GREEN",
             address=ADDRESS, **kw):
    return _svc(conn).request_lookup(
        case_id=case_id, address=address, reason=REASON,
        classification=classification, channel_binding_id=kw.get("binding"),
        contact_block_id=kw.get("block"), requested_by=who, clearance=clearance,
        held=frozenset(), writable=lambda cls, comps: None)


def _approve(conn, case_id, lookup_id, who, fetcher, clearance="RED"):
    return _svc(conn).approve_and_send(case_id=case_id, lookup_id=lookup_id,
                                       approver=who, clearance=clearance,
                                       held=frozenset(), fetcher=fetcher)


def _never(url, *, route):
    raise AssertionError("the fetcher was called")


def test_a_request_writes_requested_and_sends_nothing(conn, wkd):
    lead, _reviewer, case_id = _people(conn)
    reply = _request(conn, case_id, lead)
    lookup = reply["lookup"]
    assert lookup["state"] == "REQUESTED" and lookup["planned_urls"] == []
    assert "Nothing has been sent" in reply["notice"]
    assert "UTC" in reply["notice"]
    # The allowlist was read (nothing declared); no route was asked for
    # a send, which always declares the directory's two names.
    assert wkd and all(declared == () for declared in wkd)
    detail = conn.execute(
        "SELECT detail FROM audit.event WHERE action = 'PGP_KEY_LOOKUP_REQUESTED' "
        "AND object_id = %s", (lookup["id"],)).fetchone()[0]
    assert detail["domain"] == DOMAIN and "address" not in detail


def test_the_person_who_asked_cannot_approve(conn, wkd):
    from noctornal_api.pgp import PgpConflict
    lead, _reviewer, case_id = _people(conn)
    lookup_id = _request(conn, case_id, lead)["lookup"]["id"]
    with pytest.raises(PgpConflict, match="second person"):
        _approve(conn, case_id, lookup_id, lead, _never)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """UPDATE comms.pgp_key_lookup
                  SET state = 'SENDING', decided_by = requested_by,
                      decided_at = now(), sent_at = now(),
                      planned_urls = ARRAY['https://' || domain
                        || '/.well-known/openpgpkey/hu/' || wkd_hash]
                WHERE id = %s""", (lookup_id,))


def test_a_second_person_approves_and_the_record_leaves_first(conn, wkd):
    from noctornal_api.db import connect
    lead, reviewer, case_id = _people(conn)
    lookup_id = _request(conn, case_id, lead)["lookup"]["id"]
    seen = {}

    def fetcher(url, *, route):
        # Read through ANOTHER connection: a committed row, not our own
        # uncommitted one.
        with connect() as other:
            row = other.execute(
                "SELECT state, planned_urls FROM comms.pgp_key_lookup WHERE id = %s",
                (lookup_id,)).fetchone()
            sent = other.execute(
                "SELECT detail FROM audit.event WHERE action = "
                "'PGP_KEY_LOOKUP_SENT' AND object_id = %s", (lookup_id,)).fetchone()
        seen.update(state=row[0], planned=row[1], sent=sent[0], url=url,
                    context=route.context)
        return _Fetched(200, fix_bytes("wkd_vendor.bin"))

    out = _approve(conn, case_id, lookup_id, reviewer, fetcher)
    assert seen["state"] == "SENDING"
    assert len(seen["planned"]) == 2 and seen["sent"]["urls"] == seen["planned"]
    assert seen["url"] == seen["planned"][0]
    assert seen["context"] == f"wkd:{lookup_id}"
    assert out["state"] == "FOUND" and out["method_used"] == "ADVANCED"
    (key,) = out["keys"]
    assert key["fingerprint"] == SUB_PRIMARY
    assert key["acquisition"]["source"] == "WKD"
    assert key["acquisition"]["lookup_id"] == lookup_id
    assert key["acquisition"]["names_looked_up_address"] is True
    assert key["classification"] == "GREEN" and key["compartments"] == []
    assert key["confirmation"] is None
    assert wkd[-1] and {r.host for r in wkd[-1]} == {f"openpgpkey.{DOMAIN}", DOMAIN}


def _expired(conn, case_id, requester):
    now = datetime.now(UTC)
    return conn.execute(
        """INSERT INTO comms.pgp_key_lookup
               (case_id, address, local_part, domain, wkd_hash, reason,
                classification, ceiling, route_name, requested_by,
                requested_at, expires_at)
           VALUES (%s, %s, 'vendor', %s, %s, %s, 'GREEN', 'GREEN', 'wkd', %s,
                   %s, %s) RETURNING id""",
        (case_id, ADDRESS, DOMAIN, "y" * 32, REASON, requester,
         now - timedelta(hours=25), now - timedelta(hours=1))).fetchone()[0]


def test_an_expired_request_lapses(conn, wkd):
    from noctornal_api.pgp import PgpConflict
    lead, reviewer, case_id = _people(conn)
    lookup_id = _expired(conn, case_id, lead)
    listed = _svc(conn).lookups(case_id, viewer=reviewer, clearance="RED",
                                held=frozenset())
    assert listed[0]["effective_state"] == "EXPIRED"
    assert listed[0]["can_approve"] is False
    with pytest.raises(PgpConflict, match="lapsed"):
        _approve(conn, case_id, lookup_id, reviewer, _never)
    assert conn.execute("SELECT state FROM comms.pgp_key_lookup WHERE id = %s",
                        (lookup_id,)).fetchone()[0] == "EXPIRED"
    fresh = _expired(conn, case_id, lead)
    with pytest.raises(psycopg.errors.RaiseException, match="lapsed"):
        conn.execute(
            """UPDATE comms.pgp_key_lookup
                  SET state = 'SENDING', decided_by = %s, decided_at = now(),
                      sent_at = now(),
                      planned_urls = ARRAY['https://' || domain
                        || '/.well-known/openpgpkey/hu/' || wkd_hash]
                WHERE id = %s""", (reviewer, fresh))


def test_decline_by_an_approver_and_by_the_lead_who_asked(conn, wkd):
    lead, reviewer, case_id = _people(conn)
    one = _request(conn, case_id, lead)["lookup"]["id"]
    two = _request(conn, case_id, lead)["lookup"]["id"]
    out = _svc(conn).decline(case_id=case_id, lookup_id=one, decided_by=reviewer,
                             reason="not needed", clearance="RED", held=frozenset())
    assert out["state"] == "DECLINED"
    out = _svc(conn).decline(case_id=case_id, lookup_id=two, decided_by=lead,
                             reason="withdrawn by me", clearance="RED",
                             held=frozenset())
    assert out["state"] == "DECLINED"


def test_decline_is_gated_by_labels(conn, wkd, monkeypatch):
    """A GREEN approver declining an AMBER request
    they cannot see was a write through labels, and its 409 an oracle."""
    from noctornal_api.pgp import PgpNotFound
    lead, reviewer, case_id = _people(conn, classification="GREEN")
    monkeypatch.setenv("NOCTORNAL_WKD_CEILING", "AMBER")
    lookup_id = _request(conn, case_id, lead, classification="AMBER")["lookup"]["id"]
    for target in (lookup_id, uuid4()):
        with pytest.raises(PgpNotFound, match="no such key lookup"):
            _svc(conn).decline(case_id=case_id, lookup_id=target,
                               decided_by=reviewer, reason="nope",
                               clearance="GREEN", held=frozenset())


@pytest.mark.parametrize("case_kw,request_kw,match", [
    ({}, {"address": "vendor@elsewhere.net"}, "not on the Web Key Directory"),
    ({"classification": "RED"}, {}, "never leaves"),
    ({"classification": "AMBER"}, {}, "above what the key_directory"),
], ids=["not-on-route", "red-case", "above-ceiling"])
def test_refusals_come_before_any_row(conn, wkd, case_kw, request_kw, match):
    from noctornal_api.pgp import PgpConflict
    lead, _reviewer, case_id = _people(conn, **case_kw)
    with pytest.raises(PgpConflict, match=match):
        _request(conn, case_id, lead, **request_kw)
    assert conn.execute("SELECT count(*) FROM comms.pgp_key_lookup WHERE "
                        "case_id = %s", (case_id,)).fetchone()[0] == 0
    refused = conn.execute(
        "SELECT outcome, detail FROM audit.event WHERE action = "
        "'PGP_KEY_LOOKUP_REFUSED' AND case_id = %s", (case_id,)).fetchone()
    assert refused[0] == "DENIED" and ADDRESS not in str(refused[1])


def test_lookups_off_or_no_route_refuse_before_any_row(conn, monkeypatch):
    from noctornal_api import pgp_keys
    from noctornal_api.egress import RouteUnavailable
    from noctornal_api.pgp import PgpConflict
    lead, _reviewer, case_id = _people(conn)
    monkeypatch.delenv(pgp_keys.WKD_CEILING_ENV, raising=False)
    with pytest.raises(PgpConflict, match="switched off"):
        _request(conn, case_id, lead)
    monkeypatch.setenv(pgp_keys.WKD_CEILING_ENV, "GREEN")

    def no_route(conn, declared=()):
        raise RouteUnavailable("nothing named", code="route_unknown")
    monkeypatch.setattr(pgp_keys, "_wkd_route", no_route)
    with pytest.raises(PgpConflict, match="no Web Key Directory route"):
        _request(conn, case_id, lead)


def test_a_compartmented_case_is_never_looked_up(conn, wkd):
    from noctornal_api.pgp import PgpConflict
    key = f"PGPW-{uuid4().hex[:6].upper()}"
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'wkd test')",
                 (key,))
    lead, _reviewer, case_id = _people(conn, compartments=(key,))
    with pytest.raises(PgpConflict, match="Compartmented material"):
        _request(conn, case_id, lead)
    status = _svc(conn).directory_status(case_id)
    assert status["enabled"] and "never looked up" in status["case_problem"]


def test_a_hidden_cited_binding_is_404(conn, wkd):
    from noctornal_api.pgp import PgpNotFound
    lead, _reviewer, case_id = _people(conn)
    red = tox_binding(conn, case_id, lead, classification="RED")
    with pytest.raises(PgpNotFound):
        _request(conn, case_id, lead, clearance="AMBER", binding=red)


def test_labels_changed_between_request_and_approval(conn, wkd):
    from noctornal_api.pgp import PgpConflict
    lead, reviewer, case_id = _people(conn)
    lookup_id = _request(conn, case_id, lead)["lookup"]["id"]
    conn.execute('UPDATE core."case" SET classification = \'RED\' WHERE id = %s',
                 (case_id,))
    with pytest.raises(PgpConflict, match="labels changed"):
        _approve(conn, case_id, lookup_id, reviewer, _never)
    with pytest.raises(psycopg.errors.RaiseException, match="labels changed"):
        conn.execute(
            """UPDATE comms.pgp_key_lookup
                  SET state = 'SENDING', decided_by = %s, decided_at = now(),
                      sent_at = now(),
                      planned_urls = ARRAY['https://' || domain
                        || '/.well-known/openpgpkey/hu/' || wkd_hash]
                WHERE id = %s""", (reviewer, lookup_id))


@pytest.mark.parametrize("answer,state,detail", [
    (lambda url, *, route: _Fetched(404), "NOT_FOUND", "no key"),
    ("collection", "FAILED", "The lookup failed"),
    (lambda url, *, route: _Fetched(200, fix_bytes("detached_binary.sig")),
     "FAILED", "not a usable public key"),
    (lambda url, *, route: _Fetched(
        200, b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxcA=\n"
             b"-----END PGP PRIVATE KEY BLOCK-----\n"), "FAILED", "SECRET key"),
], ids=["404", "collection-error", "a-signature", "secret-material"])
def test_what_came_back(conn, wkd, answer, state, detail):
    from noctornal_api.pinned_http import CollectionError
    if answer == "collection":
        def answer(url, *, route):
            raise CollectionError("connection reset by 10.0.0.9")
    lead, reviewer, case_id = _people(conn)
    lookup_id = _request(conn, case_id, lead)["lookup"]["id"]
    out = _approve(conn, case_id, lookup_id, reviewer, answer)
    assert out["state"] == state and detail in out["detail"]
    assert "10.0.0.9" not in out["detail"]
    assert conn.execute("SELECT count(*) FROM comms.pgp_key_acquisition WHERE "
                        "lookup_id = %s", (lookup_id,)).fetchone()[0] == 0
    if state == "FAILED" and answer.__name__ == "<lambda>":
        assert out["response_sha256"] and len(out["response_sha256"]) == 64


def test_a_process_that_dies_mid_request_leaves_sending(conn, wkd):
    lead, reviewer, case_id = _people(conn)
    lookup_id = _request(conn, case_id, lead)["lookup"]["id"]

    class Died(BaseException):
        pass

    def dies(url, *, route):
        raise Died

    with pytest.raises(Died):
        _approve(conn, case_id, lookup_id, reviewer, dies)
    (row,) = _svc(conn).lookups(case_id, viewer=lead, clearance="RED",
                                held=frozenset())
    assert row["state"] == "SENDING" and len(row["planned_urls"]) == 2


def test_the_lookup_guard(conn, wkd):
    lead, reviewer, case_id = _people(conn)
    lookup_id = _request(conn, case_id, lead)["lookup"]["id"]
    for sql in ("UPDATE comms.pgp_key_lookup SET reason = 'something else here' "
                "WHERE id = %s",
                "UPDATE comms.pgp_key_lookup SET classification = 'AMBER' "
                "WHERE id = %s",
                "UPDATE comms.pgp_key_lookup SET address = 'x@mail.fixture-vendor.net'"
                " WHERE id = %s"):
        with pytest.raises(psycopg.errors.RaiseException, match="fixed"):
            conn.execute(sql, (lookup_id,))
    with pytest.raises(psycopg.errors.RaiseException, match="never deleted"):
        conn.execute("DELETE FROM comms.pgp_key_lookup WHERE id = %s", (lookup_id,))
    with pytest.raises(psycopg.errors.RaiseException, match="never deleted"):
        conn.execute("TRUNCATE comms.pgp_key_lookup CASCADE")
    _approve(conn, case_id, lookup_id, reviewer, lambda url, *, route: _Fetched(404))
    with pytest.raises(psycopg.errors.RaiseException, match="finished"):
        conn.execute("UPDATE comms.pgp_key_lookup SET state = 'FAILED', "
                     "http_status = NULL WHERE id = %s", (lookup_id,))


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient

    from noctornal_api import pgp_keys
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    monkeypatch.setattr(pgp_keys, "_default_fetcher",
                        lambda url, *, route: _Fetched(404))
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _url(case_id, tail=""):
    return f"/api/v1/cases/{case_id}/comms/pgp/key-lookups{tail}"


def test_over_http_two_people_and_can_approve(conn, wkd, client):
    lead, reviewer, case_id = _people(conn)
    lt, rt = session(conn, lead), session(conn, reviewer)
    r = client.post(_url(case_id), headers=auth(lt),
                    json={"address": ADDRESS, "reason": REASON})
    assert r.status_code == 201, r.text
    lookup_id = r.json()["lookup"]["id"]
    mine = client.get(_url(case_id), headers=auth(lt)).json()["lookups"][0]
    theirs = client.get(_url(case_id), headers=auth(rt)).json()["lookups"][0]
    assert mine["can_approve"] is False and mine["can_decline"] is True
    assert theirs["can_approve"] is True
    assert client.post(_url(case_id, f"/{lookup_id}/approve"),
                       headers=auth(lt)).status_code == 409
    r = client.post(_url(case_id, f"/{lookup_id}/approve"), headers=auth(rt))
    assert r.status_code == 200 and r.json()["state"] == "NOT_FOUND"
    status = client.get(f"/api/v1/cases/{case_id}/comms/pgp/key-directory",
                        headers=auth(lt)).json()
    assert status["enabled"] and status["directories"][0]["domain"] == DOMAIN


def test_over_http_a_collector_asks_and_cannot_decline(conn, wkd, client):
    lead, _reviewer, case_id = _people(conn)
    collector = user(conn, "pgpw")
    assign(conn, case_id, collector, "COLLECTOR")
    ct = session(conn, collector)
    r = client.post(_url(case_id), headers=auth(ct),
                    json={"address": ADDRESS, "reason": REASON})
    assert r.status_code == 201
    r = client.post(_url(case_id, f"/{r.json()['lookup']['id']}/decline"),
                    headers=auth(ct), json={"reason": "never mind"})
    assert r.status_code == 403


def test_over_http_step_up_is_required(conn, wkd, client):
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    lead, reviewer, case_id = _people(conn)
    _sid, stale = SessionService(PgSessionStore(conn)).create(
        uuid4(), lead, mfa_satisfied=False)
    r = client.post(_url(case_id), headers=auth(stale),
                    json={"address": ADDRESS, "reason": REASON})
    assert r.status_code == 403 and "re-authentication" in r.json()["detail"]
    lookup_id = _request(conn, case_id, lead)["lookup"]["id"]
    _sid, stale_r = SessionService(PgSessionStore(conn)).create(
        uuid4(), reviewer, mfa_satisfied=False)
    r = client.post(_url(case_id, f"/{lookup_id}/approve"), headers=auth(stale_r))
    assert r.status_code == 403
    # Decline is the third step-up route, and the refusal is in the words
    # the console's withStepUp answers with an identity prompt (F10c,
    # 2026-09-24). A fresh sign-in of the same approver then declines.
    r = client.post(_url(case_id, f"/{lookup_id}/decline"), headers=auth(stale_r),
                    json={"reason": "not wanted now"})
    assert r.status_code == 403 and "re-authentication" in r.json()["detail"]
    r = client.post(_url(case_id, f"/{lookup_id}/decline"),
                    headers=auth(session(conn, reviewer)),
                    json={"reason": "not wanted now"})
    assert r.status_code == 200 and r.json()["state"] == "DECLINED", r.text


def test_over_http_a_closed_case_refuses_all_three(conn, wkd, client):
    lead, reviewer, case_id = _people(conn)
    lookup_id = _request(conn, case_id, lead)["lookup"]["id"]
    conn.execute('UPDATE core."case" SET status = \'CLOSED\' WHERE id = %s',
                 (case_id,))
    lt, rt = session(conn, lead), session(conn, reviewer)
    assert client.post(_url(case_id), headers=auth(lt),
                       json={"address": ADDRESS, "reason": REASON}).status_code == 409
    assert client.post(_url(case_id, f"/{lookup_id}/approve"),
                       headers=auth(rt)).status_code == 409
    assert client.post(_url(case_id, f"/{lookup_id}/decline"), headers=auth(rt),
                       json={"reason": "closed"}).status_code == 409


def test_over_http_the_lookup_meter_applies(conn, wkd, client):
    lead, _reviewer, case_id = _people(conn)
    lt = session(conn, lead)
    codes = [client.post(_url(case_id), headers=auth(lt),
                         json={"address": "vendor@not.listed.net",
                               "reason": REASON}).status_code
             for _ in range(30)]
    assert 429 in codes and set(codes) <= {409, 429}

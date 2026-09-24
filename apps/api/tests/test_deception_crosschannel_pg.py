"""The Deception pane's cross-channel pivot, proposals and record forms,
against a real database (review of 2026-09-22, closed 2026-09-23).

- ux14-deception:ecrime-no-cross-channel-pivot: the address one actor
  used for the phishing page, the BEC mail and the vishing call is named
  on all three records, over what the READER may see, and a record can
  propose INFRA and LURE entities into Triage, derived and never twice,
  naming an existing entity only to a reader who may see it; case search
  finds the records by host, address or URL;
- ux14-deception:web-durable-ids-missing: the capture carries its
  certificate issue date and each hop's ASN, and is read against the
  case's first lure, dated by the recipient relay and never by the
  sender's Date header;
- ux14-deception:calls-vouched-and-tooltip-only: the call's candidates are
  merged by selector;
- ux14-deception:no-deception-ingest-ui: what the console's forms send is
  accepted, and what the table would refuse is a sentence, not a 500, and
  never after an exhibit was already written.

Email prefix `dcx-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timezone
from uuid import uuid4

import pytest

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

API = "/api/v1"
EMAIL_LIKE = "dcx-%@noctornal.test"
SHARED = "203.0.113.44"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    # The same pins as `test_deception_pg.py`: custody rows stay, and so
    # does what they point at.
    pinned_evidence = "(SELECT evidence_id FROM core.evidence_custody)"
    pinned_cases = "(SELECT case_id FROM core.evidence WHERE case_id IS NOT NULL)"
    pinned_users = (
        "(SELECT actor_id FROM core.evidence_custody WHERE actor_id IS NOT NULL"
        " UNION SELECT acquired_by FROM core.evidence WHERE acquired_by IS NOT NULL"
        ' UNION SELECT owner_user_id FROM core."case" WHERE owner_user_id IS NOT NULL'
        ' UNION SELECT deputy_user_id FROM core."case" WHERE deputy_user_id IS NOT NULL)'
    )
    with c.transaction():
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM deception.capture_hop WHERE capture_id IN "
                  f"(SELECT id FROM deception.capture WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM deception.capture WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM deception.email_hop WHERE message_id IN "
                  f"(SELECT id FROM deception.email_message WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM deception.email_attachment WHERE message_id IN "
                  f"(SELECT id FROM deception.email_message WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM deception.email_message WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM deception.call_record WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN "
                  f"(SELECT id FROM core.evidence WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub} "
                  f"AND id NOT IN {pinned_evidence}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub} '
                  f"AND id NOT IN {pinned_cases}")
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE id IN {sub} "
                  f"AND id NOT IN {pinned_users}")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, clearance="RED", roles=("CASE_OWNER",)):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"dcx-{uuid4().hex[:8]}@noctornal.test", "Dcx", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid


def _token(conn, uid) -> str:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner, classification="AMBER"):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-DCX-{uuid4().hex[:6]}", title="Cross-channel",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification=classification)


#: A chain whose boundary is CONFIRMED above hop 0: the recipient's MX
#: received from its own edge relay, which received from the actor's VPS.
EML = (
    b"Received: from edge.corp.example ([10.4.0.9]) by mail.corp.example;"
    b" Fri, 17 Jul 2026 08:14:05 +0000\r\n"
    b"Received: from vps-1.hostmarket.example ([" + SHARED.encode() + b"]) by"
    b" edge.corp.example; Fri, 17 Jul 2026 08:14:02 +0000\r\n"
    b"Received: from mail.claimed.example ([198.51.100.20]) by"
    b" vps-1.hostmarket.example; Fri, 17 Jul 2026 08:14:00 +0000\r\n"
    b"Message-ID: <MSGID@vps-1.hostmarket.example>\r\n"
    b"Date: Fri, 17 Jul 2026 08:14:00 +0000\r\n"
    b"From: \"CFO\" <cfo@corp-holdings.example>\r\n"
    b"Subject: Updated remittance details\r\n\r\n"
    b"Pay here: https://portal.secure-billing.example/verify?ref=1\r\n")


def _seed(conn, owner, case_id, *, call_classification="AMBER", eml=EML):
    """One capture, one message and one call sharing the actor's address."""
    from noctornal_api.deception import DeceptionService, parse_eml
    from noctornal_api.evidence import EvidenceService, EvidenceStorage
    svc = DeceptionService(conn)
    capture = svc.record_capture(
        case_id=case_id, requested_url="https://lure.example/r/1",
        capture_method="VICTIM_SUPPLIED", captured_by=owner,
        final_url="https://portal.secure-billing.example/verify",
        hops=[{"url": "https://lure.example/r/1", "resolved_ip": "203.0.113.90",
               "asn": 64496, "hop_kind": "REQUESTED"},
              {"url": "https://portal.secure-billing.example/verify",
               "resolved_ip": SHARED, "asn": 64496, "server_header": "nginx",
               "hop_kind": "HTTP_30X"}],
        tls={"not_before": date(2026, 7, 12)}, page_title="Supplier portal")
    raw = eml.replace(b"MSGID", uuid4().hex.encode())
    exhibit = EvidenceService(conn, EvidenceStorage()).ingest(
        case_id=case_id, title="bec.eml", media_type="message/rfc822",
        data=raw, acquired_by=owner, acquisition_method="MANUAL_UPLOAD")
    parsed = parse_eml(raw, trusted=("corp.example",))
    boundary = [h for h in parsed.hops if h.is_trusted_boundary]
    assert boundary and boundary[0].seq == 1 and boundary[0].from_ip == SHARED, (
        "the fixture's chain no longer confirms its boundary at hop 1")
    message = svc.record_email(case_id=case_id, evidence_id=exhibit.evidence_id,
                               parsed=parsed, recorded_by=owner)
    call = svc.record_call(
        case_id=case_id, started_at=datetime(2026, 7, 17, 9, 2, tzinfo=timezone.utc),
        direction="INBOUND_TO_VICTIM", record_source="CARRIER_CDR",
        recorded_by=owner, source_ip=SHARED,
        presented_number="+44 20 7946 0018", presented_number_e164="+442079460018",
        p_asserted_identity="sip:44471@trunk-04.hostmarket.example",
        sip_from_uri="sip:44471@trunk-04.hostmarket.example",
        stir_shaken_attestation="C", classification=call_classification)
    return str(capture), str(message), str(call)


def _seen(row, value):
    return next((s for s in row["also_seen"] if s["value"] == value), None)


def test_a_shared_address_is_named_on_all_three_records(conn, client):
    owner = _user(conn)
    case_id = _case(conn, owner)
    capture, message, call = _seed(conn, owner, case_id)
    token = _token(conn, owner)
    base = f"{API}/cases/{case_id}/deception"

    [cap] = client.get(f"{base}/captures", headers=_auth(token)).json()["captures"]
    shared = _seen(cap, SHARED)
    assert shared, "the capture does not say its address is shared"
    assert {(o["channel"], o["id"]) for o in shared["elsewhere"]} == {
        ("email", message), ("call", call)}
    # The host of the body's URL is the capture's final host.
    host = _seen(cap, "portal.secure-billing.example")
    assert host and host["value_defanged"] == "portal[.]secure-billing[.]example"
    assert {o["channel"] for o in host["elsewhere"]} == {"email"}

    [msg] = client.get(f"{base}/emails", headers=_auth(token)).json()["emails"]
    assert {o["channel"] for o in _seen(msg, SHARED)["elsewhere"]} == {
        "capture", "call"}
    [cl] = client.get(f"{base}/calls", headers=_auth(token)).json()["calls"]
    assert {o["channel"] for o in _seen(cl, SHARED)["elsewhere"]} == {
        "capture", "email"}
    # The call's presented number is never offered as an entity.
    assert "+442079460018" not in {p["label"] for p in cl["proposable"]}
    # One row per selector, reasons merged.
    uris = [c for c in cl["selector_candidates"] if c["selector_type"] == "SIP_URI"]
    assert len(uris) == 1 and len(uris[0]["reasons"]) == 2

    # The capture detail reads its certificate against the first lure.
    detail = client.get(f"{base}/captures/{capture}", headers=_auth(token)).json()
    assert detail["tls_not_before"].startswith("2026-07-12")
    assert detail["first_lure"]["channel"] == "email"
    assert detail["first_lure"]["id"] == message
    assert [h["asn"] for h in detail["hops"]] == [64496, 64496]
    assert _seen(detail, SHARED), "the detail does not say what it shares"


def test_an_overlap_with_a_record_above_the_readers_labels_is_not_announced(
        conn, client):
    owner = _user(conn)
    case_id = _case(conn, owner)
    capture, message, call = _seed(conn, owner, case_id, call_classification="RED")
    reader = _user(conn, clearance="AMBER", roles=())
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
                 (case_id, reader, owner))
    token = _token(conn, reader)
    [cap] = client.get(f"{API}/cases/{case_id}/deception/captures",
                       headers=_auth(token)).json()["captures"]
    shared = _seen(cap, SHARED)
    assert shared, "the email the reader can see is not named"
    assert {o["channel"] for o in shared["elsewhere"]} == {"email"}, (
        "a RED call was pointed at for an AMBER reader")


def test_a_record_proposes_what_it_holds_once_and_nothing_it_was_not_shown(
        conn, client):
    owner = _user(conn)
    case_id = _case(conn, owner)
    capture, message, call = _seed(conn, owner, case_id)
    token = _token(conn, owner)
    url = f"{API}/cases/{case_id}/deception/captures/{capture}/propose"

    r = client.post(url, headers=_auth(token), json={"key": f"ip:{SHARED}"})
    assert r.status_code == 201, r.text
    assert r.json()["created"] is True
    payload, origin = conn.execute(
        "SELECT payload, origin FROM collect.proposal WHERE id = %s",
        (r.json()["proposal_id"],)).fetchone()
    assert payload["node_type"] == "INFRA" and payload["label"] == SHARED
    assert payload["attrs"]["selector_type"] == "IPV4"
    assert origin == "deception/capture"

    again = client.post(url, headers=_auth(token), json={"key": f"ip:{SHARED}"})
    assert again.status_code == 201 and again.json()["created"] is False
    # The call offers the same address: already queued, not queued twice.
    from_call = client.post(
        f"{API}/cases/{case_id}/deception/calls/{call}/propose",
        headers=_auth(token), json={"key": f"ip:{SHARED}"})
    assert from_call.json()["created"] is False
    assert conn.execute("SELECT count(*) FROM collect.proposal WHERE case_id = %s",
                        (case_id,)).fetchone()[0] == 1

    bogus = client.post(url, headers=_auth(token), json={"key": "ip:8.8.8.8"})
    assert bogus.status_code == 409, "a key the record does not hold was proposed"
    lure = client.post(url, headers=_auth(token), json={"key": "lure"})
    assert lure.status_code == 201
    assert conn.execute("SELECT payload->>'node_type' FROM collect.proposal "
                        "WHERE id = %s", (lure.json()["proposal_id"],)
                        ).fetchone()[0] == "LURE"
    assert conn.execute("SELECT count(*) FROM core.node WHERE case_id = %s",
                        (case_id,)).fetchone()[0] == 0, "a proposal wrote the graph"


def test_proposing_names_an_entity_only_to_a_reader_who_may_see_it(conn, client):
    """The verifier (2026-09-23): "already an entity" came back with the id
    of ANY node carrying the label, so an AMBER case member proposing the
    address from a capture they could see learnt that a RED entity held it,
    and its id. Only a node the caller may see is named; one above their
    labels is treated as absent and the proposal is queued at the record's
    labels, for a reviewer who may see both."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    capture, _message, _call = _seed(conn, owner, case_id)
    from noctornal_api.graph import AssertionInput, GraphWriteService
    node_id = str(GraphWriteService(conn).create_node(
        case_id=case_id, node_type="INFRA", label=SHARED, created_by=owner,
        classification="RED",
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner,
                                 reliability="B", credibility="2")))
    url = f"{API}/cases/{case_id}/deception/captures/{capture}/propose"

    seen_by_owner = client.post(url, headers=_auth(_token(conn, owner)),
                                json={"key": f"ip:{SHARED}"})
    assert seen_by_owner.status_code == 201, seen_by_owner.text
    assert seen_by_owner.json()["state"] == "IN_GRAPH"
    assert seen_by_owner.json()["node_id"] == node_id

    amber = _user(conn, clearance="AMBER", roles=())
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
                 (case_id, amber, owner))
    r = client.post(url, headers=_auth(_token(conn, amber)),
                    json={"key": f"ip:{SHARED}"})
    assert r.status_code == 201, r.text
    assert node_id not in r.text and r.json()["state"] != "IN_GRAPH", (
        "a RED entity was named to an AMBER reader")
    assert r.json()["created"] is True
    assert conn.execute("SELECT payload->>'classification' FROM collect.proposal "
                        "WHERE id = %s", (r.json()["proposal_id"],)
                        ).fetchone()[0] == "AMBER"


def test_already_proposed_names_only_a_proposal_the_callers_queue_shows(
        conn, client):
    """Final review c20 (2026-09-24): "already proposed" matched a proposal
    from a RED capture that the AMBER member's Triage queue hides. They got
    its id and review state, learnt that RED material carried the host, and
    their own AMBER suggestion was never queued, for good once the RED one
    was rejected. One above the caller is now absent to them, as the queue
    and /source already say, and theirs is queued beside it."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    from noctornal_api.deception import DeceptionService
    svc = DeceptionService(conn)
    host = "evil-panel.example"

    def capture(classification):
        return str(svc.record_capture(
            case_id=case_id, requested_url=f"https://{host}/login",
            capture_method="VICTIM_SUPPLIED", captured_by=owner,
            classification=classification))

    red, amber_capture = capture("RED"), capture("AMBER")
    base = f"{API}/cases/{case_id}/deception/captures"
    first = client.post(f"{base}/{red}/propose", headers=_auth(_token(conn, owner)),
                        json={"key": f"host:{host}"})
    assert first.status_code == 201 and first.json()["created"] is True, first.text
    hidden = first.json()["proposal_id"]
    conn.execute("UPDATE collect.proposal SET state = 'REJECTED' WHERE id = %s",
                 (hidden,))

    amber = _user(conn, clearance="AMBER", roles=())
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
                 (case_id, amber, owner))
    token = _token(conn, amber)
    queue = client.get(f"{API}/cases/{case_id}/proposals?state=REJECTED",
                       headers=_auth(token))
    assert queue.status_code == 200 and queue.json()["proposals"] == [], (
        "the fixture no longer hides the RED proposal from the AMBER queue")
    r = client.post(f"{base}/{amber_capture}/propose", headers=_auth(token),
                    json={"key": f"host:{host}"})
    assert r.status_code == 201, r.text
    assert hidden not in r.text and r.json()["state"] == "PROPOSED", (
        "a proposal above the caller's labels was named to them")
    assert r.json()["created"] is True, "the AMBER suggestion was not queued"
    assert conn.execute("SELECT count(*) FROM collect.proposal WHERE case_id = %s",
                        (case_id,)).fetchone()[0] == 2
    # A proposal the caller's queue does show is still answered as that.
    again = client.post(f"{base}/{amber_capture}/propose", headers=_auth(token),
                        json={"key": f"host:{host}"})
    assert again.json()["created"] is False
    assert again.json()["proposal_id"] == r.json()["proposal_id"]


def test_calls_to_one_victims_pbx_are_not_linked_as_shared_infrastructure(
        conn, client):
    """Final review u17 (2026-09-24): two vishing calls to two employees
    of one company carry the company's PBX in their SIP To URIs, and each
    row said the other shared it, as if it were the actor's. The victim's
    end is no overlap and no proposal; case search still finds the calls
    by it, which is a fair question to ask."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    from noctornal_api.deception import DeceptionService
    svc = DeceptionService(conn)
    pbx = "pbx.northgate.example"

    def call(n, direction="INBOUND_TO_VICTIM", **uris):
        return str(svc.record_call(
            case_id=case_id,
            started_at=datetime(2026, 7, 17, 9, n, tzinfo=timezone.utc),
            direction=direction, record_source="CARRIER_CDR",
            recorded_by=owner, **uris))

    first = call(1, sip_from_uri="sip:1@trunk-a.example",
                 sip_to_uri=f"sip:+442071838751@{pbx}")
    second = call(2, sip_from_uri="sip:2@trunk-b.example",
                  sip_to_uri=f"sip:+442071838752@{pbx}")
    # The victim rang the actor back: now the To end is the actor's, and
    # the From end, the same PBX, is the victim's.
    back = call(3, direction="OUTBOUND_FROM_VICTIM",
                sip_from_uri=f"sip:+442071838753@{pbx}",
                sip_to_uri="sip:callback@trunk-a.example")
    token = _token(conn, owner)
    base = f"{API}/cases/{case_id}/deception"
    rows = {c["id"]: c for c in client.get(
        f"{base}/calls", headers=_auth(token)).json()["calls"]}
    for rid in (first, second, back):
        assert not _seen(rows[rid], pbx), "the victim's PBX was called shared"
        assert pbx not in {p["label"] for p in rows[rid]["proposable"]}
    # The actor's trunk still links the inbound call to the callback.
    trunk = _seen(rows[first], "trunk-a.example")
    assert trunk and {o["id"] for o in trunk["elsewhere"]} == {back}
    assert "trunk-a.example" in {p["label"] for p in rows[back]["proposable"]}

    found = client.get(f"{base}/search", params={"q": pbx},
                       headers=_auth(token)).json()
    assert {h["id"] for h in found["hits"]} == {first, second, back}


def test_the_first_lure_is_dated_by_the_relay_and_never_by_the_date_header(
        conn, client):
    """The verifier (2026-09-23): the first lure was ordered by the
    message's Date header, which the sender writes, so a backdated header
    moved the certificate finding to wherever the sender liked."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    backdated = EML.replace(b"Date: Fri, 17 Jul 2026 08:14:00 +0000",
                            b"Date: Thu, 01 Jan 2026 00:00:00 +0000")
    assert backdated != EML
    capture, message, _call = _seed(conn, owner, case_id, eml=backdated)
    detail = client.get(f"{API}/cases/{case_id}/deception/captures/{capture}",
                        headers=_auth(_token(conn, owner))).json()
    lure = detail["first_lure"]
    assert lure["id"] == message and lure["basis"] == "received"
    assert lure["at"].startswith("2026-07-17T08:14:02"), (
        "the lure is not dated by the boundary hop the recipient relay wrote")


def test_case_search_finds_the_records_that_carry_a_host_address_or_url(
        conn, client):
    """The finding's last part: "index deception hosts, IPs and URLs in case
    search". Over what the reader may see, defanged input accepted, and the
    victim's side of a call never searched."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    capture, message, call = _seed(conn, owner, case_id,
                                   call_classification="RED")
    base = f"{API}/cases/{case_id}/deception/search"
    token = _token(conn, owner)

    body = client.get(base, params={"q": SHARED}, headers=_auth(token)).json()
    found = {(h["channel"], h["id"]) for h in body["hits"]}
    assert found == {("capture", capture), ("email", message), ("call", call)}
    assert all(h["exact"] for h in body["hits"]) and body["total"] == 3
    [cl] = [h for h in body["hits"] if h["channel"] == "call"]
    assert cl["path"] == "calls" and cl["label"] == f"from {SHARED}"

    url = client.get(base, params={"q": "hxxps://portal[.]secure-billing[.]example"},
                     headers=_auth(token)).json()
    assert {h["channel"] for h in url["hits"]} == {"capture", "email"}
    for hit in url["hits"]:
        for m in hit["matches"]:
            assert "https://" not in m["value_defanged"], "a live URL came back"

    # The victim's number, and a query too short to mean anything.
    assert client.get(base, params={"q": "7946"},
                      headers=_auth(token)).json()["hits"] == []
    assert client.get(base, params={"q": "20"},
                      headers=_auth(token)).json()["too_short"] is True

    amber = _user(conn, clearance="AMBER", roles=())
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
                 (case_id, amber, owner))
    low = client.get(base, params={"q": SHARED},
                     headers=_auth(_token(conn, amber))).json()
    assert {h["channel"] for h in low["hits"]} == {"capture", "email"}, (
        "a RED call was found by an AMBER reader")

    outsider = _user(conn, roles=())
    r = client.get(base, params={"q": SHARED},
                   headers=_auth(_token(conn, outsider)))
    assert r.status_code in (403, 404), r.text


def test_what_the_capture_form_sends_is_recorded(conn, client):
    owner = _user(conn)
    case_id = _case(conn, owner)
    token = _token(conn, owner)
    base = f"{API}/cases/{case_id}/deception/captures"
    body = {
        "requested_url": "https://lure.example/r/2",
        "capture_method": "VICTIM_SUPPLIED",
        "final_url": "https://portal.example/v", "http_status": 200,
        "hops": [{"url": "https://lure.example/r/2", "hop_kind": "REQUESTED",
                  "http_status": 302, "resolved_ip": "203.0.113.90",
                  "asn": "AS64496"},
                 {"url": "https://portal.example/v", "hop_kind": "HTTP_30X"}],
        "tls_not_before": "2026-07-12", "tls_not_after": "2026-10-10",
        "favicon_hash": "-1274384433", "classification": "AMBER",
    }
    r = client.post(base, headers=_auth(token), json=body)
    assert r.status_code == 201, r.text
    detail = client.get(f"{base}/{r.json()['id']}", headers=_auth(token)).json()
    assert detail["tls_not_before"].startswith("2026-07-12")
    assert detail["hops"][0]["asn"] == 64496
    assert detail["favicon_hash"] == "-1274384433"

    bad = dict(body, hops=[{"url": "https://x.example", "resolved_ip": "not-an-ip"}])
    assert client.post(base, headers=_auth(token), json=bad).status_code == 422
    active = dict(body, capture_method="MANUAL_BROWSER")
    r = client.post(base, headers=_auth(token), json=active)
    assert r.status_code == 422 and "egress profile" in r.json()["detail"]


def test_a_key_hash_that_is_not_a_sha256_is_a_sentence_and_not_a_500(
        conn, client):
    """Final review u16 (2026-09-24): the form's key-hash field was sent as
    typed, and any hex that was not 32 bytes (a SHA-1 pin, a hash cut
    short) reached the table's capture_spki_is_a_sha256 CHECK as an opaque
    500 that named no field."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    token = _token(conn, owner)
    base = f"{API}/cases/{case_id}/deception/captures"
    body = {"requested_url": "https://lure.example/r/3",
            "capture_method": "VICTIM_SUPPLIED", "classification": "AMBER"}
    count = "SELECT count(*) FROM deception.capture WHERE case_id = %s"
    for bad in ("da39a3ee5e6b4b0d3255bfef95601890afd80709",   # a SHA-1 pin
                "ab" * 31, "ab" * 33, "not hex at all"):
        r = client.post(base, headers=_auth(token),
                        json=dict(body, tls_spki_sha256=bad))
        assert r.status_code == 422, (bad, r.status_code, r.text)
        assert "64 hex characters" in r.json()["detail"], r.text
    assert conn.execute(count, (case_id,)).fetchone()[0] == 0
    # Spaces and colons are how a certificate viewer prints it.
    good = ":".join(["AB"] * 32)
    r = client.post(base, headers=_auth(token), json=dict(body, tls_spki_sha256=good))
    assert r.status_code == 201, r.text
    detail = client.get(f"{base}/{r.json()['id']}", headers=_auth(token)).json()
    assert detail["tls_spki_sha256"] == "ab" * 32


def test_an_unknown_email_direction_is_refused_before_the_exhibit_is_written(
        conn, client):
    owner = _user(conn)
    case_id = _case(conn, owner)
    token = _token(conn, owner)
    count = 'SELECT count(*) FROM core.evidence WHERE case_id = %s'
    before = conn.execute(count, (case_id,)).fetchone()[0]
    r = client.post(f"{API}/cases/{case_id}/deception/emails",
                    headers=_auth(token),
                    files={"file": ("m.eml", EML, "message/rfc822")},
                    data={"direction": "SIDEWAYS", "classification": "AMBER"})
    assert r.status_code == 422, r.text
    assert conn.execute(count, (case_id,)).fetchone()[0] == before, (
        "the .eml was written write-once before the refusal")


def test_the_call_form_refusals_are_sentences(conn, client):
    owner = _user(conn)
    case_id = _case(conn, owner)
    token = _token(conn, owner)
    base = f"{API}/cases/{case_id}/deception/calls"
    ok = {"started_at": "2026-07-17T09:02:00Z", "direction": "INBOUND_TO_VICTIM",
          "record_source": "VICTIM_STATEMENT", "duration_seconds": 400,
          "disposition": "ANSWERED", "source_ip": SHARED,
          "presented_number": "+44 20 7946 0018", "classification": "AMBER"}
    assert client.post(base, headers=_auth(token), json=ok).status_code == 201
    for bad in ({"stir_shaken_verified": True},
                {"ended_at": "2026-07-17T08:00:00Z"},
                {"duration_seconds": -1}):
        r = client.post(base, headers=_auth(token), json={**ok, **bad})
        assert r.status_code == 422, (bad, r.status_code, r.text)

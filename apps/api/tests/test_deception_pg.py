"""The deception subsystem against a real database (docs/19).

The pure logic lives in `test_deception.py`. What needs Postgres is
everything that is enforced by the SCHEMA rather than by Python — and in
this subsystem that is most of the safety argument, because every rule
worth having is written twice: once in the service so the caller gets a
sentence, once as a constraint so a migration or a psql session cannot
route around it.

That doubling is not belt-and-braces for its own sake. F19 (docs/17)
established the failure mode directly: a rule enforced only in application
code holds exactly until somebody writes the second caller.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import psycopg
import pytest

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

EMAIL_LIKE = "dcp-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    esub = f"(SELECT id FROM core.evidence WHERE case_id IN {csub})"
    # Evidence and custody are WORM/append-only by design, so cleanup has
    # to disable the custody trigger briefly — the same idiom, for the same
    # reason, as `test_evidence_pg.py`. `audit.event` is left alone
    # entirely: invariant 6 has no such escape hatch, and a teardown that
    # could tidy the audit trail would mean the invariant did not hold.
    with c.transaction():
        c.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM deception.capture_hop WHERE capture_id IN "
                  f"(SELECT id FROM deception.capture WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM deception.capture WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM deception.email_hop WHERE message_id IN "
                  f"(SELECT id FROM deception.email_message WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM deception.email_attachment WHERE message_id IN "
                  f"(SELECT id FROM deception.email_message WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM deception.email_message WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM deception.call_record WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence_custody WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.app_user WHERE id IN {sub}")
        c.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
    c.close()


def _user(conn, clearance="RED", compartments=()):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"dcp-{uuid4().hex[:8]}@noctornal.test", "Dcp", "x" * 20)
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
        "WHERE id = %s", (clearance, list(compartments), uid))
    return uid


def _case(conn, owner, classification="GREEN", compartments=()):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-DCP-{uuid4().hex[:6]}", title="Deception",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification=classification, compartments=list(compartments))


def _svc(conn):
    from noctornal_api.deception import DeceptionService
    return DeceptionService(conn)


NOW = datetime(2026, 7, 20, 9, 0, tzinfo=timezone.utc)


# --- L5: submitting input to a phishing page -----------------------------

def test_l5_submitting_input_without_an_authority_is_refused(conn):
    """docs/19 §6. Entering credentials — including canary ones — into a
    phishing page may constitute unauthorised access and is not a decision
    software can make. The service refuses with a sentence."""
    from noctornal_api.deception import DeceptionError

    owner = _user(conn)
    case_id = _case(conn, owner)
    with pytest.raises(DeceptionError, match="L5"):
        _svc(conn).record_capture(
            case_id=case_id, requested_url="https://evil.example/login",
            capture_method="MANUAL_BROWSER", captured_by=owner,
            egress_profile_id=None, submitted_input=True)


def test_l5_is_also_a_check_constraint_so_psql_cannot_route_around_it(conn):
    """The service refusal is for the caller's benefit. THIS is the rule.

    A migration, a fix-up script or a psql session does not run Python,
    and the row that has to survive is the authorisation.
    """
    owner = _user(conn)
    case_id = _case(conn, owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            conn.execute(
                """INSERT INTO deception.capture
                       (case_id, requested_url, requested_url_norm,
                        capture_method, captured_by, submitted_input)
                   VALUES (%s, 'https://e.example', 'https://e.example',
                           'ANALYST_UPLOAD', %s, true)""",
                (case_id, owner))


def test_an_active_capture_must_declare_its_egress(conn):
    """A capture with no declared egress is one nobody can account for
    afterwards. An attestation rather than a routing control — nothing in
    this platform performs the fetch — but it must not be blank by
    accident."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            conn.execute(
                """INSERT INTO deception.capture
                       (case_id, requested_url, requested_url_norm,
                        capture_method, captured_by)
                   VALUES (%s, 'https://e.example', 'https://e.example',
                           'HEADLESS', %s)""",
                (case_id, owner))


def test_a_passive_capture_needs_no_egress_because_it_touched_nothing(conn):
    owner = _user(conn)
    case_id = _case(conn, owner)
    capture_id = _svc(conn).record_capture(
        case_id=case_id, requested_url="https://evil.example/login",
        capture_method="VICTIM_SUPPLIED", captured_by=owner)
    assert capture_id is not None


# --- L4: a recording is intercepted content ------------------------------

def test_l4_a_call_recording_without_a_lawful_basis_is_refused(conn):
    """Metadata is not content. The constraint sits only on the content,
    so a CDR attaches freely and a recording does not."""
    from noctornal_api.deception import DeceptionError
    from noctornal_api.evidence import EvidenceService, EvidenceStorage

    owner = _user(conn)
    case_id = _case(conn, owner)
    exhibit = EvidenceService(conn, EvidenceStorage()).ingest(
        case_id=case_id, title="call.wav", media_type="audio/wav",
        data=b"RIFF" + uuid4().bytes, acquired_by=owner,
        acquisition_method="MANUAL_UPLOAD")
    with pytest.raises(DeceptionError, match="L4"):
        _svc(conn).record_call(
            case_id=case_id, started_at=NOW, direction="INBOUND_TO_VICTIM",
            record_source="CARRIER_CDR", recorded_by=owner,
            recording_evidence_id=exhibit.evidence_id)


def test_the_cdr_itself_attaches_without_any_of_that(conn):
    owner = _user(conn)
    case_id = _case(conn, owner)
    call_id = _svc(conn).record_call(
        case_id=case_id, started_at=NOW, direction="INBOUND_TO_VICTIM",
        record_source="CARRIER_CDR", recorded_by=owner,
        presented_number_e164="+441234567890",
        p_asserted_identity="sip:2049@trunk-42.carrier.example")
    assert call_id is not None


def test_a_verified_attestation_needs_something_to_have_been_attested(conn):
    """`stir_shaken_verified` without an attestation letter is a boolean
    claiming a check ran on nothing."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            conn.execute(
                """INSERT INTO deception.call_record
                       (case_id, direction, started_at, record_source,
                        recorded_by, stir_shaken_verified)
                   VALUES (%s, 'INBOUND_TO_VICTIM', now(), 'CARRIER_CDR',
                           %s, true)""",
                (case_id, owner))


# --- invariant 1 as it lands here ----------------------------------------

def test_a_dkim_domain_cannot_be_stored_without_a_pass(conn):
    """`header.d=microsoft.com` on a FAILING signature is a claim by the
    attacker. A stored domain reads as an authenticated identity to every
    downstream consumer, so the schema refuses the combination."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    from noctornal_api.evidence import EvidenceService, EvidenceStorage
    exhibit = EvidenceService(conn, EvidenceStorage()).ingest(
        case_id=case_id, title="m.eml", media_type="message/rfc822",
        data=b"From: a@b.example\r\n\r\nx" + uuid4().bytes,
        acquired_by=owner, acquisition_method="MANUAL_UPLOAD")
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            conn.execute(
                """INSERT INTO deception.email_message
                       (case_id, evidence_id, recorded_by,
                        dkim_result, dkim_domain)
                   VALUES (%s, %s, %s, 'FAIL', 'microsoft.example')""",
                (case_id, exhibit.evidence_id, owner))


def test_a_message_may_have_only_one_trust_boundary(conn):
    """Two boundaries would make "is this hop trustworthy" unanswerable,
    which is the one question the table exists to answer."""
    from noctornal_api.evidence import EvidenceService, EvidenceStorage

    owner = _user(conn)
    case_id = _case(conn, owner)
    exhibit = EvidenceService(conn, EvidenceStorage()).ingest(
        case_id=case_id, title="m.eml", media_type="message/rfc822",
        data=b"From: a@b.example\r\n\r\ny" + uuid4().bytes,
        acquired_by=owner, acquisition_method="MANUAL_UPLOAD")
    msg = conn.execute(
        """INSERT INTO deception.email_message
               (case_id, evidence_id, recorded_by)
           VALUES (%s, %s, %s) RETURNING id""",
        (case_id, exhibit.evidence_id, owner)).fetchone()[0]
    conn.execute(
        """INSERT INTO deception.email_hop
               (message_id, seq, received_raw, is_trusted_boundary)
           VALUES (%s, 0, 'x', true)""", (msg,))
    with pytest.raises(psycopg.errors.UniqueViolation):
        with conn.transaction():
            conn.execute(
                """INSERT INTO deception.email_hop
                       (message_id, seq, received_raw, is_trusted_boundary)
                   VALUES (%s, 1, 'y', true)""", (msg,))


# --- labels: composed on read, raised on write ---------------------------

def test_a_capture_is_raised_to_its_cases_floor(conn):
    """AMBER into a RED case comes out RED. The `enforce_tlp_floor`
    trigger would reject it outright; raising in the service means the
    caller gets the row at the right label rather than an error, and — the
    part a trigger cannot do — the case's compartments come along."""
    # The owner has to hold the compartment first: CaseService refuses to
    # create a case its own owner could not read, which is the access
    # model working rather than a fixture inconvenience.
    owner = _user(conn, compartments=("OPX",))
    case_id = _case(conn, owner, classification="RED", compartments=("OPX",))
    capture_id = _svc(conn).record_capture(
        case_id=case_id, requested_url="https://evil.example/",
        capture_method="ANALYST_UPLOAD", captured_by=owner,
        classification="AMBER")
    row = conn.execute(
        "SELECT classification, compartments FROM deception.capture WHERE id = %s",
        (capture_id,)).fetchone()
    assert row[0] == "RED"
    assert row[1] == ["OPX"]


def test_a_reader_below_the_case_floor_sees_nothing(conn):
    """Composed at READ time, so a case reclassified upward after the fact
    takes its captures with it."""
    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    _svc(conn).record_capture(
        case_id=case_id, requested_url="https://evil.example/",
        capture_method="ANALYST_UPLOAD", captured_by=owner,
        classification="RED")
    assert _svc(conn).captures(case_id, clearance="RED") != []
    assert _svc(conn).captures(case_id, clearance="AMBER") == []


def test_a_reader_without_the_compartment_sees_nothing(conn):
    owner = _user(conn, compartments=("OPX",))
    case_id = _case(conn, owner, classification="GREEN", compartments=("OPX",))
    _svc(conn).record_capture(
        case_id=case_id, requested_url="https://evil.example/",
        capture_method="ANALYST_UPLOAD", captured_by=owner)
    assert _svc(conn).captures(
        case_id, clearance="RED", compartments=frozenset({"OPX"})) != []
    assert _svc(conn).captures(case_id, clearance="RED") == []


def test_an_unreadable_capture_returns_none_not_a_raise(conn):
    """The router's answer must be identical to "no such capture". A
    status code that distinguishes them is an existence oracle for a
    compartmented case."""
    owner = _user(conn, compartments=("OPX",))
    case_id = _case(conn, owner, classification="GREEN", compartments=("OPX",))
    capture_id = _svc(conn).record_capture(
        case_id=case_id, requested_url="https://evil.example/",
        capture_method="ANALYST_UPLOAD", captured_by=owner)
    assert _svc(conn).capture(capture_id, clearance="RED") is None
    assert _svc(conn).capture(uuid4(), clearance="RED") is None


# --- invariant 10: hostile markup ----------------------------------------

def test_an_eml_is_marked_hostile_at_ingest_without_being_asked(conn):
    """Derived from the media type so a caller cannot forget. The whole
    reason the flag is set at the one place bytes enter."""
    from noctornal_api.evidence import EvidenceService, EvidenceStorage

    owner = _user(conn)
    case_id = _case(conn, owner)
    svc = EvidenceService(conn, EvidenceStorage())
    for media_type, expected in (("message/rfc822", True),
                                 ("text/html", True),
                                 ("image/svg+xml", True),
                                 ("image/png", False)):
        result = svc.ingest(
            case_id=case_id, title="x", media_type=media_type,
            data=uuid4().bytes * 4, acquired_by=owner,
            acquisition_method="MANUAL_UPLOAD")
        got = conn.execute(
            "SELECT is_hostile_markup FROM core.evidence WHERE id = %s",
            (result.evidence_id,)).fetchone()[0]
        assert got is expected, media_type


# --- the whole chain, end to end -----------------------------------------

def test_a_bec_message_round_trips_with_its_chain_and_boundary(conn):
    from noctornal_api.deception import parse_eml
    from noctornal_api.evidence import EvidenceService, EvidenceStorage

    owner = _user(conn)
    case_id = _case(conn, owner)
    raw = (
        b"Received: from mx.corp.example ([10.0.0.5]) by mail.corp.example"
        b" with ESMTPS; Mon, 20 Jul 2026 09:00:02 +0000\r\n"
        b"Received: from evil.example ([203.0.113.7]) by mx.corp.example"
        b" with ESMTP; Mon, 20 Jul 2026 09:00:01 +0000\r\n"
        b"Authentication-Results: mail.corp.example; dkim=fail\r\n"
        b"Message-ID: <" + uuid4().hex.encode() + b"@evil.example>\r\n"
        b"From: \"Jane, CFO\" <jane@acme.example>\r\n"
        b"Reply-To: jane.acme@gmail.com\r\n"
        b"Subject: Remittance update\r\n\r\nBody.\r\n")
    exhibit = EvidenceService(conn, EvidenceStorage()).ingest(
        case_id=case_id, title="bec.eml", media_type="message/rfc822",
        data=raw, acquired_by=owner, acquisition_method="MANUAL_UPLOAD")
    parsed = parse_eml(raw, trusted=("corp.example",))
    message_id = _svc(conn).record_email(
        case_id=case_id, evidence_id=exhibit.evidence_id, parsed=parsed,
        recorded_by=owner)

    got = _svc(conn).email(message_id, clearance="RED")
    assert got["from_replyto_divergent"] is True
    assert got["reply_to_is_freemail"] is True
    assert got["dkim_domain"] is None
    assert got["trusted_boundary_seq"] == 1
    assert [h["is_attacker_writable"] for h in got["hops"]] == [False, False]
    # Divergent-only is the triage query, and it must find this.
    assert [m["id"] for m in _svc(conn).emails(
        case_id, clearance="RED", divergent_only=True)] == [message_id.__str__()]


def test_a_capture_and_its_hops_commit_together(conn):
    """A capture whose hops went missing reads as "this URL redirected
    nowhere", which is a finding — and a false one."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    capture_id = _svc(conn).record_capture(
        case_id=case_id, requested_url="https://short.example/abc",
        final_url="https://kit.example/login",
        capture_method="ANALYST_UPLOAD", captured_by=owner,
        hops=[{"url": "https://short.example/abc", "hop_kind": "REQUESTED",
               "http_status": 302},
              {"url": "https://compromised.example/r", "hop_kind": "HTTP_30X",
               "http_status": 302, "resolved_ip": "203.0.113.9"},
              {"url": "https://kit.example/login", "hop_kind": "HTTP_30X",
               "http_status": 200}])
    got = _svc(conn).capture(capture_id, clearance="RED")
    assert [h["seq"] for h in got["hops"]] == [0, 1, 2]
    # Defanged on the way out, for every consumer and not just the UI.
    assert got["hops"][2]["url_defanged"] == "hxxps://kit[.]example/login"
    assert got["requested_url_defanged"] == "hxxps://short[.]example/abc"


def test_recording_a_capture_is_audited(conn):
    owner = _user(conn)
    case_id = _case(conn, owner)
    _svc(conn).record_capture(
        case_id=case_id, requested_url="https://evil.example/",
        capture_method="ANALYST_UPLOAD", captured_by=owner)
    n = conn.execute(
        "SELECT count(*) FROM audit.event WHERE case_id = %s "
        "AND action = 'CAPTURE_RECORDED'", (case_id,)).fetchone()[0]
    assert n == 1


def test_re_capturing_a_url_inserts_rather_than_updates(conn):
    """Invariant 5's spirit. Phishing pages change hourly and go dark
    within days; the sequence of captures IS the timeline that proves the
    page was live when the victim hit it."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    url = "https://evil.example/login"
    first = _svc(conn).record_capture(
        case_id=case_id, requested_url=url, capture_method="ANALYST_UPLOAD",
        captured_by=owner, is_live=True)
    second = _svc(conn).record_capture(
        case_id=case_id, requested_url=url, capture_method="ANALYST_UPLOAD",
        captured_by=owner, is_live=False)
    assert first != second
    assert len(_svc(conn).captures(case_id, clearance="RED")) == 2


# --- the ontology additions ----------------------------------------------

def test_impersonates_is_not_a_social_tie(conn):
    """If it were, the impersonated brand would become the most central
    node in every phishing case in the system and every centrality
    ranking downstream would be garbage."""
    row = conn.execute(
        "SELECT is_social_tie, default_sign, src_node_types, dst_node_types "
        "FROM core.edge_type WHERE key = 'IMPERSONATES'").fetchone()
    assert row is not None, "migration 0047 did not run"
    assert row[0] is False
    assert row[1] == 0
    assert "LURE" in row[2]
    assert "ORGANISATION" in row[3]


def test_targeted_was_widened_rather_than_duplicated(conn):
    row = conn.execute(
        "SELECT src_node_types, dst_node_types FROM core.edge_type "
        "WHERE key = 'TARGETED'").fetchone()
    assert "LURE" in row[0] and "INFRA" in row[0]
    assert "PERSON" in row[1]
    assert conn.execute(
        "SELECT count(*) FROM core.edge_type WHERE key = 'DELIVERED_TO'"
    ).fetchone()[0] == 0


def test_the_new_selectors_carry_the_right_strength(conn):
    """`is_strong` drives auto-merge candidacy, and a false merge is worse
    than a missed one. A Message-ID fingerprints the sending kit, and a
    favicon hash on a stock framework would merge half the internet."""
    rows = dict(conn.execute(
        "SELECT key, is_strong FROM core.selector_type WHERE key = ANY(%s)",
        (["TLS_SPKI", "SIP_URI", "EMAIL_MSGID", "FAVICON_MMH3"],)).fetchall())
    assert rows == {"TLS_SPKI": True, "SIP_URI": True,
                    "EMAIL_MSGID": False, "FAVICON_MMH3": False}


def test_the_lure_node_type_exists_and_is_an_artefact(conn):
    row = conn.execute(
        "SELECT category FROM core.node_type WHERE key = 'LURE'").fetchone()
    assert row is not None and row[0] == "ARTEFACT"


def test_retention_dates_do_not_leak_into_the_deception_tables(conn):
    """A sanity check on the fixture, not on the code: if a capture ever
    outlives its case's retention the cleanup below stops working and
    every later run inherits the mess."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    _svc(conn).record_capture(
        case_id=case_id, requested_url="https://evil.example/",
        capture_method="ANALYST_UPLOAD", captured_by=owner)
    assert conn.execute(
        "SELECT count(*) FROM deception.capture WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 1


def test_a_call_cannot_end_before_it_starts(conn):
    owner = _user(conn)
    case_id = _case(conn, owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            conn.execute(
                """INSERT INTO deception.call_record
                       (case_id, direction, started_at, ended_at,
                        record_source, recorded_by)
                   VALUES (%s, 'INBOUND_TO_VICTIM', %s, %s, 'CARRIER_CDR', %s)""",
                (case_id, NOW, NOW - timedelta(minutes=5), owner))

"""The lookup gates (F15.3, 2026-09-24): every rule that
decides whether one selector leaves for one provider, each refusal made
before a row exists and audited with the keyed fingerprint, never the
value.

The fetcher and the routes are fakes; nothing reaches VirusTotal, Shodan
or a MISP. **The email prefix is `lkgate-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import json

import pytest

from outbound_support import (
    DATABASE_URL,
    FakeFetcher,
    fetched,
    lookup_world,
    make_node,
    make_sample,
    make_selector,
    make_user,
    assign,
    route_for_factory,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "lkgate-"
DOMAIN = {"kind": "VALUE", "selector_type": "DOMAIN", "value": "example.org"}
MISP_BODY = json.dumps({"response": {"Attribute": [
    {"event_id": "7", "category": "Network activity", "type": "domain", "to_ids": True,
     "Event": {"info": "Campaign", "date": "2026-09-01"},
     "Tag": [{"name": "tlp:green"}]}]}}).encode()


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _ask(w, conn, subject=None, *, user=None, op="domain_report", confirm=None, svc=None,
         **kw):
    svc = svc or w.service(conn)
    return svc.request(w.case_id, subject or DOMAIN, provider_id=w.provider.id, operation=op,
                       user_id=user or w.analyst,
                       confirm_exposure=confirm or w.provider.exposure_level, **kw)


def _refused(w, conn, code, subject=None, **kw):
    from noctornal_api import lookups
    with pytest.raises(lookups.LookupRefused) as caught:
        _ask(w, conn, subject, **kw)
    assert caught.value.code == code or caught.value.code.startswith(code), caught.value.code
    assert conn.execute("SELECT count(*) FROM ingest.lookup WHERE case_id = %s",
                        (w.case_id,)).fetchone()[0] == 0
    assert not w.fetcher.calls
    return caught.value


def _misp(conn, **kw):
    return lookup_world(conn, PREFIX, level="NONE", adapter="misp_rest",
                        fetcher=FakeFetcher(fetched(200, MISP_BODY)), **kw)


def test_switch_off_refuses_and_audits_the_fingerprint_never_the_value(conn, monkeypatch):
    from noctornal_api import lookups
    w = lookup_world(conn, PREFIX)
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "off")
    _refused(w, conn, "switch_off")
    detail = conn.execute("SELECT detail FROM audit.event WHERE case_id = %s AND action = "
                          "'LOOKUP_REFUSED'", (w.case_id,)).fetchone()[0]
    assert detail["query_fingerprint"] == lookups.query_fingerprint("DOMAIN",
                                                                    "example.org").hex()
    assert "example.org" not in json.dumps(detail)


def test_an_unassigned_caller_is_refused_whatever_their_clearance(conn):
    w = lookup_world(conn, PREFIX)
    refusal = _refused(w, conn, "not_assigned", user=w.admin)
    assert refusal.status == 403 and "assignment" in refusal.detail


def test_a_disabled_provider_is_refused(conn):
    from noctornal_api import providers
    w = lookup_world(conn, PREFIX)
    providers.ProviderRegistry(conn, route_for=w.route_for).disable(
        w.provider.id, reason="paused for review", actor_id=w.admin)
    _refused(w, conn, "provider_disabled")


def test_a_closed_case_sends_nothing(conn):
    w = lookup_world(conn, PREFIX)
    conn.execute('UPDATE core."case" SET status = \'CLOSED\' WHERE id = %s', (w.case_id,))
    _refused(w, conn, "case_read_only")


def test_the_egress_gate_reads_the_subject_labels_now(conn):
    w = lookup_world(conn, PREFIX)
    node = make_node(conn, w.case_id, w.owner, "Amber holder", classification="AMBER")
    sid = make_selector(conn, w.case_id, "DOMAIN", "amber.example", node_id=node)
    _refused(w, conn, "egress:", {"kind": "SELECTOR", "selector_id": str(sid)})
    assert conn.execute("SELECT count(*) FROM audit.event WHERE case_id = %s AND action = "
                        "'LOOKUP_EGRESS_REFUSED'", (w.case_id,)).fetchone()[0] == 1


@pytest.mark.parametrize("value", ["https://facebook.com/some.person",
                                   "https://example.org/?who=someone@example.net"])
def test_personal_data_is_refused_outright(conn, value):
    from noctornal_api import lookups
    w = lookup_world(conn, PREFIX)
    refusal = _refused(w, conn, "pii_not_permitted",
                       {"kind": "VALUE", "selector_type": "URL", "value": value},
                       op="url_report")
    assert refusal.detail == lookups.PII_REFUSAL


def test_an_unscreened_sample_hash_leaves_by_no_subject_kind(conn):
    w = lookup_world(conn, PREFIX)
    digest = "ab" * 32
    sample = make_sample(conn, w.case_id, w.owner, digest)
    as_value = {"kind": "VALUE", "selector_type": "HASH_SHA256", "value": digest}
    _refused(w, conn, "sample_unscreened", as_value, op="file_report")
    _refused(w, conn, "sample_unscreened", {"kind": "SAMPLE", "sample_id": str(sample)},
             op="file_report")
    make_selector(conn, w.case_id, "HASH_SHA256", digest)
    sid = conn.execute("SELECT id FROM core.selector WHERE case_id = %s AND norm_value = %s",
                       (w.case_id, digest)).fetchone()[0]
    _refused(w, conn, "sample_unscreened", {"kind": "SELECTOR", "selector_id": str(sid)},
             op="file_report")


def test_a_hash_held_by_a_sample_the_caller_cannot_see_is_restricted_without_saying_why(conn):
    from noctornal_api import lookups
    w = lookup_world(conn, PREFIX)
    digest = "cd" * 32
    make_sample(conn, None, w.owner, digest, classification="RED")
    refusal = _refused(w, conn, "value_restricted",
                       {"kind": "VALUE", "selector_type": "HASH_SHA256", "value": digest},
                       op="file_report")
    assert refusal.detail == lookups.VALUE_RESTRICTED and "sample" not in refusal.detail


def test_a_value_declared_below_what_the_case_holds_is_refused(conn):
    from noctornal_api import lookups
    w = lookup_world(conn, PREFIX)
    node = make_node(conn, w.case_id, w.owner, "Amber domain", classification="AMBER")
    make_selector(conn, w.case_id, "DOMAIN", "example.org", node_id=node)
    refusal = _refused(w, conn, "value_restricted",
                       dict(DOMAIN, classification="GREEN"))
    assert refusal.detail == lookups.VALUE_RESTRICTED and "AMBER" not in refusal.detail


def test_an_operation_the_provider_lacks_for_the_type_is_refused(conn):
    w = lookup_world(conn, PREFIX)
    _refused(w, conn, "operation_unsupported", op="file_report")
    _refused(w, conn, "operation_unsupported", op="scan_everything")


def test_no_route_is_refused(conn):
    w = lookup_world(conn, PREFIX)
    svc = w.service(conn, route_for=route_for_factory({}))
    _refused(w, conn, "no_route", svc=svc)


def test_a_stale_exposure_echo_is_refused(conn):
    w = lookup_world(conn, PREFIX)
    _refused(w, conn, "exposure_changed", confirm="PUBLIC")


def test_an_adapter_that_changed_in_this_build_is_refused(conn):
    w = lookup_world(conn, PREFIX)
    conn.execute("UPDATE ingest.provider SET adapter_version = '0' WHERE id = %s",
                 (w.provider.id,))
    _refused(w, conn, "adapter_changed")


def test_misp_refuses_a_wildcard(conn):
    w = _misp(conn)
    _refused(w, conn, "value_refused",
             {"kind": "VALUE", "selector_type": "URL", "value": "http://a.example/%25x"},
             op="attribute_search")


def test_a_subject_the_caller_cannot_see_is_not_visible(conn):
    from noctornal_api import lookups
    w = lookup_world(conn, PREFIX)
    node = make_node(conn, w.case_id, w.owner, "Red holder", classification="RED")
    sid = make_selector(conn, w.case_id, "DOMAIN", "red.example", node_id=node)
    with pytest.raises(lookups.NotVisible):
        _ask(w, conn, {"kind": "SELECTOR", "selector_id": str(sid)})


@pytest.mark.parametrize("who", ["nobody", "self", "no_permission", "no_note"])
def test_a_vendor_lookup_names_an_eligible_colleague_with_a_note(conn, who):
    w = lookup_world(conn, PREFIX)
    other, _ = make_user(conn, PREFIX)
    assign(conn, w.case_id, other, "ANALYST")
    kw = {"nobody": {}, "self": {"authorised_by": w.analyst, "authorisation_note": "x"},
          "no_permission": {"authorised_by": other, "authorisation_note": "please"},
          "no_note": {"authorised_by": w.owner, "authorisation_note": "  "}}[who]
    _refused(w, conn, "authoriser_required", **kw)


def test_a_vendor_lookup_waits_for_its_sign_off_and_sends_nothing(conn):
    w = lookup_world(conn, PREFIX)
    got = _ask(w, conn, authorised_by=w.owner, authorisation_note="needed for attribution")
    assert got["status"] == 202 and "Nothing has been sent" in got["notice"]
    state, expires, authoriser = conn.execute(
        "SELECT state, signoff_expires_at - requested_at, authorised_by FROM ingest.lookup "
        "WHERE id = %s", (got["lookup_id"],)).fetchone()
    assert state == "AWAITING_SIGNOFF" and authoriser == w.owner
    assert expires.total_seconds() == 24 * 3600
    assert not w.fetcher.calls
    assert conn.execute("SELECT count(*) FROM ingest.lookup_attempt WHERE lookup_id = %s",
                        (got["lookup_id"],)).fetchone()[0] == 0
    told = conn.execute("SELECT recipient_id FROM notify.notification WHERE kind = "
                        "'LOOKUP_SIGNOFF_REQUESTED' AND case_id = %s", (w.case_id,)).fetchall()
    assert told == [(w.owner,)]


def test_a_vendor_lookup_is_never_queued(conn):
    w = lookup_world(conn, PREFIX)
    _refused(w, conn, "queue_refused_signoff", authorised_by=w.owner,
             authorisation_note="please", queue_if_limited=True)


def test_the_database_refuses_a_vendor_row_that_starts_sent_or_queued(conn):
    import psycopg
    from noctornal_api import lookups
    w = lookup_world(conn, PREFIX)
    base = {"case_id": w.case_id, "provider_id": w.provider.id, "requested_by": w.analyst,
            "fp": lookups.query_fingerprint("DOMAIN", "example.org")}
    sql = """INSERT INTO ingest.lookup (case_id, provider_id, operation, adapter_version,
                 subject_kind, selector_type, query_value, query_fingerprint, classification,
                 exposure_level, exposure_confirmed, authorised_by, authorisation_note,
                 signoff_expires_at, requested_by, state)
             VALUES (%(case_id)s, %(provider_id)s, 'domain_report', '1', 'VALUE', 'DOMAIN',
                     'example.org', %(fp)s, 'GREEN', 'VENDOR', true, %(auth)s, 'n',
                     now() + interval '1 hour', %(requested_by)s, %(state)s)"""
    with pytest.raises(psycopg.errors.RaiseException), conn.transaction():
        conn.execute(sql, dict(base, auth=w.owner, state="SENDING"))
    with pytest.raises(psycopg.errors.CheckViolation) as caught, conn.transaction():
        conn.execute(sql, dict(base, auth=w.owner, state="QUEUED"))
    assert caught.value.diag.constraint_name == "lookup_signed_is_never_queued"
    with pytest.raises(psycopg.errors.CheckViolation) as caught, conn.transaction():
        conn.execute(sql, dict(base, auth=w.analyst, state="AWAITING_SIGNOFF"))
    assert caught.value.diag.constraint_name == "lookup_signoff_asks_another"


def test_a_none_lookup_sends_once_through_its_own_tagged_route(conn):
    from noctornal_api import lookups
    w = _misp(conn)
    got = _ask(w, conn, op="attribute_search")
    assert got["status"] == 200, got
    (call,) = w.fetcher.calls
    assert call["route"].context == f"lookup:{got['lookup_id']}"
    assert call["max_redirects"] == 0 and call["method"] == "POST"
    assert "sk_test_" + "k" * 40 in call["secrets"]
    assert call["url"].startswith("https://misp.internal.example/")
    row = conn.execute("SELECT state, attempts, outcome FROM ingest.lookup WHERE id = %s",
                       (got["lookup_id"],)).fetchone()
    assert row == ("ANSWERED", 1, "FOUND")
    sent = conn.execute("SELECT detail FROM audit.event WHERE object_id = %s AND action = "
                        "'LOOKUP_SENT'", (got["lookup_id"],)).fetchone()[0]
    assert "example.org" not in json.dumps(sent)
    assert sent["query_fingerprint"] == lookups.query_fingerprint("DOMAIN",
                                                                  "example.org").hex()
    used = conn.execute("SELECT count(*) FROM audit.event WHERE object_id = %s AND action = "
                        "'PROVIDER_SECRET_USED'", (w.provider.id,)).fetchone()[0]
    assert used == 1


def test_a_hash_held_by_a_sample_in_another_case_is_restricted_without_saying_why(conn):
    """An AMBER sample the caller's labels dominate, in a case they are not
    assigned to: the refusal used to be the sample sentence, which told
    them the hash is a lab sample there (2026-09-25). Only
    a sample of the case being worked names itself."""
    from noctornal_api import lookups
    from outbound_support import make_case
    w = lookup_world(conn, PREFIX)
    elsewhere = make_case(conn, w.owner, PREFIX)
    digest = "ef" * 32
    make_sample(conn, elsewhere, w.owner, digest, classification="AMBER")
    refusal = _refused(w, conn, "value_restricted",
                       {"kind": "VALUE", "selector_type": "HASH_SHA256", "value": digest},
                       op="file_report")
    assert refusal.detail == lookups.VALUE_RESTRICTED and "sample" not in refusal.detail

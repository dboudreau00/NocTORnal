"""The Deception pane's second round of fixes (review of 2026-09-22, closed
on 2026-09-23): the channels pivot on what they share, the Received chain
says where trust ends, the call row says what the network recorded and
how far it vouches, the web capture shows its durable identifiers, and
all three channels can be recorded from the console.

Pure: the shipped console and the service's pure helpers. The database
half is `test_deception_crosschannel_pg.py`.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")
SRC = STATIC.parents[1]


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


def _code(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def _fn(name: str) -> str:
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone"
    return js[m.start():js.index("\n}", m.start())]


def _router() -> str:
    return (SRC / "http" / "routers" / "deception.py").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# ux14-deception:ecrime-no-cross-channel-pivot
# ---------------------------------------------------------------------------

def test_every_record_says_where_else_its_hosts_and_addresses_appear():
    for fn in ("captureRow", "emailRow", "callRow", "openCapture",
               "openDeceptionEmail"):
        body = _fn(fn)
        assert "dcpAlsoSeen(" in body, f"{fn} does not say what it shares"
        assert "dcpProposeBar(" in body, f"{fn} cannot propose into the graph"
    seen = _fn("dcpAlsoSeen")
    assert "row.also_seen" in seen and "dcpJump(o.channel, o.id)" in seen
    assert "s.value_defanged" in seen, "a shared host is drawn live"
    jump = _fn("dcpJump")
    assert "selectDeceptionSub(" in jump
    assert "openCapture(id" in jump and "openDeceptionEmail(id" in jump
    # A call has no card: its row is brought to view once the list loads.
    assert "dcpPendingCall" in _fn("loadDeceptionCalls")
    # The server computes it for every list and both details.
    router = _router()
    for route in ("list_captures", "get_capture", "list_emails", "get_email",
                  "list_calls"):
        body = router[router.index(f"def {route}("):]
        body = body[:body.index("\n@router.")]
        assert ".annotate(" in body, f"{route} does not annotate its rows"


def test_the_call_row_shows_the_source_address_and_the_rest_of_the_record():
    row = _fn("callRow")
    for read in ("c.source_ip", "c.called_number_e164", "c.duration_seconds",
                 "c.disposition", "c.sip_call_id"):
        assert read in row, f"the call row still hides {read}"


def test_proposing_from_a_record_names_a_key_and_nothing_else():
    bar = _fn("dcpProposeBar")
    assert "json: { key: c.key }" in bar
    router = _router()
    route = router[router.index("def propose_from_record("):]
    assert 'permission_key="evidence.upload"' in route
    assert "check_writable_labels(" in route
    assert "svc.propose(case_id, channel, record, body.key," in route
    # Proposed under the reader's own ceiling, so "already an entity" is
    # said only of one they may see (the verifier, 2026-09-23).
    assert "clearance=clearance, compartments=comps)" in route
    service = (SRC / "deception.py").read_text(encoding="utf-8")
    body = service[service.index("    def propose(self"):]
    body = body[:body.index("\n    def ", 10)]
    exists = body[body.index("FROM core.node"):body.index("if exists:")]
    assert "_labels_clause()" in exists, (
        "an entity above the reader's labels is still named, with its id")


def test_case_search_reaches_the_deception_records():
    """ux14-deception:ecrime-no-cross-channel-pivot, its last part (2026-09-23):
    "index deception hosts, IPs and URLs in case search"."""
    from noctornal_api.deception import (
        SEARCH_MIN,
        _observe,
        search_needle,
        search_observed,
    )
    # A value pasted from a defanged report finds the live one.
    assert search_needle(" hxxps://Portal[.]Example/v ") == "https://portal.example/v"
    bucket: dict = {}
    _observe(bucket, "capture", "c1", "ip", "203.0.113.44", "address of redirect hop 2")
    _observe(bucket, "capture", "c1", "url", "https://portal.example/v", "final URL")
    _observe(bucket, "capture", "c1", "url", "https://portal.example/v", "redirect hop 2")
    _observe(bucket, "email", "e1", "host", "portal.example", "Return-Path domain",
             claimed=True)
    _observe(bucket, "call", "k1", "ip", "203.0.113.4", "source address")
    out = search_observed(bucket, search_needle("portal[.]example"))
    [url] = out[("capture", "c1")]
    assert url["where"] == "final URL, redirect hop 2", "one value, two rows"
    assert url["value_defanged"] == "hxxps://portal[.]example/v"
    [host] = out[("email", "e1")]
    assert host["exact"] and host["claimed"], "a sender-typed host is not marked"
    # A fragment finds both addresses; the whole one is exact only once.
    both = search_observed(bucket, "203.0.113.4")
    assert both[("call", "k1")][0]["exact"]
    assert not both[("capture", "c1")][0]["exact"]
    assert SEARCH_MIN == 3 and search_observed(bucket, "20") == {}

    router = _router()
    route = router[router.index("def search_records("):]
    route = route[:route.index("\n@router.")]
    assert 'permission_key="evidence.read"' in route
    assert "_ceiling(conn, user, case_id)" in route
    assert '@router.get("/search", dependencies=[Depends(rate_limit("search"))])' \
        in router

    # The Search pane asks for them and draws them, defanged, in a block of
    # their own; a click opens the record in Deception.
    run = _code(_fn("runSearch"))
    assert "searchDeceptionRecords(q)" in run
    assert "clearDeceptionSearch()" in _fn("refreshSearchForGlass")
    search = _code(_fn("searchDeceptionRecords"))
    assert "cpath('/deception/search?" in search
    assert "seq !== dcpSearchSeq" in search and "caseChanged(token)" in search
    hit = _code(_fn("dcpSearchHit"))
    assert "m.value_defanged" in hit and "m.value)" not in hit
    assert "selectTab('deception')" in hit and "dcpJump(hit.channel, hit.id)" in hit
    assert "onCaseSwitch(clearDeceptionSearch)" in _js()
    html = _html()
    pane = html[html.index('id="pane-search"'):html.index("<!-- COMMS")]
    assert 'id="search-deception"' in pane


def test_the_pure_overlap_names_other_records_and_merges_one_records_own():
    from noctornal_api.deception import _observe, cross_channel
    bucket: dict = {}
    _observe(bucket, "capture", "c1", "ip", "203.0.113.44", "address of redirect hop 2")
    _observe(bucket, "capture", "c1", "host", "evil.example", "final URL")
    _observe(bucket, "capture", "c1", "host", "evil.example", "redirect hop 2")
    _observe(bucket, "email", "e1", "ip", "203.0.113.44", "sending address, Received hop 2")
    _observe(bucket, "email", "e1", "host", "kit.example", "Message-ID host",
             claimed=True)
    _observe(bucket, "call", "k1", "ip", "203.0.113.44", "source address")
    out = cross_channel(bucket)
    # One entry: a host seen twice in one record and nowhere else is not
    # an overlap.
    [cap] = out[("capture", "c1")]
    assert cap["value"] == "203.0.113.44"
    assert {o["channel"] for o in cap["elsewhere"]} == {"email", "call"}
    assert ("email", "e1") in out and ("call", "k1") in out
    # Hosts are drawn defanged.
    bucket2: dict = {}
    _observe(bucket2, "capture", "c1", "host", "evil.example", "final URL")
    _observe(bucket2, "email", "e1", "host", "evil.example", "URL in the body")
    [e] = cross_channel(bucket2)[("email", "e1")]
    assert e["value_defanged"] == "evil[.]example"


def test_the_presented_number_and_an_unconfirmed_sender_are_never_proposed():
    """Invariant 9: the caller ID the victim saw is the attacker's choice,
    and a sending address at an ASSUMED boundary can be the recipient's
    own relay."""
    from noctornal_api.deception import proposal_candidates
    call = {"id": "k1", "source_ip": "203.0.113.44",
            "presented": {"number_e164": "+442079460018"},
            "sip_from_uri": "sip:44471@trunk-04.example",
            "durable": {"p_asserted_identity": "sip:44471@trunk-04.example"}}
    labels = {c["label"] for c in proposal_candidates("call", call)}
    assert "+442079460018" not in labels
    assert labels == {"203.0.113.44", "trunk-04.example"}
    email = {"id": "e1", "sending_host": {"ip": "10.4.0.9",
                                         "boundary_confirmed": None, "seq": 0},
             "extracted_urls": ["https://evil.example/x?ref=1"]}
    labels = {c["label"] for c in proposal_candidates("email", email)}
    assert "10.4.0.9" not in labels and "evil.example" in labels


def test_the_victims_end_of_a_call_is_never_proposed_as_the_actors():
    """Final review u17 (2026-09-24): the SIP To host was offered as INFRA
    whatever the call's direction. On a vishing call the To URI is the
    callee, so the victim's own PBX was one Triage click from the actor's
    graph. When the victim placed the call, From and P-Asserted-Identity
    are the victim's instead."""
    from noctornal_api.deception import proposal_candidates
    call = {"id": "k1", "source_ip": "203.0.113.44",
            "sip_from_uri": "sip:44471@trunk-04.example",
            "sip_to_uri": "sip:+442071838750@pbx.northgate.example",
            "durable": {"p_asserted_identity": "sip:44471@pai.trunk-04.example"}}

    def labels(direction):
        return {c["label"] for c in proposal_candidates(
            "call", {**call, "direction": direction})}

    for direction in ("INBOUND_TO_VICTIM", "UNKNOWN", None):
        assert labels(direction) == {
            "203.0.113.44", "trunk-04.example", "pai.trunk-04.example"}, direction
    assert labels("OUTBOUND_FROM_VICTIM") == {
        "203.0.113.44", "pbx.northgate.example"}


def test_the_sip_host_and_url_host_helpers():
    from noctornal_api.deception import _host_of, _sip_host
    assert _sip_host("sip:44471@Trunk-04.Example.;user=phone") == "trunk-04.example"
    assert _sip_host("tel:+442071838750") is None
    assert _host_of("https://A.Example./v?x=1") == "a.example"
    assert _host_of("a.example/login") == "a.example"


# ---------------------------------------------------------------------------
# ux14-deception:received-chain-above-below
# ---------------------------------------------------------------------------

def test_the_chain_says_where_trust_ends_in_words_and_not_in_green():
    body = _code(_fn("openDeceptionEmail"))
    assert "'chip good', 'trust boundary'" not in body, (
        "the attacker's own server wears a green chip again")
    assert "'true sending host, observed by '" in body
    assert "'trust-rule'" in body and "Trust ends here" in body
    assert "above the boundary" not in body.lower()
    assert "m.sending_host.boundary_confirmed" in body, (
        "an assumed boundary is stated as a confirmed one")


def test_the_chain_note_points_at_the_line_only_when_it_is_drawn():
    """The verifier's nit (2026-09-23): the note named a line marked "trust
    ends here" on a chain with no hop below the boundary, where no line is
    drawn, and on an assumed boundary, where the line reads otherwise."""
    body = _code(_fn("openDeceptionEmail"))
    note = body[body.index("note.textContent ="):body.index("chain.appendChild(note)")]
    assert '"trust ends here"' not in note
    assert "!anyClaimed" in note and "confirmed" in note, (
        "the note says the same whatever the drawing shows")
    assert body.index("const anyClaimed") < body.index("note.textContent ="), (
        "the note is written before it knows whether a line is drawn")
    rule = body[body.index("'trust-rule'"):]
    rule = rule[:rule.index(");")]
    assert "written outside the recipient" not in rule, (
        "an assumed boundary claims to know where the rows below were written")


def test_the_first_lure_is_dated_by_infrastructure_and_says_which_time():
    """The verifier (2026-09-23): the first lure was ordered by the Date
    header, the sender's to write."""
    service = (SRC / "deception.py").read_text(encoding="utf-8")
    lure = service[service.index("    def first_lure(self"):]
    lure = _code(lure[:lure.index("\n    def ", 10)])
    query = lure[lure.index('f"""'):]
    assert "date_header" not in query, "the sender's Date header dates the lure"
    assert "b.received_at" in query and "is_trusted_boundary" in query
    assert '"basis"' in lure
    age = _fn("certificateAge")
    assert "LURE_BASIS_WORDS[lure.basis]" in age


# ---------------------------------------------------------------------------
# ux14-deception:calls-vouched-and-tooltip-only
# ---------------------------------------------------------------------------

def test_the_call_block_is_neutral_and_says_what_the_attestation_means():
    row = _fn("callRow")
    assert "What the network vouched for" not in row
    assert "'What the network recorded'" in row
    assert "recorded-block" in row and "durable-block" not in row
    assert "attestationLine(d)" in row
    words = _js()[_js().index("const ATTESTATION_WORDS"):]
    words = words[:words.index("};")]
    for level in ("A:", "B:", "C:"):
        assert level in words
    assert "vouches for nothing" in words


def test_selector_candidates_are_rows_and_not_a_tooltip():
    row = _code(_fn("callRow"))
    assert "p.title = cands" not in row
    assert "for (const x of cands)" in row and "copyable(" in row
    from noctornal_api.deception import merge_candidates, selector_candidates_for_call
    call = {"p_asserted_identity": "sip:44471@trunk-04.example",
            "sip_from_uri": "sip:44471@trunk-04.example",
            "called_number_e164": "+442071838750"}
    merged = merge_candidates(selector_candidates_for_call(call))
    uris = [c for c in merged if c["selector_type"] == "SIP_URI"]
    assert len(uris) == 1, "the same SIP URI is listed twice"
    assert len(uris[0]["reasons"]) == 2
    assert "sip_from_uri" not in uris[0]["why"], "a column name reaches the row"


def test_the_presented_number_is_shown_as_displayed_first():
    row = _fn("callRow")
    first = row.index("c.presented.number\n") if "c.presented.number\n" in row \
        else row.index("c.presented.number ||")
    assert first < row.index("c.presented.number_e164"), (
        "the E.164 form is shown as what the victim saw")


# ---------------------------------------------------------------------------
# ux14-deception:no-deception-ingest-ui
# ---------------------------------------------------------------------------

def test_all_three_channels_can_be_recorded_from_the_console():
    html = _html()
    for form in ("dcp-cap-new", "dcp-eml-new", "dcp-call-new"):
        assert f'id="{form}"' in html, f"#{form} is missing"
    assert "cpath('/deception/captures'), {" in _fn("saveCapture")
    assert "cpath('/deception/emails'), { method: 'POST', form }" in _fn("saveEmail")
    assert "cpath('/deception/calls'), {" in _fn("saveCall")
    wire = _fn("wireDeceptionForms")
    for save in ("saveCapture", "saveEmail", "saveCall"):
        assert save in wire


def test_the_forms_hold_the_legal_fields_the_table_holds():
    cap = _fn("saveCapture")
    assert "submitted && !authority" in cap, "L5 input is sent without its authority"
    call = _fn("saveCall")
    assert "recording && !basis" in call, "an L4 recording is sent without its basis"
    # The presented and the recorded halves are separate groups on the form.
    html = _html()
    form = html[html.index('id="dcp-call-new"'):html.index('id="dcp-call-list"')]
    assert "presented-block" in form and "recorded-block" in form


def test_each_empty_state_says_how_records_arrive():
    html = _html()
    for empty in ("dcp-cap-empty", "dcp-eml-empty", "dcp-call-empty"):
        # `hidden` until the list answers (ux17-failure:loading-shows-empty-claims).
        text = re.search(r'<p id="' + empty + r'" class="empty"[^>]*>([^<]*)</p>', html)
        assert text and "ingest API" in text.group(1), f"#{empty} gives no next step"


def test_the_forms_are_emptied_on_a_case_switch():
    js = _js()
    start = js.index("/* --- deception: phishing captures, BEC email")
    region = _code(js[start:js.index("/* --- wiring ---", start)])
    m = re.search(r"onCaseSwitch\(\(\) => \{(.*?)\}\);", region, re.S)
    assert m
    for form in ("dcp-cap-new", "dcp-eml-new", "dcp-call-new"):
        assert f"dcpResetForm('{form}')" in m.group(1)


# ---------------------------------------------------------------------------
# ux14-deception:web-durable-ids-missing
# ---------------------------------------------------------------------------

def test_the_capture_shows_asn_certificate_age_and_favicon():
    detail = _fn("openCapture")
    for read in ("h.asn", "h.server_header_defanged", "c.tls_not_before",
                 "c.favicon_hash", "certificateAge(c)"):
        assert read in detail, f"the capture detail does not show {read}"
    age = _fn("certificateAge")
    assert "c.first_lure" in age and "before" in age and "old when captured" in age
    assert "end.asn" in _fn("captureRow")
    router = _router()
    assert "tls_not_before: date | None" in router, (
        "the API still cannot record a certificate's issue date")
    assert 'capture["first_lure"] = svc.first_lure(' in router

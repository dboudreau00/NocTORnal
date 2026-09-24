"""The Lab pane's second round of fixes (review of 2026-09-22, closed on
2026-09-23), held by reading the shipped console and the sample router.

Beside `test_lab_ui_invariants.py`, which holds the first round. Each test
names the finding it holds. Pure: no database, no browser.
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


def _router() -> str:
    return (SRC / "http" / "routers" / "samples.py").read_text(encoding="utf-8")


def _code(text: str) -> str:
    """JavaScript with its comments removed."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def _fn(name: str) -> str:
    """A top-level function's body, closed on the first `}` at column 0."""
    js = _js()
    m = re.search(rf"^(async )?function {name}\(", js, re.M)
    assert m, f"function {name} is gone"
    return js[m.start():js.index("\n}", m.start())]


def _lab() -> str:
    js = _js()
    start = js.index("/* ── LAB: malware samples")
    return js[start:js.index("/* ── live change hints", start)]


def _route(name: str) -> str:
    src = _router()
    start = src.index(f"def {name}(")
    start = src.rindex("@router.", 0, start)
    nxt = src.find("\n@router.", start + 10)
    return src[start:nxt if nxt > 0 else len(src)]


# ---------------------------------------------------------------------------
# ux13-lab:no-assign-or-record-analysis
# ---------------------------------------------------------------------------

def test_a_malware_analyst_can_assign_and_record_from_the_card():
    """The API had assign and analysis routes and the console called
    neither, so the lifecycle the filter advertises could not be advanced
    and findings would be recorded outside the system."""
    work = _fn("sampleWorkPanel")
    assert "'/assign'" in work, "the card has no way to assign a sample"
    assert "el('select'" in work, "the assignee is not picked from a list"
    assert "people.assignees" in work
    assert "analysisForm(s, people, msg)" in work
    form = _fn("analysisForm")
    assert "'/analysis'" in form
    for field in ("kind:", "tool:", "tool_version:", "narrative:",
                  "yara_hits:", "family_assessment:", "confidence:",
                  "findings:", "extracted_selectors:"):
        assert field in form, f"the record form does not send {field}"
    # A family without a confidence is refused before it is sent.
    assert "A family needs a confidence." in form
    assert "sampleWorkPanel(s, you, people)" in _fn("openSample")


def test_recorded_findings_selectors_and_the_analyst_are_drawn():
    """The Analysis renderer ignored `findings`, `extracted_selectors` and
    `analyst_id`, which the service returns."""
    row = _fn("analysisRow")
    for read in ("a.findings", "a.extracted_selectors", "a.analyst_name",
                 "a.tool_version"):
        assert read in row, f"an analysis no longer shows {read}"
    assert "el('dl', 'kv')" in row, "findings are not a key and value list"
    sel = _fn("extractedSelector")
    assert "copyable(" in sel, "an extracted selector cannot be copied"
    assert "'/propose'" in sel and "json: { index }" in sel, (
        "a selector is not proposed by naming its entry")
    # The service returns what the console reads.
    svc = (SRC / "samples.py").read_text(encoding="utf-8")
    assert '"analyst_name": r[12]' in svc and '"tool_version": r[11]' in svc


def test_the_propose_route_derives_the_proposal_and_takes_only_an_index():
    """A queue that took caller-authored proposals would be a way to push
    arbitrary suggestions at an analyst (routers/proposals.py)."""
    route = _route("propose_selector")
    assert "index: int" in _router()
    assert "_visible_or_404(conn, user, sample_id)" in route
    assert 'require_global("sample.analyse")' in route
    svc = (SRC / "samples.py").read_text(encoding="utf-8")
    body = svc[svc.index("def propose_extracted_selector("):]
    body = body[:body.index("\n    def ", 10)]
    # The read-only states by the shared set, not a literal copy (c7,
    # 2026-09-24); the route also calls the gate's own refusal first.
    for refusal in ("not attached to a case", "in CONTENT_READ_ONLY_STATES",
                    "compartments its case"):
        assert refusal in body, f"proposing no longer refuses: {refusal}"
    assert '_refuse_if_read_only(conn, user, sample, "sample.analyse")' in route
    assert "ProposalStore(self._c).propose(" in body


def test_proposing_answers_the_same_whatever_the_case_holds():
    """The verifier's existence oracle (2026-09-23): a malware analyst holds
    no case access, and the answer said which of the values they typed were
    entities in the case (with node ids), which were proposed and in what
    state, and the case's code."""
    svc = (SRC / "samples.py").read_text(encoding="utf-8")
    body = svc[svc.index("def propose_extracted_selector("):]
    body = body[:body.index("\n    def ", 10)]
    code = body[body.index('"""', body.index('"""') + 3) + 3:]
    for leak in ('"case_code"', '"IN_GRAPH"', '"created"'):
        assert leak not in code, f"the answer can still carry {leak}"
    # Every answer is the one `sent` dict: node and proposal ids reach only
    # the audit detail.
    returns = re.findall(r"\breturn (\S+)", code)
    assert returns and set(returns) == {"sent"}, returns
    assert 'sent = {"sent": True, "label": norm}' in code
    # Which it was goes to the audit trail instead.
    for outcome in ('"queued"', '"already_proposed"', '"already_in_graph"'):
        assert outcome in code
    # And the closed-case refusal no longer names the case.
    assert "f\"{code} is" not in code
    assert "status_code=202" in _route("propose_selector")
    sel = _code(_fn("extractedSelector"))
    assert "r.case_code" not in sel and "IN_GRAPH" not in sel
    assert "r.sent" in sel and "sampleCaseCode(s.case_id)" in sel


def test_assign_analysis_and_detonation_refuse_a_sample_the_caller_cannot_see():
    """Each took a sample by uuid alone, the shape CR11 closed on reject."""
    for name in ("assign", "record_analysis", "request_detonation", "people"):
        assert "_visible_or_404(conn, user, sample_id)" in _route(name), name
    assign = _route("assign")
    assert "eligible_assignees(sample_id)" in assign, (
        "any uuid can still be assigned the sample")


# ---------------------------------------------------------------------------
# ux13-lab:detail-opens-offscreen
# ---------------------------------------------------------------------------

def test_the_card_opens_under_its_row_takes_focus_and_marks_the_row():
    """The card sat after the whole queue and opened off-screen, so Open
    looked like it did nothing."""
    open_ = _fn("openSample")
    assert "smpPlaceDetail()" in open_
    assert "heading.focus({ preventScroll: true })" in open_
    assert "scrollIntoView(" in open_
    place = _fn("smpPlaceDetail")
    assert "row.after($('smp-detail'))" in place
    assert "'aria-current', 'true'" in place and "'is-open'" in place
    assert "'aria-expanded'" in place
    tag = re.search(r'<h2[^>]*id="smp-detail-title"[^>]*>', _html())
    assert tag and 'tabindex="-1"' in tag.group(0), (
        "the card's heading cannot take focus")


def test_the_card_is_parked_before_the_list_is_redrawn():
    """The card can sit inside the list; emptying the list with it inside
    would take it out of the document."""
    loader = _fn("loadSamples")
    for render in [m.start() for m in re.finditer(r"renderList\('smp-list'", loader)]:
        before = loader[:render]
        assert "smpParkDetail();" in before[before.rfind("\n  ") - 200:], (
            "the list is redrawn with the card possibly still inside it")
    assert "smpPlaceDetail();" in loader


def test_close_puts_focus_back_on_the_row_it_came_from():
    close = _fn("smpCloseDetail")
    assert "was.opener.focus()" in close
    assert "smpCloseDetail(true)" in _js()


def test_close_still_finds_the_row_after_an_action_redrew_the_list():
    """The verifier (2026-09-23): assign, record and reject redraw the list
    and re-open the card with no opener, so the card kept the old,
    disconnected Open button and Close dropped focus on the page."""
    place = _code(_fn("smpPlaceDetail"))
    assert "smpOpen.opener.isConnected" in place
    assert "smpOpen.opener = row.querySelector('.smp-open')" in place, (
        "the redrawn row's button does not replace the disconnected one")
    close = _code(_fn("smpCloseDetail"))
    assert "$('pane-samples').focus(" in close, (
        "with the row gone, focus falls to the page")
    assert re.search(r'<section id="pane-samples"[^>]*tabindex="-1"',
                     _html().replace("\n", " ")), "the pane cannot take focus"
    # The actions that redraw really do re-open without an opener.
    assert "await openSample(s.id);" in _lab()


# ---------------------------------------------------------------------------
# ux13-lab:submit-form-ignores-refusal-and-scope
# ---------------------------------------------------------------------------

def test_submit_is_closed_with_the_reason_while_ingest_is_refused():
    gate = _fn("paintSubmitGate")
    assert "!p.policy_declared" in gate
    assert "$('smp-submit').disabled = refused" in gate
    assert "$('smp-refusal')" in gate and "smpContact(p)" in gate
    assert 'id="smp-refusal"' in _html()
    assert "paintSubmitGate()" in _fn("loadSamplePolicy")


def test_submit_offers_the_analysts_own_compartments_and_sends_them():
    gate = _fn("paintSubmitGate")
    assert "p.your_compartments" in gate
    assert "p.your_clearance" in gate, "a label above the clearance is offered"
    assert "form.append('compartments'" in _fn("submitSample")
    assert 'id="smp-compartments"' in _html()
    policy = _route("policy_status")
    for key in ('"your_compartments"', '"your_clearance"', '"designated_person"'):
        assert key in policy


# ---------------------------------------------------------------------------
# ux13-lab:label-chip-understates-handling
# ---------------------------------------------------------------------------

def test_the_chips_show_the_labels_a_sample_is_handled_at():
    for fn in ("sampleRow", "sampleProvenance"):
        body = _fn(fn)
        assert "sampleLabelChips(s)" in body, f"{fn} shows the sample's own labels"
        assert "labelChips(s)" not in body.replace("sampleLabelChips(s)", "")
    chips = _fn("sampleLabelChips")
    for read in ("s.effective_classification", "s.effective_compartments",
                 "s.inherited_compartments", "s.classification_inherited"):
        assert read in chips
    # Said in the chip's own text, not only on hover.
    assert "' (from its case)'" in chips
    router = _router()
    for field in ("effective_classification", "effective_compartments",
                  "inherited_compartments", "classification_inherited"):
        assert field in router


# ---------------------------------------------------------------------------
# ux13-lab:lab-times-utc-unlabelled
# ---------------------------------------------------------------------------

def test_every_lab_time_is_utc_and_says_so():
    """The Lab sliced the ISO string, which is UTC with no label, while the
    rest of the console used the browser's zone. Every time in the Lab now
    goes through fmtTime, which prints UTC and says so."""
    lab = _code(_lab())
    # The old shape: an ISO string cut to the minute and its T replaced.
    assert ".slice(0, 16).replace('T'" not in lab
    assert not re.search(r"_at\)?\.slice\(0, 1[0-9]\)", lab), (
        "a timestamp is cut out of its ISO string instead of formatted")
    assert "toLocaleString(" not in lab
    fmt = _fn("fmtTime")
    assert "getUTCHours()" in fmt and "' UTC'" in fmt
    for fn in ("sampleRow", "sampleProvenance", "custodyPanel",
               "detonationRow", "analysisRow"):
        assert "fmtTime(" in _fn(fn), f"{fn} prints a time some other way"


# ---------------------------------------------------------------------------
# ux13-lab:detonation-authoriser-uuid
# ---------------------------------------------------------------------------

def test_the_authoriser_is_picked_by_name_and_echoed():
    panel = _fn("detonationPanel")
    assert "user id of the person" not in panel
    assert "people.detonation_authorisers" in panel
    assert "const auth = el('select'" in panel
    assert "out.authorised_by_name" in panel, (
        "the confirmation does not name who signed it off")
    svc = (SRC / "samples.py").read_text(encoding="utf-8")
    det = svc[svc.index("def request_detonation("):]
    det = det[:det.index("\n    def ", 10)]
    assert "authorised_by == requested_by" in det, "a requester can sign off their own"
    assert "detonation_authorisers(" in det


# ---------------------------------------------------------------------------
# ux13-lab:legal-banner-copy
# ---------------------------------------------------------------------------

def test_the_banner_says_it_once_in_the_analysts_words_and_folds():
    policy = _fn("loadSamplePolicy")
    assert "'Counsel must review this deployment.'" not in policy, (
        "the banner prints its own copy of the notice's first sentence again")
    assert "smpStatusLine(smpPolicy)" in policy
    assert "el('details', 'legal-fold')" in policy
    assert "smpRememberBanner(" in policy
    for helper in ("smpBannerFolded", "smpRememberBanner"):
        body = _fn(helper)
        assert "try {" in body and "catch" in body, (
            f"{helper} touches browser storage without a guard")
    # No environment variable names reach an analyst in the Lab.
    lab = _code(_lab())
    literals = re.findall(r"'(?:[^'\\]|\\.)*'", lab)
    assert not [s for s in literals if "NOCTORNAL_" in s], (
        "the Lab shows an operator setting name to an analyst")
    route = _route("policy_status")
    notice = route[route.index('"notice": ('):]
    notice = notice[:notice.index("),")]
    assert "absolute sense" not in notice, "the notice's garbled phrase is back"
    assert notice.count("Counsel must review") == 1


# ---------------------------------------------------------------------------
# gap-reject-step-up
# ---------------------------------------------------------------------------

def test_rejecting_needs_a_fresh_sign_in_server_and_console():
    reject = _route("reject")
    assert "_fresh: None = Depends(require_step_up)" in reject, (
        "the reject route does not demand a fresh sign-in")
    actions = _fn("sampleActions")
    send = actions[actions.index("go.addEventListener('click'"):]
    assert "smpSend(" in send and "'Rejecting a sample'" in send
    helper = _fn("smpSend")
    assert "stepUpStale()" in helper, "the sign-in is not asked for first"
    assert "confirmIdentity(" in helper
    assert "smpNeedsSignIn(err)" in helper and "SESSION.stepUpUntil = 0" in helper
    # The download mint and the detonation ride the same path.
    assert "smpSend(" in _fn("downloadSample")
    assert "smpSend(" in _fn("detonationPanel")

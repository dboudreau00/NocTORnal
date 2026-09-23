"""The Lab pane's fixes from the review of 2026-09-22, held by reading the
shipped console.

Beside test_ui_invariants.py and for the same reason: the console is plain
JavaScript with no build step, so a property like "the filter goes to the
server" is checkable by reading the file, and one nobody checks survives
until the first refactor. Each test names the finding it holds.

Pure: no database, no browser.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


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


def _object(name: str) -> str:
    js = _js()
    start = js.index(f"const {name} = {{")
    return js[start:js.index("};", start)]


def test_the_state_filter_is_asked_of_the_server():
    """ux13-lab:rejected-filter-always-empty. The queue fetched the working
    set and filtered it here, so Rejected, In analysis and Reported could
    never show a row, and a rejected sample vanished for good."""
    body = _fn("loadSamples")
    assert "params.set('state', wanted)" in body
    assert "s.state === wanted" not in body, (
        "the queue is filtered client-side again; the server only sends the "
        "working set, so three filters go permanently empty")
    html = _html()
    select = html[html.index('id="smp-state"'):]
    select = select[:select.index("</select>")]
    offered = set(re.findall(r'<option value="([A-Z_]+)"', select))
    words = _object("SAMPLE_STATE_WORDS")
    for state in offered:
        assert f"{state}:" in words, (
            f"the {state} filter has no words for its count or empty state")
    from noctornal_api.samples import QUEUE_STATES
    assert offered == set(QUEUE_STATES), (
        "the filter offers a state the server does not answer, or misses one")


def test_each_empty_state_says_what_it_was_filtered_by():
    """"Nothing in the queue." under a Rejected filter read as "nothing was
    ever rejected"."""
    body = _fn("sampleEmptyText")
    assert "SAMPLE_STATE_WORDS[wanted]" in body
    assert "cleared to see" in body
    assert "Nothing in the queue." not in _html()


def test_the_lab_in_a_case_lists_that_case_and_names_cases_by_code():
    """ux13-lab:lab-not-case-scoped, ux19-copy:lab-shows-other-case-samples.
    The Lab under OP-KESTREL-26 listed OP-NIGHTJAR-26's six samples, the
    badge counted them, and each card said only "CASE e2c7d48f"."""
    loader = _fn("loadSamples")
    assert "params.set('case_id', state.caseId)" in loader
    assert "smpAllCases" in loader, "there is no way to widen the scope"
    badge = _fn("refreshSampleBadge")
    assert "case_id=" in badge, "the badge counts every case's samples"
    assert "caseChanged(token)" in badge
    assert "on ' + state.caseRec.code" in _fn("paintSampleBadge"), (
        "the badge does not say which case it counts")
    assert "case_id.slice(" not in _lab(), (
        "a case is named by a uuid prefix nobody can map to anything")
    named = _fn("sampleCaseFact")
    assert "state.cases" in named and "c.code" in named
    assert "a case you cannot open" in named
    assert 'id="smp-all-cases"' in _html()


def test_the_lab_resets_on_a_case_switch_and_drops_stale_reads():
    """The 2026-09-22 case-switch registry: a pane that shows case-scoped
    data registers its reset, and its reads drop a reply that lands after
    a newer switch."""
    lab = _lab()
    assert "onCaseSwitch(() => {" in lab
    reset = lab[lab.index("onCaseSwitch(() => {"):]
    reset = reset[:reset.index("});")]
    for cleared in ("smp-list", "smp-detail", "samples-badge", "smpAllCases"):
        assert cleared in reset, f"a case switch leaves {cleared} standing"
    for name in ("loadSamples", "openSample", "refreshSampleBadge"):
        body = _fn(name)
        assert "caseToken()" in body and "caseChanged(token)" in body, name


def test_rejecting_asks_first_and_names_the_sample():
    """ux13-lab:reject-one-click-destroy. One click sent purge_bytes true
    and destroyed the bytes and the key, from a card that did not name the
    sample. Now nothing is sent until a confirmation that names the file,
    the hash and the case, and states the disposition, is confirmed."""
    body = _fn("sampleActions")
    ask = body.index("'Reject this sample?'")
    send = body.index("'/reject'")
    assert ask < send, "the rejection is sent before it is confirmed"
    confirm = body[ask:send]
    for named in ("visibleText(s.original_filename)", "s.sha256.slice(0, 16)",
                  "sampleCaseFact(s.case_id)", "sentence"):
        assert named in confirm, f"the confirmation does not state {named}"
    click = body[body.index("rejBtn.addEventListener('click'"):send]
    assert "rejectOutcome(!purged)" in click, (
        "the disposition stated is not the one for what will be sent")
    assert "go.addEventListener('click'" in click, (
        "the request is not inside the confirm button's handler")
    assert "'Why it is rejected'" in body, "the reason field has no label"
    outcome = _fn("rejectOutcome")
    assert "preservation store" in outcome and "DESTROYED" in outcome
    assert "rejected_sample_disposition" in outcome, (
        "the confirmation does not read what THIS deployment does")


def test_the_access_ledger_names_who_and_what():
    """ux13-lab:custody-ledger-hides-who-and-what. Rows showed only the
    action and the time, a submission and a failed integrity check both
    read VIEWED_META, and the help text promised looks were recorded when
    none were."""
    line = _fn("custodyLine")
    for event in ("'submitted'", "'viewed'", "'integrity_check_failed'"):
        assert event in line, f"{event} has no words of its own"
    assert "'alarm'" in line, "a failed integrity check is not styled as one"
    panel = _fn("custodyPanel")
    assert "smpPerson(c.actor_name, c.actor_email)" in panel
    assert "Every look is a row" not in _js()


def test_triage_gaps_are_named_by_the_check_that_never_ran():
    """ux13-lab:triage-gap-names-dropped. The card read `g.what || g.kind`
    and the service writes `step`, so every gap was headed "gap"."""
    js = _js()
    assert "g.what || g.kind || 'gap'" not in js
    assert "g.step" in _fn("gapStep")
    names = _object("TRIAGE_GAP_NAMES")
    from noctornal_api.samples import triage
    for gap in triage(b"MZ").gaps:
        assert f"{gap['step']}:" in names, (
            f"triage writes {gap['step']!r} and the console has no name for it")
    assert "PROHIBITED_GAP" in _fn("orderedGaps"), (
        "prohibited-content screening is not pinned first")
    assert "Not screened for prohibited content" in _fn("gapSummary")


def test_the_detail_card_shows_provenance():
    """ux13-lab:provenance-never-shown. The source note, the submitter and
    the holder were collected and returned and never displayed, and the
    card did not restate which file it was."""
    prov = _fn("sampleProvenance")
    for read in ("s.source_note", "s.submitted_by_name", "s.assigned_to_name",
                 "quarantinedFilename(s.original_filename)", "stateChip(",
                 "sampleCaseFact(s.case_id)"):
        assert read in prov, f"the provenance block does not show {read}"
    assert "sampleProvenance(s)" in _fn("openSample")
    row = _fn("sampleRow")
    assert "s.source_note" in row and "s.submitted_by_name" in row


def test_a_preserved_sample_says_how_it_comes_back():
    """F2: the Lab shows a preserved sample as preserved and says retrieval
    needs a Security Officer's authorisation. The retrieval rides the same
    two legs as a download, so the one cross-origin fetch stays one."""
    panel = _fn("preservationPanel")
    assert "Security Officer" in panel
    assert "'/preserved/retrieval-ticket'" in panel
    assert "downloadSample(s, msg," in panel
    assert "preserved:" in _object("DISPOSITION_TEXT")
    assert _js().count("fetchFromSampleOrigin(") == 1, (
        "a second cross-origin fetch appeared; the retrieval must reuse "
        "downloadSample's one call")


def test_the_lab_writes_no_dashes_a_reader_can_see():
    """The owner treats em and en dashes in UI copy as an unacceptable
    tell. Comments are not read by users; string literals are."""
    offenders = []
    for i, line in enumerate(_lab().splitlines(), 1):
        code = line.split("//")[0]
        if code.lstrip().startswith(("*", "/*")):
            continue
        for literal in re.findall(r"'(?:[^'\\]|\\.)*'", code):
            if "\u2014" in literal or "\u2013" in literal:
                offenders.append((i, literal))
    assert not offenders, offenders

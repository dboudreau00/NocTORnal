"""The console's case switching, failed reads, report pane and dates.

The review of 2026-09-22 found each of these wrong in a way no existing
check could see, because every one of them rendered SOMETHING:

- ux02-cases / ux17-failure / ux12-feeds / ux15-report: after "All cases >
  Open", the previous case's report, watch hits, entities, exhibits and ACH
  matrix stayed on screen under the new case's code and TLP chip.
- ux17-failure:failure-renders-as-empty-claim: a failed read drew the
  pane's EMPTY state, so the triage queue said "Nothing awaiting review."
  and the destruction register "Nothing has been destroyed." at the moment
  the console knew nothing.
- ux15-report: the preview printed "undefined -> undefined" for every
  relationship, and Download handed over a file with no egress check.
- ux05-inspector / ux19-copy: a day stored as midnight UTC read back as the
  previous evening west of Greenwich, and panes mixed local time with
  unlabelled UTC.
- ux02-cases:case-status-invisible-in-workspace: nothing in a CLOSED case
  said it was closed.

Pure: these read the shipped static assets (and, for the date helpers, run
them under node when it is installed, in a zone west of UTC). They live in
their own file so they do not collide with the other review groups' edits
to test_ui_invariants.py.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")
SRC = STATIC.parents[1]
APP_JS = STATIC / "app.js"
INDEX = STATIC / "index.html"
APP_CSS = STATIC / "app.css"

DASHES = ("\u2014", "\u2013", "&mdash;", "&ndash;")


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _html() -> str:
    return INDEX.read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """A top-level function's source, closed on the first `}` at column 0."""
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _resets() -> list[str]:
    """The body of every `onCaseSwitch(() => { ... });` registration."""
    js = _js()
    out = []
    for m in re.finditer(r"\nonCaseSwitch\(\(\) => \{", js):
        out.append(js[m.start():js.index("\n});", m.start())])
    return out


# ---------------------------------------------------------------------------
# Case switching
# ---------------------------------------------------------------------------

#: Every case-scoped surface this group owns, by the element its reset
#: must clear. A registration that forgets one of these leaves the previous
#: case's rows under the new header, which is the defect.
_CLEARED_ON_SWITCH = {
    # the case file itself (ux17-failure:stale-previous-case-data), and the
    # write pickers built from it, which offered the old case's entities
    "ent-body", "ev-list", "ach-matrix", "ach-ranking", "tl-note",
    "edge-src", "edge-dst", "node-evidence", "edge-evidence",
    # triage (the badge is the only signal work is waiting)
    "triage-list", "triage-badge",
    # comms results (case-switch-carries-previous-case-results)
    "comms-pgp-out", "comms-copart", "comms-copart-coverage",
    "comms-correlate-out", "comms-block-out", "comms-unverified",
    # and what was typed or pasted for the case being left (fix round): a
    # contact block pasted on one case and submitted after a switch was
    # parsed into the other
    "comms-observed", "comms-codecl", "comms-corr-observed",
    "comms-block-source", "comms-block-handle", "comms-block-text",
    "comms-pgp-message", "comms-pgp-key", "comms-pgp-fpr", "comms-pgp-confirms",
    "comms-preview",
    # feeds (collected-stale-across-case-switch) and the case queue
    "col-hits-list", "col-hits-counts", "ing-list",
    # the destruction register
    "tomb-list",
    # final review, 2026-09-23 (g06): the Analysis pane (C3) and the forms
    # whose typed content was written into the next case (C18, U14)
    "an-body", "an-leads", "an-hist-body", "an-hist-who", "an-run",
    "cap-text", "cap-title", "cap-url", "ev-file", "ev-title",
    "ach-statement", "asm-statement", "asm-basis",
    "smp-file", "smp-note", "smp-case",
}


def test_every_case_scoped_pane_registers_a_reset():
    resets = "\n".join(_resets())
    missing = sorted(i for i in _CLEARED_ON_SWITCH if f"'{i}'" not in resets)
    assert not missing, (
        "these case-scoped elements are not cleared on a case switch, so the "
        f"previous case's content survives under the new header: {missing}")


def test_the_report_pane_is_reset_on_a_switch_and_resets_everything():
    """A NIGHTJAR preview and a green "May leave" line stood under a
    KESTREL header while Check egress acted on KESTREL."""
    assert any("resetReport()" in body for body in _resets()), (
        "no case-switch reset calls resetReport")
    full = _fn("resetReport") + _fn("resetReportVerdict")
    for element in ("rep-redaction", "rep-body", "rep-release-box",
                    "rep-release-out", "rep-release-msg", "rep-download",
                    "rep-empty", "rep-msg"):
        assert f"'{element}'" in full, f"resetReport leaves #{element} standing"
    assert "state.report = null" in full
    assert "reportCleared = null" in full


def test_both_ways_of_leaving_a_case_run_the_resets():
    assert "runCaseSwitchResets();" in _fn("openCase")
    assert "runCaseSwitchResets();" in _fn("showCaseList")


#: Loaders whose answer belongs to one case. Each must take a token before
#: it awaits and drop a reply that a newer switch has overtaken.
_GUARDED = ("openCase", "loadCaseGraph", "loadEvidence", "loadAch",
            "loadTriage", "loadWatchHits", "loadIngestQueue", "loadTombstones",
            "loadUnverified", "loadCoParticipation", "verifyPgp",
            "buildReport", "releaseReport",
            # the comms writes whose replies rendered into the next case's
            # pane (fix round, 2026-09-22)
            "initCommsBind", "initCommsBlocks", "initCommsCorrelate",
            # final review, 2026-09-23 (g06): the Analysis pane (C3), the
            # saved layout and presets (U15), and the writes whose replies
            # landed in the next case's pane (C18, U14)
            "runAnalysis", "loadLatestAnalysis", "loadMetricHistory",
            "loadLayout", "loadPresets", "runCapture", "uploadEvidence",
            "submitSample")


@pytest.mark.parametrize("name", _GUARDED)
def test_a_late_reply_for_a_case_the_analyst_left_is_dropped(name):
    body = _fn(name)
    assert "caseToken()" in body, f"{name} takes no case token before it awaits"
    assert "caseChanged(token)" in body, (
        f"{name} renders whatever arrives, including a reply for the case "
        "the analyst has since left")


def test_a_comms_write_answered_after_a_switch_is_not_drawn_in_the_new_case():
    """The contact-block parse and the binding took no token, so a reply
    for the case the analyst had left rendered in the output the switch
    had just cleared (verifier, fix round of 2026-09-22)."""
    blocks = _fn("initCommsBlocks")
    assert blocks.index("caseChanged(token)") < blocks.index(
        "renderContactBlock(block)")
    assert blocks.count("caseChanged(token)") >= 2, (
        "a failure for the case left behind is drawn in this one")
    bind = _fn("initCommsBind")
    assert bind.index("caseChanged(token)") < bind.index(
        "setMsg(msg, body.durable_value")
    assert bind.count("caseChanged(token)") >= 2
    # Where the write went is still said, because it did happen.
    assert "banner(" in blocks and "banner(" in bind


def test_open_case_stops_when_overtaken_and_never_keeps_the_old_header():
    body = _fn("openCase")
    # One check after the record and after every awaited load.
    assert body.count("if (caseChanged(token)) return;") >= 6
    head = body[:body.index("try {")]
    assert "show($('hdr-tlp'), false)" in head, (
        "the previous case's TLP chip stays up while the next case loads")
    assert "'Opening '" in head


# ---------------------------------------------------------------------------
# A failed read is not an empty list
# ---------------------------------------------------------------------------

def test_the_failure_notice_is_a_sibling_and_says_unknown():
    body = _fn("showLoadFailure")
    assert "insertBefore(box, empty)" in body, (
        "the failure must not be written INTO the empty element: several "
        "empties are only ever shown or hidden, so the text would outlive "
        "the failure and caption the next genuinely empty read")
    assert "loadFailureText(what, err)" in body
    assert "unknown, not empty" in _fn("loadFailureText")
    assert "'Retry'" in body
    assert "clearLoadFailure(emptyId);" in _fn("renderList"), (
        "a successful render must remove an earlier failure notice")


def test_the_failure_sentence_is_grammatical_for_any_subject():
    """Behavioural. The notice built "<what> was refused", so a 403 on the
    inbox read "Your notifications was refused" (verifier, fix round of
    2026-09-22). Runs the shipped function on singular and plural subjects
    and on both kinds of failure."""
    js = _js()
    source = (js[js.index("function failureReason("):
                 js.index("function showLoadFailure(")]
              + js[js.index("class ApiError extends Error {"):
                   js.index("async function problemOf(")])
    script = source + """
const deny = new ApiError(403, 'Forbidden', 'needs notification.read');
const down = new ApiError(503, 'Service Unavailable', '');
console.log(JSON.stringify([
  loadFailureText('Your notifications', deny),
  loadFailureText('The triage queue', deny),
  loadFailureText("This case's exhibits", down),
  loadFailureText('The triage queue', down),
]));
"""
    got = json.loads(_run_node(script))
    assert got == [
        "Access to your notifications was refused (HTTP 403: needs "
        "notification.read). Until a read succeeds, this is unknown, not empty.",
        "Access to the triage queue was refused (HTTP 403: needs "
        "notification.read). Until a read succeeds, this is unknown, not empty.",
        "This case's exhibits could not be loaded (HTTP 503: Service "
        "Unavailable). Until a read succeeds, this is unknown, not empty.",
        "The triage queue could not be loaded (HTTP 503: Service "
        "Unavailable). Until a read succeeds, this is unknown, not empty.",
    ], got
    assert not any(d in s for s in got for d in DASHES)


#: (loader, the empty element whose claim it must not make on failure)
_FAILURE_SITES = (
    ("loadTriage", "triage-empty"),
    ("loadInbox", "inbox-empty"),
    ("loadTombstones", "tomb-empty"),
    ("loadCaseGraph", "ent-empty"),
    ("loadEvidence", "ev-empty"),
    ("loadAch", "ach-empty"),
    ("loadIngestQueue", "ing-empty"),
    ("loadKeys", "key-empty"),
    ("loadDeadLetters", "dl-empty"),
    ("loadUnverified", "comms-unverified-empty"),
    ("loadCoParticipation", "comms-copart-empty"),
    ("loadWatchHits", "col-hits-empty"),
    ("loadSources", "src-never-empty"),
)


@pytest.mark.parametrize("loader,empty_id", _FAILURE_SITES)
def test_a_failed_read_says_so_in_the_pane(loader, empty_id):
    assert f"showLoadFailure('{empty_id}'" in _fn(loader), (
        f"{loader} renders its empty state on a failed read, so #{empty_id} "
        "asserts an absence the console never checked")


def test_the_triage_and_inbox_empties_stay_hidden_after_a_failure():
    assert "!state.triageFailed" in _fn("renderTriage")
    assert "!state.inboxFailed" in _fn("renderInbox")
    badge = _fn("renderTriageBadge")
    assert "state.triageFailed" in badge and "'?'" in badge, (
        "an unreadable queue hides the badge, which reads as nothing waiting")


def test_never_polled_is_unknown_when_its_response_did_not_arrive():
    body = _fn("loadSources")
    assert "(body && body.never_polled) || []" not in body, (
        "the never-polled list is rendered from [] when the read failed, "
        "which announces 'Every source has been polled.'")


# ---------------------------------------------------------------------------
# The report pane
# ---------------------------------------------------------------------------

def test_the_preview_reads_the_fields_the_server_sends():
    """Both sides of the contract, so a rename on either fails here."""
    pane = _fn("renderReportBody")
    for dead in ("r.source_label", "r.source_id", "r.target_label",
                 "r.target_id", "r.edge_type", "a.node_type"):
        assert dead not in pane, f"the preview reads {dead}, which is never sent"
    for live in ("r.src", "r.dst", "r.type", "a.type", "a.has_evidence",
                 "r.has_evidence", "body.assumptions", "c.legal_basis",
                 "h.statement", "body.document"):
        assert live in pane, f"the preview does not show {live}"
    # The saved copy is rebuilt when it is cleared, so its Generated line
    # differs; the preview must not promise "exactly" (fix round).
    assert "exactly as it would be saved" not in pane
    assert '"Generated" line' in pane
    builder = (SRC / "reports.py").read_text(encoding="utf-8")
    for key in ('"type": n["node_type"]', '"src": str(e["src_node_id"])',
                '"dst": str(e["dst_node_id"])'):
        assert key in builder, f"reports.py no longer emits {key}"


def test_a_file_comes_only_from_the_egress_decision():
    js = _js()
    assert "fmt: 'markdown'" not in js and "fmt=markdown" not in js, (
        "the console still fetches the file from the build endpoint")
    assert "async function downloadReport" not in js
    save = _fn("saveClearedReport")
    assert "reportCleared" in save and ".document" in save
    release = _fn("releaseReport")
    for param in ("prepared.params.target_tlp",
                  "prepared.params.include_hypotheses",
                  "prepared.params.preset"):
        assert param in release, f"the release does not judge the preview's {param}"
    assert "body.content_digest !== prepared.body.content_digest" in release, (
        "a cleared document that is not the previewed one would be offered")
    assert "reportCleared = body" in release

    router = (SRC / "http" / "routers" / "reports.py").read_text(encoding="utf-8")
    assert 'if fmt == "markdown":' in router and "409" in router
    assert "include_hypotheses: bool = True" in router.split("class ReleaseBody")[1]
    assert "preset=body.preset, include_hypotheses=body.include_hypotheses" in router


def test_the_download_anchor_is_attached_and_revoked_later():
    """A detached anchor, or an object URL revoked in the same turn, is a
    download some browsers never start."""
    save = _fn("saveClearedReport")
    assert "document.body.appendChild(link)" in save
    assert re.search(r"setTimeout\(\(\) => URL\.revokeObjectURL\(url\)", save)


def test_every_choice_withdraws_what_depended_on_it():
    js = _js()
    for control in ("rep-tlp", "rep-hypotheses"):
        assert f"$('{control}').addEventListener('change', withdrawReport)" in js, (
            f"changing #{control} leaves a preview made with the old value")
    for control, event in (("rep-destination", "change"),
                           ("rep-ceiling", "change"), ("rep-note", "input")):
        assert (f"$('{control}').addEventListener('{event}', withdrawReportVerdict)"
                in js), f"changing #{control} leaves the old egress verdict up"
    assert "resetReport();" in _fn("withdrawReport")
    assert "resetReportVerdict();" in _fn("withdrawReportVerdict")
    # A reset must also void a request still in flight, not only a result
    # already drawn (verifier, fix round of 2026-09-22).
    assert "reportGen += 1" in _fn("resetReport")
    assert "verdictGen += 1" in _fn("resetReportVerdict")
    assert "gen !== reportGen" in _fn("buildReport")
    assert "gen !== verdictGen" in _fn("releaseReport")


def _report_harness() -> str:
    """The shipped report region under a fake DOM, with `api` held open so
    a test decides when each reply lands. The two renderers are swapped for
    recorders: what is under test is WHETHER a reply is drawn, not how."""
    js = _js()
    start = js.index("let reportCleared = null;")
    rel = js.index("async function releaseReport(")
    region = js[start:js.index("\n}", rel) + 2]
    return """
const nodes = {};
function $(id) {
  if (!nodes[id]) nodes[id] = { id, value: '', checked: false, hidden: false,
    textContent: '', children: [], appendChild(c) { this.children.push(c); } };
  return nodes[id];
}
function el(tag, cls, text) {
  return { tag, cls, textContent: text || '', children: [],
    appendChild(c) { this.children.push(c); } };
}
function clear(n) { n.children = []; }
function show(n, on) { n.hidden = !on; }
function setMsg(n, text) { n.textContent = text || ''; n.hidden = !text; }
function inlineProblem(n, err) { setMsg(n, String(err)); }
function shortId(id) { return String(id).slice(0, 8); }
function fmtTime(v) { return String(v); }
// The release asks for a fresh sign-in when the step-up gate is shut
// (final review C15, g01). A fresh session here; test_report_pane_ui.py
// drives the shut gate.
function stepUpStale() { return false; }
function confirmIdentity() { return Promise.resolve(true); }
function signedIn() { return true; }
const SESSION = { stepUpUntil: null };
class ApiError extends Error {}
const resets = [];
function onCaseSwitch(fn) { resets.push(fn); }
const state = { caseId: 'case-a', caseSeq: 1, caseRec: { code: 'OP-A' },
  proj: { as_of: null }, report: null };
function caseToken() { return state.caseSeq; }
function caseChanged(t) { return t !== state.caseSeq; }
function cpath(p) { return '/cases/' + state.caseId + p; }
const calls = [];
function api(path, opts) {
  return new Promise((resolve, reject) => calls.push({ path, opts, resolve, reject }));
}
const tick = () => new Promise((r) => setTimeout(r, 0));
""" + region + """
let drawn = 0;
renderRedaction = () => { drawn += 1; };
renderReportBody = () => {};
const PREVIEW = { content_digest: 'd1', redaction: { built_at_tlp: 'AMBER' } };
const CLEARED = { classification: 'GREEN', destination: 'smtp',
  content_digest: 'd1', filename: 'OP-A-TLP-GREEN.md', document: '# x' };
function snapshot() {
  return {
    report: state.report ? state.report.params.target_tlp : null,
    drawn,
    releaseBox: !$('rep-release-box').hidden,
    save: !$('rep-download').hidden,
    cleared: reportCleared !== null,
    verdictRows: $('rep-release-out').children.length,
    repMsg: $('rep-msg').textContent,
    releaseMsg: $('rep-release-msg').textContent,
  };
}
"""


def test_a_request_in_flight_is_voided_by_the_choice_that_withdrew_it():
    """Behavioural, the verifier's two reproductions. The listeners used to
    withdraw only what had already arrived, so a Prepare in flight when
    the target changed drew an AMBER preview under a GREEN control, and a
    Check egress in flight when the destination changed drew "May leave
    ... to smtp", with its Save, under in_app."""
    script = _report_harness() + """
(async () => {
  const out = {};

  // Control: nothing changes, so the preview and then the Save appear.
  $('rep-tlp').value = 'AMBER'; $('rep-hypotheses').checked = true;
  $('rep-destination').value = 'smtp';
  buildReport(); await tick();
  calls.shift().resolve(PREVIEW); await tick();
  releaseReport(); await tick();
  calls.shift().resolve(CLEARED); await tick();
  out.control = snapshot();

  // 1. The target changes while Prepare is in flight.
  drawn = 0;
  buildReport(); await tick();
  $('rep-tlp').value = 'GREEN'; withdrawReport();
  calls.shift().resolve(PREVIEW); await tick();
  out.targetChanged = snapshot();

  // 2. The destination changes while Check egress is in flight.
  $('rep-tlp').value = 'GREEN';
  buildReport(); await tick();
  calls.shift().resolve(PREVIEW); await tick();
  releaseReport(); await tick();
  $('rep-destination').value = 'in_app'; withdrawReportVerdict();
  calls.shift().resolve(CLEARED); await tick();
  out.destinationChanged = snapshot();

  // 3. A refusal in flight is voided the same way.
  $('rep-destination').value = 'smtp';
  releaseReport(); await tick();
  $('rep-note').value = 'for the prosecutor'; withdrawReportVerdict();
  calls.shift().reject(new ApiError('refused')); await tick();
  out.refusalAfterNote = snapshot();

  // 4. A case switch while Prepare is in flight.
  drawn = 0;
  buildReport(); await tick();
  state.caseSeq += 1; for (const r of resets) r();
  calls.shift().resolve(PREVIEW); await tick();
  out.caseSwitched = snapshot();

  // 5. A second Prepare overtakes the first; only the second is drawn.
  drawn = 0;
  $('rep-tlp').value = 'AMBER';
  buildReport(); await tick();
  const first = calls.shift();
  buildReport(); await tick();
  const second = calls.shift();
  second.resolve(PREVIEW); await tick();
  first.resolve({ content_digest: 'old', redaction: {} }); await tick();
  out.overtaken = Object.assign(snapshot(),
    { digest: state.report && state.report.body.content_digest });

  console.log(JSON.stringify(out));
})();
"""
    got = json.loads(_run_node(script))

    control = got["control"]
    assert control["report"] == "AMBER" and control["drawn"] == 1
    assert control["save"] and control["cleared"] and control["verdictRows"] >= 1, (
        "the harness never reached a Save, so the checks below prove nothing")

    t = got["targetChanged"]
    assert t["report"] is None and t["drawn"] == 0 and not t["releaseBox"], (
        f"a preview prepared for AMBER was drawn under GREEN: {t}")
    assert "set aside" in t["repMsg"]

    d = got["destinationChanged"]
    assert d["report"] == "GREEN", "the preview itself should survive"
    assert not d["save"] and not d["cleared"] and d["verdictRows"] == 0, (
        f"a verdict for smtp, with its Save, was drawn under in_app: {d}")
    assert "set aside" in d["releaseMsg"]

    r = got["refusalAfterNote"]
    assert r["verdictRows"] == 0 and not r["save"]

    s = got["caseSwitched"]
    assert s["report"] is None and s["drawn"] == 0 and s["repMsg"] == ""

    o = got["overtaken"]
    assert o["drawn"] == 1 and o["digest"] == "d1", (
        f"the slower, older Prepare replaced the newer one: {o}")


def test_the_download_lives_inside_the_release_box():
    html = _html()
    box = html[html.index('id="rep-release-box"'):]
    box = box[:box.index("</details>")]
    assert 'id="rep-download"' in box, (
        "Save must sit with the egress decision it depends on")


# ---------------------------------------------------------------------------
# Dates
# ---------------------------------------------------------------------------

def test_no_time_is_formatted_in_the_browsers_zone_or_locale():
    js = _js()
    for call in ("toLocaleDateString", "toLocaleTimeString"):
        assert call not in js, f"app.js formats a date with {call}"
    fmt = _fn("fmtTime")
    assert "getUTCHours" in fmt and "' UTC'" in fmt
    assert "toLocaleString" not in fmt
    assert "getUTCDate" in _fn("fmtDate")


#: The row builders this group moved off the raw `.slice(0, 16)` pattern,
#: which printed UTC without saying so beside local-time values.
_UTC_LABELLED = ("ingestRow", "deadLetterRow", "unhealthyRow", "neverPolledRow",
                 "dueRow", "personaRow", "runRow", "tombRow", "glassRow",
                 "assumptionRow",
                 # the Lab and Deception sites the fix round moved (the
                 # finding's own evidence is the Lab's "SUBMITTED 15:18")
                 "captureRow", "openCapture", "callRow", "sampleRow",
                 "openSample", "detonationRow")


@pytest.mark.parametrize("name", _UTC_LABELLED)
def test_row_timestamps_go_through_the_labelled_formatter(name):
    body = _fn(name)
    # A timestamp field sliced to its minute or its day. (A digest sliced
    # for display, like a sample's sha256, is not a time.)
    sliced = re.search(
        r"\w+_(?:at|after|before|until)\b[^\n]*\.slice\(0, 1[06]\)", body)
    assert not sliced, f"{name} slices a raw ISO timestamp: {sliced.group(0)}"
    assert "fmtTime(" in body or "fmtDate(" in body, (
        f"{name} shows a time without the UTC formatter")


def test_no_timestamp_is_sliced_anywhere():
    """The whole file, so a new row cannot bring the unlabelled pattern
    back: `.slice(0, 16).replace('T', ' ')` printed UTC with no zone next
    to values that said UTC."""
    assert ".slice(0, 16).replace('T', ' ')" not in _js()


def test_the_observed_at_field_says_utc_and_is_read_as_utc():
    """Every time the console shows is UTC, so the one field that takes a
    time must take it in UTC and say so."""
    html = _html()
    for prefix in ("node", "edge"):
        block = html[:html.index(f'id="{prefix}-observed"')]
        label = block[block.rindex('<span class="label">'):]
        assert "Observed at (UTC)" in label, (
            f"#{prefix}-observed does not say which zone it takes")
    assert "observedAtUtc(observed)" in _fn("assertionFrom")
    assert "value + 'Z'" in _fn("observedAtUtc")


def test_the_inspector_shows_days_as_days_and_both_ends_of_an_interval():
    body = _fn("renderInspector")
    assert "fmtInterval(e.valid_from, e.valid_to)" in body
    assert "fmtInterval(n.valid_from, n.valid_to)" in body
    assert "fmtTime(e.valid_from)" not in body
    assert "fmtWhen(a.observed_at)" in _fn("renderAssertions")


def _node_binary() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    win = Path("C:/Program Files/nodejs/node.exe")
    return str(win) if win.exists() else None


def _run_node(script: str, zone: str | None = None) -> str:
    """Run `script` under node (from stdin: the report harness is longer
    than a Windows command line) and return what it printed. Skips when
    node is not installed; the static checks still run."""
    node = _node_binary()
    if not node:
        pytest.skip("node is not installed; the static checks still run")
    env = dict(os.environ)
    if zone:
        env["TZ"] = zone
    res = subprocess.run([node, "-"], input=script, capture_output=True,
                         text=True, encoding="utf-8", env=env, timeout=60)
    assert res.returncode == 0, res.stderr
    return res.stdout


def _date_helpers_source() -> str:
    js = _js()
    start = js.index("const MONTHS = [")
    end = js.index("function fmtDay(")
    return js[start:end]


@pytest.mark.parametrize("zone", ["America/Halifax", "America/Los_Angeles",
                                  "Pacific/Kiritimati", "UTC"])
def test_a_stored_day_reads_back_as_the_same_day_in_every_zone(zone):
    """Behavioural, under a real JS engine with the zone set: the defect
    only exists west of UTC (or, for an inclusive end of day, east of it),
    so a check that ran in UTC alone would pass against the broken code."""
    script = _date_helpers_source() + _fn("observedAtUtc") + """
const out = {
  // What the analyst types in "Observed at (UTC)" is what reads back, in
  // every zone. Read in the browser's zone, 17:00 in Los Angeles was
  // stored as 00:00Z on the 13th and read back as "13 Jul 2025".
  typed: observedAtUtc('2025-07-12T17:00'),
  typedBack: fmtWhen(observedAtUtc('2025-07-12T17:00')),
  typedMidnight: fmtWhen(observedAtUtc('2025-07-12T00:00')),
  typedEmpty: observedAtUtc(''),
  midnight: fmtDate('2025-12-14T00:00:00Z'),
  bare: fmtDate('2025-12-14'),
  from: fmtWhen('2025-12-14T00:00:00Z'),
  inclusiveEnd: fmtWhen('2026-06-30T23:59:59Z'),
  instant: fmtTime('2026-09-17T15:18:04Z'),
  seconds: fmtTime('2026-09-17T15:18:04Z', true),
  interval: fmtInterval('2025-12-14T00:00:00Z', '2026-06-30T23:59:59Z'),
  open: fmtInterval('2025-12-14T00:00:00Z', null),
  none: fmtTime(null),
  ms: fmtDate(Date.UTC(2024, 1, 12)),
  offset: new Date('2025-12-14T00:00:00Z').getTimezoneOffset(),
};
console.log(JSON.stringify(out));
"""
    got = json.loads(_run_node(script, zone))
    # Proof the engine really ran in that zone, or the check is hollow.
    offset = got.pop("offset")
    assert (offset == 0) == (zone == "UTC"), f"{zone} ran at offset {offset}"
    assert got == {
        "typed": "2025-07-12T17:00:00.000Z",
        "typedBack": "2025-07-12 17:00 UTC",
        "typedMidnight": "12 Jul 2025",
        "typedEmpty": None,
        "midnight": "14 Dec 2025",
        "bare": "14 Dec 2025",
        "from": "14 Dec 2025",
        "inclusiveEnd": "30 Jun 2026",
        "instant": "2026-09-17 15:18 UTC",
        "seconds": "2026-09-17 15:18:04 UTC",
        "interval": "valid 14 Dec 2025 to 30 Jun 2026",
        "open": "valid from 14 Dec 2025, no end recorded",
        "none": "not recorded",
        "ms": "12 Feb 2024",
    }, f"in {zone}: {got}"


# ---------------------------------------------------------------------------
# The case's lifecycle state, inside the workspace
# ---------------------------------------------------------------------------

def test_the_workspace_names_every_state_the_server_can_be_in():
    from noctornal_api.cases import _TRANSITIONS
    js = _js()
    start = js.index("const CASE_STATE_TEXT = {")
    table = js[start:js.index("};", start)]
    for status in _TRANSITIONS:
        if status == "ACTIVE":
            continue
        assert f"{status}:" in table, (
            f"a {status} case opens with nothing saying it is {status}")
    assert "renderCaseState(rec);" in _fn("openCase")
    assert "renderCaseState(null);" in _fn("showCaseList")
    html = _html()
    assert 'id="hdr-state"' in html and 'id="case-state-strip"' in html


def test_the_state_chip_cannot_be_mistaken_for_a_handling_marking():
    """It sits beside the TLP chip. In the alert amber it read as a second
    TLP:AMBER marking, "DORMANT" beside "TLP:RED" included (verifier, fix
    round of 2026-09-22). No colour any TLP chip uses may appear in it."""
    css = re.sub(r"/\*.*?\*/", "", APP_CSS.read_text(encoding="utf-8"), flags=re.S)
    tlp_tokens = set()
    for m in re.finditer(r"\.tlp-[A-Z_]+\s*\{([^}]*)\}", css):
        tlp_tokens.update(re.findall(r"var\((--[a-z0-9-]+)\)", m.group(1)))
    assert {"--alert", "--danger", "--sign-positive"} <= tlp_tokens
    for rule in (".chip.case-state-off", ".chip.case-state "):
        m = re.search(re.escape(rule.strip()) + r"\s*\{([^}]*)\}", css)
        assert m, f"app.css has no {rule.strip()} rule"
        used = set(re.findall(r"var\((--[a-z0-9-]+)\)", m.group(1)))
        # --text-secondary is the plain chip's own text colour and
        # TLP:CLEAR's; a colour every chip shares marks nothing.
        shared = (used & tlp_tokens) - {"--text-secondary"}
        assert not shared, f"{rule.strip()} wears TLP colours: {sorted(shared)}"


def test_the_state_strip_does_not_steal_the_workspace_row():
    """The strip is hidden most of the time, and a hidden grid child takes
    no track: without explicit rows the workspace would fall into the
    strip's auto row and lose its height."""
    css = re.sub(r"/\*.*?\*/", "", APP_CSS.read_text(encoding="utf-8"), flags=re.S)
    assert "grid-template-rows: var(--appbar-h) auto 1fr" in css
    assert ".app > .main { grid-row: 3; }" in css


# ---------------------------------------------------------------------------
# House style: nothing this group wrote carries an em or en dash
# ---------------------------------------------------------------------------

_WRITTEN = ("fmtTime", "fmtDate", "fmtWhen", "fmtInterval", "failureReason",
            "showLoadFailure", "renderCaseState", "resetReport", "buildReport",
            "saveClearedReport", "renderRedaction", "reportList",
            "renderReportBody", "releaseReport", "withdrawReport",
            "withdrawReportVerdict", "loadFailureText", "observedAtUtc",
            "caseCodeNow", "initCommsBlocks")


@pytest.mark.parametrize("name", _WRITTEN)
def test_no_em_or_en_dash_in_new_copy(name):
    body = _fn(name)
    assert not any(d in body for d in DASHES), f"{name} contains a dash"


def test_no_em_or_en_dash_in_the_case_state_copy_or_report_pane():
    js = _js()
    start = js.index("const CASE_STATE_TEXT = {")
    assert not any(d in js[start:js.index("};", start)] for d in DASHES)
    html = _html()
    pane = html[html.index('<section id="pane-report"'):]
    pane = pane[:pane.index("</section>")]
    visible = re.sub(r"<!--.*?-->", "", pane, flags=re.S)
    assert not any(d in visible for d in DASHES), "the report pane shows a dash"

"""Check egress asks for the sign-in it needs, and tells its refusals apart.

Final review C15 (2026-09-23). `/report/release` is the only path to a
report file and it is step-up gated. The console never checked the gate:
every Check egress more than 15 minutes into a session came back "missing
permission report.export on this case", which `releaseReport` showed as an
egress refusal "audited as loudly as a permission would be", to a Lead
investigator who holds the permission. Nothing offered the in-place sign-in
(`confirmIdentity`) the recovery-code flow already used, so the way out was
signing out and preparing the report again.

Now: the sign-in is asked for before the request when this tab knows the
gate is shut, and once more if the server says so; the server says so
only when the sign-in is all that is missing, and still records the
refusal against the case; and only the gate's own verdict ("Egress
refused") is shown as an egress refusal.

Pure: reads the shipped assets and runs the pane's code under node when it
is installed, with the DOM, the API and the sign-in sheet faked.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")
APP_JS = STATIC / "app.js"

DASHES = ("\u2014", "\u2013")


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _fn(name: str) -> str:
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _node_binary() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    win = Path("C:/Program Files/nodejs/node.exe")
    return str(win) if win.exists() else None


def _run_node(script: str) -> str:
    node = _node_binary()
    if not node:
        pytest.skip("node is not installed; the static checks still run")
    res = subprocess.run([node, "-"], input=script, capture_output=True,
                         text=True, encoding="utf-8", timeout=60)
    assert res.returncode == 0, res.stderr
    return res.stdout


# --- static ------------------------------------------------------------------

def test_the_release_asks_for_the_sign_in_before_sending():
    release = _fn("releaseReport")
    assert "stepUpStale()" in release
    assert release.index("stepUpStale()") < release.index("await send()"), (
        "the doomed request goes out before the sign-in is asked for")
    assert "confirmIdentity(" in _fn("reportStepUp")
    assert "SESSION.stepUpUntil = 0" in release


def test_only_the_gate_s_verdict_is_shown_as_an_egress_refusal():
    release = _fn("releaseReport")
    loud = release.index("audited as loudly")
    guard = release.rfind("if (", 0, loud)
    assert "err.title === 'Egress refused'" in release[guard:loud], (
        "a permission or sign-in 403 is still presented as an egress refusal")
    assert "reportAccessRefusal(err)" in release
    refusal = _fn("reportAccessRefusal")
    assert "Lead investigator" in refusal and "report.export" in refusal


def test_the_new_copy_has_no_dashes():
    for name in ("reportNeedsSignIn", "reportStepUp", "reportAccessRefusal",
                 "releaseReport"):
        body = _fn(name)
        for dash in DASHES:
            assert dash not in body, f"{name} carries a {dash!r}"


def _stale_sign_in_detail() -> str:
    """What `require_step_up` itself answers a stale session with."""
    from uuid import uuid4

    from noctornal_api.http.deps import CurrentUser, require_step_up
    from noctornal_api.http.errors import Problem

    class _Conn:  # the refusal's audit row, which a pure test drops
        def execute(self, *a, **k):
            return None

    with pytest.raises(Problem) as refused:
        require_step_up(user=CurrentUser(uuid4(), uuid4(), None), conn=_Conn())
    return refused.value.detail


def test_the_route_says_when_the_sign_in_is_all_that_is_missing():
    """`report.export` is itself step-up, so the permission gate refused a
    stale session with "missing permission". The route's permission gate
    is now `_require_export`, which is the same five-part decision with
    one sentence changed, and that sentence is `require_step_up`'s word
    for word, so the console recognises it. The bare freshness check is
    no longer first: run first it wrote the refusal with no case (final
    review C15 follow-up, 2026-09-23). It stays on the route, after."""
    from noctornal_api.http.deps import require_step_up
    from noctornal_api.http.routers.reports import (
        STEP_UP_DETAIL,
        _require_export,
        router,
    )

    route = next(r for r in router.routes if r.path.endswith("/release"))
    calls = [d.call for d in route.dependant.dependencies]
    assert calls[0] is _require_export, calls
    assert require_step_up in calls, "the belt-and-braces freshness check went"
    assert STEP_UP_DETAIL == _stale_sign_in_detail()
    assert re.search(r"re-authenticat", STEP_UP_DETAIL, flags=re.I)
    assert "/re-authenticat/i" in _fn("reportNeedsSignIn")


def test_the_preview_says_when_the_hypotheses_went_with_the_header():
    """Final review C2: asked for is not the same as in the document."""
    assert "r.hypotheses_withheld" in _fn("renderRedaction")
    assert "r.hypothesis_evidence_withheld" in _fn("renderRedaction")
    body = _fn("renderReportBody")
    assert "hypotheses_withheld" in body
    assert "withheld with the case header" in body


# --- behaviour ---------------------------------------------------------------

def _harness() -> str:
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
function inlineProblem(n, err) { setMsg(n, 'PROBLEM ' + String(err)); }
function shortId(id) { return String(id).slice(0, 8); }
function fmtTime(v) { return String(v); }
class ApiError extends Error {
  constructor(status, title, detail) {
    super(title); this.status = status; this.title = title;
    this.detail = detail || '';
  }
}
function onCaseSwitch(fn) {}
const state = { caseId: 'case-a', caseSeq: 1, caseRec: { code: 'OP-A' },
  proj: { as_of: null }, report: null };
function caseToken() { return state.caseSeq; }
function caseChanged(t) { return t !== state.caseSeq; }
function cpath(p) { return '/cases/' + state.caseId + p; }

// The session: the step-up gate as this tab believes it, and the sheet.
let seq = [];
let gateShut = false;
let confirmAnswer = true;
const SESSION = { stepUpUntil: null };
function stepUpStale() { return gateShut; }
function signedIn() { return true; }
function confirmIdentity(why) {
  seq.push('confirm');
  return Promise.resolve(confirmAnswer);
}

const calls = [];
function api(path, opts) {
  if (path.endsWith('/report/release')) seq.push('release');
  return new Promise((resolve, reject) => calls.push({ path, resolve, reject }));
}
const tick = () => new Promise((r) => setTimeout(r, 0));
// A reply to a request that was never made is dropped, so a path that
// sends too few requests fails on the assertions below, not on a crash.
function next() { return calls.shift() || { resolve() {}, reject() {} }; }
""" + region + """
renderRedaction = () => {};
renderReportBody = () => {};
const PREVIEW = { content_digest: 'd1', redaction: { built_at_tlp: 'GREEN' } };
const CLEARED = { classification: 'GREEN', destination: 'export',
  content_digest: 'd1', filename: 'OP-A-TLP-GREEN.md', document: '# x' };
const STALE = () => new ApiError(403, 'Forbidden', """ + json.dumps(
        _stale_sign_in_detail()) + """);
const ROLE = () => new ApiError(403, 'Forbidden',
  'missing permission report.export on this case');
const EGRESS = () => new ApiError(403, 'Egress refused',
  'RED never leaves the platform (invariant 8)');

async function prepare() {
  $('rep-tlp').value = 'GREEN'; $('rep-hypotheses').checked = true;
  $('rep-destination').value = 'export';
  buildReport(); await tick();
  next().resolve(PREVIEW); await tick();
  seq = []; SESSION.stepUpUntil = null;
}

function snapshot() {
  const text = (n) => [n.textContent].concat(n.children.map(text)).join(' ');
  return {
    seq: seq.slice(),
    out: text($('rep-release-out')),
    msg: $('rep-release-msg').textContent,
    save: !$('rep-download').hidden,
    pending: verdictPending,
    stepUpUntil: SESSION.stepUpUntil,
  };
}

(async () => {
  const out = {};

  // A. The tab knows the gate is shut: sign in first, then send.
  await prepare(); gateShut = true; confirmAnswer = true;
  releaseReport(); await tick(); await tick();
  next().resolve(CLEARED); await tick();
  out.shutConfirmed = snapshot();

  // B. The same, and the analyst cancels the sheet: nothing is sent.
  await prepare(); gateShut = true; confirmAnswer = false;
  releaseReport(); await tick(); await tick();
  out.shutCancelled = Object.assign(snapshot(), { queued: calls.length });

  // C. The tab thought the gate open and the server says otherwise:
  //    sign in here and send once more.
  await prepare(); gateShut = false; confirmAnswer = true;
  releaseReport(); await tick();
  next().reject(STALE()); await tick(); await tick();
  next().resolve(CLEARED); await tick();
  out.serverAsked = snapshot();

  // D. ...and still refuses after the sign-in: said, not looped.
  await prepare(); gateShut = false; confirmAnswer = true;
  releaseReport(); await tick();
  next().reject(STALE()); await tick(); await tick();
  next().reject(STALE()); await tick();
  out.stillStale = Object.assign(snapshot(), { queued: calls.length });

  // E. A role without report.export: no sign-in offered, not an egress
  //    refusal.
  await prepare(); gateShut = false;
  releaseReport(); await tick();
  next().reject(ROLE()); await tick();
  out.role = Object.assign(snapshot(), { queued: calls.length });

  // F. The gate's own verdict is still an egress refusal.
  await prepare(); gateShut = false;
  releaseReport(); await tick();
  next().reject(EGRESS()); await tick();
  out.egress = snapshot();

  console.log(JSON.stringify(out));
})();
"""


def test_check_egress_signs_in_and_tells_its_refusals_apart():
    got = json.loads(_run_node(_harness()))

    a = got["shutConfirmed"]
    assert a["seq"] == ["confirm", "release"], (
        f"the sign-in was not asked for before the request: {a}")
    assert a["save"], f"the cleared document was not offered after sign-in: {a}"

    b = got["shutCancelled"]
    assert b["seq"] == ["confirm"] and b["queued"] == 0, (
        f"a request went out after the sign-in was cancelled: {b}")
    assert "Nothing was checked" in b["msg"]
    assert not b["pending"], "a cancelled check still counts as in flight"

    c = got["serverAsked"]
    assert c["seq"] == ["release", "confirm", "release"], c
    assert c["save"], f"the retried check did not reach Save: {c}"
    assert c["stepUpUntil"] == 0
    assert "audited as loudly" not in c["out"]

    d = got["stillStale"]
    assert d["seq"] == ["release", "confirm", "release"] and d["queued"] == 0, d
    assert "fresh sign-in" in d["out"]
    assert "audited as loudly" not in d["out"]

    e = got["role"]
    assert e["seq"] == ["release"] and e["queued"] == 0, (
        f"a role refusal offered a sign-in that cannot help: {e}")
    assert "Lead investigator" in e["out"]
    assert "audited as loudly" not in e["out"], (
        f"a permission refusal is presented as an egress refusal: {e}")

    f = got["egress"]
    assert "invariant 8" in f["out"] and "audited as loudly" in f["out"]
    assert not f["save"]

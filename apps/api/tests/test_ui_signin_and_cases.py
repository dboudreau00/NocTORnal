"""Sign-in, the case list, the case chrome and the console's reach, held
from the shipped files (review of 2026-09-22, fix pass of 2026-09-23).

One check per finding, each written so it would have failed on the code
the review measured:

- ux01-firstrun: a lockout that read as a typo, a sign-out that left the
  case in the page, case buttons that did nothing on the list, a live dot
  that stayed green on a dead session, recovery copy that told analysts to
  run a server script;
- ux02-cases: a free-text status prompt, a case record nobody could see,
  an address that never named the case, a list with nothing to triage by,
  and a header that called everyone "analyst";
- ux18-a11y: the graph pane at 200% zoom, a silent canvas, letter keys that
  fired from anywhere, rail names that changed with the window height,
  keyboard controls written only for screen readers, small text below AA,
  banners over the app bar, and unnamed pickers on the Admin card.

Pure, like test_ui_invariants.py beside it: static assets, and the real
functions run under Node against stubs where the claim is about behaviour
(skipped where Node is absent). The server half is in
test_case_record_api_pg.py and test_live_session_end_pg.py.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
STATIC = SRC / "http" / "static"


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


def _css() -> str:
    return re.sub(r"/\*.*?\*/", "", (STATIC / "app.css").read_text(encoding="utf-8"),
                  flags=re.S)


def _fn(name: str) -> str:
    """A top-level function: declaration to the first `}` at column 0."""
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    line = js[m.start():js.index("\n", m.start())]
    if line.rstrip().endswith("}") and line.count("{") == line.count("}"):
        return line + "\n"
    return js[m.start():js.index("\n}", m.start()) + 2] + "\n"


def _const(name: str) -> str:
    """A top-level const, through the first line that ends the statement
    with every bracket closed (strings in it are not bracket-counted, so
    keep brackets out of the ones this file reads)."""
    js = _js()
    m = re.search(rf"^const {re.escape(name)} =\s", js, flags=re.M)
    assert m, f"app.js has no top-level const {name}"
    out, depth = [], 0
    for line in js[m.start():].split("\n"):
        out.append(line)
        code = re.sub(r"'(?:[^'\\]|\\.)*'", "''", line)
        depth += sum(code.count(c) for c in "([{") - sum(code.count(c) for c in ")]}")
        if depth <= 0 and line.rstrip().endswith(";"):
            return "\n".join(out) + "\n"
    raise AssertionError(f"const {name} never ends")


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    default = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "nodejs" / "node.exe"
    return str(default) if default.exists() else None


def _run(source: str):
    node = _node()
    if not node:
        pytest.skip("Node is not installed; the browser-side check needs it")
    out = subprocess.run([node, "-"], input=source, capture_output=True,
                         text=True, encoding="utf-8", timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _media(query: str) -> str:
    """The body of the one `@media <query> {` block, comments removed."""
    css = _css()
    start = css.index("@media " + query + " {")
    return css[start:css.index("\n}\n", start)]


#: Elements by id, each with what the functions under test touch.
_DOM = r"""
const log = [];
const els = {};
function $(id) {
  if (!els[id]) els[id] = { id, hidden: false, value: '', textContent: '',
    children: [], className: '', title: '', disabled: false, attrs: {},
    setAttribute(k, v) { this.attrs[k] = v; },
    focus() { log.push('focus:' + id); } };
  return els[id];
}
function show(node, on) { node.hidden = !on; }
function setMsg(node, text) { node.textContent = text || ''; node.hidden = !text; }
function visibleText(s) { return s == null ? '' : String(s); }
"""


# ---------------------------------------------------------------------------
# ux01-firstrun:lockout-reads-as-typo
# ---------------------------------------------------------------------------

_WORDS = {3: "Three", 4: "Four", 5: "Five", 6: "Six", 10: "Ten"}


def test_the_sign_in_form_states_the_policy_the_server_enforces():
    """A locked account answers "invalid credentials" even with the right
    password, on purpose; nothing on the form said so, or that an
    administrator can unlock it, or that a drifted phone clock is the
    usual cause of a code that keeps failing. The numbers are the
    server's."""
    auth = (SRC / "security" / "auth.py").read_text(encoding="utf-8")
    fails = int(re.search(r"^MAX_FAILED_LOGINS = (\d+)$", auth, re.M).group(1))
    minutes = int(re.search(r"^LOCKOUT_DURATION = timedelta\(minutes=(\d+)\)$",
                            auth, re.M).group(1))
    html = _html()
    m = re.search(r'<p id="login-policy" class="help">(.*?)</p>', html, re.S)
    assert m, "the sign-in form no longer states the lockout policy"
    said = " ".join(m.group(1).split())
    assert said.startswith(f"{_WORDS[fails]} failed attempts lock an account "
                           f"for {minutes} minutes"), said
    assert "same answer even with the right password" in said
    assert "Unlock" in said and "Administration" in said
    assert "clock" in said
    # Placed under the button, inside the form.
    form = html[html.index('<form id="login-form"'):html.index("</form>")]
    assert form.index('id="login-submit"') < form.index('id="login-policy"')
    # And the admin card really has the Unlock it names (ux16-admin's card).
    js = _js()
    assert "admButton('Unlock')" in js
    assert "'/admin/users/' + u.id + '/unlock'" in js


def test_a_refused_sign_in_says_what_to_do_and_clears_the_code():
    """The 401 printed the server's lowercase "invalid credentials"; the
    429 printed "rate limit 'auth.login_failed' exceeded; retry in 212s";
    and the 30-second code stayed in the field to be resubmitted."""
    got = _run(_DOM + r"""
class ApiError extends Error {
  constructor(status, title, detail) { super(title); this.status = status;
    this.title = title; this.detail = detail || ''; }
}
function countOf(n, one, many) { return n + ' ' + (Number(n) === 1 ? one : many); }
const shown = [];
function inlineProblem(box, err) { shown.push('inline:' + err.status); }
""" + _fn("signInRefused") + r"""
const box = $('login-error');
const out = {};
$('login-totp').value = '123456';
signInRefused(box, new ApiError(401, 'Unauthenticated', 'invalid credentials'));
out.bad = { text: box.textContent, code: $('login-totp').value,
            focus: log.slice() };
$('login-totp').value = '654321';
const limited = new ApiError(429, 'Too many requests',
  "rate limit 'auth.login_failed' exceeded; retry in 212s");
limited.retryAfter = 212;
signInRefused(box, limited);
out.limited = { text: box.textContent, code: $('login-totp').value };
const one = new ApiError(429, 'Too many requests', "rate limit 'auth.login' exceeded; retry in 1s");
one.retryAfter = 1;
signInRefused(box, one);
out.one = box.textContent;
signInRefused(box, new ApiError(400, 'Invalid request', 'x'));
out.other = shown;
console.log(JSON.stringify(out));
""")
    assert got["bad"]["text"] == ("That email, password and code did not sign "
                                  "you in. Check all three, and type a fresh code.")
    assert got["bad"]["code"] == "" and got["bad"]["focus"] == ["focus:login-totp"]
    assert got["limited"]["text"] == ("Too many failed sign-ins from this network. "
                                      "Try again in 212 seconds.")
    assert got["limited"]["code"] == ""
    assert "auth.login" not in got["limited"]["text"], "the limiter's key reached the analyst"
    assert got["one"] == ("Too many sign-in attempts from this network. "
                          "Try again in 1 second.")
    assert got["other"] == ["inline:400"]
    assert "signInRefused(errBox, err)" in _fn("doLogin")


def test_retry_after_comes_from_the_header_or_the_limiters_detail():
    got = _run(_fn("retryAfterSeconds") + r"""
console.log(JSON.stringify([
  retryAfterSeconds('30', ''), retryAfterSeconds(null, "rate limit 'x' exceeded; retry in 6s"),
  retryAfterSeconds(null, 'nothing'), retryAfterSeconds('', 'retry in 12s'),
  retryAfterSeconds('0', ''),
]));
""")
    assert got == [30, 6, None, 12, 0]
    assert "retryAfterSeconds(res.headers.get('Retry-After'), p.detail)" in _fn("_fetch")


# ---------------------------------------------------------------------------
# ux01-firstrun:logout-leaves-case-in-page
# ---------------------------------------------------------------------------

_LEAVE = r"""
const log = [];
class ApiError extends Error {
  constructor(status, title, detail) { super(title); this.status = status;
    this.title = title; this.detail = detail || ''; }
}
let answer = null;
async function api(path, o) { log.push(o.method + ' ' + path); return answer(); }
function endSession(title) { log.push('endSession:' + title); }
function banner(title) { log.push('banner:' + title); }
function forgetResume() { log.push('forgetResume'); }
function closeReauth() { log.push('closeReauth'); SESSION.mode = null; }
async function revokeIfStillOurs() { log.push('revoke'); }
function $(id) { return { id, disabled: false }; }
const SESSION = { mode: null, serverEnded: false, userId: 'u1', confirmWaiters: [] };
const location = { pathname: '/ui/', replace(url) { log.push('replace:' + url); } };
"""


def test_leaving_discards_the_page_however_the_server_answered():
    """endSession hid the app and kept it: after Log out the previous
    analyst's 146 nodes, 492 edges and the header's case and name stayed
    in memory and in the hidden DOM of the sign-in screen. The first fix
    reloaded only a sign-out the server accepted; the verifier found the
    same page left behind on the two other ways an analyst leaves: a Log
    out the server answers 401 (an administrator revoked the session, or
    it idled out there first) and "Sign in as someone else" on a lapsed
    sheet, which is the hand-over of the desk itself."""
    got = _run(_LEAVE + _fn("discardPage") + _fn("doLogout") + _fn("leaveReauth") + r"""
(async () => {
  const out = {};
  answer = async () => null;
  await doLogout(); out.accepted = log.splice(0);
  answer = async () => {
    // As `_fetch` does for a 401 on /auth/logout: it ends the session first.
    log.push('endSession:Session ended');
    const e = new ApiError(401, 'Unauthenticated', 'invalid or expired session');
    e.handled = true; throw e; };
  await doLogout(); out.gone = log.splice(0);
  answer = async () => { throw new ApiError(403, 'Forbidden', 'missing or invalid CSRF token'); };
  await doLogout(); out.refused = log.splice(0);
  SESSION.mode = 'lapsed';
  await leaveReauth(); out.someoneElse = log.splice(0);
  SESSION.mode = 'lapsed'; SESSION.serverEnded = true;
  await leaveReauth(); out.someoneElseServerEnded = log.splice(0);
  SESSION.mode = 'confirm';
  await leaveReauth(); out.cancel = log.splice(0);
  console.log(JSON.stringify(out));
})();
""")
    assert got["accepted"] == ["POST /auth/logout", "endSession:null", "replace:/ui/"]
    assert got["gone"] == ["POST /auth/logout", "endSession:Session ended",
                           "forgetResume", "replace:/ui/"], (
        "a Log out the server answered 401 leaves the case in the page")
    assert got["refused"] == ["POST /auth/logout", "banner:Sign-out refused"], (
        "a sign-out the server refused must not look like one that happened")
    assert got["someoneElse"] == ["revoke", "closeReauth", "endSession:Signed out",
                                  "replace:/ui/"], (
        "the lapsed sheet hands the next person a page holding the case")
    assert got["someoneElseServerEnded"] == ["closeReauth", "endSession:Signed out",
                                             "replace:/ui/"]
    assert got["cancel"] == ["closeReauth"], "cancelling a step-up threw the page away"
    # The expiry path keeps the analyst's work behind the in-place sign-in:
    # it never discards, and nothing but the two ways of leaving does.
    js = _js()
    starts = [m.start() for m in re.finditer(r"^(?:async )?function \w+\(", js, flags=re.M)]
    callers = set()
    for m in re.finditer(r"\bdiscardPage\(\);", js):
        start = max(s for s in starts if s < m.start())
        callers.add(re.match(r"(?:async )?function (\w+)", js[start:]).group(1))
    assert callers == {"doLogout", "leaveReauth"}, callers
    assert "location.replace" not in js.replace(_fn("discardPage"), ""), (
        "the page is thrown away somewhere other than discardPage")
    assert "location.replace(location.pathname)" in _fn("discardPage")
    # What the same analyst comes back to survives the reload: it is in
    # this tab's storage, written by an ending that has a title.
    assert "endSession('Signed out'" in _fn("leaveReauth")
    assert "if (title) rememberResume();" in _fn("endSession")


# ---------------------------------------------------------------------------
# ux01-firstrun:dead-case-buttons-after-return and
# ux02-cases:case-actions-linger-on-case-list
# ---------------------------------------------------------------------------

def test_the_case_chrome_and_the_live_dot_leave_with_the_case():
    got = _run(_DOM + r"""
function closeCaseRecord() { log.push('closeRecord'); }
function closeStatus() { log.push('closeStatus'); }
""" + _fn("hideCaseChrome") + r"""
for (const id of ['btn-case-edit', 'btn-case-share', 'btn-case-status', 'live-dot']) $(id).hidden = false;
hideCaseChrome();
console.log(JSON.stringify({
  hidden: ['btn-case-edit', 'btn-case-share', 'btn-case-status', 'live-dot'].map((id) => $(id).hidden),
  log }));
""")
    assert got["hidden"] == [True, True, True, True]
    assert got["log"] == ["closeRecord", "closeStatus"]
    listing = _fn("showCaseList")
    assert "hideCaseChrome();" in listing and "disconnectLive();" in listing, (
        "the list keeps the case's buttons, or its live socket")
    assert "hideCaseChrome();" in _fn("endSession")
    assert "showCaseChrome(rec);" in _fn("openCase")


# ---------------------------------------------------------------------------
# ux01-firstrun:live-dot-green-on-dead-session
# ---------------------------------------------------------------------------

def test_the_live_dot_says_signed_out_when_the_server_ends_the_session():
    live = (SRC / "http" / "routers" / "live.py").read_text(encoding="utf-8")
    reason = re.search(r'^SESSION_ENDED_REASON = "([^"]+)"$', live, re.M).group(1)
    assert _const("LIVE_SESSION_ENDED") == f"const LIVE_SESSION_ENDED = '{reason}';\n", (
        "the console and the server disagree on the reason a dead session closes with")
    got = _run(_DOM + _const("LIVE_SESSION_ENDED") + _const("LIVE_RELINK_MS") + r"""
let _liveRelinkedAt = 0;
let lapsed = false;
const state = { caseId: 'c1', userId: 'u1', booting: false };
function signedIn() { return !!state.userId && !lapsed; }
const SESSION = { userId: 'u1' };
let _ws = null;
let now = 5000000; Date.now = () => now;
const API = '/api/v1';
function authHeaders() { return {}; }
let answer = null;
async function fetch(url, init) {
  log.push('GET ' + url + (init.signal ? ' bounded' : '')); return answer(); }
async function problemOf() { return { detail: 'invalid or expired session' }; }
function noteSessionActivity() { log.push('activity'); }
function sessionLapsed(info) { lapsed = true; log.push('lapsed:' + info.detail); }
function connectLive() { log.push('connectLive'); }
""" + _fn("liveStatus") + _fn("sessionRefusedRaw") + _fn("liveSessionStillOurs")
        + _fn("noteLiveSessionEnded") + r"""
const ok = (body) => ({ ok: true, status: 200, json: async () => body });
const refused = () => ({ ok: false, status: 401 });
const ended = { code: 1008, reason: 'session ended' };
(async () => {
  const out = {};
  await noteLiveSessionEnded({ code: 1008, reason: 'access changed' });
  out.access = log.splice(0);
  await noteLiveSessionEnded({ code: 1006, reason: 'session ended' });
  out.dropped = log.splice(0);
  // 1. The session this tab holds is gone as well: signed out, sign in again.
  answer = refused;
  await noteLiveSessionEnded(ended);
  out.gone = { dot: $('live-dot').className, title: $('live-dot').title, log: log.splice(0) };
  lapsed = false;
  // 2. The socket rode a session a sign-in has since replaced; this tab's
  //    own session is alive. The socket is reopened, nobody is signed out.
  $('live-dot').title = '';
  answer = () => ok({ user_id: 'u1' });
  await noteLiveSessionEnded(ended);
  out.replaced = { title: $('live-dot').title, log: log.splice(0) };
  //    A second such close inside the minute gets no second socket...
  now += 30 * 1000;
  await noteLiveSessionEnded(ended);
  out.again = log.splice(0);
  //    ...and one after it does.
  now += 60 * 1000;
  await noteLiveSessionEnded(ended);
  out.later = log.splice(0);
  // 3. The browser now holds another account's session.
  answer = () => ok({ user_id: 'u2' });
  await noteLiveSessionEnded(ended);
  out.other = log.splice(0);
  lapsed = false;
  // 4. The server cannot be asked: the dot stays off, nobody is signed out.
  $('live-dot').title = '';
  answer = () => { throw new TypeError('network'); };
  await noteLiveSessionEnded(ended);
  out.unreachable = { title: $('live-dot').title, log: log.splice(0) };
  // 5. Signed out while the question was out: that ending has spoken.
  answer = () => { state.userId = null; return refused(); };
  await noteLiveSessionEnded(ended);
  out.leftMeanwhile = log.splice(0);
  // 6. Already signed out: nothing is asked.
  await noteLiveSessionEnded(ended);
  out.signedOut = log.splice(0);
  console.log(JSON.stringify(out));
})();
""")
    ask = "GET /api/v1/auth/me bounded"
    mine = "lapsed:your session ended while the console was open"
    assert got["access"] == [] and got["dropped"] == []
    assert got["gone"]["dot"] == "live-dot live-off"
    assert got["gone"]["title"].startswith("Signed out.")
    # The 401 opens the sign-in as any raw request's does; the close then
    # names its reason on it.
    assert got["gone"]["log"] == [ask, "lapsed:invalid or expired session", mine], (
        "no sign-in is offered")
    assert got["replaced"] == {"title": "", "log": [ask, "activity", "connectLive"]}, (
        "an analyst whose session is alive was signed out by the socket of a "
        "session a sign-in had replaced")
    assert got["again"] == [ask, "activity"], "a server that says both things makes a loop"
    assert got["later"] == [ask, "activity", "connectLive"]
    assert got["other"] == [ask, "activity", mine]
    assert got["unreachable"] == {"title": "", "log": [ask]}
    assert got["leftMeanwhile"] == [ask] and got["signedOut"] == []
    assert "ws.addEventListener('close', noteLiveSessionEnded);" in _fn("connectLive")


def test_a_sign_in_moves_the_live_socket_onto_the_new_session():
    """The verifier's regression. The socket authenticates with the cookie
    its upgrade carried; every sign-in (Sign in again now, a step-up, a
    sibling tab's) makes a new session and leaves the old one to its own
    timeout; and `sessionRenewed` reopened the socket only for a lapsed
    tab. Once the server checked the socket's session on every ping, the
    old one's expiry closed it as "session ended" and signed out an
    analyst who had just signed in. Run through the real functions."""
    got = _run(r"""
const calls = [];
const els = {};
function $(id) { if (!els[id]) els[id] = { hidden: true, focus() {} }; return els[id]; }
function show(e, on) { e.hidden = !on; }
const state = { caseId: 'c1' };
const window = { removeEventListener() {} };
let _ws = null, _wsTimer = null;
const SESSION = { userId: 'u', lapsed: false, lapseUnsafe: false, lapseMissedRead: false,
  lapseCause: null, serverEnded: false, mode: null, hardAt: null, stepUpUntil: null,
  confirmWaiters: [], accountWasOpen: false };
""" + "".join(f"function {n}() {{}}\n" for n in (
        "hideIdleWarning", "noteSessionActivity", "renderAccountChip", "forgetResume",
        "clearSessionBanners", "showCaseList", "sessionBanner", "refreshGlassChip",
        "setAccountOpen", "guardUnsaved")) + r"""
function closeReauth() { SESSION.mode = null; }
function connectLive() { calls.push('connectLive'); }
""" + _fn("adoptStepUp") + _fn("relinkLive") + _fn("sessionRenewed") + _fn("onSessionMessage")
        + r"""
const out = {};
const socket = {};
// A step-up ("Confirm it is you") inside a case, socket open.
_ws = socket; SESSION.mode = 'confirm';
sessionRenewed(43200, { user_id: 'u', step_up_fresh_seconds: 900 });
out.stepUp = calls.splice(0);
// "Sign in again now" before the 12-hour limit, the socket between retries.
_ws = null; _wsTimer = 7; SESSION.mode = 'renew';
sessionRenewed(43200, null);
out.renew = calls.splice(0);
// Another tab's sign-in, heard by a tab with no sheet open.
_ws = socket; _wsTimer = null;
onSessionMessage({ data: { t: 'renewed', user: 'u', expiresIn: 43200, stepUpIn: 900 } });
out.sibling = calls.splice(0);
// A socket closed for good (the case gate refused it) is not reopened.
_ws = null;
sessionRenewed(43200, null);
out.closedForGood = calls.splice(0);
// Nor is anything opened on the case list.
_ws = socket; state.caseId = null;
sessionRenewed(43200, null);
out.list = calls.splice(0);
// A lapsed tab reopens it once, as before.
state.caseId = 'c1'; _ws = null; SESSION.lapsed = true; SESSION.mode = 'lapsed';
sessionRenewed(43200, null);
out.lapsed = calls.splice(0);
console.log(JSON.stringify(out));
""")
    assert got["stepUp"] == ["connectLive"], "a step-up leaves the socket on the old session"
    assert got["renew"] == ["connectLive"], "a renewal leaves the socket on the old session"
    assert got["sibling"] == ["connectLive"], (
        "another tab's sign-in leaves this tab's socket on the old session")
    assert got["closedForGood"] == [] and got["list"] == []
    assert got["lapsed"] == ["connectLive"], got["lapsed"]


# ---------------------------------------------------------------------------
# ux01-firstrun:shell-only-recovery-copy
# ---------------------------------------------------------------------------

def test_recovery_messages_give_the_analyst_a_step_they_can_take():
    """Three banners told analysts to mint a `bootstrap.py session` link,
    which needs a shell on the server they do not have."""
    half = _const("HALF_SESSION_DETAIL")
    cookie = _fn("doLogin")
    cookie = cookie[cookie.index("if (!csrfCookie())"):cookie.index("await startApp()")]
    handed = _fn("adoptSessionFromFragment")
    handed = handed[handed.index("} catch (err) {"):]
    for name, text in (("half session", half), ("cookie refused", cookie),
                       ("hand-off", handed)):
        strings = " ".join(re.findall(r"'((?:[^'\\]|\\.)*)'", text))
        assert "bootstrap" not in strings, f"the {name} banner still sends the analyst to a script"
        assert "ask" in strings.lower() or "Sign in" in strings, name


# ---------------------------------------------------------------------------
# ux02-cases:status-prompt-free-text-one-way-transitions
# ---------------------------------------------------------------------------

def test_the_server_names_the_legal_moves_from_its_own_table():
    from noctornal_api.cases import _TRANSITIONS, allowed_transitions
    for status, allowed in _TRANSITIONS.items():
        assert set(allowed_transitions(status)) == allowed, status
    assert allowed_transitions("PURGED") == []
    assert allowed_transitions("CLOSED") == ["ACTIVE", "ARCHIVED"], "not in lifecycle order"


_STATUS_DOM = r"""
const log = [];
const els = {};
function mk(id, tag) {
  return { id, tag: tag || 'DIV', hidden: false, value: '', textContent: '',
    children: [], className: '', disabled: false, checked: false, type: '',
    name: '', listeners: {},
    addEventListener(t, fn) { (this.listeners[t] ||= []).push(fn); },
    appendChild(c) { this.children.push(c); c.parent = this; return c; },
    append(...cs) { for (const c of cs) this.appendChild(c); },
    remove() { const p = this.parent; if (p) p.children = p.children.filter((x) => x !== this); },
    focus() { log.push('focus:' + (this.id || this.tag + ':' + this.value)); },
    all() { const out = []; const walk = (n) => { for (const c of n.children) { out.push(c); walk(c); } }; walk(this); return out; },
    querySelectorAll(sel) {
      if (sel === '.stance-option') return this.all().filter((n) => /stance-option/.test(n.className));
      throw new Error('fake qsa ' + sel); },
    querySelector(sel) {
      const inputs = this.all().filter((n) => n.tag === 'INPUT');
      if (sel === 'input') return inputs[0] || null;
      if (sel === 'input:checked') return inputs.find((n) => n.checked) || null;
      throw new Error('fake qs ' + sel); } };
}
function $(id) { return els[id] || (els[id] = mk(id)); }
function el(tag, cls, text) { const n = mk(null, tag.toUpperCase()); n.className = cls || '';
  if (text != null) n.textContent = String(text); return n; }
function show(node, on) { node.hidden = !on; }
function setMsg(node, text) { node.textContent = text || ''; node.hidden = !text; }
function visibleText(s) { return s == null ? '' : String(s); }
const document = { activeElement: null };
const state = { caseId: 'c1', caseRec: null };
function pick(to) {
  for (const n of $('status-options').all()) {
    if (n.tag === 'INPUT') n.checked = n.value === to;
  }
  onStatusPicked();
}
"""


def _status_source(body: str) -> str:
    return (_STATUS_DOM + _const("CASE_STATUS_RANK") + _const("STATUS_MOVES")
            + _const("STATUS_ONE_WAY")
            + "".join(_fn(n) for n in (
                "caseCan", "caseRoleWords", "statusConsequence", "openStatus",
                "statusPicked", "onStatusPicked", "syncStatusSave"))
            + "const out = {};\n" + body + "\nconsole.log(JSON.stringify(out));\n")


def test_the_status_dialog_offers_the_legal_moves_and_nothing_chosen():
    """The prompt listed all six statuses, pre-filled CLOSED, and took
    ARCHIVED (no way back) for one typed word."""
    got = _run(_status_source(r"""
state.caseRec = { code: 'OP-X', status: 'CLOSED', allowed_transitions: ['ACTIVE', 'ARCHIVED'],
  my_role: 'CASE_OWNER', my_role_name: 'Lead investigator', my_permissions: ['case.close', 'case.read'] };
openStatus();
const options = () => $('status-options').all().filter((n) => n.tag === 'INPUT');
out.offered = options().map((n) => n.value);
out.checked = options().filter((n) => n.checked).length;
out.saveDisabled = $('status-save').disabled;
out.words = $('status-options').all().filter((n) => n.className === 'help').map((n) => n.textContent);
pick('ACTIVE');
out.reopen = { save: $('status-save').disabled, confirm: $('status-confirm').hidden };
pick('ARCHIVED');
out.archive = { save: $('status-save').disabled, confirm: $('status-confirm').hidden,
                help: $('status-confirm-help').textContent };
$('status-code').value = 'OP-Y';
syncStatusSave();
out.wrongCode = $('status-save').disabled;
$('status-code').value = 'OP-X';
syncStatusSave();
out.rightCode = $('status-save').disabled;
"""))
    assert got["offered"] == ["ACTIVE", "ARCHIVED"]
    assert got["checked"] == 0 and got["saveDisabled"] is True, "a move is chosen for the analyst"
    assert got["words"][0].startswith("Reopen it")
    assert "never be reopened" in got["words"][1]
    assert got["reopen"] == {"save": False, "confirm": True}
    assert got["archive"]["save"] is True and got["archive"]["confirm"] is False
    assert "Type OP-X to confirm" in got["archive"]["help"]
    assert got["wrongCode"] is True and got["rightCode"] is False
    # The prompt is gone.
    assert "New status: DRAFT, ACTIVE" not in _js()
    assert "status.addEventListener('click', openStatus);" in _fn("wireCaseActions")


def test_a_role_without_case_close_is_told_before_it_types_anything():
    got = _run(_status_source(r"""
state.caseRec = { code: 'OP-X', status: 'ACTIVE', allowed_transitions: ['DORMANT', 'CLOSED'],
  my_role: 'ANALYST', my_role_name: 'Analyst', my_permissions: ['case.read'] };
openStatus();
out.offered = $('status-options').all().filter((n) => n.tag === 'INPUT').length;
out.none = $('status-none').textContent;
out.save = $('status-save').hidden;
state.caseRec = { code: 'OP-P', status: 'PURGED', allowed_transitions: [],
  my_role: 'CASE_OWNER', my_permissions: ['case.close'] };
openStatus();
out.final = $('status-none').textContent;
"""))
    assert got["offered"] == 0 and got["save"] is True
    assert "needs case.close, which Analyst on this case does not include" in got["none"]
    assert "DORMANT or CLOSED" in got["none"]
    assert got["final"].startswith("PURGED is final")


def test_purging_asks_for_a_fresh_sign_in_first():
    submit = _fn("submitStatus")
    assert "to === 'PURGED' && !confirmed && stepUpStale()" in submit
    assert "confirmIdentity(" in _fn("statusAfterSignIn")


def test_a_refused_purge_names_its_own_verb():
    """PURGED is gated on case.delete. g10's status sheet said so; g12's
    dialog replaced it and said case.close for every 403 (merged
    2026-09-24). The server's detail still comes first (refusalText)."""
    submit = _fn("submitStatus")
    # The two sentences are chosen into `why` first, and handed on.
    why = submit[submit.index("const why = "):]
    why = why[:why.index(";\n")]
    assert "to === 'PURGED'" in why
    assert "needs case.delete on it" in why
    assert "needs case.close on it" in why
    said = submit[submit.index("const said = "):]
    said = said[:said.index(";\n")]
    assert "refusalText(err, why)" in said


# ---------------------------------------------------------------------------
# ux02-cases:case-record-invisible-and-uneditable
# ---------------------------------------------------------------------------

def test_the_case_record_is_shown_and_corrected_within_the_servers_rules():
    html = _html()
    sheet = html[html.index('<div id="case-scrim"'):html.index('<div id="status-scrim"')]
    for text in ("Retention can only\n        be extended",
                 "Classification can only\n          be raised",
                 "The lawful basis cannot be changed"):
        assert " ".join(text.split()) in " ".join(sheet.split()), text
    assert 'role="dialog"' in sheet and 'aria-modal="true"' in sheet
    assert "Copy link to this view" in sheet
    # The Case… tooltip says what it opens, not "title or summary".
    assert "Correct this case's title or summary" not in html
    record = _fn("renderCaseRecord")
    for label in ("'Lawful basis'", "'Authority reference'", "'Review due'",
                  "'Retention until'", "'Owner'", "'Your role'", "'Created'"):
        assert label in record, label
    assert "window.prompt('Case title'" not in _js()

    got = _run(r"""
const vals = {};
function $(id) { return { get value() { return vals[id] || ''; } }; }
function fmtDate(d) { return d; }
""" + _fn("caseRecordChanges") + r"""
const rec = { title: 'T', summary: 'S', authority_ref: 'A', review_due: '2026-12-31',
              retention_until: '2028-12-31', classification: 'AMBER' };
const set = (o) => { for (const k of Object.keys(vals)) delete vals[k]; Object.assign(vals, {
  'case-edit-title': 'T', 'case-edit-summary': 'S', 'case-edit-authority': 'A',
  'case-edit-review': '2026-12-31', 'case-edit-retention': '2028-12-31',
  'case-edit-class': 'AMBER' }, o); return caseRecordChanges(rec); };
console.log(JSON.stringify({
  same: set({}), blank: set({ 'case-edit-title': '  ' }),
  shorten: set({ 'case-edit-retention': '2027-01-01' }),
  late: set({ 'case-edit-review': '2029-01-01' }),
  raise: set({ 'case-edit-class': 'RED', 'case-edit-review': '2027-03-01' }),
}));
""")
    assert got["same"] == {"refusal": "Nothing has changed."}
    assert got["blank"]["refusal"].startswith("A case title cannot be blank")
    assert got["shorten"]["refusal"].startswith("Retention can only be extended")
    assert got["late"]["refusal"].startswith("Review due must fall on or before")
    assert got["raise"] == {"body": {"review_due": "2027-03-01", "classification": "RED"}}


# ---------------------------------------------------------------------------
# ux02-cases:reload-and-back-lose-the-case
# ---------------------------------------------------------------------------

def test_the_address_names_the_case_and_pane_and_back_returns_to_the_list():
    got = _run(r"""
const calls = [];
const location = { pathname: '/ui/', hash: '' };
const history = {
  pushState(_s, _t, url) { calls.push('push ' + url); location.hash = url.slice(4); },
  replaceState(_s, _t, url) { calls.push('replace ' + url); location.hash = url.slice(4); },
};
const document = { title: 'NocTORnal analyst console' };
""" + _const("BASE_TITLE") + "let _followingHistory = false;\n"
        + _fn("readLocation") + _fn("writeLocation") + _fn("caseTitle") + r"""
const id = '0a9de2e0-ee91-45cd-8786-0d0c502e6ff1';
writeLocation(id, null, true);          // opened from the list
writeLocation(id, 'graph', false);      // the first pane
writeLocation(id, 'evidence', false);   // a pane change
writeLocation(id, 'evidence', false);   // nothing new
const read = readLocation();
writeLocation(null, null, true);        // All cases
const title = document.title;
_followingHistory = true;
writeLocation(id, 'graph', true);       // Back into the case
console.log(JSON.stringify({ calls, read, title,
  named: caseTitle({ code: 'OP-NIGHTJAR-26', classification: 'AMBER' }) }));
""")
    cid = "0a9de2e0-ee91-45cd-8786-0d0c502e6ff1"
    assert got["calls"] == [
        f"push /ui/#case={cid}",
        f"replace /ui/#case={cid}&tab=graph",
        f"replace /ui/#case={cid}&tab=evidence",
        "push /ui/",
        f"replace /ui/#case={cid}&tab=graph",
    ], got["calls"]
    assert got["read"] == {"caseId": cid, "tab": "evidence"}
    assert got["title"] == "NocTORnal analyst console"
    # Neither the code nor the marking: the browser keeps every title in
    # its history, past Log out (final review u18, 2026-09-24).
    assert got["named"] == "Case · NocTORnal"
    assert "document.title = caseTitle();" in _fn("openCase")
    assert "writeLocation(state.caseId, name, false);" in _fn("selectTab")
    assert "window.addEventListener('popstate', onHistoryMove);" in _fn("wireCaseActions")
    # Never a credential in what is written back.
    assert "token" not in _fn("writeLocation")


# ---------------------------------------------------------------------------
# ux02-cases:case-list-lacks-triage-fields
# ---------------------------------------------------------------------------

def test_the_case_list_leads_with_open_work_and_flags_an_overdue_review():
    heads = re.findall(r'<th scope="col"[^>]*>([^<]+)</th>',
                       _html()[_html().index('id="cases-table"'):])[:7]
    assert heads == ["Code", "Title", "Status", "Classification", "Your role",
                     "Review due", "Created"], heads
    got = _run(r"""
const state = { cases: [
  { code: 'A', status: 'CLOSED', created_at: '2026-09-01', review_due: '2020-01-01' },
  { code: 'B', status: 'ACTIVE', created_at: '2026-01-01', review_due: '2020-01-01' },
  { code: 'C', status: 'DRAFT', created_at: '2026-09-02', review_due: '2999-01-01' },
  { code: 'D', status: 'ACTIVE', created_at: '2026-09-03', review_due: '2999-01-01' },
] };
let filter = 'all';
function $(id) { return id === 'cases-filter' ? { value: filter } : null; }
function el(tag, cls, text) { return { className: cls, textContent: text }; }
""" + _const("CASE_STATUS_RANK") + _const("CASE_STATES_OPEN") + _fn("todayUtc")
        + _fn("reviewOverdue") + _fn("caseStatusChip") + _fn("casesShown") + r"""
const order = () => casesShown().map((c) => c.code);
const out = { all: order() };
filter = 'open'; out.open = order();
filter = 'shut'; out.shut = order();
out.overdue = state.cases.map((c) => reviewOverdue(c));
out.chips = ['ACTIVE', 'CLOSED', 'DRAFT'].map((s) => caseStatusChip(s).className);
console.log(JSON.stringify(out));
""")
    assert got["all"] == ["D", "B", "C", "A"], "open work does not lead, newest first"
    assert got["open"] == ["D", "B", "C"] and got["shut"] == ["A"]
    assert got["overdue"] == [False, True, False, False], (
        "an overdue review is not flagged, or a closed case is called overdue")
    assert got["chips"][0] == "chip case-state case-state-ACTIVE"
    assert "case-state-off" in got["chips"][1]
    assert "case-state-draft" in got["chips"][2]
    rows = _fn("renderCases")
    assert "tr.addEventListener('click', () => openCase(c.id));" in rows, (
        "the row does not open the case")
    assert "'overdue'" in rows or "' overdue'" in rows


# ---------------------------------------------------------------------------
# ux02-cases:header-says-analyst-no-permission-cues
# ---------------------------------------------------------------------------

def test_the_header_says_role_and_clearance_not_analyst():
    html = _html()
    pill = html[html.index('<button id="btn-account"'):]
    pill = pill[:pill.index("</button>")]
    assert ">analyst<" not in pill, "every account is still called analyst"
    assert 'id="hdr-role"' in pill
    got = _run(_DOM + r"""
const state = { caseId: 'c1', caseRec: { my_role: 'CASE_OWNER', my_role_name: 'Lead investigator' },
                clearance: 'RED' };
""" + _fn("caseRoleWords") + _fn("renderHeaderRole") + r"""
renderHeaderRole();
const inCase = $('hdr-role').textContent;
state.caseId = null;
renderHeaderRole();
const onList = $('hdr-role').textContent;
state.clearance = null;
renderHeaderRole();
console.log(JSON.stringify({ inCase, onList, empty: $('hdr-role').hidden }));
""")
    assert got == {"inCase": "Lead investigator · cleared RED",
                   "onList": "cleared RED", "empty": True}
    chrome = _fn("showCaseChrome")
    assert "caseCan(rec, 'case.close')" in chrome and "caseCan(rec, 'case.update')" in chrome


# ---------------------------------------------------------------------------
# ux18-a11y:zoom-200-graph-clipped
# ---------------------------------------------------------------------------

def test_the_graph_pane_scrolls_instead_of_clipping_at_deep_zoom():
    """At 683x384 the pane was `overflow: hidden` with the scrubber and the
    legend below its edge, and the controls a 16px strip capped at 38%."""
    narrow = _media("(max-width: 900px)")
    short = _media("(max-height: 620px)")
    for block in (narrow, short):
        assert re.search(r"\.pane\.pane-graph \{ overflow-y: auto; \}", block), block[:80]
    assert "max-height: 38%" not in _css(), "the projection controls are capped again"
    assert re.search(r"@media \(max-width: 1100px\), \(max-height: 620px\) \{\s*"
                     r"\.appbar \{ scrollbar-width: thin; \}", _css()), (
        "the app bar overflows with no cue")


# ---------------------------------------------------------------------------
# ux18-a11y:canvas-selection-silent and ux18-a11y:canvas-keys-undocumented
# ---------------------------------------------------------------------------

def test_a_keyboard_selection_on_the_canvas_is_announced():
    html = _html()
    wrap = html[html.index('<div class="canvas-wrap">'):html.index('<div id="scrubber"')]
    assert re.search(r'<p id="graph-say" class="sr-only" role="status"\s+aria-live="polite">',
                     wrap)
    key = _fn("onCanvasKey")
    # Space is the whole graph tab's since ux03 space-needs-canvas-focus
    # (onSpaceDown); the arrows run up to the U key that follows them.
    arrows = key[key.index("if (e.key === 'ArrowRight'"):key.index("} else if ((e.key === 'u'")]
    assert arrows.count("saySelection();") == 2, "an arrow key changes the selection in silence"
    assert "sayGraph('Selection cleared')" in key
    got = _run(r"""
const state = { graph: { nodes: [{ id: 'a' }, { id: 'b' }] }, nodeTies: new Map([['b', 11]]),
                nodeProposed: new Map([['b', 1]]), pathAnchor: null };
function nodeById(id) { return { id, node_type: 'PERSONA', label: id === 'b' ? 'sable_marten' : 'x' }; }
function labelOf(id) { return nodeById(id).label; }
function typeName() { return 'Persona'; }
function countOf(n, one, many) { return n + ' ' + (Number(n) === 1 ? one : many); }
function edgeById() { return { edge_type: 'VOUCHED_FOR', src_label: 'a', dst_label: 'b',
                               is_inferred: true, confidence: 'LOW' }; }
""" + _fn("describeNodeForSpeech") + _fn("describeEdgeForSpeech") + r"""
console.log(JSON.stringify([describeNodeForSpeech('b'), describeEdgeForSpeech('e')]));
""")
    # The ring's Triage half (ux08-triage); the tie half is nodeUnreviewed.
    assert got == ["sable_marten, Persona, 11 ties, 1 proposal in Triage, 2 of 2",
                   "VOUCHED_FOR between a and b, inferred, LOW confidence"]


def test_the_canvas_key_strip_shows_the_keyboard_as_well_as_the_mouse():
    html = _html()
    strip = html[html.index('<p class="canvas-keys">'):]
    strip = " ".join(re.sub(r"<[^>]+>", " ", strip[:strip.index("</p>")]).split())
    for said in ("&larr; &rarr; select", "Enter ego", "P path", "+ &minus; zoom",
                 "0 fit", "Esc clear"):
        assert said in strip, f"the strip does not teach {said!r}: {strip}"


# ---------------------------------------------------------------------------
# ux18-a11y:triage-letter-keys-global
# ---------------------------------------------------------------------------

def test_the_triage_letters_act_only_in_the_list_and_accept_asks_first():
    got = _run(r"""
const calls = [];
const list = { contains: (t) => !!(t && t.inList), focus() { calls.push('list-focus'); },
               children: [] };
function $(id) { return id === 'triage-list' ? list : { children: [] }; }
const document = { activeElement: null };
let dialog = false, lettersOn = true, answer = true;
function anyDialogOpen() { return dialog; }
function triageLettersOn() { return lettersOn; }
const window = { confirm: (q) => { calls.push('asked'); return answer; } };
const state = { tab: 'triage', triage: [{ id: 1, kind: 'NODE', payload: { label: 'x' } }], triageIndex: 0 };
function acceptProposal() { calls.push('accept'); }
function rejectProposal() { calls.push('reject'); }
function deferProposal() { calls.push('defer'); }
function renderTriage() {}
function visibleText(s) { return s; }
""" + _fn("triageAcceptQuestion") + _fn("triageKeyTarget") + _fn("onTriageKey")
    # The confirm names what it accepts through these (g01, final review
    # c14, 2026-09-24).
    + _fn("triageNamed") + _fn("triageTitle") + _fn("triageClaimValue") + r"""
const press = (key, target) => onTriageKey({ key, target, preventDefault() {} });
// A card as the queue draws one: the keys act on it, never on a button
// (ux08-triage:triage-keys-fire-on-browser-chords, triageKeyTarget).
const rail = { tagName: 'BUTTON' }, card = { tagName: 'DIV', inList: true,
  classList: { contains: (c) => c === 'triage-card' } };
const out = {};
press('a', rail); press('r', rail); out.fromRail = calls.splice(0);
press('a', card); out.inList = calls.splice(0);
answer = false; press('a', card); out.declined = calls.splice(0); answer = true;
dialog = true; press('a', card); out.dialog = calls.splice(0); dialog = false;
lettersOn = false; press('a', card); out.off = calls.splice(0); lettersOn = true;
// J re-renders the cards: the focus, lost with the old card, returns to the list.
press('j', card); out.moved = calls.splice(0);
console.log(JSON.stringify(out));
""")
    assert got["fromRail"] == [], "a letter pressed on a rail tab reached the queue"
    assert got["inList"] == ["asked", "accept"]
    assert got["declined"] == ["asked"], "A wrote without the analyst's yes"
    assert got["dialog"] == [] and got["off"] == []
    assert got["moved"] == ["list-focus"], "J leaves the focus outside the list"
    html = _html()
    sheet = html[html.index('<div id="keys-scrim"'):html.index('<div id="palette-scrim"')]
    assert 'id="keys-triage-letters"' in sheet, "the letters cannot be turned off"
    assert "Nothing here writes to the graph without a confirmation step" not in sheet
    assert "<dd>Defer, with a note</dd>" in sheet
    listing = html[html.index('id="triage-list"'):]
    assert 'tabindex="0"' in listing[:listing.index(">")]


# ---------------------------------------------------------------------------
# ux18-a11y:rail-laptop-labels
# ---------------------------------------------------------------------------

def test_the_rail_names_its_tabs_the_same_at_every_height():
    """`display: none` on the captions below 820px took them out of the
    accessibility tree: the tabs were named from their titles there, and
    Lab from its badge alone, "6"."""
    for query in ("(max-height: 820px)", "(max-width: 700px)"):
        block = _media(query)
        cap = re.search(r"\.rail-cap \{([^}]*)\}", block)
        assert cap, query
        assert "display: none" not in cap.group(1) and "clip: rect(0 0 0 0)" in cap.group(1), (
            f"the captions leave the accessibility tree under {query}")
    reveal = _media("(max-width: 700px), (max-height: 820px)")
    assert ".rail-btn:focus-visible .rail-cap" in reveal, "a focused tile shows no name"
    assert re.search(r"\.rail \{\s*background:[^}]*local", _css()), "the rail gives no scroll cue"


# ---------------------------------------------------------------------------
# ux18-a11y:tertiary-contrast-inspector
# ---------------------------------------------------------------------------

def _tokens() -> dict[str, str]:
    theme = (STATIC / "theme.css").read_text(encoding="utf-8")
    return dict(re.findall(r"^\s*(--[a-z0-9-]+):\s*([^;]+);", theme, re.M))


def _rgb(value: str) -> tuple[tuple[float, float, float], float]:
    value = value.strip()
    if value.startswith("#"):
        return tuple(int(value[i:i + 2], 16) for i in (1, 3, 5)), 1.0
    m = re.match(r"rgba\((\d+),\s*(\d+),\s*(\d+),\s*([0-9.]+)\)", value)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))), float(m.group(4))


def _over(top: str, ground: tuple[float, float, float]) -> tuple[float, float, float]:
    rgb, a = _rgb(top)
    return tuple(c * a + g * (1 - a) for c, g in zip(rgb, ground, strict=True))


def _contrast(a, b) -> float:
    def lum(c):
        ch = [x / 255 for x in c]
        ch = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in ch]
        return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2]
    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_small_inspector_text_clears_aa_on_the_stack_it_sits_on():
    """theme.css measured --text-tertiary on --surface-0 only (4.52). The
    inspector is --surface-1 with a card wash and an assertion wash on
    it, where tertiary falls to 3.51:1."""
    t = _tokens()
    ground = _rgb(t["--surface-1"])[0]
    card = _over(t["--wash-1"], ground)
    assertion = _over(t["--wash-2"], card)
    tertiary, secondary = _rgb(t["--text-tertiary"])[0], _rgb(t["--text-secondary"])[0]
    assert _contrast(tertiary, assertion) < 4.5, "the premise moved: re-measure"
    for where in (ground, card, assertion):
        assert _contrast(secondary, where) >= 4.5
    css = _css()
    for selector in (".assert-meta", ".metric-rank", ".metric-note", ".insp-empty",
                     ".rail-cap"):
        rule = re.search(r"(?m)^" + re.escape(selector) + r" \{([^}]*)\}", css)
        assert rule, selector
        assert "color: var(--text-secondary)" in rule.group(1), (
            f"{selector} is set below AA on the inspector's stack")


def test_what_this_pass_wrote_clears_aa_where_it_is_drawn():
    """The verifier's second and third regressions: the new lockout line,
    the status consequences ("An archived case can never be reopened") and
    the case record's rules were written in `.help`, tertiary, on the
    sign-in card (4.07:1) and on a sheet's --surface-2 (3.75:1); the case
    list's quiet ACTIVE chip was 10px tertiary on a chip wash on a card
    (3.92:1). All below AA for text that size, on what the reader acts on."""
    t = _tokens()
    ground = _rgb(t["--surface-0"])[0]
    sheet = _rgb(t["--surface-2"])[0]
    sign_in = _over(t["--wash-2"], ground)
    card = _over(t["--wash-1"], ground)
    chip_on_card = _over(t["--wash-1"], card)
    chip_in_bar = _over(t["--wash-1"], _rgb(t["--surface-1"])[0])
    tertiary, secondary = _rgb(t["--text-tertiary"])[0], _rgb(t["--text-secondary"])[0]
    for name, where in (("sheet", sheet), ("sign-in card", sign_in), ("card", card),
                        ("chip on a card", chip_on_card), ("chip in the bar", chip_in_bar)):
        assert _contrast(tertiary, where) < 4.5, f"the premise moved on the {name}: re-measure"
        assert _contrast(secondary, where) >= 4.5, name
    css = _css()
    rule = re.search(r"(?m)^\.palette \.help, \.login-card \.help \{([^}]*)\}", css)
    assert rule and "color: var(--text-secondary)" in rule.group(1), (
        "help on the sheets and the sign-in card is below AA")
    # `.help.warn` (the same specificity) still wins, by coming later.
    assert css.index(".help.warn {") > rule.start()
    chip = re.search(r"(?m)^\.chip\.case-state \{([^}]*)\}", css)
    assert chip and "color: var(--text-secondary)" in chip.group(1), (
        "the quiet status chip is below AA")
    quiet = re.search(r"(?m)^\.cases-view \.empty, \.cases-view \.table td\.absent \{([^}]*)\}",
                      css)
    assert quiet and "color: var(--text-secondary)" in quiet.group(1)
    # And each line this pass wrote is under one of those rules.
    html = _html()
    start = html.index('<form id="login-form"')
    sign_in_form = html[start:html.index("</form>", start)]
    assert 'class="card login-card"' in sign_in_form and 'id="login-policy"' in sign_in_form
    for scrim in ('<div id="case-scrim"', '<div id="status-scrim"', '<div id="keys-scrim"'):
        sheet_html = html[html.index(scrim):]
        sheet_html = sheet_html[:sheet_html.index("\n</div>\n")]
        assert 'class="palette ' in sheet_html, scrim
    assert "el('span', 'help', statusConsequence(" in _fn("openStatus")


# ---------------------------------------------------------------------------
# ux18-a11y:banners-cover-appbar
# ---------------------------------------------------------------------------

def test_banners_sit_below_the_app_bar_and_advice_expires():
    rule = re.search(r"\.banners \{([^}]*)\}", _css()).group(1)
    assert "top: calc(var(--appbar-h) + 8px)" in rule, "the stack covers the app bar"
    got = _run(r"""
class ApiError extends Error {
  constructor(status, title, detail) { super(title); this.status = status;
    this.title = title; this.detail = detail || ''; }
}
const shown = [];
function banner(title, detail, kind, expire) { shown.push([title, kind || null, expire || null]); }
// What failed, by path (ux17-failure:banners-block-appbar): none here.
function requestLabel() { return null; }
""" + _fn("fail") + r"""
const limited = new ApiError(429, 'Too many requests', 'retry in 6s');
limited.retryAfter = 6;
fail(limited);
fail(new ApiError(500, 'Internal error', 'boom'));
console.log(JSON.stringify(shown));
""")
    assert got == [["Too many requests", "warn", 7000], ["Internal error", None, None]]
    assert "setTimeout(() => b.remove(), expireMs);" in _fn("banner")


# ---------------------------------------------------------------------------
# ux18-a11y:admin-row-selects-unnamed
# ---------------------------------------------------------------------------

def test_the_admin_card_pickers_are_named_for_the_account():
    """Named for the account they change, beside their verbs: the Admin
    card's pickers since ux16-admin restructured it the same day, each in
    a labelled pair (clearancePair, grantPair)."""
    clearance = _fn("clearancePair")
    assert "clr.setAttribute('aria-label', 'New clearance for ' + visibleText(u.display_name));" in clearance
    grant = _fn("grantPair")
    assert "sel.setAttribute('aria-label', 'Role to grant to ' + visibleText(u.display_name));" in grant
    assert "el('span', 'label', 'Clearance')" in clearance
    assert "el('span', 'label', 'Role to grant')" in grant


# ---------------------------------------------------------------------------
# The copy rules, for everything this pass wrote
# ---------------------------------------------------------------------------

_NEW = ("signInRefused", "retryAfterSeconds", "hideCaseChrome", "showCaseChrome",
        "renderHeaderRole", "renderCaseRecord", "caseRecordChanges", "saveCaseRecord",
        "openStatus", "onStatusPicked", "submitStatus", "statusAfterSignIn",
        "renderCases", "triageAcceptQuestion", "describeNodeForSpeech",
        "describeEdgeForSpeech", "noteLiveSessionEnded", "onCanvasKey",
        "discardPage", "liveSessionStillOurs", "relinkLive")


@pytest.mark.parametrize("name", _NEW)
def test_this_pass_writes_no_dash_and_no_lazy_plural(name: str):
    strings = re.findall(r"'(?:[^'\\\n]|\\.)*'", _fn(name))
    bad = [s for s in strings if re.search("[\u2013\u2014]| -- |\\(s\\)", s)]
    assert not bad, bad


def test_the_new_markup_writes_no_dash():
    html = re.sub(r"<!--.*?-->", "", _html(), flags=re.S)
    for anchor in ('id="login-policy"', 'id="case-scrim"', 'id="status-scrim"',
                   'id="cases-sort-note"'):
        start = html.index(anchor)
        chunk = html[start:start + 4000]
        assert not re.search("[\u2013\u2014]|&mdash;|&ndash;", chunk), anchor
    for text in (_const("STATUS_MOVES"),):
        assert not re.search("[\u2013\u2014]", text)

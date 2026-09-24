"""The session's edges, held from the shipped console files.

Four findings of the final adversarial review (2026-09-23), each with the
check that would have caught it:

- C4: the password, TOTP secret and QR code an administrator was issued
  for another account stayed in the Admin pane after a sign-out, for the
  next analyst signed in on the same tab.
- C19: signing in on the first-run card left the sign-in form hidden, so
  the first sign-out after a first run showed an empty page.
- C20: refetches driven by the live channel slid the session's idle
  window, so a console left open on a busy case never timed out. Found
  while fixing it: every case switch after the first left the socket
  reconnecting about once a second, forever, and each handshake slides
  the session too.
- U16: a password typed into the in-place sign-in sheet stayed in its
  hidden input after Cancel or "Sign in as someone else".

Pure, like test_ui_first_run_session: the static assets, with the real
functions run under Node against stubs (skipped where Node is absent).
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
APP_JS = STATIC / "app.js"


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """A top-level function: one line when it closes on its own line,
    otherwise declaration to the first `}` at column 0."""
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    line = js[m.start():js.index("\n", m.start())]
    if line.rstrip().endswith("}") and line.count("{") == line.count("}"):
        return line + "\n"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _const(name: str) -> str:
    """A top-level `const`: its one line when that line ends the
    statement, otherwise through the line that closes it at column 0
    (`}, 900);` for a debounced body)."""
    js = _js()
    m = re.search(rf"^const {re.escape(name)} = ", js, flags=re.M)
    assert m, f"app.js has no top-level const {name}"
    line = js[m.start():js.index("\n", m.start())]
    if line.rstrip().endswith(";") and line.count("(") == line.count(")") \
            and line.count("{") == line.count("}"):
        return line + "\n"
    close = js.index("\n}", m.start()) + 1
    return js[m.start():js.index("\n", close) + 1]


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    default = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "nodejs" / "node.exe"
    return str(default) if default.exists() else None


def _run_node(source: str) -> dict:
    node = _node()
    if not node:
        pytest.skip("Node is not installed; the browser-side check needs it")
    out = subprocess.run([node, "-"], input=source, capture_output=True,
                         text=True, encoding="utf-8", timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# A DOM just big enough for the session functions: ids to nodes with a
# `hidden` flag, a value, children, and a log of what was focused.
_DOM = r"""
const log = [];
const els = {};
function $(id) {
  if (!els[id]) els[id] = { id, hidden: false, value: '', textContent: '',
    children: [], inert: false, className: '', title: '',
    focus() { log.push('focus:' + id); } };
  return els[id];
}
function show(node, on) { node.hidden = !on; log.push((on ? 'show:' : 'hide:') + node.id); }
function clear(node) { node.children = []; log.push('clear:' + node.id); }
const window = { listeners: [],
  addEventListener(type, fn, opts) { this.listeners.push({ type, fn, opts }); },
  removeEventListener() {} };
const document = { cookie: '', contains() { return true; }, activeElement: null };
"""


# ---------------------------------------------------------------------------
# C4: one-time credentials end with the session that was shown them
# ---------------------------------------------------------------------------

_FIRST_RUN_BOXES = {"setup-creds", "setup-codes-list"}


def test_every_one_time_secret_box_is_cleared_when_the_session_ends():
    """Held to the call sites, so the next pane that shows a secret cannot
    forget to clear it: every box `renderOneTimeCreds` or
    `renderRecoveryCodes` writes into is either first run's (shown before
    there is a session, with rules of its own) or emptied by
    `clearSessionSecrets`, which both ends of a session call."""
    js = _js()
    boxes = set(re.findall(
        r"render(?:OneTimeCreds|RecoveryCodes)\(\$\('([\w-]+)'\)", js))
    assert "adm-creds" in boxes and "account-codes-out" in boxes, boxes
    clears = _fn("clearSessionSecrets")
    missing = {b for b in boxes - _FIRST_RUN_BOXES if f"clear($('{b}'))" not in clears}
    assert not missing, f"secrets shown here outlive the session: {missing}"
    assert "clearSessionSecrets()" in _fn("stopSessionClock")
    start = _fn("startApp")
    assert start.index("clearSessionSecrets()") < start.index("show($('view-app'), true)"), (
        "the app is shown to the new account before the old secrets are gone")


def test_admin_credentials_do_not_reach_the_next_analyst_on_the_tab():
    """Driven through the real functions. An administrator is issued a
    new analyst's credentials; then (1) signs out, (2) lapses and signs
    back in as themself, (3) lapses and the sheet signs in a DIFFERENT
    account, which reaches `startApp` without `endSession`."""
    source = _DOM + r"""
const state = { caseId: 'c1', booting: false };
const SESSION = { timer: null, confirmWaiters: [], lapsed: false, mode: null,
  accountWasOpen: false, lapseUnsafe: false, lapseMissedRead: false,
  serverEnded: false, idleMs: 1800000 };
let me = { user_id: 'admin' };
const stub = (n) => function () { log.push(n); };
const hideIdleWarning = stub('hideIdleWarning'), guardUnsaved = stub('guard');
const disconnectLive = stub('disconnectLive'), closePalette = stub('closePalette');
const rememberResume = stub('rememberResume'), openReauth = stub('openReauth');
const describeLapse = stub('describeLapse'), adoptStepUp = stub('adoptStepUp');
const noteSessionActivity = stub('activity'), renderAccountChip = stub('chip');
const forgetResume = stub('forgetResume'), clearSessionBanners = stub('banners');
const connectLive = stub('connectLive'), showCaseList = async () => log.push('caseList');
const closeReauth = () => { log.push('closeReauth'); SESSION.mode = null; };
const setAccountOpen = stub('account'), sessionBanner = stub('sessionBanner');
const watchPresence = stub('watch'), forgetHeldLive = stub('forgetHeld');
const halfSession = () => false, endSession = stub('endSession');
const refreshGlassChip = stub('refreshGlassChip');
const adoptSessionFacts = stub('facts'), applyResume = stub('resume');
const renderHeaderRole = stub('headerRole');   // ux02-cases, 2026-09-23
const relinkLive = stub('relinkLive');         // ux01-firstrun, 2026-09-23
const endReauthChange = stub('endReauthChange'); // final review u5, 2026-09-24
const api = async () => me;
""" + "\n".join(_fn(n) for n in (
        "clearSessionSecrets", "stopSessionClock", "sessionLapsed",
        "sessionRenewed", "startApp")) + r"""
const issue = () => { $('adm-creds').children = ['password', 'secret', 'qr']; };
(async () => {
  const out = {};
  // 1. A sign-out: endSession stops the clock.
  issue(); stopSessionClock();
  out.signOut = { kids: $('adm-creds').children.length, hidden: $('adm-creds').hidden };
  // 2. A lapse, then the same administrator back in place.
  issue(); log.length = 0;
  sessionLapsed({ cause: 'idle', unsafe: false });
  out.underSheet = { kids: $('adm-creds').children.length, hidden: $('adm-creds').hidden };
  SESSION.mode = 'lapsed';
  sessionRenewed(43200, null);
  out.renewed = { kids: $('adm-creds').children.length, hidden: $('adm-creds').hidden };
  // 3. A lapse, then someone else signs in through the sheet.
  sessionLapsed({ cause: 'idle', unsafe: false });
  me = { user_id: 'someone-else' }; log.length = 0;
  await startApp();
  out.other = { kids: $('adm-creds').children.length, hidden: $('adm-creds').hidden,
    order: log.filter((l) => l === 'clear:adm-creds' || l === 'show:view-app') };
  process.stdout.write(JSON.stringify(out));
})();
"""
    got = _run_node(source)
    assert got["signOut"] == {"kids": 0, "hidden": False}, got["signOut"]
    assert got["underSheet"] == {"kids": 3, "hidden": True}, (
        "the credentials show through the scrim of a lapsed, empty desk")
    assert got["renewed"] == {"kids": 3, "hidden": False}, (
        "the administrator's own in-place sign-in lost the card")
    assert got["other"]["kids"] == 0 and got["other"]["hidden"] is False, got["other"]
    assert got["other"]["order"] == ["clear:adm-creds", "show:view-app"], got["other"]


# ---------------------------------------------------------------------------
# C19: the sign-in form survives a first run
# ---------------------------------------------------------------------------

def test_the_sign_in_form_is_there_after_a_first_run():
    """First run hides the form (`probeFirstRun`) and the card's sign-in
    goes straight to `startApp`. Driven through the real `startApp` and
    `endSession`: after a first run, a sign-out lands on the form; a 401
    between the card's sign-in and the console does too; and a first-run
    card still on screen is not covered by it."""
    assert "show($('login-form'), false)" in _fn("probeFirstRun"), (
        "first run no longer hides the form; this test's premise moved")
    source = _DOM + r"""
const state = { booting: false, userId: 'u', caseId: 'c1', token: null };
const stub = (n) => function () { log.push(n); };
const watchPresence = stub('watch'), forgetHeldLive = stub('forgetHeld');
const halfSession = () => false, adoptSessionFacts = stub('facts');
const applyResume = stub('resume'), clearSessionBanners = stub('banners');
const clearSessionSecrets = stub('secrets'), showCaseList = async () => {};
const api = async () => ({ user_id: 'u' });
const rememberResume = stub('rememberResume'), closePalette = stub('closePalette');
const stopGraph = stub('stopGraph'), disconnectLive = stub('disconnectLive');
const stopSessionClock = stub('stopClock'), sessionBanner = stub('sessionBanner');
// The case chrome and the header role go with the session (ux01-firstrun,
// ux02-cases, 2026-09-23); their own tests are in test_ui_signin_and_cases.
const hideCaseChrome = stub('hideCaseChrome'), renderHeaderRole = stub('headerRole');
const CSRF_COOKIE = '__Host-csrf';
""" + _fn("startApp") + "\n" + _fn("endSession") + r"""
const firstRun = () => {   // what probeFirstRun and the card leave behind
  $('login-form').hidden = true; $('setup-form').hidden = true;
  $('setup-done').hidden = true; $('setup-codes').hidden = true;
};
(async () => {
  const out = {};
  firstRun(); $('login-email').value = 'admin@x.test';
  await startApp();
  out.afterStart = !$('login-form').hidden;      // the view's default, for next time
  endSession(null, null);                        // Sign out
  out.signOut = { form: !$('login-form').hidden, view: !$('view-login').hidden,
                  focus: log.filter((l) => l.startsWith('focus:')).pop() };
  firstRun();
  endSession('Session ended', 'expired');       // a 401 before startApp ran
  out.early = !$('login-form').hidden;
  firstRun(); $('setup-done').hidden = false;    // the card, secrets unproven
  endSession('Session ended', 'expired');
  out.cardUp = $('login-form').hidden;
  process.stdout.write(JSON.stringify(out));
})();
"""
    got = _run_node(source)
    assert got["afterStart"] is True, "startApp leaves the sign-in form as first run hid it"
    assert got["signOut"] == {"form": True, "view": True, "focus": "focus:login-password"}, (
        f"the first sign-out after first run lands on an empty page: {got['signOut']}")
    assert got["early"] is True, "a 401 on the way into the console leaves the page empty"
    assert got["cardUp"] is True, "the sign-in form was put over a first-run card"


# ---------------------------------------------------------------------------
# C20: the live channel does not keep an empty desk signed in
# ---------------------------------------------------------------------------

_LIVE_STUBS = r"""
let now = 0; Date.now = () => now;
const API = '/api/v1';
const location = { protocol: 'http:', host: 'x' };
const state = { caseId: 'c1', token: null };
let signed = true;
function signedIn() { return signed; }
const timers = [];
const setTimeout = (fn, ms) => { timers.push(ms); return timers.length; };
const clearTimeout = () => {};
const _refetchSoon = () => log.push('refetch');
const _badgeSoon = () => log.push('badge');
// The triage queue's own refetch (ux08-triage:stale-badges-and-list,
// 2026-09-23): a reopened socket reloads it with the rest.
const _triageSoon = () => log.push('triage');
const sockets = [];
class FakeWS {
  constructor(url) { this.url = url; this.readyState = 0; this.listeners = {};
    sockets.push(this); log.push('open:' + sockets.length); }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  fire(type, ev) { for (const fn of this.listeners[type] || []) fn(ev || {}); }
  send() {}
  ready() { this.readyState = 1; this.fire('message', { data: '{"type":"ready"}' }); }
  frame(kind) { this.fire('message', { data: JSON.stringify({ type: 'change', kind }) }); }
  // As a browser does: the close event comes later, with 1005 for a close
  // this page asked for.
  close() { this.readyState = 3; Promise.resolve().then(() => this.fire('close', { code: 1005 })); }
  drop(code) { this.readyState = 3; this.fire('close', { code }); }
}
window.WebSocket = FakeWS;
const WebSocket = FakeWS;         // Node has a real one of its own
let _ws = null;
let _wsRetry = 0;
let _wsTimer = null;
"""


def _live_source(body: str) -> str:
    js = _js()
    decls = [_const("LIVE_AWAY_MS"), _const("_liveHeld"),
             _const("LIVE_SESSION_ENDED")]
    for name in ("_lastPresence", "_presenceWatched"):
        m = re.search(rf"^let {name} = .*;$", js, flags=re.M)
        assert m, f"app.js has no top-level let {name}"
        decls.append(m.group(0) + "\n")
    return (_DOM + _LIVE_STUBS + "".join(decls)
            + "\n".join(_fn(n) for n in (
                "liveAway", "watchPresence", "notePresence", "forgetHeldLive",
                "onLiveChange", "liveStatus", "noteLiveSessionEnded",
                "connectLive", "disconnectLive"))
            + "\nconst tick = () => new Promise((r) => r());\n"
            + "(async () => {\nconst out = {};\n" + body
            + "\nprocess.stdout.write(JSON.stringify(out));\n})();\n")


def test_changes_are_held_while_nobody_is_at_the_console():
    """A change frame is refetched at once while the analyst is here, and
    held once nobody has touched the page for five minutes, so an empty
    desk makes no request and the idle expiry comes. The analyst's next
    input loads what was held, once."""
    got = _run_node(_live_source(r"""
watchPresence(); watchPresence();
out.watched = window.listeners.map((l) => [l.type, !!(l.opts && l.opts.capture)]);
const presence = () => window.listeners[0].fn();
connectLive(); const ws = sockets[0]; ws.ready();
now = 60 * 1000;
ws.frame('node'); ws.frame('notification');
out.here = log.filter((l) => l === 'refetch' || l === 'badge'); log.length = 0;
now = 6 * 60 * 1000;                           // five minutes and more since the page was touched
ws.frame('node'); ws.frame('edge'); ws.frame('notification');
out.away = { calls: log.filter((l) => l === 'refetch' || l === 'badge'),
             dot: $('live-dot').className, title: $('live-dot').title };
presence(); presence();
out.back = { calls: log.filter((l) => l === 'refetch' || l === 'badge'),
             dot: $('live-dot').className };
// Held through a lapse, loaded once the session answers again.
log.length = 0; now += 6 * 60 * 1000; ws.frame('node');
signed = false; presence();
out.lapsed = log.filter((l) => l === 'refetch');
signed = true; presence();
out.renewed = log.filter((l) => l === 'refetch');
"""))
    assert got["watched"] == [["keydown", True], ["pointerdown", True],
                              ["pointermove", True], ["wheel", True]], got["watched"]
    assert got["here"] == ["refetch", "badge"], got["here"]
    assert got["away"]["calls"] == [], (
        f"an unattended console asked the server for {got['away']['calls']}")
    assert got["away"]["dot"] == "live-dot live-off" and "Paused" in got["away"]["title"], (
        "the dot stays lit over a picture that has stopped")
    assert sorted(got["back"]["calls"]) == ["badge", "refetch"], got["back"]
    assert got["back"]["dot"] == "live-dot live-live"
    assert got["lapsed"] == [] and got["renewed"] == ["refetch"], got


def test_a_case_switch_does_not_leave_the_socket_reconnecting_forever():
    """`disconnectLive` lets `_ws` go and closes the old socket, and the
    close event arrives later. The handler reconnected it anyway, and the
    reconnect closed the NEW socket, whose handler reconnected again: a
    socket a second for the life of the tab, each handshake sliding the
    session. Measured at 23 sockets in 23 seconds before the fix."""
    got = _run_node(_live_source(r"""
connectLive(); sockets[0].ready();
connectLive(); sockets[1].ready();             // the analyst opens another case
await tick(); await tick();
out.switch = { sockets: sockets.length, timers: timers.slice(),
               current: _ws === sockets[1], dot: $('live-dot').className };
// A socket the SERVER drops is still reconnected, with the backoff.
now = 60 * 1000; window.listeners.length = 0; watchPresence();
sockets[1].drop(1006);
out.dropped = { timers: timers.slice(), dot: $('live-dot').className };
// ...but not while nobody is here: the handshake slides the session too.
timers.length = 0; connectLive(); sockets[2].ready();
now += 6 * 60 * 1000;
sockets[2].drop(1006);
out.awayDrop = { timers: timers.slice(), sockets: sockets.length };
log.length = 0; window.listeners[1].fn();       // a click
out.back = { sockets: sockets.length, calls: log.filter((l) => l === 'refetch' || l === 'badge') };
// The policy close is final either way.
timers.length = 0; sockets[3].drop(1008);
now += 6 * 60 * 1000; window.listeners[0].fn();
out.policy = { timers: timers.slice(), sockets: sockets.length };
// A lapse or a sign-out closes the socket on purpose: no reconnect, and
// the dot says so, since the close handler now returns for it.
connectLive(); sockets[4].ready(); timers.length = 0;
disconnectLive(); await tick(); await tick();
out.ended = { timers: timers.slice(), dot: $('live-dot').className };
"""))
    assert got["switch"]["sockets"] == 2 and got["switch"]["timers"] == [], (
        f"closing the old case's socket scheduled a reconnect: {got['switch']}")
    assert got["switch"]["current"] is True
    assert got["switch"]["dot"] == "live-dot live-live", (
        "the old socket's close painted the new socket's dot off")
    assert got["dropped"]["timers"] == [1000] and got["dropped"]["dot"] == "live-dot live-off"
    assert got["awayDrop"] == {"timers": [], "sockets": 3}, got["awayDrop"]
    assert got["back"]["sockets"] == 4, "the analyst came back and the socket stayed shut"
    assert sorted(got["back"]["calls"]) == ["badge", "refetch"], (
        "what changed while the socket was down was never loaded")
    assert got["policy"] == {"timers": [], "sockets": 4}, got["policy"]
    assert got["ended"] == {"timers": [], "dot": "live-dot live-off"}, got["ended"]


def test_the_socket_handler_routes_every_change_through_the_hold():
    body = _fn("connectLive")
    handler = body[body.index("ws.addEventListener('message'"):body.index("ws.addEventListener('close'")]
    assert "onLiveChange(msg)" in handler
    assert "_refetchSoon(" not in handler and "_badgeSoon(" not in handler, (
        "a change frame reaches a refetch without asking whether anyone is here")
    close = body[body.index("ws.addEventListener('close'"):]
    assert close.index("if (_ws !== ws) return;") < close.index("setTimeout(connectLive"), (
        "a socket closed on purpose is reconnected")
    assert close.index("liveAway()") < close.index("setTimeout(connectLive")
    assert "watchPresence()" in _fn("startApp")


def test_a_refetch_that_fires_after_the_session_asks_nothing():
    """A held refetch can fire on the click of Sign out: 900 ms later the
    tab has no analyst, and a 401 there reads "Session ended" over the
    form the analyst just asked for. Both debounced bodies ask
    `signedIn()` when they run."""
    source = _DOM + r"""
const debounce = (fn) => fn;
const state = { caseId: 'c1' };
let signed = false;
function signedIn() { return signed; }
async function loadCaseGraph() { log.push('graph'); }
async function refreshSociogram() { log.push('sociogram'); }
function refreshInboxBadge() { log.push('badge'); }
// The badge refetch also reloads an open inbox list since
// ux08-triage:stale-badges-and-list (2026-09-23); none is open here.
function inboxOnScreen() { return false; }
""" + _const("_refetchSoon") + _const("_badgeSoon") + r"""
(async () => {
  await _refetchSoon(); _badgeSoon();
  const off = log.slice(); log.length = 0;
  signed = true; await _refetchSoon(); _badgeSoon();
  process.stdout.write(JSON.stringify({ off, on: log.slice() }));
})();
"""
    got = _run_node(source)
    assert got["off"] == [], f"a refetch went out with no session: {got['off']}"
    assert got["on"] == ["graph", "sociogram", "badge"], got["on"]


# ---------------------------------------------------------------------------
# U16: the sign-in sheet forgets what was typed into it
# ---------------------------------------------------------------------------

def test_the_sign_in_sheet_forgets_the_password_when_it_closes():
    """Cancel and Escape (`leaveReauth` in confirm mode), "Sign in as
    someone else" (lapsed mode, through `endSession`) and a teardown that
    hides the sheet directly (`stopSessionClock`) all leave both fields
    empty."""
    source = _DOM + r"""
const state = { booting: false };
const SESSION = { timer: null, confirmWaiters: [], restoreFocus: null,
  mode: 'confirm', serverEnded: true, email: 'a@x.test', userId: 'u' };
const stub = (n) => function () { log.push(n); };
const hideIdleWarning = stub('hideIdleWarning'), guardUnsaved = stub('guard');
const clearSessionSecrets = stub('secrets');
const endSession = () => { log.push('endSession'); stopSessionClock(); };
const discardPage = stub('discardPage');       // ux01-firstrun, 2026-09-23
""" + _const("REAUTH_CHANGE") + "\n".join(
        _fn(n) for n in ("closeReauth", "leaveReauth", "stopSessionClock",
                         "endReauthChange")) + r"""
// And a one-time password held for the sheet's new-password stage (final
// review u5, 2026-09-24): it still signs in until it is replaced.
const type = () => { $('reauth-password').value = 'hunter2'; $('reauth-totp').value = '123456';
  REAUTH_CHANGE.password = 'one-time'; $('reauth-new').value = 'typed new'; };
const left = () => [$('reauth-password').value, $('reauth-totp').value,
  REAUTH_CHANGE.password === null ? '' : 'held', $('reauth-new').value];
(async () => {
  const out = {};
  type(); await leaveReauth(); out.cancel = left();
  type(); SESSION.mode = 'lapsed'; await leaveReauth(); out.someoneElse = left();
  type(); stopSessionClock(); out.teardown = left();
  process.stdout.write(JSON.stringify(out));
})();
"""
    got = _run_node(source)
    for path in ("cancel", "someoneElse", "teardown"):
        assert got[path] == ["", "", "", ""], (
            f"{path} left the password in the page: {got[path]}")


# ---------------------------------------------------------------------------
# The house rule for copy: no em or en dashes in what this change wrote
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "clearSessionSecrets", "liveAway", "watchPresence", "notePresence",
    "forgetHeldLive", "onLiveChange", "liveStatus", "disconnectLive",
    "closeReauth", "stopSessionClock"])
def test_the_session_edges_carry_no_dashes(name: str):
    body = _fn(name)
    assert "\u2014" not in body and "\u2013" not in body, f"{name} carries a dash"

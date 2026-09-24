"""First run and the session, held from the shipped console files.

Four findings of the 2026-09-22 review, each with the check that would have
caught it:

- firstrun-oneclick-wipe: the first-run card showed a generated password
  and TOTP secret and one "I saved them" click removed both, with nothing
  checked. The secrets must now outlive the click until a sign-in with them
  has succeeded, or until a confirmation that says what is lost.
- totp-enrolment-typein: enrolment was a 32-character type-in (no QR code),
  the copy buttons were invisible and the enrolment URI ran out of the
  card. The QR encoder is held module for module to the `qrcode` package
  `scripts/bootstrap.py` already uses, and the browser's TOTP to
  `security/totp.py`, by running both under Node.
- recovery-codes-unobtainable: the sign-in form offered recovery codes that
  nothing in the console could issue.
- expiry-drops-context: an idle expiry arrived unannounced, did not say the
  Save that met it had failed, and dropped the analyst on the case list.

Pure, like test_ui_invariants: the static assets and the router sources,
plus Node when it is installed (the two cross-checks skip without it).
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
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


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _html() -> str:
    return INDEX.read_text(encoding="utf-8")


def _css() -> str:
    return re.sub(r"/\*.*?\*/", "", APP_CSS.read_text(encoding="utf-8"), flags=re.S)


def _fn(name: str) -> str:
    """A top-level function, declaration to the first `}` at column 0."""
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _block(html: str, element_id: str) -> str:
    """The markup of one element with this id, to its matching close tag."""
    start = html.index(f'id="{element_id}"')
    start = html.rindex("<", 0, start)
    tag = re.match(r"<(\w+)", html[start:]).group(1)
    depth, i = 0, start
    for m in re.finditer(rf"<(/?){tag}\b[^>]*>", html[start:]):
        depth += -1 if m.group(1) else 1
        if depth == 0:
            i = start + m.end()
            break
    return html[start:i]


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    default = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "nodejs" / "node.exe"
    return str(default) if default.exists() else None


def _run_node(source: str) -> str:
    node = _node()
    if not node:
        pytest.skip("Node is not installed; the browser-side cross-check needs it")
    out = subprocess.run([node, "-"], input=source, capture_output=True,
                         text=True, encoding="utf-8", timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout


# ---------------------------------------------------------------------------
# totp-enrolment-typein: a scannable code, a checkable secret
# ---------------------------------------------------------------------------

_QR_TEXTS = [
    "HELLO",
    "",
    # The shape iam_admin._otpauth_uri issues, at a realistic length.
    "otpauth://totp/NocTORnal:analyst@noctornal.test?secret="
    "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=NocTORnal&algorithm=SHA1"
    "&digits=6&period=30",
    # Long enough for version information (7+) and many interleaved blocks.
    "x" * 400,
    # Multi-byte UTF-8: byte mode counts bytes, not characters.
    "Zo\u00eb caf\u00e9 \u2603 " * 6,
]


def test_the_qr_encoder_matches_the_reference_encoder_module_for_module():
    """Every mask of every sample against `qrcode`, the package
    `bootstrap.py` prints its enrolment QR with, at the same version,
    level M and mask, in byte mode. Also the version it picks: a code one
    version too small would not hold the URI."""
    qrcode = pytest.importorskip("qrcode")
    from qrcode.util import MODE_8BIT_BYTE, QRData

    cases = [[t, m] for t in _QR_TEXTS for m in range(8)]
    cases += [[t, None] for t in _QR_TEXTS]
    source = (_fn("qrMatrix") + "\nconst cases = " + json.dumps(cases) + ";\n"
              "process.stdout.write(JSON.stringify(cases.map(([t, m]) =>"
              " qrMatrix(t, m === null ? undefined : m))));\n")
    results = json.loads(_run_node(source))
    assert len(results) == len(cases)
    for (text, _mask), got in zip(cases, results, strict=True):
        raw = text.encode("utf-8")
        fit = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=0)
        fit.add_data(QRData(raw, mode=MODE_8BIT_BYTE))
        fit.make(fit=True)
        assert got["version"] == fit.version, (text[:20], got["version"], fit.version)
        ref = qrcode.QRCode(version=got["version"], border=0, mask_pattern=got["mask"],
                            error_correction=qrcode.constants.ERROR_CORRECT_M)
        ref.add_data(QRData(raw, mode=MODE_8BIT_BYTE))
        ref.make(fit=False)
        want = ["".join("1" if c else "0" for c in row) for row in ref.get_matrix()]
        assert got["modules"] == want, (
            f"QR for {text[:24]!r} (version {got['version']}, mask {got['mask']}) "
            f"differs from the reference encoder")


def test_the_browser_computes_the_same_codes_the_server_accepts():
    """The card checks a code against the secret BEFORE a sign-in is sent,
    so a mistyped secret costs no lockout attempt. That check is only
    worth having if it agrees with `security/totp.py`, step for step, and
    with the RFC 6238 SHA-1 vector."""
    from noctornal_api.security import totp

    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    times = [59, 1_111_111_109, 1_234_567_890, 2_000_000_000, 20_000_000_000]
    rfc = base64.b32encode(b"12345678901234567890").decode("ascii")
    source = (_fn("base32Bytes") + "\n" + _fn("totpCodes") + "\n"
              "(async () => {\n"
              f"  const times = {json.dumps(times)};\n"
              "  const out = [];\n"
              f"  for (const t of times) out.push(await totpCodes({json.dumps(secret)}, t * 1000, 1));\n"
              # Spaces and lower case, as a person pastes a grouped secret.
              f"  out.push(await totpCodes({json.dumps(secret.lower())}.replace(/(.{{4}})/g, '$1 '), times[2] * 1000, 0));\n"
              f"  out.push(await totpCodes({json.dumps(rfc)}, 59000, 0));\n"
              "  out.push(await totpCodes('not base32!', 0, 0));\n"
              "  process.stdout.write(JSON.stringify(out));\n"
              "})();\n")
    got = json.loads(_run_node(source))
    for t, codes in zip(times, got[:len(times)], strict=True):
        assert codes == [totp.code_at(secret, t + d * 30) for d in (-1, 0, 1)], t
    assert got[len(times)] == [totp.code_at(secret, times[2])]
    assert got[len(times) + 1] == ["287082"], "RFC 6238 appendix B, T=59, SHA-1"
    assert got[len(times) + 2] is None, "an invalid secret must not produce codes"


def test_the_local_code_check_accepts_what_the_server_accepts_and_names_a_skew():
    """Fix round, 2026-09-22. The local checks allowed two steps either
    side where `security/totp.py` allows one, so a code from a phone about
    a minute out passed here, was refused by the server, and the refusal
    was blamed on the server's clock. The window is now the server's, and
    a code from further out is told apart from a wrong secret."""
    from noctornal_api.security import totp

    js = _js()
    drift = re.search(r"^const TOTP_SERVER_DRIFT = (\d+);", js, flags=re.M)
    assert drift and int(drift.group(1)) == totp.DRIFT_WINDOWS, (
        "the browser's code window differs from the server's")
    assert not re.search(r"totpCodes\([^)]*,\s*2\)", js), "a +/-2 check is back"
    consts = "\n".join(re.findall(r"^const TOTP_[A-Z_]+ = \d+;.*$", js, flags=re.M))

    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    t = 1_700_000_015
    offsets = [-1, 0, 1, 2, -3, 7]
    near = {totp.code_at(secret, t + d * 30) for d in range(-10, 11)}
    stranger = next(c for c in (f"{n:06d}" for n in range(1_000_000)) if c not in near)
    probes = [totp.code_at(secret, t + d * 30) for d in offsets] + [stranger]
    source = ("\n".join([_fn("base32Bytes"), _fn("totpCodes"), consts,
                         _fn("totpStepOffset")]) + "\n(async () => {\n"
              f"  const probes = {json.dumps(probes)};\n  const out = [];\n"
              f"  for (const p of probes) out.push(await totpStepOffset({json.dumps(secret)}, p, {t * 1000}));\n"
              "  process.stdout.write(JSON.stringify(out));\n})();\n")
    got = json.loads(_run_node(source))
    assert got == offsets + [None]

    # Both checks judge a match by the server's window, and say "clock"
    # rather than "wrong secret" when the code is right but out of it.
    for name in ("credCheckRow", "verifyFirstRun"):
        body = _fn(name)
        assert "TOTP_SERVER_DRIFT" in body and "totpSkewText(" in body, name
    check = _fn("credCheckRow")
    assert check.index("/^[0-9]{6}$/.test(code)") < check.index("totpStepOffset("), (
        "an unfinished code is judged as a mistyped secret again")


def test_the_credential_card_is_scannable_copyable_and_contained():
    """The QR is drawn, the secret has a manual form in groups of four, the
    Copy buttons are always visible on this card, and long values wrap."""
    render = _fn("renderOneTimeCreds")
    assert "drawQr(" in render, "the card draws no QR code"
    assert "(.{4})" in render, "the manual secret is not grouped"
    assert "credCopyButton(" in _fn("credRow")
    css = _css()
    rule = re.search(r"\.creds \.copy-btn\s*\{([^}]*)\}", css)
    assert rule and re.search(r"opacity:\s*1\b", rule.group(1)), (
        "the copy buttons on the credential card are hover-only again")
    value = re.search(r"\.creds-value\s*\{([^}]*)\}", css)
    assert value and "overflow-wrap: anywhere" in value.group(1), (
        "a long credential value can run out of its card")
    # When the clipboard refuses, the value is selected instead: never
    # unreachable (the card's own promise).
    assert "selectAllChildren" in _fn("credCopyButton")
    # The QR is painted from theme tokens, dark on light.
    draw = _fn("drawQr")
    assert "cssVar('--void')" in draw and "cssVar('--text-primary')" in draw


# ---------------------------------------------------------------------------
# firstrun-oneclick-wipe: nothing is forgotten on an assertion
# ---------------------------------------------------------------------------

def test_the_first_run_secrets_outlive_everything_but_a_proven_sign_in():
    html = _html()
    # Comments stripped: the one explaining the change quotes the old label.
    assert "I saved them" not in re.sub(r"<!--.*?-->", "", html, flags=re.S), (
        "the one-click wipe button is back")
    assert "setup-continue" not in _js()

    verify = _fn("verifyFirstRun")
    assert verify.index("api('/auth/login'") < verify.index("forgetFirstRunSecrets()"), (
        "the secrets are forgotten before the sign-in with them succeeded")
    catch = verify[verify.index("} catch (err) {"):verify.index("} finally {")]
    assert "return;" in catch and "forgetFirstRunSecrets" not in catch, (
        "a refused sign-in forgets the secrets")
    # The local checks run before anything is sent.
    assert verify.index("password !== c.password") < verify.index("api('/auth/login'")
    assert verify.index("totpStepOffset(") < verify.index("api('/auth/login'")

    # The only other way to forget them is behind a warning that says what
    # is lost.
    js = _js()
    callers = [m.start() for m in re.finditer(r"forgetFirstRunSecrets\(\)", js)]
    discard = js.index("$('setup-skip-discard').addEventListener")
    allowed = {js.index("forgetFirstRunSecrets();", js.index("async function verifyFirstRun(")),
               js.index("forgetFirstRunSecrets();", discard)}
    assert set(callers) - {js.index("function forgetFirstRunSecrets()") + 9} <= allowed, (
        "something new forgets the first-run secrets")
    confirm = _block(html, "setup-skip-confirm")
    assert "cannot be shown again" in re.sub(r"\s+", " ", confirm)
    assert 'id="setup-skip-discard"' in confirm, "discard is not behind the warning"
    assert re.search(r'id="setup-skip-confirm"[^>]*\bhidden\b', html), (
        "the warning must be hidden until skip is pressed")

    # Hiding is not forgetting, and a reload asks first.
    assert "FIRST_RUN.creds = null" not in _fn("showFirstRunCreds")
    init = _fn("initSetup")
    assert "addEventListener('beforeunload', guardFirstRun)" in init
    assert "removeEventListener('beforeunload', guardFirstRun)" in _fn("forgetFirstRunSecrets")


def test_the_operator_is_told_before_create_that_secrets_are_shown_once():
    form = _block(_html(), "setup-form")
    warn = form.index('id="setup-warn"')
    submit = form.index('id="setup-submit"')
    assert warn < submit, "the warning comes after the button that triggers it"
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", form[warn:submit]))
    assert "password" in text and "authenticator secret" in text and "once" in text


def test_the_setup_notice_no_longer_points_at_a_hidden_form():
    src = (SRC / "http" / "routers" / "setup.py").read_text(encoding="utf-8")
    literal = re.search(r'"notice": \((.*?)\),', src, flags=re.S)
    assert literal, "setup.py no longer returns a notice"
    notice = "".join(re.findall(r'"([^"]*)"', literal.group(1)))
    assert "below" not in notice, notice
    assert notice.startswith("Shown once"), notice


# ---------------------------------------------------------------------------
# recovery-codes-unobtainable
# ---------------------------------------------------------------------------

def test_recovery_codes_can_be_obtained_where_the_sign_in_says():
    js = _js()
    auth_src = (SRC / "http" / "routers" / "auth.py").read_text(encoding="utf-8")
    assert '@router.post("/recovery-codes"' in auth_src
    assert "api('/auth/recovery-codes', { method: 'POST' })" in _fn("verifyFirstRun"), (
        "the first administrator is not given recovery codes")
    assert "api('/auth/recovery-codes', { method: 'POST' })" in _fn("issueRecoveryCodes")
    assert "recovery_codes_remaining" in _fn("openAccount")
    assert "$('btn-account').addEventListener('click', openAccount)" in js
    # The step-up refusal is answered with a fresh sign-in, not a dead end.
    assert "confirmThenIssue(" in _fn("issueRecoveryCodes")
    assert "confirmIdentity(" in _fn("confirmThenIssue")

    html = _html()
    start = html.index('id="login-totp-help"')
    help_text = re.sub(r"\s+", " ", html[start:html.index("</span>", start)])
    assert "from Account" in help_text and "administrator" in help_text, (
        "the sign-in form promises recovery codes without saying where they "
        "come from, or who to ask without one")


def test_a_shut_step_up_gate_is_answered_before_the_request_spends_a_token():
    """Fix round, 2026-09-22. Every refused POST /auth/recovery-codes
    spent a token of the route's rate limit (burst 3), so Generate,
    Cancel, Generate, confirm left the analyst unable to issue codes for
    about twelve minutes. /auth/me now says how long the gate stays open
    and the console asks for the sign-in first; the 403 path remains for
    a server that does not say."""
    auth_src = (SRC / "http" / "routers" / "auth.py").read_text(encoding="utf-8")
    me_model = auth_src[auth_src.index("class Me(BaseModel):"):auth_src.index('@router.get("/me"')]
    assert "step_up_fresh_seconds: int" in me_model
    issue = _fn("issueRecoveryCodes")
    assert issue.index("stepUpStale()") < issue.index("api('/auth/recovery-codes'"), (
        "the doomed request goes out before the sign-in is asked for")
    assert "confirmThenIssue(" in issue
    for name in ("adoptSessionFacts", "sessionRenewed", "openAccount"):
        assert "adoptStepUp(" in _fn(name), f"{name} ignores the step-up window"
    # Account must not reopen over the sign-in form when the analyst left
    # the confirmation for a full sign-in.
    confirm = _fn("confirmThenIssue")
    assert confirm.index("if (!signedIn()) return;") < confirm.index("setAccountOpen(true)")


def test_the_account_sheet_is_modal_in_fact():
    """It said aria-modal and left the app behind it reachable by Tab (fix
    round, 2026-09-22). Every opening goes through `setAccountOpen`, which
    makes the app inert, and the sign-in sheet leaves it inert when it
    closes back onto Account."""
    js = _js()
    assert "$('view-app').inert = on ||" in _fn("setAccountOpen")
    assert "show($('account-scrim'), true)" not in js, (
        "Account is opened without making the app behind it inert")
    assert "setAccountOpen(true)" in _fn("openAccount")
    assert "$('view-app').inert = !$('account-scrim').hidden" in _fn("closeReauth")
    init = _fn("initSession")
    close = init[init.index("$('account-close').addEventListener"):]
    assert close.index("setAccountOpen(false)") < close.index("});")


# A small DOM for the keyboard test: parent links, listeners by phase, and
# dispatch as the DOM standard orders it (window and ancestors in capture,
# the target, then ancestors and window in bubble, with stopPropagation
# honoured between nodes). Enough to run the console's real handlers.
_FAKE_DOM = r"""
const log = [];
class N {
  constructor(id, parent, tag, attrs) {
    this.id = id; this.parent = parent; this.tagName = tag || 'DIV';
    this.children = []; this.listeners = []; this.hidden = false;
    this.disabled = false; this.tabIndex = 0; this.inert = false;
    this.isContentEditable = false; this.textContent = ''; this.value = '';
    Object.assign(this, attrs || {});
    if (parent) parent.children.push(this);
    if (id) byId[id] = this;
  }
  addEventListener(type, fn, opt) {
    this.listeners.push({ type, fn, capture: opt === true || !!(opt && opt.capture) });
  }
  contains(n) { for (let x = n; x; x = x.parent) if (x === this) return true; return false; }
  closest(sel) {
    if (sel !== '[hidden]') throw new Error('fake closest: ' + sel);
    for (let x = this; x; x = x.parent) if (x.hidden) return x;
    return null;
  }
  getClientRects() { return this.closest('[hidden]') ? [] : [{}]; }
  querySelectorAll() {
    const out = [];
    const walk = (n) => { for (const c of n.children) {
      if (/^(BUTTON|INPUT|SELECT|TEXTAREA|A|SUMMARY)$/.test(c.tagName)) out.push(c);
      walk(c); } };
    walk(this);
    return out;
  }
  focus() { document.activeElement = this; }
  click() { for (const l of this.listeners) if (l.type === 'click') l.fn({ target: this }); }
}
const byId = {};
const document = new N(null, null, '#document');
const window = { listeners: [], addEventListener: N.prototype.addEventListener,
                 removeEventListener() {} };
const body = new N('body', document, 'BODY');
document.activeElement = body;
function $(id) { return byId[id] || new N(id, null); }
function dispatch(target, key, mods) {
  const ev = Object.assign({ type: 'keydown', key, target, shiftKey: false,
    ctrlKey: false, metaKey: false, altKey: false, stopped: false, prevented: false,
    stopPropagation() { this.stopped = true; },
    stopImmediatePropagation() { this.stopped = true; },
    preventDefault() { this.prevented = true; } }, mods || {});
  const up = [];
  for (let x = target; x; x = x.parent) up.push(x);
  up.push(window);
  const fire = (node, phase) => {
    for (const l of node.listeners) {
      if (l.type !== 'keydown') continue;
      if (phase === 'capture' && !l.capture) continue;
      if (phase === 'bubble' && l.capture) continue;
      l.fn(ev);
    }
  };
  for (const node of up.slice(1).reverse()) { fire(node, 'capture'); if (ev.stopped) return ev; }
  fire(target, 'target'); if (ev.stopped) return ev;
  for (const node of up.slice(1)) { fire(node, 'bubble'); if (ev.stopped) return ev; }
  return ev;
}
"""


def test_a_session_sheet_holds_the_keyboard():
    """Fix round 2, 2026-09-23. `inert` on the app does not stop the key
    handlers on `document`: with Account open (a LIVE session) a stray a,
    r or d accepted, rejected or deferred the selected triage proposal
    behind it, Ctrl+K opened the palette over Account and one Escape then
    closed both, and Tab walked out of both sheets to the skip link.
    Driven through the real `initSession`, `onTriageKey` and sheet
    handlers over a DOM that dispatches as a browser does."""
    js = _js()
    # The page's shortcuts listen on `document` in the bubble phase, which
    # is what lets a window capture listener and a stop at the sheet's
    # edge keep keys from them. Held, so the model below stays true.
    assert "document.addEventListener('keydown', onTriageKey);" in js
    palette = _fn("initPalette")
    assert "document.addEventListener('keydown', (e) => {" in palette
    assert "}, true)" not in palette and "capture" not in palette
    assert "window.addEventListener('keydown', onSheetKey, true);" in _fn("initSession")

    source = _FAKE_DOM + r"""
const skip = new N('skip', body, 'A', { href: '#main' });
const warn = new N('idle-warn', body); warn.hidden = true;
new N('idle-stay', warn, 'BUTTON');
new N('idle-renew', warn, 'BUTTON', { hidden: true });
const reauthScrim = new N('reauth-scrim', body, 'DIV', { hidden: true });
const form = new N('reauth-form', reauthScrim, 'FORM');
for (const [id, tag] of [['reauth-email', 'INPUT'], ['reauth-password', 'INPUT'],
    ['reauth-totp', 'INPUT'], ['reauth-leave', 'BUTTON'], ['reauth-submit', 'BUTTON']]) {
  new N(id, form, tag);
}
const accScrim = new N('account-scrim', body, 'DIV', { hidden: true });
const sheet = new N('account-sheet', accScrim);
const confirmBox = new N('account-codes-confirm', sheet, 'DIV', { hidden: true });
new N('account-codes-cancel', confirmBox, 'BUTTON');
new N('account-codes-replace', confirmBox, 'BUTTON');
new N('account-codes-new', sheet, 'BUTTON');
new N('account-close', sheet, 'BUTTON');
const app = new N('view-app', body);
new N('btn-account', app, 'BUTTON');
// A triage card inside the list, as the queue draws one: the letters act
// only in the list (ux18-a11y:triage-letter-keys-global) and on a card,
// never on a button (ux08-triage:triage-keys-fire-on-browser-chords).
const triageList = new N('triage-list', app);
const row = new N('triage-row', triageList, 'DIV',
  { classList: { contains: (c) => c === 'triage-card' } });
document.body = body;
new N('keys-scrim', body, 'DIV', { hidden: true });
window.confirm = () => true;
function anyDialogOpen() {
  return ['account-scrim', 'reauth-scrim', 'keys-scrim'].some((id) => !byId[id].hidden);
}
function triageLettersOn() { return true; }
function triageAcceptQuestion() { return 'Accept?'; }

const state = { tab: 'triage', triage: [{ id: 'p1' }], triageIndex: 0 };
const SESSION = { mode: null, codesLeft: 3, confirmWaiters: [] };
function show(node, on) { node.hidden = !on; }
function clear() {}
function closePalette() { log.push('closePalette'); }
function acceptProposal() { log.push('accept'); }
function rejectProposal() { log.push('reject'); }
function deferProposal() { log.push('defer'); }
function renderTriage() {}
function leaveReauth() { log.push('leaveReauth'); }
function submitReauth() {} function openReauth() {} function openAccount() {}
function adoptStepUp() {} function api() {} function hideIdleWarning() {}
function fail() {} function issueRecoveryCodes() {}
""" + "\n".join(_fn(n) for n in (
        "triageKeyTarget", "onTriageKey", "setAccountOpen", "topSessionSheet",
        "closeOverSheets",
        "warningBesides", "sheetFocusables", "onSheetKey", "keepKeysInSheet",
        "escapeSessionSheet", "initSession")) + r"""
initSession();
document.addEventListener('keydown', onTriageKey);
// The palette's handler, as initPalette registers it: document, bubble.
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key === 'k') log.push('palette');
});
const out = {};
const press = (target, key, mods) => dispatch(target, key, mods);
const tabs = (n, shift) => { const seen = [];
  for (let i = 0; i < n; i++) {
    const ev = press(document.activeElement, 'Tab', { shiftKey: !!shift });
    seen.push((ev.prevented ? '' : 'NATIVE:') + (document.activeElement.id || '?'));
  }
  return seen; };

// No sheet: the shortcuts work as before.
press(row, 'a'); press(row, 'k', { ctrlKey: true });
out.noSheet = log.splice(0);
out.noSheetTab = press(row, 'Tab').prevented;

// Account open, the focus on its Close button, as openAccount leaves it.
setAccountOpen(true);
out.opened = { calls: log.splice(0), inert: app.inert };
byId['account-close'].focus();
for (const k of ['a', 'r', 'd']) press(byId['account-close'], k);
press(byId['account-close'], 'k', { ctrlKey: true });
// The backdrop clicked: the focus is on the page, outside the sheet.
body.focus();
press(body, 'a'); press(body, 'k', { ctrlKey: true });
out.accountKeys = log.splice(0);
out.accountTabs = tabs(6);
out.accountBackTabs = tabs(3, true);
skip.focus();
out.fromSkip = tabs(1);
warn.hidden = false;
byId['account-close'].focus();
out.withWarning = tabs(3);
warn.hidden = true;
// Escape answers the replace question first, then the sheet.
show(confirmBox, true);
press(byId['account-codes-cancel'], 'Escape');
out.escOne = { confirm: confirmBox.hidden, account: accScrim.hidden,
               focus: document.activeElement.id };
press(document.activeElement, 'Escape');
out.escTwo = { account: accScrim.hidden, inert: app.inert,
               focus: document.activeElement.id, calls: log.splice(0) };

// The lapsed sign-in sheet: keys reach nothing behind it, Escape does not
// dismiss it, and Tab stays in its five controls.
SESSION.mode = 'lapsed'; show(reauthScrim, true); app.inert = true;
byId['reauth-leave'].focus();
press(byId['reauth-leave'], 'a'); press(byId['reauth-leave'], 'Escape');
out.lapsed = { calls: log.splice(0), open: !reauthScrim.hidden, tabs: tabs(6) };
// A confirmation sheet can be cancelled with Escape.
SESSION.mode = 'confirm';
press(byId['reauth-password'], 'Escape');
out.confirm = log.splice(0);
// The 12-hour sheet opens from the warning, whose buttons its scrim covers.
SESSION.mode = 'renew'; warn.hidden = false;
byId['reauth-submit'].focus();
out.renewTabs = tabs(2);
process.stdout.write(JSON.stringify(out));
"""
    got = json.loads(_run_node(source))
    assert got["noSheet"] == ["accept", "palette"], "the guard broke the shortcuts"
    assert got["noSheetTab"] is False, "Tab is taken over with no sheet open"
    assert got["opened"]["inert"] is True and "closePalette" in got["opened"]["calls"]
    assert got["accountKeys"] == [], (
        f"keys behind Account reached the app: {got['accountKeys']}")
    assert got["accountTabs"] == ["account-codes-new", "account-close"] * 3, got["accountTabs"]
    assert got["accountBackTabs"] == ["account-codes-new", "account-close",
                                      "account-codes-new"], got["accountBackTabs"]
    assert got["fromSkip"] == ["account-codes-new"], "Tab from outside does not return to the sheet"
    assert got["withWarning"] == ["idle-stay", "account-codes-new", "account-close"], (
        "the idle warning's button cannot be reached with Account open")
    assert got["escOne"] == {"confirm": True, "account": False,
                             "focus": "account-codes-new"}, got["escOne"]
    assert got["escTwo"]["account"] is True and got["escTwo"]["inert"] is False
    assert got["escTwo"]["focus"] == "btn-account"
    assert got["escTwo"]["calls"] == [], got["escTwo"]["calls"]
    assert got["lapsed"]["calls"] == [] and got["lapsed"]["open"] is True, got["lapsed"]
    assert got["lapsed"]["tabs"] == ["reauth-submit", "reauth-email", "reauth-password",
                                     "reauth-totp", "reauth-leave", "reauth-submit"]
    assert got["confirm"] == ["leaveReauth"]
    assert got["renewTabs"] == ["reauth-email", "reauth-password"], (
        "Tab reaches the warning's buttons under the sign-in sheet's scrim")


# ---------------------------------------------------------------------------
# expiry-drops-context
# ---------------------------------------------------------------------------

def test_a_mid_session_401_keeps_the_app_and_says_what_was_not_saved():
    fetch = _fn("_fetch")
    assert "sessionLapsed({" in fetch, "a mid-session 401 still unmounts the app"
    assert "Not saved: your session had ended" in fetch
    # Sign-out and the boot probe keep the old ending.
    assert "path !== '/auth/logout'" in fetch and "!state.booting" in fetch

    lapsed = _fn("sessionLapsed")
    for banned in ("endSession(", "show($('view-app'), false)", "state.caseId = null"):
        assert banned not in lapsed, f"sessionLapsed tears the workspace down: {banned}"
    assert "disconnectLive()" in lapsed, "the live socket outlives the session"
    assert "openReauth('lapsed'" in lapsed
    assert "addEventListener('beforeunload', guardUnsaved)" in lapsed
    assert "NOT saved" in _fn("describeLapse")
    # The sheet signs the SAME account back in.
    assert "reauthSignIn(errBox)" in _fn("submitReauth")
    assert _fn("reauthSignIn").count("email: SESSION.email") == 2
    assert re.search(r'id="reauth-email"[^>]*\breadonly\b', _html())
    # A lapsed session is not signed in, for the shortcuts and the socket.
    assert "!SESSION.lapsed" in _fn("signedIn")


def test_the_idle_warning_counts_against_the_servers_own_limits():
    auth_src = (SRC / "http" / "routers" / "auth.py").read_text(encoding="utf-8")
    me_model = auth_src[auth_src.index("class Me(BaseModel):"):auth_src.index('@router.get("/me"')]
    assert "idle_timeout_seconds: int" in me_model
    assert "session_expires_in_seconds: int" in me_model
    facts = _fn("adoptSessionFacts")
    assert "me.idle_timeout_seconds" in facts and "me.session_expires_in_seconds" in facts
    tick = _fn("tickSession")
    assert "IDLE_WARN_MS" in tick and "sessionLapsed(" in tick
    # Never a request from the clock: asking the server would slide the
    # idle window and the timeout would never fire.
    assert "api(" not in tick
    assert "noteSessionActivity(sentAt)" in _fn("_fetch")


def test_the_idle_warning_is_announced_once_a_minute_not_every_second():
    """Fix round, 2026-09-22. The countdown was rewritten every second
    inside role="alert", so a screen reader read the whole sentence out
    every second for the five minutes before the limit. The m:ss text is
    now hidden from assistive technology and the alert beside it changes
    only with the whole minute. Driven through the real `tickSession`
    for the full 30 minutes of an idle session."""
    html = _html()
    warn = _block(html, "idle-warn")
    opening = warn[:warn.index(">") + 1]
    assert "role=" not in opening, "the whole warning is a live region again"
    assert re.search(r'id="idle-warn-text"[^>]*aria-hidden="true"', warn)
    assert re.search(r'id="idle-warn-say"[^>]*role="alert"', warn)
    source = (
        "let now = 0; Date.now = () => now;\n"
        "const els = {};\n"
        "function $(id) { if (!els[id]) { els[id] = { hidden: true, writes: 0, _t: '',\n"
        "  set textContent(v) { this._t = v; this.writes++; },\n"
        "  get textContent() { return this._t; } }; } return els[id]; }\n"
        "function show(e, on) { e.hidden = !on; }\n"
        "const state = { booting: false };\n"
        "const IDLE_WARN_MS = 5 * 60 * 1000;\n"
        "const SESSION = { userId: 'u', lapsed: false, lastActivity: 0,\n"
        "  idleMs: 30 * 60 * 1000, hardAt: null, said: '' };\n"
        "let lapses = 0;\n"
        "function sessionLapsed() { lapses++; SESSION.lapsed = true; }\n"
        + "\n".join(_fn(n) for n in ("fmtCountdown", "idleWarningText",
                                     "hideIdleWarning", "tickSession"))
        + "\nconst heard = [];\n"
        "for (now = 0; now <= 31 * 60 * 1000; now += 1000) {\n"
        "  const before = $('idle-warn-say').writes;\n"
        "  tickSession();\n"
        "  if ($('idle-warn-say').writes !== before) heard.push($('idle-warn-say').textContent);\n"
        "}\n"
        "process.stdout.write(JSON.stringify({ heard, seen: $('idle-warn-text').writes, lapses }));\n")
    got = json.loads(_run_node(source))
    assert got["lapses"] == 1
    assert got["seen"] >= 290, "the visible countdown stopped counting"
    assert len(got["heard"]) == 5, got["heard"]
    assert "under 5 minutes" in got["heard"][0] and "under a minute" in got["heard"][-1]


def test_a_sign_in_in_another_tab_moves_this_tabs_limits_too():
    """Fix round, 2026-09-22. Only a LAPSED tab listened for a sibling's
    sign-in, so a tab that had not lapsed kept the replaced session's
    12-hour deadline and then warned, and covered itself with a sign-in,
    at a limit that no longer applied. Also held here: a case list whose
    read met the lapse is reloaded after the sign-in, and the sheet no
    longer promises a case that "All cases" had already closed."""
    stubs = (
        "let now = 5000000; Date.now = () => now;\n"
        "const calls = [];\n"
        "const els = {};\n"
        "function $(id) { if (!els[id]) els[id] = { hidden: true, textContent: '', focus() {} };\n"
        "  return els[id]; }\n"
        "function show(e, on) { e.hidden = !on; }\n"
        "const state = { caseId: 'c1' };\n"
        "const window = { removeEventListener() { calls.push('unguard'); } };\n"
        "const SESSION = { userId: 'u', lapsed: false, lapseUnsafe: false,\n"
        "  lapseMissedRead: false, mode: null, idleMs: 1800000, hardAt: null,\n"
        "  stepUpUntil: null, confirmWaiters: [], accountWasOpen: false };\n"
        + "".join(f"function {n}() {{ calls.push('{n}'); }}\n" for n in (
            "hideIdleWarning", "noteSessionActivity", "renderAccountChip",
            "forgetResume", "clearSessionBanners", "connectLive", "showCaseList",
            "sessionBanner", "refreshGlassChip", "relinkLive"))
        + "function closeReauth() { calls.push('closeReauth'); SESSION.mode = null; }\n"
        "function setAccountOpen(on) { calls.push('account:' + on); }\n"
        "function guardUnsaved() {}\n"
        + "\n".join(_fn(n) for n in ("adoptStepUp", "sessionRenewed",
                                     "onSessionMessage", "describeLapse",
                                     "lapseReason"))
        + "\nconst out = {};\n"
        "const renewed = { t: 'renewed', user: 'u', expiresIn: 43200, stepUpIn: 900 };\n"
        # 1. A live tab, no sheet, holding the old session's deadline.
        "SESSION.hardAt = now + 60000;\n"
        "onSessionMessage({ data: { t: 'renewed', user: 'someone-else', expiresIn: 1 } });\n"
        "out.ignored = SESSION.hardAt === now + 60000;\n"
        "onSessionMessage({ data: renewed });\n"
        "out.live = { hard: SESSION.hardAt - now, step: SESSION.stepUpUntil - now,\n"
        "  calls: calls.splice(0) };\n"
        # 2. A lapsed tab inside a case.
        "SESSION.lapsed = true; SESSION.mode = 'lapsed';\n"
        "onSessionMessage({ data: renewed });\n"
        "out.lapsedCase = { lapsed: SESSION.lapsed, calls: calls.splice(0) };\n"
        # 3. A lapsed tab on the case list whose read failed.
        "state.caseId = null; $('view-cases').hidden = false;\n"
        "SESSION.lapsed = true; SESSION.mode = 'lapsed'; SESSION.lapseMissedRead = true;\n"
        "describeLapse({ cause: 'server', detail: 'invalid or expired session' });\n"
        "out.listText = $('reauth-effect').textContent;\n"
        "onSessionMessage({ data: renewed });\n"
        "out.lapsedList = calls.splice(0);\n"
        # 4. A confirmation sheet open here is answered by the other sign-in.
        "let answered = null;\n"
        "SESSION.mode = 'confirm'; SESSION.confirmWaiters.push((ok) => { answered = ok; });\n"
        "onSessionMessage({ data: renewed });\n"
        "Promise.resolve().then(() => { out.confirm = answered;\n"
        "  process.stdout.write(JSON.stringify(out)); });\n")
    got = json.loads(_run_node(stubs))
    assert got["ignored"], "another account's sign-in moved this tab's limits"
    assert got["live"]["hard"] == 43200 * 1000, "the live tab kept the old deadline"
    assert got["live"]["step"] == 900 * 1000
    assert "closeReauth" not in got["live"]["calls"]
    assert "clearSessionBanners" not in got["live"]["calls"]
    assert "hideIdleWarning" in got["live"]["calls"]
    # The socket is moved onto the new session too (verifier of
    # ux01-firstrun:live-dot-green-on-dead-session, 2026-09-23); a lapsed
    # tab reopens it through connectLive instead.
    assert "relinkLive" in got["live"]["calls"]
    assert "relinkLive" not in got["lapsedCase"]["calls"]
    assert got["lapsedCase"]["lapsed"] is False
    assert {"closeReauth", "connectLive"} <= set(got["lapsedCase"]["calls"])
    assert "your case" not in got["listText"] and "case list" in got["listText"], (
        got["listText"])
    assert "showCaseList" in got["lapsedList"], "the case list that failed is not reloaded"
    assert got["confirm"] is True


def test_every_raw_request_meets_the_session_like_api_does():
    """The report download calls fetch() itself (it wants the raw body),
    so its 401 read "invalid or expired session" in the pane with no way
    back in but a sign-out, and its success did not slide the idle clock
    (fix round, 2026-09-22). Every `fetch(API` outside `_fetch` now goes
    through `sessionRefusedRaw` before it reads the answer."""
    js = _js()
    raw = _fn("sessionRefusedRaw")
    assert "sessionLapsed({" in raw and "noteSessionActivity(sentAt)" in raw
    # `await`, so the comments that mention the pattern are not call sites.
    sites = [m.start() for m in re.finditer(r"await fetch\(API\b", js)]
    assert sites, "no raw requests found; the pattern is stale"
    starts = [m.start() for m in re.finditer(r"^(?:async )?function (\w+)\(", js, flags=re.M)]
    # The one request made on purpose outside the session's bookkeeping:
    # the sign-out sent when an analyst leaves a lapsed session, where a
    # 401 is the outcome wanted rather than a lapse to report. Held to
    # that one caller, below.
    exempt = {"_fetch", "revokeIfStillOurs"}
    assert {m.start() for m in re.finditer(r"\brevokeIfStillOurs\(", js)} == {
        js.index("async function revokeIfStillOurs(") + len("async function "),
        js.index("revokeIfStillOurs(", js.index("async function leaveReauth(")),
    }, "the session-less sign-out is called from somewhere other than leaveReauth"
    for site in sites:
        start = max(s for s in starts if s < site)
        name = re.match(r"(?:async )?function (\w+)", js[start:]).group(1)
        if name in exempt:
            continue
        body = _fn(name)
        assert "sessionRefusedRaw(res" in body, f"{name} fetches around the session"
        assert body.index("sessionRefusedRaw(res") < body.index("if (!res.ok)"), name


def test_the_same_analyst_comes_back_to_their_case_and_pane():
    end = _fn("endSession")
    assert "if (title) rememberResume();" in end
    remember = _fn("rememberResume")
    assert "state.caseId" in remember and "state.tab" in remember and "state.userId" in remember
    assert "token" not in remember.lower(), "the resume record must never hold a credential"
    resume = _fn("applyResume")
    assert "saved.user !== userId" in resume, "another account would be dropped into the case"
    start = _fn("startApp")
    assert start.index("state.userId = me.user_id") < start.index("applyResume(me.user_id)") \
        < start.index("await showCaseList()")
    assert "clearSessionBanners()" in start, "the old 'Session ended' banner outlives the sign-in"
    # And the caret goes where the next keystroke belongs.
    assert "$('login-email').value ? $('login-password') : $('login-email')" in end


def test_leaving_a_lapse_signs_out_a_session_the_server_still_holds():
    """Fix round 2, 2026-09-23. "Sign in as someone else" after this tab's
    own clock ended the session went through `endSession` alone, which
    cannot delete the HttpOnly cookie: if the server still held the
    session (the live socket's handshake slides it unseen), the previous
    analyst's session stayed live in the browser until the server's
    timeout. It is now signed out first, while the CSRF cookie the
    double-submit needs still exists, and only when it is still the same
    analyst's; nothing is sent for a session the server already refused."""
    source = r"""
const log = [];
const els = {};
function $(id) { if (!els[id]) els[id] = { id, value: '', disabled: false,
  focus() { log.push('focus:' + id); } }; return els[id]; }
const API = '/api/v1';
let cookie = 'csrf-1';
function authHeaders(method) {
  return /^(GET|HEAD|OPTIONS)$/i.test(method) ? {} : { 'x-csrf-token': cookie };
}
let answer = null;
async function fetch(url, init) {
  log.push((init.method || 'GET') + ' ' + url + ' ' + JSON.stringify(init.headers)
           + (init.signal ? ' bounded' : ''));
  return answer(url);
}
const SESSION = {};
function closeReauth() { log.push('closeReauth'); SESSION.mode = null; }
function endSession(title) { log.push('endSession:' + title); cookie = null; }
// The page is discarded after the hand-over (ux01-firstrun:logout-leaves-
// case-in-page, 2026-09-23); its own test is in test_ui_signin_and_cases.
function discardPage() { log.push('discardPage'); }
""" + _fn("revokeIfStillOurs") + "\n" + _fn("leaveReauth") + r"""
const ok = (body) => ({ ok: true, status: 200, json: async () => body });
const reset = (extra) => { log.length = 0; cookie = 'csrf-1';
  Object.assign(SESSION, { mode: 'lapsed', userId: 'u1', email: 'a@x.test',
    serverEnded: false, confirmWaiters: [] }, extra || {}); };
(async () => {
  const out = {};
  reset(); answer = (u) => u.endsWith('/auth/me') ? ok({ user_id: 'u1' })
    : { ok: true, status: 204 };
  await leaveReauth(); out.same = log.slice();
  reset(); answer = () => ok({ user_id: 'someone-else' });
  await leaveReauth(); out.other = log.slice();
  reset(); answer = () => ({ ok: false, status: 401 });
  await leaveReauth(); out.gone = log.slice();
  reset(); answer = () => { throw new TypeError('network'); };
  await leaveReauth(); out.unreachable = log.slice();
  reset({ serverEnded: true }); answer = () => { throw new Error('sent'); };
  await leaveReauth(); out.refused = log.slice();
  // Another tab signs this analyst in while the check is out.
  reset(); answer = () => { SESSION.mode = null; return ok({ user_id: 'u1' }); };
  await leaveReauth(); out.renewedMeanwhile = log.slice();
  // ...and this tab has not heard yet: the new pair is in the browser, and
  // the sign-out must carry the OLD header, which the server refuses.
  reset(); answer = (u) => { if (u.endsWith('/auth/me')) { cookie = 'csrf-2';
    return ok({ user_id: 'u1' }); } return { ok: false, status: 403 }; };
  await leaveReauth(); out.pairChanged = log.slice();
  let answered = null;
  reset({ mode: 'confirm' }); SESSION.confirmWaiters.push((v) => { answered = v; });
  await leaveReauth(); out.confirm = { log: log.slice(), answered };
  process.stdout.write(JSON.stringify(out));
})();
"""
    got = json.loads(_run_node(source))
    assert got["same"][:2] == [
        'GET /api/v1/auth/me {} bounded',
        'POST /api/v1/auth/logout {"x-csrf-token":"csrf-1"} bounded',
    ], got["same"]
    assert got["same"][2:] == ["closeReauth", "endSession:Signed out", "discardPage"], (
        "the sign-out must go out BEFORE endSession drops the CSRF cookie, "
        "and the page goes last")
    assert not any("logout" in line for line in got["other"]), (
        "another analyst's session, signed in from another tab, was revoked")
    for case in ("other", "gone", "unreachable"):
        assert got[case][-3:] == ["closeReauth", "endSession:Signed out", "discardPage"], (
            case, got[case])
    assert got["refused"] == ["closeReauth", "endSession:Signed out", "discardPage"], (
        "a request was sent for a session the server had already refused")
    assert not any("endSession" in line or "logout" in line or "discard" in line
                   for line in got["renewedMeanwhile"]), (
        "the tab signed out after another tab had signed it back in")
    logout = [line for line in got["pairChanged"] if "logout" in line]
    assert logout == ['POST /api/v1/auth/logout {"x-csrf-token":"csrf-1"} bounded'], (
        "the sign-out took the NEW pair's header and would revoke the new session")
    assert got["confirm"] == {"log": ["closeReauth"], "answered": False}


# ---------------------------------------------------------------------------
# The house rule for copy: no em or en dashes in anything a user reads
# ---------------------------------------------------------------------------

_MY_MARKUP = ["login-totp-help", "setup-form", "setup-done", "setup-codes",
              "idle-warn", "reauth-scrim", "account-scrim", "btn-account"]
_MY_FUNCTIONS = ["tickSession", "sessionLapsed", "describeLapse", "openReauth",
                 "submitReauth", "sessionRenewed", "leaveReauth", "renderAccountChip",
                 "renderRecoveryCodes", "openAccount", "showCodeCount",
                 "issueRecoveryCodes", "initSession", "credCopyButton", "credRow",
                 "credCheckRow", "renderOneTimeCreds", "verifyFirstRun", "initSetup",
                 "showFirstRunCreds", "idleWarningText", "totpSkewText",
                 "confirmThenIssue", "sessionRefusedRaw", "onSessionMessage",
                 "revokeIfStillOurs", "topSessionSheet", "closeOverSheets",
                 "warningBesides",
                 "sheetFocusables", "onSheetKey", "keepKeysInSheet",
                 "escapeSessionSheet"]


@pytest.mark.parametrize("element_id", _MY_MARKUP)
def test_first_run_and_session_markup_has_no_dashes(element_id: str):
    markup = _block(_html(), element_id)
    for bad in ("\u2014", "\u2013", "&mdash;", "&ndash;"):
        assert bad not in markup, f"#{element_id} carries {bad!r}"


@pytest.mark.parametrize("name", _MY_FUNCTIONS)
def test_first_run_and_session_strings_have_no_dashes(name: str):
    body = _fn(name)
    assert "\u2014" not in body and "\u2013" not in body, f"{name} carries a dash"

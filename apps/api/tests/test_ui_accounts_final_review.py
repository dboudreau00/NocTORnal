"""The Admin pane and the sign-in sheet, after the final review of Alpha 6
(2026-09-24). Each test names the finding it would have caught:

- c8: the creation card says the issued password is replaced at the
  account's first sign-in;
- u5: a one-time password typed into the lapse sheet asks for the new
  password IN the sheet and carries on through `sessionRenewed`, instead
  of ending the session and discarding the screen the sheet had promised
  to keep;
- u19: after an account action succeeds, the focus goes back into the
  redrawn card (into a <details> the redraw built closed, too) and the
  outcome is said through a status region that stays on the page;
- u20: a stale step-up asks for the sign-in in place, and is never said as
  a missing System administrator role or as "sign out"; the registry,
  which is not a step-up read, still shows while the accounts wait;
- u21: registering a compartment reloads the Rename or retire list too.

The `needs_node` tests run the shipped functions under Node over a stub
DOM; the rest read the shipped source. Pure: no database.
"""
from __future__ import annotations

import json
import re
import subprocess

import pytest

from test_ui_copy_no_dashes import NODE, _html, _js, _source

needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")


def _const(js: str, name: str) -> str:
    """A top-level const, one line or through the line ending its `;`."""
    m = re.search(r"(?m)^const " + re.escape(name) + r" = ", js)
    assert m, f"const {name} is gone; update this test with it"
    end = js.index(";\n", m.start())
    return js[m.start():end + 1]


def _node(source: str) -> dict:
    out = subprocess.run([NODE, "-"], input=source, capture_output=True,
                         text=True, encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


#: Nodes by id, with just enough of an element for these functions.
_DOM = r"""
const log = [];
const els = {};
const document = { body: { id: 'BODY' }, activeElement: null,
  contains(n) { return !!n && !n.detached; } };
function node(id, extra) {
  const n = Object.assign({ id: id, hidden: false, value: '', textContent: '',
    className: '', title: '', disabled: false, tabIndex: 0, dataset: {},
    children: [],
    focus() { document.activeElement = this; },
    setAttribute(k, v) { this[k] = v; } }, extra || {});
  return n;
}
function $(id) { return els[id] || (els[id] = node(id)); }
function show(n, on) { n.hidden = !on; }
function setMsg(n, t) { n.textContent = t || ''; n.hidden = !t; }
class ApiError extends Error {
  constructor(status, title, detail, type) {
    super(title); this.status = status; this.title = title;
    this.detail = detail || ''; this.type = type;
  }
}
"""


def _fns(*names: str) -> str:
    js = _js()
    return "\n".join(_source(js, n) for n in names) + "\n"


def _consts(*names: str) -> str:
    js = _js()
    return "\n".join(_const(js, n) for n in names) + "\n"


# ---------------------------------------------------------------------------
# c8
# ---------------------------------------------------------------------------

def test_the_creation_card_says_the_password_is_replaced_at_first_sign_in():
    create = _source(_js(), "initAdmin")
    assert "At their first sign-in they choose their own" in create
    assert "stays its password" not in _source(_js(), "clearSessionSecrets"), (
        "the comment still says a created account's password opens sessions")


# ---------------------------------------------------------------------------
# u5: the new password, inside the sheet
# ---------------------------------------------------------------------------

def test_the_sheet_no_longer_ends_the_session_for_a_one_time_password():
    submit = _source(_js(), "submitReauth")
    for gone in ("endSession(", "startPasswordChange("):
        assert gone not in submit, f"submitReauth still calls {gone}"
    assert "startReauthChange(json.password)" in submit
    assert "endReauthChange()" in _source(_js(), "closeReauth"), (
        "the one-time password outlives the sheet")
    assert "endReauthChange()" in _source(_js(), "openReauth")
    html = _html()
    sheet = html[html.index('id="reauth-form"'):html.index("</form>", html.index('id="reauth-form"'))]
    for part in ('id="reauth-newpw"', 'id="reauth-new"', 'id="reauth-again"',
                 'autocomplete="new-password"', 'id="reauth-password-field"',
                 'aria-describedby="reauth-totp-help"'):
        assert part in sheet, part
    assert re.search(r'id="reauth-newpw"[^>]*\bhidden\b', sheet)
    # Empty in the markup, so the code field describes nothing until the
    # new-password stage writes it.
    assert re.search(r'<span id="reauth-totp-help" class="help" hidden></span>', sheet)


_SHEET = r"""
const SESSION = { email: 'a@x.test', userId: 'u', channel: null,
                  confirmWaiters: [], mode: 'lapsed', lapsed: true };
const PASSWORD_CHANGE_TYPE = 'urn:noctornal:problem:password-change-required';
const sent = [];
let answers = [];
async function api(path, opts) {
  sent.push({ path: path, json: opts && opts.json });
  const next = answers.shift();
  if (next instanceof Error) throw next;
  return next;
}
function csrfCookie() { return 'csrf'; }
function sessionRenewed(expiresIn, me) { log.push('sessionRenewed'); closeReauth(); }
function closeReauth() { log.push('closeReauth'); endReauthChange(); }
function endSession() { log.push('endSession'); }
function startPasswordChange() { log.push('startPasswordChange'); }
function startApp() { log.push('startApp'); }
function discardPage() { log.push('discardPage'); }
function guardUnsaved() {}
function inlineProblem(box, err) { setMsg(box, err.detail || err.title); }
const window = { removeEventListener() {} };
const state = {};
"""


@needs_node
def test_a_one_time_password_in_the_lapse_sheet_keeps_the_screen(tmp_path):
    """u5, driven: the 403 turns the sheet into the new-password stage, a
    mismatch is said before anything is sent, and the change goes out as
    ONE sign-in carrying the one-time password held in memory, and ends in
    `sessionRenewed` with nothing torn down."""
    source = (_DOM + _SHEET
              + _consts("REAUTH_CHANGE", "REAUTH_CODE_HELP")
              + _fns("isPasswordChangeRequired", "startReauthChange",
                     "endReauthChange", "reauthSignIn", "submitReauth")
              + r"""
const ev = { preventDefault() {} };
(async () => {
  const out = {};
  $('reauth-password').value = 'issued-one-time';
  $('reauth-totp').value = '123456';
  answers = [new ApiError(403, 'Password change required', 'replace it',
                          PASSWORD_CHANGE_TYPE)];
  await submitReauth(ev);
  out.afterRefusal = { log: log.splice(0), held: REAUTH_CHANGE.password,
    newpw: !$('reauth-newpw').hidden, pwField: $('reauth-password-field').hidden,
    typed: $('reauth-password').value, title: $('reauth-title').textContent,
    help: $('reauth-totp-help').textContent,
    focus: document.activeElement && document.activeElement.id };

  $('reauth-new').value = 'a long new passphrase';
  $('reauth-again').value = 'not the same one';
  $('reauth-totp').value = '654321';
  await submitReauth(ev);
  out.mismatch = { sent: sent.length, said: $('reauth-error').textContent };

  $('reauth-again').value = 'a long new passphrase';
  answers = [null, { user_id: 'u', session_expires_in_seconds: 43200 }];
  await submitReauth(ev);
  out.change = { log: log.splice(0), sent: sent.slice(1),
    held: REAUTH_CHANGE.password, newpw: !$('reauth-newpw').hidden,
    fields: [$('reauth-new').value, $('reauth-again').value] };
  process.stdout.write(JSON.stringify(out));
})();
""")
    got = _node(source)
    first = got["afterRefusal"]
    assert "endSession" not in first["log"] and "startPasswordChange" not in first["log"], (
        f"the screen behind the sheet was discarded: {first['log']}")
    assert first["held"] == "issued-one-time" and first["typed"] == ""
    assert first["newpw"] is True and first["pwField"] is True
    assert first["title"] == "Choose a new password"
    assert "used up only when the new password is set" in first["help"]
    assert first["focus"] == "reauth-new"
    assert got["mismatch"] == {"sent": 1, "said": "The two new passwords are not the same."}
    change = got["change"]
    assert change["sent"][0] == {"path": "/auth/login", "json": {
        "email": "a@x.test", "password": "issued-one-time",
        "totp_code": "654321", "new_password": "a long new passphrase"}}
    assert change["sent"][1]["path"] == "/auth/me"
    assert "sessionRenewed" in change["log"], change["log"]
    for gone in ("endSession", "startApp", "discardPage", "startPasswordChange"):
        assert gone not in change["log"], change["log"]
    assert change["held"] is None and change["newpw"] is False
    assert change["fields"] == ["", ""]


# ---------------------------------------------------------------------------
# u19: focus and the announcement after a success
# ---------------------------------------------------------------------------

_ADMIN = r"""
const ADM = { notes: new Map() };
let canAdmin = true;
function stepUpStale() { return false; }
let confirmAnswer = true;
const asked = [];
async function confirmIdentity(why) { asked.push(why); return confirmAnswer; }
const SESSION = { stepUpUntil: null };
function closeClause(t) { return t; }
function refusalText(err, context) { return (err.detail || '') + (context ? ' ' + context : ''); }
function fail(err) { log.push('fail:' + err); }
function refreshAdminBlocking() { log.push('blocking'); }
let answers = [];
const sent = [];
async function api(path, opts) {
  sent.push(path);
  const next = answers.shift();
  if (next instanceof Error) throw next;
  return next;
}
// A label starting "details:" is a button inside a <details> drawn closed,
// as Save read-ins is; like a browser's, its focus() does nothing while
// that <details> is closed.
function button(label, card) {
  const folded = label.startsWith('details:');
  const text = folded ? label.slice(8) : label;
  const fold = folded ? node('fold-' + text, { open: false }) : null;
  const b = node('btn-' + text, { textContent: text, fold: fold });
  b.closest = (sel) => (sel === 'details' ? fold : card);
  b.focus = function () { if (!fold || fold.open) document.activeElement = this; };
  return b;
}
function card(id, labels) {
  const c = node('card-' + id, { dataset: { user: id } });
  c.note = node('note-' + id, { className: 'msg adm-note' });
  c.buttons = labels.map((l) => button(l, c));
  c.querySelectorAll = () => c.buttons;
  c.querySelector = (sel) => (sel === '.adm-note' ? c.note : null);
  return c;
}
let nextLabels = [];
async function loadAdminUsers() {
  for (const c of $('adm-list').children) {
    c.detached = true;
    for (const b of c.buttons) b.detached = true;
  }
  $('adm-list').children = [card('a', ['Other']), card('u', nextLabels)];
  log.push('redrawn');
}
const realSetTimeout = setTimeout;
"""


@needs_node
def test_after_a_success_the_focus_returns_to_the_card_and_it_is_said(tmp_path):
    source = (_DOM + _ADMIN
              + _consts("ADM_STEP_UP_WHY")
              + _fns("withStepUp", "admStepUp", "admStepUpRefused",
                     "admStepUpAgain", "adminAct", "admAfterRedraw", "admSay")
              + "let _admSayTimer = null;\n" + r"""
(async () => {
  const out = {};
  const u = { id: 'u' };
  $('adm-list').children = [card('u', ['Grant role', 'Revoke Analyst'])];
  // Grant: the button survives the redraw, and gets the focus back.
  let pressed = $('adm-list').children[0].buttons[0];
  pressed.focus();
  nextLabels = ['Grant role', 'Revoke Analyst'];
  answers = [{ ok: true }];
  await adminAct('/admin/users/u/roles', {}, pressed, u, () => 'Granted Analyst.');
  out.grantFocus = document.activeElement.id + ':' + document.activeElement.detached;
  out.grantNewCard = document.activeElement === $('adm-list').children[1].buttons[0];
  await new Promise((r) => realSetTimeout(r, 80));
  out.said = $('adm-say').textContent;
  // Revoke: the button is gone, so the note takes the focus.
  pressed = $('adm-list').children[1].buttons[1];
  pressed.focus();
  nextLabels = ['Grant role'];
  answers = [{ ok: true }];
  await adminAct('/admin/users/u/roles/ANALYST', {}, pressed, u, () => 'Revoked Analyst.');
  const note = $('adm-list').children[1].note;
  out.revokeFocus = document.activeElement === note;
  out.noteTab = note.tabIndex;
  await new Promise((r) => realSetTimeout(r, 80));
  out.saidAgain = $('adm-say').textContent;
  // A focus the administrator moved elsewhere meanwhile is left alone.
  const elsewhere = node('search');
  pressed = $('adm-list').children[1].buttons[0];
  answers = [{ ok: true }];
  const act = adminAct('/admin/users/u/roles', {}, pressed, u, () => 'Granted.');
  elsewhere.focus();
  await act;
  out.leftAlone = document.activeElement === elsewhere;
  process.stdout.write(JSON.stringify(out));
})();
""")
    got = _node(source)
    assert got["grantNewCard"] is True, (
        f"the focus fell to <body> after the redraw: {got['grantFocus']}")
    assert got["said"] == "Granted Analyst.", "the outcome was not announced"
    assert got["revokeFocus"] is True and got["noteTab"] == -1
    assert got["saidAgain"] == "Revoked Analyst."
    assert got["leftAlone"] is True


@needs_node
def test_save_read_ins_gets_the_focus_back_inside_its_fold(tmp_path):
    """u19, the verifier's case: Save read-ins sits in a <details> the
    redraw builds closed, and focusing a button in a closed <details> does
    nothing, so the focus stayed on <body>. The fold is opened again; and a
    button that still cannot take the focus falls back to the note."""
    source = (_DOM + _ADMIN
              + _consts("ADM_STEP_UP_WHY")
              + _fns("withStepUp", "admStepUp", "admStepUpRefused",
                     "admStepUpAgain", "adminAct", "admAfterRedraw", "admSay")
              + "let _admSayTimer = null;\n" + r"""
(async () => {
  const out = {};
  const u = { id: 'u' };
  $('adm-list').children = [card('u', ['Grant role', 'details:Save read-ins'])];
  let pressed = $('adm-list').children[0].buttons[1];
  pressed.fold.open = true;          // it was open when it was pressed
  pressed.focus();
  nextLabels = ['Grant role', 'details:Save read-ins'];
  answers = [{ ok: true }];
  await adminAct('/compartments/users/u', {}, pressed, u, () => 'Read into KX.');
  const fresh = $('adm-list').children[1].buttons[1];
  out.saveFocus = document.activeElement === fresh;
  out.onBody = document.activeElement === null || document.activeElement.detached === true;
  out.foldOpen = fresh.fold.open;
  // A button that cannot take the focus for any other reason: the note.
  const c = $('adm-list').children[1];
  c.buttons[1].focus = function () {};
  document.activeElement = document.body;
  admAfterRedraw(u, 'Save read-ins', 'Read into none.');
  out.fallback = document.activeElement === c.note;
  process.stdout.write(JSON.stringify(out));
})();
""")
    got = _node(source)
    assert got["saveFocus"] is True, (
        "Save read-ins lost the focus to <body>: its <details> was drawn closed")
    assert got["foldOpen"] is True
    assert got["onBody"] is False
    assert got["fallback"] is True, "a button that cannot take the focus left it on <body>"


def test_the_status_region_stays_on_the_page():
    html = _html()
    pane = html[html.index('<section id="pane-admin"'):]
    say = pane.index('id="adm-say"')
    assert say < pane.index('<div id="adm-readiness"'), (
        "the region sits inside a section that is hidden with it")
    assert re.search(r'<p id="adm-say" class="sr-only" role="status"', pane)


# ---------------------------------------------------------------------------
# u20: a stale step-up, in place
# ---------------------------------------------------------------------------

@needs_node
def test_a_stale_step_up_asks_in_place_and_never_says_role_or_sign_out(tmp_path):
    source = (_DOM + _ADMIN
              + _consts("ADM_STEP_UP_WHY")
              + _fns("withStepUp", "admStepUp", "admStepUpRefused",
                     "admStepUpAgain", "admStepUpWords", "adminAct",
                     "admAfterRedraw", "admSay", "loadReadiness")
              + "let _admSayTimer = null;\n"
              + "function renderBlockingBanner() {}\nfunction clear(n) { n.children = []; }\n"
              + "function el(t, c, x) { return node(t, { textContent: x || '' }); }\n"
              + "function countOf(n, a, b) { return n + ' ' + (n === 1 ? a : b); }\n"
              + "function agree(n, a, b) { return n === 1 ? a : b; }\n"
              + "function fmtTime(t) { return t; }\n"
              + "function readinessRow(c) { return el('div', 'row', c.check); }\n"
              + r"""
const stale = () => new ApiError(403, 'Forbidden', 're-authentication required');
(async () => {
  const out = {};
  const u = { id: 'u' };
  $('adm-list').children = [card('u', ['Set clearance'])];
  const btn = $('adm-list').children[0].buttons[0];
  // The server says the gate shut; the sign-in is asked for, then cancelled.
  answers = [stale()];
  confirmAnswer = false;
  const cancelled = await adminAct('/admin/users/u/clearance', {}, btn, u, () => 'Set.');
  out.cancel = { result: cancelled, asked: asked.splice(0), sent: sent.splice(0),
    note: $('adm-list').children[0].note.textContent, disabled: btn.disabled };
  // Confirmed: the same request goes again and lands.
  answers = [stale(), { ok: true }];
  confirmAnswer = true;
  nextLabels = ['Set clearance'];
  const done = await adminAct('/admin/users/u/clearance', {}, btn, u, () => 'Clearance set.');
  out.confirmed = { ok: !!done, asked: asked.splice(0).length, sent: sent.splice(0) };
  // The register: cancelled, then a missing permission.
  answers = [stale()];
  confirmAnswer = false;
  await loadReadiness();
  out.readinessStale = $('rdy-summary').textContent;
  answers = [new ApiError(403, 'Forbidden', 'missing global permission user.manage')];
  await loadReadiness();
  out.readinessRole = $('rdy-summary').textContent;
  process.stdout.write(JSON.stringify(out));
})();
""")
    got = _node(source)
    cancel = got["cancel"]
    assert cancel["result"] is None and cancel["disabled"] is False
    assert cancel["sent"] == ["/admin/users/u/clearance"], "a cancelled sign-in still sent it"
    assert cancel["asked"] and "last 15 minutes" in cancel["asked"][0]
    assert cancel["note"].startswith("Not done. It needs a sign-in from the last 15 minutes")
    assert got["confirmed"] == {"ok": True, "asked": 1, "sent": [
        "/admin/users/u/clearance", "/admin/users/u/clearance"]}
    for said in (cancel["note"], got["readinessStale"]):
        assert "Sign out" not in said and "sign out" not in said, said
        assert "user.manage" not in said and "administrator role" not in said, said
    assert got["readinessStale"].startswith(
        "The readiness register is shown only after a sign-in from the last 15 minutes.")
    assert "user.manage" in got["readinessRole"], (
        "a missing permission lost the sentence that names it")


_LOAD_USERS = r"""
let canAdmin = true;
let stale = true;
function stepUpStale() { return stale; }
let confirmAnswer = false;
const asked = [];
async function confirmIdentity(why) { asked.push(why); return confirmAnswer; }
const SESSION = { stepUpUntil: null };
const state = {};
const sent = [];
const routes = {};
async function api(path) {
  sent.push(path);
  const next = routes[path];
  if (next instanceof Error) throw next;
  return next;
}
function refusalText(err, context) { return (err.detail || '') + ' ' + context; }
function el(tag, cls, text) {
  const n = node(tag, { className: cls || '', textContent: text || '' });
  n.appendChild = (c) => { n.children.push(c); n.textContent += ' ' + c.textContent; return c; };
  return n;
}
function fact(k, v) { return el('span', 'fact', k + ': ' + v); }
function visibleText(s) { return s; }
function countOf(n, a, b) { return n + ' ' + (n === 1 ? a : b); }
function fmtTime(t) { return t; }
function listPending(listId, emptyId) { $(emptyId).textContent = 'Loading'; show($(emptyId), true); }
function renderList(listId, emptyId, rows, build) {
  $(listId).children = rows.map(build);
  $(emptyId).textContent = 'default';
  $(emptyId).refused = false;
  show($(emptyId), rows.length === 0);
}
function listRefused(emptyId, text) {
  $(emptyId).textContent = text; $(emptyId).refused = true; show($(emptyId), true);
}
function showLoadFailure() { log.push('failure'); }
function parkAdminCreds() {}
function placeAdminCreds() {}
function renderCreateCompartments() {}
async function loadRoleNames() { await api('/admin/roles'); }
function adminUserRow(u) { return el('div', 'adm-card', u.display_name); }
const ADM = { users: [], usersRead: false, usersStepUp: false, comps: null,
              notes: new Map() };
"""


@needs_node
def test_a_cancelled_step_up_still_shows_the_registry_and_says_why(tmp_path):
    """The verifier's residual on u20: the registry read sat behind the gate
    with the accounts, so a cancelled sign-in left the Compartments subpane
    saying the registry "could not be read", with the reason written into
    the hidden Accounts section. GET /compartments is not a step-up route:
    it is read beside the gate, its keys never claim "nobody" from a listing
    that was not read, and the subpane says what the sign-in would show."""
    source = (_DOM + _LOAD_USERS
              + _consts("ADM_STEP_UP_WHY")
              + _fns("withStepUp", "admStepUp", "admStepUpRefused",
                     "admStepUpWords", "loadAdminCompartments",
                     "renderCompartmentRegistry", "compartmentRow",
                     "loadAdminUsers")
              + r"""
routes['/compartments'] = { scope: 'all', compartments: [{ key: 'KX', label: 'Kestrel' }] };
routes['/admin/users'] = { you: 'a', count: 2, users: [
  { id: 'a', display_name: 'Ann', is_active: true, compartments: ['KX'] },
  { id: 'b', display_name: 'Bo', is_active: true, compartments: [] }] };
routes['/admin/roles'] = { roles: [] };
(async () => {
  const out = {};
  await loadAdminUsers();
  out.cancelled = { sent: sent.splice(0), asked: asked.splice(0).length,
    accounts: $('adm-empty').textContent,
    rows: $('adm-comp-list').children.map((c) => c.textContent),
    compEmpty: $('adm-comp-empty').textContent,
    compEmptyShown: !$('adm-comp-empty').hidden };
  stale = false;
  await loadAdminUsers();
  out.fresh = { sent: sent.splice(0).sort(),
    rows: $('adm-comp-list').children.map((c) => c.textContent),
    compEmptyShown: !$('adm-comp-empty').hidden,
    cards: $('adm-list').children.length };
  routes['/compartments'] = { scope: 'all', compartments: [{ key: 'KY', label: 'Y' }] };
  await loadAdminUsers();
  out.nobody = $('adm-comp-list').children.map((c) => c.textContent);
  process.stdout.write(JSON.stringify(out));
})();
""")
    got = _node(source)
    cancelled = got["cancelled"]
    assert cancelled["asked"] == 1
    assert cancelled["sent"] == ["/compartments"], (
        "the registry waited behind the gate, or the accounts went without it")
    assert cancelled["accounts"].startswith("The accounts are shown only after a sign-in")
    assert len(cancelled["rows"]) == 1 and "KX" in cancelled["rows"][0]
    assert "not known: the accounts were not read" in cancelled["rows"][0]
    assert "nobody" not in cancelled["rows"][0], (
        "a key claimed no holder from a listing that was never read")
    assert cancelled["compEmptyShown"] is True
    assert cancelled["compEmpty"].startswith(
        "Who is read into each is shown only after a sign-in from the last 15 minutes.")
    for said in (cancelled["accounts"], cancelled["compEmpty"]):
        assert "could not be read" not in said and "sign out" not in said.lower(), said
    fresh = got["fresh"]
    assert fresh["sent"] == ["/admin/roles", "/admin/users", "/compartments"]
    assert fresh["cards"] == 2
    assert "1 account: Ann" in fresh["rows"][0]
    assert fresh["compEmptyShown"] is False, "the sign-in line outlived the sign-in"
    assert "nobody" in got["nobody"][0], "a read listing lost its honest 'nobody'"


def test_every_admin_request_goes_through_the_gate():
    js = _js()
    assert "admStepUp(() => Promise.all(" in _source(js, "loadAdminUsers")
    assert "admStepUp(() => api('/admin/readiness'))" in _source(js, "loadReadiness")
    assert "admStepUp(() => api(path, options)" in _source(js, "adminAct")
    assert "admStepUp(() => api('/admin/users', {" in _source(js, "initAdmin")
    assert "admStepUp(" in _source(js, "registerCompartment")
    load = _source(js, "loadAdminUsers")
    assert "and it is step-up: sign in again" not in load
    assert "canAdmin ? withStepUp(" in _source(js, "admStepUp")


# ---------------------------------------------------------------------------
# u21
# ---------------------------------------------------------------------------

@needs_node
def test_registering_a_compartment_reloads_the_rename_list(tmp_path):
    source = (_DOM + r"""
let canAdmin = false;
async function api(path, opts) { log.push('api:' + path); return { key: 'OP-KESTRAL' }; }
async function loadAdminUsers() { log.push('users'); }
async function loadCompartmentKeys() { log.push('keys'); }
function closeClause(t) { return t; }
function fail(e) { log.push('fail:' + e); }
function withStepUp() { throw new Error('not for this account'); }
""" + _consts("ADM_STEP_UP_WHY")
              + _fns("admStepUp", "admStepUpRefused", "admStepUpAgain",
                     "registerCompartment") + r"""
(async () => {
  $('adm-comp-key').value = 'OP-KESTRAL';
  $('adm-comp-label').value = 'Kestrel, typed wrong';
  await registerCompartment({ preventDefault() {} });
  process.stdout.write(JSON.stringify({ log: log, msg: $('adm-comp-msg').textContent }));
})();
""")
    got = _node(source)
    assert got["log"][0] == "api:/compartments"
    assert "keys" in got["log"], (
        "the Rename or retire list is not reloaded after a registration")
    assert "users" in got["log"]
    assert got["msg"].startswith("Registered OP-KESTRAL.")

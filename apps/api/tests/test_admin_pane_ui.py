"""The Admin pane and the password flows, as the console ships them.

The ux16-admin review of 2026-09-22 found fourteen things wrong with the
Admin pane, closed 2026-09-23 together with the administrator-issued
password reset (gap-password-reset). Each test names the finding it would
have caught. The ones marked `needs_node` run the real functions under
Node over a stub DOM and read what they draw; the rest read the shipped
source, the way `test_ui_invariants.py` does.

Pure: no database.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from test_ui_copy_no_dashes import NODE, _html, _js, _source

needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
CSS = (SRC / "http" / "static" / "app.css")


def _pane_html() -> str:
    html = _html()
    start = html.index('<section id="pane-admin"')
    return html[start:html.index("</section>", start)]


_STUBS = r"""
function mk(tag, cls, text) {
  return { tag: tag, className: cls || '',
           textContent: text === undefined || text === null ? '' : String(text),
           title: '', value: '', hidden: false, disabled: false, type: '',
           children: [], dataset: {}, listeners: {},
           appendChild(c) { this.children.push(c); return c; },
           append(...cs) { for (const c of cs) this.children.push(c); },
           setAttribute(k, v) { this[k] = v; },
           addEventListener(t, fn) { this.listeners[t] = fn; } };
}
const el = mk;
const document = { createTextNode(t) {
  return { tag: '#text', textContent: String(t), children: [] }; } };
const boxes = {};
function $(id) { return boxes[id] || (boxes[id] = mk('div')); }
function clear(n) { n.children = []; }
function show(n, on) { n.hidden = !on; }
function text(n) {
  return (n.textContent || '') + (n.children || []).map(text).join('');
}
function fmtTime(iso, s) { return 'T(' + iso + (s ? ',s' : '') + ')'; }
// The pane's step-up gate (final review u20, 2026-09-24), open here: these
// tests are about what is drawn, and test_ui_accounts_final_review drives
// the gate itself.
function admStepUp(call) { return call(); }
function admStepUpRefused() { return false; }
function admStepUpWords(what) { return what; }
"""


def _run(names: list[str], body: str, tmp_path: Path, extra: str = ""):
    js = _js()
    script = tmp_path / "run.js"
    script.write_text(_STUBS + extra + "\n"
                      + "\n".join(_source(js, n) for n in names)
                      + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# ---------------------------------------------------------------------------
# The readiness register
# ---------------------------------------------------------------------------

_CHECK = ("{check: '%s', ok: %s, blocking: %s, evidence: 'ev %s', "
          "action: 'act %s', consequence: '%s', ui_target: '%s'}")


def _check(name, ok, blocking, consequence="", target=""):
    return _CHECK % (name, "true" if ok else "false",
                     "true" if blocking else "false", name, name,
                     consequence, target)


@needs_node
def test_the_banner_headline_says_everything_the_failures_refuse(tmp_path):
    """blocking-headline-understates-impact: the headline was hard-coded to
    "the collection poll route is refused" while its own items said
    ingest, download and break-glass were refused too."""
    checks = ", ".join([
        _check("a", False, True, "Sample ingest is refused."),
        _check("b", False, True, "Every sample download is refused."),
        _check("c", False, True, "", "governance/retention"),
        _check("d", False, True,
               "Break-glass is refused, and nobody can read the audit trail.",
               "admin/accounts"),
        _check("e", False, False),
        _check("f", True, True),
    ])
    got = _run(["countOf", "agree", "closeClause", "renderBlockingBanner"], """
const painted = [];
function paintAdminBlocking(names) { painted.push(names); }
function readinessGoTo(t) { return t ? el('button', 'go', 'Go ' + t) : null; }
renderBlockingBanner({checks: [%s], blocking_failures: ['a', 'b', 'c', 'd', 'z']});
const box = $('rdy-blocking');
console.log(JSON.stringify({head: text(box.children[0]), hidden: box.hidden,
  items: box.children[1].children.map(text), painted: painted}));
""" % checks, tmp_path)
    head = got["head"]
    assert head.startswith("5 BLOCKING checks failing."), head
    for said in ("Collection polling is refused until every one is settled.",
                 "Sample ingest is refused.", "Every sample download is refused.",
                 "Break-glass is refused, and nobody can read the audit trail.",
                 "2 are settled here in the console",
                 "3 need a change to the API's configuration, then a restart."):
        assert said in head, (said, head)
    assert "CollectionService" not in head and "ROUTE" not in head, (
        "the design rationale is back in the operator's headline")
    assert got["hidden"] is False
    assert any("Go governance/retention" in i for i in got["items"]), got["items"]
    assert got["painted"] == [["a", "b", "c", "d", "z"]], (
        "the badges and the banner disagree about what is blocking")


@needs_node
def test_one_failing_blocker_says_how_it_is_settled_in_the_singular(tmp_path):
    got = _run(["countOf", "agree", "closeClause", "renderBlockingBanner"], """
function paintAdminBlocking() {}
function readinessGoTo() { return null; }
renderBlockingBanner({checks: [%s], blocking_failures: ['c']});
console.log(JSON.stringify(text($('rdy-blocking').children[0])));
""" % _check("c", False, True, "", "governance/retention"), tmp_path)
    assert got == ("1 BLOCKING check failing. Collection polling is refused "
                   "until it is settled. It is settled here in the console."), got


@needs_node
def test_the_list_puts_failures_first_and_folds_the_passes(tmp_path):
    """register-long-duplicated-unsorted and readiness-stale-after-fix."""
    got = _run(["countOf", "agree", "loadReadiness"], """
let reply;
async function api() { return reply; }
function renderBlockingBanner() {}
function readinessRow(c) { return el('div', 'row', c.check); }
function refusalText(err, fallback) { return fallback; }
(async () => {
  reply = {ready: false, checked_at: '2026-09-23T12:00:05Z', checks: [
    {check: 'p1', ok: true}, {check: 'f1', ok: false}, {check: 'p2', ok: true},
    {check: 'f2', ok: false}]};
  await loadReadiness();
  const list = $('rdy-list');
  console.log(JSON.stringify({summary: $('rdy-summary').textContent,
    top: list.children.map((c) => c.tag + ':' + c.textContent),
    folded: list.children[2].children.map(text)}));
})();
""", tmp_path)
    assert got["summary"] == ("2 of 4 checks need attention. Checked "
                              "T(2026-09-23T12:00:05Z,s)."), got["summary"]
    assert got["top"] == ["div:f1", "div:f2", "details:"], got["top"]
    assert got["folded"] == ["2 checks pass", "p1", "p2"], got["folded"]


@needs_node
def test_a_slow_register_reply_does_not_land_over_a_fresh_one(tmp_path):
    got = _run(["countOf", "agree", "loadReadiness"], """
const replies = [];
function api() { return new Promise((r) => replies.push(r)); }
function renderBlockingBanner() {}
function readinessRow(c) { return el('div', 'row', c.check); }
function refusalText(err, fallback) { return fallback; }
(async () => {
  const first = loadReadiness();
  const second = loadReadiness();
  replies[1]({ready: true, checks: [{check: 'fresh', ok: true}]});
  await second;
  replies[0]({ready: false, checks: [{check: 'stale', ok: false}]});
  await first;
  console.log(JSON.stringify(text($('rdy-list'))));
})();
""", tmp_path)
    assert "fresh" in got and "stale" not in got, got


@needs_node
def test_attention_is_amber_unless_the_check_blocks(tmp_path):
    got = _run(["readinessRow"], """
function readinessGoTo() { return null; }
const rows = [
  readinessRow({check: 'smtp', ok: false, blocking: false, evidence: 'e', action: 'a'}),
  readinessRow({check: 'policy', ok: false, blocking: true, evidence: 'e', action: 'a'}),
  readinessRow({check: 'kek', ok: true, blocking: false, evidence: 'e', action: ''}),
];
console.log(JSON.stringify(rows.map((r) => ({
  chips: r.children[0].children.slice(1).map((c) => c.className),
  body: r.children.slice(1).map(text)}))));
""", tmp_path)
    smtp, policy, kek = got
    assert smtp["chips"] == ["chip warn"], smtp
    assert policy["chips"] == ["chip bad", "chip bad"], policy
    assert kek["chips"] == ["chip good"], kek
    assert policy["body"] == ["Failing: what it refuses and how to settle it "
                              "are in the red box above."], (
        "a failing blocker prints its evidence twice again")


def test_the_readiness_intro_no_longer_overclaims():
    """readiness-help-overclaims."""
    pane = _pane_html()
    intro = pane[pane.index('<div id="adm-readiness"'):pane.index('id="btn-readiness"')]
    visible = re.sub(r"<!--.*?-->", "", intro, flags=re.S)
    assert "code-side half" not in visible
    assert "nothing here can close" not in visible
    assert "only record" in visible and "lawful" in visible


# ---------------------------------------------------------------------------
# Sections, badges and the way in
# ---------------------------------------------------------------------------

def test_the_pane_is_three_sections_and_readiness_is_one_of_them():
    """blocking-banner-buried-under-account-list."""
    pane = _pane_html()
    tabs = re.findall(r'data-subtab="(\w+)"', pane)
    assert tabs == ["readiness", "accounts", "compartments"], tabs
    assert pane.index('id="rdy-blocking"') < pane.index('id="adm-accounts"'), (
        "the blocking banner is below the account list again")
    assert 'id="adm-sub-badge"' in pane
    html = _html()
    tab = html[html.index('id="tab-admin"'):]
    assert 'id="admin-badge"' in tab[:tab.index("</button>")], (
        "the Admin rail tab carries no count of what is blocking")
    assert 'id="adm-blocking-flag"' in html


@needs_node
def test_the_pane_opens_on_readiness_while_anything_blocks(tmp_path):
    got = _run(["enterAdminPane"], """
const ADM = { blocking: [], userSub: null, auto: false };
const opened = [];
function selectAdminSub(name) { opened.push([name, ADM.auto]); }
enterAdminPane();
ADM.userSub = 'compartments'; enterAdminPane();
ADM.blocking = ['security_officer_present']; enterAdminPane();
console.log(JSON.stringify({opened, auto: ADM.auto}));
""", tmp_path)
    assert got["opened"] == [["accounts", True], ["compartments", True],
                             ["readiness", True]], got
    assert got["auto"] is False


def test_the_way_in_is_badged_from_the_access_answer():
    js = _js()
    access = _source(js, "loadAdminAccess")
    assert "access.blocking_failures" in access
    assert "access.readiness_caveats" in access
    entry = _source(js, "refreshAdminEntry")
    assert "paintAdminBlocking(ADM.blocking, ADM.caveats)" in entry
    assert entry.index("await loadAdminAccess()") < entry.index("if (state.caseId"), (
        "the count is only asked for on the case list, so the rail tab "
        "inside a case never carries it")
    paint = _source(js, "paintAdminBlocking")
    for box in ("admin-badge", "adm-sub-badge", "adm-blocking-flag"):
        assert box in paint, box
    css = CSS.read_text(encoding="utf-8")
    assert re.search(r"\.rail-badge\.danger\s*\{[^}]*var\(--danger\)", css)
    assert re.search(r"\.subtab-badge\s*\{[^}]*var\(--danger\)", css)
    assert re.search(r"\.subtab-badge\.warn\s*\{[^}]*var\(--alert\)", css)


# ---------------------------------------------------------------------------
# A pass with a caveat (security-officer-false-green, the 2026-09-23
# verifier's correction: the lone officer's warning sat in a passing row's
# evidence, inside a fold nothing opens)
# ---------------------------------------------------------------------------

@needs_node
def test_a_pass_with_a_caveat_is_drawn_outside_the_fold(tmp_path):
    got = _run(["countOf", "agree", "loadReadiness"], """
let reply;
async function api() { return reply; }
function renderBlockingBanner() {}
function readinessRow(c) { return el('div', 'row', c.check); }
function refusalText(err, fallback) { return fallback; }
(async () => {
  const out = [];
  for (const ready of [true, false]) {
    reply = {ready: ready, checks: [
      {check: 'p1', ok: true, caveat: ''},
      {check: 'officer', ok: true, caveat: 'break-glass is refused to them'},
      {check: 'f1', ok: ready}, {check: 'p2', ok: true}]};
    await loadReadiness();
    const list = $('rdy-list');
    out.push({summary: $('rdy-summary').textContent,
      top: list.children.map((c) => c.tag + ':' + c.textContent),
      folded: list.children[list.children.length - 1].children.map(text)});
  }
  console.log(JSON.stringify(out));
})();
""", tmp_path)
    ready, not_ready = got
    assert ready["summary"] == ("Every check in this register passes, and 1 "
                                "carries a caveat."), ready["summary"]
    assert ready["top"] == ["div:officer", "details:"], (
        "the caveat is folded away with the clean passes again", ready["top"])
    assert ready["folded"] == ["3 other checks pass", "p1", "f1", "p2"], ready
    assert not_ready["summary"] == ("1 of 4 checks needs attention. 1 passing "
                                    "check carries a caveat."), not_ready
    assert not_ready["top"] == ["div:f1", "div:officer", "details:"], not_ready


@needs_node
def test_a_caveat_row_keeps_its_pass_and_says_the_caveat_with_a_way_there(tmp_path):
    got = _run(["readinessRow"], """
function readinessGoTo(t) { return t ? el('button', 'go', 'Go ' + t) : null; }
const rows = [
  readinessRow({check: 'security_officer_present', ok: true, blocking: true,
    evidence: 'ev', action: '', caveat: 'refused to them', ui_target: 'admin/accounts'}),
  readinessRow({check: 'kek', ok: true, blocking: false, evidence: 'ev',
    action: '', caveat: '', ui_target: ''}),
];
console.log(JSON.stringify(rows.map((r) => ({cls: r.className,
  chips: r.children[0].children.slice(1).map((c) => c.className + ':' + c.textContent),
  body: r.children.slice(1).map((c) => c.className + ':' + text(c))}))));
""", tmp_path)
    officer, kek = got
    assert "rdy-row-caveat" in officer["cls"] and "row-incomplete" not in officer["cls"]
    assert officer["chips"] == ["chip good:PASS", "chip warn:CAVEAT",
                                "chip subtle:BLOCKING"], officer["chips"]
    assert officer["body"] == ["why:ev", "help warn:refused to them",
                               "go:Go admin/accounts"], officer["body"]
    assert "rdy-row-caveat" not in kek["cls"]
    assert kek["chips"] == ["chip good:PASS"] and kek["body"] == ["why:ev"], kek


@needs_node
def test_readiness_is_marked_amber_for_a_caveat_and_red_wins(tmp_path):
    got = _run(["countOf", "agree", "paintAdminBlocking"], """
const state = { caseId: null };
const canAdmin = true;
const adminView = false;
const ADM = { blocking: [], caveats: [] };
for (const id of ['admin-badge', 'adm-sub-badge', 'adm-blocking-flag']) {
  const b = $(id);
  b.classes = new Set();
  b.classList = { toggle(c, on) { if (on) b.classes.add(c); else b.classes.delete(c); } };
}
const seen = () => ['admin-badge', 'adm-sub-badge', 'adm-blocking-flag'].map((id) => {
  const b = $(id);
  return [b.hidden, b.textContent, [...b.classes].join(' ')];
});
const out = [];
paintAdminBlocking([], ['security_officer_present']);
out.push(seen(), $('adm-sub-badge').title);
paintAdminBlocking(['prohibited_content_policy'], ['security_officer_present']);
out.push(seen());
paintAdminBlocking([], []);
out.push(seen());
console.log(JSON.stringify(out));
""", tmp_path)
    caveat, title, both, none = got
    rail, sub, flag = caveat
    assert rail[0] is True and flag[0] is True, (
        "a caveat is shown where the product says what is REFUSING work")
    assert sub == [False, "1", "warn"], sub
    assert title == ("1 passing check carries a caveat: security_officer_present. "
                     "Readiness says what it is."), title
    assert both[1] == [False, "1", ""], ("a failing blocker is amber", both)
    assert both[0][0] is False
    assert none[1][0] is True and none[1][2] == "", none


# ---------------------------------------------------------------------------
# Account cards
# ---------------------------------------------------------------------------

def test_refusals_and_successes_land_on_the_card_not_the_count():
    """refusals-land-far-from-row."""
    js = _js()
    act = _source(js, "adminAct")
    assert "adm-counts" not in act, "a refusal is written over the count again"
    assert ".adm-note" in act and "ADM.notes.set(" in act
    row = _source(js, "adminUserRow")
    assert "ADM.notes.get(u.id)" in row and "'msg adm-note'" in row


@needs_node
def test_the_last_holder_of_a_load_bearing_role_is_known(tmp_path):
    got = _run(["lastActiveHolder"], """
const ADM = { users: [
  {id: 'a', is_active: true, roles: ['SYS_ADMIN', 'SECURITY_OFFICER']},
  {id: 'b', is_active: true, roles: ['SECURITY_OFFICER']},
  {id: 'c', is_active: false, roles: ['SYS_ADMIN']}] };
const [a, b] = ADM.users;
console.log(JSON.stringify([lastActiveHolder(a, 'SYS_ADMIN'),
  lastActiveHolder(a, 'SECURITY_OFFICER'), lastActiveHolder(b, 'SYS_ADMIN')]));
""", tmp_path)
    assert got == [True, False, False], got


def test_removals_ask_first_by_name_and_look_like_removals():
    """authz-changes-one-click."""
    js = _js()
    removal = _source(js, "removalRow")
    assert removal.count("window.confirm(") >= 3, (
        "deactivate, a load-bearing revoke and a revoke on yourself each ask")
    assert "'Sign ' + who + ' out everywhere and deactivate" in removal
    assert "'danger'" in removal
    assert "lastActiveHolder(u, r)" in removal and "d.disabled = true" in removal
    grant = _source(js, "grantPair")
    assert "role === 'SECURITY_OFFICER'" in grant and "window.confirm(" in grant, (
        "granting yourself SECURITY_OFFICER does not warn that nobody "
        "reviews their own break-glass (security-officer-false-green)")
    assert "'danger'" not in grant, "Grant looks like a removal"
    reset = _source(js, "resetPasswordButton")
    assert "window.confirm(" in reset and "if (you)" in reset


def test_the_pickers_are_labelled_sized_and_start_on_nothing():
    """account-row-selects-read-as-values."""
    js = _js()
    for fn in ("clearancePair", "grantPair"):
        src = _source(js, fn)
        assert "setAttribute('aria-label'" in src, fn
        assert "'adm-pair'" in src and "el('span', 'label'," in src, fn
    grant = _source(js, "grantPair")
    assert "'Choose a role…'" in grant and "none.disabled = true" in grant
    css = CSS.read_text(encoding="utf-8")
    assert re.search(r"\.adm-pair select\.select\s*\{[^}]*width:\s*auto", css), (
        "the card's pickers are 100% wide again")


def test_last_login_is_said_as_what_it_is():
    """last-login-never-misleads."""
    row = _source(_js(), "adminUserRow")
    assert "'never'" not in row
    assert "'last password sign-in'" in row and "'none recorded'" in row
    assert "u.last_active_at" in row


def test_read_ins_are_shown_and_set_on_the_card():
    """no-compartment-readins-in-ui."""
    js = _js()
    assert "readInsFact(u)" in _source(js, "adminUserRow")
    box = _source(js, "adminReadInsBox")
    assert "'/compartments/users/' + u.id" in box and "method: 'PUT'" in box
    assert "api('/compartments')" in _source(js, "loadAdminCompartments")
    assert "api('/compartments', { method: 'POST'" in _source(js, "registerCompartment")
    create = _source(js, "initAdmin")
    assert "compartments: chosenCreateCompartments()" in create
    pane = _pane_html()
    assert 'id="adm-comp-form"' in pane and 'id="adm-create-comps"' in pane


def test_create_roles_are_checkboxes_with_a_summary_and_reset():
    """create-roles-multiselect."""
    pane = _pane_html()
    fieldset = pane[pane.index('id="adm-roles"'):pane.index("</fieldset>")]
    assert "<select" not in fieldset and "multiple" not in fieldset
    assert fieldset.count('type="checkbox"') == 10
    assert re.search(r'value="ANALYST" checked', fieldset)
    assert 'id="adm-create-summary"' in pane
    create = _source(_js(), "initAdmin")
    assert "resetCreateForm()" in create
    reset = _source(_js(), "resetCreateForm")
    assert "i.checked = i.value === 'ANALYST'" in reset


# ---------------------------------------------------------------------------
# One-time credentials
# ---------------------------------------------------------------------------

def test_credentials_are_named_placed_in_their_card_and_cleared():
    """one-time-creds-card-unanchored."""
    js = _js()
    shown = _source(js, "showAdminCreds")
    assert "renderOneTimeCreds($('adm-creds'), creds)" in shown
    assert "box.dataset.for = creds.user_id" in shown
    assert "placeAdminCreds()" in shown and "head.focus()" in shown
    assert "I have handed these over: clear them" in shown
    place = _source(js, "placeAdminCreds")
    assert "c.dataset.user === id" in place
    load = _source(js, "loadAdminUsers")
    assert load.index("parkAdminCreds()") < load.index("renderList('adm-list'"), (
        "the list is redrawn with the credentials still inside a card it "
        "throws away")
    select = _source(js, "selectTab")
    assert "else clearAdminCreds();" in select, "the credentials outlive the pane"
    assert re.search(r"onCaseSwitch\(\(\) => \{\s*clearAdminCreds\(\);", js)
    # Each issuing button puts them on ITS account's card, by name.
    for fn, heading in (("resetPasswordButton", "'One-time password for ' + who"),
                        ("reenrolButton", "'New authenticator for ' + who")):
        assert f"showAdminCreds(creds, {heading})" in _source(js, fn), fn


# ---------------------------------------------------------------------------
# The password flows (gap-password-reset)
# ---------------------------------------------------------------------------

def test_the_console_and_the_server_name_the_same_problem_type():
    from noctornal_api.http.routers.auth import PASSWORD_CHANGE_REQUIRED_TYPE
    js = _js()
    m = re.search(r"^const PASSWORD_CHANGE_TYPE = '([^']+)';", js, flags=re.M)
    assert m and m.group(1) == PASSWORD_CHANGE_REQUIRED_TYPE
    fetch = _source(js, "_fetch")
    assert "err.type = p.type" in fetch
    assert "type: body.type" in _source(js, "problemOf")


def test_sign_in_asks_for_a_new_password_and_keeps_the_old_one_only_in_memory():
    js = _js()
    login = _source(js, "doLogin")
    assert "isPasswordChangeRequired(err)" in login
    assert "startPasswordChange(" in login
    submit = _source(js, "submitNewPassword")
    assert "new_password: next" in submit and "'/auth/login'" in submit
    for fn in ("startPasswordChange", "submitNewPassword", "endPasswordChange"):
        src = _source(js, fn)
        assert "Storage" not in src and "location" not in src, fn
    end = _source(js, "endPasswordChange")
    assert "PWCHANGE.password = ''" in end
    # The in-place sign-in asks for the new password in its own sheet, so
    # the screen behind it stays (final review u5, 2026-09-24; it handed
    # over to the sign-in page's card, through endSession, until then).
    assert "startReauthChange(json.password)" in _source(js, "submitReauth")
    for fn in ("startReauthChange", "endReauthChange", "reauthSignIn"):
        src = _source(js, fn)
        assert "Storage" not in src and "location" not in src, fn
    assert "REAUTH_CHANGE.password = null" in _source(js, "endReauthChange")
    # No new credential route: the must-change sign-in IS /auth/login, so
    # the 401 exemptions stay the two routes they were.
    assert "const _CREDENTIAL_CHECKS = new Set(['/auth/login', '/auth/cookie']);" in js
    html = _html()
    card = html[html.index('id="newpw-form"'):html.index("</form>", html.index('id="newpw-form"'))]
    assert 'autocomplete="new-password"' in card and 'id="newpw-code"' in card


def test_account_changes_your_own_password_and_forgets_what_was_typed():
    js = _js()
    change = _source(js, "changeOwnPassword")
    assert "'/auth/password'" in change
    for field in ("current_password: current", "totp_code: code",
                  "new_password: next"):
        assert field in change, field
    clears = _source(js, "clearSessionSecrets")
    for field in ("account-pw-current", "account-pw-new", "account-pw-again",
                  "account-pw-code"):
        assert f"$('{field}').value = ''" in clears, field
    assert "resetAccountPassword" in _source(js, "initAccountPassword")
    assert 'id="account-pw-form"' in _html()


def test_the_reset_is_offered_on_every_card_but_your_own():
    js = _js()
    reset = _source(js, "resetPasswordButton")
    assert "'/admin/users/' + u.id + '/password'" in reset
    assert "b.disabled = true" in reset and "Account" in reset

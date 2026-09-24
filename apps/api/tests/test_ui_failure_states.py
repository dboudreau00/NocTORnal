"""The console's failure states, loading states and one-click verdicts.

The review of 2026-09-22 (ux15-report, ux17-failure) found, among others:

- loading-shows-empty-claims: the empty lines shipped visible, so while a
  read was in flight the Sources tab said "Every source is healthy." and
  the triage queue "Nothing awaiting review.";
- sticky-error-text-in-empty-slot: a refusal written into an empty line
  was never taken back, and every failure was phrased as a permission;
- banners-block-appbar: the banner stack covered All cases and Log out,
  never expired, never merged, and never said which pane had failed;
- inbox-actions-fail-silently: Mark read, Acknowledge and Mark all read
  were bare awaits, and Mark all read had no confirmation;
- breakglass-review-one-click: admin Deactivate and Revoke SYS_ADMIN were
  single clicks whose errors landed far from the row;
- case-status-purged-free-text: the terminal PURGED status was one free
  text prompt away, with CLOSED prefilled for an ACTIVE case;
- due-list-no-forward-view-no-names / unruled-categories-invisible: the
  retention panel's client half (the server half is
  test_retention_due_named_pg.py).

Pure: these read the shipped static assets and, where behaviour is the
point, run the shipped functions under node against a small stand-in DOM.
Their own file, so they do not collide with other groups' edits to
test_ui_invariants.py.
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
INDEX = STATIC / "index.html"
APP_CSS = STATIC / "app.css"

DASHES = ("\u2014", "\u2013", "&mdash;", "&ndash;", " -- ")


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _html() -> str:
    return INDEX.read_text(encoding="utf-8")


def _css() -> str:
    return APP_CSS.read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """A top-level function's source, closed on the first `}` at column 0."""
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _const(name: str) -> str:
    """A top-level `const NAME = ...;` declaration, however many lines."""
    js = _js()
    m = re.search(rf"^const {re.escape(name)} = ", js, flags=re.M)
    assert m, f"app.js has no top-level const {name}"
    opener = js[m.end()]
    if opener in "[{":
        closer = {"[": "]", "{": "}"}[opener]
        end = js.index(f"\n{closer};", m.start()) + 3
    else:
        end = js.index(";\n", m.start()) + 2
    return js[m.start():end]


def _code(src: str) -> str:
    """Source with comments removed, so a test cannot pass on a comment."""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", src)


def _rule(selector: str) -> str:
    css = _css()
    m = re.search(r"(?m)^" + re.escape(selector) + r"\s*\{([^}]*)\}", css)
    assert m, f"app.css has no rule {selector}"
    return m.group(1)


def _node() -> str | None:
    for cand in ("node", r"C:\Program Files\nodejs\node.exe"):
        found = shutil.which(cand) or (cand if Path(cand).exists() else None)
        if found:
            return found
    return None


def _run(script: str) -> object:
    node = _node()
    if not node:
        pytest.skip("node is not installed; the static checks still run")
    res = subprocess.run([node, "-"], input=script, capture_output=True,
                         text=True, encoding="utf-8", timeout=60)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


#: A small DOM: enough for the shipped helpers, and honest about what
#: `$()` finds (null for an element nobody made, as the browser does).
_DOM = r"""
const registry = {};
class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.parentNode = null;
    this.dataset = {}; this.hidden = false; this.disabled = false; this._text = '';
    this.className = ''; this.listeners = {}; this.attrs = {}; this._id = null;
    this.type = ''; this.title = ''; this.value = ''; }
  get id() { return this._id; }
  set id(v) { this._id = v; if (this.parentNode) registry[v] = this; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  set textContent(v) { this._text = String(v); this.children = []; }
  get classList() {
    const node = this;
    const list = () => node.className.split(/\s+/).filter(Boolean);
    return {
      contains: (c) => list().includes(c),
      add: (...cs) => { node.className = [...new Set(list().concat(cs))].join(' '); },
      remove: (...cs) => { node.className = list().filter((x) => !cs.includes(x)).join(' '); },
      toggle: (c, on) => { if (on) node.classList.add(c); else node.classList.remove(c); },
    };
  }
  get childElementCount() { return this.children.length; }
  get lastElementChild() { return this.children[this.children.length - 1] || null; }
  appendChild(c) { c.parentNode = this; this.children.push(c); if (c._id) registry[c._id] = c; return c; }
  append(...cs) { for (const c of cs) this.appendChild(c); }
  insertBefore(c, ref) { c.parentNode = this; const i = this.children.indexOf(ref);
    this.children.splice(i < 0 ? this.children.length : i, 0, c);
    if (c._id) registry[c._id] = c; return c; }
  remove() { if (this.parentNode) { const p = this.parentNode;
    p.children = p.children.filter((x) => x !== this); this.parentNode = null; }
    if (this._id && registry[this._id] === this) delete registry[this._id]; }
  addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); }
  fire(t) { for (const fn of this.listeners[t] || []) fn({}); }
  setAttribute(k, v) { this.attrs[k] = v; }
  querySelector(sel) {
    const cls = sel.replace(/^\./, '');
    const walk = (n) => { for (const c of n.children) {
      if (c.classList.contains(cls)) return c; const r = walk(c); if (r) return r; }
      return null; };
    return walk(this);
  }
}
const root = new Node('body');
function make(id, tag, text, parent) {
  const n = new Node(tag || 'p'); n._text = text || ''; n._id = id;
  (parent || root).appendChild(n); return n;
}
function $(id) { return registry[id] || null; }
function el(tag, cls, text) { const n = new Node(tag); if (cls) n.className = cls;
  if (text !== undefined && text !== null) n._text = String(text); return n; }
function clear(n) { n.children = []; }
function show(n, on) { n.hidden = !on; }
function setMsg(n, text) { n.textContent = text || ''; n.hidden = !text; }
const timers = [];
globalThis.setTimeout = (fn, ms) => { timers.push({ fn, ms }); return timers.length; };
globalThis.clearTimeout = () => {};
const state = { tab: 'triage', caseId: 'c1', caseSeq: 1, userId: 'u1' };
function caseToken() { return state.caseSeq; }
function visibleText(s) { return String(s); }
function shortId(id) { return id ? id.slice(0, 8) : 'unknown'; }
const selected = [];
function selectTab(t) { selected.push(t); }
"""


def _helpers() -> str:
    js = _js()
    api_error = js[js.index("class ApiError extends Error {"):
                   js.index("async function problemOf(")]
    return (_DOM + api_error + _const("LIST_PENDING_TEXT")
            + _const("BANNER_EXPIRE_MS") + _const("REQUEST_LABELS")
            + "".join(_fn(n) for n in (
                "failureReason", "loadFailureText", "showLoadFailure",
                "clearLoadFailure", "emptyDefault", "listPending",
                "showEmptyState", "listRefused", "renderList", "banner",
                "bumpBanner", "armBannerExpiry", "requestLabel", "fail")))


# ---------------------------------------------------------------------------
# ux17-failure:loading-shows-empty-claims
# ---------------------------------------------------------------------------

#: Every empty line a read answers, which must not claim anything before it.
_CLAIM_EMPTIES = (
    "triage-empty", "apr-empty", "comms-unverified-empty", "ing-empty",
    "ing-quarantine-empty", "dl-empty", "src-unhealthy-empty",
    "src-never-empty", "src-due-empty", "src-personas-empty",
    "src-runs-empty", "key-empty", "ach-empty", "ret-due-empty",
    "tomb-empty", "glass-empty", "adm-empty", "dcp-cap-empty",
    "dcp-eml-empty", "dcp-call-empty",
    # The Compartments subpane's two lists (g11's registry, g17's rename
    # and retire), which arrived beside this rule (merged 2026-09-24).
    "adm-comp-empty", "adm-cmp-life-empty",
)


@pytest.mark.parametrize("empty_id", _CLAIM_EMPTIES)
def test_an_empty_claim_ships_hidden(empty_id):
    tag = re.search(r'<p id="' + re.escape(empty_id) + r'"[^>]*>', _html())
    assert tag, f"#{empty_id} is gone from index.html"
    assert re.search(r"\shidden(?=[\s>])", tag.group(0)), (
        f"#{empty_id} is visible by default, so it makes its claim while the "
        "read that would answer it is still in flight")


#: (loader, list, empty): each says "Loading…" before it asks.
_PENDING_SITES = (
    ("loadTriage", "triage-list", "triage-empty"),
    ("loadApprovals", "apr-list", "apr-empty"),
    ("loadSources", "src-never", "src-never-empty"),
    ("loadKeys", "key-list", "key-empty"),
    ("loadDeadLetters", "dl-list", "dl-empty"),
    ("loadQuarantine", "ing-quarantine-list", "ing-quarantine-empty"),
    ("loadIngestQueue", "ing-list", "ing-empty"),
    ("loadAch", "ach-ranking", "ach-empty"),
    ("loadUnverified", "comms-unverified", "comms-unverified-empty"),
    ("loadGlassQueue", "glass-queue", "glass-empty"),
    ("loadAdminUsers", "adm-list", "adm-empty"),
    ("loadAdminUsers", "adm-comp-list", "adm-comp-empty"),
    ("loadCompartmentKeys", "adm-cmp-life", "adm-cmp-life-empty"),
    ("loadSamples", "smp-list", "smp-empty"),
    ("loadTombstones", "tomb-list", "tomb-empty"),
    ("loadRetention", "ret-due", "ret-due-empty"),
)


#: The read each list waits on, where it is not the loader's first
#: `await api(`.
_READ_MARK = {
    "loadSources": "section(",
    "loadAdminUsers": "api('/admin/users')",
    "loadRetention": "api('/retention/due",
}


@pytest.mark.parametrize("loader,list_id,empty_id", _PENDING_SITES)
def test_a_loader_says_loading_before_it_asks(loader, list_id, empty_id):
    body = _code(_fn(loader))
    call = f"listPending('{list_id}', '{empty_id}')"
    assert call in body, f"{loader} never says it is loading #{list_id}"
    read = _READ_MARK.get(loader, "await api(")
    assert body.index(call) < body.index(read), (
        f"{loader} says 'Loading…' only after the read has answered")


def test_every_source_section_pends_before_it_reads():
    body = _code(_fn("section"))
    assert body.index("listPending(listId, emptyId)") < body.index("await api(")


def test_loading_then_an_answer_then_the_claim():
    """Behavioural: before the answer the line says Loading…, an empty
    answer brings the markup's claim, rows hide it, and rows already on
    screen are not replaced by a Loading… line."""
    got = _run(_helpers() + r"""
make('src-unhealthy', 'div');
make('src-unhealthy-empty', 'p', 'Every source is healthy.').hidden = true;
const out = [];
const e = $('src-unhealthy-empty');
listPending('src-unhealthy', 'src-unhealthy-empty');
out.push([e.textContent, e.hidden, e.classList.contains('pending')]);
renderList('src-unhealthy', 'src-unhealthy-empty', [], () => el('div'));
out.push([e.textContent, e.hidden, e.classList.contains('pending')]);
renderList('src-unhealthy', 'src-unhealthy-empty', [1], () => el('div'));
out.push([e.textContent, e.hidden]);
listPending('src-unhealthy', 'src-unhealthy-empty');
out.push([e.textContent, e.hidden]);
console.log(JSON.stringify(out));
""")
    assert got == [
        ["Loading…", False, True],
        ["Every source is healthy.", False, False],
        ["Every source is healthy.", True],
        ["Every source is healthy.", True],
    ], got


# ---------------------------------------------------------------------------
# ux17-failure:sticky-error-text-in-empty-slot
# ---------------------------------------------------------------------------

def test_no_refusal_is_written_straight_into_an_empty_line():
    """Every refusal goes through `listRefused`, which marks it so the next
    answer takes it back; a bare `textContent = refusalText(` into an empty
    line is how "needs evidence.read" outlived the failure."""
    code = _code(_js())
    bare = re.findall(
        r"\$\('[\w-]*-empty'\)\.textContent\s*=\s*refusalText\(|"
        r"\$\(d\.empty\)\.textContent\s*=\s*refusalText\(|"
        r"\$\(emptyId\)\.textContent\s*=\s*refusalText\(", code)
    assert not bare, bare


def test_a_refusal_is_taken_back_by_the_next_answer():
    got = _run(_helpers() + r"""
make('dcp-cap-list', 'div');
make('dcp-cap-empty', 'p', 'No captures recorded.').hidden = true;
const e = $('dcp-cap-empty');
const out = [];
renderList('dcp-cap-list', 'dcp-cap-empty', [], () => el('div'));
listRefused('dcp-cap-empty', 'Reading deception captures needs evidence.read.');
out.push([e.textContent, e.classList.contains('refused'), e.hidden]);
renderList('dcp-cap-list', 'dcp-cap-empty', [], () => el('div'));
out.push([e.textContent, e.classList.contains('refused'), e.hidden]);
console.log(JSON.stringify(out));
""")
    assert got == [
        ["Reading deception captures needs evidence.read.", True, False],
        ["No captures recorded.", False, False],
    ], got


def test_a_deception_outage_is_not_phrased_as_a_permission():
    """The sentence the finding quoted, reproduced: a 503 on captures must
    say the list could not be loaded, and never "needs evidence.read"."""
    js = _js()
    harness = (_helpers() + _const("DCP_LISTS")
               + "const DCP_DETAIL = {};\nfunction dcpDetailClose() {}\n"
               + "function refusalText(err, ctx) { return (err.detail || '') + ' ' + ctx; }\n"
               + _fn("deceptionLoadFailed"))
    got = _run(harness + r"""
const pane = make('pane', 'div');
make('dcp-cap-list', 'div', '', pane);
make('dcp-cap-empty', 'p', 'No captures recorded.', pane).hidden = true;
make('dcp-cap-counts', 'span', '12 captures', pane);
const need = 'Reading deception captures needs evidence.read on this case.';
deceptionLoadFailed(new ApiError(503, 'Service Unavailable', ''), 'cap',
  () => el('div'), need, () => {});
const failed = $('dcp-cap-empty-failed');
const down = [failed ? failed.textContent : null, $('dcp-cap-empty').hidden,
  $('dcp-cap-counts').textContent];
deceptionLoadFailed(new ApiError(403, 'Forbidden', 'evidence.read required'),
  'cap', () => el('div'), need, () => {});
const refused = [$('dcp-cap-empty').textContent,
  $('dcp-cap-empty').classList.contains('refused'), $('dcp-cap-empty-failed')];
console.log(JSON.stringify([down, refused]));
""")
    down, refused = got
    assert down[0].startswith("The captures list could not be loaded (HTTP 503")
    assert "evidence.read" not in down[0]
    assert down[1] is True and down[2] == ""
    assert "needs evidence.read" in refused[0] and refused[1] is True
    assert refused[2] is None, "a refusal leaves the outage notice standing"
    assert "loadCaptures);" in js and "loadDeceptionCalls);" in js


def test_a_rejected_request_is_not_phrased_as_a_permission():
    """The verifier's nit (2026-09-23): co-participation and the metric
    trend gave a 400 the "needs comms.read" / "needs analytics.run"
    sentence. Only a 403, or the 404 a case route hides a case behind, is
    about access; a 400 says the server's own reason."""
    # refusalText names roles through permissionRefusal (ux19-copy
    # developer-speak-in-copy); with no role table loaded it keeps the code.
    harness = (_helpers() + _fn("refusalText") + _fn("closeClause")
               + _fn("refusedWords") + _fn("permissionRefusal")
               + _fn("roleWords") + _fn("rolesFor") + _fn("listWords")
               + "let permissionRoles = null;\n")
    got = _run(harness + r"""
const need = 'Co-participation needs comms.read on the case.';
console.log(JSON.stringify([
  refusedWords(new ApiError(400, 'Bad Request', 'window is longer than the case'), need),
  refusedWords(new ApiError(400, 'Bad Request', ''), need),
  refusedWords(new ApiError(403, 'Forbidden', 'comms.read required'), need),
  refusedWords(new ApiError(404, 'Not Found', ''), need),
]));
""")
    bad, bare, forbidden, hidden = got
    need = "Co-participation needs comms.read on the case."
    assert bad == "Window is longer than the case."
    assert bare == "The server turned the request down (HTTP 400: Bad Request)."
    assert forbidden.endswith(need) and hidden == need
    for loader in ("loadCoParticipation", "loadMetricHistory"):
        body = _code(_fn(loader))
        assert "refusedWords(" in body and "refusalText(" not in body, loader


def test_a_refusal_is_styled_as_one():
    rule = _rule(".empty.refused")
    assert "var(--alert)" in rule and "#" not in rule, (
        "a refusal in the muted grey of .empty reads as the list's answer")


# ---------------------------------------------------------------------------
# ux17-failure:banners-block-appbar
# ---------------------------------------------------------------------------

def test_the_banner_stack_starts_below_the_app_bar():
    rule = _rule(".banners")
    assert "top: calc(var(--appbar-h)" in rule, (
        "the stack covers All cases, the signed-in identity and Log out")
    assert "max-height" in rule and "overflow-y: auto" in rule


def test_identical_banners_merge_and_passing_ones_expire():
    got = _run(_helpers() + r"""
make('banners', 'div');
const out = {};
banner('Service Unavailable', '', undefined);
banner('Service Unavailable', '', undefined);
banner('Service Unavailable', '', undefined);
const stack = $('banners');
out.cards = stack.children.length;
out.count = stack.children[0].querySelector('.banner-count').textContent;
out.errorTimers = timers.length;
banner('Layout saved', '3 positions.', 'warn');
out.warnTimers = timers.map((t) => t.ms);
timers[0].fn();
out.afterExpiry = stack.children.length;
console.log(JSON.stringify(out));
""")
    assert got["cards"] == 1, "a burst of identical failures is a wall of cards"
    assert got["count"] == "3 times"
    assert got["errorTimers"] == 0, "a failure must stay until it is dismissed"
    assert got["warnTimers"] == [8000]
    assert got["afterExpiry"] == 1, "the warn banner did not go by itself"


def test_a_sticky_banner_does_not_pass_by_itself():
    """A warn banner that names a step still to take stays up; a sticky
    repeat of a passing one makes it stay too, even if its old timer fires
    (the stand-in `clearTimeout` clears nothing, as a lost race would)."""
    got = _run(_helpers() + r"""
make('banners', 'div');
const stack = $('banners');
const out = {};
banner('Not corrected', 'Add a LOW claim, then retract the HIGH one.', 'warn', { sticky: true });
out.stickyTimers = timers.length;
banner('Pins cleared', 'Every node is back under the simulation.', 'warn');
banner('Pins cleared', 'Every node is back under the simulation.', 'warn', { sticky: true });
for (const t of timers) t.fn();
out.left = stack.children.map((c) => c.querySelector('.banner-title').textContent);
console.log(JSON.stringify(out));
""")
    assert got["stickyTimers"] == 0, "a sticky banner was given an expiry"
    assert got["left"] == ["Not corrected", "Pins cleared"], got


def _session_harness() -> str:
    return (_helpers() + "const SESSION = { banners: [] };\n"
            + _fn("sessionBanner") + _fn("clearSessionBanners"))


def test_session_banners_stay_and_only_they_are_taken_down():
    """The verifier's two catches (2026-09-23): session banners were raised
    as ordinary warnings, so "Session ended" and "Signed in again: the change
    ... was not saved" passed after 8 seconds; and `sessionBanner` kept the
    stack's LAST card, which after a merge is whatever was raised in
    between, so the next sign-in took down an unrelated failure."""
    got = _run(_session_harness() + r"""
make('banners', 'div');
const stack = $('banners');
sessionBanner('Session ended', 'Sign in again to carry on.');
banner('Service Unavailable', '', undefined);
sessionBanner('Session ended', 'Sign in again to carry on.');
const out = {};
out.timers = timers.length;
out.kept = SESSION.banners.map((c) => c.querySelector('.banner-title').textContent);
for (const t of timers) t.fn();
out.afterTimers = stack.children.length;
clearSessionBanners();
out.left = stack.children.map((c) => c.querySelector('.banner-title').textContent);
console.log(JSON.stringify(out));
""")
    assert got["timers"] == 0, "a session banner passes by itself"
    assert got["kept"] == ["Session ended"], (
        "sessionBanner kept a card that is not its own: " + repr(got["kept"]))
    assert got["afterTimers"] == 2
    assert got["left"] == ["Service Unavailable"], (
        "a new sign-in took down a failure that was not about the session")


def test_the_clear_pins_undo_does_not_pass_by_itself():
    """g01's Clear pins confirms with "The message that follows can put
    them back", and that card carries the only Undo. Under the expiry it
    went after 8 seconds unless pointed at (merged 2026-09-24). A second
    identical clear is counted on the same card, so the card keeps every
    clear and its one Undo puts them all back, newest first."""
    code = _code(_fn("clearPins"))
    assert "'warn', { sticky: true })" in code
    assert "(b._pinClears || (b._pinClears = [])).push(" in code
    assert "if (b.querySelector('.pins-undo')) return;" in code, (
        "a counted repeat would grow a second Undo on the one card")
    assert "b._pinClears.slice().reverse()" in code
    assert "await restorePins(" in code


def test_the_tie_grading_banners_that_name_a_next_step_stay():
    code = _code(_js())
    assert "banner('Not corrected', lowering, 'warn', { sticky: true })" in code
    claim = code[code.index("banner('Claim recorded'"):]
    claim = claim[:claim.index(");") + 2]
    assert "sticky: tie in CONF_RANK" in claim, claim
    assert "CONF_RANK[assertion.confidence] < CONF_RANK[tie]" in claim, claim


def test_a_failure_says_which_pane_and_offers_a_retry_only_for_a_read():
    got = _run(_helpers() + r"""
make('banners', 'div');
const ws = make('view-workspace', 'div'); ws.hidden = false;
const out = {};
const read = new ApiError(503, 'Service Unavailable', '');
read.path = '/cases/c1/proposals?state=PROPOSED'; read.method = 'GET';
fail(read);
const card = $('banners').children[0];
out.title = card.querySelector('.banner-title').textContent;
out.retryShown = !card.querySelector('.banner-retry').hidden;
card.querySelector('.banner-retry').fire('click');
const write = new ApiError(503, 'Service Unavailable', '');
write.path = '/notifications/n1/read'; write.method = 'POST';
fail(write);
const second = $('banners').children[$('banners').children.length - 1];
out.writeTitle = second.querySelector('.banner-title').textContent;
out.writeRetry = !second.querySelector('.banner-retry').hidden;
const elsewhere = new ApiError(503, 'Service Unavailable', '');
elsewhere.path = '/ingest/keys'; elsewhere.method = 'GET';
fail(elsewhere);
const third = $('banners').children[$('banners').children.length - 1];
out.elsewhereRetry = !third.querySelector('.banner-retry').hidden;
Promise.resolve().then(() => {
  out.reloaded = selected.slice();
  out.firstGone = !$('banners').children.includes(card);
  console.log(JSON.stringify(out));
});
""")
    assert got["title"] == "Triage queue: Service Unavailable"
    assert got["retryShown"] is True
    assert got["reloaded"] == ["triage"], "Retry did not reload the pane"
    assert got["firstGone"] is True
    assert got["writeTitle"] == "Inbox: Service Unavailable"
    assert got["writeRetry"] is False, "a write is never retried from a banner"
    assert got["elsewhereRetry"] is False, (
        "reloading the triage pane does not ask the Feeds read again")


def test_the_retry_reloads_the_pane_it_names():
    js = _code(_fn("fail"))
    assert "err.method === 'GET'" in js and "state.tab === named[1]" in js
    assert "selectTab(tab)" in js


def test_api_errors_carry_their_request():
    body = _code(_fn("api"))
    assert "err.path = path" in body and "err.method =" in body


# ---------------------------------------------------------------------------
# ux17-failure:inbox-actions-fail-silently
# ---------------------------------------------------------------------------

def test_inbox_writes_disable_and_report_where_pressed():
    render = _code(_fn("renderInbox"))
    assert "await api(" not in render, (
        "renderInbox still posts from a bare await with no error handling")
    assert render.count("inboxAction(") == 2
    action = _code(_fn("inboxAction"))
    assert "btn.disabled = true" in action and "catch (err)" in action
    assert "setMsg(msg," in action


def test_mark_all_read_confirms_with_the_counts():
    init = _code(_fn("initInbox"))
    assert "window.confirm(inboxReadAllText())" in init
    assert "catch (err)" in init and "all.disabled = true" in init
    got = _run(_DOM + _fn("countOf") + _fn("agree") + _fn("inboxReadAllText") + r"""
state.inboxUnread = 3;
state.inbox = [
  { read_at: null, priority: 1, object_type: 'approval_request' },
  { read_at: null, priority: 1, object_type: 'merge' },
  { read_at: null, priority: 2, object_type: 'x' },
  { read_at: '2026-09-01', priority: 1, object_type: 'approval_request' },
];
const many = inboxReadAllText();
state.inboxUnread = 1;
state.inbox = [{ read_at: null, priority: 1, object_type: 'approval_request' }];
const one = inboxReadAllText();
console.log(JSON.stringify([many, one]));
""")
    many, one = got
    assert many.startswith("Mark all 3 unread notifications as read?")
    assert "Of these, 2 are urgent, and 1 is an approval request waiting for "\
           "a second signature." in many
    assert "no way to mark a notification unread again" in many
    assert "Reading does not acknowledge" in many
    assert one.startswith("Mark the 1 unread notification as read?")
    assert "It is urgent, and it is an approval request" in one
    for text in (many, one):
        assert not any(d in text for d in DASHES) and "(s)" not in text


def test_preferences_that_could_not_be_read_say_so():
    body = _code(_fn("loadInboxPreferences"))
    assert "catch (_e) { return; }" not in body
    assert "showLoadFailure('inbox-prefs-empty'" in body
    assert 'id="inbox-prefs-empty"' in _html()
    assert 'id="inbox-read-all-msg"' in _html()


# ---------------------------------------------------------------------------
# ux17-failure:breakglass-review-one-click (the admin half)
# ---------------------------------------------------------------------------

def test_deactivate_and_revoking_a_governance_role_are_confirmed():
    """In the Admin card's danger row (ux16-admin, which restructured the
    card the same day): Deactivate names the account, and revoking a
    load-bearing role asks first."""
    row = _code(_fn("removalRow"))
    assert "window.confirm('Sign ' + who + ' out everywhere and deactivate '" in row, (
        "Deactivate is one click")
    assert "ADM_LOAD_BEARING.includes(r) && !window.confirm(" in row
    held = re.search(r"^const ADM_LOAD_BEARING = \[([^\]]*)\];", _js(), flags=re.M)
    assert held and "'SYS_ADMIN'" in held.group(1)
    assert "'SECURITY_OFFICER'" in held.group(1)


def test_an_admin_error_lands_on_the_row_that_was_pressed():
    """Every account action goes through adminAct, which writes its outcome
    on the card of the button that was pressed, never the counts line."""
    row = _code(_fn("adminUserRow"))
    assert "card.appendChild(note)" in row
    act = _code(_fn("adminAct"))
    assert "btn.closest('.adm-card')" in act
    assert "card.querySelector('.adm-note')" in act
    assert "$('adm-counts')" not in act, "an action still reports to the counts line"


def test_the_break_glass_review_needs_a_note_and_a_confirmation():
    """Already true when this pass began (the g06 fix of 2026-09-23); held
    here so it stays true."""
    row = _code(_fn("glassRow"))
    assert "why.length < 10" in row
    assert "window.confirm('Record \"' + label" in row
    assert "for (const x of buttons) x.disabled = true;" in row
    mine = _code(_fn("renderGlassMine"))
    assert "Could not check whether you are operating under break-glass" in mine


# ---------------------------------------------------------------------------
# ux17-failure:case-status-purged-free-text
# ---------------------------------------------------------------------------

#: The status dialog is ux02-cases's (status-prompt-free-text-one-way-
#: transitions), which fixed this finding the same day; these hold it to
#: what this finding asked for.

def test_the_status_control_is_not_a_free_text_prompt():
    wire = _code(_fn("wireCaseActions"))
    status = wire[wire.index("status.addEventListener"):]
    assert "window.prompt" not in status
    assert "openStatus" in status


def test_the_offered_moves_are_the_server_transition_table():
    """The dialog offers the server's own list for the case
    (`CaseOut.allowed_transitions`), which is the transition table read,
    so no copy of it in the console can drift from it."""
    from noctornal_api.cases import _TRANSITIONS, allowed_transitions
    for status, moves in _TRANSITIONS.items():
        assert set(allowed_transitions(status)) == moves, status
    assert "rec.allowed_transitions" in _code(_fn("openStatus"))


def test_nothing_is_chosen_for_the_analyst_and_purged_is_typed():
    sheet = _code(_fn("openStatus"))
    assert ".checked = true" not in sheet and "radio.checked" not in sheet, (
        "a preselected move is the reflexive Enter that closed a case")
    assert "save.disabled = true" in sheet
    sync = _code(_fn("syncStatusSave"))
    assert "STATUS_ONE_WAY.has(to)" in sync
    assert "$('status-code').value.trim() !== code" in sync
    one_way = re.search(r"^const STATUS_ONE_WAY = new Set\(\[([^\]]*)\]\);", _js(),
                        flags=re.M)
    assert one_way and "'PURGED'" in one_way.group(1) and "'ARCHIVED'" in one_way.group(1)
    html = _html()
    assert 'id="status-scrim"' in html and 'aria-modal="true"' in html
    moves = _js()[_js().index("const STATUS_MOVES = {"):]
    moves = moves[:moves.index("\n};")]
    assert "Mark it for destruction. This is final" in moves
    assert "Reopen it." in moves
    assert not any(d in moves for d in DASHES)
    # A fresh sign-in is asked for before PURGED is sent.
    assert "to === 'PURGED' && !confirmed && stepUpStale()" in _code(_fn("submitStatus"))


# ---------------------------------------------------------------------------
# ux15-report: the retention panel's client half
# ---------------------------------------------------------------------------

def test_the_due_list_looks_forward_and_states_the_case_clocks():
    body = _code(_fn("loadRetention"))
    assert "q.set('as_of'" in body and "retWindowDays()" in body
    assert "renderCaseClocks()" in body
    clocks = _code(_fn("renderCaseClocks"))
    assert "rec.retention_until" in clocks and "rec.review_due" in clocks
    select = re.search(r'<select id="ret-window"[^>]*>(.*?)</select>', _html(), re.S)
    assert select and 'value="90" selected' in select.group(1)
    assert 'value="0"' in select.group(1)


def _ingest_retain_until() -> str:
    src = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
           / "ingest.py").read_text(encoding="utf-8")
    start = src.index("    def _retain_until(")
    return src[start:src.index("\n    def ", start + 1)]


def test_the_case_clocks_say_an_ingest_record_can_outlive_the_case():
    """The verifier's catch (2026-09-23): the first wording said ingest
    clocks "can only be shorter" than the case's. `ingest._retain_until`
    stamps ingest time plus the category's days and never reads the case,
    so a CHAT_EXPORT record (730 days) on a case kept one more year outlives
    it. The line must say so; if ingest ever starts reading the case clock,
    the second assertion fails and the wording changes with it."""
    retain = _code(_ingest_retain_until())
    assert "retention_until" not in retain and "effective_deadline" not in retain, (
        "ingest now clamps to the case clock: renderCaseClocks' ingest "
        "sentence is out of date, rewrite it and this test together")
    got = _run(_DOM + r"""
function fmtDate(s) { return s; }
function untilWords(s) { return 'in 30 days'; }
state.caseRec = { code: 'OP-KESTREL-26', retention_until: '2027-09-24',
                  review_due: '2027-03-24' };
make('ret-case-clocks', 'p').hidden = true;
""" + _fn("renderCaseClocks") + r"""
renderCaseClocks();
console.log(JSON.stringify([$('ret-case-clocks').textContent, $('ret-case-clocks').hidden]));
""")
    text, hidden = got
    assert hidden is False
    assert "only be shorter" not in text and "shorter" not in text
    assert "does not follow the case's date" in text
    assert "before the case or after it" in text
    assert not any(d in text for d in DASHES), text


def test_a_due_row_names_its_exhibit_and_links_to_it():
    row = _code(_fn("dueExhibitRow"))
    assert "dueItemName(d)" in row and "focusEvidence(d.object_id)" in row
    assert "d.past_deadline" in row
    got = _run(_DOM + _const("TOMB_NOUN") + _fn("dueItemName") + r"""
console.log(JSON.stringify([
  dueItemName({ object_type: 'evidence', object_id: '3f2a91bc-aaaa', title: 'Seized ledger' }),
  dueItemName({ object_type: 'evidence', object_id: '3f2a91bc-aaaa', title: null, title_withheld: true }),
  dueItemName({ object_type: 'ingest_record', object_id: '9d0e1f2a-bbbb', category: 'STEALER_LOG' }),
]));
""")
    assert got[0] == 'Exhibit "Seized ledger"'
    assert got[1] == "Exhibit 3f2a91bc (title withheld: you may not open it)"
    assert got[2] == "STEALER_LOG ingest record 9d0e1f2a"


def test_the_dry_run_lists_its_items():
    body = _code(_fn("doPurge"))
    assert "body.items" in body and "dueItemName(item)" in body


def test_unruled_categories_are_listed_and_can_be_confirmed():
    body = _code(_fn("loadRetention"))
    assert "rules.in_use" in body and "unruledRow(c)" in body
    assert "rules.unruled_notice" in body
    fill = _code(_fn("fillRetentionCategories"))
    assert "-day fallback)" in fill and "retUnruled" in fill
    sync = _code(_fn("syncRuleForm"))
    assert "retUnruled.get(cat)" in sync and "a period nobody chose" in sync

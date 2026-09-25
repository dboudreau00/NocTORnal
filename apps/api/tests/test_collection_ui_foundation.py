"""The Feeds Sources pane's collection foundation, as the console ships it
(2026-09-24).

Pure: no database. The markup is read from the shipped index.html; the
functions marked `needs_node` run under Node over a stub DOM and are judged
by what they draw and what they send. The server halves are
test_collection_sources_http_e2e.py, test_collection_binding_http_e2e.py,
test_collection_authority_http_e2e.py and
test_collected_document_hold_http_e2e.py.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from test_ui_copy_no_dashes import NODE, _html, _js, js_tokens

needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")


def _fn(name: str) -> str:
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone; update this test with it"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _const(name: str) -> str:
    js = _js()
    m = re.search(rf"(?m)^(?:const|let) {re.escape(name)} = ", js)
    assert m, f"{name} is gone"
    line = js[m.start():js.index("\n", m.start())]
    if line.rstrip().endswith(";"):
        return line + "\n"
    close = js.index("\n};", m.start())
    return js[m.start():close + 3] + "\n"


def _sources_markup() -> str:
    html = _html()
    start = html.rindex("<!--", 0, html.index("what the collector leaves alone"))
    return html[start:html.index('id="src-all-empty"', start) + 200]


def _personas_markup() -> str:
    html = _html()
    start = html.rindex("<!--", 0, html.index("a persona is created here"))
    return html[start:html.index('id="src-auth-empty"', start) + 200]


#: A stub DOM just rich enough for the rows and forms: every node records
#: its children, listeners and attributes, and `text` reads a tree back.
STUBS = r"""
function mk(tag, cls, text) {
  const n = { tag: tag, className: cls || '',
    textContent: text === undefined || text === null ? '' : String(text),
    title: '', value: '', hidden: false, disabled: false, type: '', checked: false,
    id: '', children: [], dataset: {}, listeners: {}, attrs: {}, parent: null,
    classList: { _s: new Set(), add(c) { this._s.add(c); },
                 remove(c) { this._s.delete(c); }, toggle() {},
                 contains(c) { return this._s.has(c); } },
    appendChild(c) { c.parent = this; this.children.push(c); return c; },
    setAttribute(k, v) { this.attrs[k] = v; },
    addEventListener(t, fn) { this.listeners[t] = fn; },
    remove() { if (this.parent) {
      this.parent.children = this.parent.children.filter((x) => x !== this); } },
    querySelector(sel) { return find(this, (x) => sel === '.row-inline'
      && String(x.className).split(' ').includes('row-inline')); },
    querySelectorAll(sel) { return all(this, (x) => sel === 'input:checked'
      && x.tag === 'input' && x.checked); },
    focus() {} };
  return n;
}
function all(n, pred) {
  const out = [];
  (function walk(x) { if (pred(x)) out.push(x); (x.children || []).forEach(walk); })(n);
  return out;
}
function find(n, pred) { return all(n, pred)[0] || null; }
const el = mk;
const boxes = {};
function $(id) { return boxes[id] || (boxes[id] = mk('div')); }
function clear(n) { n.children = []; }
function show(n, on) { n.hidden = !on; }
function text(n) {
  return [n.textContent || '', n.title ? '[' + n.title + ']' : '']
    .concat((n.children || []).map(text)).join(' ');
}
function buttons(n) {
  return all(n, (x) => x.tag === 'button' && !x.hidden).map((x) => x.textContent);
}
function chips(n) {
  return all(n, (x) => String(x.className).startsWith('chip'))
    .map((x) => x.className + ':' + x.textContent);
}
function fact(k, v, cls) { return mk('span', 'fact' + (cls ? ' ' + cls : ''),
  k + ': ' + (v === null || v === undefined ? 'not recorded' : v)); }
function fmtTime(x) { return 'T(' + x + ')'; }
function fmtDate(x) { return 'D(' + x + ')'; }
function pad2(n) { return String(n).padStart(2, '0'); }
function tlpChip(v) { return mk('span', 'chip tlp-' + v, v); }
function visibleText(s) { return s === null || s === undefined ? '' : String(s); }
function urlHost(u) { try { return new URL(u).host; } catch (_e) { return String(u); } }
function countOf(n, one, many) { return n + ' ' + (Number(n) === 1 ? one : many); }
function setMsg(n, t) { n.textContent = t; n.hidden = !t; }
function selectOption(v, l) { const o = mk('option', null, l); o.value = v; return o; }
const NO_VALUE = 'not recorded';
const TLP = ['CLEAR', 'GREEN', 'AMBER', 'AMBER_STRICT', 'RED'];
const state = { clearance: 'AMBER' };
class ApiError extends Error {
  constructor(status, detail) { super(detail); this.status = status; this.detail = detail; }
}
const calls = [];
globalThis.apiAnswer = null;
async function api(path, opts) { calls.push({ path, opts: opts || null });
  return globalThis.apiAnswer ? globalThis.apiAnswer(path, opts)
    : { notice: 'n', authority: {} }; }
async function withStepUp(why, call) { calls.push({ stepup: why }); return call(); }
function rowForm(card, spec) { card.appendChild(mk('div', 'row-inline', spec.submit));
  card.lastSpec = spec; }
function loadSources() { calls.push({ reload: 'sources' }); }
function loadCollectedDocuments() { calls.push({ reload: 'documents' }); }
function loadAuthorityReview() { calls.push({ reload: 'review' }); }
function fail(e) { throw e; }
"""


def _run(names: list[str], body: str, tmp_path: Path, consts=()) -> dict:
    sources = [_const(c) for c in consts] + [_fn(n) for n in names]
    script = tmp_path / "run.js"
    script.write_text(STUBS + "\n".join(sources) + "\n(async () => {\n" + body
                      + "\n})().catch((e) => { console.error(e); process.exit(1); });\n",
                      encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# ---------------------------------------------------------------------------
# The markup
# ---------------------------------------------------------------------------

NEW_IDS = (
    "src-held", "src-held-empty", "src-add-box", "src-add-form", "src-add-parser",
    "src-add-kind", "src-add-name", "src-add-url", "src-add-class", "src-add-rel",
    "src-add-every", "src-add-jitter", "src-add-rps", "src-add-persona-field",
    "src-add-persona", "src-add-egress-field", "src-add-egress", "src-add-btn",
    "src-add-error", "src-add-ok", "src-all", "src-all-empty",
    "src-persona-none", "src-persona-box", "src-persona-form", "sp-handle",
    "sp-platform", "sp-egress", "sp-ua-field", "sp-ua", "sp-lang", "sp-from",
    "sp-to", "sp-notes", "sp-btn", "sp-error", "sp-ok",
    "src-auth-box", "src-auth-form", "sa-persona", "sa-scope-public",
    "sa-scope-member", "sa-member-field", "sa-member", "sa-ref", "sa-issuer",
    "sa-jur", "sa-basis", "sa-covers", "sa-class", "sa-from", "sa-until",
    "sa-sources", "sa-btn", "sa-error", "sa-ok", "src-auth", "src-auth-empty")


def test_every_new_region_and_field_exists_once():
    html = _html()
    for ident in NEW_IDS:
        assert html.count(f'id="{ident}"') == 1, ident


def test_the_regions_come_in_the_designed_order():
    html = _html()
    order = [html.index(f'id="{i}"') for i in
             ("src-due", "src-held", "src-all", "src-personas", "src-auth", "src-runs")]
    assert order == sorted(order), order


@pytest.mark.parametrize("markup", [_sources_markup, _personas_markup],
                         ids=["held-and-sources", "personas-and-authorities"])
def test_the_new_markup_carries_no_inline_style_or_handler(markup):
    block = markup()
    assert not re.search(r"\sstyle\s*=", block, re.I)
    assert not re.search(r"\son[a-z]+\s*=", block, re.I)
    assert "<script" not in block.lower()


def test_the_markup_says_what_each_region_is_for():
    sources = _sources_markup()
    assert "Nothing is waiting on a person." in sources
    assert "No sources are configured." in sources
    assert ("A forum or Telegram source is not read until its classification is "
            "within the declared ceiling") in re.sub(r"\s+", " ", sources)
    personas = re.sub(r"\s+", " ", _personas_markup())
    assert "Do not put the account's phone number or password here." in personas
    assert "The authority itself is a document outside this system." in personas
    assert "Adapter collection carries no compartments" in personas
    assert "No collection authority is recorded." in personas


def test_the_forms_are_wired_at_boot():
    js = _js()
    for wire in ("$('src-add-form').addEventListener('submit', addSource);",
                 "$('src-persona-form').addEventListener('submit', createPersona);",
                 "$('src-auth-form').addEventListener('submit', recordAuthority);",
                 "$('src-add-parser').addEventListener('change', paintSourceKinds);",
                 "$('sa-persona').addEventListener('change', paintAuthoritySources);"):
        assert wire in js, wire


def test_the_new_copy_has_no_lazy_plural_and_no_dash():
    names = ("heldRow", "sourceRow", "openBindForm", "addSource", "createPersona",
             "paintAuthoritySources", "authorityFormProblem", "recordAuthority",
             "authorityRow", "openAddTargets", "authorityPollText", "paintHeld",
             "documentHoldActions", "authorityChip", "personaRow", "runRow")
    for name in names:
        literals, _ = js_tokens(_fn(name))
        assert literals, name
        for _, said in literals:
            assert "(s)" not in said, (name, said)
            assert not re.search("[\\u2013\\u2014]", said), (name, said)
            assert not re.search(r"\s--\s", said), (name, said)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def test_sources_are_read_before_the_authorities_and_the_forms_after_both():
    load = _fn("loadSources")
    assert "sourcesRead.then(() => section('/collection/authorities'" in load
    assert load.index("Promise.all") < load.index("paintSourceForms(sources)")
    assert "paintPersonaForm(Boolean(personas))" in load
    assert "paintAuthorityForm(Boolean(authorities))" in load
    assert ".then((body) => { paintHeld(body); return body; })" in load
    assert "'Collection authorities belong to the collector role.'" in load


@needs_node
def test_the_held_list_joins_the_three_reasons_and_says_when_it_is_unknown(tmp_path):
    got = _run(["heldRow", "personaLabel", "paintHeld"], r"""
const drawn = [];
globalThis.renderList = (list, empty, rows, build) => { drawn.push([list, rows.map((r) => text(build(r)))]); };
globalThis.showLoadFailure = (id, what) => { drawn.push(['failed', id, what]); };
paintHeld({ refused: [{ name: 'A', kind: 'XENFORO', reason: 'REFUSED', sentence: 'No ceiling is declared.' }],
            waiting_on_persona: [{ name: 'B', kind: 'MYBB', reason: 'PERSONA', sentence: 'Resting.',
                                   until: '2026-09-25T00:00:00Z', persona: { hidden: true, label: 'a persona you cannot see' } }],
            awaiting_authority: [{ name: 'C', kind: 'TELEGRAM', reason: 'AUTHORITY', sentence: 'No confirmed authority.' }] });
paintHeld(null);
console.log(JSON.stringify(drawn));
""", tmp_path, consts=["HELD_WORDS"])
    listed, emptied, failed = got
    assert emptied == ["src-held", []]
    assert listed[0] == "src-held" and len(listed[1]) == 3
    assert "needs configuring" in listed[1][0] and "No ceiling is declared." in listed[1][0]
    assert "waits on its persona" in listed[1][1] and "T(2026-09-25T00:00:00Z)" in listed[1][1]
    assert "a persona you cannot see" in listed[1][1]
    assert "waits on an authority" in listed[1][2]
    assert failed[:2] == ["failed", "src-held-empty"]


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------

SOURCE = {"id": "S1", "kind": "XENFORO", "name": "Board", "base_url": "https://board.example.test/f/7/",
          "parser_key": "xenforo", "classification": "AMBER", "is_active": True,
          "health": "OK", "persona": None, "egress_profile": {"id": "E1", "name": "exit-one"},
          "requires_authority": True, "authority": {"state": "PENDING"},
          "blocked_reason": None, "refusal": None}


@needs_node
def test_a_source_row_says_who_reads_it_and_offers_the_verbs_it_may_use(tmp_path):
    got = _run(["sourceRow", "sourceExit", "personaLabel", "authorityChip"], f"""
const s = {json.dumps(SOURCE)};
SRC.form = {{ can_manage: true, can_bind: true }};
const full = sourceRow(s);
SRC.form = {{ can_manage: false, can_bind: false }};
const reader = sourceRow({{ ...s, persona: {{ hidden: true, label: 'a persona you cannot see' }},
  egress_profile: null, refusal: 'No ceiling is declared for XENFORO sources.' }});
console.log(JSON.stringify({{ full: [text(full), buttons(full), chips(full)],
                              reader: [text(reader), buttons(reader)] }}));
""", tmp_path, consts=["SRC"])
    text, verbs, chips = got["full"]
    assert "host: board.example.test" in text and "exit: exit-one" in text
    assert verbs == ["Deactivate", "Change who reads it"]
    assert "chip warn:waiting for a second person" in chips
    reader_text, reader_verbs = got["reader"]
    assert reader_verbs == []
    assert "reads as: a persona you cannot see" in reader_text
    assert "Not read: No ceiling is declared for XENFORO sources." in reader_text


@needs_node
def test_the_authority_chip_has_one_word_and_colour_per_state(tmp_path):
    got = _run(["authorityChip"], r"""
const out = {};
for (const st of ['LIVE', 'PENDING', 'NOT_YET_VALID', 'EXPIRED', 'REVOKED', 'NONE']) {
  const c = authorityChip({ state: st, valid_until: '2026-12-01T00:00:00Z' });
  out[st] = [c.className, c.textContent];
}
out.missing = [authorityChip(null).className, authorityChip(null).textContent];
console.log(JSON.stringify(out));
""", tmp_path)
    assert got["LIVE"] == ["chip ok", "in force until D(2026-12-01T00:00:00Z) UTC"]
    assert got["PENDING"] == ["chip warn", "waiting for a second person"]
    assert got["NOT_YET_VALID"] == ["chip warn", "not yet in force"]
    assert got["EXPIRED"] == ["chip bad", "expired"]
    assert got["REVOKED"] == ["chip bad", "revoked"]
    assert got["NONE"] == got["missing"] == ["chip bad", "no authority"]


@needs_node
def test_run_rows_paint_blocked_bad_rate_limited_warn_and_an_unrecorded_start(tmp_path):
    got = _run(["runRow", "personaLabel"], r"""
const out = {};
for (const st of ['OK', 'PARTIAL', 'RATE_LIMITED', 'BLOCKED', 'FAILED']) {
  out[st] = chips(runRow({ status: st, source_name: 's', started_at: null,
    items_seen: 3, items_new: 1, items_deleted: 1, requested_by_name: 'the system',
    persona: { hidden: true, label: 'a persona you cannot see' },
    notes: ['The poll stopped at its budget.'] }))[0];
}
out.text = text(runRow({ status: 'BLOCKED', source_name: 's', started_at: null,
  items_seen: 0, items_new: 0, notes: ['The poll stopped at its budget.'],
  requested_by_name: 'the system', persona: { hidden: true, label: 'a persona you cannot see' } }));
console.log(JSON.stringify(out));
""", tmp_path, consts=["RUN_STATUS_CLASS"])
    assert got["OK"].startswith("chip ok")
    assert got["PARTIAL"].startswith("chip warn")
    assert got["RATE_LIMITED"].startswith("chip warn")
    assert got["BLOCKED"].startswith("chip bad")
    assert got["FAILED"].startswith("chip bad")
    assert "started: not recorded" in got["text"]
    assert "Notes: The poll stopped at its budget." in got["text"]
    assert "asked by: the system" in got["text"]
    assert "persona: a persona you cannot see" in got["text"]


@needs_node
def test_a_persona_row_says_what_its_platform_did_to_it(tmp_path):
    got = _run(["personaRow", "authorityChip"], r"""
const later = new Date(Date.now() + 3600000).toISOString();
const p = { id: 'P1', handle: 'quietfox', status: 'HEALTHY', platform: 'XENFORO',
  platform_uid: '4411', egress_profile_name: 'exit-two', active_window_utc: '07:00-23:00',
  sources_bound: 2, credential_stored: false, machine_hold_until: later,
  machine_lock_code: 'CREDENTIAL_REJECTED', authority: { state: 'LIVE', valid_until: '2026-12-01' } };
console.log(JSON.stringify([text(personaRow(p)), chips(personaRow(p))]));
""", tmp_path)
    body, chip_list = got
    assert "account: 4411" in body and "egress: exit-two" in body
    assert "active hours: 07:00 to 23:00 UTC" in body
    assert "sources bound: 2" in body and "credential: none yet" in body
    assert "paused by its platform until: T(" in body
    assert "Locked by its platform." in body
    assert "chip ok:in force until D(2026-12-01) UTC" in chip_list


# ---------------------------------------------------------------------------
# Poll now
# ---------------------------------------------------------------------------

@needs_node
def test_the_persona_less_confirm_names_the_agent_the_site_will_log(tmp_path):
    got = _run(["authorityPollText", "srcExitWords", "personaLabel"], r"""
SRC.form = { sources: [{ id: 'S1', egress_profile: { id: 'E1', name: 'exit-one' } }] };
SRC.personas = [{ id: 'P1', egress_profile_name: 'exit-two' }];
const s = { id: 'S1', name: 'Board', max_rps: 0.2, run_seconds: 90, persona: null };
const bound = { id: 'S2', name: 'Members', max_rps: 0.2, run_seconds: 90,
  persona: { id: 'P1', handle: 'quietfox' } };
console.log(JSON.stringify([authorityPollText(s, 'board.example.test'),
                            authorityPollText(bound, 'board.example.test')]));
""", tmp_path, consts=["SRC"])
    less, bound = got
    assert "NocTORnal-collector" in less
    assert "through egress profile exit-one" in less
    assert "No persona signs in." in less
    assert "At most 0.2 requests per second, for at most 90 seconds." in less
    assert "Whoever runs board.example.test can see the requests." in less
    assert "as persona quietfox, over egress profile exit-two." in bound
    assert "Nothing is posted or sent." in bound
    assert "NocTORnal-collector" not in bound


def test_poll_now_uses_the_authority_text_only_for_an_authority_source():
    due = _fn("dueRow")
    assert "s.requires_authority ? authorityPollText(s, host)" in due
    assert "identified honestly as a collector and not a browser" in due, (
        "an RSS poll keeps its confirmation")


# ---------------------------------------------------------------------------
# The forms
# ---------------------------------------------------------------------------

@needs_node
def test_labels_are_capped_at_the_clearance_and_the_declared_ceiling(tmp_path):
    got = _run(["labelsUpTo", "defaultLabel"], r"""
const out = [labelsUpTo(null), labelsUpTo('GREEN'), labelsUpTo('RED')];
state.clearance = 'GREEN';
out.push(labelsUpTo(null), defaultLabel(labelsUpTo(null)));
state.clearance = null;
out.push(labelsUpTo(null));
console.log(JSON.stringify(out));
""", tmp_path)
    assert got[0] == ["CLEAR", "GREEN", "AMBER"]
    assert got[1] == ["CLEAR", "GREEN"]
    assert got[2] == ["CLEAR", "GREEN", "AMBER"], "a ceiling never lifts the clearance"
    assert got[3] == ["CLEAR", "GREEN"] and got[4] == "GREEN"
    assert got[5] == ["CLEAR"]


@needs_node
def test_the_authority_form_refuses_what_the_server_would(tmp_path):
    got = _run(["authorityFormProblem"], r"""
function fill(ref, member, from, until) {
  $('sa-ref').value = ref; $('sa-member').value = member;
  $('sa-from').value = from; $('sa-until').value = until;
}
const long = 'The threads of the marketplace section named in the warrant.';
fill('WARRANT-7', '', '2026-09-24', '2026-12-23');
const out = [
  authorityFormProblem(null, 'PUBLIC_READ', [], long),
  authorityFormProblem(null, 'MEMBER_READ', ['S1'], long),
  authorityFormProblem('P1', 'MEMBER_READ', [], long),
  authorityFormProblem('P1', 'PUBLIC_READ', [], 'too short'),
  authorityFormProblem('P1', 'PUBLIC_READ', [], long),
];
fill('W7', '', '2026-09-24', '2026-12-23');
out.push(authorityFormProblem('P1', 'PUBLIC_READ', [], long));
console.log(JSON.stringify(out));
""", tmp_path)
    assert got[0] == "An authority with no persona covers sources: tick at least one."
    assert got[1] == "Reading as a member needs a persona."
    assert got[2] == "Reading as a member needs its own authority reference."
    assert got[3] == "Say what it covers, in more than 20 characters."
    assert got[4] is None, "a persona's authority may name no source"
    assert got[5] == "The authority reference is at least 3 characters."


def test_the_authority_dates_are_whole_utc_days_and_the_default_is_ninety():
    record = _fn("recordAuthority")
    assert "$('sa-from').value + 'T00:00:00Z'" in record
    assert "$('sa-until').value + 'T23:59:59Z'" in record
    assert "withStepUp('Recording an authority needs a recent sign-in.'" in record
    assert "90 * 86400000" in _fn("paintAuthorityForm")


def test_a_binding_or_a_persona_is_sent_behind_the_step_up_gate():
    assert "withStepUp('Binding a source to a persona or an exit" in _fn("addSource")
    assert "withStepUp('Creating a persona needs a recent sign-in.'" in _fn("createPersona")
    assert "withStepUp('Changing who reads a source" in _fn("openBindForm")


@needs_node
def test_a_persona_is_never_offered_an_exit_something_else_reads_through(tmp_path):
    got = _run(["paintPersonaForm", "paintPersonaIdentity", "srcEgress"], r"""
SRC.form = { adapters: [{ parser_key: 'xenforo', persona_platform: 'XENFORO', persona_http: true },
                        { parser_key: 'rss', persona_platform: null }] };
globalThis.apiAnswer = async () => ({ egress_profiles: [
  { id: 'E1', name: 'free', available: true, sources: 0 },
  { id: 'E2', name: 'held', available: false, sources: 0 },
  { id: 'E3', name: 'public-read', available: true, sources: 1 }] });
await paintPersonaForm(true);
const offered = $('sp-egress').children.map((o) => o.value);
const platforms = $('sp-platform').children.map((o) => o.value);
SRC.form = { adapters: [{ parser_key: 'rss', persona_platform: null }] };
SRC.egress = null;
await paintPersonaForm(true);
console.log(JSON.stringify({ offered, platforms, ua: $('sp-ua-field').hidden,
  none: $('src-persona-none').hidden, box: $('src-persona-box').hidden }));
""", tmp_path, consts=["SRC"])
    assert got["offered"] == ["E1"]
    assert got["platforms"] == ["XENFORO"]
    assert got["none"] is False and got["box"] is True, (
        "with no persona parser the form hides and the section says so")


# ---------------------------------------------------------------------------
# Collected documents (retention and holds, docs/00 decision 74)
# ---------------------------------------------------------------------------

@needs_node
def test_a_held_document_says_so_and_only_a_holder_gets_the_verb(tmp_path):
    got = _run(["collectedDocRow", "documentHoldActions"], r"""
const d = { id: 'D1', title: 't', triage_state: 'NEW', classification: 'AMBER',
  source_name: 's', author_handle: 'a', posted_at: null, version: 1,
  legal_hold: true, legal_hold_reason: 'Preservation order 12' };
const reader = collectedDocRow(d);
const holder = collectedDocRow(d, true);
const free = collectedDocRow({ ...d, legal_hold: false, legal_hold_reason: null }, true);
find(holder, (x) => x.tag === 'button').listeners.click();
await holder.lastSpec.submitFn(['Order discharged']);
console.log(JSON.stringify({ reader: [text(reader), buttons(reader), chips(reader)],
  holder: buttons(holder), free: buttons(free), calls }));
""", tmp_path)
    text, verbs, chip_list = got["reader"]
    assert "chip warn:on legal hold" in chip_list
    assert "A legal hold stops every deletion of this document" in text
    assert "Held: Preservation order 12" in text
    assert verbs == []
    assert got["holder"] == ["Lift the legal hold"]
    assert got["free"] == ["Place a legal hold"]
    sent = [c for c in got["calls"] if c.get("path")]
    assert sent == [{"path": "/retention/documents/D1/legal-hold",
                     "opts": {"method": "POST",
                              "json": {"on": False, "reason": "Order discharged"}}}]
    assert got["calls"][0] == {"stepup": "A legal hold needs a recent sign-in."}


def test_the_document_listing_carries_whether_the_caller_may_hold():
    load = _fn("loadCollectedDocuments")
    assert "const canHold = Boolean(body.can_hold);" in load
    # 2026-09-25: the row is wrapped with its Similar control (F6.3),
    # which passes canHold through.
    assert "(d) => collectedDocRowWithSimilar(d, canHold)" in load
    assert "collectedDocRow(d, canHold)" in _fn("collectedDocRowWithSimilar")


@needs_node
def test_a_stopped_authority_offers_nothing_and_draws_no_source_states(tmp_path):
    """Screenshot review, 2026-09-24: under a revoked authority a source
    still read 'waiting for a second person', which it never will be."""
    got = _run(["authorityRow", "authorityTargetLine", "authorityTargetText",
                "authorityChip", "personaLabel", "authorityEligible"], r"""
const target = { id: 'T1', source_id: 'S1', source_name: 'Board', source_kind: 'XENFORO',
  source_host: 'board.example.test', binding: { egress_profile: { id: 'E1', name: 'exit-one' } },
  state: 'PENDING', binding_changed: true, address_changed: false };
const base = { id: 'A1', authority_ref: 'W-7', classification: 'AMBER', scope: 'PUBLIC_READ',
  scope_words: 'Read what the platform shows to anyone', persona: null, issued_by: 'Court',
  valid_from: 'f', valid_until: 'u', recorded_by_name: 'Rec', targets: [target] };
SRC.form = { sources: [{ id: 'S2', name: 'Other', requires_authority: true, is_active: true,
  persona: null, base_url: 'https://board.example.test/f/9/', kind: 'XENFORO' }] };
const stopped = authorityRow({ ...base, state: 'REVOKED' });
const live = authorityRow({ ...base, state: 'PENDING' });
console.log(JSON.stringify({ stopped: [buttons(stopped), chips(stopped)],
                             live: [buttons(live), chips(live), text(live)] }));
""", tmp_path, consts=["SRC", "TARGET_WORDS"])
    verbs, chip_list = got["stopped"]
    assert verbs == []
    assert chip_list == ["chip tlp-AMBER:AMBER", "chip bad:revoked"]
    live_verbs, live_chips, live_text = got["live"]
    assert live_verbs == ["Add sources", "Revoke"]
    assert "chip warn:waiting for a second person" in live_chips
    assert "chip bad:no longer covered" in live_chips
    assert "valid: T(f) to T(u)" in live_text

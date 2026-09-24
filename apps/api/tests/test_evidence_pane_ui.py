"""The Evidence pane as the console draws it (ux07-evidence, 2026-09-23).

Every finding of the 2026-09-22 review's Evidence pane walk-through is held
here from the console's side; `test_evidence_register_pg.py` holds the
server's. Each was a sentence, a chip or a missing control telling the
analyst something false or nothing at all:

- worm-chip-outlives-lock: "WORM LOCKED" for ever, on a lock that lapses.
- no-forward-trace-from-exhibit: nothing said what rests on an exhibit.
- upload-drops-provenance: no acquisition time, source or authority, and
  "acquired" meant uploaded.
- custody-rows-not-court-legible: minute precision and no row detail.
- hash-and-id-not-reachable: sixteen hex in the card, the rest in a
  tooltip, and the exhibit id nowhere.
- coverage-vanishes-with-metrics: the headline figure hung on an optional
  call and vanished with it.
- no-exhibit-export-control: no way to produce an exhibit.
- evidence-list-silently-capped: the newest 200, without a word.
- verify-writes-custody-silently: a permanent entry that looked like a
  harmless check.

Pure: no database, no browser. The checks marked `needs_node` EXECUTE the
shipped functions under Node with a small DOM stub, because "the lapsed
lock renders as a warning" is a claim about behaviour; reading the source
for a class name would pass on a branch nothing reaches.
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

_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)
needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _html() -> str:
    return INDEX.read_text(encoding="utf-8")


def _code() -> str:
    """app.js without comments: the comments quote the old strings."""
    js = re.sub(r"/\*.*?\*/", "", _js(), flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", js)


def _fn(name: str) -> str:
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _const(name: str) -> str:
    js = _js()
    start = js.index(f"const {name} = ")
    return js[start:js.index(";\n", start) + 2]


def _deceptive() -> str:
    js = _js()
    start = js.index("const _DECEPTIVE = new RegExp(")
    return js[start:js.index("]', 'g');", start) + len("]', 'g');")]


#: Enough DOM for the card: elements with children, attributes and
#: listeners, and the console's own helpers where the real ones need a
#: document.
_STUBS = r"""
function mk(tag, cls, text) {
  const n = { tag, className: cls || '', title: '', hidden: false, value: '',
    disabled: false, type: '', id: '', attrs: {}, children: [], listeners: {},
    textContent: text === undefined || text === null ? '' : String(text),
    appendChild(c) { this.children.push(c); return c; },
    append(...cs) { for (const c of cs) this.children.push(c); },
    setAttribute(k, v) { this.attrs[k] = String(v); },
    addEventListener(k, f) { this.listeners[k] = f; } };
  return n;
}
function el(tag, cls, text) { return mk(tag, cls, text); }
const NO_VALUE = 'not recorded';
function fmtTime(x, s) { return 'T(' + x + (s ? ',s' : '') + ')'; }
function fmtDate(x) { return 'D(' + x + ')'; }
function fmtBytes(n) { return n + ' B'; }
function shortId(id) { return id ? String(id).slice(0, 8) : 'unknown'; }
function typeName(k) { return 'type:' + k; }
function tlpChip(v) { return mk('span', 'chip tlp-' + v, v); }
function fact(label, value, cls) {
  const w = mk('span', 'fact' + (cls ? ' ' + cls : ''));
  w.appendChild(mk('span', 'fact-k', label));
  w.appendChild(mk('span', 'fact-v', value));
  return w;
}
function copyable(node, value, label) {
  const w = mk('span', 'copyable');
  w.appendChild(node);
  w.copies = value; w.what = label;
  return w;
}
function dcpRuns(parent, runs) {
  for (const r of runs) parent.appendChild(mk('span', r.defanged ? 'defanged' : '', r.text));
}
/* Every text in a tree, in order, for assertions about what is said. */
function texts(n, out) {
  out = out || [];
  if (n.textContent) out.push(n.textContent);
  for (const c of n.children || []) texts(c, out);
  return out;
}
function find(n, pred) {
  if (pred(n)) return n;
  for (const c of n.children || []) { const hit = find(c, pred); if (hit) return hit; }
  return null;
}
"""


def _run(tmp_path: Path, names: list[str], body: str, consts=()):
    parts = [_STUBS, _deceptive()] + [_const(c) for c in consts] + [
        _fn(n) for n in names]
    script = tmp_path / "run.js"
    script.write_text("\n".join(parts) + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


_CARD_FNS = ["visibleText", "countOf", "agree", "methodName", "lockChip",
             "acquiredText", "lastCheckText", "runsFact", "exhibitIdLine",
             "backsLine", "exhibitCard"]
_CARD_CONSTS = ("EV_METHODS", "BACKS_RULE")

_EXHIBIT = {
    "id": "cfdcb38d-9950-45e4-9815-e457b8762a58", "title": "remittance-change.eml",
    "media_type": "message/rfc822", "byte_size": 1643,
    "sha256": "29c6d46fc71537e0d0bb8fa1692d0c26d9dd4ef45df0f83afdfc6df64adea0a7",
    "classification": "AMBER", "acquisition_method": "LEGAL",
    "acquired_at": "2026-09-10T09:30:00Z", "acquired_at_stated": True,
    "acquired_by": "1868ab04-0000", "acquired_by_name": "Demo Analyst",
    "lodged_at": "2026-09-17T15:18:07Z",
    "description_segments": [], "source_segments": [
        {"text": "hxxps://evil[.]example/x", "defanged": True}],
    "authority_segments": [{"text": "PO-2026-114", "defanged": False}],
    "is_worm_locked": True, "lock_until": "2027-09-17", "lock_lapsed": False,
    "legal_hold": False, "is_hostile_markup": False, "purged_at": None,
    "backs_nodes": 0, "backs_edges": 0, "last_check": None,
}


# ---------------------------------------------------------------------------
# worm-chip-outlives-lock
# ---------------------------------------------------------------------------

@needs_node
def test_the_lock_chip_carries_its_date_and_warns_once_it_has_passed(tmp_path):
    got = _run(tmp_path, ["lockChip"], """
const base = { is_worm_locked: true, legal_hold: false, purged_at: null,
               lock_ends_at: null };
const at = '2027-09-17T03:02:03Z';
console.log(JSON.stringify([
  lockChip(Object.assign({}, base, { lock_until: '2027-09-17', lock_lapsed: false,
                                     lock_ends_at: at })),
  lockChip(Object.assign({}, base, { lock_until: '2027-09-17', lock_lapsed: true,
                                     lock_ends_at: at })),
  lockChip(Object.assign({}, base, { lock_until: null, lock_lapsed: false })),
  lockChip(Object.assign({}, base, { lock_until: '2027-09-17', purged_at: 'x' })),
  lockChip(Object.assign({}, base, { lock_until: '2027-09-17', lock_lapsed: false })),
  lockChip(Object.assign({}, base, { lock_until: '2026-01-05', lock_lapsed: true })),
  lockChip(Object.assign({}, base, { lock_until: '2027-09-17', lock_lapsed: false,
                                     lock_ends_at: at, lock_short_of_case: true })),
]));
""")
    live, lapsed, undated, purged, day_only, day_only_lapsed, short = got
    assert live[:2] == ["chip flag", "WORM until D(2027-09-17)"]
    assert "until T(2027-09-17T03:02:03Z,s) the object store refuses" in live[2], (
        "the instant the store holds to, to the second")
    # x-lock-extension (2026-09-24): the lock follows the case's retention
    # date from lodging and when it is extended, so the chip no longer says
    # the lock ignores that date.
    assert "runs to the case's retention date" in live[2]
    assert "lengthened when that date is extended" in live[2]
    assert "does not follow" not in live[2]
    assert "before the case's retention date" not in live[2]
    # A lock that still ends first says so, and where it can be lengthened,
    # rather than claiming to run to the date (verifier, 2026-09-24).
    assert short[:2] == ["chip flag", "WORM until D(2027-09-17)"]
    assert "ends before the case's retention date" in short[2]
    assert "the Evidence pane can lengthen it" in short[2]
    assert "runs to the case's retention date" not in short[2]
    assert lapsed[:2] == ["chip warn", "WORM lock ended D(2027-09-17)"]
    assert "ended at T(2027-09-17T03:02:03Z,s)" in lapsed[2]
    assert "no longer refuses" in lapsed[2]
    assert undated[1] == "WORM" and "does not carry the date" in undated[2]
    assert purged is None, "a purged exhibit has no bytes to lock"
    # Only the day on record: never "until the end of" it (verifier,
    # 2026-09-23: the lock ends part way through its last day).
    assert day_only[:2] == ["chip flag", "WORM until D(2027-09-17)"]
    assert "until some time on D(2027-09-17)" in day_only[2]
    assert "do not rely on the lock on that day itself" in day_only[2]
    assert day_only_lapsed[:2] == ["chip warn",
                                   "WORM lock not counted on from D(2026-01-05)"]
    assert "may already accept" in day_only_lapsed[2]
    said = json.dumps(got)
    assert "cannot be replaced or deleted" not in said
    assert "end of" not in said, "the lock does not run to the end of its day"
    assert "at acquisition" not in said, "it runs from lodging"


def test_the_fixed_flag_is_gone_and_the_policy_line_names_the_period():
    code = _code()
    assert "'WORM LOCKED'" not in code
    policy = re.sub(r"/\*.*?\*/", "", _fn("renderEvidencePolicy"), flags=re.S)
    assert "p.lock_days" in policy and "from the moment" in policy
    assert "from acquisition" not in policy, (
        "the lock runs from lodging, and 'acquired' is the stated time")
    # x-lock-extension (2026-09-24): the lock runs to the case's date, as
    # far as the deployment's horizon, and an extension lengthens it.
    assert "until the case\\'s retention date" in policy
    assert "p.lock_horizon_days" in policy and "Extending the date lengthens" in policy
    assert "nobody can shorten one" in policy
    assert "does not follow the case" not in policy


# ---------------------------------------------------------------------------
# The card: provenance, the whole digest and id, backs, last check, actions
# ---------------------------------------------------------------------------

@needs_node
def test_the_card_says_acquired_and_lodged_apart_and_shows_every_identifier(tmp_path):
    got = _run(tmp_path, _CARD_FNS, """
const ev = %s;
const card = exhibitCard(ev, { may_export: true, may_audit: true });
const said = texts(card);
const copies = [];
(function walk(n) { if (n.copies) copies.push([n.copies, n.what]);
  for (const c of n.children || []) walk(c); })(card);
const buttons = [];
(function walk(n) { if (n.tag === 'button') buttons.push(n.textContent);
  for (const c of n.children || []) walk(c); })(card);
console.log(JSON.stringify({ said, copies, buttons, id: card.id }));
""" % json.dumps(_EXHIBIT), consts=_CARD_CONSTS)
    said = got["said"]
    assert "T(2026-09-10T09:30:00Z) by Demo Analyst" in said
    assert "T(2026-09-17T15:18:07Z,s)" in said, "lodged, to the second"
    assert "acquired" in said and "lodged" in said
    assert "hxxps://evil[.]example/x" in said and "PO-2026-114" in said
    assert "Legal process" in said
    assert [_EXHIBIT["sha256"], "the SHA-256 digest"] in got["copies"], (
        "the whole digest, selectable and copyable, not sixteen hex")
    assert [_EXHIBIT["id"], "the exhibit id"] in got["copies"]
    assert _EXHIBIT["sha256"] in said and _EXHIBIT["id"] in said
    assert "Nothing on the live graph rests on this exhibit." in said
    assert "Verify (logged)" in got["buttons"]
    assert "Export for disclosure…" in got["buttons"]
    assert "Verify the custody chain" in got["buttons"]
    assert got["id"] == "ev-" + _EXHIBIT["id"]


@needs_node
def test_an_unstated_time_is_not_passed_off_as_the_acquisition(tmp_path):
    ev = dict(_EXHIBIT, acquired_at_stated=False)
    got = _run(tmp_path, _CARD_FNS, """
const card = exhibitCard(%s, { may_export: false, may_audit: false });
const acquired = find(card, (n) => n.className === 'fact warn');
console.log(JSON.stringify({ acquired: texts(acquired), all: texts(card) }));
""" % json.dumps(ev), consts=_CARD_CONSTS)
    assert got["acquired"][0] == "acquired"
    assert "at lodging, no earlier time stated, by Demo Analyst" in got["acquired"]
    assert "Export for disclosure…" not in got["all"], "no control without the permission"
    assert "Verify the custody chain" not in got["all"]


@needs_node
def test_attacker_markup_is_produced_through_the_sample_origin(tmp_path):
    """x-hostile-export (2026-09-24). The card said "No export here" and sent
    the analyst to a procedure outside the product, because nothing could
    produce attacker markup. It now offers the production, which fetches
    the bytes from the sample origin, and never this origin's export."""
    ev = dict(_EXHIBIT, is_hostile_markup=True)
    got = _run(tmp_path, _CARD_FNS, """
const card = exhibitCard(%s, { may_export: true, may_audit: false });
const b = find(card, (n) => n.tag === 'button'
  && n.textContent === 'Produce through the sample origin…');
console.log(JSON.stringify({ said: texts(card), title: b && b.title,
  wired: b && typeof b.listeners.click }));
""" % json.dumps(ev), consts=_CARD_CONSTS)
    said = got["said"]
    assert "Export for disclosure…" not in said, "this origin never serves it"
    assert "attacker markup" in said
    assert not any("No export here" in t for t in said)
    assert got["wired"] == "function"
    assert "sample origin" in got["title"] and "EXPORTED" in got["title"]
    assert "produceExhibit(ev, verdict, custodyBox)" in _fn("exhibitCard")
    # Without the permission, nothing is offered at all.
    none = _run(tmp_path, _CARD_FNS, """
const card = exhibitCard(%s, { may_export: false, may_audit: false });
console.log(JSON.stringify(texts(card)));
""" % json.dumps(ev), consts=_CARD_CONSTS)
    assert "Produce through the sample origin…" not in none


@needs_node
def test_what_rests_on_an_exhibit_is_counted_and_opens(tmp_path):
    ev = dict(_EXHIBIT, backs_nodes=3, backs_edges=1)
    got = _run(tmp_path, _CARD_FNS, """
const card = exhibitCard(%s, { may_export: false, may_audit: false });
const b = find(card, (n) => n.tag === 'button' && n.textContent.startsWith('Backs'));
console.log(JSON.stringify({ text: b.textContent, expanded: b.attrs['aria-expanded'],
  wired: typeof b.listeners.click }));
""" % json.dumps(ev), consts=_CARD_CONSTS)
    assert got == {"text": "Backs 3 entities and 1 relationship",
                   "expanded": "false", "wired": "function"}
    assert "cpath('/evidence/' + ev.id + '/backs')" in _fn("toggleBacks")
    opened = _fn("backedButton")
    assert "selectEdge(item.id)" in opened and "selectNode(item.id)" in opened
    assert "visibleText(item.label)" in opened, "labels are de-fanged"


@needs_node
def test_a_purged_exhibit_says_why_nothing_rests_on_it(tmp_path):
    """The server counts a purged exhibit as backing nothing, as the canvas
    does (verifier, 2026-09-23); the card says why, rather than reading like
    an exhibit nobody used, and offers nothing to open."""
    ev = dict(_EXHIBIT, purged_at="2026-09-20T10:00:00Z", backs_nodes=2)
    got = _run(tmp_path, _CARD_FNS, """
const card = exhibitCard(%s, { may_export: true, may_audit: false });
const backs = find(card, (n) => n.className === 'ev-backs');
console.log(JSON.stringify({ backs: texts(backs), all: texts(card) }));
""" % json.dumps(ev), consts=_CARD_CONSTS)
    assert got["backs"] == ["Purged, so nothing on the live graph rests on it now. "
                            "Where it was attached, the inspector still lists it, "
                            "marked as purged."]
    assert not any(t.startswith("Backs ") for t in got["all"])
    assert "Verify (logged)" not in got["all"] and "Export for disclosure…" not in got["all"]


@needs_node
def test_the_last_check_is_kept_and_a_mismatch_is_loud(tmp_path):
    got = _run(tmp_path, ["visibleText", "lastCheckText"], """
console.log(JSON.stringify([
  lastCheckText(null),
  lastCheckText({ at: 'a', ok: true, by_name: 'Demo Analyst' }),
  lastCheckText({ at: 'b', ok: false, by_name: null }),
]));
""")
    none, ok, bad = got
    assert "No verification on the custody record since the exhibit was lodged" in none[1]
    assert ok == ["help ev-last", "Last verified T(a,s) by Demo Analyst: the digest matched."]
    assert bad[0] == "help ev-last fail" and "HASH MISMATCH" in bad[1]


def test_verify_says_it_is_logged_and_refreshes_an_open_log():
    """verify-writes-custody-silently: the label, and the open custody log
    fetched again after the verdict so the new row shows."""
    card = _fn("exhibitCard")
    assert "'Verify (logged)'" in card
    assert "in your name" in card
    verify = _fn("verifyExhibit")
    assert "if (!custodyBox.hidden) loadCustody(ev, custodyBox);" in verify
    assert "lastCheckText(" in verify
    said = " ".join(_html().split())
    assert ("Every verification and export is written to the exhibit's "
            "custody record in your name.") in said


# ---------------------------------------------------------------------------
# custody-rows-not-court-legible
# ---------------------------------------------------------------------------

@needs_node
def test_a_re_acquisition_reads_as_one_and_rows_are_to_the_second(tmp_path):
    got = _run(tmp_path, ["visibleText", "methodName", "custodyHashChip",
                          "custodyDetailText", "renderCustodyRow"], """
const rows = [
  { action: 'ACQUIRED', occurred_at: 'x', actor_id: 'a', actor_name: 'Demo Analyst',
    hash_verified: true, detail: { acquisition_method: 'MANUAL_UPLOAD', bytes: 1643,
    lock_ends_at: '2027-09-17T03:02:03Z' } },
  { action: 'ACQUIRED', occurred_at: 'y', actor_id: 'a', actor_name: 'Demo Analyst',
    hash_verified: null, detail: { deduplicated: true, acquisition_method: 'LEGAL',
    acquired_at_stated: true, acquired_at: '2026-09-01T09:30:00Z',
    source_segments: [{ text: 'hxxps://evil[.]example', defanged: true }],
    authority_segments: [{ text: 'PO-9', defanged: false }] } },
];
const drawn = rows.map((c) => renderCustodyRow(c));
const copy = find(drawn[0], (n) => n.className === 'copy-btn custody-id');
console.log(JSON.stringify(drawn.map((r) => texts(r)).concat(
  [[copy.value, copy.title, copy.attrs['aria-label']]])));
""", consts=("EV_METHODS",))
    first, again, copy = got
    assert copy == ["a", "Copy the account id a", "Copy the account id of Demo Analyst"], (
        "the id stays copyable beside the name")
    assert "T(x,s)" in first, "to the second"
    assert "via Manual upload, 1643 B, locked in storage until T(2027-09-17T03:02:03Z,s)" in first
    joined = " ".join(again)
    assert joined.count("re-acquired: identical bytes were already held") == 1
    assert "via Legal process" in joined and "obtained T(2026-09-01T09:30:00Z,s)" in joined
    assert "hxxps://evil[.]example" in joined and "PO-9" in joined
    assert "re-acquired" not in " ".join(first)


# ---------------------------------------------------------------------------
# coverage-vanishes-with-metrics
# ---------------------------------------------------------------------------

@needs_node
def test_coverage_is_counted_from_the_canvas_without_metrics(tmp_path):
    got = _run(tmp_path, ["countOf", "agree", "backedCount", "coverageLine"], """
const n = (h) => ({ has_evidence: h });
console.log(JSON.stringify([
  coverageLine([n(true), n(false)], [n(false)], null, false),
  coverageLine([n(false)], [n(false)], null, false),
  coverageLine([n(true)].concat(Array(199).fill(n(false))), [], null, true),
  coverageLine([{}], [], null, false),
  coverageLine([n(true), n(false)], [n(false)], { nodes: 0, edges: 0, elements: 3 }, false),
  coverageLine([], [], null, false),
]));
""")
    plain, none, tiny, unknown, disagree, empty = got
    assert plain["text"] == "evidence: 1 of 3 elements (33%) rest on an exhibit"
    # A chip in the canvas status line (ux03 control-bar-squeezes-canvas).
    assert plain["cls"] == "cs-chip coverage-low"
    assert none["cls"].endswith("coverage-none")
    assert "(<1%)" in tiny["text"] and "truncated" in tiny["title"]
    assert unknown["text"] == "evidence coverage unavailable"
    assert "counted 0 for the same elements" in disagree["title"]
    assert empty["text"] == ""
    assert "state.metrics.evidence_coverage;\n  if (!cov" not in _js()


# ---------------------------------------------------------------------------
# evidence-list-silently-capped
# ---------------------------------------------------------------------------

@needs_node
def test_the_count_line_never_presents_a_page_as_the_whole(tmp_path):
    got = _run(tmp_path, ["visibleText", "countOf", "agree", "registerCountText"], """
const items = (k) => Array(k).fill({});
const view = { q: '', unbacked: false, only: null };
console.log(JSON.stringify([
  registerCountText({ total: 212, matching: 212, offset: 50, backs_nothing: 3,
                      items: items(50) }, view),
  registerCountText({ total: 1, matching: 1, offset: 0, backs_nothing: 1,
                      items: items(1) }, view),
  registerCountText({ total: 212, matching: 0, offset: 0, backs_nothing: 0,
                      items: [] }, { q: 'phone', unbacked: true, only: null }),
  registerCountText({ total: 212, matching: 0, offset: 0, items: [] },
                    { q: '', unbacked: false, only: 'x' }),
  registerCountText({ total: 0, matching: 0, offset: 0, items: [] }, view),
  registerCountText({ total: 212, matching: 3, offset: 0, backs_nothing: 3,
                      items: items(3) }, { q: '', unbacked: true, only: null }),
  registerCountText({ total: 212, matching: 1, offset: 0, backs_nothing: 3,
                      items: items(1) }, { q: 'phone', unbacked: true, only: null }),
]));
""")
    page, single, nothing, missing, empty, idle, both = got
    assert page == ("Showing 51 to 100 of 212 exhibits in the case, most "
                    "recently acquired first. 3 exhibits in the case back "
                    "nothing on the live graph.")
    assert single == ("Showing the one exhibit in the case. 1 exhibit in the "
                      "case backs nothing on the live graph.")
    assert nothing == ('No exhibit matches "phone" and backs nothing. '
                       'The case holds 212 exhibits.')
    assert "not in this case, or is above your clearance" in missing
    assert empty == ""
    assert idle == ("Showing all 3 exhibits that back nothing, of 212 exhibits "
                    "in the case, most recently acquired first.")
    assert both == ('Showing the one exhibit matching "phone" that backs '
                    'nothing, of 212 exhibits in the case.')


@needs_node
def test_the_register_request_asks_for_a_page_and_one_exhibit_wins(tmp_path):
    got = _run(tmp_path, ["evidenceQuery"], """
console.log(JSON.stringify([
  evidenceQuery({ offset: 50, q: 'phone', unbacked: true, only: null }),
  evidenceQuery({ offset: 0, q: 'phone', unbacked: true, only: 'abc' }),
]));
""", consts=("EV_PAGE",))
    assert got[0] == "?limit=50&offset=50&q=phone&backs_nothing=true"
    assert got[1] == "?limit=50&offset=0&evidence_id=abc"


def test_the_pane_and_the_pickers_no_longer_read_the_capped_list():
    code = _code()
    assert "/evidence-list?limit=200" not in code
    load = _fn("loadEvidence")
    assert "cpath('/evidence' + evidenceQuery(evView))" in load
    assert "cpath('/evidence/index')" in load
    assert "state.evidenceTotal" in load
    pickers = _fn("refreshEvidencePickers")
    assert "state.evidenceTotal" in pickers and "not listed" in pickers
    focus = _fn("focusEvidence")
    assert "Reload the evidence tab" not in focus, (
        "the fallback advised a reload that could not reach the exhibit")
    assert "evView.only = evidenceId" in focus
    html = _html()
    for needed in ('id="ev-count"', 'id="ev-q"', 'id="ev-unbacked"',
                   'id="ev-prev"', 'id="ev-next"', 'id="ev-all"'):
        assert needed in html, needed


# ---------------------------------------------------------------------------
# upload-drops-provenance
# ---------------------------------------------------------------------------

def test_the_upload_form_asks_for_provenance():
    html = _html()
    form = html[html.index('<form id="ev-form"'):html.index("</form>",
                                                             html.index('<form id="ev-form"'))]
    assert "Acquired at (UTC)" in form and 'id="ev-acquired" type="datetime-local"' in form
    assert 'id="ev-source"' in form and 'id="ev-desc"' in form
    assert 'id="ev-authority-field"' in form and 'id="ev-authority"' in form
    assert "value === 'LEGAL'" in _fn("syncEvidenceMethod")


_UPLOAD_HARNESS = r"""
const nodes = {};
function $(id) { if (!nodes[id]) nodes[id] = { id, value: '', files: [], hidden: false,
  textContent: '' }; return nodes[id]; }
function setMsg(n, t) { n.textContent = t || ''; n.hidden = !t; }
function fmtBytes(n) { return n + ' B'; }
function caseToken() { return 1; }
function caseChanged() { return false; }
function caseCodeNow() { return 'OP-A'; }
function cpath(p) { return '/cases/a' + p; }
function inlineProblem(n, e) { setMsg(n, String(e)); }
function banner() {}
function failureReason() { return ''; }
async function loadEvidence() {}
const state = { evidencePolicy: null };
let sent = null;
async function api(path, o) { sent = { path, form: Object.fromEntries(o.form.entries()) };
  return { sha256: 'ab', deduplicated: false }; }
"""


@needs_node
def test_the_upload_sends_a_utc_acquisition_time_and_the_authority(tmp_path):
    script = tmp_path / "up.js"
    script.write_text(_UPLOAD_HARNESS + _fn("uploadEvidence") + r"""
(async () => {
  const out = {};
  const fill = (m, a, t) => { $('ev-file').files = [{ size: 1 }]; $('ev-title').value = 'Phone';
    $('ev-method').value = m; $('ev-authority').value = a; $('ev-acquired').value = t;
    $('ev-source').value = ' locker 4 '; $('ev-desc').value = ''; sent = null; };
  fill('LEGAL', '', '');
  await uploadEvidence({ preventDefault() {} });
  out.noAuthority = [sent, $('ev-error').textContent];
  fill('LEGAL', 'PO-2026-114', '2026-09-17T15:18');
  await uploadEvidence({ preventDefault() {} });
  out.legal = sent.form;
  fill('MANUAL_UPLOAD', 'PO-typed-then-changed', '');
  await uploadEvidence({ preventDefault() {} });
  out.manual = sent.form;
  fill('MANUAL_UPLOAD', '', '2999-01-01T00:00');
  await uploadEvidence({ preventDefault() {} });
  out.future = [sent, $('ev-error').textContent];
  console.log(JSON.stringify(out));
})();
""", encoding="utf-8")
    res = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert res.returncode == 0, res.stderr
    got = json.loads(res.stdout)
    assert got["noAuthority"][0] is None and "authority reference" in got["noAuthority"][1]
    legal = got["legal"]
    assert legal["acquired_at"] == "2026-09-17T15:18:00.000Z", "typed as UTC, sent as UTC"
    assert legal["authority_ref"] == "PO-2026-114"
    assert legal["source_url"] == "locker 4" and "description" not in legal
    assert "authority_ref" not in got["manual"] and "acquired_at" not in got["manual"]
    assert got["future"][0] is None and "in the future" in got["future"][1]


# ---------------------------------------------------------------------------
# no-exhibit-export-control
# ---------------------------------------------------------------------------

def test_export_goes_through_the_session_and_the_step_up():
    body = _fn("exportExhibit")
    assert "fetch(API + cpath('/evidence/' + ev.id + '/export')" in body
    assert "method: 'POST'" in body and "authHeaders('POST')" in body
    assert body.index("sessionRefusedRaw(res") < body.index("if (!res.ok)")
    assert "stepUpStale()" in body and "confirmIdentity(" in body
    assert "SESSION.stepUpUntil = 0" in body, "the server's step-up answer is retried once"
    assert "URL.revokeObjectURL" in body
    assert "loadCustody(ev, custodyBox)" in body, "the EXPORTED row shows in an open log"


@needs_node
def test_an_export_refusal_says_which_rule_and_what_to_do(tmp_path):
    got = _run(tmp_path, ["closeClause", "exportRefusalText", "exportFileName"], """
console.log(JSON.stringify([
  exportRefusalText(400, { title: 'Evidence error', detail: 'export refused: RED never leaves.' }),
  exportRefusalText(409, { title: 'Integrity check failed', detail: 'x' }),
  exportRefusalText(409, { title: 'Not served from this origin', detail: 'attacker markup.' }),
  exportRefusalText(403, { title: 'Forbidden', detail: 'missing permission evidence.export on this case' }),
  exportFileName({ title: 'Seized Phone.BIN', sha256: '29c6d46fc71537e0d0bb' }),
  exportFileName({ title: 'no extension', sha256: '29c6d46fc71537e0d0bb' }),
]));
""")
    red, integrity, hostile, role, named, bare = got
    assert red.startswith("Refused, and recorded in the audit log: export refused")
    assert "HASH MISMATCH" in integrity
    assert hostile == "Not exported: attacker markup."
    assert "Lead investigator" in role
    assert named == "exhibit-29c6d46fc71537e0.bin" and bare == "exhibit-29c6d46fc71537e0"


def test_the_routes_the_pane_calls_are_mounted(monkeypatch):
    """The register, the index and the backs list, mounted at the paths
    app.js asks for (`cpath('/evidence' + ...)`, `'/evidence/index'`,
    `'/evidence/' + id + '/backs'`). No database: the schema is read, no
    route is called."""
    monkeypatch.setenv("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@192.0.2.1:5432/x")
    from noctornal_api.http.app import create_app
    paths = create_app().openapi()["paths"]
    base = next(p for p in paths if p.endswith("/cases/{case_id}/evidence"))
    assert {"get", "post"} <= set(paths[base])
    assert "get" in paths[base + "/index"]
    assert "get" in paths[base + "/{evidence_id}/backs"]
    params = {p["name"] for p in paths[base]["get"]["parameters"]}
    assert {"offset", "limit", "q", "backs_nothing", "evidence_id"} <= params


# ---------------------------------------------------------------------------
# x-hostile-export (2026-09-24): attacker markup leaves through the sample
# origin, in two legs, as the Lab's download does
# ---------------------------------------------------------------------------

def test_a_production_is_minted_here_and_spent_at_the_sample_origin():
    body = _fn("produceExhibit")
    mint = body.index("api(cpath('/evidence/' + ev.id")
    cross = body.index("fetchFromSampleOrigin(minted.download_url")
    assert mint < cross, "the ticket is minted before anything crosses"
    assert "'/production-ticket'), { method: 'POST' })" in body, (
        "minted through api() with POST, so the CSRF double-submit applies")
    assert "withStepUp(" in body, "a stale sign-in is asked for, not refused"
    leg = body[cross:body.index("if (!res.ok)", cross)]
    assert "body: new URLSearchParams({ ticket: minted.ticket })" in leg
    assert "credentials: 'omit'" in leg
    for banned in ("headers", "authHeaders(", "Authorization", "state.token",
                   "fetch(API"):
        assert banned not in leg, (
            f"the cross-origin production sends {banned!r}: a header makes it "
            f"a preflighted request, and no session may reach that origin")
    assert "ticket=" not in body, "a ticket in a URL is a credential in every log"
    assert "URL.revokeObjectURL" in body
    assert "loadCustody(ev, custodyBox)" in body, "the EXPORTED row shows in an open log"
    assert "exportRefusalText(res.status, p)" in body, "the origin's own sentence"


@needs_node
def test_the_produced_archive_is_named_for_the_digest_never_the_title(tmp_path):
    got = _run(tmp_path, ["productionFileName"], """
console.log(JSON.stringify([
  productionFileName({ title: 'lure.html', sha256: '29c6d46fc71537e0d0bb' }),
  productionFileName({ title: 'x.eml', sha256: null, id: 'cfdcb38d99504' }),
]));
""")
    assert got == ["exhibit-29c6d46fc71537e0.zip", "exhibit-cfdcb38d99504.zip"]


@needs_node
def test_custody_says_how_an_exhibit_left_and_what_a_lock_extension_moved(tmp_path):
    got = _run(tmp_path, ["methodName", "custodyDetailText"], """
console.log(JSON.stringify([
  custodyDetailText('EXPORTED', { via: 'sample_origin', archive_format: 'ZIP_INFECTED' }),
  custodyDetailText('EXPORTED', {}),
  custodyDetailText('LOCK_EXTENDED', { lock_ends_at: '2029-03-01T00:00:00+00:00',
    previous_lock_ends_at: '2027-01-10T03:02:03+00:00',
    case_retention_until: '2029-03-01' }),
  custodyDetailText('LOCK_EXTENDED', { lock_ends_at: '2036-09-22T10:00:00+00:00',
    case_retention_until: '2208-01-01', capped_at_horizon: true }),
]));
""", consts=("EV_METHODS",))
    produced, plain, extended, capped = got
    assert produced == "produced through the sample origin, in a password-protected archive"
    assert plain == ""
    assert extended == ("locked in storage until T(2029-03-01T00:00:00+00:00,s), "
                        "was until T(2027-01-10T03:02:03+00:00,s), to meet the "
                        "case's retention date D(2029-03-01)")
    # Stopped by the horizon short of the date: the row does not claim it
    # met it (x-lock-extension, verifier, 2026-09-24).
    assert capped == ("locked in storage until T(2036-09-22T10:00:00+00:00,s), "
                      "toward the case's retention date D(2208-01-01), as far "
                      "as one step sets it")


def test_the_custody_detail_lets_the_new_keys_through():
    from noctornal_api.http.routers.evidence import custody_detail
    out = custody_detail({"via": "sample_origin", "ticket_id": "t", "origin": "o",
                          "archive_format": "ZIP_INFECTED",
                          "previous_lock_ends_at": "a", "case_retention_until": "b",
                          "capped_at_horizon": True})
    assert out == {"via": "sample_origin", "archive_format": "ZIP_INFECTED",
                   "previous_lock_ends_at": "a", "case_retention_until": "b",
                   "capped_at_horizon": True}


# ---------------------------------------------------------------------------
# x-lock-extension (2026-09-24): the case record says what the locks did
# ---------------------------------------------------------------------------

@needs_node
def test_saving_a_later_retention_date_says_what_the_locks_did(tmp_path):
    got = _run(tmp_path, ["countOf", "agree", "lockExtensionWords"], """
const at = '2029-03-01T00:00:00+00:00';
console.log(JSON.stringify([
  lockExtensionWords(null),
  lockExtensionWords({ exhibits: 0, extended: 0, failed: 0, lock_ends_at: at }),
  lockExtensionWords({ exhibits: 3, extended: 0, failed: 0, already_held: 3,
                       lock_ends_at: at }),
  lockExtensionWords({ exhibits: 2, extended: 1, failed: 0, lock_ends_at: at }),
  lockExtensionWords({ exhibits: 3, extended: 2, failed: 1, lock_ends_at: at }),
  lockExtensionWords({ exhibits: 2, extended: 0, failed: 0, date_passed: true,
                       lock_ends_at: at }),
  lockExtensionWords({ exhibits: 2, extended: 2, failed: 0, capped: true,
                       lock_ends_at: at }),
]));
""")
    none, empty, held, one, mixed, passed, capped = got
    assert none is None and empty is None and held is None and passed is None
    assert one == ["The storage lock on 1 exhibit now holds until "
                   "T(2029-03-01T00:00:00+00:00,s).", False]
    assert mixed[1] is True
    assert "on 2 exhibits now holds" in mixed[0]
    assert "on 1 exhibit could not be lengthened" in mixed[0]
    assert "audit log names each" in mixed[0]
    # A failure is retried from the Evidence pane, which counts a lock
    # short of the case; the record refuses an unchanged date (verifier,
    # 2026-09-24).
    assert "the Evidence pane offers to lengthen those locks again" in mixed[0]
    assert "until the date is extended again" not in mixed[0]
    assert "as far ahead as this deployment sets a lock in one step" in capped[0]
    assert capped[1] is False
    body = _fn("saveCaseRecord")
    assert "lockExtensionWords(out.lock_extension)" in body
    assert "delete out.lock_extension" in body, "the record is applied without it"


@needs_node
def test_a_later_retention_date_is_confirmed_with_the_year_spelled_out(tmp_path):
    """x-lock-extension, verifier, 2026-09-24. Extending the date lengthens
    a storage lock nobody can shorten, and one person typing 2208 for 2028
    made that commitment with no question asked, while raising the
    classification asks one. The question names the date and says it
    cannot be taken back, and saveCaseRecord asks it before the PATCH."""
    [q] = _run(tmp_path, ["retentionLockQuestion"], """
console.log(JSON.stringify([retentionLockQuestion('OP-NIGHTJAR-26', '2208-12-31')]));
""")
    assert q.startswith("Extend the retention of OP-NIGHTJAR-26 to D(2208-12-31)?")
    assert "00:00 UTC" in q and "Nobody can shorten" in q
    assert "not an administrator, and not the dual-control purge" in q
    assert "Check the year" in q
    body = _fn("saveCaseRecord")
    ask = body.index("retentionLockQuestion(rec.code, body.retention_until)")
    assert "window.confirm(" in body[ask - 80:ask], "asked as a confirmation"
    assert ask < body.index("api('/cases/'"), "asked before anything is saved"
    help_text = re.sub(r"\s+", " ", _html())
    assert ("Extending it also lengthens the storage lock on the case's exhibits, "
            "which nobody can shorten afterwards, so check the year.") in help_text


# ---------------------------------------------------------------------------
# x-lock-extension, verifier (2026-09-24): locks short of the case are
# counted, said, and can be lengthened from the pane
# ---------------------------------------------------------------------------

@needs_node
def test_the_pane_says_how_many_locks_fall_short_and_offers_the_control(tmp_path):
    got = _run(tmp_path, ["countOf", "agree", "shortLocksText",
                          "lengthenLocksQuestion", "renderShortLocks"], """
const nodes = { 'ev-locks': mk('div'), 'ev-locks-text': mk('p'),
                'ev-locks-go': mk('button') };
function $(id) { return nodes[id]; }
function setMsg(n, t) { n.textContent = t || ''; n.hidden = !t; }
function show(n, on) { n.hidden = !on; }
const at = '2028-12-31T00:00:00+00:00';
const out = [];
for (const page of [
  { locks_short: 0, may_lock: true, lock_target: null },
  { locks_short: 1, may_lock: true, lock_target: at },
  { locks_short: 3, may_lock: false, lock_target: at },
]) {
  renderShortLocks(page);
  out.push([nodes['ev-locks'].hidden, nodes['ev-locks-text'].textContent,
            nodes['ev-locks-go'].hidden]);
}
out.push(lengthenLocksQuestion({ locks_short: 3, lock_target: at }));
console.log(JSON.stringify(out));
""")
    none, one, three, question = got
    assert none == [True, "", True], "nothing short: nothing said, no control"
    assert one == [False, "1 exhibit in the case is held by the store for less "
                   "time than the case is retained, so a delete would be "
                   "accepted before the retention date.", False]
    assert three[0] is False and three[1].startswith("3 exhibits in the case are held")
    assert three[2] is True, "the control only for a holder of case.update"
    assert question.startswith("Lengthen the storage lock on 3 exhibits to "
                               "T(2028-12-31T00:00:00+00:00,s)?")
    assert "Nobody can shorten a storage lock" in question
    # Wired: the register draws it, the button posts to the route after the
    # confirmation, and the result is said and the register read again.
    assert "renderShortLocks(page)" in _fn("renderEvidence")
    assert "$('ev-locks-go').addEventListener('click', lengthenLocks)" in _fn(
        "wireEvidencePane")
    body = _fn("lengthenLocks")
    assert "window.confirm(lengthenLocksQuestion(page))" in body
    assert body.index("window.confirm(") < body.index("api(cpath('/evidence/locks')")
    assert "{ method: 'POST' }" in body and "lockExtensionWords(out)" in body
    assert "loadEvidence({ pageOnly: true })" in body
    html = _html()
    section = html[html.index('id="ev-count"'):html.index('id="ev-list"')]
    assert 'id="ev-locks"' in section and 'id="ev-locks-go"' in section
    assert 'id="ev-locks-msg"' in section


# ---------------------------------------------------------------------------
# x-inspector-chips (2026-09-24): the inspector's exhibit list states the
# lock and the digest the way the card does
# ---------------------------------------------------------------------------

@needs_node
def test_the_inspector_list_draws_the_cards_lock_chip_and_whole_digest(tmp_path):
    ev = {"id": _EXHIBIT["id"], "title": "invoice\u202egpj.exe",
          "classification": "AMBER", "media_type": "message/rfc822",
          "byte_size": 1643, "sha256": _EXHIBIT["sha256"],
          "is_worm_locked": True, "lock_until": "2027-09-17",
          "lock_ends_at": "2027-09-17T03:02:03Z", "lock_lapsed": True,
          "legal_hold": True, "is_hostile_markup": True, "purged_at": None,
          "purged": False, "counts": True, "backing": []}
    got = _run(tmp_path, ["visibleText", "lockChip", "exhibitIdLine",
                          "renderLinkedEvidence"], """
var state = { selection: null };
const box = mk('div');
renderLinkedEvidence(box, [%s]);
const item = box.children[0];
const chips = [];
(function walk(n) { if (/\\bchip\\b/.test(n.className || '')) chips.push([n.className, n.textContent]);
  for (const c of n.children || []) walk(c); })(item);
const copies = [];
(function walk(n) { if (n.copies) copies.push([n.copies, n.what]);
  for (const c of n.children || []) walk(c); })(item);
console.log(JSON.stringify({ said: texts(item), chips, copies }));
""" % json.dumps(ev))
    chips = [c[1] for c in got["chips"]]
    assert "WORM lock ended D(2027-09-17)" in chips, "the card's chip, not a bare WORM"
    assert "WORM" not in chips
    assert "LEGAL HOLD" in chips and "attacker markup" in chips
    assert [ev["sha256"], "the SHA-256 digest"] in got["copies"], (
        "the whole digest, copyable, not sixteen hex in a tooltip")
    assert ev["sha256"] in got["said"]
    assert not any("\u202e" in t for t in got["said"]), "the title is de-fanged"
    linked = _fn("renderLinkedEvidence")
    assert "lockChip(ev)" in linked and "exhibitIdLine('SHA-256'" in linked
    assert "shortHash(" not in linked


# ---------------------------------------------------------------------------
# The rules every pane holds
# ---------------------------------------------------------------------------

def test_the_new_evidence_code_writes_no_inline_style():
    for name in ("exhibitCard", "backsLine", "backedButton", "renderEvidence",
                 "exportExhibit", "coverageLine", "renderCustodyRow",
                 "produceExhibit", "renderLinkedEvidence", "lockExtensionWords",
                 "renderShortLocks", "lengthenLocks", "shortLocksText",
                 "retentionLockQuestion", "lengthenLocksQuestion"):
        body = _fn(name)
        assert ".style" not in body and "innerHTML" not in body, name

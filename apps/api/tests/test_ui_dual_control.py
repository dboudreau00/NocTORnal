"""Administration, Two-person controls and the case's merge switch, as the
console ships them (F9, F9b, 2026-09-24).

Pure: no database. The markup and constants are read from the shipped
source, beside test_ui_invariants.py; the functions marked `needs_node`
run under Node over a stub DOM and are judged by what they draw. The
server halves are test_dual_control_policy_pg.py,
test_dual_control_http_pg.py and test_case_merge_relax_pg.py.

The rule every card here is held to: nobody sees a button the server would
refuse them, and the person best placed to say no always can (a
countersigner the seven-day rule blocks still sees Refuse).
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from test_ui_copy_no_dashes import NODE, _html, _js

needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")


def _fn(name: str) -> str:
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone; update this test with it"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _const(name: str) -> str:
    js = _js()
    m = re.search(rf"(?m)^const {re.escape(name)} = ", js)
    assert m, f"const {name} is gone"
    line = js[m.start():js.index("\n", m.start())]
    if line.rstrip().endswith(";") and line.count("{") == line.count("}"):
        return line + "\n"
    close = js.index("\n}", m.start()) + 1
    return js[m.start():js.index("\n", close) + 1]


def _block(html: str, start_marker: str, end_marker: str) -> str:
    start = html.index(start_marker)
    return html[start:html.index(end_marker, start)]


def _dual_markup() -> str:
    return _block(_html(), '<div id="adm-dual"', '</section>')


def _policy_markup() -> str:
    return _block(_html(), '<div id="apr-policy"', '<div class="pane-head">')


_STUBS = r"""
function mk(tag, cls, text) {
  return { tag: tag, className: cls || '',
           textContent: text === undefined || text === null ? '' : String(text),
           title: '', value: '', hidden: false, disabled: false, type: '',
           id: '', children: [], dataset: {}, listeners: {}, attrs: {},
           classList: { _s: new Set(), add(c) { this._s.add(c); },
                        contains(c) { return this._s.has(c); } },
           appendChild(c) { this.children.push(c); return c; },
           append(...cs) { for (const c of cs) this.children.push(c); },
           setAttribute(k, v) { this.attrs[k] = v; },
           addEventListener(t, fn) { this.listeners[t] = fn; },
           focus() {} };
}
const el = mk;
const boxes = {};
function $(id) { return boxes[id] || (boxes[id] = mk('div')); }
function clear(n) { n.children = []; }
function show(n, on) { n.hidden = !on; }
function text(n) {
  return (n.textContent || '') + (n.children || []).map(text).join(' ');
}
function buttons(n) {
  const out = [];
  (function walk(x) {
    if (x.tag === 'button' && !x.hidden) out.push(x.textContent);
    (x.children || []).forEach(walk);
  })(n);
  return out;
}
function fact(k, v) { return mk('span', 'fact', k + ': ' + v); }
function fmtTime(x) { return 'T(' + x + ')'; }
function shortId(id) { return id ? String(id).slice(0, 8) : 'unknown'; }
function visibleText(s) { return s === null || s === undefined ? '' : String(s); }
function asSentence(t) { t = String(t || '').trim(); if (!t) return '';
  t = t.charAt(0).toUpperCase() + t.slice(1); return /[.!?]$/.test(t) ? t : t + '.'; }
function countOf(n, one, many) { return n + ' ' + (Number(n) === 1 ? one : many); }
function decideDualChange() {}
function applyDualChange() {}
function withdrawDualChange() {}
"""


def _run(sources: list[str], body: str, tmp_path: Path):
    script = tmp_path / "run.js"
    script.write_text(_STUBS + "\n".join(sources) + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# ---------------------------------------------------------------------------
# The markup
# ---------------------------------------------------------------------------

def test_the_dual_subtab_follows_compartments_and_controls_its_pane():
    html = _html()
    pane = _block(html, '<section id="pane-admin"', '<section id="pane-samples"')
    tabs = re.findall(r'data-subtab="(\w+)"', pane)
    assert tabs[tabs.index("compartments") + 1] == "dual", tabs
    tab = re.search(r'<button[^>]*data-subtab="dual"[^>]*>', pane).group(0)
    assert 'aria-controls="adm-dual"' in tab and 'role="tab"' in tab
    for ident in ("adm-dual-badge", "adm-dual", "dual-body", "dual-changes",
                  "dual-changes-empty", "dual-ops", "dual-pairs",
                  "dual-pair-form", "dual-pair-a", "dual-pair-b",
                  "dual-pair-why", "dual-pair-just", "dual-history",
                  "dual-history-empty", "dual-refused", "dual-signin",
                  "dual-say", "dual-other"):
        assert html.count(f'id="{ident}"') == 1, ident


@pytest.mark.parametrize("markup", [_dual_markup, _policy_markup],
                         ids=["two-person-controls", "merge-switch"])
def test_the_new_markup_carries_no_inline_style_or_handler(markup):
    block = markup()
    assert not re.search(r"\sstyle\s*=", block, re.I)
    assert not re.search(r"\son[a-z]+\s*=", block, re.I)
    assert "<script" not in block.lower()


def test_the_merge_switch_sits_above_the_approvals_it_produces():
    html = _html()
    for ident in ("apr-policy", "apr-policy-text", "apr-policy-btn",
                  "apr-policy-relax", "apr-policy-just", "apr-policy-send",
                  "apr-policy-msg"):
        assert html.count(f'id="{ident}"') == 1, ident
    assert html.index('id="apr-policy"') < html.index('id="apr-list"')


def test_the_help_warns_that_a_security_officer_reads_the_justification():
    visible = " ".join(re.sub(r"<!--.*?-->", "", _dual_markup(), flags=re.S).split())
    assert "Keep case details out of a justification" in visible
    assert "will stop at upgrade until the pair is removed here" in visible


# ---------------------------------------------------------------------------
# The constants agree with the server
# ---------------------------------------------------------------------------

def test_the_console_names_the_operations_the_server_does():
    from noctornal_api.approvals import MODES, OPERATIONS
    op = re.search(r"const DUAL_POLICY_OPERATION = '([^']+)'", _js()).group(1)
    assert op == "dual_control.policy" and op in OPERATIONS
    relax = re.search(r"const RELAX_OPERATION = '([^']+)'", _js()).group(1)
    assert relax == "case.policy.relax" and relax in OPERATIONS
    words = re.search(r"const DUAL_MODE_WORDS = \{([^}]*)\}", _js()).group(1)
    assert set(re.findall(r"(\w+):", words)) == set(MODES)


def test_the_admin_tab_caption_names_two_person_controls():
    assert "['admin', 'Admin', 'accounts, roles, readiness, two-person controls']" \
        in _js()


# ---------------------------------------------------------------------------
# A change card draws only the buttons its viewer may press
# ---------------------------------------------------------------------------

_CARD = r"""
const you = { user_id: 'admin-1', may_propose: true };
const officer = { user_id: 'officer-1', may_propose: false };
const base = { id: 'r1', operation: 'dual_control.policy', requested_by: 'admin-1',
  requested_by_name: 'Ada', requested_at: 'a', expires_at: 'b',
  justification: 'standing orders', state: 'PENDING', is_expired: false,
  preview: { effect: 'Every merge on this deployment will need a second signature.' },
  countersign: null, stale: false };
const card = (req, who) => { const c = dualChangeCard(Object.assign({}, base, req), who);
                             return { buttons: buttons(c), text: text(c) }; };
console.log(JSON.stringify({
  requester: card({}, you),
  other_admin: card({}, { user_id: 'admin-2', may_propose: true }),
  signer: card({ countersign: { allowed: true, may_refuse: true } }, officer),
  blocked: card({ countersign: { allowed: false, may_refuse: true,
    reason: 'You may countersign this from 2026-10-01 09:00 UTC: Bob reset your password on 2026-09-24 09:00 UTC.' } },
    officer),
  approved: card({ state: 'APPROVED', decided_by: 'officer-1', decided_at: 'c',
                   decided_by_name: 'Olu' }, you),
  stale: card({ state: 'APPROVED', decided_by: 'officer-1', decided_at: 'c',
                stale: true }, you),
  expired: card({ is_expired: true }, you),
  officer_sees_approved: card({ state: 'APPROVED', decided_by: 'officer-1',
                                decided_at: 'c' }, officer),
}));
"""


@needs_node
def test_a_change_card_draws_only_what_its_viewer_may_do(tmp_path):
    got = _run([_const("DUAL_STATE_WORDS"), "const DUAL = { notes: new Map() };",
                _fn("dualChangeCard")], _CARD, tmp_path)
    assert got["requester"]["buttons"] == ["Withdraw"]
    assert got["other_admin"]["buttons"] == []
    assert "Waiting for a Security officer" in got["other_admin"]["text"]
    assert got["signer"]["buttons"] == ["Countersign", "Refuse"]
    # The officer best placed to say no can: Refuse, never Countersign.
    assert got["blocked"]["buttons"] == ["Refuse"]
    assert "You may countersign this from" in got["blocked"]["text"]
    assert got["approved"]["buttons"] == ["Apply"]
    assert got["stale"]["buttons"] == []
    assert "No longer applicable" in got["stale"]["text"]
    assert got["expired"]["buttons"] == []
    assert "Expired" in got["expired"]["text"]
    assert got["officer_sees_approved"]["buttons"] == []
    assert "its proposer applies it" in got["officer_sees_approved"]["text"]


@needs_node
def test_an_operation_card_offers_a_change_only_to_a_proposer(tmp_path):
    got = _run([_const("DUAL_MODE_WORDS"), _fn("dualRoleNames"),
                _fn("dualDuration"), _fn("dualOperationCard"),
                "function proposeDualChange() {}"], r"""
const merge = { key: 'node.merge', description: 'Fold one entity into another',
  scope: 'case', mode: 'PER_CASE', modes: ['PER_CASE', 'ALWAYS'],
  configurable: true, enforced: true, not_enforced_because: '',
  ttl_seconds: 28800, asks: { permission: 'graph.merge', roles: [
    { key: 'ANALYST', display_name: 'Analyst' }] },
  signs: { permission: 'graph.merge', roles: [] }, cases_requiring: 3 };
const purge = { key: 'case.delete', description: 'Delete a case', scope: 'case',
  mode: 'ALWAYS', modes: ['ALWAYS'], configurable: false, enforced: false,
  not_enforced_because: 'Marking a case PURGED takes one signature today.',
  ttl_seconds: 1800, asks: { permission: 'case.delete', roles: [] },
  signs: { permission: 'case.delete', roles: [] } };
const none = Object.assign({}, merge, { cases_requiring: null });
const draw = (op, you) => { const c = dualOperationCard(op, you);
                            return { buttons: buttons(c), text: text(c) }; };
console.log(JSON.stringify({
  admin: draw(merge, { may_propose: true }),
  officer: draw(merge, { may_propose: false }),
  fixed: draw(purge, { may_propose: true }),
  nocases: draw(none, { may_propose: true }),
}));
""", tmp_path)
    assert got["admin"]["buttons"] == ["Propose change"]
    assert "3 of the cases you are assigned to ask for it today." in got["admin"]["text"]
    assert "8 hours" in got["admin"]["text"]
    assert got["officer"]["buttons"] == []
    assert got["fixed"]["buttons"] == []
    assert "Not enforced yet" in got["fixed"]["text"]
    assert "Every time" not in got["fixed"]["text"], (
        "a mode chip beside Not enforced yet contradicts it")
    assert "Where the case asks for it" in got["admin"]["text"]
    assert "30 minutes" in got["fixed"]["text"]
    assert "cases you are assigned to" not in got["nocases"]["text"]


@needs_node
def test_a_pair_row_offers_removal_only_for_a_pair_the_screen_added(tmp_path):
    got = _run([_fn("dualRoleNames"), _fn("dualPairRow"),
                "function proposeDualChange() {}"], r"""
const fixed = { permission_a: 'victim_pii.authorise', permission_b: 'victim_pii.reveal',
  why: 'docs/17 F16', origin: 'migration', a_roles: [], b_roles: [] };
const added = { permission_a: 'a.x', permission_b: 'b.y', why: 'held apart',
  origin: 'policy', added_at: 'now', proposer_name: 'Ada',
  countersigner_name: 'Olu', a_roles: [], b_roles: [] };
const draw = (p, you) => { const c = dualPairRow(p, you);
                           return { buttons: buttons(c), text: text(c) }; };
console.log(JSON.stringify({
  fixed: draw(fixed, { may_propose: true }),
  added: draw(added, { may_propose: true }),
  officer: draw(added, { may_propose: false }),
}));
""", tmp_path)
    assert got["fixed"]["buttons"] == [] and "Fixed" in got["fixed"]["text"]
    assert got["added"]["buttons"] == ["Propose removal"]
    assert "countersigned by: Olu" in got["added"]["text"]
    assert got["officer"]["buttons"] == []


# ---------------------------------------------------------------------------
# The way in: notifications, the Oversight view and the entry button
# ---------------------------------------------------------------------------

@needs_node
def test_a_caseless_approval_request_opens_the_change(tmp_path):
    got = _run([_fn("notificationRoute")], r"""
console.log(JSON.stringify({
  global: notificationRoute({ object_type: 'approval_request', object_id: 'r1',
                              case_id: null }),
  cased: notificationRoute({ object_type: 'approval_request', object_id: 'r2',
                             case_id: 'c1' }),
}));
""", tmp_path)
    assert got["global"] == {"label": "Open the change", "oversight": True,
                             "dual": "r1"}
    assert got["cased"]["tab"] == "triage"


@needs_node
def test_a_countersign_only_account_reads_oversight(tmp_path):
    got = _run([_fn("adminViewName"), _fn("adminViewTitle")], r"""
let canAdmin = false, canReview = false, canCountersign = true;
let canConfirmAuthority = false;  // the authority review reads it too (2026-09-24)
const officer = [adminViewName(), adminViewTitle()];
canAdmin = true;
const admin = adminViewName();
canAdmin = false; canCountersign = false;
const nobody = adminViewName();
console.log(JSON.stringify({ officer, admin, nobody }));
""", tmp_path)
    assert got["officer"][0] == "Oversight"
    assert "two-person changes waiting for a countersignature" in got["officer"][1]
    assert got["admin"] == "Administration"
    assert got["nobody"] == "Administration"


def test_show_admin_mounts_the_officer_section_and_leave_admin_returns_it():
    show_admin = _fn("showAdmin")
    assert "showDualReview(canCountersign && !canAdmin)" in show_admin
    assert show_admin.index("showPreservedReview(") < show_admin.index(
        "showDualReview(")
    assert "returnDualBody()" in _fn("leaveAdmin")
    assert "canCountersign" in _fn("refreshAdminEntry")
    assert "canCountersign" in _fn("buildPaletteItems")
    load = _fn("loadAdminAccess")
    for key in ("dual_control_manage", "dual_control_countersign",
                "dual_control_awaiting"):
        assert key in load, key


@needs_node
def test_the_officer_section_moves_the_body_and_back(tmp_path):
    got = _run([_fn("showDualReview"), _fn("returnDualBody"),
                "let dualReview = null; let dualHome = null;"], r"""
let loads = 0;
function loadDualControl() { loads += 1; }
const home = mk('div', 'subpane');
const body = mk('div');
function moveTo(parent, node) {
  for (const p of [home, dualReview, boxes['view-admin']]) {
    if (p) p.children = p.children.filter((c) => c !== node);
  }
  parent.children.push(node);
  node.parentNode = parent;
}
home.children.push(body); body.parentNode = home; body.nextSibling = null;
home.insertBefore = (node) => moveTo(home, node);
boxes['dual-body'] = body;
const view = $('view-admin');
view.appendChild = (node) => { moveTo(view, node);
  if (!node.appendChild.patched) {
    node.appendChild = (c) => moveTo(node, c); node.appendChild.patched = true; }
  return node; };
showDualReview(true);
const inReview = body.parentNode === dualReview && !dualReview.hidden;
view.children.push(mk('section', 'glass'));   // another section appended after
showDualReview(true);
const last = view.children[view.children.length - 1] === dualReview;
showDualReview(false);
console.log(JSON.stringify({ inReview, last, home: body.parentNode === home,
                             hidden: dualReview.hidden, loads,
                             label: dualReview.attrs['aria-label'] }));
""", tmp_path)
    assert got == {"inReview": True, "last": True, "home": True, "hidden": True,
                   "loads": 2, "label": "Two-person changes"}


# ---------------------------------------------------------------------------
# The case's merge switch
# ---------------------------------------------------------------------------

_POLICY = r"""
let may = true;
const state = { caseRec: {} };
function caseCan(rec, perm) { return perm === 'case.update' && may; }
const draw = (p) => { paintCasePolicy(p);
  return { text: $('apr-policy-text').textContent,
           button: $('apr-policy-btn').hidden ? null : $('apr-policy-btn').textContent,
           action: $('apr-policy-btn').dataset.action }; };
const out = {};
out.always = draw({ dual_control_merge_mode: 'ALWAYS', dual_control_merge: true,
                    relax_signers: 2 });
out.on = draw({ dual_control_merge_mode: 'PER_CASE', dual_control_merge: true,
                relax_signers: 1 });
out.alone = draw({ dual_control_merge_mode: 'PER_CASE', dual_control_merge: true,
                   relax_signers: 0 });
out.off = draw({ dual_control_merge_mode: 'PER_CASE', dual_control_merge: false,
                 relax_signers: 0 });
may = false;
out.reader_on = draw({ dual_control_merge_mode: 'PER_CASE', dual_control_merge: true,
                       relax_signers: 1 });
out.reader_off = draw({ dual_control_merge_mode: 'PER_CASE', dual_control_merge: false,
                        relax_signers: 1 });
console.log(JSON.stringify(out));
"""


@needs_node
def test_the_merge_switch_draws_three_states_and_only_buttons_that_work(tmp_path):
    got = _run([_fn("paintCasePolicy")], _POLICY, tmp_path)
    assert got["always"]["button"] is None
    assert "a case cannot turn it off" in got["always"]["text"]
    assert got["on"] == {"text": "Merges in this case need a second signature.",
                         "button": "Stop requiring it", "action": "relax"}
    assert got["alone"]["button"] is None
    assert "name a deputy first" in got["alone"]["text"]
    assert got["off"] == {"text": "Merges in this case take one signature.",
                          "button": "Require a second signature",
                          "action": "require"}
    assert got["reader_on"]["button"] is None
    assert got["reader_off"]["button"] is None
    assert "name a deputy" not in got["reader_on"]["text"]


def test_a_relax_approval_is_spent_from_its_own_row_as_governance():
    row = _fn("approvalRow")
    assert "a.operation === RELAX_OPERATION && mine" in row
    assert "Stop requiring it now" in row
    relax = row[row.index("RELAX_OPERATION && mine"):]
    assert "case-write" not in relax[:relax.index("return card")]
    assert "approval_request_id: a.id" in _fn("applyRelaxApproval")
    assert "epoch: casePolicy.dual_control_merge_epoch" in _fn("raiseRelaxRequest")
    assert "err.detail" in _fn("runMerge")


def test_the_closed_case_register_lists_the_switch_as_governance():
    from test_closed_case_read_only import CONSOLE_GOVERNANCE
    for name in ("setCaseMergePolicy", "raiseRelaxRequest", "applyRelaxApproval"):
        assert name in CONSOLE_GOVERNANCE, name

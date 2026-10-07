"""The console half of the seasoning rule on a case's merge switch (F39,
2026-10-02): what the switch says while nobody qualifies yet, what an
unseasoned colleague is told before they press Approve, and what the
Two-person controls screen shows for the operation.

Pure: no database. The functions run under Node over the stub DOM of
test_ui_dual_control.py and are judged by what they draw. The server half,
which decides, is test_relax_seasoning_pg.py. The rule every card is held
to is the one that file's header states: nobody sees a button the server
would refuse them, and the person best placed to say no always can.
"""
from __future__ import annotations

import pytest

from test_ui_dual_control import _STUBS, _const, _fn, _run, needs_node  # noqa: F401
from test_ui_copy_no_dashes import _js

_POLICY_STATE = r"""
let may = true;
const state = { caseRec: {} };
function caseCan(rec, perm) { return perm === 'case.update' && may; }
const draw = (p) => { paintCasePolicy(p);
  return { text: $('apr-policy-text').textContent,
           button: $('apr-policy-btn').hidden ? null : $('apr-policy-btn').textContent };
};
"""


@needs_node
def test_the_switch_says_when_the_first_colleague_qualifies(tmp_path):
    got = _run([_fn("paintCasePolicy")], _POLICY_STATE + r"""
const base = { dual_control_merge_mode: 'PER_CASE', dual_control_merge: true,
               relax_signers: 0 };
const out = {};
out.waiting = draw(Object.assign({}, base, {
  relax_seasoning_days: 7, relax_next_eligible: '2026-10-09T01:49:00Z' }));
out.one_day = draw(Object.assign({}, base, {
  relax_seasoning_days: 1, relax_next_eligible: '2026-10-09T01:49:00Z' }));
out.alone = draw(Object.assign({}, base, {
  relax_seasoning_days: 7, relax_next_eligible: null }));
out.old_server = draw(base);
out.counted = draw(Object.assign({}, base, {
  relax_signers: 1, relax_seasoning_days: 7, relax_next_eligible: null }));
may = false;
out.reader = draw(Object.assign({}, base, {
  relax_seasoning_days: 7, relax_next_eligible: '2026-10-09T01:49:00Z' }));
console.log(JSON.stringify(out));
""", tmp_path)
    assert got["waiting"]["button"] is None, (
        "nobody qualifies yet, so a request would only lapse in 24 hours")
    assert got["waiting"]["text"] == (
        "Merges in this case need a second signature. Nobody else on this "
        "case can approve turning that off yet: the second person must have "
        "held case.update on the case for 7 days, and the first colleague "
        "who does is eligible from T(2026-10-09T01:49:00Z).")
    assert "for 1 day," in got["one_day"]["text"]
    assert got["alone"]["button"] is None
    assert got["alone"]["text"].endswith("name a deputy first.")
    assert "yet" not in got["alone"]["text"]
    assert got["old_server"]["text"].endswith("name a deputy first.")
    assert got["counted"] == {"text": "Merges in this case need a second signature.",
                              "button": "Stop requiring it"}
    assert "eligible" not in got["reader"]["text"]


@needs_node
def test_an_unseasoned_colleague_sees_why_and_can_still_reject(tmp_path):
    got = _run([_const("MERGE_OPERATION"), _fn("approvalActions")], r"""
const draw = (a, mine) => {
  const c = approvalActions(a, 'Stop requiring a second signature', 'Ada', mine);
  const found = {};
  (function walk(x) {
    if (x.tag === 'button') found[x.textContent] = { disabled: x.disabled,
                                                   title: x.title };
    (x.children || []).forEach(walk);
  })(c);
  return found;
};
const reason = 'You may approve this from 2026-10-10 01:49 UTC: you were given '
  + 'the role Lead investigator on this case on 2026-10-03 01:49 UTC.';
console.log(JSON.stringify({
  blocked: draw({ operation: 'case.policy.relax',
                  signer_block: { reason: reason } }, false),
  free: draw({ operation: 'case.policy.relax', signer_block: null }, false),
  mine: draw({ operation: 'case.policy.relax',
               signer_block: { reason: reason } }, true),
}));
""", tmp_path)
    assert got["blocked"]["Approve"]["disabled"] is True
    assert got["blocked"]["Approve"]["title"].startswith(
        "You may approve this from 2026-10-10 01:49 UTC")
    assert got["blocked"]["Reject"]["disabled"] is False, (
        "a refusal is the safe direction and is never blocked")
    assert got["free"]["Approve"]["disabled"] is False
    assert got["free"]["Reject"]["disabled"] is False
    assert "Approve" not in got["mine"] and "Withdraw" in got["mine"]


def test_the_row_says_the_rule_above_the_buttons_and_only_to_the_colleague():
    row = _fn("approvalRow")
    said = row.index("a.signer_block && !mine")
    assert "visibleText(a.signer_block.reason)" in row
    assert said < row.index("approvalActions(a, title, asker, mine)")
    assert "innerHTML" not in row


@needs_node
def test_the_two_person_screen_shows_the_window_and_a_setting_it_could_not_use(
        tmp_path):
    got = _run([_const("DUAL_MODE_WORDS"), _fn("dualRoleNames"),
                _fn("dualDuration"), _fn("dualOperationCard"),
                "function proposeDualChange() {}"], r"""
const relax = { key: 'case.policy.relax',
  description: "Stop requiring a second signature on a case's merges",
  scope: 'case', mode: 'ALWAYS', modes: ['ALWAYS'], configurable: false,
  enforced: true, not_enforced_because: '', ttl_seconds: 86400,
  asks: { permission: 'case.update', roles: [
    { key: 'CASE_OWNER', display_name: 'Lead investigator' }] },
  signs: { permission: 'case.update', roles: [
    { key: 'CASE_OWNER', display_name: 'Lead investigator' }] } };
const draw = (seasoning) => text(dualOperationCard(
  Object.assign({}, relax, seasoning === undefined ? {} :
    { signer_seasoning: seasoning }), { may_propose: true }));
console.log(JSON.stringify({
  seven: draw({ permission: 'case.update', days: 7, problem: null }),
  one: draw({ permission: 'case.update', days: 1, problem: null }),
  off: draw({ permission: 'case.update', days: 0, problem: null }),
  typo: draw({ permission: 'case.update', days: 7,
               problem: 'NOCTORNAL_RELAX_SEASONING_DAYS is not a whole number.' }),
  none: draw(undefined),
}));
""", tmp_path)
    assert ("second person must have held case.update on the case for: 7 days"
            in got["seven"])
    assert "for: 1 day" in got["one"] and "1 days" not in got["one"]
    assert "no minimum (the rule is off)" in got["off"]
    assert "NOCTORNAL_RELAX_SEASONING_DAYS is not a whole number." in got["typo"]
    assert "second person must have held" not in got["none"]


def test_the_new_console_copy_has_no_dash_and_no_bracketed_plural():
    """The two copy suites scan the whole console; this pins the words this
    change added so a failure names them."""
    js = _js()
    for fragment in ("the second person must have held case.update on the case "
                     "for ", "is eligible from ", "no minimum (the rule is off)",
                     "second person must have held "):
        assert fragment in js, fragment
    added = "".join(js.split(fragment)[1][:160] for fragment in
                    ("is eligible from ", "no minimum (the rule is off)"))
    for bad in ("—", "–", " -- ", "(s)"):
        assert bad not in added, bad


@pytest.mark.parametrize("name", ["paintCasePolicy", "approvalActions",
                                  "dualOperationCard"])
def test_the_functions_this_change_touched_write_text_never_markup(name):
    body = _fn(name)
    assert "innerHTML" not in body and "insertAdjacentHTML" not in body

"""The minimisation gap in the console (decision 231), as the console ships it.

Pure: no database. Closing a case whose conversations are above everyone assigned to it raises a
warning that stays until dismissed, and the case record says the same, both in the words the case's
withheld-disclosure setting allows: nothing under NONE, "some" under PRESENCE, how many under
COUNT, never which. The server decides who is sent the field and what it holds; the console only
says it. The Security officer's Oversight section lists the cases with a case code, a status, a TLP
tier and counts, and says a refused or unread list is not known to be empty. The server half is
test_minimisation_gap_http_pg.py.
"""
from __future__ import annotations

import json
import re

from test_collection_ui_foundation import _fn, _run, needs_node

WORDS = ["minimisationGapWords", "agree"]


@needs_node
def test_the_gap_is_said_in_the_cases_own_words_and_nothing_under_none(tmp_path):
    got = _run(WORDS, r"""
console.log(JSON.stringify({
  none: minimisationGapWords(null),
  missing: minimisationGapWords(undefined),
  zero: minimisationGapWords({ incomplete: false, mode: 'COUNT' }),
  presence: minimisationGapWords({ incomplete: true, mode: 'PRESENCE' }),
  one: minimisationGapWords({ incomplete: true, mode: 'COUNT', conversations: 1 }),
  three: minimisationGapWords({ incomplete: true, mode: 'COUNT', conversations: 3 }),
}));
""", tmp_path)
    assert got["none"] == got["missing"] == got["zero"] == ""
    assert got["presence"] == (
        "Some conversations here are above everyone assigned to this case, so nobody on the "
        "team can minimise them. Ask a Lead investigator cleared for them to be assigned to "
        "this case: Share adds a colleague.")
    assert got["one"] == (
        "1 conversation here is above everyone assigned to this case, so nobody on the team "
        "can minimise it. Ask a Lead investigator cleared for it to be assigned to this case: "
        "Share adds a colleague.")
    assert got["three"].startswith("3 conversations here are above everyone assigned")
    assert "minimise them." in got["three"]
    # Under PRESENCE no number is given, so none can be read off the sentence.
    assert not any(ch.isdigit() for ch in got["presence"])


def test_closing_raises_the_gap_once_and_the_case_record_shows_it():
    submit = _fn("submitStatus")
    assert "const moved = await api('/cases/' + state.caseId + '/status'" in submit
    assert "minimisationGapWords(moved && moved.minimisation_gap)" in submit
    # Only when the case is shut, and kept up until dismissed: it names a step still to take.
    assert "CASE_STATES_SHUT.has(to)" in submit
    assert "{ sticky: true }" in submit
    assert submit.index("banner('Status changed'") < submit.index("minimisationGapWords(")
    record = _fn("renderCaseRecord")
    assert "minimisationGapWords(rec.minimisation_gap)" in record
    assert "add('Minimisation', gap, 'overdue')" in record
    words = _fn("minimisationGapWords")
    for absent in ("innerHTML", "style", "conversation_id", "classification",
                   "compartment"):
        assert absent not in words, absent


# --- the Security officer's Oversight section ------------------------------------------------

ROW = ["minimisationGapRow", "caseStatusChip"]
LOAD = ["loadMinimisationGaps"] + ROW

GAP_ROW = {"case_code": "CASE-0042", "status": "CLOSED",
           "closed_at": "2026-11-01T10:00:00+00:00", "days_since_closed": 14,
           "conversations": 2, "highest_tlp": "RED", "leads_assigned": 1,
           "eligible_elsewhere": 3}


def _js_object(row: dict) -> str:
    return json.dumps(row)


def test_the_oversight_section_is_mounted_last_for_the_oversight_permission_alone():
    build = _fn("buildMinimisationGaps")
    assert "box.id = 'mgap-review';" in build
    assert "'aria-label', 'Minimisation gaps'" in build
    admin = _fn("showAdmin")
    assert "showMinimisationGaps(canOverseeMinimisation);" in admin
    assert admin.index("showYaraReview(") < admin.index("showMinimisationGaps(")
    assert "canOverseeMinimisation = !!access.comms_minimise_oversee;" in _fn(
        "loadAdminAccess")
    assert "canOverseeMinimisation" in _fn("refreshAdminEntry")
    assert "nobody on their team can minimise" in _fn("adminViewTitle")
    shown = _fn("showMinimisationGaps")
    # Re-appended on every visit so it stays last, and emptied for an account that may not see it.
    assert "$('view-admin').appendChild(minimisationGaps);" in shown
    assert "clear($('mgap-list'))" in shown
    assert "api('/admin/minimisation-gaps')" in _fn("loadMinimisationGaps")


@needs_node
def test_an_oversight_row_draws_the_case_and_counts_and_nothing_more(tmp_path):
    row = _fn("minimisationGapRow")
    read = set(re.findall(r"\bc\.([a-z_]+)", row))
    assert read == set(GAP_ROW), read
    for absent in ("innerHTML", "style", "conversation_id", "compartment", "platform"):
        assert absent not in row, absent
    got = _run(ROW, r"""
const card = minimisationGapRow(%s);
const open = minimisationGapRow(Object.assign({}, %s,
  { status: 'ACTIVE', closed_at: null, days_since_closed: null }));
console.log(JSON.stringify({ text: text(card), chips: chips(card), open: text(open) }));
""" % (_js_object(GAP_ROW), _js_object(GAP_ROW)), tmp_path)
    for said in ("CASE-0042", "conversations: 2", "closed: T(2026-11-01T10:00:00+00:00)",
                 "days since closed: 14", "Lead investigators assigned: 1",
                 "cleared Lead investigators elsewhere: 3"):
        assert said in got["text"], said
    assert "chip tlp-RED:RED" in got["chips"]
    assert any(c.startswith("chip case-state case-state-CLOSED") for c in got["chips"])
    # A case not yet closed has no closing time to show.
    assert "closed:" not in got["open"] and "days since closed" not in got["open"]


@needs_node
def test_a_refused_or_unread_list_is_never_drawn_as_empty(tmp_path):
    got = _run(LOAD, r"""
globalThis.refusalText = (err, context) => 'refused: ' + context;
globalThis.apiAnswer = () => { throw new ApiError(403, 'missing global permission x'); };
await loadMinimisationGaps();
const refused = $('mgap-empty').textContent;
globalThis.apiAnswer = () => { throw new TypeError('network'); };
await loadMinimisationGaps();
const unread = $('mgap-empty').textContent;
globalThis.apiAnswer = () => ({ cases: [], count: 0, truncated: false });
await loadMinimisationGaps();
const none = [$('mgap-empty').textContent, $('mgap-empty').hidden, $('mgap-counts').textContent];
globalThis.apiAnswer = () => ({ cases: [%s], count: 3, truncated: true });
await loadMinimisationGaps();
console.log(JSON.stringify({ refused, unread, none, rows: $('mgap-list').children.length,
                             counts: $('mgap-counts').textContent,
                             emptyHidden: $('mgap-empty').hidden }));
""" % _js_object(GAP_ROW), tmp_path, consts=("MGAP_NONE", "minimisationGapsGen"))
    assert got["refused"] == "refused: The list needs comms.minimise.oversee."
    assert got["unread"] == ("The minimisation gaps could not be read. The list is not known "
                             "to be empty.")
    assert got["none"] == ["No case has a conversation that nobody assigned can minimise.",
                           False, "0 cases"]
    assert got["rows"] == 1 and got["emptyHidden"] is True
    assert got["counts"] == "3 cases, the first 1 shown"


@needs_node
def test_the_officers_notice_opens_oversight_at_the_minimisation_gaps(tmp_path):
    """The officer's notice names no case, so its Open goes to Oversight, as the case-less
    break-glass alert does, and brings Minimisation gaps into view; a Lead's notice opens its case."""
    got = _run(["notificationRoute", "openNotificationTarget"], r"""
const log = [];
globalThis.state = { caseId: null, caseRec: null };
globalThis.adminView = false;
globalThis.canAdmin = false;
globalThis.selectAdminSub = null;
globalThis.selectGovSub = null;
globalThis.DUAL = {};
globalThis.showAdmin = async () => { log.push('admin'); globalThis.adminView = true; };
globalThis.leaveInbox = () => log.push('leave-inbox');
globalThis.openCase = async (id) => log.push('open:' + id);
globalThis.selectTab = (t) => log.push('tab:' + t);
boxes['mgap-review'] = mk('section');
boxes['mgap-review'].scrollIntoView = () => log.push('mgap');
const officer = { kind: 'COMMS_MINIMISATION_GAP', object_type: 'case', object_id: 'c1',
                  case_id: null };
const lead = Object.assign({}, officer, { case_id: 'c1' });
const route = notificationRoute(officer);
await openNotificationTarget(officer);
const opened = log.splice(0);
boxes['mgap-review'].hidden = true;
await openNotificationTarget(officer);
console.log(JSON.stringify({ route, opened, hidden: log, lead: notificationRoute(lead) }));
""", tmp_path)
    assert got["route"] == {"label": "Open Oversight", "oversight": True,
                            "section": "mgap-review"}
    assert got["opened"] == ["admin", "leave-inbox", "mgap"]
    # Not shown to this account, so nothing is scrolled to.
    assert got["hidden"] == ["admin", "leave-inbox"]
    assert got["lead"] == {"label": "Open the case", "tab": "graph"}

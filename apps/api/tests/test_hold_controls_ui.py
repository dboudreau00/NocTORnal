"""The console's hold controls, as the console ships them.

Pure: no database. The markup is read from the shipped index.html and the functions run under Node over a
stub DOM, judged by what they draw and what they send. The server halves are
`test_legal_holds_http_pg.py` and `test_evidence_retention_http_request_role_pg.py`.

Two controls, one per half of the hold route pair: an exhibit's card (`exhibitHoldButton`) and the case
header's Hold dialog (`openCaseHold`, `submitCaseHold`). Either asks for a written reason and a sign-in
from the last 15 minutes; the routes decide everything, and the console only offers the control when the
register or case record said `may_hold`.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from test_collection_ui_foundation import STUBS, _const, _fn
from test_ui_copy_no_dashes import NODE, STATIC, _html, _js, js_tokens

needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

#: The foundation's stub DOM with the three things these controls read from
#: the page's own state: whether the sign-in is asked for or cancelled, which
#: case is open, and what the register reload was asked for.
HARNESS = STUBS.replace(
    "async function withStepUp(why, call) { calls.push({ stepup: why }); "
    "return call(); }",
    "globalThis.stepUpCancelled = false;\n"
    "async function withStepUp(why, call) { calls.push({ stepup: why });\n"
    "  return globalThis.stepUpCancelled ? null : call(); }\n"
    "let openCase = 0;\n"
    "function caseToken() { return openCase; }\n"
    "function caseChanged(t) { return t !== openCase; }\n"
    "function loadEvidence(o) { calls.push({ loadEvidence: o }); }\n"
    "function applyCaseRecord(r) { calls.push({ applied: r }); }\n"
    "function reloadRegisterIfShown() { calls.push({ reloaded: true }); }\n"
    "function refusalText(err, fallback) { return fallback; }\n"
    "function banner(title, detail, kind, opts) {\n"
    "  calls.push({ banner: [title, detail, kind, opts] }); }\n"
    "globalThis.document = { activeElement: null, contains: () => false,\n"
    "  createTextNode: (t) => mk('#text', '', t) };\n"
).replace(
    "function fail(e) { throw e; }",
    "function fail(e, what) { calls.push({ failed: [e && e.message, what || null] }); }"
).replace(
    "    appendChild(c) {",
    "    get childNodes() { return this.children; },\n    appendChild(c) {")
assert ("stepUpCancelled" in HARNESS and "failed:" in HARNESS
        and "get childNodes" in HARNESS), (
    "the foundation's stub changed; update HARNESS")

#: What a lift's steps reach beyond the hold (decision 229): the case's own paths, the tab a
#: colleague's request is decided under, and the browser's confirmation and note prompts.
HARNESS += (
    "function cpath(p) { return '/cases/c-1' + p; }\n"
    "function selectTab(t) { calls.push({ tab: t }); }\n"
    "function shortId(id) { return String(id).slice(0, 8); }\n"
    "function approvalRaisedText(r) { return 'raised:' + JSON.stringify(r); }\n"
    "globalThis.window = { confirm: () => true, prompt: () => 'checked the order' };\n")

#: The exhibit card's hold control and the lift steps it draws.
EXHIBIT_HOLD = ["exhibitHoldButton", "exhibitHoldForm", "liftWaiting", "liftApprover"]


def _run(names, body, tmp_path: Path, consts=()) -> dict:
    sources = [_const(c) for c in consts] + [_fn(n) for n in names]
    script = tmp_path / "run.js"
    script.write_text(HARNESS + "\n".join(sources) + "\n(async () => {\n" + body
                      + "\n})().catch((e) => { console.error(e); process.exit(1); });\n",
                      encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# --- the markup ----------------------------------------------------------------

HOLD_IDS = ("hdr-hold", "btn-case-hold", "hold-scrim", "hold-form", "hold-title",
            "hold-now", "hold-help", "hold-why", "hold-why-field", "hold-msg", "hold-save",
            "hold-cancel", "hold-withdraw")


def test_every_hold_region_and_field_exists_once():
    html = _html()
    for ident in HOLD_IDS:
        assert html.count(f'id="{ident}"') == 1, ident


def _dialog() -> str:
    html = _html()
    start = html.index('<div id="hold-scrim"')
    return html[start:html.index("</form>", start) + 20]


def test_the_dialog_is_a_labelled_modal_with_no_inline_style_or_handler():
    block = _dialog()
    assert 'role="dialog"' in block and 'aria-modal="true"' in block
    assert 'aria-labelledby="hold-title"' in block
    assert 'aria-describedby="hold-now"' in block
    assert not re.search(r"\sstyle\s*=", block, re.I)
    assert not re.search(r"\son[a-z]+\s*=", block, re.I)
    assert "<script" not in block.lower()
    # Hidden until opened, and the message is announced when it appears.
    assert re.search(r'id="hold-scrim"[^>]*\bhidden\b', block)
    assert re.search(r'id="hold-msg"[^>]*role="status"[^>]*\bhidden\b', block)


def test_the_header_button_and_chip_start_hidden_and_name_what_they_do():
    html = _html()
    button = re.search(r'<button id="btn-case-hold"[^>]*>[^<]*</button>', html).group(0)
    assert re.search(r"\bhidden\b", button) and 'aria-haspopup="dialog"' in button
    assert "Hold…" in button
    chip = re.search(r'<span id="hdr-hold"[^>]*>[^<]*</span>', html).group(0)
    assert re.search(r"\bhidden\b", chip) and "LEGAL HOLD" in chip


def test_the_dialog_is_wired_at_boot_and_cleared_with_the_case_chrome():
    js = _js()
    assert "wireCaseHold();" in js
    wire = _fn("wireCaseHold")
    for line in ("btn.addEventListener('click', openCaseHold);",
                 "$('hold-form').addEventListener('submit', submitCaseHold);",
                 "$('hold-cancel').addEventListener('click', closeCaseHold);",
                 "$('hold-withdraw').addEventListener('click', withdrawCaseLift);",
                 "holdDialogKeys('hold-scrim', closeCaseHold);"):
        assert line in wire, line
    chrome = _fn("hideCaseChrome")
    assert "'btn-case-hold'" in chrome and "'hdr-hold'" in chrome
    assert "closeCaseHold();" in chrome, (
        "a hold dialog left open would carry one case's name into the next")


def test_the_sign_in_question_stands_above_the_hold_dialog():
    """Found by driving the console in a real browser with a stale sign-in:
    `.reauth-scrim { z-index: 86 }` came before `.palette-scrim { z-index: 80 }`
    in the stylesheet and has the same specificity, so the later rule won and
    the question stood under the dialog that asked it, in DOM order, where it
    could be seen and not clicked."""
    css = (STATIC / "app.css").read_text(encoding="utf-8")

    def rules(selector: str) -> list[str]:
        """The bodies of the rules whose selector is exactly `selector`."""
        return [m.group(1) for m in re.finditer(
            r"(?m)^" + re.escape(selector) + r"\s*\{([^}]*)\}", css)]

    assert any("z-index" in body for body in rules(".palette-scrim")), (
        ".palette-scrim no longer sets a z-index")
    both = rules(".palette-scrim.reauth-scrim")
    assert both and "z-index: 86" in both[0], (
        "the sign-in question must outrank the dialogs it can be asked over, "
        "by a selector that is not beaten by `.palette-scrim` coming later")
    assert not rules(".reauth-scrim"), (
        "a bare .reauth-scrim rule is beaten by .palette-scrim and does nothing")
    html = _html()
    assert html.index('id="reauth-scrim"') < html.index('id="hold-scrim"'), (
        "the hold dialog comes after the question in the page, which is why "
        "the stylesheet has to do the ordering")


def test_opening_a_case_draws_the_hold_chrome_with_the_rest_of_it():
    """Found by driving the console in a real browser: `openCase` draws the
    header through `showCaseChrome` and does not call `applyCaseRecord`, so a
    chip and a button drawn only by the latter never appeared when a case was
    opened. Both paths reach the one function that draws them."""
    assert "showCaseChrome(rec);" in _fn("openCase")
    assert "showCaseChrome(rec);" in _fn("applyCaseRecord")
    assert "renderCaseHold(rec);" in _fn("showCaseChrome")


@needs_node
def test_the_case_chrome_shows_the_hold_chip_and_button_when_a_case_opens(tmp_path):
    got = _run(["showCaseChrome", "renderCaseHold"], r"""
globalThis.caseCan = () => true;
globalThis.caseRoleWords = () => 'a lead investigator';
const seen = {};
for (const [name, rec] of [
    ['held_lead', { legal_hold: true, may_hold: true }],
    ['free_lead', { legal_hold: false, may_hold: true }],
    ['held_reader', { legal_hold: true, may_hold: false }]]) {
  $('hdr-hold').hidden = true; $('btn-case-hold').hidden = true;
  showCaseChrome(rec);
  seen[name] = { chip: $('hdr-hold').hidden, btn: $('btn-case-hold').hidden };
}
console.log(JSON.stringify(seen));
""", tmp_path)
    assert got["held_lead"] == {"chip": False, "btn": False}
    assert got["free_lead"] == {"chip": True, "btn": False}
    assert got["held_reader"] == {"chip": False, "btn": True}


def test_the_exhibit_control_is_offered_only_to_a_reader_whose_register_said_so():
    card = _fn("exhibitCard")
    guard = "if (page.may_hold && !ev.purged_at) {"
    assert guard in card
    assert card.index(guard) < card.index("exhibitHoldButton(ev, item)")
    # The chip is for every reader of a held exhibit; the reason is for the
    # readers the server sent it to.
    assert "ev.legal_hold" in card and "LEGAL HOLD" in card
    assert "ev.legal_hold && ev.legal_hold_reason" in card


def test_the_register_hands_its_page_to_every_card_and_the_card_on_to_the_control():
    """`may_hold` is a fact about the page (the caller and the case), not an
    exhibit, so the card needs the page; and `exhibitCardWithSimilar` passes
    it on rather than dropping it."""
    assert "exhibitCardWithSimilar(ev, page)" in _fn("renderEvidence")
    assert "exhibitCard(ev, page)" in _fn("exhibitCardWithSimilar")
    js = _js()
    callers = re.findall(r"exhibitCard(?:WithSimilar)?\(([^)]*)\)", js)
    assert all(args.strip().endswith("page") for args in callers), callers


#: The lift's steps (decision 229) and the controls that draw them.
LIFT_STEPS = ("exhibitHoldButton", "exhibitHoldForm", "liftWaiting", "liftApprover",
              "caseHoldStep", "withdrawCaseLift", "documentHoldActions", "documentHoldForm",
              "documentLiftDecision", "openDocumentLift", "approvalTitle",
              "approvalConsequence")


def test_the_lift_copy_has_no_dash_and_no_lazy_plural():
    for name in LIFT_STEPS:
        literals, _ = js_tokens(_fn(name))
        assert literals or name == "caseHoldStep", name
        for _, said in literals:
            assert "(s)" not in said, (name, said)
            assert not re.search("[\\u2013\\u2014]", said), (name, said)
            assert not re.search(r"\s--\s", said), (name, said)
    for name in ("LIFT_TAKES", "HOLD_SAVE"):
        literals, _ = js_tokens(_const(name))
        assert literals, name
        for _, said in literals:
            assert "(s)" not in said and not re.search("[\\u2013\\u2014]", said), said


def test_the_lift_operation_keys_are_the_catalogues():
    """The console names a hold lift's operation once per kind, and each is the key
    `approvals.py` registers, so a request card and a notice route compare against the server's
    own string."""
    from noctornal_api.approvals import LIFT_CASE, LIFT_DOCUMENT, LIFT_EXHIBIT
    js = _js()
    for const, key in (("LIFT_EXHIBIT_OPERATION", LIFT_EXHIBIT),
                       ("LIFT_CASE_OPERATION", LIFT_CASE),
                       ("LIFT_DOCUMENT_OPERATION", LIFT_DOCUMENT)):
        assert f"const {const} = '{key}';" in js, const


def test_the_new_copy_has_no_lazy_plural_and_no_dash():
    for name in ("exhibitHoldButton", "renderCaseHold", "openCaseHold",
                 "closeCaseHold", "submitCaseHold", "wireCaseHold"):
        literals, _ = js_tokens(_fn(name))
        assert literals or name in ("closeCaseHold", "wireCaseHold"), name
        for _, said in literals:
            assert "(s)" not in said, (name, said)
            assert not re.search("[\\u2013\\u2014]", said), (name, said)
            assert not re.search(r"\s--\s", said), (name, said)


# --- the exhibit's control ------------------------------------------------------------

@needs_node
def test_the_exhibit_control_places_and_lifts_through_the_step_up_gate(tmp_path):
    """Placing is one step; lifting is two (decision 229): ask for a second signature, then, once a
    colleague has approved, lift with the approval. Each takes a reason and a recent sign-in."""
    got = _run(EXHIBIT_HOLD, r"""
const out = [];
const approved = { id: 'r-1', state: 'APPROVED', mine: true, decided_by_name: 'Dana Lee',
                   expires_at: 'X' };
for (const [held, lr] of [[false, null], [true, null], [true, approved]]) {
  calls.length = 0;
  const card = mk('div');
  const ev = { id: 'ev-1', title: 'Informant interview', legal_hold: held, lift_request: lr };
  const btn = exhibitHoldButton(ev, card);
  btn.listeners.click();
  const spec = card.lastSpec;
  await spec.submitFn(['  a preservation order, 2026-17  ']);
  out.push({ label: btn.textContent, aria: btn.attrs['aria-label'], type: btn.type,
             kind: spec.kind, submit: spec.submit, fields: spec.fields,
             short: spec.check(['abc ']), blank: spec.check(['     ']),
             fine: spec.check(['because']), help: spec.help, calls: calls.slice() });
}
console.log(JSON.stringify(out));
""", tmp_path, consts=["LIFT_TAKES"])
    place, ask, lift = got
    assert place["label"] == "Place a legal hold" and place["type"] == "button"
    assert place["aria"] == "Place a legal hold on Informant interview"
    assert place["kind"] == "hold" and place["submit"] == "Place a legal hold"
    assert place["fields"] == [{"label": "Why", "grow": True}]
    assert place["short"] == "Say why, in at least 5 characters."
    assert place["blank"] == "Say why, in at least 5 characters."
    assert place["fine"] is None
    assert "15 minutes" in place["help"] and "audit log" in place["help"]
    assert place["calls"] == [
        {"stepup": "A legal hold needs a recent sign-in."},
        {"path": "/retention/legal-hold",
         "opts": {"method": "POST",
                  "json": {"evidence_id": "ev-1", "on": True,
                           "reason": "a preservation order, 2026-17"}}},
        {"loadEvidence": {"pageOnly": True, "focus": "ev-1"}},
    ]
    assert ask["label"] == "Ask for a second signature to lift"
    assert ask["aria"] == "Ask for a second signature to lift on Informant interview"
    assert "second person cleared for the same material" in ask["help"]
    assert "follows the case's retention date again" in ask["help"]
    assert ask["calls"][1] == {
        "path": "/retention/legal-hold/lift-requests",
        "opts": {"method": "POST", "json": {"evidence_id": "ev-1",
                                            "justification": "a preservation order, 2026-17"}}}
    assert lift["label"] == "Lift the legal hold (approved by Dana Lee)"
    assert lift["calls"][1] == {
        "path": "/retention/legal-hold",
        "opts": {"method": "POST", "json": {"evidence_id": "ev-1", "on": False,
                                            "reason": "a preservation order, 2026-17",
                                            "approval_request_id": "r-1"}}}
    assert "spent once" in lift["help"]


@needs_node
def test_an_open_lift_the_reader_takes_no_step_on_says_who_it_waits_for(tmp_path):
    """Their own request waits for a second person and can be withdrawn; a colleague's is reviewed
    under Triage, Dual control, where every request is decided; one approved for a colleague is
    theirs to lift."""
    got = _run(EXHIBIT_HOLD, r"""
const base = { id: 'r-1', expires_at: 'X', requested_by_name: 'Sam Roe',
               decided_by_name: 'Dana Lee', justification: 'order 7 discharged' };
const ev = (lr) => ({ id: 'ev-1', title: 'T', legal_hold: true, lift_request: lr });
const seen = {};
for (const [name, lr] of [['waiting', { ...base, state: 'PENDING', mine: true }],
                          ['review', { ...base, state: 'PENDING', mine: false }],
                          ['approved', { ...base, state: 'APPROVED', mine: false }]]) {
  calls.length = 0;
  const node = exhibitHoldButton(ev(lr), mk('div'));
  const press = find(node, (x) => x.tag === 'button');
  if (press) await press.listeners.click();
  seen[name] = { text: text(node), buttons: buttons(node), calls: calls.slice(),
                 target: state.approvalTarget || null };
  state.approvalTarget = null;
}
console.log(JSON.stringify(seen));
""", tmp_path, consts=["LIFT_TAKES"])
    waiting, review, approved = got["waiting"], got["review"], got["approved"]
    assert "Waiting for a second person until T(X)." in waiting["text"]
    assert waiting["buttons"] == ["Withdraw the request"]
    assert waiting["calls"] == [
        {"path": "/cases/c-1/approvals/r-1/withdraw", "opts": {"method": "POST"}},
        {"loadEvidence": {"pageOnly": True, "focus": "ev-1"}}]
    assert "Sam Roe asks for your second signature" in review["text"]
    assert "order 7 discharged" in review["text"]
    assert review["buttons"] == ["Review the request to lift this hold"]
    assert review["calls"] == [{"tab": "triage"}] and review["target"] == "r-1"
    assert approved["buttons"] == []
    assert "Approved by Dana Lee. Sam Roe lifts it" in approved["text"]


@needs_node
def test_a_cancelled_sign_in_changes_nothing_and_reloads_nothing(tmp_path):
    got = _run(EXHIBIT_HOLD, r"""
globalThis.stepUpCancelled = true;
const card = mk('div');
const btn = exhibitHoldButton({ id: 'ev-1', title: 'T', legal_hold: false }, card);
btn.listeners.click();
let caught = null;
try { await card.lastSpec.submitFn(['a good enough reason']); }
catch (e) { caught = { handled: e.handled === true, message: e.message }; }
console.log(JSON.stringify({ caught: caught, calls: calls }));
""", tmp_path, consts=["LIFT_TAKES"])
    assert got["caught"] == {"handled": True, "message": "cancelled"}
    assert got["calls"] == [{"stepup": "A legal hold needs a recent sign-in."}], (
        "the route was called, or the register reloaded, without a sign-in")


@needs_node
def test_an_answer_that_arrives_after_the_case_changed_is_dropped(tmp_path):
    got = _run(EXHIBIT_HOLD, r"""
globalThis.apiAnswer = async (path) => { openCase += 1; return { ok: true }; };
const card = mk('div');
exhibitHoldButton({ id: 'ev-1', title: 'T', legal_hold: false }, card).listeners.click();
await card.lastSpec.submitFn(['a good enough reason']);
console.log(JSON.stringify(calls.filter((c) => c.loadEvidence)));
""", tmp_path, consts=["LIFT_TAKES"])
    assert got == [], "another case's register was reloaded for this answer"


# --- the case header ---------------------------------------------------------------------

@needs_node
def test_the_chip_shows_for_every_reader_and_the_button_only_for_who_may_hold(tmp_path):
    got = _run(["renderCaseHold"], r"""
const seen = {};
for (const [name, rec] of [
    ['none', null],
    ['free', { legal_hold: false, may_hold: true }],
    ['held', { legal_hold: true, may_hold: true }],
    ['held_reader', { legal_hold: true, may_hold: false }],
    ['free_reader', { legal_hold: false, may_hold: false }]]) {
  renderCaseHold(rec);
  seen[name] = { chip: $('hdr-hold').hidden, btn: $('btn-case-hold').hidden,
                 chipTitle: $('hdr-hold').title, btnTitle: $('btn-case-hold').title };
}
console.log(JSON.stringify(seen));
""", tmp_path)
    assert (got["none"]["chip"], got["none"]["btn"]) == (True, True)
    assert (got["free"]["chip"], got["free"]["btn"]) == (True, False)
    assert got["free"]["btnTitle"] == "Place a legal hold on this whole case"
    assert (got["held"]["chip"], got["held"]["btn"]) == (False, False)
    assert got["held"]["btnTitle"] == "Lift the legal hold on this case"
    assert "under a legal hold" in got["held"]["chipTitle"]
    assert (got["held_reader"]["chip"], got["held_reader"]["btn"]) == (False, True)
    assert (got["free_reader"]["chip"], got["free_reader"]["btn"]) == (True, True)


#: The case header's dialog and the lift's steps it draws (decision 229).
CASE_DIALOG = ["openCaseHold", "closeCaseHold", "caseHoldStep", "liftApprover"]
CASE_DIALOG_CONSTS = ["holdReturn", "HOLD_SAVE", "LIFT_TAKES"]


@needs_node
def test_the_dialog_says_what_the_hold_is_and_what_it_will_do(tmp_path):
    got = _run(CASE_DIALOG, r"""
const seen = [];
const lr = { id: 'r-1', expires_at: 'X', requested_by_name: 'Sam Roe',
             decided_by_name: 'Dana Lee', justification: 'order 7 discharged' };
const held = { id: 'c-1', code: 'OP-KESTREL', may_hold: true, legal_hold: true,
               legal_hold_reason: 'preservation order 2026-17' };
for (const rec of [
    { id: 'c-1', code: 'OP-KESTREL', may_hold: true, legal_hold: false },
    held,
    { ...held, lift_request: { ...lr, state: 'PENDING', mine: true } },
    { ...held, lift_request: { ...lr, state: 'PENDING', mine: false } },
    { ...held, lift_request: { ...lr, state: 'APPROVED', mine: true } },
    { id: 'c-1', code: 'OP-KESTREL', may_hold: false, legal_hold: false }]) {
  state.caseRec = rec; state.caseId = 'c-1';
  $('hold-scrim').hidden = true;
  $('hold-why').value = 'left over';
  openCaseHold();
  seen.push({ open: !$('hold-scrim').hidden, title: $('hold-title').textContent,
              now: $('hold-now').textContent, help: $('hold-help').textContent,
              save: $('hold-save').hidden ? null : $('hold-save').textContent,
              withdraw: !$('hold-withdraw').hidden, asks: !$('hold-why-field').hidden,
              why: $('hold-why').value });
  closeCaseHold();
  seen[seen.length - 1].closed = $('hold-scrim').hidden;
}
console.log(JSON.stringify(seen));
""", tmp_path, consts=CASE_DIALOG_CONSTS)
    place, ask, waiting, review, lift, refused = got
    assert place["open"] and place["closed"]
    assert place["title"] == "Place a legal hold on OP-KESTREL"
    assert place["now"] == "OP-KESTREL is not under a legal hold."
    assert place["save"] == "Place the hold" and place["why"] == "" and place["asks"]
    assert "A purge already running finishes the exhibit it is destroying" in place["help"]
    assert "15 minutes" in place["help"]
    assert ask["title"] == "Lift the legal hold on OP-KESTREL"
    assert ask["now"] == ("OP-KESTREL is under a legal hold, placed for: "
                          "preservation order 2026-17.")
    assert ask["save"] == "Ask for a second signature" and ask["asks"]
    assert ("Lifting needs a written reason, a sign-in from the last 15 minutes and a "
            "second person cleared for the same material.") in ask["help"]
    assert waiting["save"] is None and waiting["withdraw"] and not waiting["asks"]
    assert "You asked for a second signature to lift it, which waits until T(X)." in (
        waiting["now"])
    assert review["save"] == "Review the request" and not review["asks"]
    assert "Sam Roe asks for your second signature to lift it" in review["now"]
    assert "order 7 discharged" in review["now"]
    assert lift["save"] == "Lift the hold" and lift["asks"] and not lift["withdraw"]
    assert "approved by Dana Lee" in lift["now"]
    assert refused["open"] is False, "a reader who may not hold was shown the dialog"


SUBMIT = r"""
function run(rec, why) {
  state.caseRec = rec; state.caseId = rec.id;
  $('hold-why').value = why; $('hold-scrim').hidden = false;
  calls.length = 0;
  return submitCaseHold({ preventDefault() {} }).then(() => ({
    calls: calls.slice(), msg: $('hold-msg').textContent, open: !$('hold-scrim').hidden,
    saveDisabled: $('hold-save').disabled }));
}
"""


#: The dialog's submit and what it reads.
CASE_SUBMIT = ["submitCaseHold", "closeCaseHold", "caseHoldStep"]


@needs_node
def test_a_hold_is_placed_with_its_reason_and_the_case_is_read_again(tmp_path):
    got = _run(CASE_SUBMIT, SUBMIT + r"""
globalThis.apiAnswer = async (path) => (path === '/cases/c-1'
  ? { id: 'c-1', legal_hold: true } : { ok: true, notice: null });
const placed = await run({ id: 'c-1', code: 'OP-KESTREL', may_hold: true,
                           legal_hold: false }, '  a preservation order  ');
const lifted = await run({ id: 'c-1', code: 'OP-KESTREL', may_hold: true,
                           legal_hold: true,
                           lift_request: { id: 'r-1', state: 'APPROVED', mine: true } },
                         'order withdrawn on 2026-10-08');
console.log(JSON.stringify({ placed: placed, lifted: lifted }));
""", tmp_path, consts=["holdReturn"])
    placed, lifted = got["placed"], got["lifted"]
    assert placed["calls"][0] == {"stepup": "A legal hold needs a recent sign-in."}
    assert placed["calls"][1] == {
        "path": "/retention/cases/c-1/legal-hold",
        "opts": {"method": "POST",
                 "json": {"on": True, "reason": "a preservation order"}}}
    kinds = [next(iter(c)) for c in placed["calls"]]
    # The hold is said before the record is read again, and the record
    # after it drives the chip and the register.
    assert kinds[2:] == ["banner", "path", "applied", "reloaded"], kinds
    assert placed["calls"][3]["path"] == "/cases/c-1"
    banner = [c["banner"] for c in placed["calls"] if "banner" in c][0]
    assert banner[:3] == ["Legal hold placed",
                          "OP-KESTREL is now under a legal hold.", "info"]
    assert placed["open"] is False and placed["saveDisabled"] is False
    assert lifted["calls"][1]["opts"]["json"] == {
        "on": False, "reason": "order withdrawn on 2026-10-08",
        "approval_request_id": "r-1"}
    assert [c["banner"][0] for c in lifted["calls"] if "banner" in c] == [
        "Legal hold lifted"]


@needs_node
def test_a_lift_is_asked_for_or_reviewed_from_the_dialog_and_never_lifted_alone(tmp_path):
    """Held with no request, the dialog asks for the second signature with the reason as its
    justification; a colleague's request is reviewed under Triage, Dual control, with nothing
    sent; and the reader's own waiting request can be withdrawn."""
    got = _run(CASE_SUBMIT + ["withdrawCaseLift"], SUBMIT + r"""
globalThis.apiAnswer = async (path) => (path === '/cases/c-1'
  ? { id: 'c-1', legal_hold: true } : { id: 'r-9', approvers_notified: 1, warnings: [] });
const held = { id: 'c-1', code: 'OP-KESTREL', may_hold: true, legal_hold: true };
const asked = await run(held, 'the order was discharged on appeal');
const reviewed = await run({ ...held, lift_request: { id: 'r-2', state: 'PENDING',
                                                      mine: false } }, '');
state.caseRec = { ...held, lift_request: { id: 'r-3', state: 'PENDING', mine: true } };
calls.length = 0;
await withdrawCaseLift();
console.log(JSON.stringify({ asked: asked, reviewed: reviewed, target: state.approvalTarget,
                             withdrawn: calls.slice() }));
""", tmp_path, consts=["holdReturn"])
    asked = got["asked"]
    assert asked["calls"][1] == {
        "path": "/retention/cases/c-1/legal-hold/lift-requests",
        "opts": {"method": "POST",
                 "json": {"justification": "the order was discharged on appeal"}}}
    assert [c["banner"][0] for c in asked["calls"] if "banner" in c] == [
        "Second signature asked for"]
    assert not [c for c in asked["calls"] if c.get("path") == "/retention/cases/c-1/legal-hold"]
    assert got["reviewed"]["calls"] == [{"tab": "triage"}] and got["target"] == "r-2"
    assert got["withdrawn"][0] == {"path": "/cases/c-1/approvals/r-3/withdraw",
                                   "opts": {"method": "POST"}}
    assert [c["banner"][0] for c in got["withdrawn"] if "banner" in c] == [
        "Request withdrawn"]


@needs_node
def test_a_failed_re_read_never_says_the_hold_was_not_placed(tmp_path):
    """The hold is in force when only the record's re-read fails: the dialog
    is closed and says nothing, the banner has said the hold was placed, and
    the failure is reported as the read's."""
    got = _run(CASE_SUBMIT, SUBMIT + r"""
globalThis.apiAnswer = async (path) => {
  if (path === '/cases/c-1') throw new ApiError(0, 'the API could not be reached');
  return { ok: true, notice: null };
};
const placed = await run({ id: 'c-1', code: 'OP-KESTREL', may_hold: true,
                           legal_hold: false }, 'a preservation order');
console.log(JSON.stringify(placed));
""", tmp_path, consts=["holdReturn"])
    assert got["msg"] == "", "the dialog claimed the hold was not changed"
    assert got["open"] is False
    kinds = [next(iter(c)) for c in got["calls"]]
    assert "banner" in kinds and "applied" not in kinds
    assert {"failed": ["the API could not be reached", "The case record"]} in got["calls"]


@needs_node
def test_what_a_purge_destroyed_while_the_hold_waited_is_said_and_kept_on_screen(
        tmp_path):
    got = _run(CASE_SUBMIT, SUBMIT + r"""
const notice = 'While this hold waited for a purge to finish, it destroyed 2 '
  + 'exhibits.';
globalThis.apiAnswer = async (path) => (path === '/cases/c-1'
  ? { id: 'c-1', legal_hold: true } : { ok: true, notice: notice });
const placed = await run({ id: 'c-1', code: 'OP-KESTREL', may_hold: true,
                           legal_hold: false }, 'a preservation order');
console.log(JSON.stringify(placed.calls.filter((c) => c.banner)));
""", tmp_path, consts=["holdReturn"])
    [call] = got
    title, detail, kind, opts = call["banner"]
    assert title == "Legal hold placed" and kind == "warn"
    assert detail.endswith("it destroyed 2 exhibits.")
    assert detail.startswith("OP-KESTREL is now under a legal hold. While")
    assert opts == {"sticky": True}, "the notice must stay until it is dismissed"


@needs_node
def test_a_short_reason_or_a_cancelled_sign_in_or_a_refusal_changes_nothing(tmp_path):
    got = _run(CASE_SUBMIT, SUBMIT + r"""
const rec = { id: 'c-1', code: 'OP-KESTREL', may_hold: true, legal_hold: false };
const short = await run(rec, 'abc');
globalThis.stepUpCancelled = true;
const cancelled = await run(rec, 'a preservation order');
globalThis.stepUpCancelled = false;
globalThis.apiAnswer = async () => { throw new ApiError(403, 'not cleared'); };
const refused = await run(rec, 'a preservation order');
const reader = await run({ id: 'c-1', code: 'OP-X', may_hold: false, legal_hold: false },
                         'a preservation order');
console.log(JSON.stringify({ short: short, cancelled: cancelled, refused: refused,
                             reader: reader }));
""", tmp_path, consts=["holdReturn"])
    assert got["short"]["msg"] == "Say why, in at least 5 characters."
    assert got["short"]["calls"] == []
    assert got["cancelled"]["msg"] == "Not changed: the sign-in was cancelled."
    assert got["cancelled"]["open"] is True
    assert not [c for c in got["cancelled"]["calls"] if "path" in c]
    assert got["refused"]["msg"].startswith("Not changed: ")
    assert got["refused"]["open"] is True and got["refused"]["saveDisabled"] is False
    assert got["reader"]["calls"] == [], "a reader who may not hold sent the request"


# --- the report pane's statement -------------------------------------------------

@needs_node
def test_the_report_pane_states_each_figure_as_the_cases_setting_allows(tmp_path):
    """The three figures follow the case's withheld-disclosure setting (decision 179): the number under
    COUNT, whether there are some under PRESENCE, and nothing under NONE, where even a 0 would say what the
    case chose not to."""
    got = _run(["renderRedaction", "withStrongRuns"], r"""
const out = {};
const base = { built_at_tlp: 'GREEN', nodes_withheld: 0, edges_withheld: 0,
               evidence_withheld: 0 };
for (const [name, r] of [
  ['COUNT', { ...base, disclosure: 'COUNT', nodes_withheld: 3, edges_withheld: 4,
              evidence_withheld: 2, hypothesis_evidence_withheld: 1,
              statement: 'S-count' }],
  ['PRESENCE', { ...base, disclosure: 'PRESENCE', nodes_some_withheld: true,
                 edges_some_withheld: true, evidence_some_withheld: false,
                 hypothesis_evidence_some_withheld: true, statement: 'S-presence' }],
  ['NONE', { ...base, disclosure: 'NONE', statement: 'S-none' }],
  ['OLD', { ...base, nodes_withheld: 5, statement: 'S-old' }]]) {
  renderRedaction({ body: { redaction: r, generated_at: 'x' }, caseCode: 'OP',
                    params: { include_hypotheses: true } });
  const box = $('rep-redaction');
  out[name] = {
    facts: all(box, (n) => String(n.className).startsWith('fact')).map((n) => n.textContent)
      .filter((t) => /withheld/.test(t)),
    said: text(box).includes('S-' + name.toLowerCase()),
  };
}
console.log(JSON.stringify(out));
""", tmp_path)
    assert got["COUNT"]["facts"] == [
        "entities withheld: 3", "relationships withheld: 4",
        "exhibits withheld: 2", "hypothesis evidence withheld: 1"]
    assert got["PRESENCE"]["facts"] == [
        "entities withheld: some", "relationships withheld: some",
        "exhibits withheld: none", "hypothesis evidence withheld: some"]
    assert got["NONE"]["facts"] == [], "a figure was drawn for a case that says nothing"
    assert got["OLD"]["facts"][0] == "entities withheld: 5"
    assert all(got[k]["said"] for k in got), "the document's own statement is shown"


# --- the lift in the approvals pane and the Inbox (decision 229) ---------------------------

@needs_node
def test_the_approvals_pane_names_a_lift_and_what_it_releases(tmp_path):
    """A lift request names the exhibit it releases by the title the server sent the one reader
    shown it, or the case, and says what a purge may then do; the Approve on it is the pane's own
    decide call (`approvalActions`), as for every request."""
    got = _run(["approvalTitle", "approvalConsequence"], r"""
const exhibit = { operation: LIFT_EXHIBIT_OPERATION, payload: { evidence_id: 'ev-12345678x' },
                  subjects: { exhibit: { title: 'Informant interview' } } };
const unnamed = { operation: LIFT_EXHIBIT_OPERATION, payload: { evidence_id: 'ev-12345678x' } };
const kase = { operation: LIFT_CASE_OPERATION, payload: { epoch: 2 } };
console.log(JSON.stringify({
  exhibit: [approvalTitle(exhibit), approvalConsequence(exhibit)],
  unnamed: approvalTitle(unnamed),
  kase: [approvalTitle(kase), approvalConsequence(kase)] }));
""", tmp_path, consts=["MERGE_OPERATION", "RELAX_OPERATION", "LIFT_EXHIBIT_OPERATION",
                       "LIFT_CASE_OPERATION"])
    assert got["exhibit"][0] == 'Lift the legal hold on exhibit "Informant interview"'
    assert got["unnamed"] == "Lift the legal hold on exhibit ev-12345"
    assert got["kase"][0] == "Lift the legal hold on this case"
    for _title, consequence in (got["exhibit"], got["kase"]):
        assert consequence == ("Once lifted, what it governs follows the case's retention "
                               "date again and a purge may destroy what is past it.")
    actions = _fn("approvalActions")
    assert "cpath('/approvals/' + a.id + '/decide')" in actions


@needs_node
def test_a_document_lifts_notice_opens_collected_and_a_policy_change_opens_oversight(tmp_path):
    got = _run(["notificationRoute"], r"""
const lift = { object_type: 'approval_request', case_id: null, object_id: 'r-1',
               subject: 'A second signature is needed: legal_hold.lift_document' };
const policy = { object_type: 'approval_request', case_id: null, object_id: 'r-2',
                 subject: 'A second signature is needed: Change which operations need two people' };
console.log(JSON.stringify({ lift: notificationRoute(lift), policy: notificationRoute(policy) }));
""", tmp_path, consts=["LIFT_DOCUMENT_OPERATION"])
    assert got["lift"] == {"label": "Open Collected", "documentLift": "r-1"}
    assert got["policy"] == {"label": "Open the change", "oversight": True, "dual": "r-2"}
    assert "await openDocumentLift(route.documentLift);" in _fn("openNotificationTarget")


@needs_node
def test_opening_a_document_lifts_notice_asks_for_a_recent_sign_in_and_finds_its_card(tmp_path):
    """The deployment-wide list refuses a stale sign-in to a holder of retention.manage alone, so
    the request is read behind the sign-in question; a cancelled question opens nothing, and the
    document's card is brought into view under Feeds, Collected."""
    got = _run(["openDocumentLift"], r"""
globalThis.selectFeedsSub = (name) => calls.push({ sub: name });
globalThis.apiAnswer = async () => ({ approvals: [
  { id: 'r-1', payload: { document_id: 'D1', versions: {} } }] });
state.caseId = 'c-1';
const card = $('cdoc-D1');
card.scrollIntoView = () => {};
await openDocumentLift('r-1');
const opened = calls.slice();
calls.length = 0;
globalThis.stepUpCancelled = true;
await openDocumentLift('r-1');
console.log(JSON.stringify({ opened, cancelled: calls.slice(),
                             marked: card.classList.contains('is-highlighted') }));
""", tmp_path, consts=["LIFT_DOCUMENT_OPERATION"])
    assert got["opened"][0] == {"stepup": "Opening the request needs a recent sign-in."}
    assert got["opened"][1]["path"] == (
        "/approvals?state=OPEN&operation=legal_hold.lift_document")
    assert {"tab": "feeds"} in got["opened"] and {"sub": "collected"} in got["opened"]
    assert {"reload": "documents"} in got["opened"] and got["marked"] is True
    assert got["cancelled"] == [{"stepup": "Opening the request needs a recent sign-in."}]

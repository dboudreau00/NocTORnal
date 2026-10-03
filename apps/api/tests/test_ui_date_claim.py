"""The console half of dating a claim that never had a date, by supersession
(docs/00 open question 11, settled by the owner 2026-10-02).

Pure: no database. The functions run under Node over the stub DOM of
test_ui_dual_control.py, extended with the `remove` a form needs, and are
judged by what they send and say. The server half, which decides, is
test_supersede_assertion_pg.py.

What the console must do: offer Date this claim on a live claim that has no
date and nowhere else; send the date (as UTC) and the reason and NOTHING
else, so the form cannot regrade, rebase or re-aim the claim; refuse a form
that is incomplete or in the future before anything is sent; and say what
happened in words that do not claim the old claim was changed.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from test_ui_copy_no_dashes import NODE, _js
from test_ui_dual_control import _STUBS, _fn, needs_node

ROUTER = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
          / "http" / "routers" / "graph.py")

_SOURCES = ["observedAtUtc", "dateClaimProblem", "dateClaimBody",
            "dateClaimDoneWords", "dateClaimHelp", "openDateClaimForm"]

#: The shared stub DOM, plus remove() on every element it makes.
_DOM = _STUBS.replace("focus() {} };", "focus() {}, remove() { this.removed = true; } };")

_PRELUDE = r"""
const calls = [];
let failWith = null;
async function api(path, opts) {
  calls.push({ path: path, method: opts.method, json: opts.json });
  if (failWith) throw failWith;
  return { id: 'new', supersedes: 'old' };
}
function cpath(p) { return '/api/v1/cases/C1' + p; }
function invalidateAnalytics() { calls.push('invalidate'); }
async function reloadAll() { calls.push('reload'); }
function banner(title, text) { calls.push({ banner: title, text: text }); }
function setMsg(n, t) { n.textContent = t || ''; n.hidden = !t; }
function refusalText(err, ctx) { return (err && err.detail) || ctx; }
"""


def _run(body: str, tmp_path: Path):
    assert "remove() { this.removed = true; }" in _DOM, "the stub DOM changed"
    script = tmp_path / "run.js"
    script.write_text(_DOM + _PRELUDE + "\n".join(_fn(n) for n in _SOURCES)
                      + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@needs_node
def test_the_form_checks_before_it_sends_and_sends_only_a_date_and_a_reason(
        tmp_path):
    got = _run(r"""
function open(a) {
  const card = mk('div');
  card.querySelector = () => null;
  openDateClaimForm(a, card);
  const form = card.children[0];
  return { card: card, form: form,
           when: form.children[0].children[1], why: form.children[1].children[1],
           go: form.children[2], cancel: form.children[3], msg: form.children[4] };
}
const submit = (f) => f.form.listeners.submit({ preventDefault() {} });
(async () => {
  const out = {};
  let f = open({ id: 'A1' });
  out.shape = { type: f.when.type, goType: f.go.type, hidden: f.msg.hidden,
                role: f.msg.attrs.role, novalidate: f.form.noValidate };
  await submit(f);
  out.empty = { msg: f.msg.textContent, calls: calls.length };
  f.when.value = '2999-01-01T00:00';
  await submit(f);
  out.future = { msg: f.msg.textContent, calls: calls.length };
  f.when.value = '2026-03-01T22:30';
  f.why.value = '   ';
  await submit(f);
  out.noReason = { msg: f.msg.textContent, calls: calls.length };
  f.why.value = '  Dated from the post header.  ';
  await submit(f);
  out.sent = { msg: f.msg.textContent, hidden: f.msg.hidden,
               calls: calls.slice() };
  calls.length = 0;
  failWith = { detail: 'This claim has been retracted, so it is history.' };
  f = open({ id: 'A2' });
  f.when.value = '2026-03-01T22:30';
  f.why.value = 'Dated from the post header.';
  await submit(f);
  out.refused = { msg: f.msg.textContent, reenabled: f.go.disabled === false,
                  calls: calls.length, path: calls[0].path };
  f.cancel.listeners.click();
  out.cancelled = f.form.removed === true;
  console.log(JSON.stringify(out));
})();
""", tmp_path)
    assert got["shape"] == {"type": "datetime-local", "goType": "submit",
                            "hidden": True, "role": "alert",
                            "novalidate": True}
    assert got["empty"] == {
        "msg": "Give the date and time the claim was true, in UTC.", "calls": 0}
    assert got["future"] == {
        "msg": "A claim cannot have been observed later than now.", "calls": 0}
    assert got["noReason"]["calls"] == 0
    assert got["noReason"]["msg"].startswith("Say why this date is the one.")
    sent = got["sent"]
    assert sent["hidden"] is True
    first = sent["calls"][0]
    assert first["path"] == "/api/v1/cases/C1/assertions/A1/supersede"
    assert first["method"] == "POST"
    # The date as UTC, and the reason trimmed: nothing else goes.
    assert first["json"] == {"observed_at": "2026-03-01T22:30:00.000Z",
                             "rationale": "Dated from the post header."}
    assert sent["calls"][1:3] == ["invalidate", "reload"]
    banner = sent["calls"][3]
    assert banner["banner"] == "Claim dated"
    assert "superseded, not changed" in banner["text"]
    assert got["refused"]["msg"] == (
        "This claim has been retracted, so it is history.")
    assert got["refused"]["reenabled"] is True and got["refused"]["calls"] == 1
    assert got["refused"]["path"].endswith("/assertions/A2/supersede")
    assert got["cancelled"] is True


@needs_node
def test_a_second_press_focuses_the_open_form_instead_of_adding_another(tmp_path):
    got = _run(r"""
const card = mk('div');
let focused = 0;
const existing = mk('form', 'date-claim');
const first = mk('input');
first.focus = () => { focused += 1; };
existing.children.push(first);
existing.querySelector = () => first;
card.querySelector = (sel) => sel === '.date-claim' ? existing : null;
openDateClaimForm({ id: 'A1' }, card);
console.log(JSON.stringify({ focused: focused, added: card.children.length }));
""", tmp_path)
    assert got == {"focused": 1, "added": 0}


@needs_node
def test_the_pure_helpers_say_what_they_promise(tmp_path):
    got = _run(r"""
console.log(JSON.stringify({
  ok: dateClaimProblem('2026-03-01T22:30', 'why'),
  nodate: dateClaimProblem('', 'why'),
  junk: dateClaimProblem('not a date', 'why'),
  body: dateClaimBody('2026-03-01T22:30', ' why '),
  help: dateClaimHelp(),
  done: dateClaimDoneWords(),
}));
""", tmp_path)
    assert got["ok"] is None
    assert got["nodate"] == got["junk"]
    assert got["body"] == {"observed_at": "2026-03-01T22:30:00.000Z",
                           "rationale": "why"}
    assert "Nothing is rewritten" in got["help"]
    assert "stays on record as it was" in got["help"]
    assert "superseded, not changed" in got["done"]
    for words in (got["help"], got["done"]):
        for bad in ("—", "–", " -- ", "(s)"):
            assert bad not in words


def test_the_button_is_offered_on_a_live_undated_claim_and_nowhere_else():
    render = _fn("renderAssertions")
    live = render.index("if (!dead) {")
    button = render.index("if (!a.observed_at) {")
    appended = render.index("card.appendChild(actions)")
    assert live < button < appended, (
        "Date this claim sits inside the live-claim actions row beside "
        "Retract, so a dead claim never offers it and a read-only case turns "
        "it off with Retract")
    block = render[button:appended]
    assert "'Date this claim'" in block
    assert "openDateClaimForm(a, card)" in block
    assert "actions.appendChild(dateBtn)" in block
    assert "dateClaimHelp()" in block


def test_a_card_names_the_claim_it_replaced_and_the_one_that_replaced_it():
    render = _fn("renderAssertions")
    assert "'replaced by claim ' + shortId(a.superseded_by)" in render
    assert "'replaces claim ' + shortId(a.supersedes_id)" in render


def test_the_form_posts_the_one_route_and_writes_text_never_markup():
    body = _fn("openDateClaimForm")
    assert "cpath('/assertions/' + a.id + '/supersede')" in body
    assert "json: dateClaimBody(when.value, why.value)" in body
    assert body.index("dateClaimProblem(when.value, why.value)") < body.index(
        "await api(")
    assert "innerHTML" not in body and "insertAdjacentHTML" not in body
    # The route the console calls is the route the server serves.
    assert re.search(r'"/assertions/\{assertion_id\}/supersede"',
                     ROUTER.read_text(encoding="utf-8"))
    assert _js().count("/supersede'") == 1

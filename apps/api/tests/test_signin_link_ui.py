"""A `#token=` link asks before it signs a browser in (http_ui-017; g45, 2026-10-03).

When the browser held no usable session the console exchanged whatever bearer
sat in the URL fragment for the cookie pair and opened the app, so a link
made by anybody holding any session token signed a signed-out colleague in as
the link's author, who can read everything the colleague then does. The page
now names the account the link carries (`GET /auth/me` with the handed-over
token, which signs nothing in) and signs in only on a yes.

The function is run under Node with its collaborators stubbed (skipped where
Node is not installed): the question, the refusal, the stale link, and the
cases that must NOT ask. The first-run card's setup token field
(http_ui-010) is held here too, because it is the same file.
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
_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    js = _js()
    start = js.index(f"function {name}(")
    if js[start - 6:start] == "async ":
        start -= 6
    return js[start:js.index("\n}", start) + 2]


HARNESS = """
class ApiError extends Error {
  constructor(status, title, detail) { super(title); this.status = status;
    this.title = title; this.detail = detail; }
}
const calls = [];
const confirms = [];
const state = { token: null, deepLinkTab: null, deepLinkCase: null };
const SCENARIO = __SCENARIO__;
function visibleText(s) { return s === null || s === undefined ? '' : String(s); }
function halfSession() { return !!SCENARIO.half; }
async function api(path, options) {
  const o = options || {};
  calls.push({ path, bearer: o.bearer || null, method: o.method || 'GET' });
  const answer = SCENARIO.answers[(o.bearer ? 'bearer:' : '') + path];
  if (answer && answer.error) throw new ApiError(answer.error, 't', answer.detail || 'd');
  if (answer && answer.network) throw new Error('boom');
  return answer ? answer.body : null;
}
const window = {
  location: { hash: SCENARIO.hash, pathname: '/ui/' },
  confirm(message) { confirms.push(message); return SCENARIO.yes; },
};
const history = { replaceState() {} };
"""


def _run(scenario: dict) -> dict:
    if not NODE:
        pytest.skip("Node is not installed here")
    script = HARNESS.replace("__SCENARIO__", json.dumps(scenario)) + "\n".join([
        _fn("signInLinkQuestion"), _fn("signInLinkRefused"),
        _fn("adoptSessionFromFragment"),
        """(async () => {
  const notice = await adoptSessionFromFragment();
  console.log(JSON.stringify({ notice, calls, confirms, token: state.token }));
})();"""])
    run = subprocess.run([NODE, "-"], input=script, capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


ME = {"user_id": "u-rae", "display_name": "Rae Analyst", "email": "rae@example.test"}
SIGNED_OUT = {"/auth/me": {"error": 401}}


def _paths(result):
    return [(c["path"], c["bearer"]) for c in result["calls"]]


def test_a_signed_out_browser_is_asked_about_the_account_by_name_and_signs_in_on_a_yes():
    got = _run({"hash": "#token=abc123&tab=feeds", "yes": True, "answers": {
        **SIGNED_OUT, "bearer:/auth/me": {"body": ME}, "bearer:/auth/cookie": {"body": None}}})
    assert got["notice"] is None
    assert got["token"] == "abc123"
    assert _paths(got) == [("/auth/me", None), ("/auth/me", "abc123"),
                           ("/auth/cookie", "abc123")]
    (question,) = got["confirms"]
    assert "Rae Analyst" in question and "rae@example.test" in question
    assert "recorded against that account" in question
    assert "abc123" not in question, "the token is in the dialog"


def test_a_no_signs_nothing_in_and_forgets_the_token():
    got = _run({"hash": "#token=abc123", "yes": False, "answers": {
        **SIGNED_OUT, "bearer:/auth/me": {"body": ME}}})
    assert got["token"] is None
    assert [c["path"] for c in got["calls"] if c["method"] == "POST"] == [], (
        "the exchange ran although the person said no")
    assert got["notice"]["title"] == "Sign-in link not used"
    assert got["notice"]["kind"] == "warn"
    assert "Rae Analyst" in got["notice"]["detail"]
    assert len(got["confirms"]) == 1


def test_a_stale_link_is_refused_without_a_question_and_without_the_exchange():
    got = _run({"hash": "#token=old", "yes": True, "answers": {
        **SIGNED_OUT, "bearer:/auth/me": {"error": 401}}})
    assert got["confirms"] == []
    assert not any(c["path"] == "/auth/cookie" for c in got["calls"])
    assert "expired or has already been used" in got["notice"]["detail"]
    assert got["token"] is None


def test_an_unreachable_api_is_reported_not_asked_about():
    got = _run({"hash": "#token=abc", "yes": True, "answers": {
        **SIGNED_OUT, "bearer:/auth/me": {"network": True}}})
    assert got["confirms"] == [] and got["notice"]["title"] == "Sign-in link not used"


def test_a_live_session_keeps_its_place_and_nothing_is_asked():
    got = _run({"hash": "#token=abc123", "yes": True, "answers": {"/auth/me": {"body": ME}}})
    assert got["confirms"] == []
    assert _paths(got) == [("/auth/me", None)], "a bearer was presented over a live session"
    assert got["notice"]["title"].startswith("Already signed in as Rae Analyst")


def test_repairing_the_same_accounts_half_session_asks_nothing_but_another_account_is_asked():
    same = _run({"hash": "#token=abc123", "yes": True, "half": True, "answers": {
        "/auth/me": {"body": ME}, "bearer:/auth/me": {"body": ME},
        "bearer:/auth/cookie": {"body": None}}})
    assert same["confirms"] == [] and same["notice"] is None
    assert ("/auth/cookie", "abc123") in _paths(same)
    other = {"user_id": "u-sam", "display_name": "Sam Other", "email": "sam@example.test"}
    asked = _run({"hash": "#token=abc123", "yes": False, "half": True, "answers": {
        "/auth/me": {"body": ME}, "bearer:/auth/me": {"body": other}}})
    assert len(asked["confirms"]) == 1 and "Sam Other" in asked["confirms"][0]
    assert not any(c["path"] == "/auth/cookie" for c in asked["calls"])


def test_no_token_means_no_calls_and_no_question():
    got = _run({"hash": "#tab=feeds", "yes": True, "answers": {}})
    assert got["calls"] == [] and got["confirms"] == [] and got["notice"] is None


def test_the_question_cannot_be_dressed_up_by_the_name_it_carries():
    """Both names go through `visibleText`, the console's one defence against
    a label that looks like something it is not."""
    body = _fn("signInLinkQuestion")
    assert body.count("visibleText(") >= 2
    assert "display_name" in body and "email" in body


def test_the_exchange_is_preceded_by_the_question_in_the_source():
    body = _fn("adoptSessionFromFragment")
    ask = body.index("window.confirm(signInLinkQuestion(")
    me = body.index("api('/auth/me', { bearer: token })")
    exchange = body.index("api('/auth/cookie'")
    assert me < ask < exchange, "the account is not named before the exchange"
    assert body.index("state.token = token") > ask, "the token is held before the person agreed"


def test_a_request_that_forces_its_own_bearer_judges_that_bearer_not_the_tab_session():
    fetch = _fn("_fetch")
    assert "_CREDENTIAL_CHECKS.has(path) && !o.bearer" in fetch
    # and the set itself is unchanged, as test_ui_invariants holds it
    m = re.search(r"const _CREDENTIAL_CHECKS = new Set\(\[([^\]]*)\]\);", _js())
    assert set(re.findall(r"'([^']+)'", m.group(1))) == {"/auth/login", "/auth/cookie"}


def test_the_security_note_says_the_link_asks():
    root = Path(__file__).resolve().parents[3]
    text = re.sub(r"\s+", " ", (root / "SECURITY.md").read_text(encoding="utf-8"))
    assert "only after it has named the account the link carries" in text


# ---------------------------------------------------------------------------
# http_ui-010: the first-run card asks for the token only when told to
# ---------------------------------------------------------------------------

def test_the_first_run_card_has_a_hidden_password_field_for_the_token():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    field = html[html.index('id="setup-token-field"'):]
    field = field[:field.index("</label>")]
    assert "hidden" in html[html.index('id="setup-token-field"') - 30:
                            html.index('id="setup-token-field"') + 40]
    assert 'id="setup-token"' in field and 'type="password"' in field
    assert 'autocomplete="off"' in field


def test_the_console_sends_the_token_in_the_header_only_when_there_is_one_and_never_keeps_it():
    js = _js()
    probe = _fn("probeFirstRun")
    assert "setup_token_required" in probe and "setup-token-field" in probe
    submit = js[js.index("$('setup-form').addEventListener('submit'"):]
    submit = submit[:submit.index("$('setup-hide')")]
    assert "'X-Setup-Token'" in submit
    assert "headers: token ? { 'X-Setup-Token': token } : undefined" in submit
    assert "$('setup-token').value = ''" in submit
    api = _fn("api")
    assert "Object.assign(headers, o.headers)" in api

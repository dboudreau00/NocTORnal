"""A `#token=` link stops holding the bearer once the cookie pair is in place.

The hand-off keeps the token in page memory while it exchanges it for the
cookie pair, because a browser that refuses Secure cookies runs on that token
alone. When the exchange succeeds and the readable CSRF cookie is there, the
HttpOnly cookie is the session: a token still in memory is readable to script
and goes out in the live socket's first frame for no reason. So the success
path drops it, and keeps it only where the CSRF cookie never arrived.

Runs the function under Node with its collaborators stubbed (skipped where
Node is not installed).
"""
from __future__ import annotations

import json
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
const state = { token: null, deepLinkTab: null, deepLinkCase: null };
const SCENARIO = __SCENARIO__;
function visibleText(s) { return s === null || s === undefined ? '' : String(s); }
function halfSession() { return false; }
function csrfCookie() { return SCENARIO.csrf || null; }
async function api(path, options) {
  const o = options || {};
  const answer = SCENARIO.answers[(o.bearer ? 'bearer:' : '') + path];
  if (answer && answer.error) throw new ApiError(answer.error, 't', 'd');
  return answer ? answer.body : null;
}
const window = {
  location: { hash: '#token=abc123', pathname: '/ui/' },
  confirm() { return true; },
};
const history = { replaceState() {} };
"""

ME = {"user_id": "u-rae", "display_name": "Rae Analyst", "email": "rae@example.test"}
ANSWERS = {"/auth/me": {"error": 401}, "bearer:/auth/me": {"body": ME},
           "bearer:/auth/cookie": {"body": None}}


def _run(csrf: str | None) -> dict:
    if not NODE:
        pytest.skip("Node is not installed here")
    scenario = {"csrf": csrf, "answers": ANSWERS}
    script = HARNESS.replace("__SCENARIO__", json.dumps(scenario)) + "\n".join([
        _fn("signInLinkQuestion"), _fn("signInLinkRefused"),
        _fn("adoptSessionFromFragment"),
        """(async () => {
  const notice = await adoptSessionFromFragment();
  console.log(JSON.stringify({ notice, token: state.token }));
})();"""])
    run = subprocess.run([NODE, "-"], input=script, capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


def test_the_bearer_is_dropped_when_the_csrf_cookie_landed():
    got = _run("csrf-value")
    assert got["notice"] is None
    assert got["token"] is None, (
        "the exchange succeeded and the cookie pair is in place, but the bearer "
        "is still in page memory and the live hello will send it")


def test_the_bearer_is_kept_when_the_browser_refused_the_secure_pair():
    got = _run(None)
    assert got["notice"] is None
    assert got["token"] == "abc123", (
        "without the CSRF cookie the in-memory token is the session")


def test_the_live_hello_still_sends_a_bearer_the_tab_holds():
    assert "if (state.token) hello.token = state.token;" in _fn("connectLive")

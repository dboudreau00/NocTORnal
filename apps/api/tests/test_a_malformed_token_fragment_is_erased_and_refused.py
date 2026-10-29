"""A `#token=` fragment with a broken percent-escape is still erased.

`decodeURIComponent` throws on a trailing `%`, a cut-short `%2` or a
non-hex `%GG`. If the decode runs first, the throw skips the history erase,
so the bearer stays in the address bar and the history entry, and the
rejection escapes `boot`, which then never shows the sign-in view. The
fragment is erased before the decode, and a bad escape comes back as a link
that was not used.

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
const calls = [];
const erased = [];
const state = { token: null, deepLinkTab: null, deepLinkCase: null };
const SCENARIO = __SCENARIO__;
function visibleText(s) { return s === null || s === undefined ? '' : String(s); }
function halfSession() { return false; }
function csrfCookie() { return null; }
async function api(path, options) {
  const o = options || {};
  calls.push({ path, bearer: o.bearer || null });
  if (path === '/auth/me' && !o.bearer) throw new ApiError(401, 't', 'd');
  return path === '/auth/me' ? { user_id: 'u', display_name: 'Rae' } : null;
}
const window = {
  location: { hash: SCENARIO.hash, pathname: '/ui/' },
  confirm() { return true; },
};
const history = { replaceState(_s, _t, url) { erased.push(url); } };
"""


def _run(hash_: str) -> dict:
    if not NODE:
        pytest.skip("Node is not installed here")
    script = HARNESS.replace("__SCENARIO__", json.dumps({"hash": hash_})) + "\n".join([
        _fn("signInLinkQuestion"), _fn("signInLinkRefused"),
        _fn("adoptSessionFromFragment"),
        """(async () => {
  let threw = null, notice = null;
  try { notice = await adoptSessionFromFragment(); } catch (e) { threw = String(e); }
  console.log(JSON.stringify({ notice, threw, calls, erased, token: state.token }));
})();"""])
    run = subprocess.run([NODE, "-"], input=script, capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


@pytest.mark.parametrize("hash_", ["#token=abc123%", "#token=abc123%GG", "#token=%2"])
def test_a_bad_escape_is_erased_and_reported_not_thrown(hash_):
    got = _run(hash_)
    assert got["threw"] is None, f"boot is rejected: {got['threw']}"
    assert got["erased"] == ["/ui/"], "the fragment with the bearer was not erased"
    assert got["notice"]["title"] == "Sign-in link not used"
    assert "URIError" not in got["notice"]["detail"]
    assert got["calls"] == [] and got["token"] is None


def test_a_well_formed_escape_is_still_decoded():
    got = _run("#token=abc%2Ddef")
    assert got["erased"] == ["/ui/"] and got["notice"] is None
    assert ("/auth/me", "abc-def") in [(c["path"], c["bearer"]) for c in got["calls"]]

"""Web Key Directory lookups in the console (F10c, comms, 2026-09-24).

The source is offered only when lookups are on and the case's own labels
let an address out; asking, approving and declining go through the step-up
gate (declining is also run under node when node is installed); the
exposure sentence is on screen before anyone asks and before anyone
approves; URLs are code, never links; a lookup that started and never
finished says the request may have left. Pure: reads the shipped static
assets.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    return js[m.start():js.index("\n}", m.start()) + 2]


def test_the_wkd_source_is_hidden_unless_lookups_are_on():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert re.search(r'<label id="comms-pgpkey-src-wkd-label" class="check" hidden>', html)
    assert re.search(r'<form id="comms-pgpkey-wkd-form"[^>]*hidden>', html)
    body = _fn("loadKeyDirectory")
    assert "const usable = d.enabled && !d.case_problem;" in body
    assert "show($('comms-pgpkey-src-wkd-label'), usable)" in body


def test_the_exposure_sentence_is_present():
    body = _fn("wkdExposure")
    assert "Its operator learns" in body
    assert "Nothing is sent until a second" in body
    assert "wkdExposure(l.domain)" in _fn("renderKeyLookup")


def test_asking_and_approving_go_through_step_up():
    assert "withStepUp(" in _fn("requestKeyLookup")
    assert "withStepUp(wkdExposure(l.domain)" in _fn("approveKeyLookup")


def test_every_lookup_write_goes_through_step_up():
    """comms.key.lookup and comms.key.lookup.approve are step-up
    permissions (0090), and all three POST routes need one of them.
    Decline once called api() bare, so a sign-in older than the
    window got "re-authentication required" and no identity prompt (F10c,
    2026-09-24). Every console function that posts to a lookup
    route wraps that call in withStepUp, including any added later."""
    js = _js()
    writers = []
    for m in re.finditer(r"^(?:async )?function (\w+)\(", js, flags=re.M):
        body = js[m.start():js.index("\n}", m.start()) + 2]
        call = body.find("api(cpath('/comms/pgp/key-lookups")
        if call < 0 or "method: 'POST'" not in body:
            continue
        writers.append(m.group(1))
        wrap = body.find("withStepUp(")
        assert 0 <= wrap < call, f"{m.group(1)} posts a lookup outside withStepUp"
    assert sorted(writers) == ["approveKeyLookup", "declineKeyLookup",
                               "requestKeyLookup"]


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    windows = r"C:\Program Files\nodejs\node.exe"
    return windows if os.path.isfile(windows) else None


# Stubs for what declineKeyLookup and withStepUp reach. `api` answers the
# server's own refusal ("re-authentication required", deps.py) until the
# identity prompt has been answered, which is what a sign-in older than the
# step-up window gets from the decline route.
_DECLINE_HARNESS = """
class ApiError extends Error {
  constructor(status, detail) { super(detail); this.status = status;
    this.detail = detail; this.title = 'Forbidden'; }
}
const SESSION = { stepUpUntil: 1 };
const calls = { confirm: 0, api: 0, loaded: 0, msgs: [], path: null, body: null };
let staleAtClick = false;
let answer = true;
function stepUpStale() { return staleAtClick; }
async function confirmIdentity(why) { calls.confirm += 1; calls.why = why;
  return answer; }
async function api(path, opts) {
  calls.api += 1; calls.path = path; calls.body = opts.json;
  if (calls.confirm === 0) throw new ApiError(403, 're-authentication required');
  return { state: 'DECLINED' };
}
function cpath(p) { return '/cases/c1' + p; }
function caseToken() { return 1; }
function caseChanged() { return false; }
function loadKeyLookups() { calls.loaded += 1; }
function failureReason(e) { return String(e); }
function el(tag, cls, text) { calls.msgs.push(text); return {}; }
const card = { appendChild() {} };
"""


def _run_decline(stale_at_click: bool, answer: bool) -> dict:
    script = (_DECLINE_HARNESS + _fn("withStepUp") + "\n"
              + _fn("declineKeyLookup") + f"""
staleAtClick = {str(stale_at_click).lower()};
answer = {str(answer).lower()};
declineKeyLookup({{ id: 'L1' }}, '  no longer needed  ', card)
  .then(() => console.log(JSON.stringify(calls)));
""")
    out = subprocess.run([_node(), "-e", script], capture_output=True,
                         text=True, check=True, timeout=30).stdout
    return json.loads(out)


@pytest.mark.skipif(_node() is None, reason="node is not installed")
def test_decline_with_a_stale_sign_in_asks_who_you_are_and_retries():
    """The stale sign-in case: the server says the sign-in is too old. The
    console asks for identity once, sends again, and reloads the list; no
    refusal is left on the card. Without withStepUp the 403 landed on the
    card as text and nobody was asked."""
    got = _run_decline(stale_at_click=False, answer=True)
    assert got["confirm"] == 1 and got["why"] == "Declining a key lookup"
    assert got["api"] == 2 and got["loaded"] == 1 and got["msgs"] == []
    assert got["path"] == "/cases/c1/comms/pgp/key-lookups/L1/decline"
    assert got["body"] == {"reason": "no longer needed"}


@pytest.mark.skipif(_node() is None, reason="node is not installed")
def test_decline_known_stale_asks_first_and_cancelling_sends_nothing():
    got = _run_decline(stale_at_click=True, answer=False)
    assert got["confirm"] == 1 and got["api"] == 0
    assert got["loaded"] == 0 and got["msgs"] == []


def test_urls_are_code_and_never_links():
    body = _fn("renderKeyLookup")
    assert "el('code', 'mono-sm', url)" in body
    assert "'a'" not in body and "href" not in body


def test_the_sending_state_says_the_request_may_have_left():
    js = _js()
    assert "SENDING: 'started and never finished: the request may have left'" in js


def test_approve_and_decline_carry_case_write():
    body = _fn("renderKeyLookup")
    assert "'btn small case-write pgpkey-lookup-approve'" in body
    assert "'btn ghost small case-write pgpkey-lookup-decline'" in body
    assert "if (l.can_approve)" in body


def test_the_wkd_form_is_a_case_content_control_and_cleared_on_switch():
    js = _js()
    controls = js[js.index("const CASE_CONTENT_CONTROLS = ["):]
    assert "'comms-pgpkey-wkd-form'" in controls[:controls.index("];")]
    resets = "".join(js[m.start():js.index("\n});", m.start())]
                     for m in re.finditer(r"\nonCaseSwitch\(\(\) => \{", js))
    for element in ("comms-pgpkey-lookups", "comms-pgpkey-wkd-address",
                    "comms-pgpkey-wkd-reason", "comms-pgpkey-wkd-msg"):
        assert f"'{element}'" in resets, element
    assert "show($('comms-pgpkey-src-wkd-label'), false);" in resets


def test_the_address_is_drawn_through_visibletext():
    body = _fn("renderKeyLookup")
    assert "visibleText(l.address)" in body and "visibleText(l.reason)" in body

"""The Feeds pane's replay target and the issued ingest key's secret
(final review r2, 2026-09-24: c19 console half, and u25).

- c19: the dead-letter "Repair and replay" form offered "This case" for
  every row and selected it, whatever case the row named, so with "All my
  feeds" ticked the ordinary submit moved a fragment from its own case
  into the open one. The server now refuses that move
  (`test_breakglass_ingest_export_pg.py`); the form offers a row's own
  cases and quarantine, and selects the row's own case.
- u25: the ingest key secret shown once under Feeds > Keys stayed on the
  screen through a case switch, a pane change and a Feeds subtab change,
  unlike the Admin card's one-time credentials, until the session ended.

Pure, like `test_ui_invariants.py`: these read the shipped static assets.
The check marked `needs_node` EXECUTES `replayTargets` under Node and
skips where Node is absent.
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
needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _code(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def _fn(name: str) -> str:
    """A top-level function's source, closed on the first column-0 `}`."""
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone; update this test with it"
    return js[m.start():js.index("\n}", m.start()) + 2]


# ---------------------------------------------------------------------------
# c19: a replay goes back into its own case or into quarantine
# ---------------------------------------------------------------------------

@needs_node
def test_the_replay_form_offers_a_rows_own_cases_and_never_the_open_one(
        tmp_path):
    rows = [
        # A row of case A, read while B is open ("All my feeds").
        ({"case_ids": ["A"], "unattached": False}, True),
        # A row of the open case.
        ({"case_ids": ["B"], "unattached": False}, True),
        # A batch that fed both: the open one is chosen.
        ({"case_ids": ["A", "B"], "unattached": False}, True),
        # Unattached: nothing to leave, so the open case, not chosen.
        ({"case_ids": [], "unattached": True}, True),
        # A reader who may not name a case: quarantine only.
        ({"case_ids": ["B"], "unattached": False}, False),
        ({"case_ids": [], "unattached": True}, False),
    ]
    script = tmp_path / "run.js"
    script.write_text(
        _fn("replayTargets") + "\n"
        "const open = { id: 'B', code: 'OP-B' };\n"
        "const codeOf = (id) => 'OP-' + id;\n"
        "console.log(JSON.stringify(" + json.dumps(rows)
        + ".map(([d, into]) => replayTargets(d, open, into, codeOf))));\n",
        encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout)
    quarantine = ["", "No case: quarantine"]
    assert got == [
        {"options": [["A", "OP-A"], quarantine], "value": "A"},
        {"options": [["B", "This case (OP-B)"], quarantine], "value": "B"},
        {"options": [["A", "OP-A"], ["B", "This case (OP-B)"], quarantine],
         "value": "B"},
        {"options": [["B", "This case (OP-B)"], quarantine], "value": ""},
        {"options": [quarantine], "value": ""},
        {"options": [quarantine], "value": ""},
    ]
    # The move the server refuses is never on offer: a row of A, read in
    # B, has no "This case" option at all.
    assert all(label != "This case (OP-B)" for _v, label in got[0]["options"])


def test_the_replay_form_takes_its_choice_from_replay_targets():
    row = _code(_fn("deadLetterRow"))
    assert "replayTargets(d, { id: state.caseId," in row
    assert "options: into.options, value: into.value" in row
    assert "(state.caseId || '')" not in row, (
        "the form still selects the open case for any row")
    # The record went to the case chosen, and the flash says which.
    assert "caseId === state.caseId ? ', in this case" in row
    assert "if (caseId && caseId === state.caseId) loadIngestQueue();" in row


# ---------------------------------------------------------------------------
# u25: the issued key's secret leaves with the tab, the pane and the case
# ---------------------------------------------------------------------------

def test_the_key_secret_is_cleared_by_one_function():
    fn = _code(_fn("clearKeySecret"))
    assert "clear($('key-secret-out'))" in fn
    js = _code(_js())
    assert re.search(r"(?m)^onCaseSwitch\(clearKeySecret\);$", js), (
        "a case switch leaves the issued key on the Keys tab")


def test_the_key_secret_leaves_with_the_feeds_pane():
    tab = _code(_fn("selectTab"))
    assert "if (name !== 'feeds') clearKeySecret();" in tab, (
        "leaving the Feeds pane leaves the issued key on it")


def test_the_key_secret_leaves_with_the_keys_subtab():
    ops = _code(_fn("initOpsPanes"))
    feeds = ops[ops.index("initSubtabs('pane-feeds'"):]
    feeds = feeds[:feeds.index("});")]
    assert re.search(
        r"if \(name === 'keys'\) loadKeys\(\);\s*else clearKeySecret\(\);",
        feeds), "another Feeds subtab leaves the issued key on the Keys tab"


def test_nothing_else_writes_the_key_secret():
    """One writer and the clearers, so a new path that shows the secret is
    a change this test makes somebody look at."""
    js = _code(_js())
    uses = re.findall(r"\$\('key-secret-out'\)", js)
    # renderKeySecret, clearKeySecret, clearSessionSecrets.
    assert len(uses) == 3, uses

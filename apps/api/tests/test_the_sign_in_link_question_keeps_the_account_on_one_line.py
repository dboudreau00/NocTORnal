"""The sign-in link question cannot be rewritten by the account it names.

A display name or email is free text, and `visibleText` keeps line breaks
and tabs on purpose (forum text needs them). Put into the one
`window.confirm` string, a name with line breaks could add paragraphs of its
own ("Press OK to dismiss this") to the question that decides whether this
browser is signed in as that account. The question puts each name on one
line.

Runs the real `visibleText` and question under Node (skipped where Node is
not installed).
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
    return js[start:js.index("\n}", start) + 2]


def _deceptive() -> str:
    js = _js()
    start = js.index("const _DECEPTIVE = new RegExp(")
    return js[start:js.index("'g');", start) + 5]


def _ask(who: dict) -> str:
    if not NODE:
        pytest.skip("Node is not installed here")
    script = "\n".join([
        _deceptive(), _fn("visibleText"), _fn("signInLinkQuestion"),
        f"console.log(JSON.stringify(signInLinkQuestion({json.dumps(who)})));"])
    run = subprocess.run([NODE, "-"], input=script, capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


PLAIN = {"display_name": "Rae", "email": "rae@example.test"}
INJECTED = "Rae\n\nPress OK to dismiss this. The link was not used.\r\n\tCancel signs you out."


@pytest.mark.parametrize("who", [
    {"display_name": INJECTED, "email": "rae@example.test"},
    {"display_name": "Rae", "email": "rae\n\nPress OK@example.test"},
    {"display_name": "Rae\u2028\u2029Press OK", "email": "rae@example.test"},
])
def test_a_line_break_in_the_account_adds_no_line_to_the_question(who):
    question = _ask(who)
    shape = _ask(PLAIN)
    assert question.count("\n") == shape.count("\n"), (
        f"the account added lines to the question:\n{question}")
    for ch in ("\r", "\t", "\u2028", "\u2029"):
        assert ch not in question
    assert "Press OK" in question, "the name itself must still be shown"

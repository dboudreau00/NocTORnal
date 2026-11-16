"""The words about a watch pattern's limits agree with the code that enforces them.

The docs and the module docstring state the three clocks a pattern runs under in
seconds. These tests hold every one of those figures to the constants, so changing a constant
without the words fails here. Pure: no database, no child process.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from noctornal_api import watch_regex

ROOT = Path(__file__).resolve().parents[3]
MODULE = Path(watch_regex.__file__)


def _figures() -> list[str]:
    return [f"{watch_regex.CHILD_CPU_S} seconds",
            f"{int(watch_regex.PATTERN_WALL_S + watch_regex.STARTUP_S)} seconds",
            f"{int(watch_regex.RUN_BUDGET_S)} seconds"]


def _docs_paragraph() -> str:
    text = (ROOT / "docs" / "04-collection.md").read_text(encoding="utf-8")
    start = text.index("**How a pattern is bounded.**")
    end = text.index("**Where it runs.**", start)
    return " ".join(text[start:end].split())


def _sentences() -> str:
    return " ".join(watch_regex._LIMIT_SENTENCES.values())


def test_the_docs_state_the_limits_the_code_enforces():
    docstring = " ".join((watch_regex.__doc__ or "").split())
    for name, text in (("docs/04", _docs_paragraph()), ("docstring", docstring)):
        for figure in _figures():
            assert figure in text, f"{name} does not say {figure}"


def test_every_constant_of_the_module_has_a_comment():
    lines = MODULE.read_text(encoding="utf-8").splitlines()
    tree = ast.parse("\n".join(lines))
    wanted = {"PATTERN_WALL_S", "STARTUP_S", "RUN_BUDGET_S", "CHILD_CPU_S"}
    seen = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in wanted:
                seen.add(name)
                assert lines[node.lineno - 2].startswith("#:"), name
    assert seen == wanted


def test_the_timeout_and_budget_sentences_keep_the_words_other_tests_and_operators_read():
    assert "did not finish within its time limit" in watch_regex._LIMIT_SENTENCES["timeout"]
    assert "was stopped" in watch_regex._LIMIT_SENTENCES["timeout"]
    assert "until its watch is edited or stopped" in watch_regex._LIMIT_SENTENCES["timeout"]
    assert "time for watch patterns" in watch_regex._LIMIT_SENTENCES["budget"]
    assert not re.search(r"\d", _sentences()), "figures belong in the docs, not in the sentences"


def test_the_new_copy_has_no_dash_and_no_bracketed_plural():
    for name, text in (("docstring", watch_regex.__doc__ or ""), ("sentences", _sentences()),
                       ("docs/04", _docs_paragraph())):
        assert "\u2014" not in text and "\u2013" not in text, name
        assert "(s)" not in text, name

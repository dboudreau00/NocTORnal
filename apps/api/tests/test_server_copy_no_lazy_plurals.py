"""No count in anything the server says is hedged with a bracketed plural.

The console prints a great deal of server text verbatim (an error's
detail, a notice, a note, an audit or readiness evidence line, a purge
warning), and the README screenshot set review (2026-09-23) found counts
hedged with a bracketed "s" in it: the soft-delete note's incident edges,
the unregistered-compartment refusal, the boot refusal's problem count,
bootstrap's recovery codes. The number is known when each line is
written, so the line agrees with it: `noctornal_api.wording.count_of` and
`agree`, or an inline choice where a module imports nothing of the
application's.

The rule, read exactly as `test_server_copy_no_dashes.py` reads the dash
rule (and with its reader): no string literal under `noctornal_api`, and
none in scripts/bootstrap.py, holds a bracketed plural ending, unless the
allow-list below names it. A docstring, or a note written under an
assignment, is never seen by a reader and is skipped, as comments are;
everything else is checked, the literal parts of an f-string included.
A log line is checked too: an operator reads it.

The allow-list names notify_events.py's merge notifications. That module
was being changed elsewhere when this pass ran and was not this pass's to
edit. Each entry is keyed on the module and the exact literal, so no new
sentence can shelter under it, and fails as stale once the line agrees.
bootstrap.py has no allow-list: its messages are the product's first
words.

Pure: parses the source and imports two small modules; no database.
"""
from __future__ import annotations

import ast
import re

import pytest

from test_server_copy_no_dashes import BOOTSTRAP, SRC, _statement_strings

#: The bracket, built rather than typed so this file does not carry the
#: hedge it forbids.
B = "(" + "s)"

#: A bracketed plural ending straight after a word, or at the start of an
#: f-string's literal part (after `{noun}`).
HEDGE = re.compile(r"(?:^|\w)\((?:s|es|ies|y/ies|is/es)\)")

_WHY_NOTIFY = (
    "a merge notification in notify_events.py, which was being changed "
    "elsewhere on 2026-09-23 and was not the plural pass's to edit; drop "
    "the entry when the line agrees")

#: (module path under noctornal_api, exact literal) -> why it may keep
#: its hedge.
_ALLOWED: dict[tuple[str, str], str] = {
    ("notify_events.py", " relationship" + B + ". Sign in to review it."):
        _WHY_NOTIFY,
    ("notify_events.py", " relationship" + B + "."): _WHY_NOTIFY,
    ("notify_events.py", " relationship" + B + " BETWEEN the two were "
     "destroyed rather than moved: a tie from an entity to itself means "
     "nothing, so the merge retired it. Reversing the merge brings it "
     "back."): _WHY_NOTIFY,
    ("notify_events.py", " relationship" + B + " were restored to their "
     "original endpoints.\n\nReason given: "): _WHY_NOTIFY,
}


def hedged_literals(source: str) -> list[tuple[int, str]]:
    """(line, text) of every string literal a reader could meet that
    hedges a plural."""
    tree = ast.parse(source)
    skip = _statement_strings(tree)
    return sorted(
        (node.lineno, node.value) for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and id(node) not in skip and HEDGE.search(node.value))


def _found() -> list[tuple[str, int, str]]:
    found = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        for line, text in hedged_literals(path.read_text(encoding="utf-8")):
            found.append((rel, line, text))
    return found


# ---------------------------------------------------------------------------
# The reader is proved on known input first
# ---------------------------------------------------------------------------

_SAMPLE = f'''
"""Module docstring, 3 edge{B}, skipped."""
# a comment, 3 edge{B}, skipped
X = 1
"""A note under an assignment, 3 edge{B}, skipped."""


def f(n, noun):
    """Function docstring, 3 edge{B}, skipped."""
    plain = "3 edge{B} caught"
    log.warning("%d refusal{B} since the last line", n)
    return f"{{n}} fragment{B} caught", f"{{noun}}{B} caught", plain


class C:
    """Class docstring, 3 edge{B}, skipped."""
    label = "the hypothes(is/es) caught"
    fine = "3 edges, 1 edge, (see below) and an http link"
'''


def test_the_reader_skips_what_no_reader_sees_and_catches_the_rest():
    texts = [text for _, text in hedged_literals(_SAMPLE)]
    assert texts == [
        f"3 edge{B} caught", f"%d refusal{B} since the last line",
        f" fragment{B} caught", f"{B} caught", "the hypothes(is/es) caught",
    ], texts


# ---------------------------------------------------------------------------
# The rule itself
# ---------------------------------------------------------------------------

def test_no_server_string_hedges_a_plural():
    offenders = [(rel, line, text[:120]) for rel, line, text in _found()
                 if (rel, text) not in _ALLOWED]
    assert not offenders, (
        "a count hedged with a bracketed plural in server copy; agree it "
        "with noctornal_api.wording.count_of or agree: "
        + repr(offenders[:20]))


def test_the_allow_list_names_only_literals_that_still_need_it():
    """An exemption outliving its literal is a hole for the next one."""
    present = {(rel, text) for rel, _, text in _found()}
    stale = [key for key in _ALLOWED if key not in present]
    assert not stale, stale


def test_bootstrap_hedges_nothing():
    """No allow-list: the operator's first words from the product."""
    found = hedged_literals(BOOTSTRAP.read_text(encoding="utf-8"))
    assert not found, found


# ---------------------------------------------------------------------------
# What a few of the rewritten lines say
# ---------------------------------------------------------------------------

def test_the_helpers_choose_by_the_number():
    from noctornal_api.wording import agree, count_of
    assert count_of(1, "fragment", "fragments") == "1 fragment"
    assert count_of(0, "fragment", "fragments") == "0 fragments"
    assert count_of(3, "fragment", "fragments") == "3 fragments"
    assert (agree(1, "is", "are"), agree(2, "is", "are")) == ("is", "are")


@pytest.mark.parametrize("length,noun", [(1, "1 byte"), (5, "5 bytes")])
def test_a_short_envelope_is_counted_in_agreement(length, noun):
    from noctornal_api.security.envelope import MalformedBlob
    message = str(MalformedBlob(length))
    assert message.startswith(f"not an envelope: {noun} cannot hold"), message


def test_the_boot_refusal_counts_its_problems_in_agreement():
    """A production environment with nothing set fails several rules at
    once, and the closing line counts them without a hedge."""
    from noctornal_api.config import enforce_environment, verify_environment
    env = {"NOCTORNAL_ENV": "production"}
    problems = verify_environment(env)
    assert len(problems) > 1, problems
    with pytest.raises(RuntimeError) as refused:
        enforce_environment(env)
    message = str(refused.value)
    assert f"All {len(problems)} problems found are listed above." in message
    assert not HEDGE.search(message), message

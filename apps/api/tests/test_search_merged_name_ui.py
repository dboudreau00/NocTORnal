"""The Search pane says when a hit was found by a merged record's name
(final review U10, 2026-09-23).

Pure: no database, no browser, like test_ui_invariants.py beside it. The
server half is test_a_merged_records_own_name_finds_its_survivor and
test_a_merged_name_ranks_and_is_named_only_when_it_says_more in
test_search_selectors_pg.py. Since the fix a merged record's own name
finds its live survivor, whose label does not contain the query; a hit
like that with no line under it is a result nobody trusts, which is the
reason the selector `via` line exists at all.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")


def _function(name: str) -> str:
    """A top-level function's text, up to the first `}` at column 0."""
    js = (STATIC / "app.js").read_text(encoding="utf-8").replace("\r\n", "\n")
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    return js[m.start():js.index("\n}", m.start())]


def test_a_hit_found_by_a_merged_records_name_says_so():
    body = _function("viaLine")
    assert "hit.merged_name" in body, (
        "the server names the merged record whose name matched and the "
        "pane does not print it")
    assert "visibleText(hit.merged_name)" in body, (
        "a merged record's label is a label like any other and is "
        "de-fanged before it is drawn (CR14)")
    assert "'via the name of merged record '" in body
    # Before the early return for a hit with no selector, or a survivor
    # found only by the name would still say nothing.
    assert body.index("hit.merged_name") < body.index("if (!v) return ''")
    # And before the "the name already says why" check: the server names
    # the merged record when its exact name outranks a partial match of
    # the survivor's own, and "ember_hobby" at 1.000 for the query "ember"
    # needs the line that says the 1.000 came from the merged record
    # (verifier of the U10 fix, 2026-09-23).
    assert body.index("hit.merged_name") < body.index("const inName")


def test_the_merged_name_line_has_no_em_or_en_dash():
    body = _function("viaLine")
    line = body[body.index("hit.merged_name"):body.index("if (!v) return ''")]
    assert "\u2014" not in line and "\u2013" not in line

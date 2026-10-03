"""egress-ledger-withheld-oracle, wording left behind (verification of the
review of 2026-10-03).

The server now counts the connection log's withheld rows over the WHOLE log,
whatever route, event or window the reader asked about. The console still
printed `and N rows you are not cleared to see` under a list the reader had
filtered, which reads as N hidden rows that match the filter, the figure the
fix exists to stop being. The sentence now says the count is the whole log's
and ignores the filter.

Static, in the test_ui_egress.py style: no browser, no database.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api" / "http" / "static")
HTML = (STATIC / "index.html").read_text(encoding="utf-8")
JS = (STATIC / "app.js").read_text(encoding="utf-8")


def _loader() -> str:
    """The function, with adjacent string literals joined so a sentence split
    across source lines reads as one."""
    start = JS.index("async function loadEgressLog(")
    return re.sub(r"'\s*\+\s*'", "", JS[start:JS.index("\nfunction egressLogRow(", start)])


def test_the_footer_says_the_hidden_count_is_the_whole_logs_not_the_filters():
    text = _loader()
    assert "'The whole log also holds '" in text
    assert "That count ignores the route and event chosen above." in text
    # The old reading, a count that looks narrowed by the filter, is gone.
    assert "'and ' + countOf(body.withheld" not in text


def test_the_help_line_above_the_log_says_the_count_is_over_the_whole_log():
    start = HTML.index("<h2 class=\"h-sm\">Connection log</h2>")
    help_line = " ".join(HTML[start:HTML.index("</p>", start)].split())
    assert "counted over the whole log, not shown" in help_line


def test_no_dash_or_hedged_plural_in_the_new_wording():
    text = _loader() + HTML[HTML.index("<h2 class=\"h-sm\">Connection log</h2>"):][:400]
    for ch in (chr(0x2014), chr(0x2013)):
        assert ch not in text
    assert " " + "-" * 2 + " " not in text

"""The case list does not scroll the page sideways on a phone (2026-10-08).

docs/17 "the case list at 375 px": the page scrolled sideways by 280 to 390px
on a phone-width window while the panes inside a case did not, and the cause
was not isolated. It was measured in a browser (headless Chromium at 320, 375,
414, 600 and 768px, the page's `scrollWidth` against the window's): the
document was 741px wide at 375px. The one element that reached that far is
`<span class="sr-only">Open</span>`, the visually hidden heading of the last
column of the case table. `.sr-only` is `position: absolute`, the table sits in
a `.scroll-x` box whose `overflow-x: auto` is meant to hold it, and an
absolutely positioned element is clipped by an overflow box only when the box
is, or sits inside, its containing block. `.scroll-x` was not positioned, so
nothing was: the span (at the table's 740th pixel) was laid out against the
page and grew the page itself. `.scroll-x { position: relative }` makes the
box the containing block, and the page is the window's width at every width
measured.

A stylesheet cannot be laid out here, so these pin the three facts the fix
rests on: what is hidden is absolutely positioned, the case list's table is
inside a `.scroll-x` box, and that box is positioned.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")


def _text(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8").replace("\r\n", "\n")


def _rule(css: str, selector: str) -> str:
    match = re.search(rf"(?m)^{re.escape(selector)}\s*\{{([^}}]*)\}}", css)
    assert match, f"no rule for {selector}"
    return match.group(1)


def test_what_is_visually_hidden_is_absolutely_positioned():
    """If `.sr-only` stops being absolute the fix below is not needed; if it
    stays, a box that clips a table must contain it."""
    assert re.search(r"position:\s*absolute", _rule(_text("app.css"), ".sr-only"))


def test_the_scroll_box_around_a_table_is_the_containing_block_of_what_is_hidden_in_it():
    rule = _rule(_text("app.css"), ".scroll-x")
    assert re.search(r"position:\s*relative", rule), (
        "an absolutely positioned descendant of .scroll-x is laid out against "
        "the page, so a hidden heading past the phone's width scrolls the page")
    assert re.search(r"overflow-x:\s*auto", rule) and "max-width: 100%" in rule


def test_the_case_list_table_sits_in_a_scroll_box_and_has_the_hidden_heading_that_did_it():
    html = _text("index.html")
    at = html.index('<table class="table" id="cases-table">')
    assert html[:at].rstrip().endswith('<div class="scroll-x">'), (
        "the case table is not directly inside a .scroll-x box")
    table = html[at:html.index("</table>", at)]
    assert '<th scope="col"><span class="sr-only">Open</span></th>' in table

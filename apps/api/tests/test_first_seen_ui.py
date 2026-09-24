"""The entity list and the inspector show the derived first and last seen.

gap-first-seen (decided 2026-09-23): the server derives an entity's first
and last seen from its live claims' observed times
(`test_first_seen_pg.py`), so the entity list's First seen column fills
and the inspector's line has dates to show. This pins the console half:
the inspector says the window once, in one phrase, and says a lone
sighting once rather than twice; the list's cell says where its date comes
from. Pure: the `needs_node` tests EXECUTE the shipped functions.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

API = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
APP_JS = API / "http" / "static" / "app.js"

_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)
needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

EM, EN = chr(0x2014), chr(0x2013)


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _function(name: str) -> str:
    js = _js()
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}", start) + 2]


def _const(name: str) -> str:
    js = _js()
    start = js.index(f"const {name} =")
    return js[start:js.index(";", start) + 1]


def test_the_inspector_line_says_the_window_in_one_phrase():
    """The line is painted from the server's window as the entity opens,
    in this phrase, and again from the claims once they arrive
    (`paintSeen`, test_inspector_entry_ui.py)."""
    inspector = _function("renderInspector")
    assert "sub.textContent = nodeSubLine(n, null);" in inspector
    assert "seenPhrase(n.first_seen, n.last_seen)" in _function("seenWords")
    assert "' · first seen ' + fmtWhen(n.first_seen)" not in inspector


def test_the_entity_list_cell_says_where_its_date_comes_from():
    rows = _function("renderEntities")
    # Still quiet when absent (README screenshot review, 2026-09-23).
    assert "n.first_seen ? 'num' : 'num absent'" in rows
    assert "'The earliest observed time among its live claims'" in rows
    assert "'No live claim records when it was observed'" in rows
    # A property, never an inline style: the CSP drops those silently.
    assert "tdSeen.title = " in rows and "tdSeen.style" not in rows


REPO = API.parents[3]


def test_no_shipped_text_still_says_first_seen_is_never_filled():
    """Verifier round on gap-first-seen, 2026-09-23. The showcase seeder's
    "What is NOT here" still said that no service writes
    `core.node.first_seen`, so the First seen column stays "not recorded".
    The derivation made that false, and a seeder's docstring is the first
    thing a reader copies. Whitespace is flattened so a phrase wrapped
    across lines is still found."""
    stale = ('First seen column stays "not recorded"',
             "no service writes it")
    paths = [*(REPO / "scripts").glob("*.py"), *API.rglob("*.py"), APP_JS,
             *(REPO / "docs").glob("*.md")]
    assert len(paths) > 50, "the scan found the tree"
    for path in paths:
        flat = " ".join(path.read_text(encoding="utf-8").split())
        for phrase in stale:
            assert phrase not in flat, f"{path.name} still says: {phrase}"
    seeder = (REPO / "scripts" / "seed_readme_showcase.py").read_text(
        encoding="utf-8")
    # The seeder says instead where its column's dates come from.
    assert "`projections.seen_sql`" in seeder


@needs_node
def test_the_phrase_for_each_window(tmp_path):
    sources = [_const("MONTHS"), _const("NO_TIME"), _function("pad2"),
               _function("fmtTime"), _function("fmtDate"), _function("fmtWhen"),
               _function("seenPhrase")]
    script = tmp_path / "run.js"
    script.write_text("\n".join(sources) + """
console.log(JSON.stringify([
  seenPhrase(null, null),
  seenPhrase('2025-03-01T00:00:00Z', '2025-03-01T00:00:00Z'),
  seenPhrase('2025-01-05T09:30:00Z', '2025-08-27T17:00:00Z'),
  seenPhrase('2025-03-01T00:00:00Z', null),
]));
""", encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    none, once, span, half = json.loads(out.stdout)
    assert none == "no claim records when it was observed"
    assert once == "seen 1 Mar 2025", "one sighting is said once"
    assert span == ("first seen 2025-01-05 09:30 UTC, "
                    "last seen 2025-08-27 17:00 UTC")
    assert half == "seen 1 Mar 2025"
    for phrase in (none, once, span, half):
        assert EM not in phrase and EN not in phrase and " -- " not in phrase

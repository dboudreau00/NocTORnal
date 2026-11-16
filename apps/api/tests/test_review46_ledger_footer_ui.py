"""The connection log's footer says only that some rows are withheld, and the console says so.

The server once counted the connection log's withheld rows over the WHOLE log, and the footer printed the
number. One number for the whole log, polled and subtracted, still told a reader below a label when hidden
rows arrived and roughly how many, so the server now answers `some_withheld`, a flag, and the footer says
only that the log holds rows the reader is not cleared to see. It must still not read as hidden rows that
match the filter, so it says the notice is the whole log's whatever route and event are chosen. Verify the
chain is sent no row count by a server that withholds rows from its reader, and says every row was checked.

Static, in the test_ui_egress.py style, and the loader itself under node against a stand-in DOM. No
browser, no database.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from test_ui_copy_no_dashes import NODE, needs_node

STATIC = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api" / "http" / "static")
HTML = (STATIC / "index.html").read_text(encoding="utf-8")
JS = (STATIC / "app.js").read_text(encoding="utf-8")


def _loader() -> str:
    """The function, with adjacent string literals joined so a sentence split
    across source lines reads as one."""
    start = JS.index("async function loadEgressLog(")
    return re.sub(r"'\s*\+\s*'", "", JS[start:JS.index("\nfunction egressLogRow(", start)])


def _fn(name: str) -> str:
    """A top-level function or const of app.js, closed at its first column-0 `}` or `;`."""
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", JS, flags=re.M)
    if m:
        return JS[m.start():JS.index("\n}", m.start()) + 2]
    m = re.search(rf"^const {re.escape(name)} = ", JS, flags=re.M)
    assert m, f"app.js has no top-level {name}"
    return JS[m.start():JS.index(";\n", m.start()) + 2]


_DOM = r"""
const nodes = {};
function $(id) {
  return nodes[id] || (nodes[id] = { id, hidden: true, textContent: '', className: '',
                                     value: '', disabled: false });
}
function show(n, on) { n.hidden = !on; }
function setMsg(n, text) { n.textContent = text || ''; n.hidden = !text; }
function listPending() {}
function showLoadFailure() { throw new Error('the read failed'); }
function renderList() {}
function egressLogRow() { return null; }
class ApiError extends Error {}
let answer = null;
async function api() { return answer; }
"""


def _run(scenario: str) -> dict:
    script = (_DOM + "".join(_fn(n) for n in ("NO_TIME", "pad2", "fmtTime", "countOf",
                                               "loadEgressLog", "verifyEgressLog"))
              + "(async () => {\n" + scenario + "\n})().catch((e) => { console.error(e); "
              "process.exit(1); });\n")
    res = subprocess.run([NODE, "-"], input=script, capture_output=True, text=True,
                         encoding="utf-8", timeout=60)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


def test_the_footer_says_rows_are_withheld_and_names_no_number():
    text = _loader()
    assert "'The log also holds rows you are not cleared to see, which are not shown or counted. " \
           "This notice is about the whole log, whatever route and event are chosen above.'" in text
    # The count, and the sentences that printed it, are gone.
    assert "body.withheld" not in text and "countOf(" not in text
    assert "The whole log also holds" not in text


def test_the_help_line_above_the_log_says_hidden_rows_are_not_counted():
    start = HTML.index("<h2 class=\"h-sm\">Connection log</h2>")
    help_line = " ".join(HTML[start:HTML.index("</p>", start)].split())
    assert ("Rows you are not cleared to see are not shown or counted: the log says only "
            "that some exist.") in help_line
    assert "counted over the whole log" not in help_line


@needs_node
def test_the_notice_is_hidden_when_nothing_is_withheld():
    got = _run("""
const out = {};
const box = $('egr-log-hidden');
box.hidden = false; box.textContent = 'left from the last answer';
answer = { rows: [], some_withheld: false };
await loadEgressLog();
out.none = { hidden: box.hidden, text: box.textContent };
answer = { rows: [], some_withheld: true };
await loadEgressLog();
out.some = { hidden: box.hidden, text: box.textContent };
// An older server's count is not read as the flag.
answer = { rows: [], withheld: 7 };
await loadEgressLog();
out.count = { hidden: box.hidden, text: box.textContent };
console.log(JSON.stringify(out));
""")
    assert got["none"] == {"hidden": True, "text": ""}
    assert got["some"]["hidden"] is False
    assert got["some"]["text"].startswith("The log also holds rows you are not cleared to see")
    assert not re.search(r"\d", got["some"]["text"])
    assert got["count"] == {"hidden": True, "text": ""}


@needs_node
def test_verify_without_a_count_says_every_row_was_checked():
    got = _run("""
const out = {};
const box = $('egr-log-verified');
answer = { rows: null, first_break_seq: null, checked_at: '2026-11-15T10:00:00+00:00' };
await verifyEgressLog();
out.withheld = { cls: box.className, text: box.textContent };
answer = { rows: 12, first_break_seq: null, checked_at: '2026-11-15T10:00:00+00:00' };
await verifyEgressLog();
out.counted = box.textContent;
answer = { rows: null, first_break_seq: 7, checked_at: '2026-11-15T10:00:00+00:00' };
await verifyEgressLog();
out.broken = { cls: box.className, text: box.textContent };
console.log(JSON.stringify(out));
""")
    assert got["withheld"] == {"cls": "msg ok",
                               "text": "The chain holds: every row checked at 2026-11-15 10:00:00 UTC."}
    assert "null" not in got["withheld"]["text"]
    assert got["counted"] == "The chain holds: 12 rows checked at 2026-11-15 10:00:00 UTC."
    assert got["broken"]["cls"] == "msg bad"
    assert got["broken"]["text"].startswith("The chain breaks at row 7:")


def _verifier() -> str:
    start = JS.index("async function verifyEgressLog(")
    return re.sub(r"'\s*\+\s*'", "", JS[start:JS.index("\nfunction initEgress(", start)])


def test_no_dash_or_hedged_plural_in_the_new_wording():
    text = (_loader() + _verifier()
            + HTML[HTML.index("<h2 class=\"h-sm\">Connection log</h2>"):][:400])
    for ch in (chr(0x2014), chr(0x2013)):
        assert ch not in text
    assert " " + "-" * 2 + " " not in text
    assert "(s)" not in text

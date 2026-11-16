"""The saved report is a table of forum data, and forum data must not be able to rearrange it.

`render_markdown` puts node labels, tie endpoints, exhibit titles, assumptions and hypothesis statements
into pipe tables, and a label is only checked for being blank. A collected handle "x | RED" would shift
every later cell one column right, so the saved TLP:GREEN file would say that entity was RED; a handle
holding a newline would end its row and print "**TLP:CLEAR**" on a line of its own partway through an AMBER
document.

Also here, because they are pure: the hypothesis half of the redaction statement and its section.

Pure: builds `Report` objects directly; no database.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

HOSTILE_LABELS = (
    "x | RED",
    "evil\n\n**TLP:CLEAR**",
    "carriage\rreturn",
    "unicode\u2028line\u2029breaks\x85too",
    "a\\|b",
    "tail\\",
    "||",
)
PLAIN_BACKSLASHES = "C:\\evidence\\capture.txt"


def _redaction(**kw):
    from noctornal_api.reports import Redaction
    # Under COUNT, the setting whose statement states the figures it is given; a Redaction built by hand
    # says nothing of them otherwise.
    base = dict(built_at_tlp="AMBER", ceiling_tlp="AMBER", case_tlp="AMBER",
                nodes_withheld=0, edges_withheld=0, evidence_withheld=0,
                disclosure="COUNT")
    base.update(kw)
    return Redaction(**base)


def _report(labels=HOSTILE_LABELS, **redaction):
    from noctornal_api.reports import Report
    actors = [{"id": f"n{i}", "type": "IDENTITY", "label": label,
               "classification": "GREEN", "has_evidence": False}
              for i, label in enumerate(labels)]
    actors.append({"id": "plain", "type": "IDENTITY",
                   "label": PLAIN_BACKSLASHES, "classification": "GREEN",
                   "has_evidence": True})
    relationships = [{"type": "COMMUNICATES_WITH", "src": f"n{i}",
                      "dst": "plain", "sign": 1, "confidence": "LOW",
                      "inferred": False, "has_evidence": False}
                     for i in range(len(labels))]
    evidence = [{"id": f"e{i}", "title": label, "sha256": "ab" * 32,
                 "blake3": None, "media_type": "text/plain", "byte_size": 1,
                 "acquired_at": "2026-09-01T00:00:00+00:00",
                 "acquisition_method": "MANUAL_UPLOAD", "classification": "GREEN",
                 "purged_at": "2026-09-02T00:00:00+00:00" if i % 2 else None}
                for i, label in enumerate(labels)]
    assumptions = [{"statement": label, "basis": label, "status": "OPEN",
                    "made_by_name": label, "made_at": "2026-09-01",
                    "reviewed_at": "2026-09-02", "review_note": label}
                   for label in labels]
    hypotheses = {"method": "Ranked by inconsistency.", "warnings": [],
                  "hypotheses": [{"id": f"h{i}", "statement": label,
                                  "inconsistency": 0.0, "support": 1.0,
                                  "assessed": 1, "unassessed": 0}
                                 for i, label in enumerate(labels)]}
    case = {"id": "c", "code": "OP-X\n**TLP:CLEAR**",
            "title": "Title | with a pipe\nand a line",
            "summary": None, "status": None, "classification": "AMBER",
            "legal_basis": "order\n\n**TLP:CLEAR**", "authority_ref": None,
            "retention_until": None, "review_due": None, "opened": None}
    return Report(case=case, redaction=_redaction(**redaction),
                  summary={"entities": len(actors), "relationships": len(labels),
                           "exhibits": len(labels), "truncated": False,
                           "computed_over": "the redacted graph"},
                  actors=actors, relationships=relationships, evidence=evidence,
                  hypotheses=hypotheses, assumptions=assumptions)


def _cells_lookbehind(row: str) -> list[str]:
    """How cmark-gfm and markdown-it split a row: a "|" is a delimiter
    unless the character before it is a backslash."""
    return re.split(r"(?<!\\)\|", row)[1:-1]


def _cells_counting(row: str) -> list[str]:
    """How a renderer that honours backslash escapes one by one splits it:
    a backslash escapes the next character, whatever it is."""
    cells, current, i = [], "", 0
    while i < len(row):
        ch = row[i]
        if ch == "\\" and i + 1 < len(row):
            current += row[i:i + 2]
            i += 2
            continue
        if ch == "|":
            cells.append(current)
            current = ""
        else:
            current += ch
        i += 1
    cells.append(current)
    return cells[1:-1]


def _table(document: str, header: str) -> list[str]:
    lines = document.split("\n")
    start = lines.index(header)
    rows = []
    for line in lines[start + 2:]:
        if not line.startswith("|"):
            break
        rows.append(line)
    return rows


_TABLES = {
    "| Type | Label | TLP | Evidenced |": 4,
    "| From | Relationship | To | Sign | Confidence | Evidenced |": 6,
    "| Title | SHA-256 | Acquired | Method |": 4,
    "| Assumption | Basis | Status | Made by | Reviewed |": 5,
    "| Hypothesis | Status | Inconsistency | Support | Assessed |": 5,
}


def test_no_value_can_move_a_column():
    from noctornal_api.reports import render_markdown
    document = render_markdown(_report())
    for header, width in _TABLES.items():
        rows = _table(document, header)
        assert rows, f"no rows under {header}"
        for row in rows:
            for split in (_cells_lookbehind, _cells_counting):
                assert len(split(row)) == width, (
                    f"{split.__name__} reads {len(split(row))} cells, not "
                    f"{width}, in {row!r}")


def test_the_entity_s_own_tlp_column_still_says_its_classification():
    """"x | RED" must not make the TLP column read RED."""
    from noctornal_api.reports import render_markdown
    rows = _table(render_markdown(_report()), "| Type | Label | TLP | Evidenced |")
    hostile = next(r for r in rows if "x \\| RED" in r)
    for split in (_cells_lookbehind, _cells_counting):
        assert split(hostile)[2].strip() == "GREEN"


def test_no_value_can_start_a_line_of_its_own():
    """A newline, a carriage return or a Unicode line separator in a label does not end the row, so the
    only handling marks on their own lines are the document's."""
    from noctornal_api.reports import render_markdown
    document = render_markdown(_report())
    assert document.split("\n") == document.splitlines(), (
        "a value carried a line break other than the document's own")
    marks = [ln for ln in document.split("\n") if ln.strip() == "**TLP:CLEAR**"]
    assert marks == [], "a label printed a handling mark on a line of its own"
    assert document.split("\n")[0].startswith("# TLP:AMBER")
    assert document.rstrip().endswith("**TLP:AMBER**")


def test_text_without_a_pipe_is_left_byte_for_byte():
    """The document has to stay greppable: escaping is only where a pipe
    forces it."""
    from noctornal_api.reports import render_markdown
    document = render_markdown(_report())
    assert f"| {PLAIN_BACKSLASHES} |" in document
    assert "tail\\ |" in document


def test_rendering_leaves_the_report_itself_alone():
    """The escaping works on copies. `as_dict` hands back the report's own
    lists, and the digest the console compares is computed over them, so
    escaping in place would make the preview and the cleared file two
    different documents."""
    from noctornal_api.reports import content_digest, render_markdown
    report = _report()
    before = content_digest(report)
    render_markdown(report)
    assert content_digest(report) == before
    assert report.actors[0]["label"] == HOSTILE_LABELS[0]
    assert report.case["title"] == "Title | with a pipe\nand a line"


def test_a_backslash_before_a_pipe_is_kept_in_the_cell():
    from noctornal_api.reports import _cell
    assert _cell("a|b") == "a\\|b"
    assert _cell("a\\|b") == "a\\\\\\|b"
    assert _cell("line\nbreak") == "line break"
    assert _cell(None) == "None"


# --- the hypotheses half of the statement ----------------------------------

def test_withheld_hypotheses_are_stated_and_the_section_says_so():
    from noctornal_api.reports import render_markdown
    report = _report(labels=(), header_withheld=True, hypotheses_withheld=2)
    report.hypotheses = {}
    statement = report.redaction.statement()
    assert report.redaction.anything_withheld
    assert "2 competing hypothes" in statement
    document = render_markdown(report)
    section = document[document.index("## Competing hypotheses"):]
    assert "2 competing hypothes" in section
    assert "withheld with the case header" in section
    assert report.as_dict()["redaction"]["hypotheses_withheld"] == 2


def test_matrix_evidence_above_the_ceiling_is_never_silent():
    """A stance can rest on an element the entity counts do not include (a
    retired node, an inferred tie), so "nothing has been withheld" would
    otherwise be printed over scores that left it out."""
    redaction = _redaction(hypothesis_evidence_withheld=1)
    assert redaction.anything_withheld
    statement = redaction.statement()
    assert "nothing has been withheld" not in statement
    assert "hypothesis matrix" in statement
    assert "lower bound" in statement


def test_the_statement_still_never_says_which_classification():
    statement = _redaction(case_tlp="RED", header_withheld=True,
                           hypotheses_withheld=1,
                           hypothesis_evidence_withheld=3).statement()
    # The header is withheld, so the case's own level is part of what was
    # withheld, and nothing names the level of what was withheld.
    assert "RED" not in statement


# --- the ruled-out alternatives say they were ruled out ------------------

def test_each_hypothesis_row_carries_its_status():
    """README screenshot review, 2026-09-23. The section exists to carry
    the alternatives that were ruled out beside the one that was not, and
    the table printed statement, inconsistency, support and assessed only,
    so a REJECTED hypothesis read exactly like an open one."""
    from noctornal_api.reports import render_markdown
    report = _report(labels=("same operator", "imitator | RED"))
    report.hypotheses = {**report.hypotheses,
                         "statuses": {"h0": "REJECTED", "h1": "PROPOSED"}}
    rows = _table(render_markdown(report),
                  "| Hypothesis | Status | Inconsistency | Support | Assessed |")
    assert [_cells_counting(r)[1].strip() for r in rows] == ["REJECTED", "PROPOSED"]
    # A status the body does not carry is said, not left blank.
    report.hypotheses = {k: v for k, v in report.hypotheses.items()
                         if k != "statuses"}
    rows = _table(render_markdown(report),
                  "| Hypothesis | Status | Inconsistency | Support | Assessed |")
    assert {_cells_counting(r)[1].strip() for r in rows} == {"not recorded"}


# --- a count agrees with its noun ------------------------------------------

_HEDGES = ("(s)", "(y/ies)", "(is/es)", " -- ")


def test_the_redaction_statement_counts_in_words_that_agree():
    """README screenshot review, 2026-09-23. The Report shot withheld one
    exhibit, and the first line of the disclosure read "0 entit(y/ies), 0
    relationship(s) and 1 exhibit(s)", with a " -- " aside in the header
    sentence. Every count is known when the line is written."""
    one = _redaction(nodes_withheld=1, edges_withheld=1, evidence_withheld=1,
                     header_withheld=True, assumptions_withheld=1,
                     hypotheses_withheld=1,
                     hypothesis_evidence_withheld=1).statement()
    many = _redaction(nodes_withheld=0, edges_withheld=2, evidence_withheld=3,
                      header_withheld=True, assumptions_withheld=2,
                      hypotheses_withheld=2,
                      hypothesis_evidence_withheld=4).statement()
    for statement in (one, many):
        for hedge in _HEDGES:
            assert hedge not in statement, (hedge, statement)
    assert "1 entity, 1 relationship and 1 exhibit are above that level" in one
    assert "0 entities, 2 relationships and 3 exhibits are above that level" in many
    assert "The 1 recorded assumption the case rests on is withheld" in one
    assert "rest on a premise this document cannot state" in one
    assert "The 2 recorded assumptions the case rests on are withheld" in many
    assert "The 1 competing hypothesis recorded against the case is withheld" in one
    assert "The 2 competing hypotheses recorded against the case are withheld" in many
    assert "1 item of evidence in the hypothesis matrix rests on" in one
    assert "leave it out." in one
    assert "4 items of evidence in the hypothesis matrix rest on" in many
    assert "It is therefore not a disclosure document as it stands." in one


def test_a_withheld_section_counts_in_words_that_agree():
    """The sections that stand in for withheld ones say how many, the same
    way."""
    from noctornal_api.reports import render_markdown
    report = _report(labels=(), header_withheld=True, assumptions_withheld=1,
                     hypotheses_withheld=1)
    report.hypotheses = {}
    document = render_markdown(report)
    assert "_1 recorded assumption withheld with the case header" in document
    assert "_1 competing hypothesis withheld with the case header" in document
    report = _report(labels=(), header_withheld=True, assumptions_withheld=3,
                     hypotheses_withheld=2)
    report.hypotheses = {}
    document = render_markdown(report)
    assert "_3 recorded assumptions withheld with the case header" in document
    assert "_2 competing hypotheses withheld with the case header" in document
    assert "assumption(s)" not in document and "hypothes(is/es)" not in document


# --- the saved file is the text the console previews (independent review, CONSOLE-02) ------------------------------------

STATIC = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api" / "http" / "static")
_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)
needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

RLO = chr(0x202E)
#: A right-to-left override, an isolate, a zero-width space, a mark, a BOM, a NUL, an escape, DEL and a C1
#: control: each is a different range of what the console replaces.
DECEPTIVE_LABELS = tuple(f"relay{chr(code)}after" for code in (
    0x202E, 0x202A, 0x2066, 0x2069, 0x200B, 0x200F, 0x061C, 0xFEFF, 0x0000, 0x001B, 0x007F, 0x009F))


def _shown(code: int) -> str:
    return f"{chr(0x2039)}U+{code:04X}{chr(0x203A)}"


def _console_script() -> str:
    """The console's own `_DECEPTIVE` and `visibleText`, as shipped."""
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    start = js.index("const _DECEPTIVE = new RegExp(")
    pattern = js[start:js.index("]', 'g');", start) + len("]', 'g');")]
    fn = re.search(r"^function visibleText\(", js, flags=re.M)
    return pattern + "\n" + js[fn.start():js.index("\n}", fn.start()) + 2] + "\n"


def _node(tmp_path, body: str):
    script = tmp_path / "run.js"
    script.write_text(_console_script() + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True, encoding="utf-8",
                         timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_a_bidi_override_or_a_control_in_a_label_does_not_reach_the_file():
    """A right-to-left override inside an entity label reorders the rest of that table line in a viewer
    that applies the bidirectional algorithm, the TLP cell included. Every field that enters the markdown
    goes through `_line`, so the character is replaced by its code point wherever it is."""
    from noctornal_api.reports import render_markdown
    document = render_markdown(_report(DECEPTIVE_LABELS))
    for label in DECEPTIVE_LABELS:
        code = ord(label[len("relay")])
        assert chr(code) not in document, hex(code)
        assert "relay" + _shown(code) + "after" in document, hex(code)
    # The row keeps its four cells and its own classification, in the bytes as in any rendering.
    rows = [line for line in document.split("\n") if line.startswith("| IDENTITY | relay")]
    assert len(rows) == len(DECEPTIVE_LABELS)
    for row in rows:
        assert row.endswith(" | GREEN | NO |") and len(_cells_lookbehind(row)) == 4


def test_a_bidi_override_is_replaced_in_a_title_a_statement_and_a_case_field():
    from noctornal_api.reports import Report, render_markdown
    hostile = f"mark{RLO}ed"
    base = _report((hostile,))
    case = dict(base.case, title=hostile, legal_basis=hostile, code=hostile)
    document = render_markdown(Report(
        case=case, redaction=base.redaction, summary=base.summary, actors=base.actors,
        relationships=base.relationships, evidence=base.evidence, hypotheses=base.hypotheses,
        assumptions=base.assumptions))
    assert RLO not in document
    assert document.count(f"mark{_shown(0x202E)}ed") >= 6


def test_what_the_file_keeps_is_what_it_kept_before():
    """The substitution touches the characters above and nothing else: a tab, an ordinary label, a
    Cyrillic handle, a right-to-left word, an emoji and a path with backslashes pass through byte for
    byte."""
    from noctornal_api.reports import _line
    cyrillic = "".join(chr(code) for code in (0x434, 0x430, 0x20, 0x442, 0x435, 0x441, 0x442))
    hebrew = "".join(chr(code) for code in (0x5E9, 0x5DC, 0x5D5, 0x5DD))
    for text in ("plain label", "tab" + chr(9) + "here", cyrillic, hebrew,
                 "emoji " + chr(0x1F600), PLAIN_BACKSLASHES):
        assert _line(text) == text
    assert _line(None) == "None"


@needs_node
def test_the_python_and_the_console_replace_the_same_characters_the_same_way(tmp_path):
    """`reports._DECEPTIVE` is written out beside the console's `_DECEPTIVE` and not imported from it, so
    this is what keeps them one set: every code unit the console would show as `U+XXXX` is replaced
    here by the same text, and no other is."""
    from noctornal_api.reports import _DECEPTIVE, _visible
    console = _node(tmp_path, """
const out = {};
for (let i = 0; i < 0x10000; i += 1) {
  const ch = String.fromCharCode(i);
  const seen = visibleText(ch);
  if (seen !== ch) out[i] = seen;
}
console.log(JSON.stringify(out));
""")
    here = {str(i): _DECEPTIVE.sub(_visible, chr(i)) for i in range(0x10000)
            if _DECEPTIVE.match(chr(i))}
    assert here == console


@needs_node
def test_the_saved_report_is_the_text_the_console_previews(tmp_path):
    """The preview is the document drawn through `visibleText` under "The full text as it would be saved".
    Saved bytes that the preview would change are bytes the analyst did not see: after the fix there are
    none, whatever the labels hold."""
    from noctornal_api.reports import render_markdown
    document = render_markdown(_report(DECEPTIVE_LABELS + HOSTILE_LABELS))
    (tmp_path / "doc.json").write_text(json.dumps(document), encoding="utf-8")
    same = _node(tmp_path, """
const doc = JSON.parse(require('fs').readFileSync(%s, 'utf8'));
console.log(JSON.stringify(visibleText(doc) === doc));
""" % json.dumps(str(tmp_path / "doc.json")))
    assert same is True

"""The saved report is a table of forum data, and forum data must not be
able to rearrange it.

Final review U13 (2026-09-23). `render_markdown` put node labels, tie
endpoints, exhibit titles, assumptions and hypothesis statements into pipe
tables verbatim, and a label is only checked for being blank. A collected
handle "x | RED" shifted every later cell one column right, so the saved
TLP:GREEN file said that entity was RED; a handle holding a newline ended
its row and printed "**TLP:CLEAR**" on a line of its own partway through
an AMBER document.

Also here, because they are pure: the hypothesis half of the redaction
statement and its section (final review C2).

Pure: builds `Report` objects directly; no database.
"""
from __future__ import annotations

import re

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
    base = dict(built_at_tlp="AMBER", ceiling_tlp="AMBER", case_tlp="AMBER",
                nodes_withheld=0, edges_withheld=0, evidence_withheld=0)
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
    "| Hypothesis | Inconsistency | Support | Assessed |": 4,
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
    """The finding's reproduction: "x | RED" made the TLP column read RED."""
    from noctornal_api.reports import render_markdown
    rows = _table(render_markdown(_report()), "| Type | Label | TLP | Evidenced |")
    hostile = next(r for r in rows if "x \\| RED" in r)
    for split in (_cells_lookbehind, _cells_counting):
        assert split(hostile)[2].strip() == "GREEN"


def test_no_value_can_start_a_line_of_its_own():
    """A newline, a carriage return or a Unicode line separator in a label
    no longer ends the row, so the only handling marks on their own lines
    are the document's."""
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


# --- C2: the hypotheses half of the statement -------------------------------

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
    # The case's own mark is stated, as it always was; nothing names the
    # level of what was withheld.
    assert statement.count("RED") == 1

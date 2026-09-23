"""No em or en dash in anything the server says.

The console renders a great deal of server text verbatim: an error's
detail, a notice, a note, a projection preset's description (straight onto
the sociogram), an audit verifier's caveat, and the whole report, which is
markdown the Report pane shows as it would be saved. The owner treats an em
or en dash in shipped copy as an unacceptable tell, and once the console's
own copy was swept (test_ui_copy_no_dashes.py) 42 string literals under
`noctornal_api` still carried one (README screenshot review, 2026-09-23).

The rule: no string literal under `noctornal_api` holds U+2014 or U+2013,
unless it is data rather than copy and the allow-list below says why. A
string that stands as a statement of its own (a docstring, or a note
written under an assignment) is never seen by a reader and is skipped, as
comments are; everything else is checked, including the literal parts of
an f-string.

The allow-list has one entry: contact_blocks' `_DECORATION`, the character
class of glyphs a vendor fences a contact block with. A forum rule drawn in
em or en dashes has to keep matching, so those two dashes are the pattern
working, not copy. The entry is keyed on the pattern's exact text, so a
sentence cannot shelter under it, and it fails as stale once it is no
longer needed.

The same tell typed on a keyboard, two hyphens with a space either side,
is refused as well, as the console's test refuses it. After the em dash
sweep about 74 server literals still carried one, many of them shown
(a purge's dry-run notice, the AMBIGUOUS reasons stored with a parsed
contact block, operator refusals at boot). A flag such as `--apply` has no
space after it and is not caught. Some of these are data, not copy, and
their hyphens are syntax: a SQL comment, a Lua comment, the mail
signature separator. Those are let off by an allow-list that names each
one by module and the name its literal is assigned to, plus one rule for
SQL handed straight to the driver (the first argument of `.execute()`).
Each takes out only the syntax, so prose around it is still read, and
each fails as stale once nothing it names needs it.

scripts/bootstrap.py, the first program an operator runs, is held to both
rules with no allow-list: its messages are the product's first words.

Pure: parses the source and imports two modules; no database.
"""
from __future__ import annotations

import ast
import re
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
BOOTSTRAP = Path(__file__).resolve().parents[3] / "scripts" / "bootstrap.py"

EM, EN = "\u2014", "\u2013"
DASHES = (EM, EN)
#: Two hyphens, for building samples without typing the tell.
HH = "--"
#: Two hyphens standing in for a dash, read as the console's test reads
#: them: whitespace before and whitespace (or the end) after, or the same
#: at the very start. `--apply` and a bare `'--'` are not caught.
FAKE_DASH = re.compile(r"\s--(?:\s|$)|^--\s")


def _allowed() -> dict[tuple[str, str], str]:
    """(module path under noctornal_api, exact literal) -> why it may keep
    a dash."""
    from noctornal_api import contact_blocks
    return {
        ("contact_blocks.py", contact_blocks._DECORATION.pattern): (
            "the separator glyphs a contact block is fenced with; a rule "
            "drawn in em or en dashes must still read as decoration"),
    }


def _statement_strings(tree: ast.AST) -> set[int]:
    """Strings that stand as a statement of their own: docstrings, and a
    note written under an assignment. Nothing evaluates them, so no reader
    ever meets one."""
    return {id(node.value) for node in ast.walk(tree)
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)}


def dashed_literals(source: str) -> list[tuple[int, str]]:
    """(line, text) of every string literal a reader could meet that holds
    an em or en dash."""
    tree = ast.parse(source)
    skip = _statement_strings(tree)
    return sorted(
        (node.lineno, node.value) for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and id(node) not in skip and any(d in node.value for d in DASHES))


def _offenders() -> list[tuple[str, int, str]]:
    found = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        for line, text in dashed_literals(path.read_text(encoding="utf-8")):
            found.append((rel, line, text))
    return found


# ---------------------------------------------------------------------------
# Two hyphens: what is syntax, and where
# ---------------------------------------------------------------------------

def without_line_comments(text: str) -> str:
    """`text` with each `--` line comment cut off, from a `--` outside
    quotes to the end of its line. SQL and Lua share the syntax; a hyphen
    pair inside a quoted string is kept, because that string is output."""
    kept = []
    for line in text.split("\n"):
        quote = None
        for i, ch in enumerate(line):
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif line.startswith(HH, i):
                line = line[:i]
                break
        kept.append(line)
    return "\n".join(kept)


def without_signature_separator(text: str) -> str:
    """`text` without the lines that are exactly two hyphens and a space:
    the mail signature separator (RFC 3676, section 4.3), which a mail
    client recognises by those three characters and nothing else."""
    return re.sub(rf"(?m)^{HH} $", "", text)


Syntax = Callable[[str], str]

#: The data a spaced pair of hyphens may stay in: (module under
#: noctornal_api, the name its literal is assigned to) -> (what takes the
#: syntax out, why). Keyed on the name rather than the exact text, because
#: a query or a script is edited as code and a key on its text would go
#: stale with every edit to it. The key still admits only that one
#: assignment in that one module, and only its syntax.
_DATA_SYNTAX: dict[tuple[str, str], tuple[Syntax, str]] = {
    ("audit_verify.py", "sql"): (
        without_line_comments,
        "the audit chain query, built before it is executed; a SQL comment"),
    ("custody_verify.py", "sql"): (
        without_line_comments,
        "the custody chain query, built before it is executed; a SQL comment"),
    ("reports.py", "_ACH_CELL_FROM"): (
        without_line_comments,
        "the FROM clause the ACH matrix queries share; a SQL comment"),
    ("ratelimit_redis.py", "_GCRA_LUA"): (
        without_line_comments,
        "the GCRA script Redis runs; a Lua comment"),
    ("transports.py", "text"): (
        without_signature_separator,
        "the plain-text notification mail; the signature separator line"),
}

#: SQL handed straight to the driver: the first argument of any
#: `.execute(...)` is SQL, and its line comments are taken out.
SQL_CALL = "execute"


def _literals_in_context(tree: ast.AST):
    """(literal, in the first argument of `.execute()`, names it is assigned
    to) for every string literal a reader could meet."""
    skip = _statement_strings(tree)
    found = []

    def visit(node, in_sql: bool, names: frozenset[str]) -> None:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and id(node) not in skip:
                found.append((node, in_sql, names))
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = names | {t.id for t in targets if isinstance(t, ast.Name)}
        sql_arg = (node.args[0] if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Attribute)
                   and node.func.attr == SQL_CALL and node.args else None)
        for child in ast.iter_child_nodes(node):
            visit(child, in_sql or child is sql_arg, names)

    visit(tree, False, frozenset())
    return found


def fake_dashed_literals(source: str, module: str,
                         data: dict[tuple[str, str], tuple[Syntax, str]] | None = None):
    """(offenders, used). Offenders are the (line, text) of every literal a
    reader could meet that still fakes a dash once its syntax is out; used
    names each exemption that let a literal off (SQL_CALL, or a `data`
    key), so an exemption nothing needs can be reported as stale."""
    data = _DATA_SYNTAX if data is None else data
    offenders, used = [], set()
    for node, in_sql, names in _literals_in_context(ast.parse(source)):
        text = node.value
        if not FAKE_DASH.search(text):
            continue
        if in_sql:
            text = without_line_comments(text)
            used.add(SQL_CALL)
        for name in sorted(names):
            if (module, name) in data:
                text = data[module, name][0](text)
                used.add((module, name))
        if FAKE_DASH.search(text):
            offenders.append((node.lineno, node.value))
    return sorted(offenders), used


def _hyphen_scan() -> tuple[list[tuple[str, int, str]], set]:
    offenders, used = [], set()
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        found, keys = fake_dashed_literals(path.read_text(encoding="utf-8"), rel)
        offenders += [(rel, line, text) for line, text in found]
        used |= keys
    return offenders, used


# ---------------------------------------------------------------------------
# The reader is proved on known input first
# ---------------------------------------------------------------------------

_SAMPLE = f'''
"""Module docstring {EM} skipped."""
# a comment {EM} skipped
X = 1
"""A note under an assignment {EN} skipped."""


def f(n):
    """Function docstring {EM} skipped."""
    plain = "plain {EM} caught"
    return f"{{n}} formatted {EN} caught", plain


class C:
    """Class docstring {EN} skipped."""
    label = "attribute {EM} caught"
'''


def test_the_reader_skips_what_no_reader_sees_and_catches_the_rest():
    texts = [text for _, text in dashed_literals(_SAMPLE)]
    assert texts == [f"plain {EM} caught", f" formatted {EN} caught",
                     f"attribute {EM} caught"], texts


def test_the_reader_sees_every_module():
    """A module the walk missed would pass by being unread."""
    seen = {p.relative_to(SRC).as_posix() for p in SRC.rglob("*.py")}
    for module in ("reports.py", "projections.py", "http/routers/audit.py",
                   "security/envelope.py", "contact_blocks.py"):
        assert module in seen, module
    assert BOOTSTRAP.is_file(), BOOTSTRAP


_HYPHEN_SAMPLE = f'''
"""Module docstring {HH} skipped."""
# a comment {HH} skipped
FLAG = "run it with {HH}apply"
PROSE = "a sentence {HH} caught"


def f(conn):
    """Function docstring {HH} skipped."""
    conn.execute("""
        SELECT 1          {HH} a SQL comment, skipped
         WHERE x = 'in quotes {HH} caught'""")
    conn.execute("SELECT 2 {HH} a trailing comment, skipped")
    return conn.executemany("SELECT 3 {HH} not an execute, caught")


LUA = "local x = 1 {HH} a Lua comment, skipped"
OTHER = "local x = 1 {HH} the same under another name, caught"
SIG = "body\\n{HH} \\nsignature"
LOOSE = "body\\n{HH} not a separator, caught"
'''

_SAMPLE_DATA = {
    ("sample.py", "LUA"): (without_line_comments, "a script"),
    ("sample.py", "SIG"): (without_signature_separator, "a mail body"),
    ("sample.py", "LOOSE"): (without_signature_separator, "a mail body"),
}


def test_the_hyphen_reader_lets_off_syntax_and_nothing_else():
    """Each exemption takes out its syntax only: a pair inside a quoted SQL
    string is output, the same Lua under an unlisted name is unlisted, and
    a line that merely starts with the pair is not a signature separator."""
    found, used = fake_dashed_literals(_HYPHEN_SAMPLE, "sample.py", _SAMPLE_DATA)
    texts = [text.strip() for _, text in found]
    assert texts == [
        f"a sentence {HH} caught",
        f"SELECT 1          {HH} a SQL comment, skipped\n"
        f"         WHERE x = 'in quotes {HH} caught'",
        f"SELECT 3 {HH} not an execute, caught",
        f"local x = 1 {HH} the same under another name, caught",
        f"body\n{HH} not a separator, caught",
    ], texts
    assert used == {SQL_CALL, *_SAMPLE_DATA}, used
    # And the pattern is the console's: a flag is not a dash.
    assert not FAKE_DASH.search(f"run it with {HH}apply")
    assert FAKE_DASH.search(f"{HH} at the start") and FAKE_DASH.search(f"end {HH}")


# ---------------------------------------------------------------------------
# The rule itself
# ---------------------------------------------------------------------------

def test_no_server_string_carries_a_dash():
    allowed = _allowed()
    offenders = [(rel, line, text[:120]) for rel, line, text in _offenders()
                 if (rel, text) not in allowed]
    assert not offenders, (
        "a dash in server copy the console shows; use a full stop where it "
        "joined two sentences, a comma or colon where it introduced or "
        "appended, parentheses for an aside: " + repr(offenders[:20]))


def test_the_allow_list_names_only_literals_that_still_need_it():
    """An exemption outliving its literal is a hole for the next one."""
    present = {(rel, text) for rel, _, text in _offenders()}
    stale = [key for key in _allowed() if key not in present]
    assert not stale, stale


def test_no_server_string_fakes_a_dash_with_two_hyphens():
    offenders, _ = _hyphen_scan()
    assert not offenders, (
        "two hyphens standing in for a dash in server copy; rewrite it as "
        "the dash rule says, or, if the literal is data, add it to "
        "_DATA_SYNTAX with the syntax it is: "
        + repr([(rel, line, text[:120]) for rel, line, text in offenders[:20]]))


def test_every_data_exemption_still_lets_something_off():
    """An exemption outliving its data is a hole for the next sentence
    written under that name."""
    _, used = _hyphen_scan()
    stale = [key for key in (SQL_CALL, *_DATA_SYNTAX) if key not in used]
    assert not stale, stale


def test_bootstrap_says_nothing_with_a_dash():
    """No allow-list: nothing bootstrap.py prints or stores is data of this
    kind. The demo case it seeds is shown in the console like any other."""
    source = BOOTSTRAP.read_text(encoding="utf-8")
    assert not dashed_literals(source), dashed_literals(source)[:10]
    offenders, _ = fake_dashed_literals(source, "bootstrap.py", data={})
    assert not offenders, offenders[:10]


def test_the_separator_pattern_still_matches_a_rule_drawn_in_dashes():
    """The exemption's reason, held: take the dashes out of `_DECORATION`
    and a vendor's rule of em dashes becomes a line to resolve."""
    from noctornal_api.contact_blocks import _DECORATION
    for rule in (EM * 12, EN * 12, f" {EM} {EN} {EM} ", f"{EM}={EM}={EM}"):
        assert _DECORATION.match(rule), repr(rule)


# ---------------------------------------------------------------------------
# The report: what stood in for a dash
# ---------------------------------------------------------------------------

def _report():
    from noctornal_api.reports import Redaction, Report
    redaction = Redaction(
        built_at_tlp="AMBER", ceiling_tlp="AMBER", case_tlp="RED",
        nodes_withheld=2, edges_withheld=1, evidence_withheld=1,
        header_withheld=False, assumptions_withheld=0,
        hypotheses_withheld=0, hypothesis_evidence_withheld=0)
    case = {"id": "c", "code": "OP-1", "title": "Escrow ring",
            "summary": None, "status": "ACTIVE", "classification": "RED",
            "legal_basis": "production order 44", "authority_ref": None,
            "retention_until": "2030-01-01", "review_due": "2026-12-01",
            "opened": "2026-09-01"}
    assumptions = [
        {"statement": "The handle is one person", "basis": None,
         "status": "OPEN", "made_by_name": "Analyst One",
         "made_at": "2026-09-01T10:00:00+00:00",
         "reviewed_at": "2026-09-02T11:00:00+00:00",
         "review_note": "checked against the forum ledger"},
        {"statement": "The escrow is a service", "basis": "ledger export",
         "status": "OPEN", "made_by_name": "Analyst Two",
         "made_at": "2026-09-01T10:05:00+00:00",
         "reviewed_at": None, "review_note": None},
    ]
    return Report(
        case=case, redaction=redaction,
        summary={"entities": 0, "relationships": 0, "exhibits": 0,
                 "truncated": False, "computed_over": "the redacted graph"},
        assumptions=assumptions,
        generated_at=datetime(2026, 9, 23, tzinfo=timezone.utc))


def test_the_report_carries_no_dash_and_says_a_missing_value_in_words():
    """The heading joined the mark to the case with a dash, and a missing
    authority reference or basis printed a lone dash where the console
    now says "not recorded"."""
    from noctornal_api.reports import render_markdown
    document = render_markdown(_report())
    assert not any(d in document for d in DASHES), document

    lines = document.split("\n")
    # The mark still leads, set off from the case as the console's case
    # header sets off the code from the title.
    assert lines[0] == "# TLP:AMBER \u00b7 OP-1: Escrow ring", lines[0]
    assert "- **Authority reference:** not recorded" in lines

    header = "| Assumption | Basis | Status | Made by | Reviewed |"
    start = lines.index(header)
    rows = lines[start + 2:start + 4]
    first = [c.strip() for c in rows[0].split("|")[1:-1]]
    second = [c.strip() for c in rows[1].split("|")[1:-1]]
    assert len(first) == len(second) == 5
    assert first[1] == "not recorded"
    # The review note sits in brackets after its time, as "Made by" gives
    # the time in brackets after the name.
    assert first[4] == ("2026-09-02T11:00:00+00:00 "
                        "(checked against the forum ledger)"), first[4]
    assert second[1] == "ledger export"
    assert second[4] == "not yet"


_HEADER_DATES = ("Opened", "Retention until", "Next review")


def test_a_withheld_header_says_so_for_its_dates_too():
    """`build` leaves the three dates None when the case header is above
    the ceiling (a date or nothing), and the document printed a bare
    "None" for each, under a legal basis and an authority reference that
    said they were withheld. The dates say it in the same words now."""
    from noctornal_api.reports import WITHHELD_MARK, render_markdown
    report = _report()
    # `build` always names who generated it; the fixture above does not.
    report.generated_by = UUID("00000000-0000-4000-8000-000000000001")
    report.redaction = replace(report.redaction, header_withheld=True)
    report.case.update(
        {key: WITHHELD_MARK
         for key in ("code", "title", "legal_basis", "authority_ref")},
        summary=None, status=None,
        opened=None, retention_until=None, review_due=None)
    document = render_markdown(report)
    lines = document.split("\n")
    for field in ("Legal basis", "Authority reference", *_HEADER_DATES):
        assert f"- **{field}:** {WITHHELD_MARK}" in lines, field
    assert "None" not in document


def test_a_date_missing_from_a_header_that_is_included_says_so():
    """The schema holds all three NOT NULL, so this should not happen; if
    it does, it reads as a missing value, as the authority reference does,
    and never as "None" or as withheld."""
    from noctornal_api.reports import render_markdown
    report = _report()
    report.case["review_due"] = None
    lines = render_markdown(report).split("\n")
    assert "- **Next review:** not recorded" in lines
    assert "- **Opened:** 2026-09-01" in lines


def test_a_review_with_no_note_prints_its_time_alone():
    from noctornal_api.reports import render_markdown
    report = _report()
    report.assumptions[0]["review_note"] = None
    lines = render_markdown(report).split("\n")
    header = "| Assumption | Basis | Status | Made by | Reviewed |"
    row = lines[lines.index(header) + 2]
    assert row.rstrip().endswith("| 2026-09-02T11:00:00+00:00 |"), row

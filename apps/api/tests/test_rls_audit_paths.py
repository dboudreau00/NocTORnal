"""Every reader of the audit log says what answers it (F51, 2026-10-02).

Static: no database. 0168 puts `audit.event` under row-level security: a
request reads a row only in a case it may read, a case-less row it wrote,
every row under a global `audit.read`, or a case-less `ingest` row under a
global `ingest.manage`; work that must see the whole log runs on a system
connection or reads a definer. A reader nobody classified would fail
closed and silently: a two-person rule that permits on zero, a queue that
forgets its triage, a card that says screening never ran. So every SQL
statement in the application that reads the log is listed here by the
function (or module constant) that holds it, with its treatment, and the
test fails BY NAME on one that is not, which is what a merge of new code on
top of 0168 relies on.

Scripts are not listed: each runs as the system role
(`test_rls_system_paths.test_no_script_connects_as_anything_but_the_system_role`).
The database's own readers (the chain trigger, the countersign rule, the
screening fact) are held to SECURITY DEFINER by `test_rls_audit_event_pg.py`.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "apps" / "api" / "src" / "noctornal_api"
SCRIPTS = ROOT / "scripts"

#: A statement that reads the log: SQL (a SELECT, in any case) naming it in
#: a FROM or a JOIN. Prose that mentions the table is not a reader, and
#: docstrings are prose: they are skipped (`_statements`). Case-insensitive
#: since 2026-10-03: the first draft matched an upper-case
#: SELECT only, so `select ... from audit.event` passed unclassified.
_READS = re.compile(r"(?is)\b(?:from|join)\s+audit\.event\b")
_SQL = re.compile(r"(?i)\bselect\b")
_APPENDS = re.compile(r"(?is)\binsert\s+into\s+audit\.event\b")

#: The treatments, each checked below:
#: - CASE: the statement is held to one case (`case_id = %s`) the route has
#:   gated, so the policy's case term answers it;
#: - AUDIT_READ: the route requires `audit.read` globally (the officer);
#: - INGEST: a record's own ingest rows: on a case, under the case term (an
#:   attached record's quarantine-era state is carried onto the case,
#:   `IngestService._carry_from_quarantine`); in quarantine, under the
#:   `ingest.manage` term, which every quarantine reader requires;
#: - SYSTEM:<purpose>: runs on a system connection for that purpose.
_READERS: dict[tuple[str, str], str] = {
    ("audit_verify.py", "verify_chain"): "SYSTEM:AUDIT_VERIFY",
    ("audit_verify.py", "_check_anchor"): "SYSTEM:AUDIT_VERIFY",
    ("http/routers/ach.py", "_history"): "CASE",
    ("http/routers/audit.py", "events"): "AUDIT_READ",
    ("http/routers/governance.py", "unreviewed"): "SYSTEM:BREAK_GLASS",
    ("http/routers/graph.py", "edge_review"): "CASE",
    ("http/routers/ingest.py", "_queue_sql"): "INGEST",
    ("http/routers/ingest.py", "_TRIAGE_STATE"): "INGEST",
    ("http/routers/ingest.py", "_facets"): "INGEST",
    ("http/routers/ingest.py", "record_detail"): "INGEST",
    ("ingest.py", "IngestService.triage_state"): "INGEST",
    ("ingest.py", "IngestService._carry_from_quarantine"): "INGEST",
    ("legacy_records.py", "_UNLABELLED_WHERE"): "SYSTEM:READINESS",
    ("legacy_records.py", "_CITING_CASES_SQL"): "SYSTEM:READINESS",
    ("reports.py", "ReportBuilder._hypotheses"): "CASE",
}


def _fold(node: ast.AST) -> str | None:
    """The text of a string expression built from literals: a literal, an
    f-string (its fields elided), or literals joined with `+`. None for
    anything with a part that is not one of those."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{}"
                       for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold(node.left), _fold(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _statements_of(source: str, filename: str = "<source>") -> list[tuple[str, str]]:
    """(enclosing scope, text) of every string expression in `source`: the
    qualified function or class.method it sits in, or the module-level
    name it is assigned to. An f-string is one text, its fields elided;
    literals joined with `+` or `%` are one text (adjacent literals are
    one constant already), so a statement cannot hide by being built in
    pieces. Docstrings are prose and are left out."""
    tree = ast.parse(source, filename=filename)
    out: list[tuple[str, str]] = []

    def visit(node: ast.AST, stack: list[str]) -> None:
        doc = None
        body = getattr(node, "body", None)
        if (isinstance(body, list) and body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            doc = body[0]
        for child in ast.iter_child_nodes(node):
            scope = ".".join(stack) or "<module>"
            if child is doc:
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child, [*stack, child.name])
            elif isinstance(child, (ast.Assign, ast.AnnAssign)) and not stack:
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                visit(child, [",".join(ast.unparse(t) for t in targets)])
            elif isinstance(child, ast.BinOp) and isinstance(child.op, (ast.Add, ast.Mod)):
                text = _fold(child.left if isinstance(child.op, ast.Mod) else child)
                if text is not None:
                    out.append((scope, text))
                else:
                    visit(child, stack)
            elif isinstance(child, ast.JoinedStr):
                out.append((scope, _fold(child) or ""))
            elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                out.append((scope, child.value))
            else:
                visit(child, stack)

    visit(tree, [])
    return out


def _statements(path: Path) -> list[tuple[str, str]]:
    return _statements_of(path.read_text(encoding="utf-8"), str(path))


def _readers() -> dict[tuple[str, str], list[str]]:
    found: dict[tuple[str, str], list[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        for scope, text in _statements(path):
            if _READS.search(text) and _SQL.search(text):
                found.setdefault((rel, scope), []).append(text)
    return found


def _function(rel: str, name: str) -> ast.AST:
    tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
    leaf = name.split(".")[-1]
    found = [n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == leaf]
    assert found, f"{rel} has no function {name}"
    return found[0]


def test_every_reader_of_the_audit_log_is_classified():
    """The test the merger relies on: a new statement that reads
    audit.event, anywhere in the application, fails here by name until it
    is given a treatment (a term of the policy that answers it, a system
    purpose, or a definer), and an entry whose reader is gone fails too."""
    found = set(_readers())
    new = sorted(f"{rel}::{scope}" for rel, scope in found - set(_READERS))
    gone = sorted(f"{rel}::{scope}" for rel, scope in set(_READERS) - found)
    assert not new, (
        "these read audit.event and test_rls_audit_paths._READERS does not say "
        "what answers them under row-level security (0168). A request reads "
        "only its cases' rows, its own case-less rows, every row under a "
        "global audit.read, or case-less ingest rows under a global "
        "ingest.manage; anything else needs a system purpose or a definer "
        f"function: {new}")
    assert not gone, f"classified readers that no longer read the log: {gone}"


def _audit_alias(text: str) -> str | None:
    """The alias the statement gives `audit.event`, or None when it gives
    none (then its columns are unqualified)."""
    found = re.search(r"(?is)\b(?:from|join)\s+audit\.event\b"
                      r"(?:\s+(?:as\s+)?(?!(?:where|join|left|inner|on|order|"
                      r"group|limit|and|or|using|cross)\b)(\w+))?", text)
    return found.group(1) if found else None


def test_a_case_reader_is_held_to_one_case():
    """The predicate is on the log's own case column, by the alias the
    statement gives it: an unrelated `case_id = %s` elsewhere in the text
    (another table's) does not hold a reader to a case (2026-10-03)."""
    for (rel, scope), treatment in _READERS.items():
        if treatment != "CASE":
            continue
        for text in _readers()[(rel, scope)]:
            alias = _audit_alias(text)
            column = rf"\b{re.escape(alias)}\.case_id" if alias else r"(?<![.\w])case_id"
            assert re.search(column + r"\s*=\s*%s", text), (rel, scope, alias)


def test_the_reader_detector_finds_what_it_is_meant_to():
    """The detector is the merge guard, so it is tested against the
    stragglers it must not miss: a lower-case statement, and one built from
    pieces. And against the prose it must not trip on."""
    def found(source: str) -> bool:
        return any(_READS.search(t) and _SQL.search(t)
                   for _scope, t in _statements_of(source))

    assert found("q = 'select detail from audit.event where object_id = %s'")
    assert found("q = 'SELECT detail ' + 'FROM audit.event WHERE x = 1'")
    assert found("def f(c):\n    c.execute('SELECT 1 ' + 'FROM ' + 'audit.event')")
    assert found("q = ('select 1 from audit.event e '\n     'join x on x.id = e.object_id')")
    assert found("q = f'SELECT {cols} FROM audit.event e WHERE e.case_id = %s'")
    assert found("q = 'SELECT 1 FROM audit.event WHERE a = %s' % ()")
    assert not found('def f():\n    """Reads from audit.event, via a select."""\n    return 1')
    assert not found("q = 'INSERT INTO audit.event (action) VALUES (%s)'")


def test_the_case_predicate_must_be_the_logs_own():
    assert _audit_alias("SELECT 1 FROM audit.event ev WHERE ev.case_id = %s") == "ev"
    assert _audit_alias("SELECT 1 FROM audit.event WHERE case_id = %s") is None
    assert _audit_alias("SELECT 1 FROM audit.event e JOIN x ON x.id = e.object_id") == "e"
    assert _audit_alias("SELECT 1 FROM audit.event WHERE object_id = %s") is None


def test_an_ingest_reader_reads_its_records_own_ingest_rows():
    for (rel, scope), treatment in _READERS.items():
        if treatment != "INGEST":
            continue
        for text in _readers()[(rel, scope)]:
            assert "object_id" in text and "INGEST_" in text, (rel, scope)


def test_the_officers_search_is_gated_on_audit_read():
    for (rel, scope), treatment in _READERS.items():
        if treatment == "AUDIT_READ":
            source = ast.unparse(_function(rel, scope))
            assert 'require_global(\'audit.read\')' in source, (rel, scope)


def test_a_system_reader_runs_on_its_purpose():
    """A reader in a route names its purpose itself. The library readers
    are held through their callers: the chain walk and its anchor check are
    called only from the verify route, on the AUDIT_VERIFY connection (and
    from `scripts/audit_verify.py`, which connects as the system role); the
    legacy register only from readiness probes, whose connection is READINESS
    for every probe but the two about the request connection itself, and
    from scripts."""
    for (rel, scope), treatment in _READERS.items():
        if not treatment.startswith("SYSTEM:") or rel in ("audit_verify.py",
                                                          "custody_verify.py",
                                                          "legacy_records.py"):
            continue
        purpose = treatment.split(":", 1)[1]
        source = ast.unparse(_function(rel, scope))
        assert f"SystemPurpose.{purpose}" in source, (rel, scope)
        # The statement runs on the system connection, not the request's.
        assert "sconn.execute(" in source, (rel, scope)

    callers = [p.relative_to(SRC).as_posix() for p in SRC.rglob("*.py")
               if "verify_chain(" in p.read_text(encoding="utf-8")
               and p.name != "audit_verify.py"]
    assert callers == ["http/routers/audit.py"], callers
    verify = ast.unparse(_function("http/routers/audit.py", "verify"))
    assert "system_conn(SystemPurpose.AUDIT_VERIFY)" in verify
    assert "verify_chain(chain," in verify
    # The custody walk reads only the custody ledger, which is under a policy
    # of its own, so it is held the same way: only the verify route calls it,
    # on AUDIT_VERIFY.
    custody_callers = [p.relative_to(SRC).as_posix() for p in SRC.rglob("*.py")
                       if "verify_custody_chain(" in p.read_text(encoding="utf-8")
                       and p.name != "custody_verify.py"]
    assert custody_callers == ["http/routers/audit.py"], custody_callers
    custody = ast.unparse(_function("http/routers/audit.py", "verify_custody"))
    assert "system_conn(SystemPurpose.AUDIT_VERIFY)" in custody
    assert "verify_custody_chain(chain," in custody

    importers = sorted(p.relative_to(SRC).as_posix() for p in SRC.rglob("*.py")
                       if "legacy_records import" in p.read_text(encoding="utf-8"))
    assert importers == ["readiness.py"], importers
    from noctornal_api.readiness import _REQUEST_CONNECTION_CHECKS
    assert _REQUEST_CONNECTION_CHECKS == {"app_db_role_not_owner",
                                          "row_level_security_enforced"}


def test_the_lab_reads_when_screening_ran_through_the_fact():
    """The pass rows are the worker's or the officer's and carry no case,
    so the policy block (read by every Lab user) asks the definer (0167)."""
    text = (SRC / "screening.py").read_text(encoding="utf-8")
    assert "audit.last_screening_pass(" in text
    for fn in ("policy_block", "state"):
        assert "audit.event" not in ast.unparse(_function("screening.py", fn)), fn


def test_attach_carries_the_quarantine_state_onto_the_case():
    source = ast.unparse(_function("ingest.py", "IngestService.attach_record"))
    assert "self._carry_from_quarantine(record_id" in source


def test_no_append_asks_for_its_row_back():
    """An INSERT ... RETURNING (or ON CONFLICT) needs the new row to pass
    the SELECT policy too, and an append is often a row its writer may not
    read: an unbound connection's refusal, a row on another case. The
    append would be refused and the event lost."""
    offenders = []
    for path in sorted([*SRC.rglob("*.py"), *SCRIPTS.glob("*.py")]):
        for scope, text in _statements(path):
            if _APPENDS.search(text) and re.search(r"(?i)\b(returning|on\s+conflict)\b",
                                                   text):
                offenders.append(f"{path.relative_to(ROOT)}::{scope}")
    assert not offenders, offenders

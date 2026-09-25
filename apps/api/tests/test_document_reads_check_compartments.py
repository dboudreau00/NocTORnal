"""Every read of a collected document checks its compartments (L1,
2026-09-24).

A capture into a compartmented case is stored under the case's
compartments, and the value of that is lost the moment one reader forgets
to check them: the document is then listed, searched or quoted to somebody
outside the compartment. test_document_compartments_pg.py proves the
predicate is bound to the right set on every route that exists; this file
is the static half, which a NEW reader meets before anyone writes a route
test for it (a forum adapter's listing, a raw-HTML read, the similarity
reads' join back).

The rule, read from the source and never by importing a module whose
optional extra may be absent:

- a UNIT is one SQL text: a string literal, f-string or `+` chain as it
  appears in the code, with module constants (this module's, or imported
  from another module of the package) resolved into it. One unit per
  statement, not per function, so a guarded statement cannot vouch for an
  unguarded one beside it;
- a unit is a DOCUMENT READ when it names `collect.document` and touches a
  column of it other than id, source_id, classification, compartments,
  purged_at or captured_at (title, body_text, body_html_key, author_uid,
  thread_ref, anything added later), or label-checks it
  (`classification <=`). A pure INSERT writes and reads nothing;
- a document read must carry `<alias>.compartments <@` for one of the
  aliases it gives `collect.document` (or `compartments <@` unqualified
  when it gives none), or `proposals._SOURCE_COMPARTMENTS <@`;
- once any migration binds `collect.source.compartments` (none does yet),
  a document read that joins the source must check
  `<alias>.compartments <@` on the source too, as it already checks the
  source's classification (docs/05, rule 7);
- `EXEMPT` names the few units that are not reads by a person, each with
  its reason, and an entry that no longer matches one fails as stale.

Pure: parses the source; no database.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
SCHEMA = Path(__file__).resolve().parents[3] / "db" / "schema.sql"

#: "module:Qualified.name" of the enclosing function (or "module:*" for a
#: whole module) -> why its document reads need no compartment predicate.
#: APPEND-ONLY, marked `# gNN:`.
EXEMPT: dict[str, str] = {
    "collection:CollectionService._store_document": (
        "the collector's writer: it asks whether a poll's item is stored "
        "already and shows nothing to a person"),
    "collection:CollectionService._match_watches": (
        "the collector's watch matcher: it finds the row a poll just stored "
        "to hang a hit on, and shows nothing to a person"),
    "collection:CollectionService._suppressed": (
        "the collector's suppression window: it asks whether a thread hit "
        "recently, and shows nothing to a person"),
    "retention:RetentionService.due": (
        "the retention sweep's due list is an operator listing across every "
        "case by design, and names no content"),
    "retention:RetentionService.purge_due": (
        "the retention sweep empties bodies and shows nothing to a person"),
    "proposals:ProposalReview._observed_at": (
        "dates an accepted claim from the document its proposal cites; the "
        "accept route has already held the reviewer to the proposal's "
        "readability, which includes the document's compartments "
        "(_READABLE), and the date is written, never shown here"),
    # The collector's and the retention sweep's own statements (2026-09-24):
    # worker paths with no reader and no label check.
    "collection:CollectionService._attach_raw": (
        "the collector's writer: it points a document it just stored at its "
        "markup object, and shows nothing to a person"),
    "collection:CollectionService._delete_unused_raw": (
        "the collector's clean-up: it asks whether any document still names a "
        "markup object before deleting it, and shows nothing to a person"),
    "collection:CollectionService._mark_deleted": (
        "the collector's writer: it flags the latest version of an item the "
        "site no longer shows, and shows nothing to a person"),
    # Telegram (F5.3, 2026-09-24): the adapter's commit marks the deletions a
    # session saw on the latest version of each message; a worker path.
    "telegram:TelegramAdapter.commit": (
        "the Telegram collector's writer: it marks a deleted message on its "
        "latest version, and shows nothing to a person"),
    "retention:<module>": (
        "the document-citation registry: the legs the retention sweep joins "
        "to find the cases that cite a document, never a read by a person"),
    "retention:_held_sql": (
        "the hold predicate the retention sweep evaluates; it names no "
        "content and shows nothing to a person"),
    "retention:RetentionService._held_document_count": (
        "the retention sweep's count of held documents: a number, no content"),
    "retention:RetentionService._purge_documents": (
        "the retention sweep's purge: it locks, rechecks and empties "
        "documents, and shows nothing to a person"),
    # The embedding pass (F6.1, F6.4, 2026-09-24).
    "embeddings:EmbeddingService.read_items": (
        "the embedding pass reads every document to embed it; nothing it reads "
        "is returned to a person, and every similarity read joins back with "
        "d.compartments <@ (test_embeddings_sql_labels.py)"),
    "embeddings:_assertion_facts_sql": (
        "the embedding pass reads a claim's cited document for its labels and "
        "category, to withhold the claim from a model endpoint; nothing is "
        "returned to a person"),
}
# legacy_records.py's listings are operator reads across every case by
# design (scripts/legacy_records.py, run on the server). They need no entry
# above: they assemble their statements from function arguments, which a
# static read cannot resolve, so they are never units here. That is the
# scan's limit, stated rather than hidden; the route tests are the guard
# for anything a person reads.

#: The columns a unit may touch without reading content: identity and the
#: labels the gate itself compares.
LABEL_COLUMNS = frozenset({"id", "source_id", "classification",
                           "compartments", "purged_at", "captured_at"})

_TABLE = re.compile(r'collect\.(?:"document"|document\b)', re.IGNORECASE)
_SOURCE_TABLE = re.compile(r'collect\.(?:"source"|source\b)', re.IGNORECASE)
_AFTER = re.compile(r'\s+(?:AS\s+)?([A-Za-z_]\w*)', re.IGNORECASE)
_KEYWORDS = frozenset("""
WHERE JOIN LEFT RIGHT INNER OUTER FULL CROSS ON SET ORDER GROUP LIMIT USING
RETURNING VALUES WITH FOR UNION WINDOW HAVING OFFSET FETCH SELECT FROM AND
OR NATURAL LATERAL TABLESAMPLE EXCEPT INTERSECT
""".split())


def document_columns() -> frozenset[str]:
    """The columns of collect.document, from the schema dump (regenerated
    from the migrations), with `compartments` whether or not the dump
    carries it yet."""
    text = SCHEMA.read_text(encoding="utf-8")
    body = text[text.index("CREATE TABLE collect.document ("):]
    body = body[:body.index("\n);")]
    cols = {line.split()[0] for line in body.splitlines()[1:]
            if line.strip() and not line.strip().startswith("CONSTRAINT")}
    return frozenset(cols | {"compartments"})


# ---------------------------------------------------------------------------
# Reading SQL out of Python source
# ---------------------------------------------------------------------------

UNKNOWN = "{?}"


class _Module:
    """A module's constants and imports, resolved lazily across modules."""

    def __init__(self, name: str, tree: ast.Module, registry: dict):
        self.name = name
        self.tree = tree
        self.registry = registry
        self.assigned: dict[str, ast.AST] = {}
        self.imports: dict[str, tuple[str, str]] = {}
        for node in tree.body:
            target = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                target = node.target
            if isinstance(target, ast.Name):
                self.assigned[target.id] = node.value
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and \
                    node.module.startswith("noctornal_api."):
                other = node.module.split(".", 1)[1].replace(".", "/")
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = (other, alias.name)
        self._cache: dict[str, str] = {}

    def constant(self, name: str, depth: int = 0) -> str:
        if depth > 20:
            return UNKNOWN
        if name in self._cache:
            return self._cache[name]
        if name in self.assigned:
            value = text_of(self.assigned[name], self, depth + 1)
        elif name in self.imports:
            other, attr = self.imports[name]
            module = self.registry.get(other)
            value = (module.constant(attr, depth + 1) if module else UNKNOWN)
        else:
            value = UNKNOWN
        self._cache[name] = value
        return value


def text_of(node: ast.AST, module: _Module, depth: int = 0) -> str:
    """The SQL text an expression renders, with what cannot be known
    statically written as {?}."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        out = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                out.append(str(part.value))
            elif isinstance(part, ast.FormattedValue):
                out.append(text_of(part.value, module, depth + 1))
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return (text_of(node.left, module, depth + 1)
                + text_of(node.right, module, depth + 1))
    if isinstance(node, ast.Name):
        return module.constant(node.id, depth + 1)
    return UNKNOWN


def _stringy(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _stringy(node.left) or _stringy(node.right)
    return False


def units(module: _Module) -> list[tuple[str, int, str]]:
    """(qualified name of the enclosing function or '<module>', line,
    text) for every maximal string expression that is not a docstring."""
    found: list[tuple[str, int, str]] = []
    docstrings = {id(n.value) for n in ast.walk(module.tree)
                  if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
                  and isinstance(n.value.value, str)}

    def visit(node: ast.AST, scope: list[str], inside: bool) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            scope = [*scope, node.name]
        here = _stringy(node) and id(node) not in docstrings
        if here and not inside:
            found.append((".".join(scope) or "<module>", node.lineno,
                          text_of(node, module)))
        for child in ast.iter_child_nodes(node):
            visit(child, scope, inside or here)

    visit(module.tree, [], False)
    return found


def load_package(root: Path = SRC) -> dict[str, _Module]:
    registry: dict[str, _Module] = {}
    for path in sorted(root.rglob("*.py")):
        name = path.relative_to(root).with_suffix("").as_posix()
        registry[name] = _Module(
            name, ast.parse(path.read_text(encoding="utf-8")), registry)
    return registry


# ---------------------------------------------------------------------------
# The rule
# ---------------------------------------------------------------------------

def aliases(text: str, table: re.Pattern) -> tuple[set[str], bool]:
    """(aliases the unit gives the table, whether it also names it bare)."""
    named, bare = set(), False
    for m in table.finditer(text):
        after = _AFTER.match(text, m.end())
        if after and after.group(1).upper() not in _KEYWORDS:
            named.add(after.group(1))
        else:
            bare = True
    return named, bare


def verdict(text: str, *, columns: frozenset[str], source_fragment: str,
            source_bound: bool) -> str | None:
    """Why `text` is a document read that does not check compartments, or
    None when it is not a read or does check them."""
    if not _TABLE.search(text):
        return None
    flat = " ".join(text.split())
    if flat.upper().startswith("INSERT INTO COLLECT.") and "SELECT" not in flat.upper():
        return None
    named, bare = aliases(text, _TABLE)
    touched: set[str] = set()
    checks_label = False
    guarded = False
    for alias in named:
        touched |= set(re.findall(rf"(?<![\w.]){re.escape(alias)}\.(\w+)", text))
        checks_label |= bool(re.search(
            rf"(?<![\w.]){re.escape(alias)}\.classification\s*<=", text))
        guarded |= bool(re.search(
            rf"(?<![\w.]){re.escape(alias)}\.compartments\s*<@", text))
    if bare:
        touched |= {w for w in re.findall(r"(?<![\w.])(\w+)", text)
                    if w in columns}
        checks_label |= bool(re.search(r"(?<![\w.])classification\s*<=", text))
        guarded |= bool(re.search(r"(?<![\w.])compartments\s*<@", text))
    if source_fragment and re.search(re.escape(source_fragment) + r"\s*<@", text):
        guarded = True
    content = touched - LABEL_COLUMNS
    if not content and not checks_label:
        return None
    if not guarded:
        what = ", ".join(sorted(content)) or "its label"
        return f"reads collect.document ({what}) and checks no compartments"
    if source_bound and _SOURCE_TABLE.search(text):
        src_named, _ = aliases(text, _SOURCE_TABLE)
        if not any(re.search(rf"(?<![\w.]){re.escape(a)}\.compartments\s*<@",
                             text) for a in src_named):
            return ("joins collect.source, which carries compartments, and "
                    "checks none of the source's")
    return None


def _source_fragment(registry: dict[str, _Module]) -> str:
    return registry["proposals"].constant("_SOURCE_COMPARTMENTS")


def _source_bound() -> bool:
    from test_compartment_contract_pg import added_bound_columns
    return any(t[:3] == ("collect", "source", "compartments")
               for t in added_bound_columns())


def findings(registry: dict[str, _Module], *, source_bound: bool
             ) -> tuple[list[str], set[str]]:
    """(unguarded reads, EXEMPT keys that matched a read)."""
    columns = document_columns()
    fragment = _source_fragment(registry)
    bad, used = [], set()
    for name, module in registry.items():
        for scope, line, text in units(module):
            why = verdict(text, columns=columns, source_fragment=fragment,
                          source_bound=source_bound)
            if why is None:
                continue
            for key in (f"{name}:{scope}", f"{name}:*"):
                if key in EXEMPT:
                    used.add(key)
                    break
            else:
                bad.append(f"{name}.py:{line} ({scope}) {why}")
    return bad, used


# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------

def test_every_document_read_checks_the_readers_compartments():
    registry = load_package()
    bad, used = findings(registry, source_bound=_source_bound())
    assert bad == [], "\n".join(bad)
    stale = set(EXEMPT) - used
    assert not stale, f"EXEMPT entries that match no document read: {stale}"


def test_the_queue_rule_carries_the_document_compartments():
    """Every proposal read (the queue, the counts, the source view, the
    waiting badges, deception's lookup) goes through `_READABLE`, so the
    document's compartments are checked there."""
    from noctornal_api import proposals
    assert "d.compartments" in proposals._SOURCE_COMPARTMENTS
    assert "b.compartments" in proposals._SOURCE_COMPARTMENTS
    assert re.search(re.escape(proposals._SOURCE_COMPARTMENTS)
                     + r"\s*<@ %\(held\)s", proposals._READABLE)


def test_the_scan_catches_what_it_is_for():
    """The scanner on code written to fail it, so a scanner that stopped
    looking would fail here rather than pass everything."""
    sample = '''
from noctornal_api.proposals import _SOURCE_COMPARTMENTS
_COLS = "d.title, d.body_html_key"


def lists(conn, held):
    guarded = conn.execute(
        "SELECT d.title FROM collect.document d "
        "WHERE d.compartments <@ %s", (held,))
    naked = conn.execute(
        "SELECT " + _COLS + " FROM collect.document d WHERE d.id = %s")
    return guarded, naked


def by_label(conn):
    return conn.execute("SELECT 1 FROM collect.document "
                        "WHERE classification <= %s")


def raw_html(conn):
    return conn.execute(f"""SELECT author_uid FROM collect.document
                             WHERE id = %s""")


def fine(conn):
    conn.execute("SELECT id, compartments FROM collect.document WHERE id = %s")
    conn.execute("INSERT INTO collect.document (title) VALUES (%s)")
    conn.execute("SELECT x FROM collect.document_embedding e")
    conn.execute("SELECT p.id FROM collect.proposal p JOIN collect.document d "
                 "ON d.id = p.document_id WHERE " + _SOURCE_COMPARTMENTS
                 + " <@ %s AND d.title = 'x'")
    return conn.execute("SELECT body_text FROM collect.document "
                        "WHERE compartments <@ %s")


def sourced(conn):
    return conn.execute(
        "SELECT d.title FROM collect.document d JOIN collect.source s "
        "ON s.id = d.source_id WHERE d.compartments <@ %s")
'''
    registry = load_package()
    registry["sample"] = _Module("sample", ast.parse(sample), registry)
    columns = document_columns()
    fragment = _source_fragment(registry)
    got = {}
    for scope, _line, text in units(registry["sample"]):
        why = verdict(text, columns=columns, source_fragment=fragment,
                      source_bound=False)
        if why:
            got.setdefault(scope, []).append(why)
    assert set(got) == {"lists", "by_label", "raw_html"}, got
    assert len(got["lists"]) == 1, "one unguarded statement, not the function"
    assert "body_html_key" in got["lists"][0] and "title" in got["lists"][0]
    assert "author_uid" in got["raw_html"][0]
    # Once a source carries compartments, a read that joins it checks them.
    sourced = [t for s, _l, t in units(registry["sample"]) if s == "sourced"]
    assert verdict(sourced[0], columns=columns, source_fragment=fragment,
                   source_bound=True).startswith("joins collect.source")
    assert verdict(sourced[0], columns=columns, source_fragment=fragment,
                   source_bound=False) is None

"""Every connection that sees every row says why (S1, 2026-09-25).

Static: no database. Under row-level security the request role sees only
what its user may read, and some work must see everything (a purge, a
legal hold, a guard that permits on zero, the withheld counts, a merge,
sign-in, every script). That work runs on `db.connect_system(purpose)`,
`db.system_connection(purpose, ...)` or the `deps.system_conn(purpose)`
dependency, and the purpose is a `db.SystemPurpose` member, so the list
of places that bypass row security is one grep and one enum.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "apps" / "api" / "src" / "noctornal_api"
SCRIPTS = ROOT / "scripts"

#: The one script that connects as the OWNER on purpose: it creates and
#: grants the runtime roles, which the system role cannot do.
_OWNER_SCRIPTS = {"runtime_roles.py"}
_CALLS = ("connect_system", "system_connection", "system_conn")


def _files() -> list[Path]:
    return sorted([*SRC.rglob("*.py"), *SCRIPTS.glob("*.py")])


def _purpose_calls(path: Path) -> list[tuple[int, str]]:
    """(line, first-argument source) of every call to one of `_CALLS`."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name in _CALLS and path.name != "db.py":
            first = ast.unparse(node.args[0]) if node.args else "<none>"
            # deps.system_conn is the dependency's own definition: it passes
            # through the purpose its caller named.
            if path.name == "deps.py" and first == "purpose":
                continue
            out.append((node.lineno, first))
    return out


def test_every_system_connection_names_a_purpose():
    from noctornal_api.db import SystemPurpose

    members = {f"SystemPurpose.{m.name}" for m in SystemPurpose}
    bad = []
    for path in _files():
        for line, first in _purpose_calls(path):
            if first not in members:
                bad.append(f"{path.relative_to(ROOT)}:{line} passes {first}")
    assert not bad, bad


def test_every_purpose_has_a_caller():
    """A member nobody uses is a claim about a bypass that does not exist."""
    from noctornal_api.db import SystemPurpose

    used = {first for path in _files() for _line, first in _purpose_calls(path)}
    unused = sorted(f"SystemPurpose.{m.name}" for m in SystemPurpose
                    if f"SystemPurpose.{m.name}" not in used)
    assert not unused, unused


def test_no_script_connects_as_anything_but_the_system_role():
    """A script serves no request and binds no user: on the request role it
    would see nothing under row-level security, and a sweep that silently
    saw nothing reports success."""
    offenders = []
    for path in sorted(SCRIPTS.glob("*.py")):
        if path.name in _OWNER_SCRIPTS:
            continue
        text = path.read_text(encoding="utf-8")
        if re.search(r"from noctornal_api\.db import [^\n]*\bconnect\b(?!_)", text):
            offenders.append(path.name)
    assert not offenders, (
        "these scripts import the plain connect; use db.connect_system with a "
        f"SystemPurpose: {offenders}")


def test_the_request_path_opens_request_connections():
    """The HTTP request's own connection, the websocket's and the
    out-of-band audit connection are the request role's, never a plain
    `connect()` that a development switch could not reach."""
    for rel in ("http/deps.py", "http/routers/live.py"):
        text = (SRC / rel).read_text(encoding="utf-8")
        assert "connect_request" in text, rel
        assert not re.search(r"(?<![\w.])connect\(\)", text), rel


#: (module, function) pairs that must run their work on a system
#: connection, each with its system purpose.
_MUST_BE_SYSTEM = {
    ("graph.py", "_refuse_if_ties_above_clearance"): "GRAPH_GUARD",
    ("projections.py", "withheld"): "WITHHELD",
    ("reports.py", "ach_cells_withheld"): "WITHHELD",
    ("http/routers/governance.py", "legal_hold"): "RETENTION",
    ("http/routers/governance.py", "purge"): "RETENTION",
    ("http/routers/governance.py", "purge_out_of_schedule"): "RETENTION",
    ("http/routers/governance.py", "invoke"): "BREAK_GLASS",
    ("http/routers/merges.py", "merge"): "MERGE",
    ("http/routers/merges.py", "reverse"): "MERGE",
    ("http/routers/cases.py", "create_case"): "CASE_MEMBERSHIP",
    ("http/routers/cases.py", "_extend_exhibit_locks"): "EVIDENCE_LOCKS",
    ("http/routers/auth.py", "login"): "AUTH",
    ("http/routers/compartments.py", "retire_compartment"): "COMPARTMENTS",
    ("http/routers/evidence.py", "mint_production_ticket"): "TICKETS",
    ("http/routers/samples.py", "mint_download_ticket"): "TICKETS",
    # S1, 2026-09-25: the collected-document tables under policy (0118).
    # Each dedupes, counts or sweeps across every document, exhibit or
    # claim, or writes every version of one.
    ("http/routers/collection.py", "run_once"): "COLLECTION",
    ("http/routers/proposals.py", "capture"): "COLLECTION",
    ("http/routers/governance.py", "document_legal_hold"): "RETENTION",
    ("http/routers/embeddings.py", "register_embedding_space"): "EMBEDDINGS",
    ("http/routers/embeddings.py", "activate_embedding_space"): "EMBEDDINGS",
    ("http/routers/embeddings.py", "retire_embedding_space"): "EMBEDDINGS",
    ("http/routers/embeddings.py", "recheck_embedding_space"): "EMBEDDINGS",
    ("http/routers/embeddings.py", "run_embedding_pass"): "EMBEDDINGS",
    ("readiness.py", "_probe_connections"): "READINESS",
    # S1, 2026-09-25: the Lab under policy (0121). A submission's duplicate
    # check, the officer's label-free screening record and its passes, and
    # the lookup refusal for the hash of never-screened material.
    ("http/routers/samples.py", "submit"): "SAMPLE_INTAKE",
    ("http/routers/samples.py", "screening_overview"): "SCREENING",
    ("http/routers/samples.py", "import_screening_list"): "SCREENING",
    ("http/routers/samples.py", "start_screening_pass"): "SCREENING",
    ("http/routers/samples.py", "review_screening_result"): "SCREENING",
    ("lookups.py", "_sample_hashes"): "LOOKUPS",
    # S1, 2026-09-25: comms under policy (0122). Minimisation is a legal
    # obligation done in full, and the incidental flag it finds third
    # parties by.
    ("http/routers/comms.py", "minimise"): "MINIMISATION",
    ("http/routers/comms.py", "mark_incidental"): "MINIMISATION",
    # S1, 2026-09-25: watches under policy (0124). A quarantined record
    # scores against every watch in the deployment.
    ("ingest.py", "_watches_for"): "INGEST",
}


def test_the_work_that_must_see_every_row_runs_on_a_system_connection():
    missing = []
    for (rel, fn), purpose in _MUST_BE_SYSTEM.items():
        tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
        found = [n for n in ast.walk(tree)
                 # Async routes too (an upload route is async, S1 2026-09-25).
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name == fn]
        assert found, f"{rel} has no function {fn}"
        source = ast.unparse(found[0])
        if f"SystemPurpose.{purpose}" not in source:
            missing.append(f"{rel}::{fn} ({purpose})")
    assert not missing, missing


def test_a_legal_hold_that_changed_nothing_is_refused():
    """A legal hold on an exhibit: a blind UPDATE that matched no row must
    not be audited as a hold."""
    tree = ast.parse((SRC / "retention.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "set_legal_hold")
    assert "rowcount != 1" in ast.unparse(fn)

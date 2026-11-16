"""Every statement that reads iam.case_assignment says what answers it under a row policy.

Static: no database. Who holds which role on which case is under a row policy (0192, rls-6). It shows
a request its own assignments, whatever the case's labels, and every assignment on a case in
`iam.rls_cases()` (the case's labels within the caller's reach and a live assignment of the caller's
own on it, a break-glass grant counted), which is the team the roster (`GET /cases/{id}/users`) already
shows the case's members. A connection bound to nobody reads none. A reader the policy does not answer
comes back empty and refuses silently: a gate that finds no role, a fan-out that tells nobody. So every
SQL statement in the application and the scripts that names the table is listed here by the function
(or module constant) that holds it, with what answers it, and a new one fails BY NAME until it has one.

What a reader must be:

- OWN: it reads the caller's own assignments, which the policy shows whatever the case's labels (the
  break-glass invoke reads one on a case above the caller's clearance). The statement holds the table's
  `user_id` to a parameter its callers fill with the caller, or to a notice's recipient, whom the
  notification policy holds to the caller.
- TEAM: it reads other people's assignments on ONE case its route has gated with a case verb, so the
  case is in `iam.rls_cases()`. The statement holds the table's `case_id` to a parameter.
- SYSTEM:<purpose>: it runs on a system connection for that purpose, or in a script, which connects as
  the system role (`test_rls_system_paths.test_no_script_connects_as_anything_but_the_system_role`).
  Every write of the table is one: the request role holds no write on it (0109).

What is none of those needs something else. While a reader is owed it (`_OWED`, `_UNBOUND`) the policy
cannot stand, so with the policy in place both stay empty:

- another person's assignment on a case the caller need not be on: a definer that says who may ask,
  never the table (`_THROUGH_A_DEFINER`);
- a gate on a connection bound to nobody: a binding to the caller first, or the resolver's own read
  (OWN) finds no row and the gate refuses (`_BOUND_BEFORE_THE_GATE`, and the live socket's
  `_LIVE_CONNECTIONS`).

The database's own readers (`iam.case_code`, `iam.case_leads`, `iam.rls_cases`, `notify.enqueue`) are
SECURITY DEFINER and read as the owner, whom no policy binds.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "apps" / "api" / "src" / "noctornal_api"
SCRIPTS = ROOT / "scripts"

#: A statement that names the table where SQL names a table. Prose that mentions it is not a reader,
#: and docstrings are prose: they are skipped (`_statements`). A lock key that spells the name is not
#: SQL either.
_NAMES = re.compile(r"(?is)\b(?:from|join|into|update)\s+iam\.case_assignment\b")

#: (file, scope) -> treatment. Files under the application package by their path inside it; scripts as
#: `scripts/<name>`.
_READERS: dict[tuple[str, str], str] = {
    ("approvals.py", "assignment_block"): "TEAM",
    ("approvals.py", "ApprovalService.awaiting_signature"): "OWN",
    ("cases.py", "CaseService.revoke_user"): "SYSTEM:CASE_MEMBERSHIP",
    ("cases.py", "CaseService.list_for_user"): "OWN",
    ("cases.py", "CaseService._grant"): "SYSTEM:CASE_MEMBERSHIP",
    ("cases.py", "CaseService._refuse_second_live"): "SYSTEM:CASE_MEMBERSHIP",
    ("dual_control.py", "DualControlPolicyService._cases_requiring"): "OWN",
    ("http/routers/approvals.py", "_relax_signers"): "TEAM",
    ("http/routers/cases.py", "_with_caller"): "OWN",
    ("http/routers/cases.py", "_assignees_below"): "TEAM",
    ("http/routers/cases.py", "assign_case_user"): "TEAM",
    ("http/routers/cases.py", "list_case_users"): "TEAM",
    ("http/routers/cases.py", "revoke_case_user"): "TEAM",
    ("http/routers/comms.py", "_visible_cases"): "OWN",
    ("http/routers/governance.py", "_authorised_cases"): "OWN",
    ("http/routers/governance.py", "_categories_in_use"): "OWN",
    ("http/routers/governance.py", "_assigned_case_code"): "OWN",
    ("http/routers/ingest.py", "_authorised_cases_for_ingest"): "OWN",
    ("iam_admin.py", "IamAdminService._stranded_assignments"): "SYSTEM:IAM_ADMIN",
    # The requester's own row on a request, and theirs again at sign-off and at the drain, which run
    # as LOOKUPS.
    ("lookups.py", "LookupService.holds"): "OWN",
    ("lookups.py", "LookupService.lookup_authorisers"): "TEAM",
    ("notifications.py", "readable_predicate"): "OWN",
    ("notify_events.py", "approval_requested"): "TEAM",
    ("pgp_keys.py", "PgpLookupService._can_approve"): "OWN",
    ("proposals.py", "ProposalStore.waiting_by_case"): "OWN",
    ("stores.py", "PgAccessResolver.resolve"): "OWN",
    ("scripts/seed_readme_showcase.py", "_run"): "SYSTEM:SCRIPT",
}

#: What an OWED reader is owed, by name.
_OWED: dict[tuple[str, str], str] = {}

#: Readers of another person's assignment on a case the caller need not be on, each through the
#: definer that says who may ask, and never through the table.
_THROUGH_A_DEFINER: dict[tuple[str, str], str] = {
    # The detonation sign-off: the Lab analyst who asks is seldom on the case (0191).
    ("samples.py", "SampleService.detonation_authorisers"): "iam.case_leads(",
}

#: Functions that put the gate to a connection nobody has bound: the resolver's own read of the
#: caller's assignment (OWN) would find no row there. Each is owed a binding to the caller first.
_UNBOUND: dict[tuple[str, str], str] = {}

#: Functions that start on a connection bound to nobody and bind it themselves before the gate,
#: with the call that binds it.
_BOUND_BEFORE_THE_GATE: dict[tuple[str, str], str] = {
    # The sample origin runs no session: the ticket is spent unbound, then bound to its holder.
    ("evidence.py", "EvidenceService.redeem_production_ticket"): "bind_ticket(self._c, presented)",
}

#: Every function in the live socket that opens a request connection, with what it does there.
_LIVE_CONNECTIONS: dict[str, str] = {
    "_authenticate": "the handshake: bound by `refuse_unbindable_session` before the gate",
    "_bound_request_connection": "every per-delivery check: bound to the subscriber's session",
    "_session_alive": "the session through `iam.session_by_token`; no gate, no assignment",
    "_Hub._run": "the change channel's LISTEN; no gate, no assignment",
}

#: The routes that write the table, with the purpose each writes it on.
_WRITERS: dict[tuple[str, str], str] = {
    ("http/routers/cases.py", "create_case"): "CASE_MEMBERSHIP",
    ("http/routers/cases.py", "assign_case_user"): "CASE_MEMBERSHIP",
    ("http/routers/cases.py", "revoke_case_user"): "CASE_MEMBERSHIP",
    ("http/routers/compartments.py", "set_user_compartments"): "IAM_ADMIN",
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
    literals joined with `+` or `%` are one text, so a statement cannot
    hide by being built in pieces. Docstrings are prose and are left out.
    `test_rls_audit_paths._statements_of` is the same walk."""
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


def _files() -> list[tuple[str, Path]]:
    found = [(p.relative_to(SRC).as_posix(), p) for p in sorted(SRC.rglob("*.py"))]
    found += [(f"scripts/{p.name}", p) for p in sorted(SCRIPTS.glob("*.py"))]
    return found


def _readers() -> dict[tuple[str, str], list[str]]:
    found: dict[tuple[str, str], list[str]] = {}
    for rel, path in _files():
        for scope, text in _statements_of(path.read_text(encoding="utf-8"), str(path)):
            if _NAMES.search(text):
                found.setdefault((rel, scope), []).append(text)
    return found


def _function(rel: str, name: str) -> ast.AST:
    """The function `name` (a bare name or `Class.method`) in `rel`."""
    tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
    *owner, leaf = name.split(".")
    for node in ast.walk(tree):
        if owner and not (isinstance(node, ast.ClassDef) and node.name == owner[-1]):
            continue
        for child in (node.body if owner else [node]):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == leaf:
                return child
    raise AssertionError(f"{rel} has no function {name}: the table above is stale")


def _alias(text: str) -> str | None:
    """The alias the statement gives `iam.case_assignment`, or None when it
    gives none (then its columns are unqualified)."""
    found = re.search(r"(?is)\b(?:from|join)\s+iam\.case_assignment\b"
                      r"(?:\s+(?:as\s+)?(?!(?:where|join|left|inner|on|order|"
                      r"group|limit|and|or|using|cross)\b)(\w+))?", text)
    return found.group(1) if found else None


def _column(text: str, name: str) -> str:
    """A pattern for the table's own `name` column, by the alias the
    statement gives it: another table's column of the same name does not
    count."""
    alias = _alias(text)
    return rf"\b{re.escape(alias)}\.{name}" if alias else rf"(?<![.\w]){name}"


_PARAMETER = r"\s*=\s*%(?:\(\w+\))?s"


def test_every_reader_of_case_assignment_is_classified():
    """The test a new reader meets: a statement that names
    iam.case_assignment, anywhere in the application or the scripts, fails
    here by name until it is given a treatment the row policy answers, and an
    entry whose statement is gone fails too."""
    found = set(_readers())
    new = sorted(f"{rel}::{scope}" for rel, scope in found - set(_READERS))
    gone = sorted(f"{rel}::{scope}" for rel, scope in set(_READERS) - found)
    assert not new, (
        "these name iam.case_assignment and test_case_assignment_readers._READERS "
        "does not say what answers them under its row policy. A request reads its "
        "own assignments and the teams of the cases it may open; anything else "
        f"needs a system purpose or a definer: {new}")
    assert not gone, f"classified readers that no longer name the table: {gone}"
    unknown = sorted(f"{rel}::{scope} ({t})" for (rel, scope), t in _READERS.items()
                     if t not in ("OWN", "TEAM", "OWED") and not t.startswith("SYSTEM:"))
    assert not unknown, unknown


def test_the_reader_detector_finds_what_it_is_meant_to():
    """The detector is the merge guard, so it is tested against the
    stragglers it must not miss (a lower-case statement, one built from
    pieces, an f-string, a write) and against the prose and the lock key it
    must not trip on."""
    def found(source: str) -> bool:
        return any(_NAMES.search(t) for _scope, t in _statements_of(source))

    assert found("q = 'select role_key from iam.case_assignment where user_id = %s'")
    assert found("q = 'SELECT 1 ' + 'FROM iam.case_assignment WHERE x = 1'")
    assert found("def f(c):\n    c.execute('SELECT 1 ' + 'FROM ' + 'iam.case_assignment')")
    assert found("q = f'SELECT {cols} FROM iam.case_assignment a WHERE a.case_id = %s'")
    assert found("q = ('select 1 from iam.role r '\n     'join iam.case_assignment a on true')")
    assert found("q = 'DELETE FROM iam.case_assignment WHERE case_id = %s'")
    assert found("q = 'INSERT INTO iam.case_assignment (case_id) VALUES (%s)'")
    assert not found('def f():\n    """Reads from iam.case_assignment."""\n    return 1')
    assert not found("key = f'iam.case_assignment.single_case:{role}:{user}'")
    assert not found("x = {'iam.case_assignment': 'the IAM plane'}")


def test_an_own_reader_is_held_to_the_caller():
    """The table's own `user_id`, by the alias the statement gives it, is a
    parameter (the caller) or a notice's recipient (the caller, under the
    notification policy)."""
    readers = _readers()
    loose = []
    for (rel, scope), treatment in _READERS.items():
        if treatment != "OWN":
            continue
        for text in readers[(rel, scope)]:
            column = _column(text, "user_id")
            if not re.search(column + rf"(?:{_PARAMETER}|\s*=\s*\{{\}}\.recipient_id)", text):
                loose.append(f"{rel}::{scope}")
    assert not loose, loose


def test_a_team_reader_is_held_to_one_case():
    readers = _readers()
    loose = []
    for (rel, scope), treatment in _READERS.items():
        if treatment != "TEAM":
            continue
        for text in readers[(rel, scope)]:
            if not re.search(_column(text, "case_id") + _PARAMETER, text):
                loose.append(f"{rel}::{scope}")
    assert not loose, loose


def test_the_predicate_must_be_the_tables_own():
    assert _alias("SELECT 1 FROM iam.case_assignment ca WHERE ca.user_id = %s") == "ca"
    assert _alias("SELECT 1 FROM iam.case_assignment WHERE user_id = %s") is None
    assert _alias("SELECT 1 FROM x JOIN iam.case_assignment a ON a.case_id = x.id") == "a"
    text = "SELECT 1 FROM iam.case_assignment a JOIN iam.app_user u ON u.id = %s"
    assert not re.search(_column(text, "user_id") + _PARAMETER, text)
    assert re.search(_column("SELECT 1 FROM iam.case_assignment WHERE user_id = %(me)s",
                             "user_id") + _PARAMETER,
                     "SELECT 1 FROM iam.case_assignment WHERE user_id = %(me)s")


def test_the_table_is_written_only_on_a_system_connection():
    """Every write is the CASE_MEMBERSHIP or IAM_ADMIN purpose's, made on
    the system connection the route opened for it: the library's system
    readers are held through these callers."""
    missing = []
    for (rel, fn), purpose in _WRITERS.items():
        source = ast.unparse(_function(rel, fn))
        if (f"SystemPurpose.{purpose}" not in source
                or not re.search(r"(?:CaseService|IamAdminService)\(sconn\)\.", source)):
            missing.append(f"{rel}::{fn} ({purpose})")
    assert not missing, missing
    writes = re.compile(r"([\w.]+(?:\([^()]*\))?)\.(assign_user|assign_user_checked|"
                        r"revoke_user|set_compartments)\(")
    elsewhere = []
    for rel, path in _files():
        if rel.startswith("scripts/") or rel in ("cases.py", "iam_admin.py"):
            continue
        for receiver, verb in writes.findall(path.read_text(encoding="utf-8")):
            if receiver not in ("CaseService(sconn)", "IamAdminService(sconn)"):
                elsewhere.append(f"{rel}: {receiver}.{verb}")
    assert not elsewhere, elsewhere


def test_the_live_socket_reads_the_gate_only_on_a_bound_connection():
    """A socket outlives the request that opened it, so each delivery borrows a connection of its
    own. Every one that reaches the gate is bound to the subscriber first, and a new one is listed
    here by name."""
    rel = "http/routers/live.py"
    tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
    opened: set[str] = set()

    def visit(node: ast.AST, stack: list[str]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child, [*stack, child.name])
                continue
            if isinstance(child, ast.Name) and child.id == "connect_request":
                opened.add(".".join(stack) or "<module>")
            visit(child, stack)

    visit(tree, [])
    assert opened == set(_LIVE_CONNECTIONS), {
        "opens a request connection, not listed": sorted(opened - set(_LIVE_CONNECTIONS)),
        "listed, opens none": sorted(set(_LIVE_CONNECTIONS) - opened)}
    handshake = ast.unparse(_function(rel, "_authenticate"))
    assert handshake.index("refuse_unbindable_session(") < handshake.index("_may_read(")
    assert "bind_session(conn, token)" in ast.unparse(_function(rel, "_bound_request_connection"))
    for fn in ("_recheck", "_change_visible", "_delivery_verdict"):
        assert "_bound_request_connection(user_id, token)" in ast.unparse(_function(rel, fn)), fn


def test_a_reader_that_needs_more_than_the_policy_reads_through_a_definer():
    tabled = []
    for (rel, fn), definer in _THROUGH_A_DEFINER.items():
        code = ast.unparse(_function(rel, fn))
        if definer not in code or "iam.case_assignment" in code:
            tabled.append(f"{rel}::{fn}")
    assert not tabled, tabled


def test_a_connection_that_starts_unbound_is_bound_before_the_gate():
    late = []
    for (rel, fn), call in _BOUND_BEFORE_THE_GATE.items():
        code = ast.unparse(_function(rel, fn))
        if call not in code or code.index(call) > code.index("PgAccessResolver("):
            late.append(f"{rel}::{fn}")
    assert not late, late


def test_what_is_owed_is_named():
    """An OWED reader says what it is owed, and every function still owed a
    binding still exists."""
    owed = {key for key, treatment in _READERS.items() if treatment == "OWED"}
    assert owed == set(_OWED), {"OWED without a reason": sorted(owed - set(_OWED)),
                                "a reason for no OWED reader": sorted(set(_OWED) - owed)}
    for rel, fn in _UNBOUND:
        _function(rel, fn)


def test_nothing_is_owed_once_the_table_is_policied():
    """The order the policy depends on: while a reader is owed a definer or
    a binding, the table cannot move into the registry's POLICY map."""
    from noctornal_api import rls_registry

    owed = sorted([f"{rel}::{scope}" for rel, scope in _OWED]
                  + [f"{rel}::{fn}" for rel, fn in _UNBOUND])
    if "iam.case_assignment" in rls_registry.POLICY:
        assert not owed, f"the policy stands and these still read as before it: {owed}"

"""The notification readers that must see every row run as a system
purpose, and nothing but `notify.enqueue` writes a notification (F51,
2026-10-02).

Static: no database. Under 0126 a notification is its recipient's own, so
work that spans recipients (the drain, the delivery ledger and its
requeue, Jira's administration, a request's reach count) reads on a
system connection, and every notice is raised through the definer, which
checks the recipient instead of the writer. A reader that forgot either
would fail closed and silently: an empty ledger, a drain that sends
nothing, a retire that closes nobody's links.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "apps" / "api" / "src" / "noctornal_api"
SCRIPTS = ROOT / "scripts"

#: (module, function) -> the system purpose its work runs under.
_MUST_BE_SYSTEM = {
    ("http/routers/notifications.py", "dispatch"): "NOTIFY",
    ("http/routers/notifications.py", "deliveries"): "NOTIFY_ADMIN",
    ("http/routers/notifications.py", "deliveries_summary"): "NOTIFY_ADMIN",
    ("http/routers/notifications.py", "requeue"): "NOTIFY_ADMIN",
    ("http/routers/notifications.py", "requeue_bulk"): "NOTIFY_ADMIN",
    ("http/routers/approvals.py", "_approvers_reached"): "WITHHELD",
}

#: Every route of Jira's administration takes its connection from this
#: dependency, and the overview's Jira card as well.
_JIRA_ROUTES = ("overview", "get_jira", "create_jira", "patch_jira",
                "put_jira_credential", "test_jira", "activate_jira", "pause_jira",
                "resume_jira", "retire_jira", "jira_links")


def _function(rel: str, name: str) -> ast.FunctionDef:
    tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
    found = [n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]
    assert found, f"{rel} has no function {name}"
    return found[0]


def test_the_readers_that_span_recipients_run_on_a_system_connection():
    missing = [f"{rel}::{fn} ({purpose})"
               for (rel, fn), purpose in _MUST_BE_SYSTEM.items()
               if f"SystemPurpose.{purpose}" not in ast.unparse(_function(rel, fn))]
    assert not missing, missing


def test_jiras_administration_takes_the_notify_admin_connection():
    rel = "http/routers/integrations.py"
    text = (SRC / rel).read_text(encoding="utf-8")
    assert "_ADMIN_CONN = system_conn(SystemPurpose.NOTIFY_ADMIN)" in text
    for name in _JIRA_ROUTES:
        source = ast.unparse(_function(rel, name))
        assert "Depends(_ADMIN_CONN)" in source, name
        if name == "overview":
            # The overview's own reads (routes, readiness) stay as they were;
            # its Jira card is the administration's.
            assert "JiraAdmin(sconn)" in source
        else:
            assert "Depends(get_conn)" not in source, name
    # The case's own view stays on the request connection, under policy.
    for name in ("get_case_routing", "put_case_routing"):
        assert "Depends(get_conn)" in ast.unparse(_function(rel, name)), name


def test_the_cron_drain_is_the_notify_purpose():
    text = (SCRIPTS / "notify_drain.py").read_text(encoding="utf-8")
    assert "connect_system(SystemPurpose.NOTIFY)" in text


def test_nothing_but_the_definer_writes_a_notification_or_its_deliveries():
    """No INSERT into either table anywhere in the application or its
    scripts: a notice is for someone else, and the request role's own
    INSERT is refused (0126) while the definer checks the recipient."""
    pattern = re.compile(r"INSERT\s+INTO\s+notify\.(notification|delivery)\b", re.I)
    offenders = []
    for path in sorted([*SRC.rglob("*.py"), *SCRIPTS.glob("*.py")]):
        text = path.read_text(encoding="utf-8")
        if pattern.search(text):
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, offenders
    fn = _function("notifications.py", "enqueue")
    code = "\n".join(ast.unparse(stmt) for stmt in fn.body
                     if not (isinstance(stmt, ast.Expr)
                             and isinstance(stmt.value, ast.Constant)))
    assert "notify.enqueue(" in code and "RETURNING" not in code


def test_the_coalescing_reads_moved_into_the_definer():
    """The producers' one-open-notice guards read other recipients' rows,
    which the caller cannot see: none of them reads notify.notification
    itself any more, outside the drain's own sweeps."""
    tree = ast.parse((SRC / "notify_events.py").read_text(encoding="utf-8"))
    drain_only = {"case_reviews_due"}
    readers = [n.name for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name not in drain_only
               and "notify.notification" in ast.unparse(n)]
    assert not readers, readers

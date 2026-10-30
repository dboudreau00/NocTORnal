"""`scripts/runtime_roles.py ensure` names every revision after 0108 that takes a privilege back.

0108's blanket grant hands the runtime roles every write on every table, and each later revision that
narrows a privilege exports its SQL (`PRIVILEGES_SQL`, `GRANTS_SQL` or `REVOKE_SQL`) for the repair to
replay after it. The list in the script is kept by hand, so a revision added without a line there would
leave a repaired database holding what the migration took away. This holds the list to the revisions
that export such SQL. No database.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ROOT / "db" / "migrations" / "versions"
SCRIPT = (ROOT / "scripts" / "runtime_roles.py").read_text(encoding="utf-8")

EXPORTS = {"PRIVILEGES_SQL", "GRANTS_SQL", "REVOKE_SQL"}
#: Replayed by 0108 itself, through its RUNTIME_REVOKES list.
BEFORE_THE_BLANKET_GRANT = 108


def _exports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    return names & EXPORTS


def _named(path: Path) -> bool:
    """Whether the script names the revision, by its number or by the words after the number."""
    number, stem = path.stem.split("_", 1)
    return bool(re.search(rf"[\"']{number}[\"']", SCRIPT) or re.search(rf"[\"']{stem}[\"']", SCRIPT))


def test_the_repair_replays_every_revision_that_exports_grants():
    exporting = [p for p in sorted(VERSIONS.glob("0*.py"))
                 if int(p.stem.split("_", 1)[0]) > BEFORE_THE_BLANKET_GRANT and _exports(p)]
    assert exporting, "no revision after 0108 exports grants; the scan is looking in the wrong place"
    missing = [p.name for p in exporting if not _named(p)]
    assert missing == [], (
        f"scripts/runtime_roles.py does not replay {missing}: add each to grant() after the blanket grant")

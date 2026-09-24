"""What an Alpha 5.2 deployment reads while it upgrades, held to the code.

The Alpha 6 pre-release check (2026-09-23) upgraded a populated Alpha 5.2
database and found three things an operator or a script client would be
told wrongly or not at all. The upgrade notes in release/CHANGELOG.md now
point at the files under `release/alpha6-upgrade/`, and these tests hold
those files, and the API document a script client reads, to what the tree
actually does:

- `app-role-grants.sql` is 0060's grants and 0063's revoke, COPIED. A copy
  that drifted from the migrations would hand the runtime role something
  other than what a fresh install gives it, silently.
- `0064-ties-before.sql` runs on the Alpha 5.2 schema, so it may not call
  anything 0064 installs. Whether it predicts the backfill is a database
  question, answered in `test_alpha6_upgrade_ties_pg.py`.
- `POST /samples/{id}/reject` documented itself as destroying the bytes,
  and `purge_bytes` carried no description, so the OpenAPI a 5.2 client
  reads showed no change at all when the default became preservation.

Pure: no database. Reads the migrations, the files and the app's schema.
"""
from __future__ import annotations

import importlib.util
import inspect
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
UPGRADE = ROOT / "release" / "alpha6-upgrade"
VERSIONS = ROOT / "db" / "migrations" / "versions"


def _migration(name: str):
    spec = importlib.util.spec_from_file_location(f"m{name[:4]}", VERSIONS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sql_body(path: Path) -> str:
    """The file without its leading comment block: what psql executes."""
    lines = path.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n")
    while lines and lines[0].startswith("--"):
        lines.pop(0)
    return "\n".join(lines)


def test_the_upgrade_files_are_where_the_notes_send_operators():
    for name in ("0064-ties-before.sql", "0064-ties-after.sql",
                 "app-role-grants.sql"):
        assert (UPGRADE / name).is_file(), f"release/alpha6-upgrade/{name} is missing"


def test_the_role_grants_are_the_migrations_own_statements():
    """0060's UPGRADE_SQL, then the DO block in 0063's upgrade() that takes
    DELETE on lab.preservation_authorisation back, inside one transaction.
    Rendered here from the version files, not retyped, so the comparison
    is with what a fresh install actually runs."""
    m0060 = _migration("0060_app_role_grants")
    m0063 = _migration("0063_sample_preservation")
    block = re.search(
        r'run\(f"""\n(DO \$noc\$.*?REVOKE DELETE ON '
        r'lab\.preservation_authorisation.*?\$noc\$;)\n"""\)',
        inspect.getsource(m0063.upgrade), re.S)
    assert block, "0063 no longer revokes DELETE on lab.preservation_authorisation in one DO block"
    revoke = block.group(1).replace("{APP_ROLE}", m0063.APP_ROLE)
    assert "{" not in revoke, revoke

    expected = ("\\set ON_ERROR_STOP on\nBEGIN;\n" + m0060.UPGRADE_SQL.strip()
                + "\n" + revoke + "\nCOMMIT;\n")
    assert _sql_body(UPGRADE / "app-role-grants.sql") == expected, (
        "release/alpha6-upgrade/app-role-grants.sql no longer matches 0060's "
        "UPGRADE_SQL and 0063's revoke; render it again from the migrations")


def test_the_before_query_runs_on_the_alpha_5_2_schema():
    """It is run BEFORE the upgrade, where 0064's functions do not exist yet,
    and must not change anything it reads."""
    body = _sql_body(UPGRADE / "0064-ties-before.sql").lower()
    for name in ("tie_grade", "tie_confidence", "sync_tie_confidence"):
        assert name not in body, f"the before query calls {name}, which 0064 installs"
    for verb in ("insert", "update", "delete", "alter", "drop", "create", "grant"):
        assert not re.search(rf"\b{verb}\b", body), f"the before query says {verb.upper()}"


def test_the_after_query_is_read_only():
    body = _sql_body(UPGRADE / "0064-ties-after.sql").lower()
    for verb in ("insert", "update", "delete", "alter", "drop", "create", "grant"):
        assert not re.search(rf"\b{verb}\b", body), f"the after query says {verb.upper()}"


def _reject_operation() -> tuple[dict, dict]:
    from noctornal_api.http.app import create_app

    schema = create_app().openapi()
    path = next(p for p in schema["paths"] if p.endswith("/samples/{sample_id}/reject"))
    operation = schema["paths"][path]["post"]
    ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    body = schema["components"]["schemas"][ref.rsplit("/", 1)[-1]]
    return operation, body


def test_the_api_document_says_a_rejection_preserves_by_default():
    """What a script client written against Alpha 5.2 reads. Before the fix
    the description still said the bytes go, and nothing said the same
    request body now keeps them under a legal hold."""
    operation, _ = _reject_operation()
    text = operation["description"]
    assert "NOCTORNAL_REJECTED_SAMPLE_DISPOSITION" in text
    assert "preserve" in text and "destroy" in text
    assert "without retaining the content" not in text
    assert "The bytes go" not in text


def test_purge_bytes_is_described_where_a_client_reads_it():
    _, body = _reject_operation()
    field = body["properties"]["purge_bytes"]
    assert field.get("default") is True, "the default must not move: clients rely on it"
    description = field.get("description", "")
    assert "NOCTORNAL_REJECTED_SAMPLE_DISPOSITION" in description
    assert "preserve" in description and "destroy" in description

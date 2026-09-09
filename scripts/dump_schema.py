"""Regenerate `db/schema.sql` from a live database, or check that it is current.

## Why this exists

`db/schema.sql` has called itself a "mirror" of the Alembic chain since
2026-07-24 (docs/00 decision 17), and it was maintained by hand. By
2026-09-09 the migrations created ten schemas and the file named five --
`comms`, `deception`, `ingest`, `lab` and `notify` were simply absent, along
with everything revisions 0040-0058 added. Nothing checked it, so the one
file a reader is sent to for "the whole schema, end to end" described a
database that had not existed for six weeks. That is this codebase's
signature defect: a document claiming something the code does not do.

The fix is to stop writing the mirror by hand. This script produces it from
the database itself and CI regenerates and diffs it on every push (the
"Schema mirror matches the migrations" step in `.github/workflows/ci.yml`,
the same shape as the ontology drift gate), so the file can no longer
silently fall behind.

## pg_dump, and only pg_dump

The dump is `pg_dump --schema-only --no-owner --no-privileges`. There is
deliberately NO fallback that re-implements the dump over `psycopg` and the
catalogs. A second emitter can never produce byte-identical output, so the
first time CI (which has `pg_dump`) regenerated a file that a developer
(who did not) had produced with the fallback, the diff would report
"schema drift" for what is really a difference between two emitters -- a
failure reported as the wrong thing, which is the other half of the defect
this pass exists to remove. If `pg_dump` is not on PATH, point
`NOCTORNAL_PG_DUMP` at one. The development host this was written on has
no client tools installed and runs Postgres in a container under WSL, so it
uses the server image's own binary:

    NOCTORNAL_PG_DUMP="wsl -d Ubuntu-24.04 -- docker exec noctornal-postgres-1 pg_dump"

CI does the same against its service container (`docker exec <id> pg_dump`),
which means both sides dump with the binary shipped in `pgvector/pgvector:pg16`
rather than whatever client version happens to be installed on the host.

## What is normalised, and why each line is volatile

- `SET ...;` and `SELECT pg_catalog.set_config(...)` -- session settings
  that differ by client version (17 adds `transaction_timeout`) and carry
  no schema.
- `-- Dumped from database version ...` / `-- Dumped by pg_dump version ...`
  -- change on every minor upgrade of either side.
- `\\restrict <token>` / `\\unrestrict <token>` -- added by pg_dump 16.10 /
  17.6 for CVE-2025-8714, with a RANDOM token per run.
- The `alembic_version` ROW is not in a schema-only dump at all; the
  revision it holds is read separately and written into the header so the
  file says which revision it mirrors, and `test_schema_mirror.py` holds
  that header to the chain's head.
- Runs of blank lines are collapsed to one, because removing the lines
  above leaves gaps that would otherwise change with client version too.

Usage:

    python scripts/dump_schema.py            # rewrite db/schema.sql
    python scripts/dump_schema.py --check    # exit 1 with a diff if stale
    python scripts/dump_schema.py --out X    # write somewhere else

Reads DATABASE_URL (SQLAlchemy form `postgresql+psycopg://...` accepted; the
`+psycopg` is stripped for libpq) and NOCTORNAL_PG_DUMP as above.
"""
from __future__ import annotations

import argparse
import difflib
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TARGET = REPO / "db" / "schema.sql"

#: Lines that vary by client version, by run, or that carry no schema.
_VOLATILE = (
    "SET ",
    "SELECT pg_catalog.set_config(",
    "-- Dumped from database version",
    "-- Dumped by pg_dump version",
    "\\restrict",
    "\\unrestrict",
)

_REVISION_LINE = re.compile(r"^-- Alembic revision: (\w+)$", re.M)


def libpq_url(url: str) -> str:
    """SQLAlchemy spells the driver into the scheme; libpq does not know it."""
    return re.sub(r"^postgresql\+psycopg(?:2)?://", "postgresql://", url)


def pg_dump_command() -> list[str]:
    override = os.environ.get("NOCTORNAL_PG_DUMP")
    if override:
        return shlex.split(override)
    found = shutil.which("pg_dump")
    if found:
        return [found]
    sys.exit(
        "pg_dump is not on PATH and NOCTORNAL_PG_DUMP is not set. This script "
        "does not fall back to a hand-written dump (see the module docstring "
        "for why); point NOCTORNAL_PG_DUMP at a pg_dump, e.g.\n"
        "  NOCTORNAL_PG_DUMP=\"wsl -d Ubuntu-24.04 -- docker exec "
        "noctornal-postgres-1 pg_dump\""
    )


def current_revision(url: str) -> str:
    """The revision the database is AT, read from the table Alembic keeps.

    Read from the database rather than from `alembic heads` on purpose: the
    file must say what it mirrors, and if somebody dumps a database that is
    behind head the header will say so and the test will refuse it.
    """
    import psycopg

    with psycopg.connect(libpq_url(url)) as conn:
        rows = conn.execute("SELECT version_num FROM public.alembic_version").fetchall()
    if len(rows) != 1:
        sys.exit(f"expected exactly one alembic_version row, found {len(rows)}: {rows}")
    return rows[0][0]


def normalise(raw: str) -> str:
    out: list[str] = []
    blank = False
    for line in raw.replace("\r\n", "\n").split("\n"):
        if line.startswith(_VOLATILE):
            continue
        if line.strip() == "":
            if blank:
                continue
            blank = True
            out.append("")
            continue
        blank = False
        out.append(line.rstrip())
    while out and out[-1] == "":
        out.pop()
    while out and out[0] == "":
        out.pop(0)
    return "\n".join(out) + "\n"


def header(revision: str) -> str:
    return (
        "-- =====================================================================\n"
        "-- NocTORnal -- db/schema.sql\n"
        "--\n"
        f"-- GENERATED MIRROR of the schema at Alembic revision {revision}.\n"
        "-- Produced by scripts/dump_schema.py from\n"
        "--   pg_dump --schema-only --no-owner --no-privileges\n"
        "-- with session SET lines, version comments and pg_dump's per-run\n"
        "-- \\restrict tokens removed. DO NOT EDIT BY HAND: the authoritative\n"
        "-- schema is the Alembic chain in db/migrations/versions/, every change\n"
        "-- lands there as a new revision, and this file is regenerated with\n"
        "--\n"
        "--   python scripts/dump_schema.py\n"
        "--\n"
        "-- against a database at head. CI regenerates it and fails on any\n"
        "-- difference (.github/workflows/ci.yml, \"Schema mirror matches the\n"
        "-- migrations\"), and apps/api/tests/test_schema_mirror.py holds the\n"
        "-- revision below to the chain's head. The commentary on WHY each table\n"
        "-- is shaped as it is lives in the migration that created it; a dump\n"
        "-- cannot carry it, and until 2026-09-09 the hand-written commentary\n"
        "-- here described five of the ten schemas.\n"
        "--\n"
        "-- Read docs/01-domain-model.md alongside this. The five commitments\n"
        "-- the migrations encode: nothing is a fact (every element has an\n"
        "-- assertion -- constraint triggers in 0022); a handle is not a person\n"
        "-- (IDENTITY and PERSON are separate node types); bitemporal history is\n"
        "-- superseded, never overwritten; edges are signed and time-bounded;\n"
        "-- the ontology lives in reference tables, not enums.\n"
        "--\n"
        f"-- Alembic revision: {revision}\n"
        "-- =====================================================================\n"
        "\n"
    )


def dump(url: str) -> str:
    cmd = pg_dump_command() + [
        "--schema-only", "--no-owner", "--no-privileges", "--dbname", libpq_url(url),
    ]
    proc = subprocess.run(cmd, capture_output=True, check=False)
    if proc.returncode != 0:
        sys.exit(
            f"pg_dump failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    text = proc.stdout.decode("utf-8")
    if "CREATE TABLE" not in text:
        # A dump with no tables is not a mirror of anything; refuse rather than
        # write a file that would make the next diff "pass".
        sys.exit("pg_dump produced no CREATE TABLE statements -- wrong database?")
    return header(current_revision(url)) + normalise(text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--check", action="store_true",
                    help="do not write; exit 1 with a diff if db/schema.sql is stale")
    ap.add_argument("--out", type=Path, default=TARGET, help=f"output path (default {TARGET})")
    args = ap.parse_args(argv)

    url = os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("DATABASE_URL is not set; this script refuses to guess a database.")

    fresh = dump(url)

    if args.check:
        if not args.out.exists():
            print(f"{args.out} does not exist; run scripts/dump_schema.py", file=sys.stderr)
            return 1
        committed = args.out.read_text(encoding="utf-8").replace("\r\n", "\n")
        if committed == fresh:
            rev = _REVISION_LINE.search(fresh)
            print(f"{args.out.relative_to(REPO).as_posix()} matches the database "
                  f"(Alembic revision {rev.group(1) if rev else '?'}).")
            return 0
        diff = difflib.unified_diff(
            committed.splitlines(), fresh.splitlines(),
            fromfile="db/schema.sql (committed)", tofile="db/schema.sql (database)",
            lineterm="", n=2,
        )
        lines = list(diff)
        print(f"db/schema.sql is STALE: {len(lines)} diff line(s). Regenerate with "
              f"`python scripts/dump_schema.py` and commit the result.", file=sys.stderr)
        for line in lines[:400]:
            print(line, file=sys.stderr)
        if len(lines) > 400:
            print(f"... {len(lines) - 400} more line(s)", file=sys.stderr)
        return 1

    args.out.write_text(fresh, encoding="utf-8", newline="\n")
    rev = _REVISION_LINE.search(fresh)
    print(f"wrote {args.out} ({fresh.count(chr(10))} lines, "
          f"Alembic revision {rev.group(1) if rev else '?'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Fill the similarity indexes: the embedding pass (F6.1 and F6.2,
embeddings, 2026-09-24). In collection_poll.py's shape: one process, one
connection, one pass per role, one counters line per role, an exit code.

    python scripts/embed_pass.py                      # both roles
    python scripts/embed_pass.py --role wording       # the built-in embedder only
    python scripts/embed_pass.py --limit 0 --max-seconds 0   # a first backfill
    python scripts/embed_pass.py --dry-run            # counts, touches nothing

Run it as its own compose service (embed-pass, a loop with a 60 second
sleep), not inside the cron loop, so notify_drain and collection_poll keep
their cadence. A first backfill on a large deployment is one manual run
with no limit and no clock: about 40 minutes per million average
documents for similar wording at the measured rate, plus the HNSW inserts.

## What each role does

WORDING runs the built-in embedder in this process. It sends nothing
anywhere, so it does not wait on the readiness register: it collects
nothing and discloses nothing. Its first index is registered active at
once, and a new built-in version is rebuilt in a free slot automatically.
Only the first: when an administrator has retired a role's last index,
neither role registers a new one by itself (refused=retired), because a
new similar meaning index sends every eligible text again and that is an
operator's act (Administration, Embeddings, Rebuild).

MEANING sends item text to an operator's model endpoint, so before ANY
send it needs, in order: settings without problems, no failing BLOCKING
readiness check (with no Security officer nobody can read the trail of
what was sent), a route that reaches the endpoint, and for an endpoint
outside this host the AUTHORITY declaration. A refusal writes no row and
prints refused=<why>. Every batch is audited, with the ids it carries,
before it is sent.

## The counters line

    role=wording space=1a2b3c4d selected=.. embedded=.. empty=.. excluded=..
    withheld=.. failed=.. busy=.. deferred=.. cleared=.. no_free_slot=..
    model_mismatch=.. refused=none locked=0 table_bytes=..

Counts and codes only: never a title, a text, a source name, a document or
a case. `table_bytes` is the size of the three vector tables with their
indexes; this log is the operator's, read at host level, and no API route
reports sizes. `busy` items were being changed by someone else and are
first on the next pass; `deferred` items were not reached before the
clock ran out; `locked` means another pass of the role was running, which
is not a failure.

## Exit code

1 when any item FAILED, or when a configured MEANING role was refused
(readiness, configuration, unrouted, route refused, no authority, an
endpoint error, a changed model); 0 otherwise. A retired index
(refused=retired) is an administrator's choice, not a failure.
"""
from __future__ import annotations

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402
from noctornal_api import embedders  # noqa: E402
from noctornal_api.db import SystemPurpose, connect_system  # noqa: E402
from noctornal_api.embeddings import EmbeddingService  # noqa: E402

load_env_local()


def connect():
    """Every script connects as the system role (S1, 2026-09-25). A
    script serves no request and binds no user, so on the request role it
    would see nothing under row-level security; `db.connect_system` refuses
    rather than hand it a connection that silently sees part of the data.
    Named `connect` so the tests that replace it still find it."""
    return connect_system(SystemPurpose.EMBEDDINGS)

DEFAULT_LIMIT = 5000
DEFAULT_MAX_SECONDS = 240
#: The feature cache of this worker: about 100 MB at 500,000 entries, which
#: a long backfill pays back many times over.
CACHE_SLOTS = 500_000

_TABLE_BYTES = """SELECT coalesce(sum(pg_total_relation_size(c.oid)), 0)
                    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE (n.nspname, c.relname) IN (
                     ('collect', 'document_embedding'), ('core', 'evidence_embedding'),
                     ('core', 'assertion_embedding'))"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fill the similarity indexes.")
    parser.add_argument("--role", choices=("wording", "meaning", "all"), default="all")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                        help="items per role in this pass; 0 is no cap")
    parser.add_argument("--max-seconds", type=float, default=DEFAULT_MAX_SECONDS,
                        help="stop starting batches after this; 0 is no clock")
    parser.add_argument("--dry-run", action="store_true",
                        help="register nothing, send nothing, print what is queued")
    args = parser.parse_args(argv)
    if args.limit < 0 or args.max_seconds < 0:
        parser.error("--limit and --max-seconds are 0 or more")

    roles = ([embedders.ROLE_WORDING, embedders.ROLE_MEANING] if args.role == "all"
             else [args.role.upper()])
    failed = False
    with connect() as conn:
        service = EmbeddingService(conn, cache_slots=CACHE_SLOTS)
        if not args.dry_run:
            service.ensure_spaces()
        for role in roles:
            result = service.run_pass(role, limit=args.limit,
                                      max_seconds=args.max_seconds,
                                      dry_run=args.dry_run)
            size = conn.execute(_TABLE_BYTES).fetchone()[0]
            if args.dry_run:
                print(f"role={role.lower()} dry_run=1 queued={result.pending}")
                continue
            print(result.counters(table_bytes=int(size)), flush=True)
            if result.failed:
                failed = True
            if (role == embedders.ROLE_MEANING and result.refused
                    and result.refused != "retired"
                    and service.configuration.meaning_url_set):
                failed = True
            if result.model_mismatch:
                failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Fill the similarity indexes: one pass per embedding role, one counters line each, an exit code.

    python scripts/embed_pass.py                      # both roles
    python scripts/embed_pass.py --role wording       # the built-in embedder only
    python scripts/embed_pass.py --limit 0 --max-seconds 0   # a first backfill
    python scripts/embed_pass.py --dry-run            # counts, touches nothing

It runs as its own compose service (embed-pass), not in the cron loop, so notify_drain and
collection_poll keep their cadence. A first backfill is one manual run with no limit and no clock,
about 40 minutes per million documents for wording, plus the HNSW inserts.

WORDING embeds in this process and sends nothing anywhere. MEANING sends item text to an
operator's endpoint, so before any send it needs clean settings, no failing blocking readiness
check, a route to the endpoint and, for an endpoint off this host, the AUTHORITY declaration; every
batch is audited with its ids before it is sent. Once an administrator has retired a role's last
index, neither role registers a new one by itself (refused=retired): a new meaning index resends
every eligible text, which is an operator's act. The counters line carries counts and codes only,
never a title, text, source, document or case.

Exit 1 when an item failed or a configured MEANING role was refused; refused=retired is not a
failure. Exit 2 (`config.JOB_REFUSAL_EXIT`) when `config.refuse_unsafe_job_environment` refuses the
production environment, before arguments are read or anything is connected.
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
from noctornal_api.config import JOB_REFUSAL_EXIT, refuse_unsafe_job_environment  # noqa: E402
from noctornal_api.db import SystemPurpose, connect_system  # noqa: E402
from noctornal_api.embeddings import EmbeddingService  # noqa: E402

load_env_local()


def connect():
    """Connect as the system role: a script binds no user, so under row-level security the request
    role would see nothing. Named `connect` because the tests replace it by that name."""
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
    # Before anything is read or connected to: this service starts without waiting for the API, so
    # it refuses an unsafe production environment itself (a published or owner credential, a
    # persona key).
    refusals = refuse_unsafe_job_environment("embed_pass")
    if refusals:
        print("\n".join(refusals), file=sys.stderr)
        return JOB_REFUSAL_EXIT
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

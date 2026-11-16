"""Whether this process can serve: the question a cluster's readiness probe asks (`GET /readyz`).

Ready means two things and no more: a connection with the process's own `DATABASE_URL` opens and
answers within `CONNECT_TIMEOUT_S`, and `public.alembic_version` holds exactly the heads of
`db/migrations`. That is what compose gets from `depends_on` the migrate service completing, and a
pod has no such thing: a pod that starts before its schema is at head would answer every request
with a missing column. Redis, the object store, the egress proxy and the analysis worker are not
asked, because the console must come up while they do not (the readiness register says which of
them is down, and `/api/v1/admin/readiness` is for a person, not a probe).

The answer is nothing a stranger can use: the caller is told ready or not, never a version, a
revision or a reason; the reason goes to the log by its name. The verdict is held for
`VERDICT_TTL_S` and computed by one caller at a time, so an unauthenticated flood costs the database
one connection a window per process, whatever its size. The others are not made to wait: the
endpoint is open and shares the server's threads with `/healthz`, so a database that accepts and
never answers must hold one thread, not all of them. A caller that finds the question in flight is
told the last verdict, or not ready where there has been none. `scripts/wait_for_schema.py` asks
the same question (`schema_problem`) of a pod that serves no HTTP.

`noctornal_app` already holds SELECT on `public.alembic_version` (0060), so no grant is needed.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

import psycopg

log = logging.getLogger("noctornal.readyz")

#: The migration scripts, from this file and never the working directory (the API starts from
#: wherever the operator happens to be). The same place readiness reads them from.
MIGRATIONS_DIR = Path(__file__).resolve().parents[4] / "db" / "migrations"
#: libpq's own connect timeout is whole seconds and treats less than 2 as 2.
CONNECT_TIMEOUT_S = 2
STATEMENT_TIMEOUT_MS = 2000
#: How long a verdict is believed. Module attributes so a test can shrink them.
VERDICT_TTL_S = 5.0


def migration_heads(directory: Path | None = None) -> list[str]:
    """The heads of the migration scripts in `directory`, as alembic reads them. The one reader:
    the readiness row `migrations_at_head`, this endpoint and `scripts/wait_for_schema.py` call
    it, so they cannot disagree about what the head is."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config()
    cfg.set_main_option("script_location", str(directory or MIGRATIONS_DIR))
    return list(ScriptDirectory.from_config(cfg).get_heads())


def schema_problem(url: str | None = None, *, heads: list[str] | None = None) -> str | None:
    """Why this process's database cannot serve, as a fixed word, or None when it can: the
    database answers and its schema is at head. `url` is the DSN to use (DATABASE_URL by
    default). The word names a class of failure and never a value, so it may be logged and printed."""
    from noctornal_api import db

    if heads is None:
        try:
            if not MIGRATIONS_DIR.is_dir():
                return "migrations_missing"
            heads = migration_heads()
        except Exception:  # noqa: BLE001 - an unreadable script directory is a class, not a crash
            return "migrations_unreadable"
        if not heads:
            return "migrations_unreadable"
    try:
        url = url if url is not None else db.dsn()
    except RuntimeError:
        return "database_url_unusable"
    try:
        options = db.session_options(url) + f" -c statement_timeout={STATEMENT_TIMEOUT_MS}"
        with psycopg.connect(url, autocommit=True, connect_timeout=CONNECT_TIMEOUT_S,
                             options=options) as conn:
            stamped = [r[0] for r in conn.execute(
                "SELECT version_num FROM public.alembic_version "
                "ORDER BY version_num").fetchall()]
    except psycopg.errors.UndefinedTable:
        return "schema_absent"
    except psycopg.Error:
        return "database_unreachable"
    if stamped and sorted(stamped) == sorted(heads):
        return None
    return "schema_not_at_head"


#: Guards the three names below for an instant and is never held across the database: a caller that
#: waited on it would hold one of the server's threads for the whole of a hung database's wait, and
#: /healthz shares those threads.
_lock = threading.Lock()
#: (monotonic expiry, the reason or None) of the last verdict. Kept after it expires, so a caller
#: that finds a computation in flight can be told what was last known.
_known: tuple[float, str | None] | None = None
_last_logged: str | None = None
#: True while one caller is asking the database.
_computing = False


def forget() -> None:
    """Drop the remembered verdict (a test changes the database under it)."""
    global _known, _last_logged
    with _lock:
        _known = None
        _last_logged = None


def verdict() -> bool:
    """Whether this process is ready, from the remembered answer while it is fresh, else asked of
    the database by this caller alone. A caller that finds the question already being asked does not
    wait for it: it is told the last answer, or not ready where there has been none, at once."""
    global _known, _last_logged, _computing
    with _lock:
        if _known is not None and time.monotonic() < _known[0]:
            return _known[1] is None
        if _computing:
            return _known is not None and _known[1] is None
        _computing = True
    reason = "verdict_failed"
    try:
        reason = schema_problem()
    finally:
        with _lock:
            _computing = False
            _known = (time.monotonic() + VERDICT_TTL_S, reason)
            changed = reason != _last_logged
            _last_logged = reason
    if changed:
        if reason:
            log.warning("readyz: not ready (%s)", reason)
        else:
            log.info("readyz: ready")
    return reason is None


__all__ = ["CONNECT_TIMEOUT_S", "MIGRATIONS_DIR", "VERDICT_TTL_S", "forget",
           "migration_heads", "schema_problem", "verdict"]

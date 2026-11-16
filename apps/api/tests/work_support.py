"""What one request does: the statements it sends and the audit rows it adds.

Two requests that send the same statements in the same order do the same work, whatever the host's
timing, so the equality of a hidden id and a missing one (decision 230) is pinned on this record and
not on a clock. A statement is its SQL text with the whitespace collapsed; the parameters are left
out, since the ids differ by construction. The request connection and the system connections are
kept apart. An audit row is the columns a reader compares (actor, action, object, case, outcome,
detail); its id, sequence, hashes and time are not compared.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass
from uuid import UUID

import psycopg

_SPACE = re.compile(r"\s+")

#: The audit columns two refusals are compared on.
AUDIT_COLUMNS = ("actor_id", "actor_kind", "action", "object_type", "object_id",
                 "case_id", "outcome", "detail")


@dataclass(frozen=True)
class Work:
    """One request: what the caller was told, what it sent and what it recorded."""
    answer: tuple[int, str | None, str | None]
    statements: tuple[str, ...]
    system: tuple[str, ...]
    rows: tuple[dict, ...]


def normalise(query, context) -> str:
    """The statement's SQL with its whitespace collapsed to single spaces."""
    if isinstance(query, bytes):
        text = query.decode()
    elif isinstance(query, str):
        text = query
    else:
        text = query.as_string(context)
    return _SPACE.sub(" ", text).strip()


def _cursor_recording(log: list[str]) -> type[psycopg.Cursor]:
    class Recording(psycopg.Cursor):
        def execute(self, query, params=None, **kwargs):
            log.append(normalise(query, self))
            return super().execute(query, params, **kwargs)

        def executemany(self, query, params_seq, **kwargs):
            log.append(normalise(query, self))
            return super().executemany(query, params_seq, **kwargs)

    return Recording


@contextmanager
def recording(app):
    """Record every statement `app` sends while the block runs: its request connections through an
    override of `deps.get_conn`, and its system connections through `db.connect_system`. Yields the
    two logs."""
    from noctornal_api import db
    from noctornal_api.http import deps

    request_log: list[str] = []
    system_log: list[str] = []
    real_connect_system = db.connect_system

    def get_conn():
        conn = db.connect_request()
        conn.cursor_factory = _cursor_recording(request_log)
        try:
            yield conn
        finally:
            conn.close()

    def connect_system(purpose):
        conn = real_connect_system(purpose)
        conn.cursor_factory = _cursor_recording(system_log)
        return conn

    app.dependency_overrides[deps.get_conn] = get_conn
    db.connect_system = connect_system
    try:
        yield request_log, system_log
    finally:
        db.connect_system = real_connect_system
        app.dependency_overrides.pop(deps.get_conn, None)


def answer(response) -> tuple[int, str | None, str | None]:
    """What the caller is told: the status, the problem's title and its sentence."""
    try:
        body = response.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    detail = body.get("detail")
    return (response.status_code, body.get("title"),
            detail if isinstance(detail, str) else None)


def _last_seq(owner) -> int:
    return owner.execute("SELECT coalesce(max(seq), 0) FROM audit.event").fetchone()[0]


def audit_rows_since(owner, seq: int, actor: UUID) -> tuple[dict, ...]:
    rows = owner.execute(
        f"SELECT {', '.join(AUDIT_COLUMNS)} FROM audit.event "
        "WHERE seq > %s AND actor_id = %s ORDER BY seq", (seq, actor)).fetchall()
    return tuple(dict(zip(AUDIT_COLUMNS, row, strict=True)) for row in rows)


def record(client, owner, method: str, url: str, *, headers: dict, json=None,
           actor: UUID) -> Work:
    """Send one request through `client` and return its `Work`."""
    before = _last_seq(owner)
    with recording(client.app) as (request_log, system_log):
        response = client.request(method, url, headers=headers, json=json)
    return Work(answer=answer(response), statements=tuple(request_log),
                system=tuple(system_log),
                rows=audit_rows_since(owner, before, actor))

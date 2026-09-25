"""The egress connection ledger: what left this deployment, through which
route, to where, and how it ended (the egress proxy S2, 2026-09-24;
docs/00 decision 68: every connection is logged append-only).

## An event ledger, written by the proxy alone

`collect.egress_connection` (migration 0086) takes one row per EVENT:

- OPEN, committed BEFORE the proxy dials, so a connection that happened
  always has its row: when the INSERT fails the proxy refuses the client
  with ledger_unavailable and dials nothing;
- REFUSED, once the route is known (the credentials held), with the
  egress_policy code as the reason;
- CLOSE at teardown, with the bytes each way, the duration and one of
  CLOSE_REASONS. A proxy killed mid-tunnel leaves an OPEN with no CLOSE,
  and the reader says so rather than inventing one;
- PREAUTH: refusals before the credentials held (a bad token, a malformed
  head, the handshake caps) are COUNTED per peer address and written at
  most once a minute per peer, so a flood from a compromised container
  costs one row a minute and never holds the chain lock against OPEN
  rows. Nothing the client presented is stored;
- REWRAP: `python -m noctornal_api.egress_proxy rewrap --apply` re-sealed
  that many exits under the active key.

Development without a proxy writes NO row (docs/20 section 10, reading
3), and the readiness probe route is never written (it dials and resolves
nothing).

## Append-only and hash-chained from the first row

A BEFORE UPDATE OR DELETE row trigger and a BEFORE TRUNCATE statement
trigger refuse every change, and the chain trigger takes the advisory lock
and THEN draws `seq` from its sequence, so seq order is chain order and
concurrent writers cannot fork it. audit.event draws its seq before the
lock, which audit_verify.py documents as producing false breaks; the proxy
writes from eight executor threads, so this ledger does not copy that.
`verify` recomputes the chain with the trigger's own expression, which is
duplicated here from the migration and held equal by a test.

## Labels are decided when a row is READ

A persona row names a forum host, which is exactly what a RED source's
label protects. So the reader shows a persona row only within the
caller's clearance, taking the GREATER of the stored label and its
source's CURRENT label (a source raised from AMBER to RED raises every
earlier row), and, once collect.source carries compartments, only to a
caller holding all of the source's CURRENT compartments. An ACT or STOP
row whose destination matched no source (an address inside the profile's
networks) is labelled by the persona's currently bound sources. A row
whose source has since been deleted is shown on its stored label only when
it was not compartmented. Integration rows are GREEN: their destinations
are an administrator's exact allowlist entries, configuration an
egress.log.read holder already sees.

## Who can write it

The proxy connects as `noctornal_egress`, which holds exactly
EGRESS_GRANTS (the migration's grant block, the proxy's start check and
test_egress_role_privileges_pg.py all hold that list), and the
application role keeps SELECT only, so the API cannot forge a proxy row.
The schema owner can rewrite anything, the chain included; the chain is
evidence against any writer less than the owner, and `verify` is how it
is read.
"""
from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

import psycopg

#: The proxy's database role, created at initdb by db/init/20-egress-role.sh.
EGRESS_ROLE = "noctornal_egress"

#: Every privilege the proxy's role holds, as (kind, object, privilege,
#: columns or None). ONE list: migration 0086 grants a copy of it (a
#: migration does not import the app, and a test holds the two equal), the
#: proxy refuses to start unless has_column_privilege / has_table_privilege
#: confirm every entry, and test_egress_role_privileges_pg.py asserts the
#: role holds exactly this. The collection columns are the collection
#: foundation's; a column a later migration adds (for example
#: collect.source.compartments) is appended here, with its grant in a
#: guarded migration block.
EGRESS_GRANTS: tuple[tuple[str, str, str, tuple[str, ...] | None], ...] = (
    ("schema", "collect", "USAGE", None),
    ("table", "collect.egress_profile", "SELECT", None),
    ("table", "collect.egress_profile", "UPDATE", ("exit_sealed", "exit_seal_key_id")),
    ("table", "collect.egress_integration_route", "SELECT", None),
    ("table", "collect.egress_destination", "SELECT", None),
    ("table", "collect.egress_binding", "SELECT", None),
    ("table", "collect.collection_run", "SELECT",
     ("id", "status", "source_id", "collection_account_id", "egress_profile_id",
      "authority_id", "authority_target_id", "started_at")),
    ("table", "collect.source", "SELECT",
     ("id", "kind", "parser_key", "base_url", "classification", "is_active",
      "collection_account_id", "egress_profile_id")),
    # Never the secret columns: the proxy reads a persona's state, its
    # binding and its venue source, and nothing it could log in in with.
    ("table", "collect.collection_account", "SELECT",
     ("id", "status", "cooldown_until", "machine_hold_until",
      "machine_lock_code", "egress_profile_id", "source_id")),
    ("table", "collect.collection_authority", "SELECT",
     ("id", "collection_account_id", "recorded_at", "confirmed_at",
      "revoked_at", "valid_from", "valid_until")),
    ("table", "collect.collection_authority_target", "SELECT",
     ("id", "authority_id", "source_id", "added_at", "confirmed_at",
      "revoked_at", "target_base_url")),
    ("table", "collect.egress_connection", "SELECT",
     ("seq", "row_hash", "event", "occurred_at", "context_kind",
      "collection_account_id")),
    ("table", "collect.egress_connection", "INSERT", None),
    ("sequence", "collect.egress_connection_seq", "USAGE", None),
)

#: How a CLOSE row says a tunnel ended. authority_revoked also covers an
#: authority that a later widening voided; route_withdrawn covers a route
#: switched off, retired or narrowed, and a source raised above the
#: profile's ceiling; persona_withdrawn covers a persona burnt, locked,
#: held by its platform or unbound (2026-09-24).
CLOSE_REASONS = ("client_closed", "upstream_closed", "idle_timeout",
                 "session_limit", "proxy_shutdown", "error", "authority_revoked",
                 "run_finished", "route_withdrawn", "persona_withdrawn")

EVENTS = ("OPEN", "REFUSED", "CLOSE", "PREAUTH", "REWRAP")
PROTOCOLS = ("HTTP_CONNECT", "SOCKS5")

#: The key a destination digest is made with, derived from the client key,
#: so repeated refusals of one hidden destination correlate without the
#: destination being written.
_DIGEST_LABEL = b"noctornal-egress-ledger-v1"

#: The row hash, with `{r}` the row and `{prev}` the previous hash. The
#: migration's trigger carries the same text with NEW and prev (a
#: migration does not import the app); test_egress_connection_ledger_pg.py
#: reads both and holds them equal.
ROW_HASH_SQL = """public.digest(convert_to(concat_ws(chr(31),
  coalesce(encode({prev},'hex'),'GENESIS'),
  {r}.seq::text,
  to_char({r}.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  {r}.event,
  coalesce({r}.connection_id::text,'-'),
  coalesce({r}.protocol,'-'),
  coalesce({r}.route_kind,'-'),
  {r}.route_id,
  coalesce({r}.peer_address::text,'-'),
  coalesce({r}.egress_profile_id::text,'-'),
  coalesce({r}.integration_route_id::text,'-'),
  coalesce({r}.collection_run_id::text,'-'),
  coalesce({r}.source_id::text,'-'),
  coalesce({r}.collection_account_id::text,'-'),
  coalesce({r}.authority_id::text,'-'),
  coalesce({r}.context_kind,'-'),
  coalesce({r}.context_id::text,'-'),
  coalesce({r}.dest_host,'-'),
  coalesce(encode({r}.dest_digest,'hex'),'-'),
  coalesce({r}.dest_port::text,'-'),
  coalesce({r}.resolved_address::text,'-'),
  coalesce({r}.exit_kind,'-'),
  {r}.reason,
  coalesce({r}.item_count::text,'-'),
  coalesce({r}.bytes_up::text,'-'),
  coalesce({r}.bytes_down::text,'-'),
  coalesce({r}.duration_ms::text,'-'),
  {r}.classification::text,
  {r}.source_compartmented::text
), 'UTF8'), 'sha256')"""


def _render_grant(kind: str, obj: str, privilege: str,
                  columns: tuple[str, ...] | None) -> str:
    cols = f" ({', '.join(columns)})" if columns else ""
    target = {"schema": "SCHEMA ", "table": "", "sequence": "SEQUENCE "}[kind]
    return f"GRANT {privilege}{cols} ON {target}{obj} TO {EGRESS_ROLE};"


#: What scripts/egress_setup.py role-sql prints for a cluster that predates
#: the role: the grants, once the superuser has created it.
EGRESS_ROLE_SQL = "\n".join(_render_grant(*entry) for entry in EGRESS_GRANTS)


def missing_grants(conn: psycopg.Connection, role: str | None = None) -> list[str]:
    """Every EGRESS_GRANTS entry `role` (the connected user by default) does
    not hold, as 'PRIVILEGE ON object(column)'. The proxy refuses to start
    on the first, so a column renamed by a later migration fails loudly at
    start rather than as an opaque refusal of every persona connection."""
    role = role or conn.execute("SELECT current_user").fetchone()[0]
    missing: list[str] = []
    for kind, obj, privilege, columns in EGRESS_GRANTS:
        if kind == "schema":
            ok = conn.execute("SELECT has_schema_privilege(%s, %s, %s)",
                              (role, obj, privilege)).fetchone()[0]
            if not ok:
                missing.append(f"{privilege} ON SCHEMA {obj}")
            continue
        exists = conn.execute("SELECT to_regclass(%s) IS NOT NULL",
                              (obj,)).fetchone()[0]
        if not exists:
            missing.append(f"{privilege} ON {obj} (it does not exist)")
            continue
        if kind == "sequence":
            ok = conn.execute("SELECT has_sequence_privilege(%s, %s, %s)",
                              (role, obj, privilege)).fetchone()[0]
            if not ok:
                missing.append(f"{privilege} ON SEQUENCE {obj}")
            continue
        if columns is None:
            ok = conn.execute("SELECT has_table_privilege(%s, %s, %s)",
                              (role, obj, privilege)).fetchone()[0]
            if not ok:
                missing.append(f"{privilege} ON {obj}")
            continue
        schema, _, table = obj.partition(".")
        for column in columns:
            present = conn.execute(
                """SELECT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_schema = %s AND table_name = %s
                      AND column_name = %s)""", (schema, table, column)).fetchone()[0]
            if not present:
                missing.append(f"{privilege} ON {obj} ({column}: no such column)")
                continue
            ok = conn.execute("SELECT has_column_privilege(%s, %s, %s, %s)",
                              (role, obj, column, privilege)).fetchone()[0]
            if not ok:
                missing.append(f"{privilege} ON {obj} ({column})")
    return missing


def destination_digest(client_key: bytes, host: str, port: int | None) -> bytes:
    """A keyed digest of a destination that must not be written in the
    clear: a persona refusal whose destination failed the source tie, or a
    host that did not normalise. Correlates repeats; names nothing."""
    key = hmac.new(client_key, _DIGEST_LABEL, hashlib.sha256).digest()
    return hmac.new(key, f"{host}:{port}".encode("utf-8", "replace"),
                    hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Writers (run on the proxy's executor, each one statement, autocommit)
# ---------------------------------------------------------------------------

_COLUMNS = ("event", "connection_id", "protocol", "route_kind", "route_id",
            "peer_address", "egress_profile_id", "integration_route_id",
            "collection_run_id", "source_id", "collection_account_id",
            "authority_id", "context_kind", "context_id", "dest_host",
            "dest_digest", "dest_port", "resolved_address", "exit_kind", "reason",
            "item_count", "bytes_up", "bytes_down", "duration_ms",
            "classification", "source_compartmented")


@dataclass
class Row:
    """One ledger row to write. Only the fields its event takes are set."""

    event: str
    route_id: str
    reason: str
    connection_id: UUID | None = None
    protocol: str | None = None
    route_kind: str | None = None
    peer_address: str | None = None
    egress_profile_id: UUID | None = None
    integration_route_id: UUID | None = None
    collection_run_id: UUID | None = None
    source_id: UUID | None = None
    collection_account_id: UUID | None = None
    authority_id: UUID | None = None
    context_kind: str | None = None
    context_id: UUID | None = None
    dest_host: str | None = None
    dest_digest: bytes | None = None
    dest_port: int | None = None
    resolved_address: str | None = None
    exit_kind: str | None = None
    item_count: int | None = None
    bytes_up: int | None = None
    bytes_down: int | None = None
    duration_ms: int | None = None
    classification: str = "GREEN"
    source_compartmented: bool = False


def write(conn: psycopg.Connection, row: Row) -> int:
    """INSERT one row and return its seq. On an autocommit connection the
    statement is its own transaction, so the row is COMMITTED when this
    returns: the proxy dials only after it has."""
    if row.event not in EVENTS:
        raise ValueError(f"unknown ledger event {row.event!r}")
    if row.event == "CLOSE" and row.reason not in CLOSE_REASONS:
        raise ValueError(f"unknown close reason {row.reason!r}")
    values = [getattr(row, name) for name in _COLUMNS]
    placeholders = ", ".join(["%s"] * len(_COLUMNS))
    return conn.execute(
        f"INSERT INTO collect.egress_connection ({', '.join(_COLUMNS)}) "
        f"VALUES ({placeholders}) RETURNING seq", values).fetchone()[0]


def stops_in_last_hour(conn: psycopg.Connection, persona_id: UUID) -> int:
    """STOP OPEN rows of one persona in the last hour. Called inside the
    per-persona advisory lock the OPEN insert then runs under."""
    return conn.execute(
        """SELECT count(*) FROM collect.egress_connection
            WHERE collection_account_id = %s AND context_kind = 'stop'
              AND event = 'OPEN' AND occurred_at > clock_timestamp() - interval '1 hour'""",
        (persona_id,)).fetchone()[0]


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

def verify(conn: psycopg.Connection) -> dict:
    """Recompute the chain positionally with the trigger's expression.
    {rows, first_break_seq, checked_at}: first_break_seq is None when every
    row's prev_hash is the row before's row_hash and every row_hash
    recomputes."""
    expression = ROW_HASH_SQL.format(r="r", prev="r.expected_prev")
    row = conn.execute(
        f"""WITH r AS (
              SELECT c.*, lag(c.row_hash) OVER (ORDER BY c.seq) AS expected_prev
                FROM collect.egress_connection c)
            SELECT count(*),
                   min(r.seq) FILTER (
                     WHERE r.prev_hash IS DISTINCT FROM r.expected_prev
                        OR r.row_hash IS DISTINCT FROM {expression})
              FROM r""").fetchone()
    return {"rows": row[0], "first_break_seq": row[1],
            "checked_at": datetime.now(timezone.utc).isoformat()}


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

_CLOSE_WORDS = {
    "client_closed": "The client closed it.",
    "upstream_closed": "The destination closed it.",
    "idle_timeout": "Closed after it sat idle.",
    "session_limit": "Closed at the route's session limit.",
    "proxy_shutdown": "Closed when the proxy stopped.",
    "error": "Closed on an error.",
    "authority_revoked": "Closed because its collection authority no longer covered it.",
    "run_finished": "Closed because its run finished.",
    "route_withdrawn": "Closed because its route was switched off, retired or narrowed.",
    "persona_withdrawn": "Closed because its persona could no longer be used.",
}
NO_CLOSE = "No close was recorded: the proxy stopped while this was open."


def close_sentence(reason: str) -> str:
    return _CLOSE_WORDS.get(reason, "Closed.")


def source_has_compartments(conn: psycopg.Connection) -> bool:
    """Whether collect.source carries a compartments column (no
    migration adds one yet). Read per call: cheap, and a reader built
    before such a migration ran must not keep the old answer."""
    return conn.execute(
        """SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'collect' AND table_name = 'source'
              AND column_name = 'compartments')""").fetchone()[0]


def listing(conn: psycopg.Connection, *, clearance: str,
            compartments: Iterable[str] = (), route_id: str | None = None,
            event: str | None = None, since: datetime | None = None,
            limit: int = 200) -> dict:
    """The rows the caller may see, newest first, each OPEN paired with its
    CLOSE, with how many matching rows were withheld. `clearance` is a TLP
    name (deps.user_ceiling, no case)."""
    if event is not None and event not in ("OPEN", "REFUSED", "PREAUTH", "REWRAP"):
        raise ValueError("event is OPEN, REFUSED, PREAUTH or REWRAP")
    held = sorted(set(compartments))
    has_comp = source_has_compartments(conn)
    # Which sources a persona is bound to is the collection framework's
    # column; before it exists no ACT or STOP row can have been written.
    bound = conn.execute(
        """SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'collect' AND table_name = 'source'
              AND column_name = 'collection_account_id')""").fetchone()[0]
    where = ["c.event <> 'CLOSE'"]
    named: dict = {"held": held, "clearance": clearance}
    if route_id:
        where.append("c.route_id = %(route_id)s")
        named["route_id"] = route_id
    if event:
        where.append("c.event = %(event)s")
        named["event"] = event
    if since is not None:
        where.append("c.occurred_at >= %(since)s")
        named["since"] = since
    # The effective label: the greater of the stored label and, for a
    # persona row, its source's current label, or for an ACT or STOP row
    # that matched no source, the persona's bound sources' labels now. A
    # row's source is the one it names, else its run's: a RUN row the proxy
    # refused before it matched a source still belongs to that run's
    # source, and is labelled and compartmented by it (2026-09-25).
    subject = "coalesce(c.source_id, r.source_id)"
    if has_comp and bound:
        comp_ok = f"""(
          CASE
            WHEN c.route_kind IS DISTINCT FROM 'persona' THEN true
            WHEN {subject} IS NOT NULL AND s.id IS NULL THEN NOT c.source_compartmented
            WHEN {subject} IS NOT NULL THEN coalesce(s.compartments, '{{}}') <@ %(held)s::text[]
            WHEN c.context_kind IN ('act', 'stop') THEN NOT EXISTS (
              SELECT 1 FROM collect.source s3
               WHERE s3.collection_account_id = c.collection_account_id
                 AND NOT (coalesce(s3.compartments, '{{}}') <@ %(held)s::text[]))
            ELSE true END)"""
    else:
        comp_ok = f"""(
          CASE WHEN {subject} IS NOT NULL AND s.id IS NULL
               THEN NOT c.source_compartmented ELSE true END)"""
    persona_label = (f"""CASE WHEN c.route_kind = 'persona' AND {subject} IS NULL
                                  AND c.context_kind IN ('act', 'stop')
                             THEN (SELECT max(s3.classification) FROM collect.source s3
                                    WHERE s3.collection_account_id = c.collection_account_id)
                        END""" if bound else "NULL::core.tlp")
    base = f"""
      WITH filtered AS (
        SELECT c.*, s.id AS live_source,
               GREATEST(c.classification,
                        CASE WHEN c.route_kind = 'persona' AND s.id IS NOT NULL
                             THEN s.classification END,
                        {persona_label}) AS effective,
               {comp_ok} AS compartments_ok
          FROM collect.egress_connection c
          LEFT JOIN collect.collection_run r
                 ON c.source_id IS NULL AND r.id = c.collection_run_id
          LEFT JOIN collect.source s ON s.id = {subject}
         WHERE {' AND '.join(where)})
    """
    visible = "(f.effective <= %(clearance)s::core.tlp AND f.compartments_ok)"
    withheld = conn.execute(
        base + f"SELECT count(*) FROM filtered f WHERE NOT {visible}", named).fetchone()[0]
    named["limit"] = max(1, min(int(limit), 500))
    rows = conn.execute(
        base + f"""
        SELECT f.seq, f.occurred_at, f.event, f.connection_id, f.protocol,
               f.route_kind, f.route_id, f.egress_profile_id, f.integration_route_id,
               f.collection_run_id, f.source_id, f.collection_account_id,
               f.context_kind, f.context_id, f.dest_host, f.dest_port,
               f.resolved_address::text, f.exit_kind, f.reason, f.item_count,
               f.effective::text,
               cl.occurred_at, cl.reason, cl.bytes_up, cl.bytes_down, cl.duration_ms,
               f.dest_digest IS NOT NULL
          FROM filtered f
          LEFT JOIN LATERAL (
            SELECT x.occurred_at, x.reason, x.bytes_up, x.bytes_down, x.duration_ms
              FROM collect.egress_connection x
             WHERE f.event = 'OPEN' AND x.event = 'CLOSE'
               AND x.connection_id = f.connection_id
             ORDER BY x.seq LIMIT 1) cl ON true
         WHERE {visible}
         ORDER BY f.seq DESC
         LIMIT %(limit)s""", named).fetchall()
    out = []
    for r in rows:
        item = {
            "seq": r[0], "occurred_at": r[1].isoformat(), "event": r[2],
            "connection_id": _s(r[3]), "protocol": r[4], "route_kind": r[5],
            "route_id": r[6], "egress_profile_id": _s(r[7]),
            "integration_route_id": _s(r[8]), "collection_run_id": _s(r[9]),
            "source_id": _s(r[10]), "collection_account_id": _s(r[11]),
            "context_kind": r[12], "context_id": _s(r[13]), "dest_host": r[14],
            "dest_port": r[15], "resolved_address": r[16], "exit_kind": r[17],
            "reason": r[18], "item_count": r[19], "classification": r[20],
            "destination_withheld": bool(r[26]),
            "reason_text": _reason_text(r[2], r[18]),
        }
        if r[5] == "persona" and r[9] is None and r[10] is None and r[11] is None \
                and r[14] is not None:
            # A persona row with no run, source or persona has nothing to be
            # labelled by today; the proxy no longer writes a host on one,
            # and an older row keeps its host to itself.
            item["dest_host"] = None
            item["destination_withheld"] = True
        if r[2] == "OPEN":
            if r[21] is None:
                item["closed"] = None
                item["close_text"] = NO_CLOSE
            else:
                item["closed"] = {"occurred_at": r[21].isoformat(), "reason": r[22],
                                  "bytes_up": r[23], "bytes_down": r[24],
                                  "duration_ms": r[25]}
                item["close_text"] = close_sentence(r[22])
        out.append(item)
    return {"rows": out, "withheld": withheld}


def _s(value) -> str | None:
    return None if value is None else str(value)


def _reason_text(event: str, reason: str) -> str:
    from noctornal_api.egress_policy import CODES, explain

    if event == "OPEN":
        return "Allowed."
    if event == "PREAUTH":
        return "Refused before its credentials were accepted."
    if event == "REWRAP":
        return "Sealed exits were sealed again under the active key."
    if reason in CODES:
        text = explain(reason)
        return text[0].upper() + text[1:] + "."
    return "Refused."

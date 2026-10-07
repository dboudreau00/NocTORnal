"""Database connection helper.

Reads DATABASE_URL (the same variable Alembic uses) and normalises the
SQLAlchemy-style scheme to plain psycopg. Secrets come from the
environment, never a default in code (repo convention).
"""
from __future__ import annotations

import hashlib
import os
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

import psycopg


def dsn() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        # SET-BUT-EMPTY is a different problem from ABSENT, and reporting
        # "is not set" for it sends people to look in the wrong place --
        # typically at .env.local, where the value is sitting perfectly
        # correctly the whole time.
        #
        # The variable ends up defined-and-empty more easily than it looks:
        # `docker run -e DATABASE_URL` with no `=value` forwards it as
        # empty when the host has no such variable, a CI matrix can supply
        # a blank default, and PowerShell's
        # `[Environment]::SetEnvironmentVariable(name, $null, 'Process')`
        # leaves the name defined with an empty value rather than removing
        # it. In every one of those cases scripts/_env.py deliberately
        # declines to override an already-defined variable, so the file
        # value never arrives.
        if "DATABASE_URL" in os.environ:
            raise RuntimeError(
                "DATABASE_URL is set but empty. An empty value still counts "
                "as set, so it overrides the one in .env.local. Unset the "
                "variable entirely, or give it a value.")
        raise RuntimeError("DATABASE_URL is not set")
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


def connect() -> psycopg.Connection:
    # autocommit=True: the stores are single-statement and atomic (the TOTP
    # counter advance and the lockout increment are compare-and-set UPDATEs),
    # so no multi-statement transaction is needed and read paths never leave
    # a connection "idle in transaction" pinning the vacuum horizon.
    #
    # connect_timeout: libpq's default is effectively "wait for ever" on a
    # host that does not answer. A database that is down therefore did not
    # FAIL -- every request, every test and every script sat in TCP connect
    # until something external killed it (a 300s CI timeout, a person).
    # Found 2026-09-01 when the dev stack was down and a read-only audit
    # hung for five minutes with no message. A connect that cannot complete
    # in ten seconds is not going to; say so.
    url = dsn()
    return psycopg.connect(url, autocommit=True,
                           connect_timeout=connect_timeout_seconds(),
                           options=session_options(url))


#: Server settings every application connection is opened with (G62 load
#: gate, 2026-10-07). JIT compiles a query's expressions once the planner's
#: cost estimate passes `jit_above_cost`, and row security's policies inflate
#: that estimate on every case read: on a 1,000,000-claim database the search,
#: the triage queue and the graph view each spent 1.5 to 2.4 s compiling for
#: 0.1 to 0.5 s of work. JIT never changes an answer, only how it is
#: computed, and nothing this process asks Postgres is an analytical scan
#: that would repay it (the graph maths runs in igraph).
SESSION_OPTIONS = "-c jit=off"


def session_options(conninfo: str) -> str:
    """The `options` a connection to `conninfo` is opened with: whatever the
    DSN already names, then SESSION_OPTIONS, so an operator's own settings
    in DATABASE_URL are kept rather than replaced."""
    from psycopg.conninfo import conninfo_to_dict
    named = conninfo_to_dict(conninfo).get("options")
    return f"{named} {SESSION_OPTIONS}" if named else SESSION_OPTIONS


def connect_timeout_seconds() -> int:
    """Seconds to wait for the TCP/handshake phase before giving up.

    Overridable for tests and for genuinely slow links; never unbounded.
    A value of 0 would mean "no limit" to libpq, so it is clamped to 1.
    """
    raw = os.environ.get("NOCTORNAL_DB_CONNECT_TIMEOUT", "10").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 10


# ---------------------------------------------------------------------------
# Row-level security (S1, 2026-09-25). Everything below is how a
# connection comes to be subject to the policies (the request role, bound to
# a user) or exempt from them (the system role, for work that must see every
# row).
#
# Development and the test suite connect as the schema OWNER, which row
# security never filters. On such a connection nothing below changes
# behaviour: `system_connection(..., reuse=conn)` hands back `conn` itself,
# so the transaction a caller opened is still the one its work runs in, and
# binding only sets a setting nothing reads.
# ---------------------------------------------------------------------------

#: The request role (db/init/10-app-role.sh, 0060).
APP_ROLE = "noctornal_app"
#: The system role (db/init/10-app-role.sh, 0108): BYPASSRLS, owns nothing.
WORKER_ROLE = "noctornal_worker"
#: The system role's DSN. Empty is unset: the sample origin's compose value
#: is "", because the process that serves hostile bytes must not hold it.
WORKER_DSN_ENV = "NOCTORNAL_WORKER_DATABASE_URL"
#: Development and CI only (config refuses it in production): request
#: connections SET ROLE to the request role and system connections to the
#: system role, from the owner's own login, so the HTTP suites run in
#: production's shape with no runtime password in the test environment.
ASSUME_ROLE_ENV = "NOCTORNAL_TEST_ASSUME_ROLE"


class SystemPurpose(StrEnum):
    """Why a connection needs to see every row. Each member names work whose
    correctness depends on completeness (a count, a guard that permits on
    zero, a sweep, a chain) or that writes the IAM plane, which the request
    role may only read (0109). `test_rls_system_paths.py` holds every call
    site to a member and every member to a call site."""
    AUTH = "auth"                        # sign-in, sessions, second factors
    IAM_ADMIN = "iam_admin"              # accounts, roles, compartments, policy
    CASE_MEMBERSHIP = "case_membership"  # case creation and its assignments
    BREAK_GLASS = "break_glass"          # invoke, revoke, review
    TICKETS = "tickets"                  # download and production ticket mint
    GRAPH_GUARD = "graph_guard"          # retirement refused over hidden ties
    WITHHELD = "withheld"                # counts of what a reader cannot see
    RETENTION = "retention"              # due, purge, legal hold
    EVIDENCE_LOCKS = "evidence_locks"    # every exhibit's lock follows the case
    COMPARTMENTS = "compartments"        # rename, retire, where carried
    MERGE = "merge"                      # merge and unmerge with their approval
    # Every probe of the readiness register but the two about the request
    # connection itself: each counts across the deployment (S1, 2026-09-25).
    READINESS = "readiness"
    AUDIT_VERIFY = "audit_verify"        # the audit and custody chain walks
    LAB_PROPOSE = "lab_propose"          # the Lab proposes into a case it is not on
    NOTIFY = "notify"                    # the outbox drain, cron or Drain now
    # The delivery ledger, its requeue and the Jira destination's
    # administration: an administrator's view across every recipient and
    # case, which names no content (F51, 2026-10-02).
    NOTIFY_ADMIN = "notify_admin"
    # The poll, a manual run and a pasted capture: each dedupes against every
    # stored document and matches every watch (S1, 2026-09-25).
    COLLECTION = "collection"
    # The lookup drain, and an interactive send, a sign-off and the
    # provider test from the gates on: each stores an answer at the
    # provider's label and counts every attempt on the provider; a
    # provider's withdrawal and a batch's cancel, which reach every case's
    # rows (F51, 2026-10-02).
    LOOKUPS = "lookups"
    LAB_TRIAGE = "lab_triage"            # static triage and YARA
    # Prohibited-content screening: the worker, and the Security Officer's
    # label-free match list, its counts, a review and a console pass, which
    # govern every match whatever its labels (S1, 2026-09-25).
    SCREENING = "screening"
    # A sample submission's duplicate check, which must refuse a duplicate
    # the submitter may not see, and say nothing about it (S1, 2026-09-25).
    SAMPLE_INTAKE = "sample_intake"
    # An exhibit upload's duplicate check, which must see an exhibit above
    # the uploader so their bytes never land on it, and say nothing about it
    # (rls-4, evidence-ingest-dedup-oracle, 2026-10-03).
    EVIDENCE_INTAKE = "evidence_intake"
    # A Telegram chat's duplicate check, which must refuse a chat already
    # added under a source the adder may not see, and say nothing about it
    # (F51, 2026-10-02).
    TELEGRAM_INTAKE = "telegram_intake"
    # The persona act queue (A collector process, 2026-10-02): the
    # collector's claims, its sweeps and every outcome, and the inline
    # runner's; the request role may only enqueue and read its own acts.
    PERSONA_ACTS = "persona_acts"
    # Comms minimisation (docs/16 L4) and the incidental-party flag it
    # relies on: an obligation done in full, never to the minimiser's
    # labels (S1, 2026-09-25).
    MINIMISATION = "minimisation"
    # Ingest scoring's watch list: a quarantined record scores against every
    # watch in the deployment (S1, 2026-09-25).
    # And, since ingest.record is policied (0154), a batch's parse, a dead
    # letter's replay, every scoring pass and the fingerprint correlation:
    # each dedupes or answers across every record and writes rows at the
    # feed key's label, which may sit above its caller (F51, 2026-10-02).
    INGEST = "ingest"
    SANDBOX = "sandbox"                  # detonation dispatch and polling
    # The embedding pass, and an index's registration, activation, recheck
    # and retirement, which queue and sweep every item (S1, 2026-09-25).
    EMBEDDINGS = "embeddings"
    SCRIPT = "script"                    # seeders, bootstrap, maintenance


class SystemContextUnavailable(RuntimeError):
    """A system connection could not be had, or would not be exempt. Never
    fall back to a row-filtered connection: a purge or a count that silently
    sees fewer rows reports health (http/errors.py answers 503)."""


class SystemContextMisconfigured(SystemContextUnavailable):
    """The deployment NAMED a system connection and it is the wrong one: not
    exempt from row security, or in production a superuser or the schema
    owner. Apart from `SystemContextUnavailable` for "none is configured" (the
    sample origin holds none, on purpose) so a writer that falls back to a
    weaker write can say so: a misconfigured deployment must be loud, not
    quietly lose actor attribution (g49v-system-fallback-silent,
    2026-10-03). Still a `SystemContextUnavailable`, so every handler that
    answers 503 for the one answers for both."""


@dataclass(frozen=True)
class RlsBinding:
    actor: UUID | None
    exempt: bool


#: Whether a connection is exempt from row security, remembered per
#: connection (a connection's role does not change after it is handed out).
_EXEMPT: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()

#: Exempt: a superuser, a BYPASSRLS role, or a member of the owner. Read
#: from the catalog, not from 0111's iam.rls_caller_exempt(), so asking works
#: on a database at any revision. Also says superuser and owner apart.
_EXEMPT_SQL = """
SELECT coalesce(bool_or(r.rolsuper OR r.rolbypassrls
                        OR pg_has_role(r.oid, c.relowner, 'USAGE')), false),
       coalesce(bool_or(r.rolsuper), false),
       coalesce(bool_or(pg_has_role(r.oid, c.relowner, 'USAGE')), false)
  FROM pg_roles r, pg_class c
 WHERE r.rolname = current_user AND c.oid = 'core.node'::regclass
"""


def _assume_role() -> bool:
    return os.environ.get(ASSUME_ROLE_ENV, "").strip().lower() in {"1", "true"}


def _production() -> bool:
    return os.environ.get("NOCTORNAL_ENV", "").strip().lower() == "production"


def is_exempt(conn) -> bool:
    """Whether row security filters nothing on `conn`. A test double (any
    object that is not a psycopg connection) counts as exempt: no policy
    applies to something that is not a database connection."""
    if not isinstance(conn, psycopg.Connection):
        return True
    known = _EXEMPT.get(conn)
    if known is None:
        known = bool(conn.execute(_EXEMPT_SQL).fetchone()[0])
        _EXEMPT[conn] = known
    return known


#: The request DSNs (as a digest, never the text) whose role a production
#: request connection has already been shown not to be privileged.
_REQUEST_ROLE_PROVEN: set[str] = set()

#: A superuser, a BYPASSRLS role, or a member of the schema owner. Unlike
#: `_EXEMPT_SQL` it answers on a database with no schema yet (the owner is
#: then NULL, which `refuse_privileged_request_role` treats as unproven),
#: so the readiness register can still say "migrate" on a fresh one.
_REQUEST_ROLE_SQL = """
SELECT r.rolsuper, r.rolbypassrls,
       coalesce(pg_has_role(r.oid, c.relowner, 'USAGE'), false),
       c.oid IS NOT NULL
  FROM pg_roles r LEFT JOIN pg_class c ON c.oid = to_regclass('core.node')
 WHERE r.rolname = current_user
"""


def refuse_privileged_request_role(conn: psycopg.Connection) -> None:
    """In production, refuse a request connection whose role is a
    superuser, bypasses row security or is the schema owner (infra-4,
    2026-10-03).

    Row-level security does not bind such a role and it may ALTER TABLE ...
    DISABLE TRIGGER on the audit and custody chains, so every analyst
    request would run with the protection switched off while the register
    showed a running deployment. `config.verify_environment` refuses the
    names it can see in the DSN at boot; this reads the catalog, once per
    process and DSN, for a role under another name or one that merely holds
    the owner's membership. `connect_system` makes the same refusal for the
    system role. Development and the suite connect as the owner on purpose
    and are not asked."""
    if not _production():
        return
    key = hashlib.sha256(dsn().encode()).hexdigest()
    if key in _REQUEST_ROLE_PROVEN:
        return
    superuser, bypass, owner, known = conn.execute(_REQUEST_ROLE_SQL).fetchone()
    if superuser or bypass or owner:
        raise SystemContextUnavailable(
            f"the request database connection is a superuser, bypasses "
            f"row-level security or is the schema owner; DATABASE_URL must "
            f"name {APP_ROLE}, which is none of those.")
    if known:
        _REQUEST_ROLE_PROVEN.add(key)


def connect_request() -> psycopg.Connection:
    """A connection for one HTTP request (or one websocket): the request
    role in production, bound to its user by `bind_session`."""
    conn = connect()
    try:
        if _assume_role():
            conn.execute(f"SET ROLE {APP_ROLE}")
        refuse_privileged_request_role(conn)
    except BaseException:
        conn.close()
        raise
    return conn


def worker_dsn() -> str | None:
    """The system role's DSN, or None when unset or empty."""
    raw = os.environ.get(WORKER_DSN_ENV, "")
    if not raw.strip():
        return None
    return raw.strip().replace("postgresql+psycopg://", "postgresql://", 1)


def connect_system(purpose: SystemPurpose) -> psycopg.Connection:
    """A NEW connection that sees every row, for `purpose`.

    Outside production with no system DSN it is DATABASE_URL's own role,
    which on a development stack is the owner. Whatever it connects as, it
    is REFUSED unless row security exempts it, and in production also when
    it is a superuser or the owner (the system role owns nothing)."""
    if not isinstance(purpose, SystemPurpose):
        raise TypeError("connect_system needs a SystemPurpose member")
    target = worker_dsn()
    if target is None:
        if _production():
            raise SystemContextUnavailable(
                f"{WORKER_DSN_ENV} is not set, so this process has no system "
                f"database connection for {purpose.value}.")
        conn = connect()
    else:
        conn = psycopg.connect(
            target, autocommit=True, connect_timeout=connect_timeout_seconds(),
            application_name=f"noctornal:system:{purpose.value}",
            options=session_options(target))
    try:
        if _assume_role():
            conn.execute(f"SET ROLE {WORKER_ROLE}")
        exempt, superuser, owner = conn.execute(_EXEMPT_SQL).fetchone()
        if not exempt:
            raise SystemContextMisconfigured(
                f"the system database connection for {purpose.value} is subject "
                f"to row-level security, so it would silently see part of the "
                f"data; {WORKER_DSN_ENV} must name {WORKER_ROLE}.")
        if _production() and (superuser or owner):
            raise SystemContextMisconfigured(
                f"{WORKER_DSN_ENV} names a superuser or the schema owner; it "
                f"must name {WORKER_ROLE}, which owns nothing.")
    except BaseException:
        conn.close()
        raise
    _EXEMPT[conn] = True
    return conn


@contextmanager
def system_connection(purpose: SystemPurpose, *,
                      reuse=None) -> Iterator[psycopg.Connection]:
    """`reuse` itself when it is already exempt (the owner in development
    and the main suite, the system role in a script), so the caller's
    transaction still holds the work; otherwise a new system connection,
    closed on exit. A caller whose writes and the system's must commit
    together runs all of them on what this yields."""
    if not isinstance(purpose, SystemPurpose):
        raise TypeError("system_connection needs a SystemPurpose member")
    if reuse is not None and is_exempt(reuse):
        yield reuse
        return
    conn = connect_system(purpose)
    try:
        yield conn
    finally:
        conn.close()


def bind_session(conn: psycopg.Connection, raw_token: str) -> RlsBinding:
    """Bind `conn` to the session whose raw token this is (0111 rls_bind).
    One round trip; returns who the database now believes the actor is."""
    from noctornal_api.security.tokens import rls_proof
    row = conn.execute("SELECT actor, exempt FROM iam.rls_bind(%s)",
                       (rls_proof(raw_token),)).fetchone()
    binding = RlsBinding(row[0], bool(row[1]))
    _EXEMPT[conn] = binding.exempt
    return binding


def bind_ticket(conn: psycopg.Connection, raw_ticket: str) -> RlsBinding:
    """Bind `conn` to the holder of a ticket spent in the last five minutes:
    the sample origin, which runs no session."""
    row = conn.execute("SELECT actor, exempt FROM iam.rls_bind_ticket(%s)",
                       (raw_ticket,)).fetchone()
    binding = RlsBinding(row[0], bool(row[1]))
    _EXEMPT[conn] = binding.exempt
    return binding


def connect_like(conn) -> psycopg.Connection:
    """A NEW connection of the same kind as `conn` (0150,
    evidence-ledger-actor-time-forgeable, 2026-10-03): a request connection
    for a caller that row security filters, a system connection for one it
    does not.

    A refusal that a rollback must not take is written on a second
    connection. The request role cannot attribute a row to a user it is not
    bound to, so a caller that is itself the system role (a merge, a purge, an
    administrator's two-person change) needs a second system connection to
    keep naming the person. Its purpose is the caller's own, read back from the
    application name `connect_system` sets; with none (development, the suite)
    it is the administration of accounts and policy, which is where most of
    these refusals come from."""
    if not is_exempt(conn):
        return connect_request()
    purpose = SystemPurpose.IAM_ADMIN
    if isinstance(conn, psycopg.Connection):
        name = conn.info.get_parameters().get("application_name", "")
        prefix = "noctornal:system:"
        if name.startswith(prefix):
            try:
                purpose = SystemPurpose(name[len(prefix):])
            except ValueError:
                pass
    return connect_system(purpose)


def bind_like(target: psycopg.Connection, source: psycopg.Connection) -> None:
    """Bind `target` to whoever `source` is bound to, if anyone (0150,
    evidence-ledger-actor-time-forgeable, 2026-10-03).

    A side connection that writes a row for the person the request belongs to
    (a refusal that a rollback must not take) is otherwise bound to nobody,
    and the audit trigger demotes an actor the database cannot verify.
    Binding it to the same session or ticket lets the database verify the
    actor, so the row keeps its name. It copies the caller's own binding and
    nothing else: a `source` bound to nobody leaves `target` bound to nobody.
    """
    if not isinstance(source, psycopg.Connection):
        return
    try:
        proof, ticket = source.execute(
            "SELECT nullif(current_setting('noctornal.rls_proof', true), ''), "
            "nullif(current_setting('noctornal.rls_ticket', true), '')"
        ).fetchone()
    except psycopg.Error:
        # A source in a failed transaction cannot be asked. The row is still
        # written, bound to nobody, and the trigger demotes its actor.
        return
    if proof:
        target.execute("SELECT actor, exempt FROM iam.rls_bind(%s)", (proof,))
    if ticket:
        target.execute("SELECT actor, exempt FROM iam.rls_bind_ticket(%s)",
                       (ticket,))

"""The facts from the legal register (docs/16) that code can check, in one
place. Not every entry in docs/16 -- see "What is deliberately NOT here".

docs/16 lists what must be settled before this build may be switched on.
Some of those entries are decisions only a human can take and the software
can only record; the rest are facts the software CAN establish -- an
environment variable is set, a table row is confirmed, a role has a
holder, a service answers and is configured the way the code assumes.
Until 2026-09-02 those facts were scattered: docs/16's blocking items
behind a Lab banner, the unconfirmed retention rules behind
`GET /retention/rules`, "is there a security officer" behind a break-glass
refusal, and the KEK, rate-limit and Redis warnings in process-log lines
nobody reads after boot. Readiness was whatever the last person to look at
the logs remembered.

`report(conn)` runs every check and returns `{ready, checks}`, where
`ready` is the conjunction and nothing else, and every check carries
EVIDENCE -- the number, the name, the version, the error -- because a
verdict without evidence is an opinion, and an operator cannot act on an
opinion.

## Two rules every check follows

**A down service is a failed check, never a 500.** A readiness endpoint
that crashes when Redis is down has reported the outage as its own bug,
which is this codebase's signature defect ("a failure reported as the
wrong thing") wearing an operator's hat. Every probe runs under
`_guarded`, so an exception becomes `ok=False` with the exception as
evidence and the check's standing action.

**One reader per fact.** Where the code already decides something
(`limits.rate_limiting_disabled`, `samples.policy_declared`,
`samples.sample_origin`, `envelope._load_kek`), the check calls that
reader rather than keeping its own copy of the rule. Two internally
consistent halves that are wrong together is the other signature defect,
and a readiness check that kept its own list of off-values would be
exactly that. `_totp_kek_set` is the cautionary tale: until 2026-09-02 it
CLAIMED to apply the envelope's test and instead applied a stricter one,
so a KEK the product encrypted and decrypted with every day was reported
not-ready. A rule stated in a docstring and not in the code is not a rule.

## Two tiers, because a register nothing refuses on is a list

Until 2026-09-10 every entry here was worth the same: eleven rows, one
`ready` boolean, and nothing anywhere in the tree REFUSED on either.
`GET /admin/readiness` served the report and the admin pane drew it, and
that was the whole of the consequence -- read, never acted on. An
operator could leave four of them red for a month and the product would
collect covertly against a real target the whole time, because the only
consequence of a failed check was a row on a pane nobody had to open.
That is a quiet green -- a control that reports rather than refuses --
and it is the same defect as a log line nobody reads after boot, which
is the thing this module was written to end.

So four checks are now BLOCKING (`BLOCKING_CHECKS`, which justifies each
one) and the rest are not. A blocking check is not "a more important
check": it names a decision that has to be settled BEFORE real material
arrives rather than after it, so a caller may REFUSE on it. For three of
the four the reason it cannot wait is that running anyway does harm
nothing afterwards can undo; the fourth (`sample_origin_configured`) is
reversible and blocks on the first ground alone, which its own entry
says in those words -- a tier whose stated bar three of its rows meet
and the fourth does not is exactly the failure "One reader per fact"
above ends on: a rule stated in a docstring and not in the code.
`blocking_failures(conn)` is the cheap form for a caller that refuses --
the poll route, and the cron in `scripts/collection_poll.py`, which asks
once per pass so the UNATTENDED path is gated and not only the one an
analyst is watching. It runs only those four, because making a
collection poll wait on a MinIO round trip would turn a readiness
refusal into a latency bug. `report()`
carries the tier on every check (`blocking`) and lists the failing ones
once (`blocking_failures`) so a caller does not re-derive it and get a
different answer from the rows beneath it.

## What is deliberately NOT here

Whether the referenced policy exists, whether counsel has reviewed the
deployment, whether the retention periods are the right ones: the software
records declarations and cannot verify them, and docs/16 says so. This
module reports that the declarations have been made. `ready=true` means
"the code-side preconditions hold", not "this deployment is lawful".

Two register items are checked only as far as the code CAN check them,
and each says so in its own passing evidence rather than leaving the
operator to infer it. docs/16 C8: the check confirms Redis is reachable
and reports its eviction policy, but whether the limiter has an instance
to itself is a deployment fact nothing here can see. docs/16 C9: the
check reads `samples.origin_split()` -- the same verdict `download()`
refuses or serves on -- so it can say that the sample origin is set, is
an origin, is not a second name for the application's, and which of the
two THIS process is configured as. It cannot see the other process, and
docs/16 says outright that the runtime "cannot tell the difference
between a real origin split and a CNAME", so that the sample origin is
actually served by a process configured as it, and that the two hostnames
are genuinely separate, stay human confirmations. When
`NOCTORNAL_SAMPLE_ORIGIN` is unset the check FAILS and says the control is
off: every download refuses, and `ready=true` must not be readable as
"invariant 10 holds".

And the register below is NOT claimed to be exhaustive over docs/16.
docs/16 runs to L1-L5, D1-D8 and C1-C13, most of which are decisions and
external confirmations with no code-side half; `_CHECKS` holds the ones
that do have one and that somebody has since wired up. So `ready=true`
means "every check in this list passes", which is weaker than "docs/16 is
satisfied" -- read it alongside docs/16, never instead of it. Saying so
here is the point: until 2026-09-02 this docstring described itself as the
code-side half of the register "in one place" while C9's env fact was not
checked at all, which made ready=true claim more than it had established.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

import psycopg

log = logging.getLogger("noctornal.readiness")

#: Where the migration scripts live relative to this file: the repository
#: root is four levels up (noctornal_api / src / api / apps). Resolved
#: from `__file__` rather than the working directory because the API is
#: started from wherever the operator happens to be, and a check that
#: depended on `cwd` would fail on a correctly migrated database run from
#: the wrong shell.
_REPO_ROOT = Path(__file__).resolve().parents[4]
_MIGRATIONS_DIR = _REPO_ROOT / "db" / "migrations"

#: How long a readiness probe waits on a service that does not answer.
#: Longer than the limiter's own 250ms (this is an operator asking once,
#: not a request path) but short enough that a hung MinIO does not hold
#: the whole report for minutes -- urllib3's default is five.
_PROBE_CONNECT_S = 1.0
_PROBE_READ_S = 5.0

_TOTP_KEK_ENV = "NOCTORNAL_TOTP_KEK"
_PEPPER_ENV = "NOCTORNAL_INGEST_PEPPER"

#: The table whose ownership `_app_db_role_not_owner` reads. Any table
#: Alembic created would answer the same question -- one migration run
#: creates them all as one role -- and core.node is the one that has
#: existed at every head since 0002. The ledgers the answer is ABOUT are
#: `audit.event` and `core.evidence_custody`, whose append-only triggers
#: are what an owner can switch off in a single statement.
_OWNERSHIP_PROBE_TABLE = "core.node"


@dataclass(frozen=True)
class Check:
    """One line of the register.

    `action` is what an operator does about a failure; it is empty when
    `ok` is True, because "everything is fine, and here is what to do
    about it" is noise.

    `blocking` says a caller may refuse on this row rather than merely
    display it. It is stamped from the register in `run_checks` and never
    by the probe: a probe that decided its own tier would be a second
    copy of a rule that exists precisely so ONE list decides what
    refuses, and this module has already been bitten once by a check that
    kept its own copy of a rule (`_totp_kek_set`, below).
    """
    check: str
    ok: bool
    evidence: str
    action: str = ""
    blocking: bool = False

    def as_dict(self) -> dict:
        return {"check": self.check, "ok": self.ok,
                "evidence": self.evidence, "action": self.action,
                "blocking": self.blocking}


def _guarded(name: str, action: str, probe: Callable[[], Check]) -> Check:
    """Run one probe; an exception is a failed check with the error as
    evidence, and never propagates. See the module docstring for why."""
    try:
        return probe()
    except Exception as exc:  # noqa: BLE001 - every failure is a verdict here
        log.warning("readiness check %s raised", name, exc_info=True)
        # Type name first so a truncated message still says what happened;
        # truncated because a urllib3 MaxRetryError repeats itself for
        # several hundred characters.
        detail = f"{type(exc).__name__}: {str(exc)[:300]}"
        return Check(name, False, detail, action)


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------

def _prohibited_content_policy(conn: psycopg.Connection) -> Check:
    """docs/16 L1. The verdict is `samples.policy_declared`'s, because that
    is the reader that decides whether ingest runs; this only adds the
    designated person to the evidence."""
    from noctornal_api.samples import policy_declared

    declared, reference = policy_declared()
    person = os.environ.get("NOCTORNAL_DESIGNATED_PERSON", "").strip()
    if declared:
        return Check(
            "prohibited_content_policy", True,
            f"NOCTORNAL_PROHIBITED_CONTENT_POLICY={reference}; "
            f"NOCTORNAL_DESIGNATED_PERSON={person}. This is a declaration the "
            f"software records, not one it can verify (docs/16 L1).")
    policy_set = bool(os.environ.get("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "").strip())
    return Check(
        "prohibited_content_policy", False,
        f"not declared: NOCTORNAL_PROHIBITED_CONTENT_POLICY is "
        f"{'set' if policy_set else 'unset'}, NOCTORNAL_DESIGNATED_PERSON is "
        f"{'set' if person else 'unset'}; sample ingest is refused",
        "have counsel write the prohibited-content policy first (docs/11, "
        "docs/16 L1), then set NOCTORNAL_PROHIBITED_CONTENT_POLICY to a "
        "reference an auditor can follow and NOCTORNAL_DESIGNATED_PERSON to "
        "whoever material is escalated to")


def _retention_rules_confirmed(conn: psycopg.Connection) -> Check:
    """docs/16 D3. The seeded periods are placeholders; a rule is confirmed
    when a named human has attached a rationale to it."""
    confirmed, total = conn.execute(
        "SELECT count(confirmed_at), count(*) FROM core.retention_rule"
    ).fetchone()
    evidence = f"{confirmed} of {total} retention rules confirmed"
    if total > 0 and confirmed == total:
        return Check("retention_rules_confirmed", True, evidence)
    if total == 0:
        evidence += " (no rules at all: the seed did not run)"
    return Check(
        "retention_rules_confirmed", False, evidence,
        "confirm each placeholder with POST /retention/rules/{category} "
        "(retention.manage, step-up); the periods are jurisdictional and the "
        "build cannot choose them (docs/16 D3). GET /retention/rules lists "
        "which are still placeholders")


def _active_holders(conn: psycopg.Connection, role: str) -> int:
    return conn.execute(
        """SELECT count(DISTINCT u.id)
             FROM iam.app_user u
             JOIN iam.user_role ur ON ur.user_id = u.id
            WHERE ur.role_key = %s AND u.is_active""",
        (role,),
    ).fetchone()[0]


def _security_officer_present(conn: psycopg.Connection) -> Check:
    """Break-glass REFUSES to grant when nobody can review it, so a
    deployment with no active SECURITY_OFFICER has no emergency access at
    all -- and nothing said so until someone needed it."""
    n = _active_holders(conn, "SECURITY_OFFICER")
    return Check(
        "security_officer_present", n >= 1,
        f"{n} active SECURITY_OFFICER account(s)",
        "" if n >= 1 else
        "grant SECURITY_OFFICER to an active account "
        "(POST /admin/users/{user_id}/roles); break-glass refuses every "
        "request while nobody can review it, and audit.read is held by "
        "this role alone")


def _sys_admin_present(conn: psycopg.Connection) -> Check:
    """`user.manage` is held by SYS_ADMIN alone. With none active, accounts
    can only be repaired from the database shell."""
    n = _active_holders(conn, "SYS_ADMIN")
    return Check(
        "sys_admin_present", n >= 1,
        f"{n} active SYS_ADMIN account(s)",
        "" if n >= 1 else
        "grant SYS_ADMIN to an active account; user.manage is held by "
        "SYS_ADMIN alone, so with none the only repair path is "
        "scripts/bootstrap.py on the server")


def _totp_kek_set(conn: psycopg.Connection) -> Check:
    """Calls `envelope._load_kek`, the reader every encrypt and every
    decrypt already calls, so this check and the envelope cannot disagree
    about what a usable KEK is. The evidence is the reader's own refusal.

    Until 2026-09-02 this check claimed exactly that and did not do it: it
    kept a private copy of the rule and decoded with
    `base64.b64decode(raw, validate=True)` while `envelope._load_kek`
    decodes leniently. A KEK carrying a trailing newline -- what a Docker
    or Kubernetes secret file and a copy-pasted `.env` line routinely hold
    -- sealed and opened every TOTP secret in the product and was still
    reported `ok=false, ready=false` with the evidence
    "NOCTORNAL_TOTP_KEK is set but is not valid base64". That is a working
    deployment reported as broken, with the wrong reason, which is the
    defect this module exists to prevent, and it is why "one reader per
    fact" above is a rule and not a preference. It was also the one entry
    in the register no test ever flipped, which is how it survived.

    Neither `_load_kek`'s messages nor this check quote the value, so the
    KEK cannot leak into an operator's screenshot of the register.
    """
    from noctornal_api.security.envelope import _load_kek

    action = (
        f"set {_TOTP_KEK_ENV} to a base64-encoded 32-byte key in the API's "
        f"environment; without it no TOTP secret can be sealed or opened, so "
        f"nobody can enrol or sign in")
    try:
        key = _load_kek()
    except (RuntimeError, ValueError) as exc:
        # RuntimeError is `_load_kek`'s own refusal (unset, wrong length).
        # ValueError catches binascii.Error, which it lets through
        # unwrapped for a value even the lenient decoder cannot parse
        # (bad padding) -- reporting that here rather than letting
        # `_guarded` label it a crash keeps the operator's action right.
        return Check("totp_kek_set", False, str(exc), action)
    return Check("totp_kek_set", True,
                 f"{_TOTP_KEK_ENV} is set and decodes to {len(key)} bytes")


def _ingest_pepper_set(conn: psycopg.Connection) -> Check:
    """Calls `ingest._pepper`, the reader every issued ingest key and
    every victim-credential fingerprint already goes through, for the
    reason `_totp_kek_set` gives at length: a check carrying its own copy
    of "what counts as a usable pepper" is a check that can disagree with
    the product it reports on.

    Added 2026-09-10. Until then the pepper had no entry in this register
    at all, so a deployment missing it passed every row and then failed
    at the first ingest key operation -- an `IngestError` raised from
    inside the issue path, which reads to whoever hits it as a bug in the
    endpoint rather than as a variable nobody set. The register exists to
    move that discovery from the first user to the operator.

    NOT blocking. An unset pepper stops ingest keys and fingerprint
    correlation and touches nothing else; refusing a collection poll over
    it would be refusing the wrong thing, and a refusal that fires on an
    unrelated fault is how a gate gets switched off wholesale.

    The value is never quoted, only its length, so the pepper cannot
    reach an operator's screenshot of the register -- the same rule
    `_totp_kek_set` follows for the KEK.
    """
    from noctornal_api.ingest import IngestError, _pepper

    action = (
        f"set {_PEPPER_ENV} in the API's environment to a long random string. "
        f"Set it ONCE and keep it: the ingest keys and victim-credential "
        f"fingerprints already stored were HMAC'd with the previous value and "
        f"do not survive a rotation (docs/12)")
    try:
        pepper = _pepper()
    except IngestError as exc:
        return Check("ingest_pepper_set", False, str(exc), action)
    return Check(
        "ingest_pepper_set", True,
        f"{_PEPPER_ENV} is set and is {len(pepper)} bytes; it is deliberately "
        f"a different secret from {_TOTP_KEK_ENV}, so a compromise of one is "
        f"not a compromise of the other")


def _app_db_role_not_owner(conn: psycopg.Connection) -> Check:
    """Can the role this process is connected as switch off the
    append-only triggers?

    `audit.event` and `core.evidence_custody` are append-only because a
    BEFORE UPDATE OR DELETE trigger says so, and `ALTER TABLE ... DISABLE
    TRIGGER` is available to the table's OWNER and to any superuser. So
    an API connected as the owner holds tamper-evidence it can turn off
    from inside the request path in one statement -- which is exactly
    what ten of this suite's own `*_pg` fixtures do, to write the
    tampering the verifier is meant to catch. The guarantee was never
    "the application code does not contain that statement"; it is "the
    server refuses it", and that is a fact about which role the DSN
    names, not about the code.

    Hence the two roles the production compose file creates
    (infra/production/compose.yml): `noctornal` owns the schema and runs
    Alembic under NOCTORNAL_MIGRATION_DATABASE_URL, and `noctornal_app`
    -- not the owner, not a member of it, not a superuser -- is what
    DATABASE_URL names for the API and every runtime process.

    Membership is read as well as ownership, because "is not the owner"
    is where a naive reading stops: a role that may `SET ROLE noctornal`
    is the owner the moment it decides to be, and `pg_has_role` is the
    only thing that sees that. `rolsuper` is read for the same reason in
    the other direction -- a superuser's ownership is irrelevant because
    it may disable a trigger on any table in the cluster.

    NOT blocking, and it is EXPECTED to fail on every developer machine
    and in CI: the test suites must own the tables in order to disable
    those triggers on purpose, so they connect as the owner. A refusal
    keyed to a check that is red everywhere except production would be a
    refusal that gets disabled the first week.
    """
    action = (
        "point DATABASE_URL at the least-privilege role `noctornal_app` and "
        "keep the owner `noctornal` for Alembic alone, in "
        "NOCTORNAL_MIGRATION_DATABASE_URL; infra/production/compose.yml sets "
        "both, and migration 0060 grants the app role the table privileges it "
        "needs without making it an owner, a member of one, or a superuser. "
        "On a development or CI database this check is expected to fail -- the "
        "test suites own the tables because they disable the append-only "
        "triggers deliberately")
    row = conn.execute(
        """SELECT current_user,
                  c.relowner::regrole::text,
                  (SELECT r.rolsuper FROM pg_roles r
                    WHERE r.rolname = current_user),
                  pg_has_role(current_user, c.relowner, 'MEMBER')
             FROM pg_class c
            WHERE c.oid = to_regclass(%s)""",
        (_OWNERSHIP_PROBE_TABLE,),
    ).fetchone()
    if row is None:
        # `to_regclass` returns NULL for a table that is not there rather
        # than raising, so this is a missing schema and not a crash --
        # and reporting it as its own answer keeps the operator's action
        # right, which is to migrate rather than to change the DSN.
        who = conn.execute("SELECT current_user").fetchone()[0]
        return Check(
            "app_db_role_not_owner", False,
            f"connected as {who}; {_OWNERSHIP_PROBE_TABLE} does not exist in "
            f"this database, so there is no owner to read and nothing to "
            f"compare the connected role against",
            "run `alembic upgrade head` as the owner role first; this check "
            "reads the owner of a table that exists and cannot answer before "
            "one does")

    who, owner, is_super, is_member = row
    ledgers = ("the append-only ledgers (audit.event, core.evidence_custody) "
               "are enforced by convention rather than by the server")
    if is_super:
        return Check(
            "app_db_role_not_owner", False,
            f"connected as {who}, which is a SUPERUSER: ownership is beside "
            f"the point, because a superuser may ALTER TABLE ... DISABLE "
            f"TRIGGER on {_OWNERSHIP_PROBE_TABLE} and on every other table in "
            f"the cluster, so {ledgers}",
            action)
    if is_member:
        how = (f"and {who} IS that owner" if who == owner else
               f"and {who} is a member of it, so `SET ROLE {owner}` makes it "
               f"the owner on demand")
        return Check(
            "app_db_role_not_owner", False,
            f"connected as {who}, which is not a superuser; "
            f"{_OWNERSHIP_PROBE_TABLE} is owned by {owner}, {how}. ALTER "
            f"TABLE ... DISABLE TRIGGER is available to this connection, so "
            f"{ledgers}",
            action)
    return Check(
        "app_db_role_not_owner", True,
        f"connected as {who}, which is not a superuser; "
        f"{_OWNERSHIP_PROBE_TABLE} is owned by {owner} and {who} is not a "
        f"member of it, so ALTER TABLE ... DISABLE TRIGGER on the append-only "
        f"ledgers is refused by the server rather than merely absent from the "
        f"code")


def _sample_origin_configured(conn: psycopg.Connection) -> Check:
    """docs/16 C9. Reads `samples.origin_split()` -- the one verdict
    `samples.download()` refuses or serves on -- rather than the
    environment variables directly.

    Added 2026-09-02. C9 was the one register entry with a code-checkable
    half that this module did not check, so `ready=true` was returned for
    deployments where every sample download refuses outright (invariant
    10) while the module docstring claimed to be the code-side half of the
    register "in one place".

    Rewritten 2026-09-09. Until then it passed on "the variable is set",
    and the download itself compared that variable against the Host
    header: a deployment whose sample origin was a second name for the
    application origin passed this check and served hostile bytes from
    the application, and one whose console could not reach the sample
    origin at all (the UI CSP allowed only 'self') passed it too. The
    check now fails on the same three deployment problems the download
    refuses on -- unset, not an origin, equal to the application origin --
    and, when the split is usable, says which of the two origins THIS
    process is configured as, because a register that passed on the
    application process was silent about whether anything served at the
    sample origin.

    Unset is reported as the control being OFF, in those words: there is
    no origin split, every download refuses, and a reader of `ready`
    must not be able to take a passing register as "invariant 10 holds".
    What stays human (docs/16 C9, named in "What is deliberately NOT
    here"): that the sample origin is served by a process configured as
    it, and that the two hostnames are a real split and not a CNAME.
    """
    from noctornal_api.samples import origin_split, sample_origin

    split = origin_split()
    action = (
        "set NOCTORNAL_SAMPLE_ORIGIN to a genuinely separate origin -- its own "
        "host, cookie scope and CSP, never a path on the app's own host "
        "(docs/16 C9) -- and, on the process that serves it, set "
        "NOCTORNAL_PUBLIC_ORIGIN to the same value; NOCTORNAL_BASE_URL names "
        "the application origin on both. Until the split is usable, "
        "samples.download() refuses every request, so no analyst can "
        "retrieve a sample at all")
    if split.role == "unconfigured":
        return Check(
            "sample_origin_configured", False,
            "CONTROL OFF: NOCTORNAL_SAMPLE_ORIGIN is not set, so there is no "
            "origin split and samples.download() refuses every request on "
            "every process (invariant 10: sample bytes are only ever served "
            "from a separate origin). Nothing about this deployment satisfies "
            "the invariant",
            action)
    if split.split_problem is not None:
        return Check(
            "sample_origin_configured", False,
            f"NOCTORNAL_SAMPLE_ORIGIN={sample_origin()}: {split.split_problem}",
            action)
    if split.serves_here:
        return Check(
            "sample_origin_configured", True,
            f"NOCTORNAL_SAMPLE_ORIGIN={split.sample}; this process is configured "
            f"as the sample origin (NOCTORNAL_PUBLIC_ORIGIN) and serves sample "
            f"downloads to the console at {split.app} and nothing else. That "
            f"this is a real origin split and not a CNAME onto the app's own "
            f"host is a human confirmation (docs/16 C9), which the runtime "
            f"cannot make")
    return Check(
        "sample_origin_configured", True,
        f"NOCTORNAL_SAMPLE_ORIGIN={split.sample}; this process is configured "
        f"as the application origin ({split.this}) and refuses every "
        f"download, directing the console to {split.sample}. That a process "
        f"configured with NOCTORNAL_PUBLIC_ORIGIN={split.sample} is serving "
        f"there is that process's own readiness to confirm, and that the two "
        f"are a real origin split and not a CNAME onto the app's own host is "
        f"a human confirmation (docs/16 C9), which the runtime cannot make")


def _rate_limiting_enabled(conn: psycopg.Connection) -> Check:
    """Reads the limiter's own off-switch, not a copy of it."""
    from noctornal_api.http.limits import rate_limiting_disabled

    setting = os.environ.get("NOCTORNAL_RATELIMIT", "")
    if rate_limiting_disabled():
        return Check(
            "rate_limiting_enabled", False,
            f"NOCTORNAL_RATELIMIT={setting.strip()!r}: RATE LIMITING IS DISABLED; "
            f"login guessing is braked only by the account lockout and the "
            f"analytics endpoints are an unmetered CPU-bound path",
            "unset NOCTORNAL_RATELIMIT (or set it to anything but an off value) "
            "and restart the API")
    return Check(
        "rate_limiting_enabled", True,
        f"NOCTORNAL_RATELIMIT is {'unset' if not setting.strip() else repr(setting.strip())}; "
        f"the limiter is built at startup")


def _redis_limiter_store(conn: psycopg.Connection) -> Check:
    """Reachable, and not an evictor. An unknown policy is NOT ok: the
    register is a list of things confirmed, and "the server would not
    say" confirms nothing. The action tells the operator to confirm it by
    other means, which is what docs/16 C8 already asks."""
    from noctornal_api.http.limits import redacted_url
    from noctornal_api.ratelimit_redis import (
        CONNECT_TIMEOUT_S,
        RedisBackend,
        is_evicting_policy,
    )

    url = os.environ.get("REDIS_URL", "").strip()
    if not url:
        return Check(
            "redis_limiter_store", False,
            "REDIS_URL is not set: rate limiting is per process, so N uvicorn "
            "workers enforce N times the configured rate",
            "set REDIS_URL to a Redis reserved for the limiter, running with "
            "maxmemory-policy=noeviction (docs/16 C8)")
    where = redacted_url(url)
    backend = RedisBackend(url)
    try:
        if not backend.ping():
            return Check(
                "redis_limiter_store", False,
                f"Redis at {where} did not answer PING within {CONNECT_TIMEOUT_S}s; "
                f"every limit with on_backend_failure=DENY is refusing requests",
                "start Redis, or point REDIS_URL at the instance that is running")
        policy = backend.maxmemory_policy()
    finally:
        backend.close()
    if policy is None:
        return Check(
            "redis_limiter_store", False,
            f"Redis at {where} answers PING; maxmemory-policy is UNKNOWN because "
            f"CONFIG GET was refused (managed Redis usually disables CONFIG)",
            "confirm out of band that the limiter's Redis runs with "
            "maxmemory-policy=noeviction, or point REDIS_URL at one that "
            "answers CONFIG GET (docs/16 C8)")
    if is_evicting_policy(policy):
        return Check(
            "redis_limiter_store", False,
            f"Redis at {where} answers PING; maxmemory-policy={policy}, which "
            f"deletes live rate-limit meters under memory pressure -- a deleted "
            f"meter admits the subject it was refusing with a full burst",
            "run the limiter's Redis with maxmemory-policy=noeviction, or give "
            "it its own instance (docs/16 C8; infra/docker-compose.yml sets "
            "allkeys-lru and must not be copied into production as it is)")
    return Check(
        "redis_limiter_store", True,
        f"Redis at {where} answers PING; maxmemory-policy="
        f"{policy or '(unset, defaults to noeviction)'}; whether the "
        f"limiter has this instance to itself is a deployment fact the "
        f"runtime cannot see (docs/16 C8)")


def _evidence_bucket_object_lock(conn: psycopg.Connection) -> Check:
    """The WORM guarantee `EvidenceStorage.put` relies on: a bucket created
    with object lock (which forces versioning on). A per-object COMPLIANCE
    retention on a bucket WITHOUT lock is rejected by the store, so
    evidence writes fail -- or, worse on some stores, succeed without the
    lock, and a delete before `retain_until` would then go through."""
    endpoint = os.environ.get("MINIO_ENDPOINT", "").strip()
    access = os.environ.get("MINIO_ACCESS_KEY", "")
    secret = os.environ.get("MINIO_SECRET_KEY", "")
    bucket = os.environ.get("EVIDENCE_BUCKET", "noctornal-evidence")
    action = (
        "set MINIO_ENDPOINT / MINIO_ACCESS_KEY / MINIO_SECRET_KEY, and create the "
        "evidence bucket WITH object lock (`mc mb --with-lock`); lock cannot be "
        "switched on for a bucket that already exists, so an unlocked bucket "
        "has to be replaced")
    if not endpoint:
        return Check(
            "evidence_bucket_object_lock", False,
            "MINIO_ENDPOINT is not set: EvidenceStorage refuses to construct, so "
            "no exhibit can be stored", action)
    if not (access and secret):
        missing = [n for n, v in (("MINIO_ACCESS_KEY", access),
                                  ("MINIO_SECRET_KEY", secret)) if not v]
        return Check(
            "evidence_bucket_object_lock", False,
            f"MINIO_ENDPOINT={endpoint} but {' and '.join(missing)} not set", action)

    import urllib3
    from minio import Minio
    from minio.error import S3Error

    # The client's default pool waits five minutes and retries five times;
    # a readiness probe against a hung store would hold the report for
    # longer than the operator waits for a page.
    http = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=_PROBE_CONNECT_S, read=_PROBE_READ_S),
        retries=urllib3.Retry(total=0),
    )
    secure = os.environ.get("MINIO_SECURE", "false").lower() == "true"
    client = Minio(endpoint, access_key=access, secret_key=secret,
                   secure=secure, http_client=http)
    try:
        config = client.get_object_lock_config(bucket)
    except S3Error as exc:
        if exc.code == "ObjectLockConfigurationNotFoundError":
            return Check(
                "evidence_bucket_object_lock", False,
                f"bucket {bucket} at {endpoint} exists but object lock is NOT "
                f"enabled; a delete before retain_until would succeed", action)
        if exc.code == "NoSuchBucket":
            return Check(
                "evidence_bucket_object_lock", False,
                f"bucket {bucket} does not exist at {endpoint}", action)
        return Check("evidence_bucket_object_lock", False,
                     f"bucket {bucket} at {endpoint}: {exc.code}: {exc.message}",
                     action)
    if config.mode:
        default = f"default retention {config.mode} {config.duration} {config.duration_unit}"
    else:
        default = "no default rule (every put sets its own COMPLIANCE retention)"
    return Check(
        "evidence_bucket_object_lock", True,
        f"bucket {bucket} at {endpoint}: object lock enabled, {default}")


def _migrations_at_head(conn: psycopg.Connection) -> Check:
    """The database's stamped revision against the head of the scripts on
    disk. A deployment whose code is ahead of its schema fails on the
    first query that touches the new column, and reports that as a bug in
    whatever endpoint happened to run first."""
    action = ("run `alembic upgrade head` from the repository root with "
              "DATABASE_URL set to this database")
    if not _MIGRATIONS_DIR.is_dir():
        return Check(
            "migrations_at_head", False,
            f"migration scripts not found at {_MIGRATIONS_DIR}; cannot compare",
            "run the API from a checkout that carries db/migrations, or set the "
            "layout right -- this check locates the scripts relative to the "
            "package")

    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config()
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    heads = ScriptDirectory.from_config(cfg).get_heads()
    stamped = [r[0] for r in conn.execute(
        "SELECT version_num FROM alembic_version ORDER BY version_num").fetchall()]
    evidence = (f"database at {', '.join(stamped) or '(no alembic_version row)'}; "
                f"scripts head {', '.join(heads)}")
    if stamped and sorted(stamped) == sorted(heads):
        return Check("migrations_at_head", True, evidence)
    return Check("migrations_at_head", False, evidence, action)


def _smtp_configured(conn: psycopg.Connection) -> Check:
    """Configured, and not in the plaintext exception. docs/07: "never
    plaintext" -- SMTP_ALLOW_PLAINTEXT exists for a development relay
    (Mailpit), and a production deployment carrying it would send case
    summaries in the clear on the day STARTTLS fails."""
    host = os.environ.get("SMTP_HOST", "").strip()
    port = os.environ.get("SMTP_PORT", "587").strip()
    plaintext = os.environ.get("SMTP_ALLOW_PLAINTEXT", "").lower() in {"1", "true"}
    if not host:
        return Check(
            "smtp_configured", False,
            "SMTP_HOST is not set: every email delivery raises TransportError",
            "set SMTP_HOST (and SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD): 587 "
            "with STARTTLS or 465 with implicit TLS (docs/07)")
    if plaintext:
        return Check(
            "smtp_configured", False,
            f"SMTP_HOST={host}:{port} with SMTP_ALLOW_PLAINTEXT set: a failed "
            f"STARTTLS negotiation falls back to sending in the clear",
            "unset SMTP_ALLOW_PLAINTEXT; it is for a development relay only "
            "(docs/07: never plaintext)")
    return Check("smtp_configured", True,
                 f"SMTP_HOST={host}:{port}; TLS required")


# ---------------------------------------------------------------------------
# The register
# ---------------------------------------------------------------------------

#: (name, probe, action-on-crash). The action here is what the operator is
#: told when the probe itself blew up, which is usually "the service is
#: down or misconfigured" rather than the check's own failure mode.
_CHECKS: tuple[tuple[str, Callable[[psycopg.Connection], Check], str], ...] = (
    ("prohibited_content_policy", _prohibited_content_policy,
     "set NOCTORNAL_PROHIBITED_CONTENT_POLICY and NOCTORNAL_DESIGNATED_PERSON "
     "(docs/16 L1)"),
    ("sample_origin_configured", _sample_origin_configured,
     "set NOCTORNAL_SAMPLE_ORIGIN to a separate origin, and "
     "NOCTORNAL_PUBLIC_ORIGIN on the process that serves it (docs/16 C9)"),
    ("retention_rules_confirmed", _retention_rules_confirmed,
     "the retention table could not be read; run alembic upgrade head and "
     "then confirm each rule at POST /retention/rules/{category}"),
    ("security_officer_present", _security_officer_present,
     "the role table could not be read; once it can, grant SECURITY_OFFICER "
     "to an active account so break-glass has a reviewer"),
    ("sys_admin_present", _sys_admin_present,
     "the role table could not be read; once it can, grant SYS_ADMIN to an "
     "active account"),
    ("totp_kek_set", _totp_kek_set,
     f"set {_TOTP_KEK_ENV} to a base64-encoded 32-byte key"),
    ("ingest_pepper_set", _ingest_pepper_set,
     f"set {_PEPPER_ENV} to a long random string, once, and keep it"),
    ("rate_limiting_enabled", _rate_limiting_enabled,
     "unset NOCTORNAL_RATELIMIT and restart the API"),
    ("redis_limiter_store", _redis_limiter_store,
     "fix REDIS_URL or start the Redis it names; run it with "
     "maxmemory-policy=noeviction (docs/16 C8)"),
    ("evidence_bucket_object_lock", _evidence_bucket_object_lock,
     "fix MINIO_ENDPOINT / MINIO_ACCESS_KEY / MINIO_SECRET_KEY or start the "
     "object store; the evidence bucket must be created with object lock"),
    ("migrations_at_head", _migrations_at_head,
     "run `alembic upgrade head` from the repository root with DATABASE_URL "
     "set to this database"),
    ("app_db_role_not_owner", _app_db_role_not_owner,
     "the catalogue could not be read; the connected role should be "
     "`noctornal_app` (DATABASE_URL), never the schema owner `noctornal`"),
    ("smtp_configured", _smtp_configured,
     "set SMTP_HOST to a relay that speaks TLS (docs/07)"),
)

#: The names, in the order the report lists them. Public so the router
#: test can read the service's list and the wire's list and insist they
#: are the same list.
CHECK_NAMES: tuple[str, ...] = tuple(name for name, _, _ in _CHECKS)

#: The four an operator must settle before real material enters this
#: system. "Blocking" means one specific thing -- a caller may REFUSE on
#: it -- so the bar is not "important" (everything in this register is
#: important) but "a decision that has to be settled before real material
#: arrives, and cannot sensibly be taken once it has".
#:
#: For three of the four -- prohibited_content_policy,
#: retention_rules_confirmed and security_officer_present -- what makes it
#: unwaitable is that running anyway does harm nothing afterwards can
#: undo: each leaves material in the building under a decision nobody
#: took, and no amount of tidying up later puts it back. The fourth is
#: reversible and says so in its own entry; the bar above is the one that
#: is true of all four, and stating the irreversibility one as the bar
#: (as this comment did until 2026-09-10) made the tier claim something
#: a quarter of it did not meet, on the very list that decides what
#: refuses. Each, and why:
#:
#: prohibited_content_policy (docs/16 L1). Without a declared policy and a
#:   named person, the first piece of prohibited material that arrives has
#:   nobody it goes to and no written rule for what happens to it. That is
#:   a criminal-liability question about material already in the building,
#:   and it cannot be settled retrospectively.
#: sample_origin_configured (docs/16 C9). The control is OFF: every sample
#:   download refuses, so nothing collected into the Lab can be retrieved,
#:   and no part of the deployment satisfies invariant 10. Alone among the
#:   four this failure is REVERSIBLE -- setting the variable fixes it, and
#:   nothing already collected is worse off for the delay -- so it blocks
#:   on the first ground only. What it is settled by is a deployment
#:   decision (a genuinely separate host, with its own cookie scope and
#:   CSP), and a deployment decision taken in a hurry with material
#:   already waiting is taken the cheap way: a second name for the
#:   application's own origin, which serves hostile bytes from the
#:   console's origin and is precisely what this check now fails on.
#:   Refusing the poll settles it while it is still free to settle.
#: retention_rules_confirmed (docs/16 D3). The seeded periods are
#:   PLACEHOLDERS. Collecting under them holds personal data to a number
#:   nobody chose, and the purge that eventually runs against it is
#:   equally arbitrary -- destroying material early is exactly as
#:   irreversible as keeping it too long.
#: security_officer_present. Break-glass refuses to grant while nobody can
#:   review it, and `audit.read` is held by this role alone. A deployment
#:   with no active officer has no emergency access AND nobody who can
#:   read the trail of what was collected, so a covert collection would
#:   run unreviewable by construction.
#:
#: sys_admin_present is deliberately NOT here, and not because it matters
#: less than the four. It is an OPERABILITY failure rather than a decision
#: taken too late: with no active SYS_ADMIN accounts cannot be
#: administered, but nothing about material already collected becomes
#: unfixable, and `scripts/bootstrap.py` on the server closes it
#: afterwards. Reversible alone would not exclude it --
#: sample_origin_configured is reversible and blocks -- but there is no
#: decision here that gets harder once material has arrived: granting the
#: role is the same act on day ninety as on day one, where an origin split
#: retrofitted under pressure is the one that gets done the cheap and
#: wrong way. A refusal would also land on somebody who cannot act on it.
#: `user.manage` is held by SYS_ADMIN alone and this register is gated on
#: `user.manage`, so in the exact state this check reports there is nobody
#: left who can open `/admin/readiness` and read the evidence the refusal
#: sends them to -- a poll refused by name, with the report that explains
#: the name unreadable, is a dead end rather than an instruction. (Note
#: the asymmetry with the four above: the register's READER always holds
#: user.manage, which is why `test_the_sys_admin_check_counts_the_caller_in`
#: can say this check is never honestly false for whoever is looking at
#: it; the caller a blocking check refuses is the COLLECTOR on the poll
#: route, who holds `collection.run` and need not hold user.manage at all,
#: so "the reader is always a SYS_ADMIN" is not on its own a reason a
#: blocking entry could never fire.)
#:
#: Held in register order so `blocking_failures` and `report` name them
#: in the order the pane lists them.
BLOCKING_CHECKS: tuple[str, ...] = (
    "prohibited_content_policy",
    "sample_origin_configured",
    "retention_rules_confirmed",
    "security_officer_present",
)


def run_checks(conn: psycopg.Connection) -> list[Check]:
    """Every check, in register order, each one guarded. `conn` is the
    caller's autocommit connection, so a check whose query fails does not
    leave an aborted transaction for the next check to trip over.

    The tier is stamped HERE rather than inside each probe, so
    `BLOCKING_CHECKS` is the one place that decides what refuses --
    including for a check that crashed, where `_guarded` built the Check
    and the probe never ran at all.
    """
    return [replace(_guarded(name, action, lambda probe=probe: probe(conn)),
                    blocking=name in BLOCKING_CHECKS)
            for name, probe, action in _CHECKS]


def blocking_failures(conn: psycopg.Connection) -> list[str]:
    """The blocking checks failing right now, in register order.

    Public so a caller can refuse without rendering the register: it
    wants four verdicts, not thirteen paragraphs of evidence, and it is
    standing on a request path -- or in a cron pass with a due list
    waiting -- while it asks. Both callers exist:
    `POST /collection/sources/{id}/run` and `scripts/collection_poll.py`,
    which calls this ONCE per pass, before it asks what is due.

    Runs ONLY the blocking probes. The other nine include a Redis PING, a
    MinIO round trip and an Alembic script scan, and making every
    collection poll wait on the object store would turn a readiness
    refusal into a latency bug -- a failure reported as the wrong thing,
    which is the defect this module exists to prevent, aimed at the
    request path instead of at the operator. Each probe is still
    `_guarded`, so one that raises is a name in this list rather than a
    500 in the caller.
    """
    return [name for name, probe, action in _CHECKS
            if name in BLOCKING_CHECKS
            and not _guarded(name, action, lambda probe=probe: probe(conn)).ok]


def report(conn: psycopg.Connection) -> dict:
    """`{ready, checks, blocking_failures}`. `ready` is the conjunction of
    `ok` and nothing else: an operator reading ready=true must be able to
    trust that no row below it says otherwise, and a `ready` computed any
    other way would be a second opinion dressed as a summary.

    `blocking_failures` is derived from THESE checks and not from a
    second run of the blocking probes. Two runs a few milliseconds apart
    can disagree -- somebody confirms the last retention rule between
    them -- and a summary line that named a check the rows below it show
    as passing is the two-internally-consistent-halves defect with the
    operator standing in the middle of it.
    """
    checks = run_checks(conn)
    return {"ready": all(c.ok for c in checks),
            "checks": [c.as_dict() for c in checks],
            "blocking_failures": [c.check for c in checks
                                  if c.blocking and not c.ok]}

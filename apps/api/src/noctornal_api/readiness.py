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
check confirms NOCTORNAL_SAMPLE_ORIGIN is set, but docs/16 says outright
that the runtime "cannot tell the difference between a real origin split
and a CNAME", so whether the configured origin is genuinely separate is a
human confirmation.

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
from dataclasses import dataclass
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


@dataclass(frozen=True)
class Check:
    """One line of the register.

    `action` is what an operator does about a failure; it is empty when
    `ok` is True, because "everything is fine, and here is what to do
    about it" is noise.
    """
    check: str
    ok: bool
    evidence: str
    action: str = ""

    def as_dict(self) -> dict:
        return {"check": self.check, "ok": self.ok,
                "evidence": self.evidence, "action": self.action}


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


def _sample_origin_configured(conn: psycopg.Connection) -> Check:
    """docs/16 C9. Reads `samples.sample_origin()` -- the reader
    `samples.download()` itself consults before handing over live malware
    -- rather than the environment variable directly.

    Added 2026-09-02. C9 was the one register entry with a code-checkable
    half that this module did not check, so `ready=true` was returned for
    deployments where every sample download refuses outright (invariant
    10) while the module docstring claimed to be the code-side half of the
    register "in one place".

    What it establishes is deliberately narrow, and the passing evidence
    says so: that a second origin is CONFIGURED, not that it is genuinely
    separate. docs/16 C9 is explicit that the runtime "cannot tell the
    difference between a real origin split and a CNAME", so that half stays
    a human confirmation and is named in "What is deliberately NOT here".
    """
    from noctornal_api.samples import sample_origin

    origin = sample_origin()
    action = (
        "set NOCTORNAL_SAMPLE_ORIGIN to a genuinely separate origin -- its own "
        "host, cookie scope and CSP, never a path on the app's own host "
        "(docs/16 C9); until it is set, samples.download() refuses every "
        "request, so no analyst can retrieve a sample at all")
    if not origin:
        return Check(
            "sample_origin_configured", False,
            "NOCTORNAL_SAMPLE_ORIGIN is not set, so samples.download() refuses "
            "every request (invariant 10: sample bytes are only ever served "
            "from a separate origin)",
            action)
    return Check(
        "sample_origin_configured", True,
        f"NOCTORNAL_SAMPLE_ORIGIN={origin}; that this is a real origin split "
        f"and not a CNAME onto the app's own host is a human confirmation "
        f"(docs/16 C9), which the runtime cannot make")


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
        f"{policy or '(unset, defaults to noeviction)'}")


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
     "set NOCTORNAL_SAMPLE_ORIGIN to a separate origin (docs/16 C9)"),
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
    ("smtp_configured", _smtp_configured,
     "set SMTP_HOST to a relay that speaks TLS (docs/07)"),
)

#: The names, in the order the report lists them. Public so the router
#: test can read the service's list and the wire's list and insist they
#: are the same list.
CHECK_NAMES: tuple[str, ...] = tuple(name for name, _, _ in _CHECKS)


def run_checks(conn: psycopg.Connection) -> list[Check]:
    """Every check, in register order, each one guarded. `conn` is the
    caller's autocommit connection, so a check whose query fails does not
    leave an aborted transaction for the next check to trip over."""
    return [_guarded(name, action, lambda probe=probe: probe(conn))
            for name, probe, action in _CHECKS]


def report(conn: psycopg.Connection) -> dict:
    """`{ready, checks}`. `ready` is the conjunction of `ok` and nothing
    else: an operator reading ready=true must be able to trust that no
    row below it says otherwise, and a `ready` computed any other way
    would be a second opinion dressed as a summary."""
    checks = run_checks(conn)
    return {"ready": all(c.ok for c in checks),
            "checks": [c.as_dict() for c in checks]}

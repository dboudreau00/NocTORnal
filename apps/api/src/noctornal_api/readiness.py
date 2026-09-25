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
operator to infer it. docs/16 C8: `redis_limiter_store` confirms Redis is
reachable and reports its eviction policy, and since 2026-09-23
(sec-redis-isolation) `redis_limiter_isolated` counts the keys in it that
are not the limiter's and the keys in the instance's other databases,
reading no value. A tenant holding no keys at that moment, or a second
server behind the same address, stays invisible, and that row's passing
evidence says so. docs/16 C9: the
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

docs/16 C2 is checked the same partial way, and since 2026-09-22 by
behaviour rather than by configuration: the two bucket checks try to
DELETE a locked canary version and pass only when the store refuses (the
block above `prove_write_once` says why a configuration read was not
evidence). That establishes that this store refused this delete today.
It cannot establish that nothing else can remove an object (whoever holds
the volume can), and that the store's upstream is archived and unpatched
(docs/17 F24) is a custody question for a human, which no probe answers.

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
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg

from noctornal_api.config import EVIDENCE_CAP_ENV
from noctornal_api.wording import agree, count_of

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

    `consequence` and `ui_target` are stamped the same way and for the
    same reason, and only on a FAILED row (2026-09-23). `consequence` is
    what the product refuses while this check fails, in a sentence: the
    admin banner's headline used to be hard-coded to "the collection poll
    route is refused" while its own items said sample ingest, every
    sample download and break-glass were refused too, so an operator who
    read the headline alone decided the red box could wait
    (ux16-admin:blocking-headline-understates-impact). `ui_target` names
    where in the console the check is settled, as "tab/subtab", so the
    pane can offer a way there instead of a path template for curl
    (ux16-admin:readiness-actions-speak-api). `consequence` is empty when
    the check passes; `ui_target` is empty when the check is settled by
    configuration, and when it passes with no caveat.

    `caveat` is the PROBE's, and only on a PASSING row (2026-09-23,
    ux16-admin:security-officer-false-green): a standing condition the
    operator has to see although the verdict is right to pass. A lone
    SECURITY_OFFICER who can also invoke break-glass passes, because a
    single-operator install is a design choice, and has no emergency
    access at all. That sentence was first written into the evidence, and
    the console folds passing rows away, so nobody would ever have read
    it; a caveat is drawn outside the fold and marked. A failed row has an
    action instead, so `_register_facts` drops a caveat from it.
    """
    check: str
    ok: bool
    evidence: str
    action: str = ""
    blocking: bool = False
    consequence: str = ""
    ui_target: str = ""
    caveat: str = ""

    def as_dict(self) -> dict:
        return {"check": self.check, "ok": self.ok,
                "evidence": self.evidence, "action": self.action,
                "blocking": self.blocking, "consequence": self.consequence,
                "ui_target": self.ui_target, "caveat": self.caveat}


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

#: docs/17 F2, decided by the owner 2026-09-22: a REJECTED sample is
#: preserved by default, and destroyed only where the deployment declares
#: it. The variable, its two values and its default are the preservation
#: store's contract (`samples.py`); read here only to say in the L1
#: evidence which of the two a rejection will actually do.
DISPOSITION_ENV = "NOCTORNAL_REJECTED_SAMPLE_DISPOSITION"
PRESERVE_BUCKET_ENV = "PRESERVE_BUCKET"
PRESERVE_BUCKET_DEFAULT = "noctornal-preserved"


def rejected_sample_disposition() -> tuple[str | None, str]:
    """`(disposition, raw)`: "preserve" or "destroy", or None when the
    variable holds anything else, which the reject path refuses on (docs/17
    F2: "any other value refuses with a message naming the variable").
    Unset or blank is the default, preserve. Read through
    `samples.disposition_setting()`, the reject path's own reading, so the
    register cannot report a disposition the reject path would not apply.
    Imported here rather than at the top: the register loads for every
    readiness probe, and the sample service is only needed for this."""
    from noctornal_api.samples import disposition_setting
    disposition, _problem = disposition_setting()
    return disposition, os.environ.get(DISPOSITION_ENV, "")


def _disposition_evidence() -> str:
    """The sentence the L1 evidence carries about what a rejection does.

    Added 2026-09-22 with docs/17 F2. Until then the L1 row said the policy
    was declared and nothing about what the software would do with the
    material the policy is about, so an operator could read a green L1 on
    a build that destroyed every rejected sample, in a jurisdiction where
    destroying it is itself the offence."""
    disposition, raw = rejected_sample_disposition()
    bucket = preservation_store_settings().bucket
    if disposition == "preserve":
        how = "the default" if not raw.strip() else f"{DISPOSITION_ENV}={raw.strip()}"
        return (f"A rejected sample is PRESERVED into {bucket} under a legal "
                f"hold ({how}), and retrieving it needs a second person's "
                f"authorisation")
    if disposition == "destroy":
        return (f"A rejected sample is DESTROYED ({DISPOSITION_ENV}=destroy): "
                f"its bytes and data key are deleted, except under a legal "
                f"hold, which refuses the destruction. Nothing is preserved")
    return (f"{DISPOSITION_ENV}={raw.strip()!r} is neither preserve nor "
            f"destroy, so every rejection is refused until it is corrected")


def _prohibited_content_policy(conn: psycopg.Connection) -> Check:
    """docs/16 L1. The verdict is `samples.policy_declared`'s, because that
    is the reader that decides whether ingest runs; this only adds the
    designated person and the rejected-sample disposition to the
    evidence. The disposition does not move the verdict: a wrong value
    refuses every rejection loudly rather than doing harm quietly, and
    `preservation_bucket_object_lock` fails on it by name."""
    from noctornal_api.samples import policy_declared

    declared, reference = policy_declared()
    person = os.environ.get("NOCTORNAL_DESIGNATED_PERSON", "").strip()
    disposition = _disposition_evidence()
    if declared:
        return Check(
            "prohibited_content_policy", True,
            f"NOCTORNAL_PROHIBITED_CONTENT_POLICY={reference}; "
            f"NOCTORNAL_DESIGNATED_PERSON={person}. {disposition}. "
            # F13: one clause from the screening reader, so each fact
            # keeps one reader; the verdict does not move on it.
            f"{_screening_clause(conn)} This is a "
            f"declaration the software records, not one it can verify "
            f"(docs/16 L1).")
    policy_set = bool(os.environ.get("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "").strip())
    return Check(
        "prohibited_content_policy", False,
        f"not declared: NOCTORNAL_PROHIBITED_CONTENT_POLICY is "
        f"{'set' if policy_set else 'unset'}, NOCTORNAL_DESIGNATED_PERSON is "
        f"{'set' if person else 'unset'}; sample ingest is refused. "
        f"{disposition}",
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
    # The console first (ux16-admin:readiness-actions-speak-api,
    # 2026-09-23): Records, Retention has had a Confirm rule form since
    # the day this action sent operators to curl, and `ui_target` below
    # makes it a link. The route stays, second, for a scripted deployment.
    # "Records", not "Lifecycle" (u23, 2026-09-24): the rail tab was
    # renamed in the same pass this sentence was written, so it sent
    # operators to a tab that no longer exists, one line above the
    # console's own "open any case, then Records, Retention".
    return Check(
        "retention_rules_confirmed", False, evidence,
        "confirm each placeholder rule in the console under Records, "
        "Retention (Confirm rule; it needs retention.manage and a sign-in "
        "from the last 15 minutes). The periods are jurisdictional and the "
        "build cannot choose them (docs/16 D3). Over the API: POST "
        "/retention/rules/{category}, and GET /retention/rules lists which "
        "are still placeholders")


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
    all, and nothing said so until someone needed it.

    The evidence names the holders, and says when the only one can also
    INVOKE break-glass (ux16-admin:security-officer-false-green,
    2026-09-23). Nobody reviews their own break-glass, so `invoke()`
    refuses unless an officer OTHER than the invoker exists
    (`break_glass.py`, final review C6): a lone officer who is also an
    administrator or a Lead investigator has no emergency access at all,
    and the register used to pass that with "1 active SECURITY_OFFICER
    account" and nothing else.
    The verdict does not move: a single-operator install holding every
    role is a documented design choice (`iam_admin.create_first_admin`),
    and failing a BLOCKING check on it would refuse collection on every
    fresh install. What moves is that the register now says it, as the
    row's `caveat` and not inside its evidence: the console folds passing
    rows away, and a warning in a passing row's evidence sat in a fold
    nothing opens, on exactly the out-of-the-box install it was written
    for (the 2026-09-23 verifier's correction to the first fix).
    """
    rows = conn.execute(
        """SELECT u.email,
                  EXISTS (SELECT 1 FROM iam.user_role r2
                            JOIN iam.role_permission rp
                              ON rp.role_key = r2.role_key
                           WHERE r2.user_id = u.id
                             AND rp.permission_key = 'break_glass.invoke')
             FROM iam.app_user u
             JOIN iam.user_role ur ON ur.user_id = u.id
            WHERE ur.role_key = 'SECURITY_OFFICER' AND u.is_active
            ORDER BY u.email""").fetchall()
    n = len(rows)
    # Agreed, not a bracketed plural: the register prints this as its
    # evidence (README screenshot set review, 2026-09-23). The count stays
    # first, because tests and operators both read it as the verdict.
    evidence = count_of(n, "active SECURITY_OFFICER account",
                        "active SECURITY_OFFICER accounts")
    if n:
        shown = ", ".join(r[0] for r in rows[:5])
        evidence += f" ({shown}{', and more' if n > 5 else ''})"
    caveat = ""
    if n == 1 and rows[0][1]:
        caveat = (
            f"{rows[0][0]} is the only Security Officer and can also invoke "
            "break-glass. Nobody reviews their own, so break-glass is refused "
            "to them until a second person holds this role. Grant "
            "SECURITY_OFFICER to a second person, ideally one who "
            "administers nothing and leads no case.")
    return Check(
        "security_officer_present", n >= 1, evidence,
        "" if n >= 1 else
        "grant SECURITY_OFFICER to an active account in the console under "
        "Admin, Accounts (Grant role), ideally to someone who is not the "
        "administrator configuring this: nobody reviews their own "
        "break-glass. Break-glass refuses every request while nobody can "
        "review it, and audit.read is held by this role alone. Over the "
        "API: POST /admin/users/{user_id}/roles",
        caveat=caveat)


def _sys_admin_present(conn: psycopg.Connection) -> Check:
    """`user.manage` is held by SYS_ADMIN alone. With none active, accounts
    can only be repaired from the database shell."""
    n = _active_holders(conn, "SYS_ADMIN")
    return Check(
        "sys_admin_present", n >= 1,
        count_of(n, "active SYS_ADMIN account", "active SYS_ADMIN accounts"),
        "" if n >= 1 else
        "grant SYS_ADMIN to an active account (Admin, Accounts); "
        "user.manage is held by SYS_ADMIN alone, so with none the only "
        "repair path is scripts/bootstrap.py on the server")


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


def _kek_ring_opens_stored_secrets(conn: psycopg.Connection) -> Check:
    """Does the ring open every key id the database actually holds?

    `totp_kek_set` proves the active key DECODES. This proves the keys
    OPEN things: up to `sealed.SAMPLE_ROWS` blobs per (table, key id)
    across the five sealed columns (`security/sealed.SEALED_COLUMNS`),
    through `envelope.can_open`, which is `decrypt` with the plaintext
    thrown away -- and COUNTED, because before the ring every blob was
    recorded under one id whatever key sealed it, so one row's verdict
    is not a group's (`sealed.py` says how that was found). The distinction is the whole finding it exists for: until
    2026-09-11 a KEK that had changed under a live database -- rotated,
    or restored from the wrong backup -- left this register green while
    every login answered 500, because the only KEK check there was asked
    whether the value was 32 bytes.

    Failure evidence names the table, the row count and the key id, and
    says which of the two faults it is: no key of that id in the ring, or
    a key of that id that does not open the blob (the key changed and the
    id did not). It never prints key material; ids are labels.

    Not blocking. It is an operability failure -- nobody can sign in --
    of the kind the tier note above says belongs to `sys_admin_present`'s
    class, not to the decisions that cannot wait.
    """
    from noctornal_api.security import envelope
    from noctornal_api.security.sealed import inventory

    name = "kek_ring_opens_stored_secrets"
    action = (
        "add the key that sealed those rows to NOCTORNAL_TOTP_KEK_RETIRED as "
        "id=base64 (or restore it as NOCTORNAL_TOTP_KEK), restart, then run "
        "scripts/rewrap_secrets.py --apply to move every row under the active "
        "key; security/envelope.py has the runbook")
    try:
        ids = envelope.key_ids()
    except (RuntimeError, ValueError) as exc:
        return Check(name, False, str(exc), action)
    active, retired = ids[0], ids[1:]
    ring = f"active {active}" + (
        f", retired {', '.join(retired)}" if retired else ", no retired keys")
    groups = inventory(conn)
    if not groups:
        return Check(name, True, f"ring: {ring}; no sealed rows yet")
    bad = [g for g in groups if not g.opens]
    if bad:
        detail = "; ".join(g.describe() for g in bad)
        return Check(name, False, f"ring: {ring}; cannot open: {detail}", action)
    held = ", ".join(g.describe() for g in groups)
    evidence = f"ring: {ring}; every checked row opens ({held})"
    if any(g.key_id != active for g in groups):
        evidence += ("; rows under a retired id remain, so run "
                     "scripts/rewrap_secrets.py --apply before dropping it")
    return Check(name, True, evidence)


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


def _credentials_not_published(conn: psycopg.Connection) -> Check:
    """Does any credential this process holds carry a value somebody has
    already published? (sec-dev-secrets-in-production, 2026-09-23)

    The verdict is `config.published_credentials`', the reader a
    production boot refuses on, so this row and the boot cannot disagree
    about what "published" means. It is here as well as there because the
    boot refuses only under `NOCTORNAL_ENV=production`, exactly spelt, and
    config.py names the misspelling as the edge it cannot close: a
    deployment that meant production and wrote `prod` starts on the
    development password with nothing said. This row says it on every
    process.

    It sees this process's environment and nothing else. The production
    compose file hands every service the whole of secrets.env, so there
    that is every credential the stack has; a Postgres or MinIO configured
    somewhere this process cannot read is not covered, and the passing
    evidence says so rather than claiming the store's own password.

    NOT blocking, and red on every development machine and in CI by
    design, for the reason `app_db_role_not_owner` gives: a development
    stack runs on the published password on purpose, and a refusal keyed
    to a check that is red everywhere except production would be switched
    off within a week. Values are never quoted, only variable names and
    which published value each one carries.
    """
    from noctornal_api.config import ENV_VAR, PRODUCTION, published_credentials

    name = "credentials_not_published"
    found = published_credentials()
    if not found:
        return Check(
            name, True,
            "no credential in this process's environment carries a value this "
            "repository, its CI workflow, its test suites or MinIO publish; a "
            "store configured outside this environment is not visible from here")
    listed = "; ".join(f"{p.variable} ({p.label})" for p in found)
    production = os.environ.get(ENV_VAR, "").strip().lower() == PRODUCTION
    mode = ("this process runs as production, so it should not have started "
            "at all" if production else
            f"{ENV_VAR} is not {PRODUCTION}, so the boot check that refuses "
            f"these did not run; a development stack runs on them by design")
    return Check(
        name, False,
        f"{count_of(len(found), 'credential carries', 'credentials carry')} a "
        f"value anyone who has read the source already holds: {listed}. {mode}",
        "replace each with a value generated for this deployment (python -c "
        "\"import secrets; print(secrets.token_urlsafe(32))\", or for the KEK "
        "the base64 of 32 random bytes), give the limiter's Redis a password, "
        "and restart; under NOCTORNAL_ENV=production the API refuses to start "
        "on any of these")


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
        "On a development or CI database this check is expected to fail: the "
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
        "set NOCTORNAL_SAMPLE_ORIGIN to a genuinely separate origin (its own "
        "host, cookie scope and CSP, never a path on the app's own host; "
        "docs/16 C9) and, on the process that serves it, set "
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
        # The bundled stack is named for what it runs now. The action said
        # infra/docker-compose.yml sets allkeys-lru, which stopped being true
        # when that file moved to noeviction (Alpha 6 pre-release check,
        # 2026-09-23). An evicting policy seen here is an operator's own
        # Redis, or a dev stack started from the older file and never
        # recreated, so the action names the command that recreates it.
        return Check(
            "redis_limiter_store", False,
            f"Redis at {where} answers PING; maxmemory-policy={policy}, which "
            f"deletes live rate-limit meters under memory pressure, and a deleted "
            f"meter admits the subject it was refusing with a full burst",
            "run the limiter's Redis with maxmemory-policy=noeviction, or give "
            "it its own instance (docs/16 C8). The bundled "
            "infra/docker-compose.yml runs noeviction; a dev stack started "
            "from an older copy of that file keeps its old policy until "
            "`docker compose -f infra/docker-compose.yml up -d` recreates it")
    return Check(
        "redis_limiter_store", True,
        f"Redis at {where} answers PING; maxmemory-policy="
        f"{policy or '(unset, defaults to noeviction)'}; whether the "
        f"limiter has this instance to itself is redis_limiter_isolated's "
        f"question (docs/16 C8)")


# ---------------------------------------------------------------------------
# The limiter's Redis, to itself (sec-redis-isolation, 2026-09-23)
# ---------------------------------------------------------------------------
#
# `noeviction` is half of docs/16 C8. The other half is that nothing else
# lives in that Redis, and until 2026-09-23 the register said that half was
# "a deployment fact the runtime cannot see". Part of it can be seen. A
# cache, a queue or a session store sharing the instance leaves KEYS, and
# the harm arrives through the memory those keys hold: `maxmemory` is per
# instance, so under noeviction a co-tenant filling it makes every meter
# write fail and every limit that fails closed refuse everyone, and under
# an evicting policy the co-tenant's pressure is what deletes the meters.
#
# So the check counts two things and reads no value. Key NAMES in the
# limiter's own database, with SCAN, split by whether they sit under the
# limiter's prefix; and the key COUNT of every other database on the
# instance, from INFO keyspace, which carries no name at all. The evidence
# holds counts and never a key name: another tenant's names can carry a
# user id or an email, and this evidence goes into a screenshot.
#
# What it cannot see, said in its passing evidence: a tenant that holds no
# keys at the moment it looks, and a second instance behind the same
# address. A green row means "nothing else has left keys here", which is
# the part of C8 a runtime can establish.

#: SCAN page size, and the most keys one probe will walk before it stops
#: and says it did not finish. A limiter holds one meter per live subject
#: per limit, and each expires within its window, so a real deployment
#: holds hundreds; the ceiling is there so a Redis that turns out to be a
#: million-key cache is reported as shared quickly rather than walked.
_CENSUS_PAGE = 1000
_CENSUS_LIMIT = 100_000
_CENSUS_BUDGET_S = 2.0

#: Keys a managed Redis writes into database 0 for its own bookkeeping,
#: matched by exact name and never by pattern. c24 (2026-09-24): AWS
#: documents that ElastiCache adds `ElastiCacheMasterReplicationTimestamp`
#: to every Valkey or Redis OSS cluster to measure replication lag, so a
#: limiter alone on ElastiCache was reported SHARED on every call, with an
#: action ("move whatever else writes to this one elsewhere") nobody could
#: carry out. The service is not a co-tenant: the key is one small value
#: it rewrites in place, nothing that grows towards `maxmemory`. The
#: evidence counts these separately and still never prints a name.
_PROVIDER_BOOKKEEPING = frozenset({b"ElastiCacheMasterReplicationTimestamp"})


def _limiter_prefix() -> bytes:
    """The prefix every key the limiter writes starts with, meters and
    audit throttles alike (`rl:<limit>:<subject>`, `rl:audit:...`).

    Read from `RateLimiter`'s own constructor default, which is the value
    `http.limits.build_limiter` builds with, so this cannot drift from what
    the limiter writes if the default ever changes."""
    import inspect

    from noctornal_api.ratelimit import RateLimiter

    prefix = inspect.signature(RateLimiter).parameters["key_prefix"].default
    return f"{prefix}:".encode()


@dataclass(frozen=True)
class _Census:
    """What one walk of the limiter's Redis found. Counts only."""
    db: int
    total: int                  # DBSIZE of the limiter's database
    scanned: int                # keys the walk looked at (SCAN may repeat one)
    foreign: int                # distinct keys outside the limiter's prefix
    complete: bool              # the walk reached the end of the keyspace
    others: dict[int, int] | None  # {db: key count}; None when INFO was refused
    provider: int = 0           # distinct _PROVIDER_BOOKKEEPING keys, not foreign


def _text(value) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _limiter_db(client) -> int:
    """The database number the client talks to, as redis-py parsed it out
    of REDIS_URL (the `/N` path or `?db=N`)."""
    kwargs = getattr(getattr(client, "connection_pool", None), "connection_kwargs", {})
    try:
        return int(kwargs.get("db", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _other_databases(client, own: int) -> dict[int, int] | None:
    """`{db: keys}` for every database but `own` that holds a key, from
    INFO keyspace; None when the server will not answer INFO."""
    try:
        info = client.info("keyspace")
    except Exception as exc:  # noqa: BLE001 - an ACL or a renamed command
        log.debug("INFO keyspace was refused: %s: %s", type(exc).__name__, exc)
        return None
    others: dict[int, int] = {}
    for section, stats in (info or {}).items():
        label = _text(section)
        if not label.startswith("db"):
            continue
        try:
            index = int(label[2:])
        except ValueError:
            continue
        if isinstance(stats, dict):
            keys = stats.get("keys", stats.get(b"keys", 0))
        else:  # "keys=3,expires=1,avg_ttl=0", on a client that did not parse it
            keys = dict(p.split("=", 1) for p in _text(stats).split(",")
                        if "=" in p).get("keys", 0)
        if index != own and int(keys):
            others[index] = int(keys)
    return others


def _census(client, prefix: bytes, *, clock=time.monotonic) -> _Census:
    """Walk the limiter's database with SCAN and count, never read.

    SCAN, DBSIZE and INFO are the only commands sent: none of them returns
    a value, and a key's name is compared with the prefix and dropped
    (only the foreign ones are held, as a set, so a key SCAN returns twice
    is counted once). SCAN rather than KEYS, because KEYS blocks the server
    for the length of the walk and this Redis is on the request path.
    The page, the ceiling and the budget are read at call time, so a test
    can shrink them.
    """
    page, limit = _CENSUS_PAGE, _CENSUS_LIMIT
    own = _limiter_db(client)
    total = int(client.dbsize())
    deadline = clock() + _CENSUS_BUDGET_S
    foreign: set[bytes] = set()
    provider: set[bytes] = set()
    scanned = 0
    cursor = 0
    complete = False
    while True:
        cursor, keys = client.scan(cursor=cursor, count=page)
        for key in keys:
            name = key if isinstance(key, bytes) else str(key).encode()
            scanned += 1
            if name.startswith(prefix):
                continue
            # Only in database 0, where the service writes it: the same
            # name anywhere else was put there by somebody else (c24,
            # 2026-09-24).
            if own == 0 and name in _PROVIDER_BOOKKEEPING:
                provider.add(name)
            else:
                foreign.add(name)
        if int(cursor) == 0:
            complete = True
            break
        if scanned >= limit or clock() >= deadline:
            break
    return _Census(own, total, scanned, len(foreign), complete,
                   _other_databases(client, own), len(provider))


def _redis_limiter_isolated(conn: psycopg.Connection) -> Check:
    """docs/16 C8, the half `redis_limiter_store` cannot answer: does the
    limiter have its Redis to itself? See the block above for what is
    counted, what is never read, and what stays invisible.

    Not blocking, like the rest of C8: a shared Redis endangers the limits,
    and refusing a collection poll over it would be refusing the wrong
    thing. A walk that cannot finish, or a server that will not answer
    SCAN or INFO, is NOT ok, on the rule `redis_limiter_store` states for
    an unknown eviction policy: the register lists things confirmed.
    """
    from noctornal_api.http.limits import redacted_url
    from noctornal_api.ratelimit_redis import CONNECT_TIMEOUT_S, RedisBackend

    name = "redis_limiter_isolated"
    action = (
        "give the rate limiter a Redis instance of its own, running "
        "maxmemory-policy=noeviction, and point REDIS_URL at it; move "
        "whatever else writes to this one elsewhere (docs/16 C8)")
    url = os.environ.get("REDIS_URL", "").strip()
    if not url:
        return Check(
            name, False,
            "REDIS_URL is not set, so there is no limiter Redis to inspect "
            "(redis_limiter_store reports the same fault)",
            "set REDIS_URL to a Redis reserved for the limiter, running with "
            "maxmemory-policy=noeviction (docs/16 C8)")
    where = redacted_url(url)
    prefix = _limiter_prefix()
    shown = prefix.decode()
    backend = RedisBackend(url)
    try:
        if not backend.ping():
            return Check(
                name, False,
                f"Redis at {where} did not answer PING within "
                f"{CONNECT_TIMEOUT_S}s, so who else uses it cannot be read "
                f"(redis_limiter_store reports the outage)",
                "start Redis, or point REDIS_URL at the instance that is running")
        # The backend's own client, so the walk runs under the limiter's
        # timeouts and no-retry setting (ratelimit_redis.py, point 3): a
        # sick Redis fails this row in a quarter of a second rather than
        # holding the whole register.
        try:
            census = _census(backend._redis, prefix)
        except Exception as exc:  # noqa: BLE001 - a refused SCAN is a verdict
            return Check(
                name, False,
                f"Redis at {where} answers PING but would not list its keys "
                f"({type(exc).__name__}: {str(exc)[:200]}), so whether anything "
                f"else writes to it is UNKNOWN",
                "confirm out of band that nothing but the rate limiter uses "
                "this Redis, or let REDIS_URL's user run SCAN, DBSIZE and INFO "
                "(docs/16 C8)")
    finally:
        backend.close()

    db = f"database {census.db} at {where}"
    others = census.others
    shared: list[str] = []
    if census.foreign:
        shared.append(
            f"{'at least ' if not census.complete else ''}"
            f"{count_of(census.foreign, 'key', 'keys')} in it "
            f"{agree(census.foreign, 'is', 'are')} not the limiter's "
            f"(outside {shown}, of {census.total} in all)")
    if others:
        shared.append("other databases on the instance hold keys: " + ", ".join(
            f"db{index} {count_of(n, 'key', 'keys')}"
            for index, n in sorted(others.items())))
    if shared:
        if (not census.foreign and census.db != 0 and set(others or {}) == {0}
                and others[0] <= len(_PROVIDER_BOOKKEEPING)):
            # The one shape a managed service's bookkeeping leaves when the
            # limiter is on another database: INFO carries counts only, so
            # the key in db0 cannot be recognised from here, and the way to
            # let it be is to put the limiter where it can (c24,
            # 2026-09-24).
            action += (
                ". On AWS ElastiCache, database 0 always holds one key the "
                "service writes for itself, which this check recognises only "
                "in the limiter's own database: point REDIS_URL at database "
                "0 there")
        return Check(
            name, False,
            f"SHARED: the limiter uses {db}; {'; '.join(shared)}. maxmemory is "
            f"per instance, so a co-tenant's memory is what fills it until "
            f"every meter write fails, or what an evicting policy deletes "
            f"meters to make room for. No key name or value was read into "
            f"this evidence",
            action)
    if not census.complete:
        return Check(
            name, False,
            f"{db}: the first {census.scanned} of {census.total} keys scanned "
            f"are all under {shown}, and the walk stopped there, so the rest "
            f"are UNKNOWN",
            "confirm out of band that nothing but the rate limiter uses this "
            "Redis (docs/16 C8); a limiter alone does not usually hold this "
            "many live meters")
    meters = census.total - census.provider
    own = (f"{db} holds no keys (nothing has been metered yet)" if not census.total
           else f"{db} holds {count_of(census.total, 'key', 'keys')}, "
                f"{agree(census.total, 'and it is', 'all of them')} under the "
                f"limiter's prefix {shown}")
    if census.provider:
        # Said, not silently dropped: a reader comparing this row with
        # DBSIZE should find every key accounted for (c24, 2026-09-24).
        bookkeeping = (
            f"{count_of(census.provider, 'key', 'keys')} the hosting service "
            f"writes for its own replication bookkeeping (AWS ElastiCache), "
            f"which is not a co-tenant")
        own = (f"{db} holds nothing metered yet, only {bookkeeping}"
               if meters <= 0 else
               f"{db} holds {count_of(census.total, 'key', 'keys')}: "
               f"{meters} under the limiter's prefix {shown} and {bookkeeping}")
    if others is None:
        return Check(
            name, False,
            f"{own}, but INFO keyspace was refused, so the instance's other "
            f"databases are UNKNOWN",
            "confirm out of band that no other database on this instance is "
            "in use, or let REDIS_URL's user run INFO (docs/16 C8)")
    return Check(
        name, True,
        f"{own}, and no other database on the instance holds a key. A tenant "
        f"that holds no keys right now, or a second server behind the same "
        f"address, is not visible from here (docs/16 C8)")


# ---------------------------------------------------------------------------
# Write-once, PROVEN rather than read (docs/17 F24, docs/16 C2)
# ---------------------------------------------------------------------------
#
# Until 2026-09-22 `evidence_bucket_object_lock` passed on
# `get_object_lock_config` answering with a configuration. That is the
# store's opinion of itself, and the owner's F24 decision (stay on the
# pinned MinIO build, accepted in writing) rests on a store that actually
# refuses. Research for that decision found why the opinion is not enough:
# SeaweedFS accepts a COMPLIANCE retention and has let the delete succeed
# anyway (seaweedfs issues 8350 and 11333, the second deleting the locked
# version by its id), and Garage implements no object lock at all. Either
# would satisfy a configuration read and hold nothing.
#
# So each probe tries to destroy something. One canary object per bucket
# lives at a fixed key, written under a short COMPLIANCE retention only
# when it is absent or about to expire, and every probe issues a DELETE of
# THAT VERSION ID and passes only when the store refuses it for retention
# and the version is still there afterwards. The version id is the whole
# test: on a versioned bucket a DELETE without one adds a delete marker and
# succeeds, which proves nothing (evidence.py measured exactly that on
# 2026-08-10, and it is what seaweedfs 8350 reports as a failure).
#
# A refusal only proves something when the credentials making the attempt
# were ALLOWED to make it. An `AccessDenied` is the account's policy
# talking, not the lock, so a proof stopped by one says "denied" and never
# "proven" (the preservation check below then tries the one credential here
# that may delete, because the preservation account is minted unable to).
#
# The final review of 2026-09-23 found two claims the refusal did not back.
# C10: a plain DELETE is refused under GOVERNANCE exactly as under
# COMPLIANCE, and GOVERNANCE yields to anyone holding the bypass permission,
# the root credential included. The probe asked for COMPLIANCE and never
# looked at what the store recorded, so a store that recorded GOVERNANCE
# passed with evidence naming the mode it had REQUESTED. The mode is now
# read back, and anything but COMPLIANCE fails. C9: a preserved sample is
# protected by a LEGAL HOLD and no retention, and a hold is a separate S3
# mechanism that a store can record without enforcing, so the preservation
# check also proves a hold (`_prove_hold`), written the way `preserve()`
# writes every rejected sample.

#: The one object each probed bucket carries for this. A fixed key, so
#: repeated probes reuse one locked version instead of filling the bucket.
WORM_CANARY_KEY = ".noctornal-worm-canary"
#: The preservation bucket's second canary, for the mechanism its samples
#: rely on: a legal hold and no retention (final review C9, 2026-09-23).
#: Its own key and never WORM_CANARY_KEY, because a held version does not
#: lapse, and `_tidy_canaries` would retry it on every probe and spend its
#: `_TIDY_LIMIT` on it. One held version, kept for good: a hold has no
#: expiry, so it costs one small object and no tidying.
HOLD_CANARY_KEY = ".noctornal-hold-canary"
#: How long a canary is locked. COMPLIANCE cannot be shortened by anyone,
#: so a new canary version is written at most about once a day per bucket,
#: and the versions whose day has passed are removed by the probe that
#: next succeeds (`_tidy_canaries`), so the bucket carries one or two.
CANARY_RETENTION = timedelta(days=1)
#: A canary with less than this left is replaced rather than tested, so a
#: lock that lapses between the read and the delete cannot be reported as
#: a store that does not enforce one.
CANARY_MARGIN = timedelta(hours=1)
#: The longest one CHECK's proof may take, every attempt included. Each
#: store call keeps the 1s connect and 5s read timeouts above, but a proof
#: is up to six calls where the configuration read it replaced was one, so
#: a store that answers each call slowly could otherwise hold the register
#: for most of a minute (verifier, 2026-09-22). Checked before every call:
#: the worst case is this plus one read timeout.
_PROBE_BUDGET_S = 10.0
#: Old canary versions one probe removes at most, so tidying up after an
#: outage that left many cannot itself become the slow part.
_TIDY_LIMIT = 5
_CANARY_BODY = (
    b"NocTORnal write-once canary. Written by the readiness register "
    b"(readiness.py) under a short COMPLIANCE retention; every probe tries to "
    b"delete this exact version and passes only when the store refuses.\n")
_HOLD_CANARY_BODY = (
    b"NocTORnal legal-hold canary. Written by the readiness register "
    b"(readiness.py) under a legal hold and no retention, the way a rejected "
    b"sample is preserved; every probe tries to delete this exact version "
    b"and passes only when the store refuses. A hold has no expiry, so this "
    b"version is kept for good.\n")
#: What a HEAD of an absent key comes back as. minio-py synthesises the
#: code for a bodiless 404, and a delete marker as the latest version is
#: a 404 too.
_ABSENT = frozenset({"NoSuchKey", "NoSuchVersion"})
#: The refusal that is about the CREDENTIALS rather than the object.
_DENIED = "AccessDenied"


@dataclass(frozen=True)
class _Proof:
    ok: bool
    evidence: str
    #: True when a step was refused by the credentials' own policy
    #: (`AccessDenied` that `is_retention_refusal` does not recognise), so
    #: this attempt says nothing about the store either way.
    denied: bool = False
    #: For a denied proof, the refused step in a few words ("may not
    #: delete a version (AccessDenied)"), for a sentence about the account.
    step: str = ""
    #: Denied at the very first step: these credentials may not even read
    #: the bucket, which is a different fact from "may not delete in it".
    unreadable: bool = False
    #: The account rejected samples are preserved WITH was refused a step
    #: `PreservationStorage.preserve` takes itself (a held PUT, or reading
    #: the hold back), so every rejection is refused, and a proof made
    #: around it with another credential would hide exactly that.
    cannot_preserve: bool = False


class _OutOfTime(Exception):
    """The proof's budget ran out before its next store call."""


class _NotCompliance(Exception):
    """The store recorded another mode than COMPLIANCE on a canary this
    probe wrote under COMPLIANCE (final review C10, 2026-09-23)."""

    def __init__(self, version: str, mode: str | None, until: datetime | None):
        super().__init__(version)
        self.version, self.mode, self.until = version, mode, until


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M UTC")


_MISSING = _Proof(False, (
    "the bucket does not exist (NoSuchBucket), so nothing can be written "
    "to it, locked or not"))


def _denied(what: str, exc, tail: str = "") -> _Proof:
    """A step refused on the credentials' own policy: says nothing either
    way, and says so."""
    return _Proof(False, (
        f"these credentials may not {what}{tail} ({exc.code}: "
        f"{exc.message}). A permissions refusal says nothing about "
        f"write-once either way"),
        denied=True, step=f"may not {what} ({exc.code})")


def _not_compliance(exc: _NotCompliance) -> _Proof:
    until = f" until {_stamp(exc.until)}" if exc.until else ""
    return _Proof(False, (
        f"the store recorded {exc.mode}{until} on canary {WORM_CANARY_KEY} "
        f"version {exc.version}, which this probe only ever writes under "
        f"COMPLIANCE. A plain DELETE is refused under GOVERNANCE too, and "
        f"GOVERNANCE yields to anyone holding s3:BypassGovernanceRetention "
        f"(the root credential included), so nothing here is proven "
        f"write-once. If that retention was set by hand rather than by the "
        f"store, remove that version and the next probe writes a fresh "
        f"canary"))


def _out_of_time(exc: _OutOfTime) -> _Proof:
    return _Proof(False, (
        f"the proof did not finish within {_PROBE_BUDGET_S:g}s (it had "
        f"reached {exc}): the store answers, but too slowly for this "
        f"probe to show that it refuses anything"))


class _Budgeted:
    """A store client whose every call first checks one shared deadline."""

    def __init__(self, client, deadline: float, clock: Callable[[], float]):
        self._client, self._deadline, self._clock = client, deadline, clock

    def __getattr__(self, name: str):
        method = getattr(self._client, name)

        def call(*args, **kwargs):
            if self._clock() >= self._deadline:
                raise _OutOfTime(name)
            return method(*args, **kwargs)
        return call


def _object_store_client(endpoint: str, access: str, secret: str,
                         secure: bool):
    """A client that gives up quickly. Module level so a test can swap
    in a fake store without a network. The client's default pool waits
    five minutes and retries five times; a readiness probe against a hung
    store would hold the report for longer than the operator waits."""
    import urllib3
    from minio import Minio

    http = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=_PROBE_CONNECT_S, read=_PROBE_READ_S),
        retries=urllib3.Retry(total=0),
    )
    return Minio(endpoint, access_key=access, secret_key=secret,
                 secure=secure, http_client=http)


def _utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _live_canary(client, bucket: str, now: datetime):
    """`(version_id, retain_until, how)` of a canary locked for long
    enough to test, or None. Anything short of that (absent, a delete
    marker on top, no retention, about to lapse) is None, and the caller
    writes a fresh one. A failed HEAD other than "absent" raises, for the
    caller to name, and so does a canary the store recorded under another
    mode than COMPLIANCE (`_NotCompliance`, final review C10, 2026-09-23).

    Credentials that may not READ a retention (`s3:GetObjectRetention`,
    which nothing else in the product needs) get the canary's lock from
    its write time instead: this probe is the only writer of the key and
    always asks for `CANARY_RETENTION`. Until 2026-09-22 they got None, so
    every probe wrote another locked version (verifier). The inference
    picks WHICH version to test and never the verdict: if the store did
    not in fact lock it, the delete below succeeds and the check fails.
    """
    from minio.commonconfig import COMPLIANCE
    from minio.error import S3Error

    try:
        stat = client.stat_object(bucket, WORM_CANARY_KEY)
    except S3Error as exc:
        if exc.code in _ABSENT:
            return None
        raise
    if not stat.version_id:
        return None
    try:
        retention = client.get_object_retention(
            bucket, WORM_CANARY_KEY, version_id=stat.version_id)
    except S3Error as exc:
        written = getattr(stat, "last_modified", None)
        if exc.code != _DENIED or written is None:
            # The PUT below meets the same store and reports what it says
            # precisely; guessing at it here would be a second, vaguer
            # reading.
            return None
        until, how = _utc(written) + CANARY_RETENTION, "inferred"
    else:
        if retention is None:
            return None
        if retention.mode != COMPLIANCE:
            # This probe is the key's only writer and always asks for
            # COMPLIANCE, so another mode is the store's answer. Until the
            # final review (C10, 2026-09-23) this returned None: every probe
            # then wrote one more canary, the store locked it GOVERNANCE,
            # the plain DELETE was refused and the check passed claiming
            # COMPLIANCE, leaving a version per probe nobody could tidy.
            raise _NotCompliance(stat.version_id, retention.mode,
                                 _utc(retention.retain_until_date))
        until, how = _utc(retention.retain_until_date), "read"
    if until <= now + CANARY_MARGIN:
        return None
    return stat.version_id, until, how


def _tidy_canaries(client, bucket: str, *, keep: str,
                   now: datetime) -> tuple[int, str]:
    """Remove canary versions whose day has passed; `(removed, problem)`.

    Runs only after a proof passed, so on a store that has just shown it
    refuses a locked delete. Touches nothing but `WORM_CANARY_KEY`, never
    the version just tested, and only versions written more than
    `CANARY_RETENTION` ago (plus any delete marker, which hides nothing and
    whose removal destroys nothing). A version still locked, by clock skew
    or a longer retention some other tool applied, is refused and kept.
    Best effort: a failure here is reported beside a proof that stands.

    "Any failure" means any: the probe's client retries nothing and reads
    for five seconds at most, so a reset connection, a read timeout or a
    proxy's HTML answer (urllib3 errors, minio's InvalidResponseError and
    ServerError, none of them an S3Error) is ordinary here. Until the final
    review (U6, 2026-09-23) only S3Error was caught, and one of those after
    a passed proof turned the row red with "start the object store".
    """
    from minio.error import S3Error

    from noctornal_api.evidence import is_retention_refusal

    removed = attempts = 0
    try:
        for v in client.list_objects(bucket, prefix=WORM_CANARY_KEY,
                                     include_version=True):
            if attempts >= _TIDY_LIMIT:
                break
            if v.object_name != WORM_CANARY_KEY or v.version_id == keep:
                continue
            written = getattr(v, "last_modified", None)
            if not v.is_delete_marker and (
                    written is None or _utc(written) + CANARY_RETENTION > now):
                continue
            attempts += 1
            try:
                client.remove_object(bucket, WORM_CANARY_KEY,
                                     version_id=v.version_id)
            except S3Error as exc:
                if is_retention_refusal(exc):
                    continue
                return removed, exc.code
            if not v.is_delete_marker:
                removed += 1
    except S3Error as exc:
        return removed, exc.code
    except _OutOfTime:
        return removed, "the probe's time ran out"
    except Exception as exc:  # noqa: BLE001 - best effort, see the docstring
        return removed, f"{type(exc).__name__}: {str(exc)[:120]}"
    return removed, ""


def _prove(client, bucket: str, *, now: datetime, deadline: float,
           clock: Callable[[], float]) -> _Proof:
    """The proof itself; see `prove_write_once` for what passes."""
    try:
        return _prove_steps(_Budgeted(client, deadline, clock), bucket, now)
    except _OutOfTime as exc:
        return _out_of_time(exc)


def _prove_steps(client, bucket: str, now: datetime) -> _Proof:
    import io

    from minio.commonconfig import COMPLIANCE
    from minio.error import S3Error
    from minio.retention import Retention

    from noctornal_api.evidence import is_retention_refusal

    try:
        live = _live_canary(client, bucket, now)
    except _NotCompliance as exc:
        return _not_compliance(exc)
    except S3Error as exc:
        if exc.code == "NoSuchBucket":
            return _MISSING
        if exc.code == _DENIED:
            return replace(_denied("read this bucket", exc), unreadable=True)
        return _Proof(False, (
            f"the store would not say whether the canary exists "
            f"({exc.code}: {exc.message})"))
    #: The store reported NO retention on the version this probe just wrote
    #: under one, so a refused DELETE below cannot be tied to COMPLIANCE.
    unrecorded = False
    if live is None:
        requested = now + CANARY_RETENTION
        try:
            result = client.put_object(
                bucket, WORM_CANARY_KEY, io.BytesIO(_CANARY_BODY),
                len(_CANARY_BODY), content_type="text/plain",
                retention=Retention(COMPLIANCE, requested))
        except S3Error as exc:
            if exc.code == "NoSuchBucket":
                return _MISSING
            if exc.code == _DENIED and not is_retention_refusal(exc):
                return _denied("write an object under a retention "
                               "(s3:PutObjectRetention)", exc)
            return _Proof(False, (
                f"the store refused to write a canary under a COMPLIANCE "
                f"retention ({exc.code}: {exc.message}); on a bucket without "
                f"object lock that is the refusal to expect, and nothing "
                f"written to this bucket is write-once"))
        version = getattr(result, "version_id", None)
        if not version:
            return _Proof(False, (
                "the store accepted a canary under a COMPLIANCE retention and "
                "returned no version id, so the bucket is not versioned and "
                "no lock can be holding it. A store that accepts a retention "
                "it cannot enforce is the failure this probe exists to catch"))
        # What the store RECORDED, not what was asked (final review C10,
        # 2026-09-23). A plain DELETE is refused under GOVERNANCE too, so
        # the refusal below cannot tell the two apart; only this read can.
        # A permissions refusal is the account's policy and the proof goes
        # on, saying the mode is requested and not confirmed. Any other
        # answer is the store declining to name the lock, which fails.
        try:
            applied = client.get_object_retention(
                bucket, WORM_CANARY_KEY, version_id=version)
        except S3Error as exc:
            if exc.code != _DENIED:
                return _Proof(False, (
                    f"the store took canary {WORM_CANARY_KEY} version "
                    f"{version} under a COMPLIANCE retention and then would "
                    f"not say what retention it recorded ({exc.code}: "
                    f"{exc.message}), so the lock a refused DELETE meets "
                    f"cannot be named"))
            lock = f"COMPLIANCE requested until {_stamp(requested)}"
            how = ("written by this probe; these credentials may not read a "
                   "retention, so the mode the store recorded is not "
                   "confirmed")
        else:
            if applied is not None and applied.mode != COMPLIANCE:
                return _not_compliance(_NotCompliance(
                    version, applied.mode, _utc(applied.retain_until_date)))
            if applied is None:
                unrecorded = True
                lock = f"COMPLIANCE requested until {_stamp(requested)}"
                how = "written by this probe; the store reports no retention on it"
            else:
                lock = f"COMPLIANCE until {_stamp(_utc(applied.retain_until_date))}"
                how = "written by this probe and read back"
    else:
        version, until, how = live
        if how == "read":
            lock, how = f"COMPLIANCE until {_stamp(until)}", "reused"
        else:
            lock = f"COMPLIANCE requested until {_stamp(until)}"
            how = ("reused; its lock is taken from when it was written, as "
                   "these credentials may not read a retention, so the mode "
                   "the store recorded is not confirmed")

    what = f"canary {WORM_CANARY_KEY} version {version} ({lock}, {how})"
    try:
        client.remove_object(bucket, WORM_CANARY_KEY, version_id=version)
    except S3Error as exc:
        if not is_retention_refusal(exc):
            if exc.code == _DENIED:
                return _denied("delete a version", exc,
                               f", so a DELETE of {what} proved nothing")
            return _Proof(False, (
                f"a DELETE of {what} was refused, but not for retention "
                f"({exc.code}: {exc.message}), so the refusal says nothing "
                f"about write-once"))
        refusal = exc.code
    else:
        return _Proof(False, (
            f"a DELETE of {what} SUCCEEDED: this store accepts a COMPLIANCE "
            f"retention and does not enforce it, so no object in this bucket "
            f"is write-once"))
    try:
        client.stat_object(bucket, WORM_CANARY_KEY, version_id=version)
    except S3Error as exc:
        if exc.code in _ABSENT:
            return _Proof(False, (
                f"a DELETE of {what} was answered with a retention refusal "
                f"({refusal}) and the version is gone anyway ({exc.code})"))
        return _Proof(False, (
            f"a DELETE of {what} was refused for retention ({refusal}), but "
            f"the version could not be read back to confirm it is still "
            f"there ({exc.code}: {exc.message})"), denied=exc.code == _DENIED,
            step=f"may not read a version back ({exc.code})")
    if unrecorded:
        return _Proof(False, (
            f"a DELETE of {what} was refused ({refusal}) and the version is "
            f"still there, but with no retention recorded on it the refusal "
            f"cannot be tied to COMPLIANCE, and a GOVERNANCE lock refuses a "
            f"plain DELETE too"))
    tidied, problem = _tidy_canaries(client, bucket, keep=version, now=now)
    after = ""
    if tidied:
        after += (f"; {tidied} canary version{'s' if tidied > 1 else ''} "
                  f"past {'their' if tidied > 1 else 'its'} lock removed")
    if problem:
        after += f"; older canary versions were not tidied ({problem})"
    return _Proof(True, (
        f"write-once PROVEN, not read from configuration: a DELETE of {what} "
        f"was refused ({refusal}) and the version is still there{after}"))


def prove_write_once(client, bucket: str, *, now: datetime | None = None,
                     clock: Callable[[], float] = time.monotonic
                     ) -> tuple[bool, str]:
    """Try to delete the canary's locked version; `(ok, evidence)`.

    `ok` is True only when the store REFUSED a DELETE naming the version
    id, the refusal is a retention refusal by `evidence.is_retention_refusal`
    (the one classifier the purge uses, so a policy denial counts here
    exactly as little as it counts on a tombstone), the version is still
    readable afterwards, and the store has not reported a mode other than
    COMPLIANCE on it (final review C10, 2026-09-23: GOVERNANCE refuses the
    same plain DELETE, and yields to a bypass). Every answer the store
    gives that is not that, a missing bucket included, is False with a
    sentence saying which it was. A store that cannot be reached at all
    raises, and the register reports it through `_guarded` as every other
    down service is reported. `client` is anything shaped like a minio
    client.
    """
    proof = _prove(client, bucket, now=now or datetime.now(timezone.utc),
                   deadline=clock() + _PROBE_BUDGET_S, clock=clock)
    return proof.ok, proof.evidence


def _prove_hold(client, bucket: str, *, writer: str,
                deleters: list[tuple[str, Callable[[], object]]],
                deadline: float, clock: Callable[[], float]) -> _Proof:
    """Prove a LEGAL HOLD holds (final review C9, 2026-09-23).

    The COMPLIANCE proof above says nothing about a hold: they are separate
    S3 headers, APIs and enforcement paths, and a store can refuse one
    delete and let the other through. A preserved sample has a hold and no
    retention, so the preservation check proves this too. The canary is
    written by `client`, the account rejections are preserved with, the way
    `PreservationStorage.preserve` writes (hold in the PUT, then read back
    as ON), so a pass also shows that account can do what a rejection
    needs. The DELETE goes to each of `deleters` in turn, `(variable,
    client factory)`, moving on only when one is refused on its own
    permissions, because the production preservation account may not
    delete by design. The budget is the caller's, shared with the proof
    above, so one check still has one budget.
    """
    def budgeted(factory: Callable[[], object]) -> Callable[[], object]:
        return lambda: _Budgeted(factory(), deadline, clock)

    try:
        return _prove_hold_steps(
            _Budgeted(client, deadline, clock), bucket, writer,
            [(label, budgeted(factory)) for label, factory in deleters])
    except _OutOfTime as exc:
        return _out_of_time(exc)


def _prove_hold_steps(client, bucket: str, writer: str,
                      deleters: list[tuple[str, Callable[[], object]]]
                      ) -> _Proof:
    import io

    from minio.error import S3Error

    from noctornal_api.evidence import is_retention_refusal

    def refused(what: str, exc: S3Error) -> _Proof:
        # The account rejected samples are written with may not do what
        # `preserve()` does, so every rejection is refused rather than
        # preserved. Proving the hold with another credential would hide
        # exactly that, so nothing else is tried.
        return _Proof(False, (
            f"{writer} may not {what} ({exc.code}: {exc.message}), and "
            f"rejected samples are preserved with that account, so every "
            f"rejection is refused rather than preserved"),
            cannot_preserve=True)

    def held(version: str) -> bool | _Proof:
        try:
            return client.is_object_legal_hold_enabled(
                bucket, HOLD_CANARY_KEY, version_id=version)
        except S3Error as exc:
            if exc.code == _DENIED:
                return refused("read a legal hold (s3:GetObjectLegalHold)", exc)
            return _Proof(False, (
                f"the store would not say whether hold canary "
                f"{HOLD_CANARY_KEY} version {version} is held ({exc.code}: "
                f"{exc.message})"))

    version = None
    try:
        stat = client.stat_object(bucket, HOLD_CANARY_KEY)
    except S3Error as exc:
        if exc.code == "NoSuchBucket":
            return _MISSING
        if exc.code == _DENIED:
            return refused("read this bucket", exc)
        if exc.code not in _ABSENT:
            return _Proof(False, (
                f"the store would not say whether the hold canary exists "
                f"({exc.code}: {exc.message})"))
    else:
        if stat.version_id:
            answer = held(stat.version_id)
            if isinstance(answer, _Proof):
                return answer
            if answer:
                version, how = stat.version_id, "reused"
    if version is None:
        # Absent, or its hold no longer reads ON (lifted by hand, or never
        # kept): a fresh held version, and the old one stays where it is.
        try:
            result = client.put_object(
                bucket, HOLD_CANARY_KEY, io.BytesIO(_HOLD_CANARY_BODY),
                len(_HOLD_CANARY_BODY), content_type="text/plain",
                legal_hold=True)
        except S3Error as exc:
            if exc.code == "NoSuchBucket":
                return _MISSING
            if exc.code == _DENIED and not is_retention_refusal(exc):
                return refused("write an object under a legal hold "
                               "(s3:PutObjectLegalHold)", exc)
            return _Proof(False, (
                f"the store refused to write a canary under a legal hold "
                f"({exc.code}: {exc.message}); on a bucket without object "
                f"lock that is the refusal to expect, and nothing preserved "
                f"in this bucket is held"))
        version = getattr(result, "version_id", None)
        if not version:
            return _Proof(False, (
                "the store accepted a canary under a legal hold and returned "
                "no version id, so the bucket is not versioned and no hold "
                "can be keeping it"))
        answer = held(version)
        if isinstance(answer, _Proof):
            return answer
        if not answer:
            return _Proof(False, (
                f"the store took hold canary {HOLD_CANARY_KEY} version "
                f"{version} under a legal hold and then reported no hold on "
                f"it; a rejected sample is written and read back the same "
                f"way, so every rejection is refused"))
        how = f"written by this probe with {writer}, as a rejected sample is"

    what = (f"hold canary {HOLD_CANARY_KEY} version {version} (legal hold ON "
            f"and no retention, {how})")
    passed_over: list[str] = []
    for label, make in deleters:
        try:
            make().remove_object(bucket, HOLD_CANARY_KEY, version_id=version)
        except S3Error as exc:
            if is_retention_refusal(exc):
                refusal, by = exc.code, label
                break
            if exc.code == _DENIED:
                passed_over.append(f"{label} may not delete a version "
                                   f"({exc.code})")
                continue
            return _Proof(False, (
                f"a DELETE of {what} with {label} was refused, but not for a "
                f"lock ({exc.code}: {exc.message}), so the refusal says "
                f"nothing about the hold"))
        else:
            return _Proof(False, (
                f"a DELETE of {what} with {label} SUCCEEDED: this store "
                f"accepts a legal hold and does not enforce it, so no "
                f"rejected sample preserved in this bucket is held"))
    else:
        return _Proof(False, (
            f"a DELETE of {what} was refused on the credentials' own "
            f"permissions ({'; '.join(passed_over)}) and no other credential "
            f"this process holds addresses that store, so the hold cannot be "
            f"proven from here"), denied=True, step="may not delete a version")
    try:
        client.stat_object(bucket, HOLD_CANARY_KEY, version_id=version)
    except S3Error as exc:
        if exc.code in _ABSENT:
            return _Proof(False, (
                f"a DELETE of {what} was answered with a lock refusal "
                f"({refusal}) and the version is gone anyway ({exc.code})"))
        return _Proof(False, (
            f"a DELETE of {what} was refused for a lock ({refusal}), but the "
            f"version could not be read back to confirm it is still there "
            f"({exc.code}: {exc.message})"))
    around = (f"; {', '.join(passed_over)}, so the DELETE was made with {by}"
              if passed_over else "")
    return _Proof(True, (
        f"legal hold PROVEN: a DELETE of {what} with {by} was refused "
        f"({refusal}) and the version is still there{around}"))


def _first_env(*names: str) -> tuple[str, str]:
    """`(name, value)` of the first variable that is set and not empty, or
    `("", "")`. The rule `samples.PreservationStorage` applies to its
    fallbacks, kept identical so the probe reaches the store rejections are
    written to. The name travels into the evidence so a fallback says so."""
    for name in names:
        value = os.environ.get(name)
        if value:
            return name, value
    return "", ""


@dataclass(frozen=True)
class PreservationSettings:
    """Where rejected samples are preserved, resolved exactly as
    `samples.PreservationStorage.__init__` resolves it (group g04, 2026-09-22).

    One reader per fact would have this module ASK that class; it cannot
    yet, because the class builds its client in its constructor with the
    library's five-minute timeouts. So the rule is copied once, here, and
    `test_readiness_worm_probe` holds the copy to the class whenever the
    class is importable. Until 2026-09-22 this copy fell back to
    MINIO_SECURE for TLS where the store falls back to false, so the probe
    could pass over TLS while rejections connected in plain text (verifier).
    Each field is `(variable, value)` so the evidence can name a fallback.
    """
    endpoint: tuple[str, str]
    access: tuple[str, str]
    secret: tuple[str, str]
    secure: bool
    bucket: str


def preservation_store_settings() -> PreservationSettings:
    secure = _first_env("PRESERVE_SECURE", "SAMPLE_SECURE")[1] or "false"
    return PreservationSettings(
        endpoint=_first_env("PRESERVE_ENDPOINT", "SAMPLE_ENDPOINT",
                            "MINIO_ENDPOINT"),
        access=_first_env("PRESERVE_ACCESS_KEY", "SAMPLE_ACCESS_KEY",
                          "MINIO_ACCESS_KEY"),
        secret=_first_env("PRESERVE_SECRET_KEY", "SAMPLE_SECRET_KEY",
                          "MINIO_SECRET_KEY"),
        secure=secure.lower() == "true",
        bucket=os.environ.get(PRESERVE_BUCKET_ENV) or PRESERVE_BUCKET_DEFAULT)


def _config_gap(name: str, bucket: str, endpoint: tuple[str, str],
                access: tuple[str, str], secret: tuple[str, str],
                wanted: tuple[str, ...], action: str) -> Check | None:
    """The failed Check for a store this process cannot even address, or
    None. `wanted` names the variables an operator would set (endpoint,
    access key, secret key), each with its fallbacks."""
    if not endpoint[1].strip():
        return Check(name, False,
                     f"{wanted[0]} is not set: the store cannot be reached, so "
                     f"nothing can be written to {bucket}", action)
    missing = [w for w, (_, v) in zip(wanted[1:], (access, secret), strict=True)
               if not v]
    if missing:
        return Check(name, False,
                     f"{endpoint[0]}={endpoint[1].strip()} but "
                     f"{' and '.join(missing)} not set", action)
    return None


def _evidence_bucket_object_lock(conn: psycopg.Connection) -> Check:
    """The WORM guarantee `EvidenceStorage.put` relies on, proven by the
    store refusing to destroy a locked version (see the block above), read
    through the same variables `EvidenceStorage` constructs from."""
    name = "evidence_bucket_object_lock"
    bucket = os.environ.get("EVIDENCE_BUCKET", "noctornal-evidence")
    endpoint = _first_env("MINIO_ENDPOINT")
    access, secret = _first_env("MINIO_ACCESS_KEY"), _first_env("MINIO_SECRET_KEY")
    action = (
        "set MINIO_ENDPOINT / MINIO_ACCESS_KEY / MINIO_SECRET_KEY, and create "
        "the evidence bucket WITH object lock (`mc mb --with-lock`) on a store "
        "that enforces it; lock cannot be switched on for a bucket that "
        "already exists, so an unlocked bucket has to be replaced, and a store "
        "that accepts a lock and deletes anyway has to be replaced (docs/16 "
        "C2, docs/17 F24)")
    gap = _config_gap(name, bucket, endpoint, access, secret,
                      ("MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY"),
                      action)
    if gap:
        return gap
    where = f"bucket {bucket} at {endpoint[1].strip()}"
    client = _object_store_client(
        endpoint[1].strip(), access[1], secret[1],
        os.environ.get("MINIO_SECURE", "false").lower() == "true")
    proof = _prove(client, bucket, now=datetime.now(timezone.utc),
                   deadline=time.monotonic() + _PROBE_BUDGET_S,
                   clock=time.monotonic)
    evidence = proof.evidence
    if proof.denied:
        evidence += (". The API writes and purges exhibits with these same "
                     "credentials, so they need that permission anyway")
    return Check(name, proof.ok, f"{where}: {evidence}",
                 "" if proof.ok else action)


def _preservation_bucket_object_lock(conn: psycopg.Connection) -> Check:
    """docs/17 F2: rejected samples are preserved under a legal hold in
    their own bucket, and a hold on a store that does not enforce it
    preserves nothing. Two proofs, and both must pass: the evidence
    bucket's COMPLIANCE proof, and a LEGAL HOLD proof (`_prove_hold`),
    because the hold is what a preserved sample actually carries. Until
    the final review (C9, 2026-09-23) only the first ran, and this
    docstring said it proved the hold: a store that enforced a retention
    and merely recorded a hold passed, while every held sample could be
    deleted by version.

    The store is addressed exactly as `samples.PreservationStorage`
    addresses it (`preservation_store_settings`), and the evidence names
    the variable that supplied each credential so a fallback in production
    is visible. When the deployment declared `destroy`, nothing is
    preserved and the bucket is not probed; an unrecognised disposition
    fails here, because every rejection is refused until it is fixed.

    ## The preservation account may not delete, by design

    infra/production/compose.yml mints PRESERVE_ACCESS_KEY with a policy
    that can write, read and set a hold, and nothing that deletes or sets a
    retention. That is the right account for rejections and the wrong one
    for this proof: its refusal is `AccessDenied` whatever the store would
    have done. So when the preservation account is refused on its own
    permissions, and the MINIO_* credentials address the SAME endpoint, the
    proof is made with those instead (in the shipped topology they are the
    store's root, which may delete anything a lock does not stop), and the
    evidence says so. Where no credential here may delete on that store,
    the check fails and says the proof cannot be made from this process,
    rather than passing on a refusal that proves nothing.

    The one refusal that does NOT go to the second credential is the first
    step's: an account that may not even read the bucket is not the
    least-privilege preservation account, it is one whose policy does not
    reach this bucket at all (the SAMPLE_* fallback, as the production
    compose mints it). `PreservationStorage` writes with that account and
    reads each held version back, so every rejection is refused, and a
    green row proven with some other credential would hide exactly that.
    The hold proof holds the same line for the two steps `preserve()`
    itself takes, a held PUT and reading the hold back: those are always
    the preservation account's, and only its DELETE may move to MINIO_*.
    """
    name = "preservation_bucket_object_lock"
    disposition, raw = rejected_sample_disposition()
    action = (
        f"set {PRESERVE_BUCKET_ENV} and PRESERVE_ENDPOINT / PRESERVE_ACCESS_KEY / "
        f"PRESERVE_SECRET_KEY (a production deployment gives the preservation "
        f"store its own credentials), and create the bucket WITH object lock "
        f"on a store that enforces it (docs/17 F2, docs/16 C2)")
    if disposition is None:
        return Check(
            name, False,
            f"{DISPOSITION_ENV}={raw.strip()!r} is neither preserve nor destroy; "
            f"every rejection is refused until it is corrected",
            f"set {DISPOSITION_ENV} to preserve (the default) or destroy, as the "
            f"prohibited-content policy decides (docs/16 L1), and restart")
    # F13: a HELD sample that matches a screening list is always
    # preserved, whatever the disposition, so while a list is active the
    # bucket is probed under destroy too.
    if disposition == "destroy" and not _screening_active(conn):
        return Check(
            name, True,
            f"not probed: {DISPOSITION_ENV}=destroy, so a rejected sample is "
            f"destroyed and nothing is preserved. That is the deployment's "
            f"declared choice (docs/16 L1), which this register records and "
            f"cannot verify")
    s = preservation_store_settings()
    gap = _config_gap(
        name, s.bucket, s.endpoint, s.access, s.secret,
        tuple(f"{p} (or {q}, {m})" for p, q, m in (
            ("PRESERVE_ENDPOINT", "SAMPLE_ENDPOINT", "MINIO_ENDPOINT"),
            ("PRESERVE_ACCESS_KEY", "SAMPLE_ACCESS_KEY", "MINIO_ACCESS_KEY"),
            ("PRESERVE_SECRET_KEY", "SAMPLE_SECRET_KEY", "MINIO_SECRET_KEY"))),
        action)
    if gap:
        return gap
    fallback = [n for n in (s.endpoint[0], s.access[0], s.secret[0])
                if not n.startswith("PRESERVE_")]
    note = (f"; endpoint and credentials from "
            f"{', '.join(dict.fromkeys(fallback))} (fallback, meant for a "
            f"single-node development stack)" if fallback else "")
    where = f"bucket {s.bucket} at {s.endpoint[1]}"
    now = datetime.now(timezone.utc)
    deadline = time.monotonic() + _PROBE_BUDGET_S
    reach = (
        "give the preservation store its own account (PRESERVE_ACCESS_KEY / "
        "PRESERVE_SECRET_KEY) with a policy that reaches this bucket and may "
        "set and read a hold, as infra/production/compose.yml mints it "
        "(docs/17 F2)")
    elsewhere = (
        "run the preservation bucket on the MINIO_ENDPOINT store, whose "
        "credentials the proof can use, or prove its object lock out of "
        "band and record how (docs/16 C2)")
    own_client = _object_store_client(s.endpoint[1], s.access[1], s.secret[1],
                                      s.secure)
    m_endpoint = os.environ.get("MINIO_ENDPOINT", "").strip()
    m_access = os.environ.get("MINIO_ACCESS_KEY", "")
    m_secret = os.environ.get("MINIO_SECRET_KEY", "")
    #: The one other credential that may make a DELETE here: MINIO_* on the
    #: SAME endpoint, and only when it is a different account. Built once,
    #: and only if a proof needs it.
    other = bool(m_endpoint and m_access and m_secret
                 and m_endpoint == s.endpoint[1].strip()
                 and m_access != s.access[1])
    built: list = []

    def minio_client():
        if not built:
            built.append(_object_store_client(
                m_endpoint, m_access, m_secret,
                os.environ.get("MINIO_SECURE", "false").lower() == "true"))
        return built[0]

    proof = _prove(own_client, s.bucket, now=now, deadline=deadline,
                   clock=time.monotonic)
    retention = proof.evidence
    if proof.denied:
        own = f"{s.access[0]} {proof.step}"
        if proof.unreadable:
            return Check(
                name, False,
                f"{where}: {own}, so the account rejected samples are "
                f"preserved with cannot reach this bucket and every rejection "
                f"is refused rather than preserved{note}", reach)
        if not other:
            return Check(
                name, False,
                f"{where}: {own}, and no other credential this process holds "
                f"addresses that store, so write-once cannot be proven from "
                f"here{note}", elsewhere)
        second = _prove(minio_client(), s.bucket, now=now, deadline=deadline,
                        clock=time.monotonic)
        retention = (f"{own}, as its policy intends, so the proof was made "
                     f"with MINIO_ACCESS_KEY on the same store: "
                     f"{second.evidence}")
        if not second.ok:
            return Check(name, False, f"{where}: {retention}{note}", action)
    elif not proof.ok:
        return Check(name, False, f"{where}: {retention}{note}", action)

    deleters = [(s.access[0], lambda: own_client)]
    if other:
        deleters.append(("MINIO_ACCESS_KEY", minio_client))
    hold = _prove_hold(own_client, s.bucket, writer=s.access[0],
                       deleters=deleters, deadline=deadline,
                       clock=time.monotonic)
    if hold.ok:
        return Check(name, True, f"{where}: {retention}; {hold.evidence}{note}")
    return Check(
        name, False,
        f"{where}: {hold.evidence}. The COMPLIANCE retention proof on this "
        f"bucket passed, and a retention says nothing about a hold{note}",
        reach if hold.cannot_preserve else elsewhere if hold.denied else action)


def _evidence_size_cap_declared(conn: psycopg.Connection) -> Check:
    """Is the exhibit size cap a decision or a default -- and is the value
    this process ENFORCES the one the environment now says?

    Two facts, because either can be wrong on its own. The declaration
    (docs/08): every accepted exhibit byte is locked under COMPLIANCE for
    the retention period, so a cap left at the 256 MiB default is a
    permanent commitment nobody here decided. And the enforced value: the
    routers read the declaration ONCE, at import, so an operator who edits
    the variable and does not restart has a register that would otherwise
    report a cap the process is not applying. The check reads the routers'
    own constants and says "restart" when they and the environment differ.

    Both caps are read through `config`, the reader the routers use, for
    the reason `_totp_kek_set` gives at length. Not blocking: an exhibit
    accepted under the default is expensive, not unlawful.
    """
    from noctornal_api import samples
    from noctornal_api.config import (
        SAMPLE_CAP_ENV,
        cap_is_declared,
        cap_problem,
        declared_cap,
    )
    from noctornal_api.http.routers import evidence as evidence_router

    name = "evidence_size_cap_declared"
    action = (
        f"declare {EVIDENCE_CAP_ENV} (bytes, or 512MiB) in the API's "
        f"environment and restart it; every accepted exhibit byte is locked "
        f"under COMPLIANCE for the retention period (docs/08)")

    def mib(n: int) -> str:
        return f"{n / (1 << 20):g} MiB"

    enforced = (f"this process accepts exhibits up to "
                f"{mib(evidence_router.MAX_EVIDENCE_BYTES)} and samples up to "
                f"{mib(samples.MAX_SAMPLE_BYTES)}")
    for env_name, in_force in ((EVIDENCE_CAP_ENV, evidence_router.MAX_EVIDENCE_BYTES),
                               (SAMPLE_CAP_ENV, samples.MAX_SAMPLE_BYTES)):
        problem = cap_problem(env_name)
        if problem:
            return Check(name, False, f"{problem}; {enforced}", action)
        if declared_cap(env_name) != in_force:
            return Check(
                name, False,
                f"{env_name} now reads {mib(declared_cap(env_name))} but this "
                f"process started with {mib(in_force)} and enforces that; "
                f"restart it", action)
    if not cap_is_declared(EVIDENCE_CAP_ENV):
        return Check(name, False,
                     f"{EVIDENCE_CAP_ENV} is unset: {enforced}, the default, "
                     f"which nobody in this deployment decided", action)
    evidence = f"{EVIDENCE_CAP_ENV} declared; {enforced}"
    if not cap_is_declared(SAMPLE_CAP_ENV):
        evidence += f" ({SAMPLE_CAP_ENV} unset, default)"
    return Check(name, True, evidence)


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
            "layout right (this check locates the scripts relative to the "
            "package)")

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
    # F8 A7 (2026-09-24). Email leaves only through the egress route
    # "smtp" (docs/00 decision 68); a route that is missing or does not allow the
    # relay HOLDS every email, so this row says so rather than the drain.
    from noctornal_api import transports
    state = transports.route_state(transports.SMTP, conn)
    if not state.ok:
        return Check(
            "smtp_configured", False,
            f"SMTP_HOST={host}:{port}, and email is held: {state.why}",
            f"add {host}:{port} to the smtp route in Administration, Egress, or "
            f"fix SMTP_HOST")
    return Check("smtp_configured", True,
                 f"SMTP_HOST={host}:{port}; TLS required; "
                 f"{transports.route_line(state)}")


# The compartment registry and the records written under older rules
# (docs/00 decision 71, L1 and L2, 2026-09-24). Counts and column labels only: the
# register's reader holds user.manage, not case content.

def _labels(items: list[str]) -> str:
    return ", ".join(items)


def _compartment_bindings_intact(conn: psycopg.Connection) -> Check:
    """Every bound column this release knows has a readable, enabled
    binding in the database, and the database binds nothing this release
    does not know (docs/00 decision 71, 2026-09-24).

    `iam.compartment_in_use` reads the bindings from the catalog and
    refuses while any cannot be read, and `compartment_lifecycle`'s rename
    and retire move and count the columns it lists; the two are held to
    one set by test, and this watches them at runtime, which is how a
    trigger dropped or disabled by hand in psql is noticed. One reader per
    fact: `iam.compartment_bindings()` is the registry's own reading."""
    from noctornal_api.compartment_lifecycle import BOUND_COLUMNS
    rows = conn.execute(
        """SELECT schema_name, table_name, column_name, kind, enabled,
                  problem FROM iam.compartment_bindings()""").fetchall()
    broken = [(f"{s}.{t}", p) for s, t, _c, _k, _e, p in rows
              if p is not None]
    formed = {(s, t, c, k) for s, t, c, k, _e, p in rows if p is None}
    disabled = sorted(f"{s}.{t}.{c}" for s, t, c, _k, e, p in rows
                      if p is None and not e)
    known = set(BOUND_COLUMNS)
    missing = sorted(f"{s}.{t}.{c}" for s, t, c, _k in known - formed)
    unknown = sorted(f"{s}.{t}.{c}" for s, t, c, _k in formed - known)
    if not (broken or disabled or missing or unknown):
        n = len(formed)
        return Check("compartment_bindings_intact", True,
                     f"{count_of(n, 'compartment column is', 'compartment columns are')} "
                     f"bound to the registry, as this release expects.")
    said = []
    if missing:
        k = len(missing)
        said.append(
            f"{count_of(k, 'column this release binds has', 'columns this release binds have')} "
            f"no binding in the database ({_labels(missing)}), so an "
            f"unregistered key can be written into "
            f"{agree(k, 'it', 'them')} and a key "
            f"{agree(k, 'it carries', 'they carry')} can be dropped.")
    if unknown:
        j = len(unknown)
        said.append(
            f"{count_of(j, 'column is', 'columns are')} bound in the "
            f"database and unknown to this release ({_labels(unknown)}): "
            f"renaming a key {agree(j, 'it carries', 'they carry')} is "
            f"refused until the release knows {agree(j, 'it', 'them')}.")
    if disabled:
        said.append(
            f"The binding on {_labels(disabled)} "
            f"{agree(len(disabled), 'is', 'are')} disabled, so an "
            f"unregistered key can be written there.")
    for table, problem in broken:
        said.append(
            f"The binding on {table} cannot be read ({problem}), so no "
            f"compartment can be renamed or retired.")
    return Check(
        "compartment_bindings_intact", False, " ".join(said),
        "run alembic upgrade head; if the database is already at head, "
        "recreate each named binding as the migration that added it did, "
        "and rename or retire no compartment until this passes")


def _captured_documents_compartmented(conn: psycopg.Connection) -> Check:
    """Captured documents a compartmented case cites that carry no
    compartment (L1, 2026-09-24): the captures 0071 could not label,
    because no lock fits every case that cites them. And captures that
    carry a compartment an ingest feed now uses for victim data. Always
    passes: nothing here is refused, and the caveat keeps it in view."""
    from noctornal_api.legacy_records import (
        unlabelled_captures_count,
        victim_data_captures_count,
    )
    n = unlabelled_captures_count(conn)
    v = victim_data_captures_count(conn)
    if n:
        evidence = (f"{count_of(n, 'captured document', 'captured documents')} "
                    f"that a compartmented case cites "
                    f"{agree(n, 'carries', 'carry')} no compartment.")
    else:
        evidence = ("Every captured document a compartmented case cites "
                    "carries a compartment.")
    caveats = []
    if n:
        caveats.append(
            f"{agree(n, 'It was', 'They were')} captured before this release "
            f"into cases with no compartment in common, so no lock fits every "
            f"case that cites {agree(n, 'it', 'them')}, and "
            f"{agree(n, 'it is', 'they are')} listed in the collection to "
            f"every reader at {agree(n, 'its', 'their')} TLP. python "
            f"scripts/legacy_records.py --section captures lists "
            f"{agree(n, 'it', 'them')}.")
    if v:
        caveats.append(
            f"{count_of(v, 'captured document carries', 'captured documents carry')} "
            f"a compartment an ingest feed now uses to wall off third-party "
            f"personal data, so {agree(v, 'its', 'their')} text is in the "
            f"collection's free-text index. python scripts/legacy_records.py "
            f"--section victim-captures lists {agree(v, 'it', 'them')}.")
    return Check("captured_documents_compartmented", True, evidence,
                 caveat=" ".join(caveats))


def _triage_claims_within_labels(conn: psycopg.Connection) -> Check:
    """ATTRIBUTE claims accepted from Triage before Alpha 6 that the accept
    would now refuse (L2, 2026-09-24): readable below the label of what
    they were found in, or attached to an entity in another case. Listed,
    never moved: a claim's own columns are not written again (invariant 5),
    and no verb raises an existing entity's label."""
    from noctornal_api.legacy_records import claim_counts
    counts = claim_counts(conn)
    n, k = counts["underlabelled"], counts["underlabelled_cases"]
    m, shut = counts["other_case"], counts["closed"]
    if not n and not m:
        return Check("triage_claims_within_labels", True,
                     "No claim accepted from Triage is readable below the "
                     "label of what it was found in.")
    parts = []
    if n:
        parts.append(
            f"{count_of(n, 'claim', 'claims')} accepted from Triage before "
            f"Alpha 6 {agree(n, 'is', 'are')} readable below the label of "
            f"what {agree(n, 'it was', 'they were')} found in, in "
            f"{count_of(k, 'case', 'cases')}")
    if m:
        parts.append(
            f"{count_of(m, 'claim was', 'claims were')} attached to an "
            f"entity in another case")
    evidence = ", and ".join(parts) + ". Nothing moves them automatically."
    if shut:
        evidence += (f" {count_of(shut, 'of them is', 'of them are')} in a "
                     f"closed case, which must be reopened to retract "
                     f"{agree(shut, 'it', 'them')}.")
    return Check(
        "triage_claims_within_labels", False, evidence,
        "run python scripts/legacy_records.py --section underlabelled on the "
        "server and give each case's analysts its rows to retract")


def _triage_claims_dated(conn: psycopg.Connection) -> Check:
    """Claims accepted from Triage before Alpha 6 that cite a document and
    carry no observation date (L2, 2026-09-24). Always passes: a missing
    date shortens First seen and Last seen and harms nothing else, and the
    fill waits on the owner's decision about invariant 5."""
    from noctornal_api.legacy_records import undated_count
    n = undated_count(conn)
    if not n:
        return Check("triage_claims_dated", True,
                     "Every claim accepted from Triage that cites a document "
                     "carries its date.")
    return Check(
        "triage_claims_dated", True,
        f"{count_of(n, 'claim', 'claims')} accepted from Triage before "
        f"Alpha 6 {agree(n, 'has', 'have')} no observation date.",
        caveat=(f"First seen and Last seen ignore {agree(n, 'it', 'them')}. "
                f"python scripts/legacy_records.py --section undated lists "
                f"{agree(n, 'it', 'them')} with the date each document "
                f"gives; an analyst adds a dated claim where it matters."))
# The network boundary (docs/20 section 6.4 and docs/00 decision 68,
# 2026-09-24). Its PROXY branch is the route provider's own verdict, so the
# egress proxy fills it without a line here.
_EGRESS_DEV_CAVEAT = (
    "The network boundary is not in force: outbound traffic leaves from this "
    "host's own address. That is acceptable in development only.")


def _joined(sentences: list[str]) -> str:
    if len(sentences) <= 1:
        return "".join(sentences)
    return ", ".join(sentences[:-1]) + " and " + sentences[-1]


def _egress_boundary(conn: psycopg.Connection) -> Check:
    """Whether outbound connections leave through the egress proxy.

    Not blocking, and with no consequence entry: the failure is reversible
    configuration and is refused where it matters, at route_for, by name
    (the reasoning `sys_admin_present` gives for itself). Uses are stated,
    never named: a readiness report is not the place a source's name or a
    relay's host is shown to whoever can read it. The collection use is a
    presence rather than a count, because a count would tell an
    administrator below a source's label that the source exists
    (2026-09-24)."""
    from noctornal_api import egress
    from noctornal_api.egress_policy import DECISION_REF

    name = "egress_boundary"
    problem = egress.proxy_problem()
    if problem is not None:
        return Check(name, False, problem,
                     f"set {egress.PROXY_URL_ENV} to http://HOST:PORT, or unset it")
    settings = egress.proxy_settings()
    try:
        provider = egress._route_provider()
    except egress.RouteUnavailable as exc:
        # A provider module that does not load or does not match refuses
        # every route, with or without a proxy, so the row cannot say that
        # connections are being made directly.
        return Check(name, False, str(exc),
                     "install a build whose egress route provider matches this one")
    if settings is not None:
        if provider is None:
            return Check(
                name, False,
                f"{egress.PROXY_URL_ENV} is set and no egress route provider is "
                f"loaded, so every outbound connection that asks for a route is "
                f"refused.",
                f"Check that noctornal_api.egress_routes imports (the API log says "
                f"why it did not), or unset {egress.PROXY_URL_ENV}.")
        verdict = provider.boundary_probe(conn, settings)
        # A failed row always says what to do (the register's own rule); a
        # provider verdict that names no action still gets one.
        return Check(name, bool(verdict.ok), verdict.evidence,
                     "" if verdict.ok else (
                         verdict.action or "Check the egress proxy and its routes."),
                     caveat=(verdict.caveat or "") if verdict.ok else "")
    uses = egress.outbound_uses(conn)
    if not egress._production():
        evidence = ("No egress proxy is configured: outbound connections are made "
                    "directly by this process under the in-process policy "
                    "(egress_policy.py). ")
        evidence += (f"Configured: {_joined(uses)}." if uses else
                     "No collection source is polled and no outbound integration "
                     "is configured.")
        return Check(name, True, evidence, caveat=_EGRESS_DEV_CAVEAT)
    if not uses:
        return Check(name, True,
                     "No collection source is polled, no outbound integration is "
                     "configured, and no egress proxy is.")
    return Check(
        name, False,
        f"No egress proxy is configured, and {_joined(uses)}: each of those "
        f"connections leaves from this host's own address, with no network "
        f"boundary in force ({DECISION_REF}).",
        f"Run the egress proxy and set {egress.PROXY_URL_ENV}.")
# The egress proxy (S2, 2026-09-24). Two rows beside egress_boundary,
# whose PROXY branch is the route provider's own probe.
# Neither is blocking: each failure is refused where it matters, at
# route_for and at the proxy, and none becomes irreversible once material
# arrives, the bar BLOCKING_CHECKS states. Both state presence or counts of
# configuration, never a source's name or a count of sources.
def _egress_routes_cover_sources(conn: psycopg.Connection) -> Check:
    """Whether every outbound use has a route to leave through: feeds a
    passive default, persona and persona-less sources a profile that can
    carry them, and each configured integration its route."""
    from noctornal_api import egress_routes
    ok, evidence, action, caveat = egress_routes.cover_sources(conn)
    return Check("egress_routes_cover_sources", ok, evidence, action, caveat=caveat)


def _egress_exits_open(conn: psycopg.Connection) -> Check:
    """Whether the egress proxy holds the key every sealed exit is sealed
    under and can open each one (the probe route's headers)."""
    from noctornal_api import egress_routes
    ok, evidence, action, caveat = egress_routes.exits_open(conn)
    return Check("egress_exits_open", ok, evidence, action, caveat=caveat)
# F1 roles (CONCOR), 2026-09-24. This row fails when role analysis runs
# without its BLAS cap: numpy's OpenBLAS starts a thread per core, and four
# worker processes each running a worst case took about
# 50 s apiece uncapped against 6 s capped. threadpoolctl is not pinned, so
# `blockmodel` caps through it when installed and otherwise through the
# OpenBLAS numpy bundles; on a numpy with neither (Apple's Accelerate) the
# cap does nothing, and this row says so instead of the analysis slowing
# every worker unexplained.
def _role_analysis_thread_capped(conn: psycopg.Connection) -> Check:
    """Reads the cap back from `blockmodel`, which took it on import. Never
    blocking: an uncapped BLAS is slow, not unsafe."""
    from noctornal_api import blockmodel
    capped, evidence = blockmodel.blas_cap_report()
    if capped:
        return Check("role_analysis_thread_capped", True, evidence)
    return Check(
        "role_analysis_thread_capped", False, evidence,
        "install threadpoolctl==3.7.0 with -c constraints.txt, or run on a "
        "numpy build that bundles OpenBLAS (the Linux and Windows wheels do), "
        "and restart the API")
# The two-person policy (F9, 2026-09-24).
def _dual_control_policy_changeable(conn: psycopg.Connection) -> Check:
    """Whether two DIFFERENT people could change which operations need two
    people: an active account that may propose a change, and an active
    account that may countersign one without also being able to propose
    it. An account holding both roles is one person and is never the
    second one (2026-09-24), so the first-run account,
    which holds SYS_ADMIN and SECURITY_OFFICER, cannot countersign what it
    or anyone else proposes.

    Informative, not blocking, with no CONSEQUENCES entry: a policy nobody
    can change is frozen in the safe direction, every operation keeping the
    requirement it has. `dual_control.signers` is the one reader."""
    from noctornal_api.dual_control import (
        DualControlPolicyService,
        readiness_evidence,
    )

    signers = DualControlPolicyService(conn).signers()
    evidence = readiness_evidence(signers)
    if signers["distinct_pair"]:
        return Check("dual_control_policy_changeable", True,
                     evidence + ", so two different people can change which "
                     "operations need two people")
    return Check(
        "dual_control_policy_changeable", False, evidence,
        "grant SECURITY_OFFICER to an active account that is not an "
        "administrator, in the console under Admin, Accounts (Grant role). "
        "An account holding SYS_ADMIN proposes changes and never "
        "countersigns them, so the first-run account, which holds both, "
        "cannot be the second person. Until then nobody can change which "
        "operations need two people, which is the safe direction: every "
        "operation keeps the requirement it has. Over the API: POST "
        "/admin/users/{user_id}/roles")
# Comms (F10a and F10c, 2026-09-24). Neither is blocking and neither
# has a console target: both are settled by configuration and a restart.
def _pgp_verifier(conn: psycopg.Connection) -> Check:
    """Whether a signature check made now could produce a verdict. With no
    gpg, or one below the version floor (pgp.MIN_GPG_VERSIONS), every
    check records NO_VERIFIER and no binding can be confirmed, and nothing
    said so: the production image carried gpgv, not gpg."""
    from noctornal_api import pgp
    usable, evidence = pgp.verifier_status()
    if usable:
        return Check("pgp_verifier", True, evidence)
    return Check(
        "pgp_verifier", False, evidence[:1].upper() + evidence[1:],
        "install GnuPG 2.4.9 or later (or 2.5.14 or later) or set NOCTORNAL_GPG "
        "to its full path; for a distribution build that carries those fixes "
        f"under an older version number, set {pgp.PATCHED_AS_ENV} to the "
        "upstream release it matches; then restart")


def _pgp_key_directory(conn: psycopg.Connection) -> Check:
    """Web Key Directory lookups: off (a pass), on (a pass with the
    exposure said out loud), or half configured (a fail naming the fix).
    Whether the network boundary is in force is egress_boundary's row."""
    from noctornal_api import pgp_keys
    ceiling = os.environ.get(pgp_keys.WKD_CEILING_ENV, "").strip()
    policy = pgp_keys.directory_policy(conn)
    if policy.enabled:
        domains = ", ".join(d for d, _m in policy.directories)
        return Check(
            "pgp_key_directory", True,
            f"on, at most TLP:{policy.ceiling}, through the integration route "
            f"wkd. Through the egress proxy only a URL whose host resolves can "
            f"work, so a directory that uses the direct method is listed as "
            f"<domain>:443 alone",
            caveat=(f"Lookups go to {domains}, each approved by a second person. "
                    f"Each directory's operator sees which address was looked "
                    f"up, when, and from which address the request came."))
    if not ceiling and policy.problem == pgp_keys.OFF_PROBLEM:
        try:
            pgp_keys._wkd_route(conn)
        except Exception:  # noqa: BLE001 - no route at all is the off state
            return Check("pgp_key_directory", True,
                         "off: vendor keys come from a file or a paste, and "
                         "nothing is fetched")
        return Check(
            "pgp_key_directory", False,
            "the integration route wkd exists and NOCTORNAL_WKD_CEILING is not "
            "set, so lookups are off with a route standing ready",
            "set NOCTORNAL_WKD_CEILING to CLEAR, GREEN or AMBER, or retire the "
            "route, and restart")
    if policy.problem == pgp_keys.NO_ROUTE or (
            policy.problem or "").startswith(pgp_keys.NO_ROUTE):
        action = ("create the integration route named wkd under "
                  "Administration, listing openpgpkey.<domain>:443 for the "
                  "advanced method or <domain>:443 for the direct one (a "
                  "directory that uses the direct method is listed as "
                  "<domain>:443 alone), or unset NOCTORNAL_WKD_CEILING")
    elif policy.problem == pgp_keys.BAD_CEILING:
        action = "set NOCTORNAL_WKD_CEILING to CLEAR, GREEN or AMBER, and restart"
    elif policy.problem == pgp_keys.NO_GPG:
        action = ("install a gpg the pgp_verifier row accepts, or unset "
                  "NOCTORNAL_WKD_CEILING, and restart")
    else:
        action = ("list each directory on the integration route wkd by name, "
                  "as openpgpkey.<domain>:443 or <domain>:443, under "
                  "Administration")
    return Check("pgp_key_directory", False, policy.problem or "lookups are off",
                 action)


# F11 and F12 (2026-09-24). Not blocking; no console target: both are
# settled by configuration and by scheduling scripts/lab_triage.py.

#: How long the oldest queued run may wait, with nothing finishing, before
#: the register says nothing is draining the queue. Five cron passes.
_TRIAGE_STALE_MINUTES = 60


def _sample_static_analysis(conn: psycopg.Connection) -> Check:
    """Whether static triage can run here, under which limits, and whether
    anything is draining its queue (F11 N).

    Fails on a settings problem, on a child that will not start or whose
    selftest fails, and when the oldest queued run has waited an hour with
    no run finishing in that hour ("nothing is running static triage"); a
    large backfill that is draining does not fail it. Passes with a caveat
    for what the child can still reach (lab_static's docstring), for
    platforms that cannot bound its memory, and when YARA is not
    installed."""
    from urllib.parse import urlsplit

    from noctornal_api import fuzzyhash, lab_static, lab_triage
    from noctornal_api.yara_rules import engine_version
    name = "sample_static_analysis"
    settings, problem = lab_triage.analysis_settings()
    if problem:
        return Check(name, False, problem,
                     "correct the setting it names and restart")
    dsn = urlsplit(os.environ.get("DATABASE_URL", "").replace("+psycopg", ""))
    try:
        probe = {"host": dsn.hostname, "port": dsn.port or 5432} \
            if dsn.hostname else {}
    except ValueError:
        probe = {}
    try:
        out = lab_triage.selftest(settings, probe=probe)
    except RuntimeError as exc:
        return Check(name, False, f"the analysis child failed its selftest: {exc}",
                     "check that this server's Python can run "
                     "python -m noctornal_api.lab_static, and its log")
    caps = out.get("capabilities") or {}
    kind = caps.get("limits") or lab_static.limits_kind()
    leaked = [k for k in out.get("environment_keys") or []
              if k.startswith(("NOCTORNAL_", "DATABASE", "MINIO_", "SAMPLE_",
                               "PRESERVE_", "REDIS", "SMTP_"))]
    if leaked:
        return Check(name, False,
                     f"the analysis child was started with "
                     f"{count_of(len(leaked), 'secret setting', 'secret settings')} "
                     f"in its environment",
                     "report this: the child's environment must hold no "
                     "credential")
    depth, oldest, last_done = conn.execute(
        """SELECT count(*) FILTER (WHERE status = 'QUEUED'),
                  min(queued_at) FILTER (WHERE status = 'QUEUED'),
                  max(finished_at) FILTER (WHERE status = 'DONE')
             FROM lab.static_run""").fetchone()
    def fmt(t) -> str:
        return (t.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                if t else "never")
    yara = engine_version()
    evidence = (
        f"pefile {caps.get('pefile') or 'not installed'}; {fuzzyhash.TLSH_IMPLEMENTATION}; "
        f"{fuzzyhash.SSDEEP_IMPLEMENTATION}; yara-x {yara or 'not installed'}. "
        f"Limits: {lab_static.LIMITS_WORDS[kind]}. Analysis maximum "
        f"{settings.max_bytes // (1 << 20)} MiB, fuzzy hashing up to "
        f"{settings.fuzzy_max_bytes // (1 << 20)} MiB, "
        f"{settings.timeout_s} seconds per step. Queue: "
        f"{count_of(depth, 'run', 'runs')} waiting"
        + (f", the oldest since {fmt(oldest)}" if oldest else "")
        + f"; last finished run {fmt(last_done)}.")
    now = datetime.now(timezone.utc)
    stale = timedelta(minutes=_TRIAGE_STALE_MINUTES)
    if depth and oldest and now - oldest > stale and (
            last_done is None or now - last_done > stale):
        return Check(name, False, evidence,
                     "nothing is running static triage; schedule "
                     "scripts/lab_triage.py (docs/11)")
    caveats = []
    exposure = out.get("exposure") or {}
    reach = []
    if exposure.get("proc_environ_readable"):
        reach.append("read the environment of processes running as this "
                     "user, which holds this deployment's secrets")
    if exposure.get("database_reachable"):
        reach.append("open a connection to the database host")
    if reach:
        # F11 (2026-09-24): worded so the sentence agrees whether one
        # exposure applies or both.
        caveats.append(
            "The analysis child can " + " and ".join(reach) + ", so a "
            "parser exploit in a hostile sample could do the same. Run the "
            "analysis in a container with no secrets and no network to "
            "close this (docs/16).")
    if kind != "rlimit":
        caveats.append(f"On this platform the child is bounded by "
                       f"{lab_static.LIMITS_WORDS[kind]}.")
    if yara is None:
        caveats.append("YARA is not installed, so static triage scans with no "
                       "rules: install noctornal-api[yara].")
    return Check(name, True, evidence, caveat=" ".join(caveats))


def _yara_rules_active(conn: psycopg.Connection) -> Check:
    """Whether every active YARA rule set has a build this host can load
    (F12 M). Counts only: readiness has no caller, so it names no set and
    no person."""
    from noctornal_api.yara_rules import RulesetService, build_key
    name = "yara_rules_active"
    active = conn.execute(
        """SELECT a.version_id FROM lab.yara_activation a
            WHERE a.deactivated_at IS NULL""").fetchall()
    waiting = conn.execute(
        """SELECT count(*) FROM lab.yara_ruleset_version v
            WHERE NOT EXISTS (SELECT 1 FROM lab.yara_activation a
                               WHERE a.version_id = v.id
                                 AND a.deactivated_at IS NULL)
              AND NOT EXISTS (SELECT 1 FROM lab.yara_ruleset_version n
                               WHERE n.ruleset_id = v.ruleset_id
                                 AND n.version > v.version)""").fetchone()[0]
    key = build_key()
    if key is None:
        return Check(name, True,
                     f"{count_of(len(active), 'rule set is', 'rule sets are')} "
                     f"active; {count_of(waiting, 'version awaits', 'versions await')} "
                     f"activation.",
                     caveat="The YARA engine (yara-x) is not installed, so no "
                            "rule set scans anything: install "
                            "noctornal-api[yara].")
    svc = RulesetService(conn)
    built = stuck = 0
    for (version_id,) in active:
        found = svc.build_status(version_id, key)
        if found.get("status") in ("COMPILED", "PARTIAL"):
            built += 1
            continue
        job = conn.execute(
            """SELECT status, attempts, updated_at FROM lab.yara_compile_job
                WHERE version_id = %s AND engine = %s AND platform = %s
                  AND fingerprint = %s""",
            (version_id, key.engine, key.platform, key.fingerprint)).fetchone()
        if (found.get("status") == "FAILED" or job is None
                or job[0] == "FAILED" or job[1] >= 1
                or datetime.now(timezone.utc) - job[2] > timedelta(minutes=15)):
            stuck += 1
    evidence = (f"{count_of(len(active), 'rule set is', 'rule sets are')} "
                f"active; {built} with a verified build for {key.engine} on "
                f"{key.platform}; "
                f"{count_of(waiting, 'version awaits', 'versions await')} "
                f"activation.")
    if stuck:
        return Check(name, False, evidence,
                     f"{count_of(stuck, 'active rule set has', 'active rule sets have')} "
                     f"no build this host can load after a full pass: deactivate "
                     f"{agree(stuck, 'it', 'them')} or upload a version that "
                     f"compiles, and check that scripts/lab_triage.py runs")
    if not active:
        return Check(name, True, evidence,
                     caveat="No YARA rule set is active, so static triage "
                            "scans with none.")
    return Check(name, True, evidence)
# The collection foundation (docs/00 decision 69, 2026-09-24). Two
# informative rows, not blocking and with no CONSEQUENCES entry: what each
# failure stops (a source the collector leaves alone) is said in its
# evidence and action, and every refusal is enforced where it matters, by
# the poll. Counts, never names: a readiness report is not the place a
# source's name is shown to whoever can read it.
_COLLECTION_IDLE = "No forum or Telegram source is active, so nothing is read from one."

#: cause -> (one, many) for the configured row's evidence.
_CAUSE_WORDS = {
    "kind": ("is read by a parser that does not read its kind",
             "are read by a parser that does not read their kind"),
    "binding": ("has a binding its parser does not take",
                "have a binding their parser does not take"),
    "inactive": ("is deactivated", "are deactivated"),
    "above_ceiling": ("is labelled above the ceiling declared for its kind",
                      "are labelled above the ceiling declared for their kind"),
    "no_egress": ("has no egress profile", "have no egress profile"),
    "persona": ("is read by a persona that does not fit",
                "are read by a persona that does not fit"),
    "adapter": ("is refused by its parser", "are refused by their parser"),
}


def _authority_sources(conn: psycopg.Connection):
    """(active sources read by an adapter that requires authority, the
    registry): the sources the two rows are about."""
    from noctornal_api.collection import (
        _SOURCE_COLUMNS,
        _attr,
        _row_to_source,
        default_adapters,
    )

    adapters = default_adapters()
    rows = conn.execute(
        f"SELECT {_SOURCE_COLUMNS} FROM collect.source s WHERE s.is_active"
    ).fetchall()
    sources = [s for s in (_row_to_source(r) for r in rows)
               if (a := adapters.get(s.parser_key)) is not None
               and _attr(a, "requires_authority")]
    return sources, adapters


def _collection_sources_configured(conn: psycopg.Connection) -> Check:
    """Whether every active forum and Telegram source could be read: a
    declared ceiling it sits within, an exit or a persona that fits, and a
    parser that does not refuse it. Passes with a caveat when a parser that
    keeps raw markup is active and there is nowhere to keep it."""
    from collections import Counter

    from noctornal_api.collection import CollectionService, _attr
    from noctornal_api.rawstore import (
        collect_raw_bucket,
        document_raw_bucket_exists,
    )
    from noctornal_api.wording import agree, count_of

    name = "collection_sources_configured"
    sources, adapters = _authority_sources(conn)
    if not sources:
        return Check(name, True, _COLLECTION_IDLE)
    svc = CollectionService(conn, adapters)
    causes: Counter = Counter()
    unset: Counter = Counter()
    for source in sources:
        found = svc.refusal_cause(source, adapters[source.parser_key])
        if found is None:
            continue
        causes[found[0]] += 1
        if found[0] == CollectionService.CAUSE_NO_CEILING:
            var = _ceiling_var(source.kind)
            if var:
                unset[var] += 1
    total = len(sources)
    head = (f"{count_of(total, 'active forum and Telegram source', 'active forum and Telegram sources')}")
    refused = sum(causes.values())
    if refused:
        parts = []
        if causes.get(CollectionService.CAUSE_NO_CEILING):
            n = causes[CollectionService.CAUSE_NO_CEILING]
            variables = ", ".join(sorted(v for v in unset if v))
            parts.append(f"{n} {agree(n, 'has', 'have')} no ceiling declared"
                         + (f" ({variables})" if variables else ""))
        for cause, (one, many) in _CAUSE_WORDS.items():
            n = causes.get(cause, 0)
            if n:
                parts.append(f"{n} {one if n == 1 else many}")
        return Check(
            name, False,
            f"{head}; {refused} {agree(refused, 'is', 'are')} refused before "
            f"any request: {_joined(parts)}.",
            "declare the ceiling for each kind and restart, bind an egress "
            "profile or a persona to each source under Feeds, Sources, or "
            "deactivate it")
    caveat = ""
    if any(_attr(adapters[s.parser_key], "keeps_raw") for s in sources):
        try:
            exists = document_raw_bucket_exists()
        except Exception:  # noqa: BLE001 - a store that does not answer is the caveat
            exists = False
        if exists is None:
            caveat = ("No object storage is configured for collected pages: "
                      "raw markup is not kept, so collected pages cannot be "
                      "re-parsed.")
        elif not exists:
            caveat = (f"The bucket {collect_raw_bucket()} does not exist or does "
                      f"not answer: raw markup is not kept, so collected pages "
                      f"cannot be re-parsed.")
    return Check(name, True,
                 f"{head}; {agree(total, 'it', 'each')} could be read once "
                 f"its authority is confirmed.", caveat=caveat)


def _ceiling_var(kind: str) -> str:
    from noctornal_api.collection_authority import SOURCE_CEILING_ENV
    return SOURCE_CEILING_ENV.get(kind, "")


def _collection_authority_current(conn: psycopg.Connection) -> Check:
    """Whether every active forum and Telegram source is covered by a
    confirmed authority, and whether any authority ends soon."""
    from noctornal_api.collection_authority import CollectionAuthorityService
    from noctornal_api.wording import agree, count_of

    name = "collection_authority_current"
    sources, adapters = _authority_sources(conn)
    if not sources:
        return Check(name, True, _COLLECTION_IDLE)
    service = CollectionAuthorityService(conn, adapters)
    uncovered = len(service.uncovered_map(sources))
    if uncovered:
        return Check(
            name, False,
            f"{count_of(uncovered, 'active forum and Telegram source', 'active forum and Telegram sources')} "
            f"{agree(uncovered, 'has', 'have')} no confirmed authority, so the "
            f"collector leaves {agree(uncovered, 'it', 'them')} alone.",
            "a collection manager records the authority for each source under "
            "Feeds, Sources, and a security officer confirms it under Oversight")
    expiring = service.expiring_count()
    caveat = (f"{count_of(expiring, 'authority expires', 'authorities expire')} "
              f"within 14 days." if expiring else "")
    total = len(sources)
    return Check(name, True,
                 f"{count_of(total, 'active forum and Telegram source', 'active forum and Telegram sources')}; "
                 f"{agree(total, 'it is', 'each is')} covered by a confirmed "
                 f"authority.", caveat=caveat)


# The forum adapters (F3 and F4, 2026-09-24). Not
# blocking, no CONSEQUENCES entry: the poll enforces every refusal the row
# describes. Fails while NOCTORNAL_FORUM_ALLOW_DIRECT is set (a forum read
# with no proxy leaves from this host) or while forum sources are active
# and the parser is not installed; passes with a caveat while no retention
# rule covers FORUM_POST or FORUM_MEMBER. Counts, never names.
def _forum_collection(conn: psycopg.Connection) -> Check:
    from noctornal_api import forum_adapters

    ok, evidence, action, caveat = forum_adapters.readiness(conn)
    return Check("forum_collection", ok, evidence, action, caveat=caveat)


# ---------------------------------------------------------------------------
# The similarity indexes (F6.1 and F6.2, 2026-09-24). Not
# blocking. Neither row carries a count or a proportion: the register is
# read by user.manage holders, who need not read collected documents, and
# a deployment-wide count of what is indexed is a volume disclosure.
# ---------------------------------------------------------------------------

def _utc_words(moment) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _embedding_wording_current(conn: psycopg.Connection) -> Check:
    """Whether similar wording is built and still reproduces itself: an
    active index whose built-in model this build carries, whose stored
    canary equals a fresh local embedding of the canary text (compared in
    SQL after the vector(768) cast, at distance zero), and no item that
    has been failing for over an hour."""
    from noctornal_api import embedders as E
    from noctornal_api.embeddings import FAILED_STALE, EmbeddingService

    name = "embedding_wording_current"
    cfg = E.configured()
    if cfg.wording_setting == "off":
        return Check(name, True, f"{E.WORDING_ENV} is off.", caveat=(
            "Similar wording is off by configuration, so reposts, light edits and "
            "transliterations of a passage cannot be found."))
    service = EmbeddingService(conn, embedders=cfg, blocking_failures=lambda _c: [])
    active = service.active(E.ROLE_WORDING)
    building = service.building(E.ROLE_WORDING)
    if active is None and building is None and service.ever_registered(E.ROLE_WORDING):
        # Only the first index registers itself; one an administrator
        # retired stays retired (2026-09-25).
        return Check(name, False, "The similar wording index was retired and no new "
                     "one has been started.",
                     "rebuild it under Administration, Embeddings")
    if active is None:
        return Check(name, False, "No similar wording index exists yet.",
                     "run scripts/embed_pass.py, or start the embed-pass service")
    embedder = E.builtin(active.model)
    if embedder is None:
        return Check(
            name, False,
            f"The similar wording index was built with {active.model}, which this "
            f"build no longer carries, so it serves no query and receives nothing.",
            "run scripts/embed_pass.py: it builds the index again with this build's "
            "model in a free slot (Administration, Embeddings frees one)")
    canary = embedder.embed_one(E.CANARY_TEXT).vector
    same = conn.execute(
        "SELECT (canary <-> %s::vector(768)) = 0 FROM core.embedding_space WHERE id = %s",
        (E.vector_literal(canary), active.id)).fetchone()[0]
    if not same:
        return Check(
            name, False,
            "The built-in embedder no longer reproduces its own canary: a code change "
            "altered vectors without a new version.",
            "install a build whose built-in model is versioned, or rebuild the "
            "similar wording index under Administration, Embeddings")
    stale = any(conn.execute(
        f"SELECT EXISTS (SELECT 1 FROM {table} WHERE slot = %s AND status = 'FAILED' "
        f"AND first_failed_at < now() - interval '{FAILED_STALE}')",
        (active.slot,)).fetchone()[0]
        for table in ("collect.document_embedding", "core.evidence_embedding",
                      "core.assertion_embedding"))
    if stale:
        return Check(name, False,
                     "Some items have failed to embed for over an hour.",
                     "read the embed-pass log")
    evidence = (f"Model {active.model} in slot {active.slot}, active since "
                f"{_utc_words(active.activated_at)}.")
    caveat = ""
    if building is not None:
        caveat = ("A rebuild of the similar wording index is in progress; queries use "
                  "the current index until it completes.")
    elif active.model != E.BUILTIN_CURRENT and service._free_slot() is None:
        caveat = ("This build carries a newer built-in model and no slot is free to "
                  "rebuild the index with it: retire an index under Administration, "
                  "Embeddings.")
    return Check(name, True, evidence, caveat=caveat)


def _embedding_meaning_endpoint(conn: psycopg.Connection) -> Check:
    """Whether similar meaning can reach its model endpoint lawfully:
    settings without problems, a route that reaches it, AUTHORITY for an
    endpoint outside this host, the model unchanged. The canary is read
    from the pass's last result and sent again only when that result is
    over an hour old (a send on every render would be a network call
    triggered by opening a page), and never while a blocking
    check fails or without AUTHORITY outside this host."""
    from noctornal_api import embedders as E
    from noctornal_api.egress import _production
    from noctornal_api.embeddings import (
        CANARY_FRESH_SECONDS,
        EmbeddingService,
        EmbedRefused,
        reason_text,
    )

    name = "embedding_meaning_endpoint"
    cfg = E.configured()
    if not cfg.meaning_url_set:
        return Check(name, True, (
            "No model endpoint is configured, so no case text is sent anywhere to be "
            "embedded. Similar meaning is off."))
    settings = cfg.meaning_settings
    if settings is None:
        problems = [p for p in cfg.problems if E.MEANING_PREFIX in p]
        return Check(name, False, " ".join(problems),
                     "correct the settings named above and restart")
    service = EmbeddingService(conn, embedders=cfg)
    try:
        endpoint = service.open(settings, context_kind="check")
    except EmbedRefused as exc:
        if exc.code in ("unrouted", "route_refused"):
            return Check(name, False, f"No egress route reaches the model endpoint: {exc}",
                         f"create the integration route embeddings under "
                         f"Administration, Egress, and allow {settings.endpoint} on it")
        return Check(name, False, "The model endpoint cannot be reached: "
                     + reason_text(exc.code) + ".",
                     "check the model server's address in NOCTORNAL_EMBED_MEANING_URL")
    locality = endpoint.locality
    evidence = (f"Endpoint {settings.endpoint}, {locality.words}; destination "
                f"{endpoint.destination.value}; ceiling TLP:{settings.ceiling}; "
                f"authority {settings.authority or 'not declared'}; message authority "
                f"{settings.message_authority or 'not declared'}.")
    if not locality.on_this_host and not settings.authority:
        return Check(
            name, False,
            evidence + " The endpoint is outside this host and no written authority to "
            "send case text there is declared, so nothing is sent, not even the public "
            "canary.",
            "record the decision (docs/16) and set NOCTORNAL_EMBED_MEANING_AUTHORITY to "
            "its reference, or use a model server on this host")
    caveats = []
    if not locality.on_this_host and settings.scheme == "http":
        if locality.kind == "internet":
            return Check(name, False, evidence + " It is reached over plain http "
                         "across the internet.",
                         "use an https:// address for the model endpoint")
        caveats.append("The model endpoint is reached over plain http, which anyone "
                       "on that network can read.")
    if settings.local_host and _production():
        caveats.append("NOCTORNAL_EMBED_MEANING_LOCAL_HOST has no effect in production: "
                       "a model endpoint there is always outside this host.")
    blocked = service._blocking_failures(conn)
    if blocked:
        caveats.append("Sends are paused while blocking readiness checks fail.")
    active = service.active(E.ROLE_MEANING)
    if active is None:
        if (service.building(E.ROLE_MEANING) is None
                and service.ever_registered(E.ROLE_MEANING)):
            caveats.append("The similar meaning index was retired, and nothing is sent "
                           "until an administrator rebuilds it (Administration, "
                           "Embeddings).")
        else:
            caveats.append("No similar meaning index exists yet: the next embedding "
                           "pass builds it.")
        return Check(name, True, evidence, caveat=" ".join(caveats))
    fresh = (active.canary_checked_at is not None
             and (datetime.now(timezone.utc) - active.canary_checked_at).total_seconds()
             < CANARY_FRESH_SECONDS)
    if not fresh and not blocked:
        try:
            service._check_canaries(settings, [active], timeout_s=5,
                                     context_kind="check")
        except EmbedRefused:
            pass
        active = service.space(active.id)
    if active.model_mismatch_at is not None:
        return Check(name, False, evidence + " The model behind the endpoint has changed "
                     "since the index was built.",
                     "rebuild the similar meaning index under Administration, Embeddings")
    if active.canary_ok is False:
        return Check(name, False, evidence + " The last canary sent to the model "
                     "endpoint failed: " + reason_text(active.canary_problem) + ".",
                     "check the model server and its route; the embed-pass log names "
                     "the failure")
    if active.canary_checked_at is not None:
        evidence += f" Canary last checked {_utc_words(active.canary_checked_at)}."
    return Check(name, True, evidence, caveat=" ".join(caveats))


# Outbound integrations (F8, F7 and F15.2, 2026-09-24). Not blocking: each
# refuses at the point of use, and a blocking row would stop collection
# polls for a feature nobody turned on.
#: How long a due email or webhook may wait before the outbox row says no
#: drain is reaching it.
OUTBOX_OVERDUE_AFTER = timedelta(minutes=30)


def _notify_outbox_draining(conn: psycopg.Connection) -> Check:
    """Is anything draining the outbox? Over the email and webhook channels
    that can send: Jira's backlog is jira_destination's business, and a
    held channel (no route) is smtp_configured's and the Integrations
    card's, so a Jira outage or a missing route is never reported as "no
    drain is running" (F8 F)."""
    from noctornal_api import transports
    from noctornal_api.wording import count_of

    sendable, held = [], []
    for channel in (transports.SMTP, transports.WEBHOOK):
        state = transports.route_state(channel, conn)
        (sendable if state.ok else held).append((channel, state))
    notes = [f"{'Email' if c == transports.SMTP else 'Webhook'} held: {s.why}"
             for c, s in held if not (c == transports.WEBHOOK
                                      and transports.webhook_url() is None)]
    channels = [c for c, _ in sendable]
    row = conn.execute(
        """SELECT count(*), min(deliver_after) FROM notify.delivery
            WHERE state = 'PENDING' AND deliver_after <= now() - %s
              AND channel = ANY(%s)""",
        (OUTBOX_OVERDUE_AFTER, channels)).fetchone()
    overdue, oldest = int(row[0]), row[1]
    if overdue:
        return Check(
            "notify_outbox_draining", False,
            f"{count_of(overdue, 'delivery', 'deliveries')} overdue, the oldest due "
            f"at {oldest:%Y-%m-%d %H:%M} UTC: no drain has run since, or it stops "
            f"before sending.",
            "Start the cron service (infra/production/compose.yml, service cron), "
            "or run python scripts/notify_drain.py every five minutes; Drain now in "
            "Administration, Integrations runs one pass.")
    due = conn.execute(
        """SELECT min(deliver_after) FROM notify.delivery
            WHERE state = 'PENDING' AND deliver_after <= now() AND channel = ANY(%s)""",
        (channels,)).fetchone()[0]
    evidence = "Nothing has waited more than 30 minutes past its due time."
    if due is not None:
        evidence += f" The oldest due row has waited since {due:%Y-%m-%d %H:%M} UTC."
    if notes:
        evidence += " " + " ".join(notes)
    return Check("notify_outbox_draining", True, evidence)


def _jira_destination(conn: psycopg.Connection) -> Check:
    """The Jira destination's own verdict (F7): its route, its
    credential, its health and its backlog."""
    from noctornal_api import jira

    ok, evidence, action, caveat = jira.readiness_verdict(conn)
    return Check("jira_destination", ok, evidence, "" if ok else action,
                 caveat=caveat if ok else "")


def _outbound_lookup_providers(conn: psycopg.Connection) -> Check:
    """The host switch and every enabled provider's key, route and adapter
    (F15.2)."""
    from noctornal_api import providers

    ok, evidence, action, caveat = providers.readiness_verdict(conn)
    return Check("outbound_lookup_providers", ok, evidence, "" if ok else action,
                 caveat=caveat if ok else "")


# Telegram collection (F5.3, 2026-09-24). Not blocking and with no
# CONSEQUENCES entry: every refusal is enforced where it matters, by the
# poll and the acts. The library, the enrolled sessions and the machine
# locks only; the ceiling and the proxy are other rows'.
def _telegram_collection(conn: psycopg.Connection) -> Check:
    from noctornal_api import telegram_service

    ok, evidence, action = telegram_service.readiness_verdict(conn)
    return Check("telegram_collection", ok, evidence, "" if ok else action)


# ---------------------------------------------------------------------------
# Prohibited-content screening (F13, 2026-09-24). Not blocking: holding
# hash lists may itself be unlawful, so no list loaded must pass.
# ---------------------------------------------------------------------------

def _screening_active(conn: psycopg.Connection) -> bool:
    return conn.execute(
        "SELECT EXISTS (SELECT 1 FROM lab.screening_list "
        "WHERE retired_at IS NULL)").fetchone()[0]


def _screening_clause(conn: psycopg.Connection) -> str:
    """The policy row's sentence about screening."""
    from noctornal_api import screening
    n = len(screening.state(conn).active_lists)
    if not n:
        return "Screening: no hash list is loaded."
    return f"Screening: {count_of(n, 'hash list is', 'hash lists are')} active."


def _prohibited_content_screening(conn: psycopg.Connection) -> Check:
    """Whether the hash lists held are held under a recorded authority,
    whether every held sample has been screened against the newest, and
    whether every matched sample's bytes have left the working store.

    No list loaded PASSES with the docs/16 C3 caveat: not holding lists is
    the lawful default in most deployments, so it must not make the
    register unreachable. The evidence says WHETHER samples wait or are
    behind, never how many: this row is read by every holder of
    user.manage, and the counts span every compartment;
    the officer's section has the numbers."""
    from noctornal_api import screening
    name = "prohibited_content_screening"
    now = screening.state(conn)
    authority = (f"{screening.AUTHORITY_ENV} is declared ({now.authority})"
                 if now.authority else
                 f"{screening.AUTHORITY_ENV} is not declared")
    if not now.active_lists:
        return Check(
            name, True, f"No prohibited-content hash list is loaded; {authority}.",
            caveat=("No prohibited-content hash list is loaded, so nothing is "
                    "compared (docs/16 C3). Import one only if counsel confirms "
                    "this deployment may hold it."))
    lists = "; ".join(
        f"{x['name']} ({count_of(x['entry_count'], 'entry', 'entries')}, "
        f"{', '.join(x['algorithms'])})" for x in now.active_lists)
    last = (now.last_pass_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            if now.last_pass_at else "never")
    # The worker's budget is stated, so an operator can see how long one
    # pass may hold its loop (2026-09-24).
    evidence = (f"Active: {lists}. {authority}. Last screening pass {last}; "
                f"the worker's pass budget {screening.PASS_BUDGET_S} seconds. "
                f"{screening.EXACT_HASH_SENTENCE} "
                f"{screening.ARCHIVE_MEMBERS_SENTENCE} Perceptual matching is "
                f"not built.")
    if now.authority is None:
        return Check(name, False,
                     f"hash lists are held with no recorded authority "
                     f"({screening.AUTHORITY_ENV}). {evidence}",
                     "declare the authority counsel gave, or retire the lists "
                     "with their entries")
    if now.pending_preservation:
        return Check(name, False,
                     f"matched samples still have their bytes in the working "
                     f"store, where nothing releases them; each screening pass "
                     f"retries the move. {evidence}",
                     "check the preservation store (preservation_bucket_"
                     "object_lock) and run scripts/sample_screen.py")
    if now.behind:
        return Check(name, False,
                     f"samples have not been screened against the newest list. "
                     f"{evidence}",
                     "schedule scripts/sample_screen.py (the production "
                     "compose's lab-cron service runs it)")
    caveats = []
    if now.unreviewed_matches:
        caveats.append("Some matches have no review recorded: the Security "
                       "Officer's screening section lists them.")
    if now.bytes_not_found:
        caveats.append("Some matched samples' bytes were found in neither "
                       "store and need the Security Officer's review.")
    return Check(name, True, evidence, caveat=" ".join(caveats))



# ---------------------------------------------------------------------------
# The sandbox (F14, 2026-09-24). Not blocking: with no sandbox
# configured a detonation is recorded and nothing is sent.
# ---------------------------------------------------------------------------

#: How long a QUEUED detonation may wait before the register says nothing
#: is sending (the worker runs every few minutes).
_SANDBOX_STALE_MINUTES = 60


def _sandbox_integration(conn: psycopg.Connection) -> Check:
    """Whether the configured CAPEv2 can be reached through its egress
    route, takes the token, and refuses every read made without it (its
    API and its web interface), and whether the worker is sending."""
    from uuid import uuid4

    from noctornal_api import sandbox
    from noctornal_api.pinned_http import OutboundError
    from noctornal_api.sandbox_capev2 import CapeV2Client
    name = "sandbox_integration"
    settings, problem = sandbox.sandbox_settings()
    if settings is None and problem is None:
        return Check(name, True,
                     f"no sandbox is configured ({sandbox.PROVIDER_ENV} is "
                     f"unset): a detonation request is recorded and nothing is "
                     f"sent anywhere")
    if settings is None:
        return Check(name, False, problem,
                     "correct the setting it names and restart")
    routes = ", ".join(f"{r} ({c.lower()})" for r, c in settings.routes)
    evidence = (f"{settings.provider} {settings.name} at {settings.host}; exposure "
                f"{settings.exposure}, declared by the operator (docs/16 D5); "
                f"ceiling TLP:{settings.ceiling}; network routes {routes}; the "
                f"worker's pass budget {settings.pass_budget_s} seconds")
    client = CapeV2Client(settings, conn=conn)
    rule_words = (f"{settings.target_host}"
                  + (f" in {settings.network}" if settings.network else ""))
    try:
        route = client.route(f"check:{uuid4()}")
        reachable = route.permits(settings.host, settings.port)
    except OutboundError as exc:
        return Check(name, False, f"{evidence}. No route: {exc}",
                     f"create the integration route sandbox under "
                     f"Administration, Egress, with an allowlist entry for "
                     f"{rule_words}")
    if not reachable:
        return Check(name, False, f"{evidence}. The sandbox route does not name "
                     f"{settings.target_host}",
                     f"add an allowlist entry for {rule_words} to the sandbox "
                     f"route under Administration, Egress")
    probe = client.probe(context=f"check:{uuid4()}")
    evidence += f"; answered in {probe.latency_ms} ms"
    if probe.error:
        return Check(name, False, f"{evidence}. Unreachable: {probe.error}",
                     "check that the sandbox is running and reachable through "
                     "the egress route")
    if not probe.token_accepted:
        return Check(name, False, f"{evidence}. The token was refused",
                     f"set {sandbox.TOKEN_ENV} to a token the sandbox accepts")
    if probe.open_without_token:
        return Check(name, False,
                     f"{evidence}. It answers without a token at "
                     f"{', '.join(probe.open_paths)}, so anyone who can reach it "
                     f"can read every report and fetch every sample sent there",
                     "set token_auth_enabled = yes in CAPE's api.conf and "
                     "enabled = yes under [web_auth] in its web.conf, or do not "
                     "serve the web interface on the allowlisted host and port")
    stale, orphan, sent = conn.execute(
        """SELECT count(*) FILTER (WHERE status = 'QUEUED'
                                     AND requested_at < now() - %s),
                  count(*) FILTER (WHERE status IN ('AWAITING_SIGNOFF',
                                                    'QUEUED', 'SUBMITTED')
                                     AND target_key IS DISTINCT FROM %s),
                  count(*) FILTER (WHERE submitted_at IS NOT NULL)
             FROM lab.detonation WHERE mode = 'SUBMIT'""",
        (timedelta(minutes=_SANDBOX_STALE_MINUTES), settings.name)).fetchone()
    if stale:
        return Check(name, False,
                     f"{evidence}. Detonations have waited over an hour to be "
                     f"sent", "schedule scripts/sandbox_dispatch.py (the "
                     "production compose's lab-cron service runs it)")
    if orphan:
        return Check(name, False,
                     f"{evidence}. Requests in flight name a sandbox that is no "
                     f"longer configured",
                     "restore the sandbox's name, or cancel those requests")
    caveats = []
    if any(c == sandbox.LIVE for _r, c in settings.routes) or any(
            c == sandbox.LIVE for _m, c in settings.machines):
        caveats.append("A live network route or machine is offered: a sample "
                       "sent on it can reach its operators, and each such send "
                       "needs a second person's sign-off.")
    if settings.exposure != "NONE":
        caveats.append(f"The target's exposure is {settings.exposure}: every "
                       f"send needs a sign-off and a sample screened against "
                       f"every active hash list.")
    holders = conn.execute(
        """SELECT count(DISTINCT ur.user_id) FROM iam.role_permission rp
             JOIN iam.user_role ur ON ur.role_key = rp.role_key
             JOIN iam.app_user u ON u.id = ur.user_id
            WHERE rp.permission_key = 'sample.detonate' AND u.is_active""").fetchone()[0]
    if not holders:
        caveats.append("No active account holds sample.detonate, so nobody can "
                       "ask for a send.")
    if not sent:
        caveats.append("Nothing has been sent to it yet.")
    return Check(name, True, evidence + ".", caveat=" ".join(caveats))


# ---------------------------------------------------------------------------
# Row-level security (S1, 2026-09-25). Not blocking, no console target,
# and EXPECTED to fail on every developer machine and in the main CI suite
# for app_db_role_not_owner's reason: they connect as the owner, which row
# security never filters.
# ---------------------------------------------------------------------------

_RLS_ACTION = (
    "point DATABASE_URL at `noctornal_app` and NOCTORNAL_WORKER_DATABASE_URL at "
    "`noctornal_worker` (infra/production/compose.yml), keep the sample origin "
    "without the worker DSN, and if either role was created after its migration "
    "ran, run `python scripts/runtime_roles.py ensure --production` as a "
    "superuser; then `alembic upgrade head` as the owner")


def _row_level_security_enforced(conn: psycopg.Connection) -> Check:
    """Is row-level security actually the second line here?

    Four facts, all required: every table the registry puts under policy
    (`rls_registry.POLICY`) has row security enabled and at least one
    policy, and there are at least `POLICY_FLOOR` of them, so a database
    with no policies at all is not vacuously "enforced"; THIS connection is
    subject to it (the request role, not the owner, not a BYPASSRLS role);
    the IAM plane is read-only to this connection's role (0109), without
    which a forged session row would rebind it; and a system connection
    opens, is exempt, and is neither a superuser nor the owner, because the
    work that must see every row has to have somewhere to run.
    """
    from noctornal_api import rls_registry
    from noctornal_api.db import (
        _EXEMPT_SQL,
        SystemContextUnavailable,
        SystemPurpose,
        connect_system,
        is_exempt,
    )

    name = "row_level_security_enforced"
    wanted = sorted(rls_registry.POLICY)
    rows = conn.execute(
        """SELECT n.nspname || '.' || c.relname, c.relrowsecurity,
                  (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname || '.' || c.relname = ANY(%s)""",
        (wanted,)).fetchall()
    enforced = {r[0] for r in rows if r[1] and r[2] > 0}
    missing = [t for t in wanted if t not in enforced]
    who = conn.execute("SELECT current_user").fetchone()[0]
    problems: list[str] = []
    if missing or len(enforced) < rls_registry.POLICY_FLOOR:
        problems.append(
            f"{count_of(len(missing), 'table', 'tables')} the registry puts under "
            f"policy {'has' if len(missing) == 1 else 'have'} no row security: "
            f"{', '.join(missing)}")
    if is_exempt(conn):
        problems.append(
            f"connected as {who}, which row-level security does not filter "
            f"(the owner, a superuser or a BYPASSRLS role)")
    iam_writable = conn.execute(
        "SELECT has_table_privilege(current_user, 'iam.session', 'INSERT')"
    ).fetchone()[0]
    if iam_writable:
        problems.append(
            f"{who} may write the IAM plane, so an injected statement could "
            f"forge the session that binds it (0109)")
    try:
        system = connect_system(SystemPurpose.READINESS)
    except (SystemContextUnavailable, psycopg.Error) as exc:
        problems.append(f"no system connection: {exc}")
    else:
        try:
            _exempt, superuser, owner = system.execute(_EXEMPT_SQL).fetchone()
            system_role = system.execute("SELECT current_user").fetchone()[0]
        finally:
            system.close()
        if superuser or owner:
            problems.append(
                f"system connections use {system_role}, which is "
                f"{'a superuser' if superuser else 'the schema owner'}, not a "
                f"role that owns nothing")
    if problems:
        return Check(name, False, "; ".join(problems) + ".", _RLS_ACTION)
    return Check(
        name, True,
        f"connected as {who}, which row-level security filters; "
        f"{count_of(len(enforced), 'table carries', 'tables carry')} policies; "
        f"the IAM plane is read-only to {who}; system connections use "
        f"{system_role}, which owns nothing.")


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
    ("kek_ring_opens_stored_secrets", _kek_ring_opens_stored_secrets,
     "the sealed tables could not be read; once they can, every key id they "
     "hold must be in the ring (NOCTORNAL_TOTP_KEK / _RETIRED)"),
    ("ingest_pepper_set", _ingest_pepper_set,
     f"set {_PEPPER_ENV} to a long random string, once, and keep it"),
    # sec-dev-secrets-in-production, 2026-09-23.
    ("credentials_not_published", _credentials_not_published,
     "replace every credential that carries a published value with one "
     "generated for this deployment, and restart"),
    ("rate_limiting_enabled", _rate_limiting_enabled,
     "unset NOCTORNAL_RATELIMIT and restart the API"),
    ("redis_limiter_store", _redis_limiter_store,
     "fix REDIS_URL or start the Redis it names; run it with "
     "maxmemory-policy=noeviction (docs/16 C8)"),
    # sec-redis-isolation, 2026-09-23.
    ("redis_limiter_isolated", _redis_limiter_isolated,
     "fix REDIS_URL or start the Redis it names; the limiter needs an "
     "instance of its own (docs/16 C8)"),
    ("evidence_bucket_object_lock", _evidence_bucket_object_lock,
     "fix MINIO_ENDPOINT / MINIO_ACCESS_KEY / MINIO_SECRET_KEY or start the "
     "object store; the evidence bucket must be created with object lock"),
    ("preservation_bucket_object_lock", _preservation_bucket_object_lock,
     "fix PRESERVE_ENDPOINT / PRESERVE_ACCESS_KEY / PRESERVE_SECRET_KEY (or "
     "their SAMPLE_* / MINIO_* fallbacks) or start the object store; the "
     "preservation bucket must be created with object lock"),
    ("evidence_size_cap_declared", _evidence_size_cap_declared,
     f"declare {EVIDENCE_CAP_ENV} (bytes, or 512MiB) and restart the API; "
     "every accepted exhibit byte is locked under COMPLIANCE for the "
     "retention period (docs/08)"),
    ("migrations_at_head", _migrations_at_head,
     "run `alembic upgrade head` from the repository root with DATABASE_URL "
     "set to this database"),
    ("app_db_role_not_owner", _app_db_role_not_owner,
     "the catalogue could not be read; the connected role should be "
     "`noctornal_app` (DATABASE_URL), never the schema owner `noctornal`"),
    # S1, 2026-09-25. Beside its sibling rather than last: the two rows
    # answer "what can this connection do to the data". Not blocking, no
    # console target.
    ("row_level_security_enforced", _row_level_security_enforced,
     "the catalogue could not be read; run alembic upgrade head as the owner"),
    ("smtp_configured", _smtp_configured,
     "set SMTP_HOST to a relay that speaks TLS (docs/07)"),
    # The compartment registry, L1 and L2 (2026-09-24). Not blocking, no
    # console target.
    ("compartment_bindings_intact", _compartment_bindings_intact,
     "the catalogue could not be read; run alembic upgrade head"),
    ("captured_documents_compartmented", _captured_documents_compartmented,
     "the collection tables could not be read; run alembic upgrade head"),
    ("triage_claims_within_labels", _triage_claims_within_labels,
     "the claim tables could not be read; run alembic upgrade head"),
    ("triage_claims_dated", _triage_claims_dated,
     "the claim tables could not be read; run alembic upgrade head"),
    # The network boundary (docs/00 decision 68, 2026-09-24). Not blocking.
    ("egress_boundary", _egress_boundary,
     "the collection tables could not be read; run alembic upgrade head"),
    # F1 roles, 2026-09-24.
    ("role_analysis_thread_capped", _role_analysis_thread_capped,
     "numpy or the role analysis module could not be loaded; reinstall with "
     "-c constraints.txt and restart the API"),
    # The two-person policy (F9, 2026-09-24).
    ("dual_control_policy_changeable", _dual_control_policy_changeable,
     "the role table could not be read; once it can, grant SECURITY_OFFICER "
     "to an active account that is not an administrator"),
    # F11 and F12 (2026-09-24). Not blocking, no console target.
    ("sample_static_analysis", _sample_static_analysis,
     "the static triage tables could not be read; run alembic upgrade head"),
    ("yara_rules_active", _yara_rules_active,
     "the YARA rule set tables could not be read; run alembic upgrade head"),
    # The collection foundation (docs/00 decision 69, 2026-09-24). Not
    # blocking.
    ("collection_sources_configured", _collection_sources_configured,
     "the collection tables could not be read; run alembic upgrade head"),
    ("collection_authority_current", _collection_authority_current,
     "the collection tables could not be read; run alembic upgrade head"),
    # The egress proxy (S2, 2026-09-24). Not blocking.
    ("egress_routes_cover_sources", _egress_routes_cover_sources,
     "the egress tables could not be read; run alembic upgrade head"),
    ("egress_exits_open", _egress_exits_open,
     "the egress tables could not be read; run alembic upgrade head"),
    # Comms (F10a and F10c, 2026-09-24). Not blocking, no console target.
    ("pgp_verifier", _pgp_verifier,
     "the gpg binary could not be run; install GnuPG 2.4.9 or later, or set "
     "NOCTORNAL_GPG to its full path, and restart"),
    ("pgp_key_directory", _pgp_key_directory,
     "the key lookup settings could not be read; check NOCTORNAL_WKD_CEILING "
     "and the integration route wkd"),
    # The similarity indexes (F6.1 and F6.2, 2026-09-24). Not blocking.
    ("embedding_wording_current", _embedding_wording_current,
     "the similarity tables could not be read; run alembic upgrade head"),
    ("embedding_meaning_endpoint", _embedding_meaning_endpoint,
     "the similarity tables could not be read, or the model endpoint check "
     "failed; run alembic upgrade head and read the API log"),
    # Outbound integrations (F8, F7 and F15.2, 2026-09-24). Not blocking.
    ("notify_outbox_draining", _notify_outbox_draining,
     "the delivery table could not be read; run alembic upgrade head"),
    ("jira_destination", _jira_destination,
     "the Jira tables could not be read; run alembic upgrade head"),
    ("outbound_lookup_providers", _outbound_lookup_providers,
     "the provider table could not be read; run alembic upgrade head"),
    # Screening (F13, 2026-09-24). Not blocking, no console target.
    ("prohibited_content_screening", _prohibited_content_screening,
     "the screening tables could not be read; run alembic upgrade head"),
    # The sandbox (F14, 2026-09-24). Not blocking, no console target.
    ("sandbox_integration", _sandbox_integration,
     "the detonation table could not be read; run alembic upgrade head"),
    # The forum adapters (F3 and F4, 2026-09-24). Not blocking.
    ("forum_collection", _forum_collection,
     "the forum sources could not be read; run alembic upgrade head"),
    # Telegram collection (F5.3, 2026-09-24). Not blocking.
    ("telegram_collection", _telegram_collection,
     "the collection tables could not be read; run alembic upgrade head"),
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


#: What the product refuses while a BLOCKING check fails, beyond the
#: collection poll that every one of them refuses (2026-09-23,
#: ux16-admin:blocking-headline-understates-impact). The admin banner
#: builds its headline from these, so it can no longer say "the poll
#: route" while its own items say ingest, download and break-glass are
#: refused too. Each is the refusal the check's own reader makes:
#: `samples.policy_declared` gates ingest, `samples.origin_split` gates
#: every download, and break-glass refuses to grant with no reviewer.
CONSEQUENCES: dict[str, str] = {
    "prohibited_content_policy": "Sample ingest is refused.",
    "sample_origin_configured": "Every sample download is refused.",
    "security_officer_present":
        "Break-glass is refused, and nobody can read the audit trail.",
}

#: Where in the console a check is settled, as "tab/subtab" (2026-09-23,
#: ux16-admin:readiness-actions-speak-api). A check absent from this map
#: is settled by the API's configuration and a restart. Named by the
#: console's own `data-tab` and `data-subtab` values, never by the
#: labels, which the console owns.
UI_TARGETS: dict[str, str] = {
    "retention_rules_confirmed": "governance/retention",
    "security_officer_present": "admin/accounts",
    "sys_admin_present": "admin/accounts",
    # The two-person policy (F9, 2026-09-24).
    "dual_control_policy_changeable": "admin/accounts",
    # The collection foundation (docs/00 decision 69, 2026-09-24).
    "collection_sources_configured": "feeds/sources",
    "collection_authority_current": "feeds/sources",
    # Settled under Administration, Egress (S2, 2026-09-24).
    "egress_boundary": "admin/egress",
    "egress_routes_cover_sources": "admin/egress",
    "egress_exits_open": "admin/egress",
    # The similarity indexes (F6.1 and F6.2, 2026-09-24).
    "embedding_wording_current": "admin/embeddings",
    "embedding_meaning_endpoint": "admin/embeddings",
    # Outbound integrations (F8, F7 and F15.2, 2026-09-24).
    "notify_outbox_draining": "admin/integrations",
    "jira_destination": "admin/integrations",
    "outbound_lookup_providers": "admin/providers",
    # The forum adapters (F3 and F4, 2026-09-24).
    "forum_collection": "feeds/sources",
    # Telegram collection (F5.3, 2026-09-24).
    "telegram_collection": "feeds/sources",
}


def _register_facts(name: str, check: Check) -> Check:
    """The register's facts about a row: its tier always, and what it
    refuses and where it is settled while it fails. Also for a probe that
    crashed, which never got to say anything about itself.

    A passing row with a caveat gets its `ui_target` too (2026-09-23,
    ux16-admin:security-officer-false-green): the lone officer's caveat
    says to grant the role to a second person, and the console can take
    the operator to where that is done. A caveat on a failed row is
    dropped: its action already says what to do, and a row that said two
    different things about itself would leave the operator to choose."""
    failing = not check.ok
    caveat = "" if failing else check.caveat
    return replace(check, blocking=name in BLOCKING_CHECKS,
                   consequence=CONSEQUENCES.get(name, "") if failing else "",
                   ui_target=UI_TARGETS.get(name, "") if failing or caveat else "",
                   caveat=caveat)


#: The probes whose question is about the REQUEST connection itself: which
#: role it is and whether row security filters it. Every other probe counts
#: or reads across the deployment, and runs on a system connection (S1,
#: 2026-09-25): taken as the request role under row-level security, a count
#: of captured documents, claims, static runs or deliveries would describe
#: only what the administrator reading the register may read, and a row
#: would report health for everything they may not.
_REQUEST_CONNECTION_CHECKS = frozenset({"app_db_role_not_owner",
                                        "row_level_security_enforced"})


class _NoSystemConnection:
    """Stands in for the system connection a probe needed and could not
    have: its first query raises, so `_guarded` turns that probe into a
    failed row naming why. Never a quiet fallback to the request
    connection, whose counts would read low."""

    def __init__(self, exc: BaseException):
        self._why = f"{type(exc).__name__}: {str(exc)[:300]}"

    def execute(self, *_args, **_kwargs):
        from noctornal_api.db import SystemContextUnavailable
        raise SystemContextUnavailable(
            f"this check counts across the deployment and needs a system "
            f"connection, which could not be opened ({self._why})")

    def __getattr__(self, _name):
        return self.execute


@contextmanager
def _probe_connections(conn: psycopg.Connection
                       ) -> Iterator[Callable[[str], psycopg.Connection]]:
    """(check name -> the connection its probe runs on). In development
    and the test suite the request connection is the exempt owner and the
    system connection IS it, so nothing changes there."""
    from noctornal_api.db import (
        SystemContextUnavailable,
        SystemPurpose,
        system_connection,
    )
    with ExitStack() as stack:
        try:
            sconn = stack.enter_context(
                system_connection(SystemPurpose.READINESS, reuse=conn))
        except (SystemContextUnavailable, psycopg.Error) as exc:
            sconn = _NoSystemConnection(exc)
        yield lambda name: conn if name in _REQUEST_CONNECTION_CHECKS else sconn


def run_checks(conn: psycopg.Connection) -> list[Check]:
    """Every check, in register order, each one guarded. `conn` is the
    caller's autocommit connection, so a check whose query fails does not
    leave an aborted transaction for the next check to trip over.

    The tier is stamped HERE rather than inside each probe, so
    `BLOCKING_CHECKS` is the one place that decides what refuses --
    including for a check that crashed, where `_guarded` built the Check
    and the probe never ran at all.
    """
    # `blocking=name in BLOCKING_CHECKS` is spelled inside `_register_facts`.
    with _probe_connections(conn) as on:
        return [_register_facts(name, _guarded(
                    name, action, lambda probe=probe, name=name: probe(on(name))))
                for name, probe, action in _CHECKS]


def check(name: str, conn: psycopg.Connection) -> Check:
    """ONE registered probe, guarded and stamped exactly as the register
    stamps it, so a page that shows one row (Administration, Integrations)
    and the register cannot disagree: one reader per fact (F8 E,
    2026-09-24). KeyError for a name the register does not hold."""
    for registered, probe, action in _CHECKS:
        if registered == name:
            with _probe_connections(conn) as on:
                return _register_facts(
                    name, _guarded(name, action, lambda probe=probe: probe(on(name))))
    raise KeyError(name)


def blocking_failures(conn: psycopg.Connection) -> list[str]:
    """The blocking checks failing right now, in register order.

    Public so a caller can refuse without rendering the register: it
    wants four verdicts, not a paragraph of evidence per check, and it is
    standing on a request path -- or in a cron pass with a due list
    waiting -- while it asks. Both callers exist:
    `POST /collection/sources/{id}/run` and `scripts/collection_poll.py`,
    which calls this ONCE per pass, before it asks what is due.

    Runs ONLY the blocking probes. The others include a Redis PING, two
    object-store probes that each try a delete (the WORM proofs, which may
    also write a canary) and an Alembic script scan, and making every
    collection poll wait on the object store would turn a readiness
    refusal into a latency bug -- a failure reported as the wrong thing,
    which is the defect this module exists to prevent, aimed at the
    request path instead of at the operator. Each probe is still
    `_guarded`, so one that raises is a name in this list rather than a
    500 in the caller.
    """
    return [name for name, check in _blocking_rows(conn) if not check.ok]


def _blocking_rows(conn: psycopg.Connection) -> list[tuple[str, Check]]:
    """The blocking probes alone, each guarded and stamped, in register
    order: the one run both `blocking_failures` and `blocking_state` read."""
    return [(name, _register_facts(
                name, _guarded(name, action, lambda probe=probe: probe(conn))))
            for name, probe, action in _CHECKS if name in BLOCKING_CHECKS]


def blocking_state(conn: psycopg.Connection) -> dict:
    """`{failures, caveats}` from ONE run of the blocking probes, for the
    console's badges (`GET /admin/access`). `failures` is exactly
    `blocking_failures`; `caveats` names the blocking checks that pass
    with a caveat (2026-09-23, ux16-admin:security-officer-false-green),
    so the Readiness section can be marked while its passing rows say
    something the operator has not read. Two separate calls could
    disagree a few milliseconds apart; one run cannot."""
    rows = _blocking_rows(conn)
    return {"failures": [name for name, check in rows if not check.ok],
            "caveats": [name for name, check in rows if check.caveat]}


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
    # `checked_at` (2026-09-23, ux16-admin:readiness-stale-after-fix): with
    # no time on it, a report taken before a fix, or before an API
    # restart, could not be told from a fresh one, which is the stale
    # report the console's own comments guard against. UTC, as every
    # time the console shows is.
    return {"ready": all(c.ok for c in checks),
            "checks": [c.as_dict() for c in checks],
            "blocking_failures": [c.check for c in checks
                                  if c.blocking and not c.ok],
            "checked_at": datetime.now(timezone.utc).isoformat()}

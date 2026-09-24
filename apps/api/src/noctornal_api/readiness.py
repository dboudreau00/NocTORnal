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
from collections.abc import Callable
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
            f"NOCTORNAL_DESIGNATED_PERSON={person}. {disposition}. This is a "
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
    if disposition == "destroy":
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
    return [_register_facts(name, _guarded(name, action, lambda probe=probe: probe(conn)))
            for name, probe, action in _CHECKS]


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

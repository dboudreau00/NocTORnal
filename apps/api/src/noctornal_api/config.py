"""What a production deployment must have before this build will start.

Until 2026-09-10 nothing looked at the configuration at boot. An API
started with no `NOCTORNAL_TOTP_KEK`, no `NOCTORNAL_INGEST_PEPPER` and
`dev_only_change_me` still in its DSN came up, answered `/healthz` with
`{"status": "ok"}` and served the console -- and then failed one
operation at a time, days apart and to a different person each time: the
first enrolment raised on the KEK, the first ingest key raised on the
pepper, and the published password in the DSN was never going to raise at
all, because it works. Each of those arrives as "the enrolment endpoint is
broken" rather than "this deployment was never configured", which is this
codebase's signature defect -- a failure reported as the wrong thing --
with an operator holding the pager. `enforce_environment()` moves the
whole set to the one moment where it is cheap: before the process serves
anything.

## Configuration only. This function opens no sockets.

Every rule below reads the environment and nothing else. That is a
boundary, not an accident: a boot check that dialled Redis or MinIO would
turn a dependency's restart into a refusal to start, so a five-second
Redis blip during a rolling deploy would leave the operator with no API
at all -- an outage manufactured by the safety check. So this module
answers "is REDIS_URL set", and `readiness.py` answers "does Redis
answer, and is it an evictor". The two questions have different costs
when they are wrong and belong in different places.

`readiness.py` is the other half and deliberately overlaps: the KEK, the
pepper, the rate-limit off-switch, `REDIS_URL`, `MINIO_SECURE` and the
SMTP plaintext exception all appear in both. They must not be able to
disagree, so where a reader for a fact already exists this module borrows
it rather than copying its rule -- see `_borrowing`. What separates the
two is WHEN the question is asked, not how important the answer is.
Readiness is asked over and over while the process runs -- by an operator
opening `/admin/readiness`, and by `routers/collection.py`, which refuses
a collection run with 409 while a BLOCKING check is red -- so its verdict
can go red and green again under a live deployment. This is asked once,
before the process serves anything, and nothing downstream of it gets a
choice.

## Production only, and why the default is off

`NOCTORNAL_ENV` must be exactly `production` (case and surrounding space
aside) for any of this to apply. Unset -- the default -- means
development and every rule is skipped, no matter how bad the values are.

That is not timidity. CI's environment is deliberately the development
one: `.github/workflows/ci.yml` sets `dev_only_change_me` as the Postgres
password, leaves `MINIO_SECURE` unset and runs against a plaintext MinIO,
all of which are correct for a throwaway container and every one of which
is a refusal below. A check that fired there would be switched off within
a week, and a check that is switched off catches nothing -- which is the
argument `ruff.toml` makes about linters, applied to boot refusals.
`infra/production/compose.yml` sets `NOCTORNAL_ENV=production`; nothing
else in the tree does.

The sharp edge, stated plainly because it cannot be closed from here: a
misspelt value (`prod`, `Production ` is fine, `pruduction` is not) is
development, silently, and a deployment that meant to be production would
then start on whatever it was given. The refusals cannot default to ON
without breaking every laptop and CI run, so the mitigation is that the
value is written in exactly one file that ships with this repository.
Since 2026-09-23 (sec-dev-secrets-in-production) the readiness row
`credentials_not_published` asks `published_credentials` on every process
whatever this variable says, so a misspelt production running on a
published password is at least reported, if not refused.
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

#: The literal every development stack in this repository ships as its
#: password: `infra/docker-compose.yml`, `scripts/launch.ps1`,
#: `scripts/launch.sh`, `release/install.*`, the CI workflow and the
#: READMEs all set it. A production value equal to this is not a weak
#: password, it is a PUBLISHED one -- the attacker does not have to guess
#: it, they have to clone the repository.
DEV_CREDENTIAL = "dev_only_change_me"

#: The environment variable that turns the refusals on, and the one value
#: that does it.
ENV_VAR = "NOCTORNAL_ENV"
PRODUCTION = "production"

#: A variable is treated as carrying a credential when its NAME says so.
#:
#: The scan below walks the value of EVERY variable rather than a fixed
#: list of six, because a fixed list is a list of what the development
#: stack sets today: the moment somebody adds a seventh service with a
#: `dev_only_change_me` password, a list would go on passing the
#: deployment while the new secret sat published in git. Scanning values
#: catches the seventh for free.
#:
#: It refuses only where the name marks the value as a secret, though,
#: because the two errors are not symmetrical. Missing a credential means
#: booting with a published password. Refusing on a NON-credential --
#: a bucket name, a policy reference, a path that happens to contain the
#: string -- means an operator cannot start their API for a cosmetic
#: reason, at which point the next person to hit it sets NOCTORNAL_ENV to
#: something else and loses every refusal in this module, not just the one
#: that annoyed them. A false refusal here does not fail safe; it teaches
#: people to turn the safety off.
#:
#: `_URL` and `_DSN` are in the list because `DATABASE_URL` and
#: `REDIS_URL` embed their password in the value -- a URL is a credential
#: whenever it carries userinfo, and this deployment's two do.
_CREDENTIAL_NAME_MARKERS = (
    "PASSWORD", "SECRET", "TOKEN", "CREDENTIAL", "PEPPER", "KEK",
    "_KEY", "_URL", "_DSN",
)


def _carries_credential(name: str) -> bool:
    return any(marker in name.upper() for marker in _CREDENTIAL_NAME_MARKERS)


#: Names that hold the IDENTITY half of a credential pair rather than its
#: secret: MinIO's access key is the account name the secret belongs to,
#: a `_KEK_ID` labels a key without being one. `_KEY` marks all of them as
#: credentials above, but a published identity is not a leak: knowing that
#: an account is called `minioadmin` or `noctornal` opens nothing without
#: the secret beside it, and that secret is scanned in its own variable.
#: So the published-value rule below passes over them (the 2026-09-23
#: review of sec-dev-secrets-in-production found it refusing an operator
#: who kept MinIO's customary root user name with a strong password, which
#: is the false refusal the paragraph above warns about).
#:
#: A secret word in the name wins over the suffix, because
#: `AWS_SECRET_ACCESS_KEY` ends like an access key and is the secret.
#: `apps/api/tests/test_published_credentials.py` classifies the files it
#: scans with this same function, so the two cannot drift apart.
_IDENTITY_SUFFIXES = ("_ACCESS_KEY", "_USER", "_USERNAME", "_ROLE", "_ID")
_SECRET_WORDS = ("PASSWORD", "SECRET")


def _names_identity(name: str) -> bool:
    upper = name.upper()
    return (upper.endswith(_IDENTITY_SUFFIXES)
            and not any(word in upper for word in _SECRET_WORDS))


# ---------------------------------------------------------------------------
# Every credential value somebody has already published
# (sec-dev-secrets-in-production, 2026-09-23)
# ---------------------------------------------------------------------------
#
# Until 2026-09-23 the scan above knew ONE published value, DEV_CREDENTIAL,
# and this repository publishes more than one. A production deployment that
# copied infra/production/secrets.env.example and replaced nothing but the
# KEK started cleanly on `replace-me-redis-password`, a pepper lifted from a
# test file was a working pepper, the CI workflow's KEK sealed every second
# factor with a key printed in `.github/workflows/ci.yml`, and a REDIS_URL
# copied from `.env.local` pointed the limiter at a Redis that asks nobody
# for a password. Each of those is a secret an attacker reads rather than
# guesses. `published_credentials` is the one reader of the whole set:
# `verify_environment` refuses a production boot on it, and the readiness
# register's `credentials_not_published` row reports it on every process,
# so a deployment whose NOCTORNAL_ENV was misspelt is still told.
#
# The markers are matched inside a credential's value, case aside, because
# each is a fragment nobody generating a secret produces by accident and
# every place this repository writes one embeds it in something longer (a
# DSN, a `replace-me-<what>` label). `apps/api/tests/test_published_
# credentials.py` reads the files that publish them and fails if one of
# their credential values is not refused, so a new published value cannot
# be added to those files without this list learning it.
_PUBLISHED_MARKERS: tuple[tuple[str, str], ...] = (
    (DEV_CREDENTIAL,
     f"the development credential {DEV_CREDENTIAL!r}, which is committed to "
     f"this repository in infra/docker-compose.yml, the CI workflow and the "
     f"installers"),
    ("replace-me",
     "a 'replace-me' placeholder, which infra/production/secrets.env.example "
     "ships in place of every secret it asks for"),
    ("not-a-real-one",
     "the throwaway value the test suites and the demo seeders set (it ends "
     "'not-a-real-one')"),
)

#: Whole values a COMPONENT publishes rather than this repository: MinIO
#: starts on `minioadmin` for both halves of its root credential when it is
#: given none (infra/production/compose.yml says why that matters).
#: Matched as the whole value, not a fragment, and only in the secret half:
#: `minioadmin` as the root USER is MinIO's customary name and harmless
#: beside a strong password, which is also where MinIO's own
#: default-credential warning draws the line (see `_names_identity`).
_PUBLISHED_VALUES: dict[str, str] = {
    "minioadmin": "'minioadmin', the root credential MinIO starts on when it "
                  "is given none",
}

#: The short name each kind is listed under in the readiness evidence,
#: where one line has to carry several variables.
_PUBLISHED_LABELS: dict[str, str] = {
    DEV_CREDENTIAL: "the development password",
    "replace-me": "a secrets.env.example placeholder",
    "not-a-real-one": "the test suites' throwaway value",
    "minioadmin": "MinIO's built-in root credential",
    "kek": "a key of one repeated byte, as CI and the test suites publish",
    "redis": "no password, the development stack's shape",
}


@dataclass(frozen=True)
class PublishedCredential:
    """One variable carrying a value somebody has already published.

    `kind` is the marker, the vendor value, `kek` or `redis`; `refusal` is
    the whole sentence a production boot is refused with. Neither quotes
    the variable's value: a published marker is named, the secret around
    it never is.
    """
    variable: str
    kind: str
    refusal: str

    @property
    def label(self) -> str:
        return _PUBLISHED_LABELS[self.kind]


def _published_in(value: str) -> tuple[str, str] | None:
    """`(kind, description)` of the published value `value` carries, or None."""
    folded = value.lower()
    for marker, description in _PUBLISHED_MARKERS:
        if marker.lower() in folded:
            return marker, description
    whole = value.strip().lower()
    if whole in _PUBLISHED_VALUES:
        return whole, _PUBLISHED_VALUES[whole]
    return None


def _redis_url_without_password(url: str) -> bool:
    """A plain `redis://` URL with no password in it.

    `rediss://` and `unix://` are left alone on purpose: a TLS client
    certificate and a socket's file permissions are both ways to
    authenticate that put nothing in the URL, and refusing them would stop
    a correctly secured deployment for looking unlike ours.

    A `password` query argument counts as a password, because redis-py's
    `parse_url` passes it to the connection exactly as it does the
    userinfo one: `redis://redis:6379/0?password=...` authenticates, and
    refusing it at boot for "asking for no password" stopped a correctly
    secured deployment with a sentence that was false (c23, 2026-09-24).
    `parse_qs` drops a blank value as redis-py does, so `?password=` with
    nothing after it is still refused, and the name is matched exactly
    because redis-py matches it exactly.
    """
    parts = urlsplit(url)
    return (parts.scheme.lower() == "redis" and not parts.password
            and not parse_qs(parts.query).get("password"))


def published_credentials(env: Mapping[str, str] | None = None) -> list[PublishedCredential]:
    """Every credential in `env` that somebody has already published, one
    entry per variable, sorted by name. Reads `os.environ` by default and
    opens nothing.

    Mode-blind: it answers in development too, where the answer is
    expected to be long, because the readiness register reports it on every
    process and only `verify_environment` turns it into a refusal.
    """
    if env is None:
        env = os.environ
    found: dict[str, PublishedCredential] = {}
    for name in sorted(env):
        if not _carries_credential(name) or _names_identity(name):
            continue
        published = _published_in(env[name])
        if published is None:
            continue
        kind, description = published
        # A component's default is published by its documentation, not by
        # this repository's source, and the sentence says which.
        reader = ("MinIO's documentation" if kind in _PUBLISHED_VALUES
                  else "the source")
        found[name] = PublishedCredential(
            name, kind,
            f"{name} still carries {description}, so anyone who has read "
            f"{reader} already holds this deployment's secret.")

    redis_url = env.get("REDIS_URL", "").strip()
    if ("REDIS_URL" not in found and redis_url
            and _redis_url_without_password(redis_url)):
        found["REDIS_URL"] = PublishedCredential(
            "REDIS_URL", "redis",
            "REDIS_URL names a redis:// server that asks for no password, "
            "which is the development stack's shape (every installer writes "
            "redis://127.0.0.1:6379/0), so anything that can reach it can "
            "delete the limiter's meters, which admits whoever they were "
            "refusing, or fill it until every limit that fails closed refuses "
            "everyone.")

    # The KEK through the envelope's own reader, so "the key" means what
    # every seal means by it (a trailing newline and all). One byte
    # repeated is the shape of both keys this repository prints, CI's
    # base64 of 32 'A's and the suites' 32 zero bytes, and os.urandom has
    # a 2**-248 chance of producing it, so a refusal on it cannot fire on
    # a key anybody generated.
    if "NOCTORNAL_TOTP_KEK" not in found and env.get("NOCTORNAL_TOTP_KEK"):
        from noctornal_api.security.envelope import _load_kek

        with _borrowing(env, "NOCTORNAL_TOTP_KEK"):
            try:
                key = _load_kek()
            except (RuntimeError, ValueError):
                key = b""  # unusable; verify_environment says so on its own
        if key and len(set(key)) == 1:
            found["NOCTORNAL_TOTP_KEK"] = PublishedCredential(
                "NOCTORNAL_TOTP_KEK", "kek",
                "NOCTORNAL_TOTP_KEK decodes to one byte repeated 32 times, the "
                "shape of the key the CI workflow and the test suites publish "
                "and of no key a random generator produces, so every TOTP "
                "secret, persona credential and sample data key it seals opens "
                "for anyone who has read the source.")
    return [found[name] for name in sorted(found)]


#: The two legal declarations (docs/16 L1). Not credentials, so the scan
#: above passes over them, but secrets.env.example ships a placeholder in
#: both and `samples.policy_declared` accepts any non-empty string, so a
#: template copied as it stands declared a policy nobody wrote and turned
#: the blocking `prohibited_content_policy` row green on it.
_DECLARATIONS = ("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "NOCTORNAL_DESIGNATED_PERSON")


@contextmanager
def _borrowing(env: Mapping[str, str], *names: str) -> Iterator[None]:
    """Make `names` read out of `env` through `os.environ` for the body,
    then put `os.environ` back exactly as it was.

    The three readers this module borrows -- `envelope._load_kek`,
    `limits.rate_limiting_disabled` and `sessions.strict_binding_enabled`
    -- read the process environment, because at runtime that is where
    their value comes from. `verify_environment` takes a mapping instead,
    so a test can describe a whole production environment without setting
    one on the process running the test, and so the function stays a
    function of its argument. This is the one place the two meet, and it
    is deliberately three lines of swap rather than a copied rule.

    Copying was the alternative, and `readiness.py` documents at length
    what it costs: until 2026-09-02 `_totp_kek_set` said it called the
    envelope's reader and kept a private, stricter copy instead, so a KEK
    with a trailing newline -- what a Docker secret file routinely holds
    -- sealed every TOTP secret in the product and was reported not-ready
    with the wrong reason. The same mistake here would refuse to START an
    API whose KEK the envelope decrypts with every day -- the identical
    defect with the blast radius of a total outage, at the one moment
    nobody can override it. `NOCTORNAL_SESSION_STRICT_BINDING` is the
    concrete trap in the other direction: its
    reader strips before comparing, so a value of `" 1"` is ON as far as
    every session check is concerned, and a local test that forgot the
    strip would refuse a correctly configured deployment.

    Exactly the named variables move, and they are restored in a
    `finally`, absent ones included. Boot is single-threaded and so are
    the tests; nothing else is reading `os.environ` while this runs.
    """
    absent = object()
    saved: dict[str, object] = {name: os.environ.get(name, absent) for name in names}
    try:
        for name in names:
            value = env.get(name)
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, previous in saved.items():
            if previous is absent:
                os.environ.pop(name, None)
            else:
                os.environ[name] = str(previous)


def _truthy(value: str) -> bool:
    """`.lower() in {"1", "true"}`, with NO strip.

    Restated here rather than borrowed because neither variable it serves
    has a named reader to borrow: `app.py` writes this expression inline
    for `NOCTORNAL_ENABLE_DOCS` and `transports.py` writes it inline for
    `SMTP_ALLOW_PLAINTEXT`. Restated EXACTLY, missing strip and all, for a
    reason that looks backwards at first glance: `SMTP_ALLOW_PLAINTEXT=" 1"`
    does NOT enable plaintext as far as `transports.py` is concerned, so a
    tidier stripping test here would refuse to boot a deployment with
    nothing wrong with it. The strictness of a boot refusal has to be the
    strictness of the thing it is refusing on behalf of, not more.
    """
    return value.lower() in {"1", "true"}


# ---------------------------------------------------------------------------
# Upload caps: a policy, not a tunable (docs/08, "Exhibit size policy")
# ---------------------------------------------------------------------------
#
# Every accepted evidence byte is written once under a COMPLIANCE object
# lock that no credential can shorten, so the largest exhibit a deployment
# accepts is a decision about a permanent storage commitment. Until
# 2026-09-11 it was a module constant -- 256 MiB, changed by editing
# source -- which is a decision nobody in the deployment took. It is now
# DECLARED: read here, once, by the two upload routers at import; refused
# at a production boot when absent (`verify_environment`); reported by the
# readiness check `evidence_size_cap_declared`, which compares what the
# environment says now with what this process started with; and shown to
# the analyst beside the file picker (`GET .../evidence/policy`).
EVIDENCE_CAP_ENV = "NOCTORNAL_MAX_EVIDENCE_BYTES"
SAMPLE_CAP_ENV = "NOCTORNAL_MAX_SAMPLE_BYTES"
#: What a development deployment gets when it declares nothing.
DEFAULT_UPLOAD_CAP = 256 * 1024 * 1024
#: Below a mebibyte nothing real fits; above 64 GiB the number is a typo
#: about to become a permanent commitment.
CAP_FLOOR = 1024 * 1024
CAP_CEILING = 64 * 1024 * 1024 * 1024

#: Bytes, or a whole number with K, M or G -- binary, whatever suffix
#: follows the letter: `256MiB`, `256M`, `256MB` are all 256 * 2**20.
_SIZE = re.compile(r"^\s*(\d+)\s*(?:([KMG])(?:I?B)?|B)?\s*$", re.I)
_UNIT = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30}


def parse_size(text: str) -> int:
    """`268435456`, `256MiB`, `1GiB`, `512 M` -> bytes. ValueError otherwise."""
    match = _SIZE.match(text)
    if not match:
        raise ValueError(f"not a size: {text.strip()!r}")
    return int(match.group(1)) * _UNIT[(match.group(2) or "").upper()]


def cap_problem(name: str) -> str | None:
    """Why the declaration in `name` cannot be used, or None (unset counts
    as usable here: whether it may be unset is the caller's rule)."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = parse_size(raw)
    except ValueError:
        return (f"{name} is not a size (bytes, or a whole number with a "
                f"binary K, M or G, such as 512MiB)")
    if not CAP_FLOOR <= value <= CAP_CEILING:
        return f"{name} must be between 1 MiB and 64 GiB"
    return None


def cap_is_declared(name: str) -> bool:
    return bool(os.environ.get(name, "").strip())


def declared_cap(name: str, default: int = DEFAULT_UPLOAD_CAP) -> int:
    """The cap `name` declares, or `default` when it is unset.

    A value that is set and unusable raises at import, which is the loud
    direction: a typo in a cap must not quietly become 256 MiB.
    """
    problem = cap_problem(name)
    if problem:
        raise RuntimeError(
            f"{problem}; refusing to start with a cap this process cannot state")
    raw = os.environ.get(name, "").strip()
    return parse_size(raw) if raw else default


def verify_environment(env: Mapping[str, str] | None = None) -> list[str]:
    """Every reason this environment must not run a production deployment.

    Pure: it reads `env` (the process environment by default), opens
    nothing, and returns the refusals rather than raising, so the rules
    can be tested one at a time against a dictionary. `os.environ` is
    momentarily swapped for three borrowed readers and restored -- see
    `_borrowing` -- which is the only externally visible thing it touches.

    Returns `[]` for anything but `NOCTORNAL_ENV=production`, including
    unset. The module docstring says why that direction, and what it costs.

    Each refusal is one sentence naming the variable, what is wrong and
    what it costs, because an operator reading a wall of refusals at 03:00
    has to be able to decide from the sentence alone which one is the
    reason their deployment is down. No refusal quotes a VALUE: these are
    credentials, and this list goes into a container log, a screenshot and
    a support ticket.
    """
    if env is None:
        env = os.environ
    if env.get(ENV_VAR, "").strip().lower() != PRODUCTION:
        return []

    problems: list[str] = []

    # Sorted so the list is the same list on every process that reads the
    # same environment: `os.environ` iterates in whatever order the
    # process was handed, and two workers printing the same refusals in
    # different orders reads like two different faults.
    #
    # Every published value, not only DEV_CREDENTIAL, through the one
    # reader the readiness register also asks (sec-dev-secrets-in-
    # production, 2026-09-23). A variable refused here is not refused again
    # below for the same value: one variable, one refusal.
    published = published_credentials(env)
    problems.extend(p.refusal for p in published)
    already = {p.variable for p in published}

    for name in _DECLARATIONS:
        if "replace-me" in env.get(name, "").lower():
            problems.append(
                f"{name} still carries the placeholder "
                f"infra/production/secrets.env.example ships, so sample ingest "
                f"would run under a declaration nobody made: a placeholder is "
                f"not a reference an auditor can follow, and the readiness "
                f"register would report the prohibited-content policy as "
                f"declared (docs/16 L1).")

    # The verdict is `envelope._load_kek`'s, the reader every seal and
    # every open already calls; only the choice of sentence is local, and
    # it is chosen on whether the variable is set rather than by parsing
    # the reader's message. `_load_kek` raises RuntimeError for its own
    # refusals (unset, not 32 bytes) and lets binascii.Error -- a
    # ValueError -- through for a value even its lenient base64 decoder
    # cannot parse.
    from noctornal_api.security.envelope import _load_kek, ring

    kek_usable = True
    with _borrowing(env, "NOCTORNAL_TOTP_KEK"):
        try:
            _load_kek()
        except (RuntimeError, ValueError):
            kek_usable = False
            if "NOCTORNAL_TOTP_KEK" in already:
                pass  # the placeholder was the refusal; its shape is not news
            elif not env.get("NOCTORNAL_TOTP_KEK"):
                problems.append(
                    "NOCTORNAL_TOTP_KEK is not set, so no TOTP secret can be "
                    "sealed or opened: nobody can enrol, and nobody with an "
                    "enrolled account can complete a login.")
            else:
                problems.append(
                    "NOCTORNAL_TOTP_KEK is set but the envelope cannot use it "
                    "(it must be base64 decoding to exactly 32 bytes), so every "
                    "enrolment and every second factor fails at the point of "
                    "use rather than here.")

    # The rest of the ring, through its own reader and only once the
    # active key is usable (a second refusal about the same variable
    # would read as two faults). `ring()` refuses a retired entry that is
    # not `id=base64`, one that reuses the active id, or one whose key is
    # not 32 bytes -- by position and id, never by value.
    if kek_usable:
        with _borrowing(env, "NOCTORNAL_TOTP_KEK", "NOCTORNAL_TOTP_KEK_ID",
                        "NOCTORNAL_TOTP_KEK_RETIRED"):
            try:
                ring()
            except (RuntimeError, ValueError) as exc:
                problems.append(
                    f"the key ring is not usable ({exc}), so every blob sealed "
                    f"under a retired key (every TOTP secret, persona credential "
                    f"and sample data key from before a rotation) opens for "
                    f"nobody, and the process would otherwise start and find that "
                    f"out at the first login.")

    # `.strip()` because `ingest._pepper` strips: a pepper of one space is
    # unset as far as key issuance is concerned, and must be unset here.
    if not env.get("NOCTORNAL_INGEST_PEPPER", "").strip():
        problems.append(
            "NOCTORNAL_INGEST_PEPPER is not set, so ingest keys have no pepper "
            "to be HMAC'd with (docs/12) and every key this deployment issues "
            "would be an unusable credential its holder cannot authenticate with.")

    if not env.get("REDIS_URL", "").strip():
        problems.append(
            "REDIS_URL is not set, so rate limiting is per process and N uvicorn "
            "workers between them admit N times the configured rate: the login "
            "limit an attacker actually meets is the one this deployment thinks "
            "it set, multiplied by its own worker count.")

    # The limiter's own off-switch, not a copy of its off-value set:
    # `rate_limiting_disabled` is public precisely so that the readiness
    # register and this cannot disagree about what "off" means.
    from noctornal_api.http.limits import rate_limiting_disabled

    with _borrowing(env, "NOCTORNAL_RATELIMIT"):
        if rate_limiting_disabled():
            problems.append(
                "NOCTORNAL_RATELIMIT is set to an off value, so no limiter is "
                "built at all: login guessing is braked only by the account "
                "lockout, and the analytics endpoints are an unmetered "
                "CPU-bound path any authenticated session can pin.")

    if _truthy(env.get("SMTP_ALLOW_PLAINTEXT", "")):
        problems.append(
            "SMTP_ALLOW_PLAINTEXT is set, so a failed STARTTLS negotiation "
            "silently falls back to handing the relay this deployment's SMTP "
            "credentials and its case notifications in clear text (docs/07: "
            "never plaintext); it exists for a development Mailpit.")

    # The exact expression the clients write inline -- default "false", no
    # strip, equality against "true". `evidence.py`, `rawstore.py` and
    # `readiness.py` write it for MINIO_SECURE; `samples.py` writes the
    # same expression for SAMPLE_SECURE, which is why the two are asked
    # separately here rather than folded into one rule. Written the same
    # strict way on purpose: `MINIO_SECURE=" true"` builds a PLAINTEXT
    # client in every one of those readers, so it has to build a refusal
    # here. A more forgiving test would pass exactly the deployments that
    # talk to the object store in the clear while believing they do not.
    #
    # Neither message says the credentials cross the wire, because under
    # SigV4 the secret never does: what an interceptor gets is the bytes,
    # the access key id and a signature it can replay while the request is
    # still in date. That is bad enough to refuse on and it is what is
    # true, and a refusal an operator can disprove is a refusal they
    # discount the next time.
    if env.get("MINIO_SECURE", "false").lower() != "true":
        problems.append(
            'MINIO_SECURE is not "true", so the evidence client speaks plain '
            "HTTP: every exhibit's bytes cross the network in clear text, and "
            "each request carries a signature anything on the path can lift and "
            "replay against the evidence bucket until it expires.")
    if env.get("SAMPLE_SECURE", "false").lower() != "true":
        problems.append(
            'SAMPLE_SECURE is not "true", so the sample client speaks plain '
            "HTTP: live malware bytes cross the network in clear text, and each "
            "request's signature can be lifted off the wire and replayed against "
            "the sample bucket (docs/11).")

    base_url = env.get("NOCTORNAL_BASE_URL", "").strip()
    if not base_url:
        problems.append(
            "NOCTORNAL_BASE_URL is not set, so it defaults to "
            "http://127.0.0.1:8000: every emailed link points at the loopback "
            "of whichever container sent it, and the origin split compares the "
            "sample origin against a value no analyst's browser ever sees.")
    elif urlsplit(base_url).scheme != "https":
        problems.append(
            f"NOCTORNAL_BASE_URL is {urlsplit(base_url).scheme or 'not a URL'} "
            f"rather than https, so session cookies, TOTP codes and case "
            f"content travel unencrypted, and the emailed links this build "
            f"sends invite analysts to sign in over plain HTTP.")

    # `sessions.strict_binding_enabled` rather than a local test: its
    # reader strips and this must strip identically, or a deployment where
    # binding IS enforced would be refused for not enforcing it.
    from noctornal_api.security.sessions import strict_binding_enabled

    with _borrowing(env, "NOCTORNAL_SESSION_STRICT_BINDING"):
        if not strict_binding_enabled():
            problems.append(
                "NOCTORNAL_SESSION_STRICT_BINDING is not on, so a session token "
                "lifted from a log, a proxy or a workstation is accepted from "
                "any address and any client: 0058 records where each session "
                "was minted, and with the control off nothing ever compares a "
                "presentation against it, not even to audit the difference.")

    if _truthy(env.get("NOCTORNAL_ENABLE_DOCS", "")):
        problems.append(
            "NOCTORNAL_ENABLE_DOCS is set, so the full route inventory and every "
            "request and response shape of a law-enforcement case system is "
            "published unauthenticated at /api/v1/openapi.json.")

    # docs/11: the sample bucket has its OWN credentials, so that a
    # compromise of the evidence path does not reach the malware store and
    # a compromise of the malware store does not reach the exhibits.
    # `SampleStorage.__init__` falls back per variable -- `SAMPLE_ACCESS_KEY
    # or MINIO_ACCESS_KEY` -- so a deployment that sets one and forgets the
    # other is half-fallen-back and there is nothing at runtime that says
    # so: the client constructs, the puts succeed, and the two buckets
    # quietly share a blast radius. Reported per variable because that is
    # the granularity the fallback works at.
    #
    # `SAMPLE_ENDPOINT` falls back the same way and is deliberately NOT
    # refused: one object store serving two buckets is a legitimate
    # production shape, and it is the credentials docs/11 asks to be
    # separate, not the host.
    for name, evidence_twin in (("SAMPLE_ACCESS_KEY", "MINIO_ACCESS_KEY"),
                                ("SAMPLE_SECRET_KEY", "MINIO_SECRET_KEY")):
        if not env.get(name, "").strip():
            problems.append(
                f"{name} is not set, so SampleStorage silently falls back to "
                f"{evidence_twin} and the malware bucket is opened with the "
                f"evidence bucket's credentials (docs/11 requires the sample "
                f"bucket to have its own), and nothing at runtime reports the "
                f"fallback.")

    # docs/08, "Exhibit size policy". Every accepted evidence byte is
    # written once under a COMPLIANCE lock no credential can shorten, so
    # the largest exhibit a deployment accepts is a decision about a
    # permanent commitment, not a tunable with a sensible default. Refused
    # when it is not DECLARED, and when either cap is declared unusably --
    # the second through the routers' own reader, so this and the import
    # that follows it cannot disagree about what a size is.
    for name in (EVIDENCE_CAP_ENV, SAMPLE_CAP_ENV):
        with _borrowing(env, name):
            problem = cap_problem(name)
        if problem:
            problems.append(
                f"{problem}, so the upload route would refuse to import at all "
                f"rather than start with a cap it cannot state.")
    if not env.get(EVIDENCE_CAP_ENV, "").strip():
        problems.append(
            f"{EVIDENCE_CAP_ENV} is not set, so the largest exhibit this "
            f"deployment accepts (and locks under COMPLIANCE for the whole "
            f"retention period, which no credential can shorten) is a "
            f"default nobody here decided; declare it (docs/08, exhibit size "
            f"policy).")

    # The egress settings (docs/20 sections 6.3 and 6.5, 2026-09-24),
    # through the readers the route layer itself uses, so this and
    # route_for cannot disagree about what a usable value is. Neither
    # quotes the value.
    from noctornal_api import egress, egress_policy

    if egress.proxy_problem(env) is not None:
        problems.append(
            f"{egress.PROXY_URL_ENV} is not an http:// address with a host and a "
            f"port and nothing else, so no outbound connection could take a route "
            f"through the egress proxy ({egress_policy.DECISION_REF}).")
    try:
        egress_policy.internal_networks(env, production=True)
    except ValueError:
        problems.append(
            f"{egress_policy.INTERNAL_CIDRS_ENV} is not a comma list of networks, "
            f"so the deployment's own networks cannot be kept out of every route.")
    # F11 and F12, 2026-09-24. The static-triage and YARA settings,
    # through their one reader each, so the runner, readiness and this
    # cannot disagree about what is usable. Named, never quoted.
    from noctornal_api.lab_triage import analysis_settings
    from noctornal_api.yara_rules import yara_settings
    for reader, what in ((analysis_settings, "static triage"),
                         (yara_settings, "YARA scanning")):
        _settings, problem = reader(env)
        if problem:
            problems.append(
                f"{problem}, so {what} would run with limits nobody here "
                f"decided (the development defaults) or not at all.")

    # Collection ceilings (docs/00 decision 69, 2026-09-24). A ceiling SET
    # to a label the collector may not read at (invariant 8 caps it at
    # AMBER). Unset is valid: that collection is off. Through the module
    # the poll reads, so the two cannot disagree; no value is quoted.
    from noctornal_api.collection_authority import ceiling_problems

    problems.extend(ceiling_problems(env))

    # S2, the egress proxy (2026-09-24). With a proxy configured, the
    # keys this process needs to use it, read through the readers that use
    # them. Skipped for the sample origin, which makes no outbound
    # connection and holds no egress key. Whether anything goes outbound at
    # all is the start refusal's (egress_routes.enforce_production_egress,
    # from egress.outbound_uses): one reader of that. Nothing is quoted.
    problems.extend(_egress_key_problems(env))

    # Outbound integrations (F8, F7 and F15.2, 2026-09-24). The senders
    # refuse the same things at send time, because the cron that drains
    # never runs this check.
    webhook = env.get("NOCTORNAL_WEBHOOK_URL", "").strip()
    if webhook and not webhook.lower().startswith("https://"):
        problems.append(
            "NOCTORNAL_WEBHOOK_URL is not an https address, so every webhook would "
            "carry case summaries in the clear.")
    for flag, what in (("NOCTORNAL_WEBHOOK_ALLOW_HTTP", "a webhook"),
                       ("NOCTORNAL_JIRA_ALLOW_HTTP", "Jira")):
        if env.get(flag, "").strip():
            problems.append(
                f"{flag} is set, and it lets {what} be reached over plain http; it "
                f"exists for development and tests only.")
    ceiling = env.get("NOCTORNAL_JIRA_CEILING", "").strip()
    if ceiling and ceiling.upper() not in ("CLEAR", "GREEN", "AMBER"):
        problems.append(
            "NOCTORNAL_JIRA_CEILING is not CLEAR, GREEN or AMBER, so Jira would "
            "refuse everything rather than guess what it may hold.")
    # The Jira network (2026-09-25), parsed by the reader the
    # Jira route itself uses, so this and the route cannot disagree.
    from noctornal_api import jira as _jira
    _net, net_problem = _jira.jira_network(env)
    if net_problem is not None:
        problems.append(net_problem)
    for name in ("NOCTORNAL_JIRA_CA_FILE", "NOCTORNAL_LOOKUP_CA_FILE"):
        path = env.get(name, "").strip()
        if path and not (os.path.isfile(path) and os.access(path, os.R_OK)):
            problems.append(
                f"{name} names a file that does not exist or cannot be read, so "
                f"the private certificate authority it should add is missing.")
    lookups = env.get("NOCTORNAL_OUTBOUND_LOOKUPS", "").strip().lower()
    if lookups == "on" and egress.proxy_problem(env) is None \
            and not env.get(egress.PROXY_URL_ENV, "").strip():
        problems.append(
            f"NOCTORNAL_OUTBOUND_LOOKUPS is on and {egress.PROXY_URL_ENV} is not set, "
            f"so case selectors would leave from this host's own address instead of "
            f"through the egress proxy ({egress_policy.DECISION_REF}).")

    # F13, 2026-09-24. The hash-set authority is a legal declaration
    # like the two above, and secrets.env.example ships a placeholder in it;
    # the list cap is a size, read by the one size reader. Named, never
    # quoted.
    from noctornal_api.screening import AUTHORITY_ENV, LIST_CAP_ENV
    if "replace-me" in env.get(AUTHORITY_ENV, "").lower():
        problems.append(
            f"{AUTHORITY_ENV} still carries the placeholder "
            f"infra/production/secrets.env.example ships, so prohibited-content "
            f"hash lists would be imported under an authority nobody recorded "
            f"(docs/16 L1 item 5).")
    with _borrowing(env, LIST_CAP_ENV):
        list_problem = cap_problem(LIST_CAP_ENV)
    if list_problem:
        problems.append(
            f"{list_problem}, so the hash list import could not state the "
            f"largest list it takes.")
    # F14, 2026-09-24. The sandbox's settings, through their one
    # reader (sandbox.sandbox_settings), so the worker, readiness and this
    # cannot disagree. Named, never quoted.
    from noctornal_api.sandbox import production_problems
    problems.extend(production_problems(env))

    # The similarity settings (F6.1 and F6.2, 2026-09-24), through the
    # one reader of NOCTORNAL_EMBED_*, so this and the pass cannot disagree
    # about what a usable value is. No sentence quotes a value.
    from noctornal_api import embedders

    problems.extend(embedders.configured(env).problems)

    # F3 and F4 (forum adapters, 2026-09-24). The development override
    # that lets a forum be read with no egress proxy, from this host's own
    # address, has no place in production. Its value is not quoted.
    if env.get("NOCTORNAL_FORUM_ALLOW_DIRECT", "").strip():
        problems.append(
            "NOCTORNAL_FORUM_ALLOW_DIRECT is set, and it lets a forum be read "
            "from this server's own address with no egress proxy; it exists for "
            "development only.")

    # Row-level security (S1, 2026-09-25). Who holds the system role's
    # DSN, which bypasses row security. Named, never quoted.
    problems.extend(_row_security_problems(env))

    return problems


def _dsn_user(dsn: str) -> str | None:
    """The role a URL-style DSN names, or None when it names none."""
    from urllib.parse import urlsplit
    try:
        return urlsplit(dsn.strip()).username or None
    except ValueError:
        return None


def _row_security_problems(env: Mapping[str, str]) -> list[str]:
    """The production refusals row-level security needs (S1).

    The system connection (`db.connect_system`) is what retention, lock
    extension, legal holds, the withheld counts, merges, sign-in and every
    script run on, so a process without it cannot do that work, and one
    with it can read every row. So: required on every process except the
    sample origin; refused ON the sample origin, which serves hostile bytes
    and must never hold the bypass (compose sets it to ""); never the same
    role DATABASE_URL names, or the request role would be the bypass role;
    the initdb-only password on no runtime process; and the development
    switch that makes the suite assume the runtime roles never in
    production. Empty counts as unset everywhere."""
    from noctornal_api.db import ASSUME_ROLE_ENV, WORKER_DSN_ENV
    from noctornal_api.samples import origin_split

    problems: list[str] = []
    worker = env.get(WORKER_DSN_ENV, "").strip()
    with _borrowing(env, "NOCTORNAL_SAMPLE_ORIGIN", "NOCTORNAL_BASE_URL",
                    "NOCTORNAL_PUBLIC_ORIGIN"):
        sample_origin = origin_split().serves_here
    if sample_origin and worker:
        problems.append(
            f"{WORKER_DSN_ENV} is set on the sample origin, the process that "
            f"serves hostile bytes, and that connection bypasses row-level "
            f"security; leave it empty there (infra/production/compose.yml).")
    elif not sample_origin and not worker:
        problems.append(
            f"{WORKER_DSN_ENV} is not set, so retention, legal holds, lock "
            f"extension, merges, sign-in and every script would have no "
            f"connection that sees every row; point it at noctornal_worker.")
    request_user = _dsn_user(env.get("DATABASE_URL", ""))
    if worker and request_user and _dsn_user(worker) == request_user:
        problems.append(
            f"{WORKER_DSN_ENV} and DATABASE_URL name the same role, so every "
            f"request would run as the role that bypasses row-level security.")
    if env.get("NOCTORNAL_WORKER_DB_PASSWORD", "").strip():
        problems.append(
            "NOCTORNAL_WORKER_DB_PASSWORD is set on a runtime process; it is "
            "read once, by the database at initialisation "
            "(infra/production/postgres-init.env), and nothing else should "
            "hold it.")
    if env.get(ASSUME_ROLE_ENV, "").strip():
        problems.append(
            f"{ASSUME_ROLE_ENV} is set, and it makes this process switch roles "
            f"from the connection it was given; it exists for development and "
            f"tests only.")
    return problems


def _egress_key_problems(env: Mapping[str, str]) -> list[str]:
    """The egress client keys a production process with a proxy needs."""
    from noctornal_api import egress, egress_routes
    from noctornal_api.pinned_http import RouteUnavailable
    from noctornal_api.samples import origin_split
    from noctornal_api.security import egress_seal

    if egress.proxy_problem(env) is not None or egress.proxy_settings(env) is None:
        return []
    with _borrowing(env, "NOCTORNAL_SAMPLE_ORIGIN", "NOCTORNAL_BASE_URL",
                    "NOCTORNAL_PUBLIC_ORIGIN"):
        if origin_split().serves_here:
            return []
    problems = []
    try:
        egress_routes.client_key(env)
    except RouteUnavailable as exc:
        problems.append(str(exc))
    try:
        egress_seal.fingerprint_key(env)
    except egress_seal.SealError:
        problems.append(
            f"{egress_seal.FINGERPRINT_KEY_ENV} is not base64 of 32 bytes, so no egress "
            f"exit can be sealed and a sealed one cannot be matched with what the "
            f"proxy opens.")
    if env.get(egress_seal.SEAL_PUBLIC_ENV, "").strip():
        try:
            egress_seal.load_public(env[egress_seal.SEAL_PUBLIC_ENV])
        except egress_seal.SealError:
            problems.append(
                f"{egress_seal.SEAL_PUBLIC_ENV} is not a 32 byte X25519 public key, so "
                f"no egress exit can be sealed for the proxy.")


    return problems


def enforce_environment(env: Mapping[str, str] | None = None) -> None:
    """Refuse to continue when `verify_environment` found anything.

    Does nothing at all unless `NOCTORNAL_ENV=production`, because
    `verify_environment` returns `[]` for every other value. The mode is
    read in ONE place for the same reason every other fact in this module
    has one reader: an `enforce` that tested for production itself could
    end up enforcing on an environment `verify` had already excused.

    The RuntimeError names EVERY problem at once. An operator told only
    the first one restarts, is told the second, restarts, is told the
    third -- and each of those restarts is a production API not answering,
    so a first-deployment misconfiguration turns into an evening of
    self-inflicted outages. The list is what makes it one fix.
    """
    problems = verify_environment(env)
    if not problems:
        return
    listed = "\n".join(f"  - {problem}" for problem in problems)
    raise RuntimeError(
        f"{ENV_VAR}={PRODUCTION}, and this environment is not one this build "
        f"will start on:\n{listed}\n"
        # Agreed with the count rather than a bracketed plural (README
        # screenshot set review, 2026-09-23). One problem is still said to
        # be the only one, which is the point of listing them all.
        + ("The one problem found is listed above. There is no second one "
           "waiting behind it. " if len(problems) == 1 else
           f"All {len(problems)} problems found are listed above. There is "
           f"no further one waiting behind them. ")
        + f"Unset {ENV_VAR} to run as "
        f"development, which is what a laptop and CI do."
    )

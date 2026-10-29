"""What a production deployment must have before this build will start.

`enforce_environment()` moves a set of configuration failures to the one moment where they are
cheap: before the process serves anything. Otherwise an API with no `NOCTORNAL_TOTP_KEK`, no
`NOCTORNAL_INGEST_PEPPER` or `dev_only_change_me` still in its DSN comes up healthy and fails one
operation at a time, each reported as "the endpoint is broken" instead of "this deployment was never
configured".

Configuration only: every rule reads the environment and opens no sockets, because a boot check that
dialled Redis or MinIO would turn a dependency's restart into a refusal to start. This module
answers "is REDIS_URL set"; `readiness.py` answers "does Redis answer, and is it an evictor". The
two overlap on purpose (the KEK, the pepper, the rate-limit off-switch, `REDIS_URL`, `MINIO_SECURE`,
the SMTP plaintext exception), so where a reader for a fact already exists this module borrows it
(`_borrowing`) and the two cannot disagree. What separates them is when the question is asked:
readiness repeatedly while the process runs, this once, before it serves anything.

Production only: `NOCTORNAL_ENV` must be exactly `production` (case and surrounding space aside);
unset, the default, means development and every rule is skipped. CI's environment is deliberately
the development one (`.github/workflows/ci.yml` uses `dev_only_change_me` and a plaintext MinIO),
and a check that fired there would be switched off. `infra/production/compose.yml` is the only file
that sets it. The sharp edge: a misspelt value (`pruduction`) is development, silently. The
readiness row `credentials_not_published` asks `published_credentials` on every process whatever
this variable says, so a misspelt production running on a published password is at least reported.
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

#: The literal every development stack in this repository ships as its password
#: (`infra/docker-compose.yml`, `scripts/launch.ps1`, `scripts/launch.sh`, `release/install.*`, the
#: CI workflow, the READMEs). A production value equal to it is not a weak password but a PUBLISHED
#: one: the attacker only has to clone the repository.
DEV_CREDENTIAL = "dev_only_change_me"

#: The environment variable that turns the refusals on, and the one value
#: that does it.
ENV_VAR = "NOCTORNAL_ENV"
PRODUCTION = "production"


def is_production(env: Mapping[str, str] | None = None) -> bool:
    """Whether `env` (the process environment by default) is a production deployment:
    `NOCTORNAL_ENV` is `production`, case and surrounding space aside, and nothing else is (a
    misspelt value is development).

    The one reader of the mode: every module that asks calls this instead of spelling the
    comparison, so two readings of one variable cannot disagree
    (apps/api/tests/test_duplicated_rules.py holds the tree to it)."""
    source = os.environ if env is None else env
    return source.get(ENV_VAR, "").strip().lower() == PRODUCTION


#: A variable is treated as carrying a credential when its NAME says so. The scan walks the value of
#: EVERY variable rather than a fixed list, so a new service with a `dev_only_change_me` password is
#: caught without editing a list. It refuses only where the name marks a secret: a false refusal on
#: a bucket name or a path teaches operators to turn the safety off, while a missed credential boots
#: with a published password. `_URL` and `_DSN` are listed because `DATABASE_URL` and `REDIS_URL`
#: embed their password.
_CREDENTIAL_NAME_MARKERS = (
    "PASSWORD", "SECRET", "TOKEN", "CREDENTIAL", "PEPPER", "KEK",
    "_KEY", "_URL", "_DSN",
)


def _carries_credential(name: str) -> bool:
    return any(marker in name.upper() for marker in _CREDENTIAL_NAME_MARKERS)


#: Names that hold the IDENTITY half of a credential pair, not its secret: MinIO's access key is the
#: account name, a `_KEK_ID` labels a key without being one. `_KEY` marks them as credentials above,
#: but a published identity opens nothing without the secret beside it, which is scanned in its own
#: variable, so the published-value rule below passes over them. A secret word in the name wins over
#: the suffix: `AWS_SECRET_ACCESS_KEY` ends like an access key and is the secret.
#: `apps/api/tests/test_published_credentials.py` classifies the files it scans with this same
#: function.
_IDENTITY_SUFFIXES = ("_ACCESS_KEY", "_USER", "_USERNAME", "_ROLE", "_ID")
_SECRET_WORDS = ("PASSWORD", "SECRET")


def _names_identity(name: str) -> bool:
    upper = name.upper()
    return (upper.endswith(_IDENTITY_SUFFIXES)
            and not any(word in upper for word in _SECRET_WORDS))


# Every credential value this repository already publishes (an example secrets file, a pepper lifted
# from a test file, the CI workflow's KEK, a REDIS_URL from `.env.local`) is a secret an attacker
# reads rather than guesses. `published_credentials` is the one reader of the whole set:
# `verify_environment` refuses a production boot on it, and the readiness row
# `credentials_not_published` reports it on every process. Markers are matched inside a credential's
# value, case aside, because each is a fragment nobody generating a secret produces by accident.
# `apps/api/tests/test_published_credentials.py` fails if a credential value in the files that
# publish them is not refused, so a new published value cannot be added without this list learning
# it.
_PUBLISHED_MARKERS: tuple[tuple[str, str], ...] = (
    (DEV_CREDENTIAL,
     f"the development credential {DEV_CREDENTIAL!r}, which is committed to "
     f"this repository in infra/docker-compose.yml, the CI workflow and the "
     f"installers"),
    # "And the templates beside it": the placeholder also ships in postgres-init.env.example and
    # migrate.env.example, and the migration job refuses it there.
    ("replace-me",
     "a 'replace-me' placeholder, which infra/production/secrets.env.example "
     "and the templates beside it ship in place of every secret they ask for"),
    ("not-a-real-one",
     "the throwaway value the test suites and the demo seeders set (it ends "
     "'not-a-real-one')"),
)

#: Whole values a COMPONENT publishes rather than this repository: MinIO starts on `minioadmin` for
#: both halves of its root credential when given none (infra/production/compose.yml says why that
#: matters). Matched as the whole value and only in the secret half: `minioadmin` as the root USER
#: is MinIO's customary name and harmless beside a strong password, which is where MinIO's own
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

    `rediss://` and `unix://` are left alone: a TLS client certificate and a socket's file
    permissions authenticate without putting anything in the URL. A `password` query argument counts
    as a password, because redis-py's `parse_url` passes it to the connection as it does the
    userinfo one. `parse_qs` drops a blank value as redis-py does, so `?password=` with nothing
    after it is still refused.
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

    # The KEK through the envelope's own reader, so "the key" means what every seal means by it. One
    # byte repeated is the shape of both keys this repository prints (CI's base64 of 32 'A's and the
    # suites' 32 zero bytes), and os.urandom has a 2**-248 chance of producing it, so a refusal on
    # it cannot fire on a key anybody generated.
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
    # The persona key gets the same shape test: the suites publish 32 bytes of 0x01 for it. Decoded
    # with the envelope's lenient reader rather than the persona ring's, which refuses outside the
    # collector in production and would hide it.
    persona = env.get("NOCTORNAL_PERSONA_KEK", "")
    if "NOCTORNAL_PERSONA_KEK" not in found and persona.strip():
        from noctornal_api.security.envelope import _decode_key

        try:
            key = _decode_key(persona, name="NOCTORNAL_PERSONA_KEK")
        except (RuntimeError, ValueError):
            key = b""
        if key and len(set(key)) == 1:
            found["NOCTORNAL_PERSONA_KEK"] = PublishedCredential(
                "NOCTORNAL_PERSONA_KEK", "kek",
                "NOCTORNAL_PERSONA_KEK decodes to one byte repeated 32 times, "
                "the shape of the key the test suites publish and of no key a "
                "random generator produces, so every persona credential it "
                "seals opens for anyone who has read the source.")
    return [found[name] for name in sorted(found)]


#: The two legal declarations (docs/16 L1). Not credentials, so the scan above passes over them, but
#: secrets.env.example ships a placeholder in both and `samples.policy_declared` accepts any
#: non-empty string, so a template copied as it stands would turn the blocking
#: `prohibited_content_policy` row green.
_DECLARATIONS = ("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "NOCTORNAL_DESIGNATED_PERSON")


@contextmanager
def _borrowing(env: Mapping[str, str], *names: str) -> Iterator[None]:
    """Make `names` read out of `env` through `os.environ` for the body, then restore `os.environ`
    exactly.

    The readers this module borrows (`envelope._load_kek`, `limits.rate_limiting_disabled`,
    `sessions.strict_binding_enabled`) read the process environment, while `verify_environment`
    takes a mapping so a test can describe a whole production environment. This swap is the one
    place the two meet. Copying the rules instead would let them disagree and refuse to START an API
    whose KEK the envelope opens every day (a KEK with a trailing newline, as a Docker secret file
    holds, is the case), or refuse a correct `NOCTORNAL_SESSION_STRICT_BINDING` whose reader strips
    before comparing.

    Exactly the named variables move and are restored in a `finally`, absent ones included. Boot is
    single-threaded, as are the tests.
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

    Restated here because neither variable it serves (`NOCTORNAL_ENABLE_DOCS` in `app.py`,
    `SMTP_ALLOW_PLAINTEXT` in `transports.py`) has a named reader to borrow. The missing strip is
    deliberate: `SMTP_ALLOW_PLAINTEXT=" 1"` does not enable plaintext there, so a stripping test
    here would refuse to boot a sound deployment. A boot refusal is exactly as strict as the thing
    it refuses for.
    """
    return value.lower() in {"1", "true"}


# Upload caps are a policy, not a tunable (docs/08, "Exhibit size policy"). Every accepted evidence
# byte is written once under a COMPLIANCE object lock no credential can shorten, so the largest
# exhibit is a decision about a permanent storage commitment. The cap is declared: read here once by
# the two upload routers at import, refused at a production boot when absent (`verify_environment`),
# reported by the readiness check `evidence_size_cap_declared`, and shown to the analyst beside the
# file picker (`GET .../evidence/policy`).
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


def verify_environment(env: Mapping[str, str] | None = None, *,
                       collector: bool = False, outbound: bool = True) -> list[str]:
    """Every reason this environment must not run a production deployment.

    `collector` is True only from scripts/collector.py: the one process that must hold the persona
    key, where every other must not (`persona_key_problems`). `outbound` is False from a job that
    sends nothing out and is given no egress proxy (scripts/lab_triage.py); the sample origin is
    recognised by its origin, as `egress_routes.enforce_production_egress` recognises it. Neither is
    refused for an outbound integration with no proxy: both read secrets.env, where the operator
    turns lookups and the sandbox on for the processes that send them.

    Pure: it reads `env` (the process environment by default), opens nothing, and returns the
    refusals rather than raising, so each rule can be tested against a dictionary. The only thing it
    touches is `os.environ`, momentarily swapped for the borrowed readers (see `_borrowing`).
    Returns `[]` for anything but `NOCTORNAL_ENV=production`, including unset; the module docstring
    says why.

    Each refusal is one sentence naming the variable, what is wrong and what it costs, so an
    operator can decide from the sentence alone. No refusal quotes a VALUE: these are credentials,
    and this list goes into a container log, a screenshot and a support ticket.
    """
    if env is None:
        env = os.environ
    if not is_production(env):
        return []

    problems: list[str] = []

    # Sorted so every process reading the same environment prints the same list: `os.environ`
    # iterates in whatever order the process was handed, and differing orders read like different
    # faults.
    #
    # Every published value goes through the one reader the readiness register also asks. A variable
    # refused here is not refused again below for the same value: one variable, one refusal.
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

    # The first-run door's token (`http/setup_token.py`). Optional: unset, a production deployment
    # has no web first-run at all. A short one is a lock that opens by asking, so it is refused
    # rather than guessed. The length is `setup_token.MIN_TOKEN_CHARS`, written out because this
    # module must not import the HTTP package.
    setup_token = env.get("NOCTORNAL_SETUP_TOKEN", "").strip()
    if setup_token and len(setup_token) < 32 and "NOCTORNAL_SETUP_TOKEN" not in already:
        problems.append(
            "NOCTORNAL_SETUP_TOKEN is set but shorter than 32 characters, so "
            "the first-run door it guards could be opened by guessing it: "
            "generate one with `openssl rand -hex 32`, or leave it unset and "
            "create the first account with scripts/bootstrap.py create-user.")

    # The verdict is `envelope._load_kek`'s, the reader every seal and open calls; only the choice
    # of sentence is local, chosen on whether the variable is set rather than by parsing the
    # reader's message. `_load_kek` raises RuntimeError for its own refusals (unset, not 32 bytes)
    # and lets binascii.Error (a ValueError) through for a value even its lenient base64 decoder
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

    # The rest of the ring, through its own reader and only once the active key is usable (a second
    # refusal about the same variable would read as two faults). `ring()` refuses a retired entry
    # that is not `id=base64`, reuses the active id, or whose key is not 32 bytes, by position and
    # id, never by value.
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

    # The exact expression the clients write inline: default "false", no strip, equality against
    # "true". `evidence.py`, `rawstore.py` and `readiness.py` write it for MINIO_SECURE;
    # `samples.py` writes the same for SAMPLE_SECURE, so the two are asked separately. Strict on
    # purpose: `MINIO_SECURE=" true"` builds a PLAINTEXT client in every one of those readers, so a
    # more forgiving test here would pass exactly the deployments that talk to the object store in
    # the clear.
    #
    # Neither message says the credentials cross the wire: under SigV4 the secret never does. What
    # an interceptor gets is the bytes, the access key id and a signature it can replay while the
    # request is in date, which is enough to refuse on and is true.
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
    # The preservation store falls back to SAMPLE_SECURE when its own is unset
    # (samples.PreservationStorage), so only a value SET and not "true" is refused.
    preserve_secure = env.get("PRESERVE_SECURE")
    if preserve_secure and preserve_secure.lower() != "true":
        problems.append(
            'PRESERVE_SECURE is set and not "true", so the preservation client '
            "speaks plain HTTP: rejected samples under a legal hold cross the "
            "network in clear text (docs/11).")

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

    # docs/11: the sample bucket has its OWN credentials, so a compromise of the evidence path does
    # not reach the malware store or the reverse. `SampleStorage.__init__` falls back per variable
    # (`SAMPLE_ACCESS_KEY or MINIO_ACCESS_KEY`), so a deployment that sets one and forgets the other
    # is half-fallen-back with nothing at runtime to say so; hence reported per variable.
    # `SAMPLE_ENDPOINT` falls back the same way and is deliberately NOT refused: one object store
    # serving two buckets is legitimate, and docs/11 asks for separate credentials, not a separate
    # host.
    for name, evidence_twin in (("SAMPLE_ACCESS_KEY", "MINIO_ACCESS_KEY"),
                                ("SAMPLE_SECRET_KEY", "MINIO_SECRET_KEY")):
        if not env.get(name, "").strip():
            problems.append(
                f"{name} is not set, so SampleStorage silently falls back to "
                f"{evidence_twin} and the malware bucket is opened with the "
                f"evidence bucket's credentials (docs/11 requires the sample "
                f"bucket to have its own), and nothing at runtime reports the "
                f"fallback.")

    # docs/08, "Exhibit size policy". Every accepted evidence byte is written once under a
    # COMPLIANCE lock no credential can shorten, so the cap is a decision about a permanent
    # commitment, not a tunable with a default. Refused when not DECLARED and when either cap is
    # unusable, the second through the routers' own reader so this and the import that follows
    # cannot disagree about what a size is.
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

    # The egress settings (docs/20 sections 6.3 and 6.5), through the readers the route layer itself
    # uses, so this and route_for cannot disagree about what a usable value is. Neither quotes the
    # value.
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
    # The static-triage and YARA settings, through their one reader each, so the runner, readiness
    # and this cannot disagree about what is usable. Named, never quoted.
    from noctornal_api.lab_archive import archive_settings
    from noctornal_api.lab_triage import analysis_settings
    from noctornal_api.yara_rules import yara_settings
    for reader, what in ((analysis_settings, "static triage"),
                         (yara_settings, "YARA scanning"),
                         (archive_settings, "archive expansion")):
        _settings, problem = reader(env)
        if problem:
            problems.append(
                f"{problem}, so {what} would run with limits nobody here "
                f"decided (the development defaults) or not at all.")
    # Where hostile input is parsed, through the runner's one reader. Only a value SET and unusable
    # is refused here: an unset socket in production refuses every analysis at the point of use and
    # readiness says so, but does not stop the console starting (docs/00 says why). Named, never
    # quoted.
    from noctornal_api.analysis_runner import setting_problem
    runner_problem = setting_problem(env)
    if runner_problem:
        problems.append(
            f"{runner_problem}, so static triage and forum parsing would refuse "
            f"every request rather than guess where to run.")

    # Collection ceilings (docs/00 decision 69). A ceiling SET to a label the collector may not read
    # at (invariant 8 caps it at AMBER) is refused. Unset is valid: that collection is off. Through
    # the module the poll reads, so the two cannot disagree; no value is quoted.
    from noctornal_api.collection_authority import ceiling_problems

    problems.extend(ceiling_problems(env))

    # The egress proxy: with a proxy configured, the keys this process needs to use it, read through
    # the readers that use them. Skipped for the sample origin, which makes no outbound connection
    # and holds no egress key. Whether anything goes outbound at all is the start refusal's
    # (egress_routes.enforce_production_egress, from egress.outbound_uses): one reader of that.
    # Nothing is quoted.
    problems.extend(_egress_key_problems(env))

    # Outbound integrations. The senders refuse the same things at send time, because the cron that
    # drains never runs this check.
    webhook = env.get("NOCTORNAL_WEBHOOK_URL", "").strip()
    if webhook and not webhook.lower().startswith("https://"):
        problems.append(
            "NOCTORNAL_WEBHOOK_URL is not an https address, so every webhook would "
            "carry case summaries in the clear.")
    # The webhook signature scheme, read by the reader the sender uses, so this and the drain cannot
    # disagree. The secret is only asked for once there is a webhook to sign; a value that is
    # neither v1 nor v2 is refused whether or not one is configured.
    from noctornal_api import transports as _transports
    _version, _sig_problem = _transports.webhook_signature_version(env)
    if _sig_problem is None and webhook:
        _sig_problem = _transports.webhook_signature_problem(env)
    if _sig_problem is not None:
        problems.append(_sig_problem)
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
    # The Jira network, parsed by the reader the Jira route itself uses, so the two cannot disagree.
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
    from noctornal_api.egress_routes import _serves_samples
    sends = outbound and not _serves_samples(env)
    lookups = env.get("NOCTORNAL_OUTBOUND_LOOKUPS", "").strip().lower()
    if sends and lookups == "on" and egress.proxy_problem(env) is None \
            and not env.get(egress.PROXY_URL_ENV, "").strip():
        problems.append(
            f"NOCTORNAL_OUTBOUND_LOOKUPS is on and {egress.PROXY_URL_ENV} is not set, "
            f"so case selectors would leave from this host's own address instead of "
            f"through the egress proxy ({egress_policy.DECISION_REF}).")

    # The hash-set authority is a legal declaration like the two above, and secrets.env.example
    # ships a placeholder in it; the list cap is a size, read by the one size reader. Named, never
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
    # The sandbox's settings, through their one reader (sandbox.sandbox_settings), so the worker,
    # readiness and this cannot disagree. Named, never quoted.
    from noctornal_api.sandbox import production_problems
    problems.extend(production_problems(env, sends=sends))

    # The similarity settings, through the one reader of NOCTORNAL_EMBED_*, so this and the pass
    # cannot disagree about what a usable value is. No sentence quotes a value.
    from noctornal_api import embedders

    problems.extend(embedders.configured(env).problems)

    # The development override that lets a forum be read with no egress proxy, from this host's own
    # address, has no place in production. Its value is not quoted.
    if env.get("NOCTORNAL_FORUM_ALLOW_DIRECT", "").strip():
        problems.append(
            "NOCTORNAL_FORUM_ALLOW_DIRECT is set, and it lets a forum be read "
            "from this server's own address with no egress proxy; it exists for "
            "development only.")

    # The second person on a case's merge switch, through its one reader, so the decide route and
    # this cannot disagree about what a usable value is. A malformed value is held to the default at
    # runtime, never to 0; this makes the typo visible at boot. Not quoted.
    from noctornal_api.approvals import relax_seasoning

    _window, relax_problem = relax_seasoning(env)
    if relax_problem:
        problems.append(relax_problem)

    # Row-level security: who holds the system role's DSN, which bypasses it. Named, never quoted.
    problems.extend(_row_security_problems(env))

    # Who holds the persona key.
    problems.extend(persona_key_problems(env, collector=collector))

    # The schema owner's credential on a runtime process (docs/17). One variable, one refusal: a
    # published value in it has already been refused above.
    problems.extend(owner_credential_problems(env, skip=already))

    return problems


# The schema owner's credential (docs/17). The owner role `noctornal` is the Postgres image's
# bootstrap superuser: row-level security does not bind it, and it can `ALTER TABLE ... DISABLE
# TRIGGER` on the append-only audit and custody tables in one statement. Its password
# (POSTGRES_PASSWORD) and DSN (NOCTORNAL_MIGRATION_DATABASE_URL) live in postgres-init.env (the
# database alone) and migrate.env (the migration job alone), never in secrets.env, which every
# application service and caddy read. A runtime process that still holds either is refused here
# rather than trusted to ignore it. The sentence names the fix and never the value.
OWNER_PASSWORD_ENV = "POSTGRES_PASSWORD"
MIGRATION_DSN_ENV = "NOCTORNAL_MIGRATION_DATABASE_URL"

#: The installers' upgrade step, named in every sentence that needs it. It runs with sudo: the files
#: it rewrites are root's, mode 600, so run as anybody else it can read none of them.
SECRETS_STEP = ("sudo bash release/install.sh --production-secrets (release/install.ps1 "
                "-ProductionSecrets on Windows)")
#: The upgrade note every refusal of the old layout points at.
SECRETS_UPGRADE_NOTE = "release/secrets-upgrade/README.md"


def owner_credential_problems(env: Mapping[str, str] | None = None, *,
                              skip: frozenset[str] | set[str] = frozenset()
                              ) -> list[str]:
    """Refusals for a RUNTIME process holding the schema owner's password or DSN (docs/17).
    Mode-blind and pure, like `published_credentials`: `verify_environment` applies it in
    production, and a cron script may call it for its own refusal. Empty counts as unset. A variable
    in `skip` was refused already, for its value, and is not refused twice."""
    if env is None:
        env = os.environ
    problems: list[str] = []
    for name, home, reader in (
            (OWNER_PASSWORD_ENV, "infra/production/postgres-init.env",
             "the database (at initialisation)"),
            (MIGRATION_DSN_ENV, "infra/production/migrate.env",
             "the migration job")):
        if name not in skip and env.get(name, "").strip():
            problems.append(
                f"{name} is set on a runtime process, and it is the schema owner's "
                f"credential, which row-level security does not bind and which can "
                f"switch off the append-only triggers on the audit and custody "
                f"tables; since docs/17 F52 it belongs in {home}, which only "
                f"{reader} reads, so remove it from this process's environment: for "
                f"the compose deployment, {SECRETS_STEP} moves it there and keeps a "
                f"backup ({SECRETS_UPGRADE_NOTE}).")
    return problems


#: The exit status of a job that refuses to run on its environment, one number for every job. It is
#: 2, not 1, because 1 means a pass RAN and something in it failed, so an alert can tell "would not
#: start" from "ran and had a bad pass". `argparse` also uses 2 for a usage error; the first words
#: of the line (the job's name, then `refusing to run`) say which it was.
JOB_REFUSAL_EXIT = 2


def refuse_unsafe_job_environment(job: str, env: Mapping[str, str] | None = None,
                                  *, holds_owner_credential: bool = False,
                                  holds_persona_key: bool = False,
                                  whole_environment: bool = False,
                                  outbound: bool = True
                                  ) -> list[str]:
    """Why the job `job` must not run here: one line per problem, each led by the job's name, naming
    variables and never a value. `[]` outside NOCTORNAL_ENV=production, as `verify_environment` is.

    The ONE refusal for every job that is not the API, called once, first, before anything is read
    or connected to, by collection_poll, notify_drain, lookup_drain, embed_pass, the collector
    (scripts/collector.py) and the migration job (through `migration_job_problems` in
    scripts/migrate_job.py, and again at the top of db/migrations/env.py, so a bare `alembic` is
    held to it too). The Lab's workers (lab_triage, sample_screen, sandbox_dispatch) hold the sample
    store's credentials, the key ring and the sandbox token, so they ask for the API's whole list
    (`whole_environment=True`: `verify_environment`, which replaces the narrower questions below). A
    caller prints the lines on stderr and exits `JOB_REFUSAL_EXIT`. `outbound=False` is
    lab_triage's, which sends nothing out and is given no egress proxy (`verify_environment` says
    what that excuses).

    Two refusals every job needs, as the API makes them: a credential somebody has already
    published, and the schema owner's password or DSN, which no runtime process may hold. One
    helper, so the jobs cannot drift apart. `holds_owner_credential` is for the migration job, the
    schema owner's by design: it holds the owner's DSN because that is what it connects with, so the
    owner half is not asked of it, but the published half is, DSN included.

    A third, from the persona key's split (docs/00 decision 174): a job that is not the collector
    holds no persona key and no mark of the collector, and the inline mode that runs persona acts in
    the API is no setting for any production process (`persona_key_problems`). `holds_persona_key`
    is for the two jobs that are the key's by design, the collector and the poll it starts as a
    child: the key half is not asked of them here, and each makes the collector's own half (the mark
    present and the ring usable) in its own way. They are still refused a published credential and
    the owner's, and the collector never receives the owner's credential."""
    if env is None:
        env = os.environ
    if not is_production(env):
        return []
    if whole_environment:
        return [f"{job}: refusing to run: {problem}"
                for problem in verify_environment(env, outbound=outbound)]
    published = published_credentials(env)
    problems = [p.refusal for p in published]
    if not holds_owner_credential:
        problems.extend(owner_credential_problems(
            env, skip={p.variable for p in published}))
    if not holds_persona_key:
        problems.extend(persona_key_problems(env, collector=False))
    return [f"{job}: refusing to run: {problem}" for problem in problems]


def migration_job_problems(env: Mapping[str, str] | None = None) -> list[str]:
    """Why the production migration job must not run (docs/17): one line per problem, each led by
    `migrate:`. Returns `[]` outside `NOCTORNAL_ENV=production`, like `verify_environment`.

    The job is the one process that holds the owner's DSN, so the refusal of a published owner
    password is made here: otherwise moving the credential out of the API's sight would also move it
    out of the check's. That refusal, and the published half for every other variable the job holds,
    is `refuse_unsafe_job_environment` with the owner half switched off, as every other job makes
    it; what is left here is what only this job needs, a DSN to connect with that names a role."""
    if env is None:
        env = os.environ
    if not is_production(env):
        return []
    dsn = env.get(MIGRATION_DSN_ENV, "").strip()
    if not dsn:
        return [
            f"migrate: {MIGRATION_DSN_ENV} is not set for the migration job: since "
            f"docs/17 F52 (2026-10-02) the schema owner's DSN lives in "
            f"infra/production/migrate.env, which only this job reads, rather than "
            f"in secrets.env, and {SECRETS_STEP} moves it there from an older "
            f"secrets.env and keeps a backup ({SECRETS_UPGRADE_NOTE})."]
    problems = refuse_unsafe_job_environment("migrate", env, holds_owner_credential=True)
    if not problems and not _dsn_user(dsn):
        problems.append(
            f"migrate: {MIGRATION_DSN_ENV} names no role, so the migration job would "
            f"connect as whatever the driver defaults to rather than as the schema owner.")
    return problems


def persona_key_problems(env: Mapping[str, str] | None = None, *,
                         collector: bool) -> list[str]:
    """The production refusals the persona key's split needs. Pure, like `verify_environment`, and
    `[]` outside production.

    The collector is the one process that holds NOCTORNAL_PERSONA_KEK, and carries
    NOCTORNAL_COLLECTOR=1 from the compose file so the vault opens with it there. Every other
    production process (the API, the sample origin, the cron loop, the Lab workers) is refused when
    it holds the key or the collector's mark, and the inline mode, which runs persona acts inside
    the API, is refused everywhere. Named, never quoted."""
    from noctornal_api.persona_acts import INLINE_ENV, inline_requested
    from noctornal_api.security import persona_envelope as pe

    if env is None:
        env = os.environ
    if not is_production(env):
        return []
    problems: list[str] = []
    if inline_requested(env):
        problems.append(
            f"{INLINE_ENV} is set, and it runs persona acts inside the API "
            f"process, which in production holds no persona key; it exists for "
            f"development only.")
    if not collector:
        held = pe.held(env)
        if held:
            problems.append(
                f"{' and '.join(held)} {'is' if len(held) == 1 else 'are'} set on "
                f"a process that is not the collector: in production the persona "
                f"key is held by the collector service alone "
                f"(infra/production/collector.env), so no other process can open "
                f"a persona credential.")
        if pe.is_collector(env):
            problems.append(
                f"{pe.COLLECTOR_ENV} is set on a process that is not the "
                f"collector; it marks the collector service alone "
                f"(infra/production/compose.yml).")
        return problems
    if not pe.is_collector(env):
        problems.append(
            f"{pe.COLLECTOR_ENV} is not set on the collector, so its vault would "
            f"refuse to open any persona credential; the compose file sets it on "
            f"the collector service.")
        return problems
    with _borrowing(env, ENV_VAR, pe.COLLECTOR_ENV, pe.KEK_ENV,
                    pe.KEK_ID_ENV, pe.RETIRED_ENV):
        try:
            pe.ring()
        except pe.PersonaKeyError as exc:
            problems.append(
                f"the persona key ring is not usable ({exc}), so the collector "
                f"could open no persona credential and every persona act and "
                f"poll would be refused.")
    return problems


def enforce_persona_key_boundary(env: Mapping[str, str] | None = None, *,
                                 collector: bool) -> None:
    """`persona_key_problems` as a refusal, for the cron entries that do not run the whole of
    `enforce_environment`. Nothing at all outside production."""
    problems = persona_key_problems(env, collector=collector)
    if problems:
        listed = "\n".join(f"  - {problem}" for problem in problems)
        raise RuntimeError(
            f"{ENV_VAR}={PRODUCTION}, and this process may not run with its "
            f"persona key settings:\n{listed}")


def _dsn_user(dsn: str) -> str | None:
    """The role a URL-style DSN names, or None when it names none."""
    from urllib.parse import urlsplit
    try:
        return urlsplit(dsn.strip()).username or None
    except ValueError:
        return None


#: Role names a request connection must never carry, whatever else is set:
#: the cluster's default superuser and the schema owner this repository's
#: compose file creates. A role the DSN names that equals the migration
#: DSN's or POSTGRES_USER is refused too (`_request_role_problems`).
_PRIVILEGED_ROLE_NAMES = frozenset({"postgres", "noctornal"})


def _request_role_problems(env: Mapping[str, str]) -> list[str]:
    """Production refuses a request DSN that names the schema owner or a superuser.

    Row-level security does not bind the owner and an owner may ALTER TABLE ... DISABLE TRIGGER on
    the audit and custody chains, so a request connection that carries either switches both off for
    every analyst request while the register shows the deployment running. The system connection
    already refuses exactly that role (`db.connect_system`); this is the same refusal for the
    request one, from the names alone. What a DSN cannot say (a superuser or a BYPASSRLS role under
    another name, a member of the owner) is refused at the first request connection by
    `db.connect_request`, from the catalog. Names variables and never the role."""
    user = _dsn_user(env.get("DATABASE_URL", ""))
    if not user:
        return []
    owners = {_dsn_user(env.get("NOCTORNAL_MIGRATION_DATABASE_URL", "")),
              (env.get("POSTGRES_USER", "").strip() or None)}
    if user in _PRIVILEGED_ROLE_NAMES or user in owners - {None}:
        return [
            "DATABASE_URL names the schema owner or a superuser, so row-level "
            "security filters nothing for any request and the append-only "
            "triggers on the audit and custody chains can be disabled from "
            "the request path; point it at noctornal_app and keep the owner "
            "for NOCTORNAL_MIGRATION_DATABASE_URL alone. A volume initialised "
            "without NOCTORNAL_APP_DB_PASSWORD has no such role yet: create it "
            "first (infra/production/README.md, step 2)."]
    return []


def _row_security_problems(env: Mapping[str, str]) -> list[str]:
    """The production refusals row-level security needs.

    The system connection (`db.connect_system`) is what retention, lock extension, legal holds, the
    withheld counts, merges, sign-in and every script run on, so a process without it cannot do that
    work, and one with it can read every row. So: required on every process except the sample
    origin; refused ON the sample origin, which serves hostile bytes and must never hold the bypass
    (compose sets it to ""); never the same role DATABASE_URL names, or the request role would be
    the bypass role; the initdb-only password on no runtime process; and the development switch that
    makes the suite assume the runtime roles never in production. Empty counts as unset
    everywhere."""
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
    problems.extend(_request_role_problems(env))
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


def enforce_environment(env: Mapping[str, str] | None = None, *,
                        collector: bool = False) -> None:
    """Refuse to continue when `verify_environment` found anything.

    Does nothing unless `NOCTORNAL_ENV=production`, because `verify_environment` returns `[]` for
    every other value. The mode is read in one place, so `enforce` cannot enforce on an environment
    `verify` had excused.

    The RuntimeError names EVERY problem at once: an operator told one at a time restarts a
    production API once per problem, so the list is what makes a first-deployment misconfiguration
    one fix.
    """
    problems = verify_environment(env, collector=collector)
    if not problems:
        return
    listed = "\n".join(f"  - {problem}" for problem in problems)
    raise RuntimeError(
        f"{ENV_VAR}={PRODUCTION}, and this environment is not one this build "
        f"will start on:\n{listed}\n"
        # Agreed with the count rather than a bracketed plural. One problem is still said to be the
        # only one, which is the point of listing them all.
        + ("The one problem found is listed above. There is no second one "
           "waiting behind it. " if len(problems) == 1 else
           f"All {len(problems)} problems found are listed above. There is "
           f"no further one waiting behind them. ")
        + f"Unset {ENV_VAR} to run as "
        f"development, which is what a laptop and CI do."
    )

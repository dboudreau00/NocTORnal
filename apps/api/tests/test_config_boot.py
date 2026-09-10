"""The boot-time refusals (`noctornal_api.config`).

No database, no Redis, no object store: every rule under test reads a
dictionary, which is the whole reason `verify_environment` takes one.

Three things this file is here to hold, beyond "each rule fires":

* **The rule set is not vacuous.** A `verify_environment` that returned
  `[]` unconditionally would pass every "a good environment is accepted"
  test ever written, and would be the most dangerous possible outcome --
  a refusal everyone believes in and nothing enforces. `test_bare_production_
  environment_is_refused_on_every_count` is the guard.
* **The mapping wins over the process.** The KEK, the rate-limit switch
  and the session binding are decided by borrowed readers that natively
  read `os.environ`, so a test whose verdict came from the test runner's
  own environment would be testing nothing.
* **`os.environ` comes back.** `_borrowing` swaps it. If it leaked, the
  damage would land on whichever test ran next, which is the hardest kind
  of failure to read.
"""

import base64
import os

import pytest

from noctornal_api.config import DEV_CREDENTIAL, enforce_environment, verify_environment


def _production() -> dict[str, str]:
    """An environment with nothing wrong with it. Every rule test below
    starts from this and breaks exactly one thing, so a refusal it
    produces can only have come from that one thing."""
    return {
        "NOCTORNAL_ENV": "production",
        "DATABASE_URL":
            "postgresql+psycopg://noctornal_app:Xk9pQ@db:5432/noctornal",
        "REDIS_URL": "redis://:Zm4tR@redis:6379/0",
        "NOCTORNAL_TOTP_KEK": base64.b64encode(b"k" * 32).decode(),
        "NOCTORNAL_INGEST_PEPPER": "9f2c1ad4e6b8",
        "NOCTORNAL_BASE_URL": "https://noctornal.example.gov",
        "NOCTORNAL_SESSION_STRICT_BINDING": "1",
        "MINIO_ENDPOINT": "minio:9000",
        "MINIO_ACCESS_KEY": "evidence-writer",
        "MINIO_SECRET_KEY": "Qp7xL2vD",
        "MINIO_SECURE": "true",
        "SAMPLE_ACCESS_KEY": "sample-writer",
        "SAMPLE_SECRET_KEY": "Wr3nB8fH",
        "SAMPLE_SECURE": "true",
        "SMTP_HOST": "smtp.example.gov",
        "SMTP_PASSWORD": "Td5mJ1cV",
    }


def _only(problems: list[str], variable: str) -> str:
    """Assert exactly one refusal, and that it names `variable`. One,
    because the fixture broke one thing: a second refusal means a rule
    fired on something the test did not touch."""
    assert len(problems) == 1, problems
    assert variable in problems[0], problems[0]
    return problems[0]


def test_good_production_environment_is_accepted():
    assert verify_environment(_production()) == []


def test_the_refusals_never_quote_a_value():
    """A refusal list goes into a container log, a screenshot and a
    support ticket. It may name a variable; it may not print one."""
    env = _production()
    env["MINIO_SECURE"] = "false"
    env["SAMPLE_SECURE"] = "false"
    del env["NOCTORNAL_TOTP_KEK"]
    del env["SAMPLE_SECRET_KEY"]
    report = "\n".join(verify_environment(env))
    for secret in ("Xk9pQ", "Zm4tR", "Qp7xL2vD", "Wr3nB8fH", "Td5mJ1cV"):
        assert secret not in report


# ---------------------------------------------------------------------------
# The development credential
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("variable", [
    "DATABASE_URL", "REDIS_URL", "MINIO_SECRET_KEY", "SAMPLE_SECRET_KEY",
    "POSTGRES_PASSWORD", "SMTP_PASSWORD",
])
def test_the_published_password_is_refused_wherever_it_is_set(variable):
    env = _production()
    env[variable] = f"prefix-{DEV_CREDENTIAL}-suffix"
    _only(verify_environment(env), variable)


def test_the_published_password_is_found_in_a_variable_no_rule_names():
    """The point of scanning values instead of a fixed list: a service
    added after this module was written carries the same password and is
    caught without anyone editing the rule."""
    env = _production()
    env["RABBITMQ_PASSWORD"] = DEV_CREDENTIAL
    _only(verify_environment(env), "RABBITMQ_PASSWORD")


def test_a_non_credential_variable_carrying_it_is_not_refused():
    """The other half of that choice. Refusing on a bucket name would
    stop a deployment for a cosmetic reason, and an operator who cannot
    start their API unsets NOCTORNAL_ENV -- losing every other rule with
    it."""
    env = _production()
    env["EVIDENCE_BUCKET"] = f"noctornal-{DEV_CREDENTIAL}"
    env["NOCTORNAL_DESIGNATED_PERSON"] = DEV_CREDENTIAL
    assert verify_environment(env) == []


# ---------------------------------------------------------------------------
# Secrets that must exist and must be usable
# ---------------------------------------------------------------------------

def test_missing_totp_kek_is_refused():
    env = _production()
    del env["NOCTORNAL_TOTP_KEK"]
    assert "not set" in _only(verify_environment(env), "NOCTORNAL_TOTP_KEK")


@pytest.mark.parametrize("kek", [
    base64.b64encode(b"k" * 16).decode(),   # right shape, wrong length
    base64.b64encode(b"k" * 64).decode(),
    "not base64!!",                          # not decodable at all
])
def test_unusable_totp_kek_is_refused(kek):
    env = _production()
    env["NOCTORNAL_TOTP_KEK"] = kek
    assert "cannot use it" in _only(verify_environment(env), "NOCTORNAL_TOTP_KEK")


def test_a_kek_with_a_trailing_newline_is_accepted():
    """The envelope decodes leniently, and a KEK read out of a Docker or
    Kubernetes secret file routinely carries a newline. Until 2026-09-02
    `readiness.py` reported exactly this configuration as not-ready
    because it kept its own stricter copy of the rule; a boot refusal
    making the same mistake would not report a working deployment as
    broken, it would stop it from starting."""
    env = _production()
    env["NOCTORNAL_TOTP_KEK"] = base64.b64encode(b"k" * 32).decode() + "\n"
    assert verify_environment(env) == []


@pytest.mark.parametrize("pepper", ["", "   "])
def test_missing_ingest_pepper_is_refused(pepper):
    env = _production()
    env["NOCTORNAL_INGEST_PEPPER"] = pepper
    _only(verify_environment(env), "NOCTORNAL_INGEST_PEPPER")


def test_unset_ingest_pepper_is_refused():
    env = _production()
    del env["NOCTORNAL_INGEST_PEPPER"]
    _only(verify_environment(env), "NOCTORNAL_INGEST_PEPPER")


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_missing_redis_url_is_refused():
    env = _production()
    del env["REDIS_URL"]
    _only(verify_environment(env), "REDIS_URL")


def test_every_off_value_the_limiter_recognises_is_refused():
    """Parametrised over the limiter's OWN off-set rather than a copy of
    it: if somebody adds a seventh spelling of "off" to `limits._OFF`,
    this test starts covering it without being edited, and if the boot
    check ever grows its own list the two will disagree here first."""
    from noctornal_api.http.limits import _OFF

    assert _OFF, "the limiter's off-set is empty; this test proves nothing"
    for value in _OFF:
        env = _production()
        env["NOCTORNAL_RATELIMIT"] = value
        _only(verify_environment(env), "NOCTORNAL_RATELIMIT")


def test_the_off_value_is_read_the_way_the_limiter_reads_it():
    """`rate_limiting_disabled` strips and lower-cases before comparing,
    so this must too -- a deployment whose limiter never builds must not
    be allowed to start because of the case of the word that disabled it."""
    env = _production()
    env["NOCTORNAL_RATELIMIT"] = "  OFF  "
    _only(verify_environment(env), "NOCTORNAL_RATELIMIT")


def test_a_rate_limit_value_that_is_not_an_off_value_is_accepted():
    env = _production()
    env["NOCTORNAL_RATELIMIT"] = "on"
    assert verify_environment(env) == []


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["1", "true", "TRUE"])
def test_smtp_plaintext_exception_is_refused(value):
    env = _production()
    env["SMTP_ALLOW_PLAINTEXT"] = value
    _only(verify_environment(env), "SMTP_ALLOW_PLAINTEXT")


def test_smtp_plaintext_is_read_exactly_as_transports_reads_it():
    """`transports.py` does NOT strip, so " 1" leaves plaintext DISABLED
    and there is nothing to refuse. A tidier test here would refuse a
    deployment that is already doing the right thing."""
    env = _production()
    env["SMTP_ALLOW_PLAINTEXT"] = " 1"
    assert verify_environment(env) == []


@pytest.mark.parametrize("variable", ["MINIO_SECURE", "SAMPLE_SECURE"])
@pytest.mark.parametrize("value", ["false", "", "1", "yes", " true"])
def test_object_store_without_tls_is_refused(variable, value):
    """" true" is in the list on purpose: the MinIO clients compare
    without stripping, so a leading space gives them a PLAINTEXT client
    and must give this a refusal."""
    env = _production()
    env[variable] = value
    _only(verify_environment(env), variable)


@pytest.mark.parametrize("variable", ["MINIO_SECURE", "SAMPLE_SECURE"])
def test_unset_object_store_tls_is_refused(variable):
    env = _production()
    del env[variable]
    _only(verify_environment(env), variable)


def test_missing_base_url_is_refused():
    env = _production()
    del env["NOCTORNAL_BASE_URL"]
    _only(verify_environment(env), "NOCTORNAL_BASE_URL")


@pytest.mark.parametrize("value", [
    "http://noctornal.example.gov",
    "noctornal.example.gov",
    "ftp://noctornal.example.gov",
])
def test_base_url_that_is_not_https_is_refused(value):
    env = _production()
    env["NOCTORNAL_BASE_URL"] = value
    _only(verify_environment(env), "NOCTORNAL_BASE_URL")


def test_https_base_url_with_a_path_prefix_is_accepted():
    """`NOCTORNAL_BASE_URL` may carry a path for a deployment mounted
    under one (see `samples.normalise_origin`), and that is not a
    transport problem."""
    env = _production()
    env["NOCTORNAL_BASE_URL"] = "https://gov.example/noctornal"
    assert verify_environment(env) == []


# ---------------------------------------------------------------------------
# Controls that are off by default and must be on (or on and must be off)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["", "0", "off", "no"])
def test_session_binding_not_enforced_is_refused(value):
    env = _production()
    env["NOCTORNAL_SESSION_STRICT_BINDING"] = value
    _only(verify_environment(env), "NOCTORNAL_SESSION_STRICT_BINDING")


def test_unset_session_binding_is_refused():
    env = _production()
    del env["NOCTORNAL_SESSION_STRICT_BINDING"]
    _only(verify_environment(env), "NOCTORNAL_SESSION_STRICT_BINDING")


@pytest.mark.parametrize("value", ["1", " 1", "true", "TRUE "])
def test_session_binding_is_read_exactly_as_sessions_reads_it(value):
    """`strict_binding_enabled` DOES strip, so " 1" is on. Refusing it
    would refuse a deployment that is enforcing the binding."""
    env = _production()
    env["NOCTORNAL_SESSION_STRICT_BINDING"] = value
    assert verify_environment(env) == []


@pytest.mark.parametrize("value", ["1", "true"])
def test_published_openapi_document_is_refused(value):
    env = _production()
    env["NOCTORNAL_ENABLE_DOCS"] = value
    _only(verify_environment(env), "NOCTORNAL_ENABLE_DOCS")


# ---------------------------------------------------------------------------
# The sample bucket's own credentials (docs/11)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("variable,twin", [
    ("SAMPLE_ACCESS_KEY", "MINIO_ACCESS_KEY"),
    ("SAMPLE_SECRET_KEY", "MINIO_SECRET_KEY"),
])
def test_silent_fallback_to_the_evidence_credentials_is_refused(variable, twin):
    """`SampleStorage` falls back per variable, so setting one and
    forgetting the other is half a fallback and nothing at runtime says
    so. Each missing variable is reported on its own for that reason."""
    env = _production()
    del env[variable]
    assert twin in _only(verify_environment(env), variable)


def test_a_shared_endpoint_is_not_refused():
    """`SAMPLE_ENDPOINT` falls back to `MINIO_ENDPOINT` the same way and
    is deliberately allowed: one object store serving two buckets under
    two credentials is a legitimate production shape, and docs/11 asks
    for separate credentials, not a separate host."""
    env = _production()
    assert "SAMPLE_ENDPOINT" not in env
    assert verify_environment(env) == []


# ---------------------------------------------------------------------------
# Everything at once, and nothing at all
# ---------------------------------------------------------------------------

_ALL_BROKEN_NAMES = (
    "DATABASE_URL", "MINIO_SECRET_KEY", "NOCTORNAL_TOTP_KEK",
    "NOCTORNAL_INGEST_PEPPER", "REDIS_URL", "NOCTORNAL_RATELIMIT",
    "SMTP_ALLOW_PLAINTEXT", "MINIO_SECURE", "SAMPLE_SECURE",
    "NOCTORNAL_BASE_URL", "NOCTORNAL_SESSION_STRICT_BINDING",
    "NOCTORNAL_ENABLE_DOCS", "SAMPLE_ACCESS_KEY", "SAMPLE_SECRET_KEY",
)


def _all_broken() -> dict[str, str]:
    """Everything wrong at once: the two variables below carry the
    published password, and every other rule fails by omission."""
    return {
        "NOCTORNAL_ENV": "production",
        "DATABASE_URL": f"postgresql+psycopg://noctornal:{DEV_CREDENTIAL}@db:5432/n",
        "MINIO_SECRET_KEY": DEV_CREDENTIAL,
        "NOCTORNAL_RATELIMIT": "off",
        "SMTP_ALLOW_PLAINTEXT": "1",
        "NOCTORNAL_ENABLE_DOCS": "true",
        "NOCTORNAL_BASE_URL": "http://noctornal.example.gov",
    }


def test_every_problem_is_reported_at_once():
    """Not the first. An operator told one problem per restart spends the
    evening restarting a production API to be told the next one."""
    problems = verify_environment(_all_broken())
    for name in _ALL_BROKEN_NAMES:
        assert any(name in p for p in problems), f"{name} was not reported"
    assert len(problems) == len(_ALL_BROKEN_NAMES), problems


#: Every rule whose failure mode is OMISSION, and therefore everything a
#: production environment with nothing at all set must be refused on. The
#: four that need a bad value rather than a missing one -- the published
#: password, the rate-limit off-switch, the SMTP plaintext exception and
#: the published schema -- cannot fire on an empty mapping and are held by
#: `_all_broken` instead.
_REFUSED_ON_AN_EMPTY_ENVIRONMENT = (
    "NOCTORNAL_TOTP_KEK", "NOCTORNAL_INGEST_PEPPER", "REDIS_URL",
    "MINIO_SECURE", "SAMPLE_SECURE", "NOCTORNAL_BASE_URL",
    "NOCTORNAL_SESSION_STRICT_BINDING", "SAMPLE_ACCESS_KEY",
    "SAMPLE_SECRET_KEY",
)


def test_bare_production_environment_is_refused_on_every_count():
    """The vacuity guard. A `verify_environment` that had lost its rules
    -- or never ran them -- would pass every other test in this file by
    returning `[]`, and would be a boot refusal in name only.

    It names the nine rather than asserting a floor, because a floor is
    the weaker half of the same guard: `>= 8` goes on passing after
    somebody deletes a rule, which is the case this test exists for."""
    problems = verify_environment({"NOCTORNAL_ENV": "production"})
    for name in _REFUSED_ON_AN_EMPTY_ENVIRONMENT:
        assert any(name in problem for problem in problems), f"{name} was not reported"
    assert len(problems) == len(_REFUSED_ON_AN_EMPTY_ENVIRONMENT), problems
    assert all(problem.endswith(".") for problem in problems), problems


@pytest.mark.parametrize("mode", [None, "", "development", "dev", "staging",
                                  "PRODUCTION_LIKE", "prod"])
def test_a_development_environment_is_untouched(mode):
    """CI runs with `dev_only_change_me`, no TLS to MinIO and the docs
    enabled, all of it deliberately. Only the exact word turns the rules
    on -- and `prod` is in this list to record that the near miss is
    development, which the module docstring names as the sharp edge."""
    env = _all_broken()
    if mode is None:
        del env["NOCTORNAL_ENV"]
    else:
        env["NOCTORNAL_ENV"] = mode
    assert verify_environment(env) == []


@pytest.mark.parametrize("mode", ["production", "  Production  ", "PRODUCTION"])
def test_the_mode_is_matched_past_case_and_space(mode):
    env = _all_broken()
    env["NOCTORNAL_ENV"] = mode
    assert verify_environment(env) != []


# ---------------------------------------------------------------------------
# The mapping, not the process
# ---------------------------------------------------------------------------

def test_the_verdict_comes_from_the_mapping_not_the_process(monkeypatch):
    """The KEK, the limiter switch and the session binding are decided by
    readers that natively read `os.environ`. Here the process holds the
    opposite of the mapping for all three: a good environment must still
    be accepted."""
    monkeypatch.setenv("NOCTORNAL_TOTP_KEK", "obviously-not-base64-32-bytes")
    monkeypatch.setenv("NOCTORNAL_RATELIMIT", "off")
    monkeypatch.delenv("NOCTORNAL_SESSION_STRICT_BINDING", raising=False)
    assert verify_environment(_production()) == []


def test_a_good_process_environment_does_not_rescue_a_bad_mapping(monkeypatch):
    """The inverse, which is the one that matters: the test runner's own
    environment carries a valid KEK (conftest sets one), so a borrowed
    reader that ignored the mapping would report this as fine."""
    monkeypatch.setenv("NOCTORNAL_TOTP_KEK", base64.b64encode(b"z" * 32).decode())
    monkeypatch.setenv("NOCTORNAL_SESSION_STRICT_BINDING", "1")
    env = _production()
    del env["NOCTORNAL_TOTP_KEK"]
    del env["NOCTORNAL_SESSION_STRICT_BINDING"]
    problems = verify_environment(env)
    assert any("NOCTORNAL_TOTP_KEK" in p for p in problems), problems
    assert any("NOCTORNAL_SESSION_STRICT_BINDING" in p for p in problems), problems


@pytest.mark.parametrize("env_factory", [_production, _all_broken])
def test_the_process_environment_is_put_back(env_factory):
    """`_borrowing` swaps `os.environ` and restores it in a `finally`. A
    leak here would land on whichever test ran next, which is the hardest
    kind of failure to trace back to its cause."""
    before = dict(os.environ)
    verify_environment(env_factory())
    assert dict(os.environ) == before


def test_the_default_argument_is_the_process_environment():
    """Called with nothing it reads `os.environ`, which in this process is
    not production -- so it returns nothing, and importing this module has
    no opinion about the machine running the suite."""
    assert os.environ.get("NOCTORNAL_ENV", "").strip().lower() != "production"
    assert verify_environment() == []


# ---------------------------------------------------------------------------
# enforce_environment
# ---------------------------------------------------------------------------

def test_enforce_raises_with_every_problem_named():
    with pytest.raises(RuntimeError) as excinfo:
        enforce_environment(_all_broken())
    message = str(excinfo.value)
    for name in _ALL_BROKEN_NAMES:
        assert name in message, f"{name} missing from the refusal"
    assert "NOCTORNAL_ENV" in message


def test_enforce_is_silent_on_a_good_production_environment():
    enforce_environment(_production())


@pytest.mark.parametrize("mode", [None, "development"])
def test_enforce_does_nothing_outside_production(mode):
    env = _all_broken()
    if mode is None:
        del env["NOCTORNAL_ENV"]
    else:
        env["NOCTORNAL_ENV"] = mode
    enforce_environment(env)


def test_enforce_does_nothing_in_this_process():
    """`create_app` calls this with no argument, so every suite in this
    tree that imports `noctornal_api.http.app` -- and CI, which imports it
    for the whole HTTP surface -- runs it at collection time. This file
    does not import the app, which is exactly why the assertion belongs
    here: it pins the precondition those suites depend on without
    borrowing their imports to do it."""
    enforce_environment()

"""The one reader of the object store's settings.

Five roles reach a store, each through its own chain of variables. The chains are the ones each store
read for itself before this module existed, with the neutral `OBJECT_STORE_*` names placed in front of
the `MINIO_*` ones they alias; nothing was renamed, so every deployment, installer and test that sets
`MINIO_*` reads exactly what it read before. The first variable in a chain that is set and not empty
wins.

| role          | endpoint, access key, secret key                          | secure                                |
|---------------|-----------------------------------------------------------|---------------------------------------|
| `evidence`    | `OBJECT_STORE_*`, then `MINIO_*`                          | `OBJECT_STORE_SECURE`, `MINIO_SECURE` |
| `ingest`      | the same                                                  | the same                              |
| `collect_raw` | the same                                                  | the same                              |
| `sample`      | `SAMPLE_*`, then `OBJECT_STORE_*`, then `MINIO_*`         | `SAMPLE_SECURE` only                  |
| `preserve`    | `PRESERVE_*`, `SAMPLE_*`, `OBJECT_STORE_*`, then `MINIO_*` | `PRESERVE_SECURE`, `SAMPLE_SECURE`    |

`secure` is the strict, unstripped equality the readers have always used: the value, lower-cased, must
be exactly `true` (`config.verify_environment` says why a forgiving test would be worse). The sample and
preservation stores never take `secure` from the evidence store's variables, as before.

Three settings are deployment-wide: `NOCTORNAL_OBJECT_STORE` (the profile, `minio` or `s3`, default
`minio`), `OBJECT_STORE_REGION` (passed to the client so it never has to ask the store for a bucket's
location) and `OBJECT_STORE_ADDRESSING` (`auto`, the client's default of path style except on AWS hosts,
`path` or `virtual`). The profile chooses how a refused delete is read and how the operator is spoken
to, never a different client. A value that is neither of the words a setting takes is refused here
rather than guessed at.

A neutral name and its `MINIO_*` alias both set to different values name two stores, which is a
misconfiguration: the neutral one wins here, and a production start refuses it (`problems`).
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

PROFILE_ENV = "NOCTORNAL_OBJECT_STORE"
MINIO = "minio"
S3 = "s3"
PROFILES = (MINIO, S3)
DEFAULT_PROFILE = MINIO

REGION_ENV = "OBJECT_STORE_REGION"
ADDRESSING_ENV = "OBJECT_STORE_ADDRESSING"
ADDRESSING = ("auto", "path", "virtual")

ROLES = ("evidence", "ingest", "collect_raw", "sample", "preserve")

#: (field, neutral name, alias). The pairs whose two names may not disagree.
ALIASES: tuple[tuple[str, str, str], ...] = (
    ("endpoint", "OBJECT_STORE_ENDPOINT", "MINIO_ENDPOINT"),
    ("access_key", "OBJECT_STORE_ACCESS_KEY", "MINIO_ACCESS_KEY"),
    ("secret_key", "OBJECT_STORE_SECRET_KEY", "MINIO_SECRET_KEY"),
    ("secure", "OBJECT_STORE_SECURE", "MINIO_SECURE"),
)

_PREFIXES: dict[str, tuple[str, ...]] = {
    "evidence": ("OBJECT_STORE_", "MINIO_"),
    "ingest": ("OBJECT_STORE_", "MINIO_"),
    "collect_raw": ("OBJECT_STORE_", "MINIO_"),
    "sample": ("SAMPLE_", "OBJECT_STORE_", "MINIO_"),
    "preserve": ("PRESERVE_", "SAMPLE_", "OBJECT_STORE_", "MINIO_"),
}
_SECURE: dict[str, tuple[str, ...]] = {
    "evidence": ("OBJECT_STORE_SECURE", "MINIO_SECURE"),
    "ingest": ("OBJECT_STORE_SECURE", "MINIO_SECURE"),
    "collect_raw": ("OBJECT_STORE_SECURE", "MINIO_SECURE"),
    "sample": ("SAMPLE_SECURE",),
    "preserve": ("PRESERVE_SECURE", "SAMPLE_SECURE"),
}

#: The bucket each role writes, and the name the code falls back to. Each reads its variable the way its
#: store always has: evidence, ingest and samples take an empty value as given, the collected markup
#: strips it and the preservation bucket treats empty as unset.
BUCKET_ENV = {"evidence": "EVIDENCE_BUCKET", "ingest": "INGEST_BUCKET",
              "collect_raw": "COLLECT_RAW_BUCKET", "sample": "SAMPLE_BUCKET",
              "preserve": "PRESERVE_BUCKET"}
BUCKET_DEFAULT = {"evidence": "noctornal-evidence", "ingest": "noctornal-raw",
                  "collect_raw": "noctornal-collect-raw", "sample": "noctornal-samples",
                  "preserve": "noctornal-preserved"}
#: The buckets whose objects are write-once (a COMPLIANCE retention or a legal hold), and so must be
#: created with object lock; every other bucket must be created without it (docs/22).
LOCKED_ROLES = frozenset({"evidence", "preserve"})


class StoreConfigError(ValueError):
    """A setting this module will not guess at. The sentence names the variable, never a value."""


def chain(role: str, what: str) -> tuple[str, ...]:
    """The variables `role` reads for `what` (`ENDPOINT`, `ACCESS_KEY` or `SECRET_KEY`), in order."""
    if role not in _PREFIXES:
        raise StoreConfigError(f"{role!r} is not an object store role")
    return tuple(prefix + what for prefix in _PREFIXES[role])


def secure_chain(role: str) -> tuple[str, ...]:
    if role not in _SECURE:
        raise StoreConfigError(f"{role!r} is not an object store role")
    return _SECURE[role]


def first_set(env: Mapping[str, str], names: tuple[str, ...]) -> tuple[str, str]:
    """`(name, value)` of the first variable set and not empty; `(names[0], "")` when none is, so a
    sentence about an unset setting names the variable an operator would set."""
    for name in names:
        value = env.get(name)
        if value:
            return name, value
    return names[0], ""


def profile_of(env: Mapping[str, str] | None = None) -> str:
    """`minio` or `s3`. Unset or empty is `minio`, case and surrounding space aside; anything else raises,
    because a classifier chosen by guess is how a policy denial gets recorded as a lock."""
    env = os.environ if env is None else env
    raw = env.get(PROFILE_ENV, "").strip().lower()
    if not raw:
        return DEFAULT_PROFILE
    if raw in PROFILES:
        return raw
    raise StoreConfigError(
        f"{PROFILE_ENV} is neither minio nor s3, so how a refused delete is read "
        f"cannot be chosen")


def addressing_of(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    raw = env.get(ADDRESSING_ENV, "").strip().lower()
    if not raw:
        return "auto"
    if raw in ADDRESSING:
        return raw
    raise StoreConfigError(
        f"{ADDRESSING_ENV} is not auto, path or virtual, so the store's address "
        f"cannot be built")


def bucket_for(role: str, env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    name, default = BUCKET_ENV[role], BUCKET_DEFAULT[role]
    if role == "collect_raw":
        return env.get(name, "").strip() or default
    if role == "preserve":
        return env.get(name) or default
    return env.get(name, default)


def endpoint_label(endpoint: str) -> str:
    """`host:port` of an endpoint, with anything before an `@` dropped, for evidence and custody rows."""
    text = (endpoint or "").strip()
    if not text:
        return ""
    parts = urlsplit("//" + text)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{parts.port}" if parts.port else host


@dataclass(frozen=True)
class StoreSettings:
    """Where one role's store is and how to speak to it. `sources` maps each field to the variable that
    supplied it, so a register sentence can name a fallback. The secret key is never in a repr."""
    role: str
    profile: str
    endpoint: str
    access_key: str
    secret_key: str = field(repr=False)
    secure: bool
    region: str | None
    addressing: str
    bucket: str
    sources: Mapping[str, str] = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.endpoint and self.access_key and self.secret_key)

    @property
    def host(self) -> str:
        return endpoint_label(self.endpoint)

    def named(self, what: str) -> tuple[str, str]:
        """`(variable, value)` for `endpoint`, `access_key` or `secret_key`."""
        return self.sources[what], getattr(self, what)


def resolve(role: str, env: Mapping[str, str] | None = None) -> StoreSettings:
    """`role`'s settings from `env` (the process environment by default). Raises `StoreConfigError` for an
    unknown role, profile or addressing; a store that is not configured is returned as such
    (`configured` is False) for its caller to refuse in its own words."""
    env = os.environ if env is None else env
    endpoint = first_set(env, chain(role, "ENDPOINT"))
    access = first_set(env, chain(role, "ACCESS_KEY"))
    secret = first_set(env, chain(role, "SECRET_KEY"))
    secure_name, secure_raw = first_set(env, secure_chain(role))
    region = env.get(REGION_ENV, "").strip() or None
    return StoreSettings(
        role=role, profile=profile_of(env), endpoint=endpoint[1],
        access_key=access[1], secret_key=secret[1],
        secure=(secure_raw or "false").lower() == "true",
        region=region, addressing=addressing_of(env), bucket=bucket_for(role, env),
        sources={"endpoint": endpoint[0], "access_key": access[0],
                 "secret_key": secret[0], "secure": secure_name})


def configured(role: str, env: Mapping[str, str] | None = None) -> bool:
    """Whether `role` has an endpoint, an access key and a secret key, without judging the rest."""
    env = os.environ if env is None else env
    return all(first_set(env, chain(role, what))[1]
               for what in ("ENDPOINT", "ACCESS_KEY", "SECRET_KEY"))


def problems(env: Mapping[str, str] | None = None) -> list[str]:
    """Every reason these settings must not run a production deployment, one sentence each, naming
    variables and never a value. `config.verify_environment` asks this."""
    env = os.environ if env is None else env
    found: list[str] = []
    for reader in (profile_of, addressing_of):
        try:
            reader(env)
        except StoreConfigError as exc:
            found.append(f"{exc}.")
    for _field, neutral, alias in ALIASES:
        a, b = env.get(neutral, ""), env.get(alias, "")
        if a and b and a != b:
            found.append(
                f"{neutral} and {alias} are both set and differ, so two object "
                f"stores are named and only {neutral} would be used; set one of "
                f"the two names.")
    return found

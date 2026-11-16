"""The one reader of the object store's settings (`objectstore/settings.py`).

Every store used to read its own variables, and the readiness register kept a copy of the preservation
store's rule. One reader now answers for all five roles, and these tests hold it to the chains the stores
read before it existed, with the neutral `OBJECT_STORE_*` names in front of the `MINIO_*` ones: a deployment
that sets only `MINIO_*` must read exactly what it read before, and one that sets the neutral names must win
with them. Nothing here opens a socket.
"""
from __future__ import annotations

import pytest

from noctornal_api.objectstore import settings

_ALL = ("ENDPOINT", "ACCESS_KEY", "SECRET_KEY")


def _env(**values: str) -> dict[str, str]:
    return dict(values)


def test_the_neutral_names_win_and_the_minio_names_still_work():
    old = settings.resolve("evidence", _env(
        MINIO_ENDPOINT="m:9000", MINIO_ACCESS_KEY="ma", MINIO_SECRET_KEY="ms",
        MINIO_SECURE="true"))
    assert (old.endpoint, old.access_key, old.secret_key, old.secure) == (
        "m:9000", "ma", "ms", True)
    assert old.sources["endpoint"] == "MINIO_ENDPOINT"
    both = settings.resolve("evidence", _env(
        MINIO_ENDPOINT="m:9000", MINIO_ACCESS_KEY="ma", MINIO_SECRET_KEY="ms",
        OBJECT_STORE_ENDPOINT="o:443", OBJECT_STORE_ACCESS_KEY="oa",
        OBJECT_STORE_SECRET_KEY="os", OBJECT_STORE_SECURE="true",
        MINIO_SECURE="false"))
    assert (both.endpoint, both.access_key, both.secret_key, both.secure) == (
        "o:443", "oa", "os", True)
    assert both.sources == {"endpoint": "OBJECT_STORE_ENDPOINT",
                            "access_key": "OBJECT_STORE_ACCESS_KEY",
                            "secret_key": "OBJECT_STORE_SECRET_KEY",
                            "secure": "OBJECT_STORE_SECURE"}
    # An empty neutral name is unset, so the alias still answers.
    empty = settings.resolve("evidence", _env(
        OBJECT_STORE_ENDPOINT="", MINIO_ENDPOINT="m:9000"))
    assert empty.endpoint == "m:9000"


@pytest.mark.parametrize("role, prefixes", [
    ("evidence", ("OBJECT_STORE_", "MINIO_")),
    ("ingest", ("OBJECT_STORE_", "MINIO_")),
    ("collect_raw", ("OBJECT_STORE_", "MINIO_")),
    ("sample", ("SAMPLE_", "OBJECT_STORE_", "MINIO_")),
    ("preserve", ("PRESERVE_", "SAMPLE_", "OBJECT_STORE_", "MINIO_")),
])
def test_every_role_keeps_its_old_fallback_chain(role, prefixes):
    """Each prefix answers when every one before it is unset, field by field, so a deployment that set one
    variable of a pair and forgot the other is half fallen back, as the stores always were."""
    for what in _ALL:
        assert settings.chain(role, what) == tuple(p + what for p in prefixes)
    for i, prefix in enumerate(prefixes):
        env = {p + what: f"{p}{what}".lower() for p in prefixes[i:] for what in _ALL}
        s = settings.resolve(role, env)
        assert (s.endpoint, s.access_key, s.secret_key) == tuple(
            f"{prefix}{what}".lower() for what in _ALL), (role, prefix)
        assert s.sources["endpoint"] == prefix + "ENDPOINT"
    half = settings.resolve(role, {prefixes[0] + "ENDPOINT": "first:1",
                                   prefixes[-1] + "ACCESS_KEY": "last-a",
                                   prefixes[-1] + "SECRET_KEY": "last-s"})
    assert (half.endpoint, half.access_key) == ("first:1", "last-a")
    assert half.sources["access_key"] == prefixes[-1] + "ACCESS_KEY"


def test_the_preservation_chain_is_the_one_the_store_has_always_read():
    """The cases `test_readiness_worm_probe.py` holds the register to, read through the one reader."""
    s = settings.resolve("preserve", _env(
        MINIO_ENDPOINT="m:9000", MINIO_ACCESS_KEY="ma", MINIO_SECRET_KEY="ms",
        MINIO_SECURE="true"))
    assert (s.endpoint, s.access_key, s.secret_key, s.secure, s.bucket) == (
        "m:9000", "ma", "ms", False, "noctornal-preserved")
    s = settings.resolve("preserve", _env(
        PRESERVE_ENDPOINT="", SAMPLE_ENDPOINT="s:9000", PRESERVE_ACCESS_KEY="pa",
        PRESERVE_SECRET_KEY="ps", PRESERVE_BUCKET=""))
    assert (s.endpoint, s.access_key, s.bucket) == ("s:9000", "pa", "noctornal-preserved")


@pytest.mark.parametrize("role, env, expect", [
    # Strict and unstripped: " true" is plaintext, as every reader has always taken it.
    ("evidence", {"MINIO_SECURE": " true"}, False),
    ("evidence", {"MINIO_SECURE": "TRUE"}, True),
    ("evidence", {"OBJECT_STORE_SECURE": "false", "MINIO_SECURE": "true"}, False),
    ("evidence", {}, False),
    # The sample and preservation stores never take it from the evidence store's variables.
    ("sample", {"MINIO_SECURE": "true", "OBJECT_STORE_SECURE": "true"}, False),
    ("sample", {"SAMPLE_SECURE": "true"}, True),
    ("preserve", {"MINIO_SECURE": "true", "OBJECT_STORE_SECURE": "true"}, False),
    ("preserve", {"SAMPLE_SECURE": "true"}, True),
    ("preserve", {"PRESERVE_SECURE": "false", "SAMPLE_SECURE": "true"}, False),
    ("preserve", {"PRESERVE_SECURE": "", "SAMPLE_SECURE": "true"}, True),
])
def test_secure_is_strict_equality_and_does_not_fall_back_for_sample_and_preserve(
        role, env, expect):
    assert settings.resolve(role, env).secure is expect


@pytest.mark.parametrize("raw, expect", [
    (None, "minio"), ("", "minio"), ("  ", "minio"), ("minio", "minio"),
    (" S3 ", "s3"), ("MINIO", "minio"),
])
def test_the_profile_defaults_to_minio(raw, expect):
    env = {} if raw is None else {settings.PROFILE_ENV: raw}
    assert settings.profile_of(env) == expect
    assert settings.resolve("evidence", env).profile == expect


@pytest.mark.parametrize("name, value", [
    (settings.PROFILE_ENV, "aws"), (settings.PROFILE_ENV, "ceph"),
    (settings.ADDRESSING_ENV, "dns"),
])
def test_an_unknown_profile_is_refused(name, value):
    """Fail closed: a profile chosen by guess decides how a refused delete is recorded."""
    with pytest.raises(settings.StoreConfigError) as info:
        settings.resolve("evidence", {name: value})
    assert name in str(info.value)
    assert value not in str(info.value)
    problems = settings.problems({name: value})
    assert len(problems) == 1 and name in problems[0]


def test_a_disagreeing_pair_of_store_names_is_a_problem():
    env = {"OBJECT_STORE_ENDPOINT": "o:443", "MINIO_ENDPOINT": "m:9000",
           "OBJECT_STORE_SECRET_KEY": "one-secret", "MINIO_SECRET_KEY": "another"}
    found = settings.problems(env)
    assert len(found) == 2, found
    assert any("OBJECT_STORE_ENDPOINT and MINIO_ENDPOINT" in p for p in found)
    assert not any("one-secret" in p or "another" in p for p in found)
    # The same value under both names names one store.
    assert settings.problems({"OBJECT_STORE_ENDPOINT": "m:9000",
                              "MINIO_ENDPOINT": "m:9000"}) == []


def test_the_secret_never_appears_in_repr():
    s = settings.resolve("evidence", _env(
        OBJECT_STORE_ENDPOINT="o:443", OBJECT_STORE_ACCESS_KEY="oa",
        OBJECT_STORE_SECRET_KEY="the-secret-value"))
    assert "the-secret-value" not in repr(s)
    assert "the-secret-value" not in str(s)


@pytest.mark.parametrize("role, env, expect", [
    ("evidence", {}, "noctornal-evidence"),
    ("evidence", {"EVIDENCE_BUCKET": "ev"}, "ev"),
    ("ingest", {}, "noctornal-raw"),
    ("sample", {}, "noctornal-samples"),
    ("collect_raw", {"COLLECT_RAW_BUCKET": "  "}, "noctornal-collect-raw"),
    ("preserve", {"PRESERVE_BUCKET": ""}, "noctornal-preserved"),
    ("preserve", {"PRESERVE_BUCKET": "held"}, "held"),
])
def test_each_bucket_keeps_its_default_and_its_own_reading(role, env, expect):
    assert settings.resolve(role, env).bucket == expect


@pytest.mark.parametrize("endpoint, label", [
    ("minio:9000", "minio:9000"), (" s3.example:443 ", "s3.example:443"),
    ("user:pass@store.example:9000", "store.example:9000"),
    ("[::1]:9000", "[::1]:9000"), ("", ""),
])
def test_the_endpoint_label_names_host_and_port_and_nothing_else(endpoint, label):
    assert settings.endpoint_label(endpoint) == label


def test_region_and_addressing_are_deployment_wide():
    env = {settings.REGION_ENV: " eu-west-2 ", settings.ADDRESSING_ENV: "Virtual"}
    for role in settings.ROLES:
        s = settings.resolve(role, env)
        assert (s.region, s.addressing) == ("eu-west-2", "virtual")
    assert settings.resolve("evidence", {}).region is None
    assert settings.resolve("evidence", {}).addressing == "auto"


def test_only_the_evidence_and_preservation_buckets_are_locked():
    assert settings.LOCKED_ROLES == {"evidence", "preserve"}
    assert set(settings.ROLES) - settings.LOCKED_ROLES == {
        "ingest", "collect_raw", "sample"}

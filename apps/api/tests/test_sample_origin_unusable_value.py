"""An origin setting that cannot be read is logged, and never told back to the caller (independent review, CONSOLE-03).

`origin_split()` is asked by the download routes before they read a session, so its refusal reaches a caller
with no credentials at all, and by `GET /samples/policy`, which any signed-in account reads. When
`NOCTORNAL_SAMPLE_ORIGIN` was set to something `normalise_origin` rejects, the refusal quoted it: a value
with userinfo (`https://user:secret@host`), a path or a query came back in the problem body. The refusal is
one fixed sentence now, the same for every such value, and the server log has the value, once, with any
userinfo masked.

Pure: environment variables only, no database. The HTTP side is in `test_sample_origin_http_pg.py`.
"""
from __future__ import annotations

import logging

import pytest

APP = "https://app.example"
SAMPLES = "https://samples.example"
SECRET = "hunter2-not-a-real-secret"

#: Each is rejected by `normalise_origin`, for a different reason, and each carries something a caller
#: must not be told back.
UNUSABLE = [
    f"https://svc:{SECRET}@samples.internal",
    f"https://svc:pa@ss{SECRET}@samples.internal",
    f"https://samples.internal/lab-{SECRET}",
    f"https://samples.internal/?token={SECRET}",
    f"samples-{SECRET}.internal",
    f"ftp://samples-{SECRET}.internal",
]


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    from noctornal_api import samples
    for var in ("NOCTORNAL_SAMPLE_ORIGIN", "NOCTORNAL_PUBLIC_ORIGIN", "NOCTORNAL_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setattr(samples, "_NOTED_UNUSABLE", set())


@pytest.mark.parametrize("value", UNUSABLE)
def test_an_unusable_sample_origin_is_refused_in_one_fixed_sentence(monkeypatch, value):
    from noctornal_api.samples import normalise_origin, origin_split
    assert normalise_origin(value) is None
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", value)
    split = origin_split()
    assert split.role == "invalid" and not split.serves_here
    assert split.refusal == split.split_problem, "the policy endpoint says what the download says"
    for fragment in (SECRET, "samples.internal", "samples-", "svc", "lab-", "token="):
        assert fragment not in split.refusal, fragment
    assert "NOCTORNAL_SAMPLE_ORIGIN" in split.refusal and "not an origin" in split.refusal


def test_every_unusable_value_is_refused_in_the_same_words(monkeypatch):
    from noctornal_api.samples import origin_split
    said = set()
    for value in UNUSABLE:
        monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", value)
        said.add(origin_split().refusal)
    assert len(said) == 1


@pytest.mark.parametrize("value", UNUSABLE)
def test_the_value_is_in_the_server_log_once_with_its_userinfo_masked(monkeypatch, caplog, value):
    from noctornal_api.samples import origin_split
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", value)
    with caplog.at_level(logging.WARNING, logger="noctornal.samples"):
        for _ in range(5):
            origin_split()
    lines = [r.getMessage() for r in caplog.records if r.name == "noctornal.samples"]
    assert len(lines) == 1, lines
    assert "NOCTORNAL_SAMPLE_ORIGIN" in lines[0] and "not an origin" in lines[0]
    if "@" in value:
        assert SECRET not in lines[0] and "pa@ss" not in lines[0]
        assert "***@samples.internal" in lines[0]
    else:
        assert value in lines[0], "the operator can see what to fix"


def test_a_second_unusable_value_is_logged_too(monkeypatch, caplog):
    from noctornal_api.samples import origin_split
    with caplog.at_level(logging.WARNING, logger="noctornal.samples"):
        for value in UNUSABLE[:3]:
            monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", value)
            origin_split()
            origin_split()
    assert len([r for r in caplog.records if r.name == "noctornal.samples"]) == 3


def test_an_unusable_public_origin_is_not_told_back_either(monkeypatch, caplog):
    """The sentence a process that is not the sample origin gives named its own configured origin, and
    quoted `NOCTORNAL_PUBLIC_ORIGIN` as typed when that was not an origin: the same echo, one line below."""
    from noctornal_api.samples import origin_split
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", f"https://svc:{SECRET}@app.internal")
    with caplog.at_level(logging.WARNING, logger="noctornal.samples"):
        split = origin_split()
    assert split.role == "app" and not split.serves_here
    assert SECRET not in split.refusal and "app.internal" not in split.refusal
    assert SAMPLES in split.refusal, "the origin to fetch from is still named"
    lines = [r.getMessage() for r in caplog.records if r.name == "noctornal.samples"]
    assert len(lines) == 1 and SECRET not in lines[0] and "***@app.internal" in lines[0]


@pytest.mark.parametrize("raw, masked", [
    (f"https://svc:{SECRET}@samples.internal", "https://***@samples.internal"),
    (f"https://svc:pa@ss{SECRET}@samples.internal", "https://***@samples.internal"),
    (f"https://svc:pa/ss{SECRET}@samples.internal", "https://***@samples.internal"),
    (f"svc:{SECRET}@samples.internal", "***@samples.internal"),
    (f"https://svc:{SECRET}@samples.internal/lab?x=1", "https://***@samples.internal/lab?x=1"),
    ("https://samples.internal/?x=a@b", "https://samples.internal/?x=a@b"),
    ("https://samples.example/lab", "https://samples.example/lab"),
])
def test_the_logged_value_carries_no_credential_whatever_its_shape(raw, masked):
    """The log is where the value goes, so the mask covers userinfo with an "@" or a "/" in it and userinfo
    on a value with no scheme."""
    from noctornal_api.samples import masked_origin
    assert masked_origin(raw) == masked
    assert SECRET not in masked_origin(raw)


def test_a_usable_deployment_is_unchanged(monkeypatch, caplog):
    from noctornal_api.samples import origin_split
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)
    with caplog.at_level(logging.WARNING, logger="noctornal.samples"):
        split = origin_split()
        monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
        served = origin_split()
    assert split.role == "app" and APP in (split.app, split.this) and SAMPLES in split.refusal
    assert served.role == "sample" and served.serves_here
    assert [r for r in caplog.records if r.name == "noctornal.samples"] == []

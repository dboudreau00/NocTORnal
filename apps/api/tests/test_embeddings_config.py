"""The similarity settings and their production refusals (F6.1 and F6.2,
embeddings, 2026-09-24).

`embedders.configured()` is the one reader of every NOCTORNAL_EMBED_*
variable; config.verify_environment borrows it, so the start refusal and
the pass cannot disagree about what a usable value is. No refusal quotes a
value (a URL- or key-shaped variable is scanned as a credential).

Pure.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from noctornal_api import embedders as E
from noctornal_api.config import verify_environment

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"

GOOD = {E.URL_ENV: "https://models.example.org/v1", E.MODEL_ENV: "nomic-embed-text",
        E.CEILING_ENV: "AMBER"}


def _prod(**extra) -> list[str]:
    return verify_environment({"NOCTORNAL_ENV": "production", **extra})


def test_unset_and_on_and_off_are_the_wording_settings():
    assert E.configured({}).wording_setting == "on"
    assert E.configured({E.WORDING_ENV: "on"}).wording is not None
    off = E.configured({E.WORDING_ENV: "off"})
    assert off.wording_setting == "off" and off.wording is None
    assert not off.problems


def test_any_other_wording_value_is_refused_in_production():
    problems = _prod(**{E.WORDING_ENV: "sometimes"})
    assert any(E.WORDING_ENV in p for p in problems)
    assert not any(E.WORDING_ENV in p for p in _prod(**{E.WORDING_ENV: "off"}))


def test_development_refuses_nothing():
    assert verify_environment({E.WORDING_ENV: "sometimes", E.URL_ENV: "ftp://x"}) == []


def test_a_sound_meaning_configuration_has_no_problem():
    cfg = E.configured(GOOD)
    assert cfg.problems == () and cfg.meaning_settings is not None
    assert cfg.meaning_configured
    assert not any("NOCTORNAL_EMBED" in p for p in _prod(**GOOD))


def test_meaning_is_off_when_the_url_is_unset():
    cfg = E.configured({E.MODEL_ENV: "m", E.CEILING_ENV: "AMBER"})
    assert cfg.meaning_settings is None and not cfg.meaning_configured
    assert cfg.problems == ()


@pytest.mark.parametrize("change,variable", [
    ({E.MODEL_ENV: None}, E.MODEL_ENV),
    ({E.CEILING_ENV: None}, E.CEILING_ENV),
    ({E.CEILING_ENV: "SECRET"}, E.CEILING_ENV),
    ({E.URL_ENV: "ftp://models.example.org/v1"}, E.URL_ENV),
    ({E.URL_ENV: "https://user:pw@models.example.org/v1"}, E.URL_ENV),
    ({E.URL_ENV: "https://models.example.org/v1?k=1"}, E.URL_ENV),
    ({E.URL_ENV: "https://models.example.org/v1#x"}, E.URL_ENV),
    ({E.URL_ENV: "http://169.254.169.254/v1"}, E.URL_ENV),
    ({E.URL_ENV: "http://metadata.google.internal/v1"}, E.URL_ENV),
    ({E.MAX_CHARS_ENV: "50"}, E.MAX_CHARS_ENV),
    ({E.BATCH_ENV: "500"}, E.BATCH_ENV),
    ({E.TIMEOUT_ENV: "soon"}, E.TIMEOUT_ENV),
    ({E.DIMENSIONS_ENV: "1024"}, E.DIMENSIONS_ENV),
    ({E.AUTHORITY_ENV: "replace-me"}, E.AUTHORITY_ENV),
    ({E.MESSAGE_AUTHORITY_ENV: "REPLACE-ME please"}, E.MESSAGE_AUTHORITY_ENV),
    ({E.LOCAL_HOST_ENV: "other.example.org"}, E.LOCAL_HOST_ENV),
    ({E.NETWORK_ENV: "10.0.0.0/8"}, E.NETWORK_ENV),
    ({E.CA_FILE_ENV: "/no/such/bundle.pem"}, E.CA_FILE_ENV),
])
def test_each_meaning_problem_is_refused_in_production_without_its_value(change, variable):
    env = {**GOOD, **change}
    env = {k: v for k, v in env.items() if v is not None}
    cfg = E.configured(env)
    assert cfg.meaning_settings is None
    problems = [p for p in _prod(**env) if variable in p]
    assert problems, (variable, _prod(**env))
    for value in change.values():
        if value and value not in ("50", "500", "1024", "soon"):
            assert all(value not in p for p in problems)


def test_the_key_is_a_credential_by_name_and_never_in_repr():
    cfg = E.configured({**GOOD, E.KEY_ENV: "sk-live-abcdefgh"})
    assert "sk-live" not in repr(cfg.meaning_settings)
    from noctornal_api.config import _carries_credential
    assert _carries_credential(E.KEY_ENV) and _carries_credential(E.URL_ENV)


def _reads_embed_setting(tree: ast.AST) -> list[int]:
    lines = []
    for node in ast.walk(tree):
        args = []
        if isinstance(node, ast.Call):
            name = (node.func.attr if isinstance(node.func, ast.Attribute)
                    else getattr(node.func, "id", ""))
            if name in ("get", "getenv", "pop", "setdefault"):
                args = node.args
        elif isinstance(node, ast.Subscript):
            args = [node.slice]
        for arg in args:
            if (isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                    and arg.value.startswith("NOCTORNAL_EMBED_")):
                lines.append(node.lineno)
    return lines


def test_no_other_module_reads_a_similarity_setting():
    offenders = {}
    for base in (SRC, SCRIPTS):
        for path in base.rglob("*.py"):
            if path.name == "embedders.py":
                continue
            found = _reads_embed_setting(ast.parse(path.read_text(encoding="utf-8")))
            if found:
                offenders[str(path)] = found
    assert not offenders, offenders


def test_the_query_hash_is_keyed_and_absent_without_a_pepper(monkeypatch):
    """ingest._pepper raises when unset, and a
    query must not fail because ingest was never set up; a bare sha256 of a
    short query is reversed by guessing."""
    import hashlib

    from noctornal_api.embeddings import query_hmac
    monkeypatch.delenv("NOCTORNAL_INGEST_PEPPER", raising=False)
    assert query_hmac("vendor42") is None
    monkeypatch.setenv("NOCTORNAL_INGEST_PEPPER", "a pepper long enough to use")
    keyed = query_hmac("vendor42")
    assert keyed and keyed != hashlib.sha256(b"vendor42").hexdigest()
    assert keyed == query_hmac("vendor42") != query_hmac("vendor43")

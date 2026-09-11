"""The exhibit size cap is a declared policy, not a constant (2026-09-11).

Pure: the reader, the readiness check (which opens no connection), and
the console/document contract, read from the shipped files.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from noctornal_api.config import (
    DEFAULT_UPLOAD_CAP,
    EVIDENCE_CAP_ENV,
    SAMPLE_CAP_ENV,
    cap_problem,
    declared_cap,
    parse_size,
)

ROOT = Path(__file__).resolve().parents[3]
STATIC = ROOT / "apps" / "api" / "src" / "noctornal_api" / "http" / "static"


@pytest.mark.parametrize("text, expected", [
    ("268435456", 268435456), ("256MiB", 256 << 20), ("256M", 256 << 20),
    ("256MB", 256 << 20), ("1GiB", 1 << 30), ("2 g", 2 << 30),
    ("4096KiB", 4096 << 10), ("1048576B", 1 << 20), (" 512 MiB ", 512 << 20),
])
def test_sizes_parse_in_every_spelling_an_operator_writes(text, expected):
    assert parse_size(text) == expected


@pytest.mark.parametrize("text", ["", "lots", "256MB2", "-1", "1.5GiB",
                                  "256 TiB", "MiB", "0x100"])
def test_what_is_not_a_size_is_refused(text):
    with pytest.raises(ValueError):
        parse_size(text)


def test_the_cap_defaults_only_when_nothing_is_declared(monkeypatch):
    monkeypatch.delenv(EVIDENCE_CAP_ENV, raising=False)
    assert declared_cap(EVIDENCE_CAP_ENV) == DEFAULT_UPLOAD_CAP
    assert cap_problem(EVIDENCE_CAP_ENV) is None
    monkeypatch.setenv(EVIDENCE_CAP_ENV, "512MiB")
    assert declared_cap(EVIDENCE_CAP_ENV) == 512 << 20
    monkeypatch.setenv(EVIDENCE_CAP_ENV, "   ")            # unset as far as a reader goes
    assert declared_cap(EVIDENCE_CAP_ENV) == DEFAULT_UPLOAD_CAP


@pytest.mark.parametrize("value, fragment", [
    ("lots", "not a size"), ("1", "between 1 MiB and 64 GiB"), ("65GiB", "between"),
])
def test_an_unusable_declaration_is_loud_at_import(monkeypatch, value, fragment):
    """A typo in a cap must not quietly become 256 MiB."""
    monkeypatch.setenv(EVIDENCE_CAP_ENV, value)
    assert fragment in cap_problem(EVIDENCE_CAP_ENV)
    with pytest.raises(RuntimeError, match=fragment):
        declared_cap(EVIDENCE_CAP_ENV)


def test_the_readiness_check_reads_what_this_process_enforces(monkeypatch):
    """Two facts: declared or defaulted, and whether the environment still
    says what the routers started with. The routers read the declaration
    once at import, so an edit without a restart is a register that would
    otherwise report a cap the process is not applying."""
    from noctornal_api import readiness, samples
    from noctornal_api.http.routers import evidence as evidence_router
    monkeypatch.delenv(EVIDENCE_CAP_ENV, raising=False)
    monkeypatch.delenv(SAMPLE_CAP_ENV, raising=False)
    monkeypatch.setattr(evidence_router, "MAX_EVIDENCE_BYTES", 256 << 20)
    monkeypatch.setattr(samples, "MAX_SAMPLE_BYTES", 256 << 20)

    unset = readiness._evidence_size_cap_declared(None)
    assert unset.ok is False and "unset" in unset.evidence and "256 MiB" in unset.evidence

    monkeypatch.setenv(EVIDENCE_CAP_ENV, "268435456")
    declared = readiness._evidence_size_cap_declared(None)
    assert declared.ok is True and "256 MiB" in declared.evidence
    assert SAMPLE_CAP_ENV in declared.evidence            # says the sample cap is defaulted

    monkeypatch.setenv(EVIDENCE_CAP_ENV, "1GiB")           # edited, not restarted
    stale = readiness._evidence_size_cap_declared(None)
    assert stale.ok is False and "restart" in stale.evidence and "1024 MiB" in stale.evidence

    monkeypatch.setenv(EVIDENCE_CAP_ENV, "lots")
    junk = readiness._evidence_size_cap_declared(None)
    assert junk.ok is False and "not a size" in junk.evidence

    monkeypatch.setenv(EVIDENCE_CAP_ENV, "268435456")
    monkeypatch.setenv(SAMPLE_CAP_ENV, "64MiB")            # the other cap, edited
    other = readiness._evidence_size_cap_declared(None)
    assert other.ok is False and SAMPLE_CAP_ENV in other.evidence

    assert "evidence_size_cap_declared" in readiness.CHECK_NAMES
    assert "evidence_size_cap_declared" not in readiness.BLOCKING_CHECKS


def test_the_console_asks_for_the_policy_and_refuses_before_uploading():
    """Both sides of the picker contract: the console reads the two
    policy responses, names the caps beside both file inputs, and refuses
    a file over the cap before the upload starts (the server stays the
    authority)."""
    app_js = (STATIC / "app.js").read_text(encoding="utf-8")
    index = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "cpath('/evidence/policy')" in app_js
    assert "smpPolicy.max_sample_bytes" in app_js
    assert 'id="ev-cap"' in index and 'id="smp-cap"' in index
    assert len(re.findall(r"file\.size > cap", app_js)) == 2, \
        "both upload handlers compare the file against the cap"


def test_the_documents_and_the_template_declare_it():
    """docs/08 owns the policy; the production template declares the
    variable UNCOMMENTED, because the boot refuses without it; the
    production README names the check."""
    governance = (ROOT / "docs" / "08-governance.md").read_text(encoding="utf-8")
    assert "## Exhibit size policy" in governance
    assert EVIDENCE_CAP_ENV in governance and "evidence_size_cap_declared" in governance
    template = (ROOT / "infra" / "production" / "secrets.env.example").read_text(
        encoding="utf-8")
    assert re.search(rf"^{EVIDENCE_CAP_ENV}=\S+", template, re.M), \
        "the template must declare the evidence cap on an uncommented line"
    readme = (ROOT / "infra" / "production" / "README.md").read_text(encoding="utf-8")
    assert "evidence_size_cap_declared" in readme

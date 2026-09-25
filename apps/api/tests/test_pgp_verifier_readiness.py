"""The pgp_verifier readiness row (F10a, comms, 2026-09-24).

With no gpg, or one below the version floor, every signature check
records NO_VERIFIER and no binding can be confirmed, and until this row
nothing said so (the production image carried gpgv, not gpg). Not
blocking: a deployment without it is honest about what it cannot check.
Pure: the probe reads no table.
"""
from __future__ import annotations

import pytest

from noctornal_api import pgp, readiness


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.delenv(pgp.PATCHED_AS_ENV, raising=False)
    pgp._version_line.cache_clear()
    yield


def test_no_gpg_fails_and_says_what_to_install(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_GPG", "/nonexistent/gpg-binary")
    check = readiness._pgp_verifier(None)
    assert check.ok is False
    assert "NO_VERIFIER" in check.evidence
    assert "does not exist" in check.evidence
    assert "GnuPG 2.4.9" in check.action and pgp.PATCHED_AS_ENV in check.action


def test_a_gpg_below_the_floor_fails_naming_the_version(monkeypatch):
    monkeypatch.setattr(pgp, "gpg_path", lambda: "/usr/bin/gpg")
    monkeypatch.setattr(pgp, "_version_line", lambda path: "gpg (GnuPG) 2.4.4")
    check = readiness._pgp_verifier(None)
    assert check.ok is False
    assert "2.4.4" in check.evidence and "2.4.9" in check.evidence


def test_an_attested_distribution_build_passes_and_says_so(monkeypatch):
    monkeypatch.setattr(pgp, "gpg_path", lambda: "/usr/bin/gpg")
    monkeypatch.setattr(pgp, "_version_line", lambda path: "gpg (GnuPG) 2.4.4")
    monkeypatch.setenv(pgp.PATCHED_AS_ENV, "2.4.9")
    check = readiness._pgp_verifier(None)
    assert check.ok is True
    assert "attested by the operator" in check.evidence


def test_a_current_gpg_passes(monkeypatch):
    monkeypatch.setattr(pgp, "gpg_path", lambda: "/usr/bin/gpg")
    monkeypatch.setattr(pgp, "_version_line", lambda path: "gpg (GnuPG) 2.4.9")
    check = readiness._pgp_verifier(None)
    assert check.ok is True
    assert check.evidence.startswith("GnuPG 2.4.9 at /usr/bin/gpg")


def test_the_row_is_registered_and_not_blocking():
    assert "pgp_verifier" in readiness.CHECK_NAMES
    assert "pgp_verifier" not in readiness.BLOCKING_CHECKS
    assert "pgp_verifier" not in readiness.CONSEQUENCES

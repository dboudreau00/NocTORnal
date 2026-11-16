"""The keyed hashes the audit log records for a peer's address and a failed sign-in's typed identifier
(`security/audit_hash.py`).

Pure: no database. The pepper is set per test through the environment, which is where the module reads
it on every call.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re

import pytest

from noctornal_api.security import audit_hash

PEPPER = "first-audit-pepper-not-a-real-one"
OTHER = "second-audit-pepper-not-a-real-one"
ADDRESS = "203.0.113.9"


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    """No development key and no rate-limit memory carried in from another test."""
    monkeypatch.setattr(audit_hash, "_development_key", None)
    monkeypatch.setattr(audit_hash, "_unset_said_at", None)
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    monkeypatch.setenv(audit_hash.PEPPER_ENV, PEPPER)


def test_the_ip_hash_is_keyed_so_the_same_address_hashes_differently_under_two_peppers(monkeypatch):
    first = audit_hash.ip_hash(ADDRESS)
    assert audit_hash.ip_hash(ADDRESS) == first, "one key, one address, one hash"
    monkeypatch.setenv(audit_hash.PEPPER_ENV, OTHER)
    assert audit_hash.ip_hash(ADDRESS) != first


def test_the_ip_hash_is_16_bytes_and_never_equals_the_old_sha256():
    got = audit_hash.ip_hash(ADDRESS)
    assert isinstance(got, bytes) and len(got) == audit_hash.IP_HASH_BYTES == 16
    old = hashlib.sha256(ADDRESS.encode()).digest()
    assert len(old) == 32, "the length is what tells a legacy row from a keyed one"
    assert got != old and got != old[:16]


def test_an_ip_hash_and_an_identifier_hash_of_one_value_are_domain_separated():
    value = "analyst@agency.example.org"
    as_address = audit_hash.ip_hash(value)
    as_identifier = audit_hash.identifier_hash(value)
    assert as_address.hex()[:audit_hash.IDENT_HEX_CHARS] != as_identifier
    unlabelled = hmac.new(PEPPER.encode(), value.encode(), hashlib.sha256).digest()
    assert as_address != unlabelled[:16]
    assert as_identifier != unlabelled.hex()[:16]


def test_the_hashes_are_hmac_sha256_under_their_labels():
    """Pinned, so the line docs/17 gives a Security Officer who holds the pepper recomputes a stored
    `email_hmac` for a candidate address."""
    value = "analyst@agency.example.org"
    key = PEPPER.encode()
    assert audit_hash.identifier_hash(value) == hmac.new(
        key, b"noctornal/audit/identifier/v1\0" + value.encode(), "sha256").hexdigest()[:16]
    assert audit_hash.ip_hash(ADDRESS) == hmac.new(
        key, b"noctornal/audit/ip/v1\0" + ADDRESS.encode(), "sha256").digest()[:16]


def test_the_key_is_the_stripped_value(monkeypatch):
    """Stripped, as the boot refusal and the readiness row read it: a pepper read out of a secret file
    with a trailing newline is the same key."""
    want = audit_hash.ip_hash(ADDRESS)
    monkeypatch.setenv(audit_hash.PEPPER_ENV, f"  {PEPPER}\n")
    assert audit_hash.ip_hash(ADDRESS) == want


@pytest.mark.parametrize("address", [None, ""])
def test_no_address_hashes_to_none(address):
    assert audit_hash.ip_hash(address) is None


def test_the_identifier_hash_is_16_hex_chars():
    accented, lone_surrogate = "caf" + chr(0xE9) + "@example.test", chr(0xD800)
    for value in ("", "x", "Hunter2@home.net", "p" * 4096, accented, lone_surrogate):
        got = audit_hash.identifier_hash(value)
        assert re.fullmatch(r"[0-9a-f]{16}", got), (value[:10], got)
    assert audit_hash.identifier_hash("a") != audit_hash.identifier_hash("b")


def test_a_production_process_with_no_audit_pepper_records_no_hash_and_never_falls_back_to_sha256(
        monkeypatch, caplog):
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    for unset in (None, "", "   "):
        if unset is None:
            monkeypatch.delenv(audit_hash.PEPPER_ENV, raising=False)
        else:
            monkeypatch.setenv(audit_hash.PEPPER_ENV, unset)
        with caplog.at_level(logging.ERROR, logger="noctornal.audit_hash"):
            assert audit_hash.ip_hash(ADDRESS) is None
            assert audit_hash.identifier_hash("Hunter2@home.net") is None
    assert audit_hash._development_key is None, "production never makes a key of its own"
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    # Six rows without a key inside the window are one line, naming the variable.
    assert len(errors) == 1, [r.getMessage() for r in errors]
    assert audit_hash.PEPPER_ENV in errors[0].getMessage()


def test_the_production_error_line_is_said_again_once_the_window_has_passed(monkeypatch, caplog):
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv(audit_hash.PEPPER_ENV, raising=False)
    clock = [1000.0]
    monkeypatch.setattr(audit_hash.time, "monotonic", lambda: clock[0])
    with caplog.at_level(logging.ERROR, logger="noctornal.audit_hash"):
        audit_hash.ip_hash(ADDRESS)
        clock[0] += audit_hash.UNSET_LOG_SECONDS - 1
        audit_hash.ip_hash(ADDRESS)
        clock[0] += 2
        audit_hash.ip_hash(ADDRESS)
    assert len([r for r in caplog.records if r.levelno == logging.ERROR]) == 2


def test_a_development_process_with_no_audit_pepper_uses_a_random_key_that_is_stable_within_the_process(
        monkeypatch, caplog):
    monkeypatch.delenv(audit_hash.PEPPER_ENV, raising=False)
    with caplog.at_level(logging.WARNING, logger="noctornal.audit_hash"):
        first = audit_hash.ip_hash(ADDRESS)
        assert audit_hash.ip_hash(ADDRESS) == first
        assert audit_hash.identifier_hash("x") == audit_hash.identifier_hash("x")
    assert len(first) == 16 and first != hashlib.sha256(ADDRESS.encode()).digest()[:16]
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1, "one warning for the process, not one per row"
    assert audit_hash.PEPPER_ENV in warnings[0].getMessage()
    # A process that restarted has another key, so nothing correlates across it.
    monkeypatch.setattr(audit_hash, "_development_key", None)
    assert audit_hash.ip_hash(ADDRESS) != first


# ---------------------------------------------------------------------------
# The verdict the boot refusal and the readiness row share
# ---------------------------------------------------------------------------

def test_a_long_pepper_of_its_own_is_usable():
    state = audit_hash.pepper_state({audit_hash.PEPPER_ENV: PEPPER})
    assert state == (True, len(PEPPER), "")


@pytest.mark.parametrize("value", [None, "", "   "])
def test_an_unset_pepper_is_not_usable(value):
    env = {} if value is None else {audit_hash.PEPPER_ENV: value}
    assert audit_hash.pepper_state(env) == (
        False, 0, f"{audit_hash.PEPPER_ENV} is not set")


def test_a_short_pepper_is_not_usable_and_its_value_is_never_quoted():
    short = "Sh0rt-pepper-15"
    assert len(short) == audit_hash.MIN_PEPPER_CHARS - 1
    state = audit_hash.pepper_state({audit_hash.PEPPER_ENV: short})
    assert not state.ok and state.length == 15
    assert state.why == f"{audit_hash.PEPPER_ENV} is 15 characters, fewer than 16"
    assert short not in state.why
    one = audit_hash.pepper_state({audit_hash.PEPPER_ENV: "x"})
    assert one.why == f"{audit_hash.PEPPER_ENV} is 1 character, fewer than 16"
    assert audit_hash.pepper_state({audit_hash.PEPPER_ENV: "y" * 16}).ok


@pytest.mark.parametrize("other", audit_hash.OTHER_SECRETS)
def test_a_pepper_that_is_another_secret_is_not_usable(other):
    assert set(audit_hash.OTHER_SECRETS) == {"NOCTORNAL_INGEST_PEPPER", "NOCTORNAL_TOTP_KEK"}
    state = audit_hash.pepper_state({audit_hash.PEPPER_ENV: PEPPER, other: f"{PEPPER}\n"})
    assert state == (False, len(PEPPER), f"{audit_hash.PEPPER_ENV} is the same value as {other}")
    assert PEPPER not in state.why


def test_the_verdict_reads_the_process_environment_by_default(monkeypatch):
    monkeypatch.setenv(audit_hash.PEPPER_ENV, "z" * 20)
    assert audit_hash.pepper_state().ok
    monkeypatch.setenv("NOCTORNAL_INGEST_PEPPER", "z" * 20)
    assert not audit_hash.pepper_state().ok


# ---------------------------------------------------------------------------
# The writers
# ---------------------------------------------------------------------------

def _request(peer: str):
    from starlette.requests import Request
    return Request({"type": "http", "method": "GET", "path": "/", "headers": [],
                    "client": (peer, 40000)})


def test_every_audit_ip_hash_writer_records_the_keyed_16_byte_hash(monkeypatch):
    """The four functions that hand `ip_hash` to `audit.event` and `lab.download_ticket` (the sign-in
    rows, the rate-limit refusals, the rejected sessions, and the sample and production tickets through
    `samples._ip_hash`) all record `audit_hash.ip_hash` of the address `client_ip` reads."""
    from noctornal_api.http import limits, session_rejections
    from noctornal_api.http.routers import auth, evidence, samples

    monkeypatch.delenv("NOCTORNAL_TRUSTED_PROXY_HOPS", raising=False)
    want = audit_hash.ip_hash(ADDRESS)
    assert len(want) == 16
    writers = (auth._ip_hash, limits._ip_hash, session_rejections.ip_hash, samples._ip_hash,
               evidence._ip_hash)
    for writer in writers:
        assert writer(_request(ADDRESS)) == want, writer.__module__
    assert evidence._ip_hash is samples._ip_hash


_ADDRESS_WORDS = re.compile(r"\b(ip|address|addr|peer|client_ip)\b")


def _unkeyed_hashes_of(words: re.Pattern) -> list[str]:
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    found = []
    for base in (root / "apps" / "api" / "src", root / "scripts"):
        for path in base.rglob("*.py"):
            if path.name == "audit_hash.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = ast.unparse(node.func)
                # Unkeyed digests only: `hmac.new` takes a key, and is what a keyed hash looks like.
                if not re.fullmatch(r"(hashlib\.)?(sha256|sha1|md5|blake2b|blake2s)|hashlib\.new", name):
                    continue
                if any(words.search(ast.unparse(arg)) for arg in node.args):
                    found.append(f"{path.relative_to(root)}:{node.lineno}")
    return found


_IDENTIFIER_WORDS = re.compile(r"\b(email|identifier|typed|username|login)\b")


def test_only_audit_hash_hashes_a_peer_address_or_a_typed_identifier():
    """A fifth private copy of `sha256(client_ip(...))`, or the old `sha256(email)` prefix, would be an
    unkeyed hash back in the audit log. The rate limiter's Redis subject keys (`ratelimit.hashed`) take
    a subject string, not an address, and are a transient store."""
    assert _unkeyed_hashes_of(_ADDRESS_WORDS) == []
    assert _unkeyed_hashes_of(_IDENTIFIER_WORDS) == []


def test_every_failed_signin_writer_records_the_typed_identifier_through_audit_hash():
    """The console's sign-in and the two scripts that sign an operator in write AUTH_FAILED; each
    records what was typed through `typed_identifier`, and none puts the value under `email`."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    writers = {path: path.read_text(encoding="utf-8")
               for base in (root / "apps" / "api" / "src", root / "scripts")
               for path in base.rglob("*.py")
               if re.search(r"""['"]AUTH_FAILED['"]""", path.read_text(encoding="utf-8"))}
    named = {p.name for p in writers}
    assert {"auth.py", "telegram_persona.py", "egress_setup.py"} <= named, named
    for path, text in writers.items():
        if path.name == "bootstrap.py":
            continue  # prints a query for the operator, writes no row
        assert "typed_identifier(" in text, path.name
        assert not re.search(r"""['"]email['"]\s*:\s*(body\.)?email\b""", text), path.name

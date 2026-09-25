"""Reading vendor keys with gpg for the case key registry (F10b, comms,
2026-09-24). Pure: no database. Not gated on gpg, for the reason
test_pgp.py gives.

Every key is attacker material: the walker refuses secret packets and
anything that is not public key framing before gpg runs, gpg runs with no
agent under one budget, the colon listing is split on b"\\n" only, and a
user ID is decoded for display and never decided on.
"""
from __future__ import annotations

import base64
import subprocess

import pytest

from noctornal_api import pgp, pgp_keys
from noctornal_api.pgp import PgpError
from noctornal_api.pgp_keys import _colon_records, _mbox, _parse_listing, inspect_keys
from pgp_support import SUB_PRIMARY, SUB_SIGNING, VENDOR_FPR, fix, fix_bytes


def _no_subprocess(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("gpg was run on input the walker should refuse")
    monkeypatch.setattr(subprocess, "run", refuse)


def _armour(kind: str, data: bytes) -> bytes:
    body = base64.b64encode(data).decode()
    return (f"-----BEGIN PGP {kind}-----\n\n{body}\n"
            f"-----END PGP {kind}-----\n").encode()


def test_the_vendor_key_inspects_to_its_fingerprint_and_user_id():
    keys = inspect_keys(fix_bytes("vendor_pub.asc"))
    assert [k.primary_fingerprint for k in keys] == [VENDOR_FPR]
    assert keys[0].user_ids and keys[0].user_ids[0]["mbox"] == "t@example.invalid"
    assert keys[0].material.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert len(keys[0].material_sha256) == 32


def test_a_signing_subkey_is_listed_with_its_capability():
    (key,) = inspect_keys(fix_bytes("subkey_pub.asc"))
    assert key.primary_fingerprint == SUB_PRIMARY
    assert [s["fingerprint"] for s in key.subkeys] == [SUB_SIGNING]
    assert "s" in key.subkeys[0]["capabilities"]
    assert key.user_ids[0]["mbox"] == "vendor@mail.fixture-vendor.net"


def test_a_multi_key_file_gives_one_row_per_primary():
    keys = inspect_keys(fix_bytes("multi_key_pub.asc"))
    assert {k.primary_fingerprint for k in keys} == {
        SUB_PRIMARY, fix("multi_second_fingerprint.txt").strip()}


def test_a_revoked_key_comes_back_revoked():
    (key,) = inspect_keys(fix_bytes("revoked_pub.asc"))
    assert key.primary_fingerprint == fix("revoked_fingerprint.txt").strip()
    assert key.revoked is True


def test_a_binary_key_file_reads_as_its_armoured_twin():
    (binary,) = inspect_keys(fix_bytes("wkd_vendor.bin"))
    assert binary.primary_fingerprint == SUB_PRIMARY


@pytest.mark.parametrize("data", [
    _armour("PRIVATE KEY BLOCK", bytes([0xC5, 2, 4, 0])),
    _armour("PUBLIC KEY BLOCK", bytes([0xC5, 2, 4, 0])),
    fix_bytes("wkd_vendor.bin") + bytes([0xC7, 2, 4, 0]),
    fix_bytes("detached_binary.asc"),
    b"not a key at all",
    b"",
], ids=["private-block", "tag-5-under-public-armour", "binary-tag-7",
        "a-detached-signature", "text", "empty"])
def test_what_is_not_public_key_material_is_refused_before_any_subprocess(
        monkeypatch, data):
    _no_subprocess(monkeypatch)
    with pytest.raises(PgpError):
        inspect_keys(data)


def test_more_than_eight_keys_is_refused(monkeypatch):
    listing = b"".join(
        b"pub:-:255:22:%016X:1790299864:::-:::scSC:::::ed25519:::0:\n"
        b"fpr:::::::::" + (f"{i:040X}").encode() + b":\n" for i in range(9))
    _fake_gpg(monkeypatch, listing)
    with pytest.raises(PgpError, match="at most 8"):
        inspect_keys(fix_bytes("vendor_pub.asc"))


def test_zero_keys_is_refused(monkeypatch):
    _fake_gpg(monkeypatch, b"")
    with pytest.raises(PgpError, match="no public key"):
        inspect_keys(fix_bytes("vendor_pub.asc"))


def test_an_import_that_read_secret_material_is_refused(monkeypatch):
    """gpg's own count is the third line after the walker and the absent
    agent: IMPORT_RES reporting a secret key read refuses the key."""
    _fake_gpg(monkeypatch, b"", import_res=b"1 0 1 0 0 0 0 0 0 1 0 0 0 0 0")
    with pytest.raises(PgpError, match="could not read this as a public key"):
        inspect_keys(fix_bytes("vendor_pub.asc"))


def _fake_gpg(monkeypatch, listing: bytes, *,
              import_res: bytes = b"1 0 1 0 0 0 0 0 0 0 0 0 0 0 0"):
    def fake_run(argv, *a, **k):
        if "--version" in argv:
            return subprocess.CompletedProcess(argv, 0, "gpg (GnuPG) 2.4.9\n", "")
        if "--import" in argv:
            return subprocess.CompletedProcess(
                argv, 0, b"[GNUPG:] IMPORT_RES " + import_res + b"\n", b"")
        if "--list-keys" in argv:
            return subprocess.CompletedProcess(argv, 0, listing, b"")
        return subprocess.CompletedProcess(
            argv, 0, b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n", b"")
    monkeypatch.setattr(subprocess, "run", fake_run)
    pgp._version_line.cache_clear()


def test_colon_parsing_splits_on_newline_only():
    """A user ID carrying U+0085 (an escaped colon too) stays one user ID:
    the listing is bytes, split on b"\\n"."""
    # gpg escapes a colon in a user ID as \x3a; U+0085 it leaves alone.
    injected = "\\x3a" * 9 + "B" * 40 + "\\x3a"
    listing = ("pub:-:255:22:AAAA:1790299864:::-:::cSC:::::ed25519:::0:\n"
               f"fpr:::::::::{VENDOR_FPR}:\n"
               f"uid:-::::1790299864::HASH::Vendor\u0085fpr{injected} "
               "<v@shop.example>::::::::::0:\n").encode("utf-8")
    (key,) = _parse_listing(listing)
    assert key["fingerprint"] == VENDOR_FPR
    assert len(key["user_ids"]) == 1
    assert key["user_ids"][0]["mbox"] == "v@shop.example"
    assert ":" in key["user_ids"][0]["uid"]


def test_a_user_id_with_invalid_utf8_is_replaced_for_display():
    rec = _colon_records(b"uid:-::::1::H::Bad \xff\xfe name <a@b.example>::\n")
    assert rec[0][9] == b"Bad \xff\xfe name <a@b.example>"
    listing = (b"pub:-:255:22:AAAA:1790299864:::-:::cSC:::::ed25519:::0:\n"
               + f"fpr:::::::::{VENDOR_FPR}:\n".encode()
               + b"uid:-::::1::H::Bad \xff\xfe name <a@b.example>::\n")
    (key,) = _parse_listing(listing)
    assert "�" in key["user_ids"][0]["uid"]
    assert key["user_ids"][0]["mbox"] == "a@b.example"


@pytest.mark.parametrize("uid,mbox", [
    ("Vendor <V@Shop.Example>", "v@shop.example"),
    ("Two <a@x.example> and <b@y.example>", "b@y.example"),
    ("bare@shop.example", "bare@shop.example"),
    ("No address here", None),
])
def test_the_mailbox_of_a_user_id(uid, mbox):
    assert _mbox(uid) == mbox


def test_the_exports_share_the_imports_budget(monkeypatch):
    """One budget per keyring: a fake clock that spends seven seconds per
    run leaves the later exports only what is left."""
    clock = {"now": 0.0}
    monkeypatch.setattr(pgp, "_monotonic", lambda: clock["now"])
    timeouts = []
    real = subprocess.run

    def timed(argv, *a, **k):
        if "--version" not in argv:
            timeouts.append(k["timeout"])
            clock["now"] += 7.0
        return real(argv, *a, **{**k, "timeout": 30})

    monkeypatch.setattr(subprocess, "run", timed)
    pgp._version_line.cache_clear()
    with pytest.raises(pgp.PgpUnavailable, match="did not return"):
        inspect_keys(fix_bytes("multi_key_pub.asc"))
    assert timeouts[:3] == [20.0, 13.0, 6.0]


def test_only_relative_paths_and_no_autostart_reach_gpg(monkeypatch):
    seen = []
    real = subprocess.run

    def spy(argv, *a, **k):
        seen.append(list(argv))
        return real(argv, *a, **k)

    monkeypatch.setattr(subprocess, "run", spy)
    inspect_keys(fix_bytes("vendor_pub.asc"))
    import re
    runs = [a for a in seen if "--version" not in a]
    assert runs
    for argv in runs:
        assert "--no-autostart" in argv
        assert not any(i.startswith("/") or re.match(r"^[A-Za-z]:", i)
                       for i in argv[1:]), argv


def test_no_usable_gpg_is_unavailable(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_GPG", "/nonexistent/gpg-binary")
    with pytest.raises(pgp_keys.PgpUnavailable):
        inspect_keys(fix_bytes("vendor_pub.asc"))

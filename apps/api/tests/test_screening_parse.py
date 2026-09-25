"""Prohibited-content screening, the pure half (F13, 2026-09-24).

The list parser is a parser of operator-supplied files, so it is tested as
hostile input: the length decides the algorithm, a prefix must agree with
it, one bad line refuses the whole list (a partial list is a silent gap),
and an error quotes at most sixteen printable characters. The derived gaps
use F11's vocabulary; the submission disposition follows the deployment;
the hash-set authority needs a real reference.
"""
from __future__ import annotations

import hashlib
import io

import pytest

from noctornal_api.screening import (
    MAX_LINE_BYTES,
    ScreeningError,
    hash_set_authority,
    parse_hash_list,
    read_lines,
    screening_gaps,
    submission_disposition_for,
)

MD5 = hashlib.md5(b"a").hexdigest()
SHA1 = hashlib.sha1(b"a").hexdigest()
SHA256 = hashlib.sha256(b"a").hexdigest()


def _parse(text: bytes) -> list[tuple[str, bytes]]:
    return list(parse_hash_list(read_lines(io.BytesIO(text))))


def test_the_digest_length_decides_the_algorithm():
    got = _parse(f"{MD5}\n{SHA1}\n{SHA256.upper()}\n".encode())
    assert [a for a, _ in got] == ["md5", "sha1", "sha256"]
    assert got[2][1] == bytes.fromhex(SHA256)


def test_a_prefix_must_agree_with_the_length():
    assert _parse(f"sha256:{SHA256}\nMD5:{MD5}\n".encode())[1][0] == "md5"
    with pytest.raises(ScreeningError, match="line 1: says sha1"):
        _parse(f"sha1:{SHA256}\n".encode())


def test_the_first_field_of_csv_tab_or_space_lines_is_taken():
    text = f"{SHA256},name.exe,1\n{MD5}\tfile\n{SHA1} trailing words\n{MD5};x\n"
    assert [a for a, _ in _parse(text.encode())] == ["sha256", "md5", "sha1", "md5"]


def test_comments_blank_lines_crlf_and_a_bom_are_handled():
    text = b"\xef\xbb\xbf# header\r\n\r\n   \n" + SHA256.encode() + b"\r\n#x\n"
    assert _parse(text) == [("sha256", bytes.fromhex(SHA256))]


def test_one_bad_line_refuses_the_whole_list_naming_its_number_and_quoting_at_most_16_characters():
    bad = b"zzzz\x00\x1b[31m" + b"Q" * 100
    with pytest.raises(ScreeningError) as err:
        _parse(SHA256.encode() + b"\n" + bad + b"\n" + MD5.encode() + b"\n")
    message = str(err.value)
    assert message.startswith("line 2:")
    quoted = message.split("begins ", 1)[1].split(")", 1)[0]
    assert len(quoted.strip("'")) <= 16
    assert "\x00" not in message and "\x1b" not in message
    assert "Q" * 17 not in message


def test_a_line_longer_than_the_bound_is_refused_not_buffered():
    huge = b"a" * (MAX_LINE_BYTES * 4)
    with pytest.raises(ScreeningError, match=f"longer than {MAX_LINE_BYTES}"):
        _parse(SHA256.encode() + b"\n" + huge)


def test_a_wrong_length_or_non_hex_entry_is_refused():
    for bad in (b"abc", SHA256[:-1].encode(), b"g" * 32, b"md5:" + b"0" * 31):
        with pytest.raises(ScreeningError, match="line 1"):
            _parse(bad + b"\n")


def test_duplicates_are_parsed_and_counted_once_by_the_import():
    """The parser hands every line on; the import stages them and counts
    DISTINCT (algorithm, digest), which test_screening_pg holds."""
    assert len(_parse(f"{SHA256}\n{SHA256}\n".encode())) == 2


def test_screening_gaps_use_the_f11_vocabulary():
    from noctornal_api.samples import DERIVED_GAP_STEPS, GAP_STATUSES
    none = screening_gaps("NOT_SCREENED", "PE/MZ")
    assert [g["step"] for g in none] == ["prohibited_content_screening"]
    screened = screening_gaps("NO_MATCH", "ZIP or OOXML")
    assert [g["step"] for g in screened] == [
        "prohibited_content_perceptual", "prohibited_content_archive_members"]
    for gap in none + screened:
        assert gap["status"] in GAP_STATUSES and gap["reason"]
        assert gap["step"] in DERIVED_GAP_STEPS


def test_submission_disposition_follows_the_deployment():
    assert submission_disposition_for("preserve", False) == ("preserve", [])
    assert submission_disposition_for("destroy", False) == ("not_stored", [])
    assert submission_disposition_for(None, False) == (
        "preserve", ["disposition_unrecognised"])


def test_a_case_hold_forces_preserve():
    assert submission_disposition_for("destroy", True) == (
        "preserve", ["case_legal_hold"])


def test_the_hash_set_authority_needs_a_real_reference():
    assert hash_set_authority({})[0] is None
    assert hash_set_authority({"NOCTORNAL_HASH_SET_AUTHORITY": "   "})[0] is None
    assert hash_set_authority(
        {"NOCTORNAL_HASH_SET_AUTHORITY": "replace-me"})[0] is None
    assert hash_set_authority({"NOCTORNAL_HASH_SET_AUTHORITY": "a b c"})[0] is None
    ok, problem = hash_set_authority({"NOCTORNAL_HASH_SET_AUTHORITY": "COUNSEL-7"})
    assert ok == "COUNSEL-7" and problem is None

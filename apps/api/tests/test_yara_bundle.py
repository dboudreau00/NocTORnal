"""Rule bundle intake, a hostile-input parser in the API process (F12 C,
2026-09-24).

A .yar/.yara file or a .zip of them, read with the standard library under
caps: the entry count and directory size are refused from the end record
BEFORE zipfile builds an object per entry (2026-09-24); entries are read
through a bounded reader that does not trust header sizes; zip bombs,
nested and encrypted archives, climbing, absolute, control-character and
case-colliding paths are refused by name;
anything that is not a rule is listed, never dropped.

Pure: no database.
"""
from __future__ import annotations

import io
import struct
import zipfile

import pytest

from noctornal_api import yara_rules
from noctornal_api.yara_rules import BundleError, parse_bundle

RULE = b'rule r { strings: $a = "abc" condition: $a }\n'


def _zip(entries, *, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def test_a_single_rule_file_is_one_accepted_entry():
    b = parse_bundle("rules.yar", RULE)
    assert [(f.path, f.status) for f in b.files] == [("rules.yar", "accepted")]
    with pytest.raises(BundleError, match=".yar or .yara"):
        parse_bundle("rules.txt", RULE)


def test_a_zip_bomb_is_refused_by_ratio_and_by_total(monkeypatch):
    with pytest.raises(BundleError, match="expands more than"):
        parse_bundle("b.zip", _zip([("a.yar", b"A" * (3 << 20))]))
    with pytest.raises(BundleError, match="larger than 8 MiB"):
        parse_bundle("b.zip", _zip([("a.yar", b"A" * (9 << 20))]))
    monkeypatch.setattr(yara_rules, "MAX_SOURCE_BYTES", 2000)
    with pytest.raises(BundleError, match="add up to more than"):
        parse_bundle("b.zip", _zip([(f"{i}.yar", RULE * 20) for i in range(4)],
                                   compression=zipfile.ZIP_STORED))


def test_header_sizes_are_not_trusted():
    """A central directory that lies about an entry's size: the bounded
    reader and zipfile's own check refuse it, and nothing is stored."""
    real = b"B" * 100_000
    data = bytearray(_zip([("a.yar", real)], compression=zipfile.ZIP_STORED))
    cd = data.rfind(b"PK\x01\x02")
    struct.pack_into("<I", data, cd + 24, 10)          # uncompressed size
    with pytest.raises(BundleError):
        parse_bundle("b.zip", bytes(data))


def test_the_entry_count_is_refused_before_zipfile_parses_the_directory(monkeypatch):
    monkeypatch.setattr(yara_rules, "MAX_ENTRIES", 10)
    data = _zip([(f"{i}.yar", RULE) for i in range(11)])

    def never(*a, **k):
        raise AssertionError("zipfile was asked to parse the directory")

    monkeypatch.setattr(yara_rules.zipfile, "ZipFile", never)
    with pytest.raises(BundleError, match="has 11 entries"):
        parse_bundle("b.zip", data)


def _directory(n: int) -> bytes:
    """`n` minimal central directory records (a one-byte name each)."""
    one = struct.pack("<4s4B4HL2L5H2L", b"PK\x01\x02", 20, 0, 20, 0, 0, 0, 0,
                      0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) + b"a"
    return one * n


def _lying_zip(n: int, *, zip64: bool, plain_total: int = 1,
               plain_size: int | None = None) -> bytes:
    """A zip whose real directory holds `n` records. The plain end record
    claims `plain_total` entries; with `zip64` a zip64 record and locator,
    which zipfile honours whatever the plain record says, name the real
    directory (a bypass found 2026-09-24)."""
    body = b"PK\x03\x04" + b"\x00" * 26 + b"a"
    cd = _directory(n)
    cd_at = len(body)
    out = body + cd
    if zip64:
        z64_at = len(out)
        out += struct.pack("<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0,
                           n, n, len(cd), cd_at)
        out += struct.pack("<4sIQI", b"PK\x06\x07", 0, z64_at, 1)
    size = len(cd) if plain_size is None else plain_size
    out += struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, plain_total,
                       plain_total, size, cd_at, 0)
    return out


def test_a_zip64_record_behind_a_lying_end_record_is_refused():
    """The bypass: the plain end record claims one entry and a
    46-byte directory, and a zip64 record names 6,000 entries. zipfile
    trusts the zip64 record; so does the preflight now."""
    data = _lying_zip(6000, zip64=True, plain_size=46)
    # The construction is a real bypass for zipfile left to itself.
    assert len(zipfile.ZipFile(io.BytesIO(data)).infolist()) == 6000
    with pytest.raises(BundleError, match="6000 entries"):
        parse_bundle("b.zip", data)


def test_an_understated_count_is_refused_by_what_zipfile_is_handed(monkeypatch):
    """A plain record that understates the count, and a zip64 one that
    hides past the preflight entirely: the guard counts the directory
    zipfile actually reads, before zipfile parses it, so no bound depends
    on a record the uploader wrote."""
    plain = _lying_zip(6000, zip64=False)
    assert len(zipfile.ZipFile(io.BytesIO(plain)).infolist()) == 6000
    parsed = []
    real_info = zipfile.ZipInfo

    class Counting(real_info):
        def __init__(self, *a, **k):
            parsed.append(1)
            super().__init__(*a, **k)

    monkeypatch.setattr(zipfile, "ZipInfo", Counting)
    with pytest.raises(BundleError, match="more than 5000 entries"):
        parse_bundle("b.zip", plain)
    assert parsed == []
    # With the preflight out of the way, the guard alone still holds.
    monkeypatch.setattr(yara_rules, "_zip_preflight", lambda data: None)
    with pytest.raises(BundleError, match="more than 5000 entries"):
        parse_bundle("b.zip", _lying_zip(6000, zip64=True, plain_size=46))
    assert parsed == []


def test_a_directory_larger_than_a_bundle_is_never_read(monkeypatch):
    """A consistent 5 MiB directory: refused by the preflight, and, with
    the preflight out of the way, by the guard before zipfile reads it."""
    body = b"PK\x03\x04" + b"\x00" * 26 + b"a"
    cd = _directory(1) + b"\x00" * (5 << 20)
    z64_at = len(body) + len(cd)
    data = (body + cd
            + struct.pack("<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0,
                          1, 1, len(cd), len(body))
            + struct.pack("<4sIQI", b"PK\x06\x07", 0, z64_at, 1)
            + struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, 46,
                          len(body), 0))
    with pytest.raises(BundleError, match="central directory is larger"):
        parse_bundle("b.zip", data)
    reads = []
    real_read = yara_rules._DirectoryGuard.read

    def watched(self, n=-1):
        reads.append(n)
        return real_read(self, n)

    monkeypatch.setattr(yara_rules, "_zip_preflight", lambda data: None)
    monkeypatch.setattr(yara_rules._DirectoryGuard, "read", watched)
    with pytest.raises(BundleError, match="central directory is larger"):
        parse_bundle("b.zip", data)
    assert max(reads) == len(cd)


@pytest.mark.parametrize("name, words", [
    ("../x.yar", "climbs"),
    ("a/../../x.yar", "climbs"),
    ("/etc/x.yar", "absolute"),
    ("C:/x.yar", "absolute"),
    ("a\x01b.yar", "control"),
    ("a\u202eb.yar", "control"),
    ("x" * 300 + ".yar", "longer than"),
])
def test_traversal_absolute_control_and_long_names_are_refused_by_name(name, words):
    with pytest.raises(BundleError, match=words) as err:
        parse_bundle("b.zip", _zip([(name, RULE)]))
    if words in ("control",):
        assert "\\x01" in str(err.value) or "\\u202e" in str(err.value)


def test_duplicate_names_by_case_are_refused():
    with pytest.raises(BundleError, match="differ only by case"):
        parse_bundle("b.zip", _zip([("A.yar", RULE), ("a.yar", RULE)]))


def test_non_rule_entries_are_listed_as_ignored_not_dropped():
    b = parse_bundle("b.zip", _zip([("r.yar", RULE), ("README.md", b"hi"),
                                    ("sub/", b""), ("x.exe", b"MZ")]))
    got = {f.path: (f.status, f.reason) for f in b.files}
    assert got["r.yar"] == ("accepted", None)
    assert got["README.md"] == ("ignored", "not a .yar or .yara file")
    assert got["x.exe"][0] == "ignored"
    _gz, meta = b.pack()
    assert {m["path"] for m in meta} == {"r.yar", "README.md", "x.exe"}


def test_non_utf8_rule_file_is_recorded_not_dropped():
    b = parse_bundle("b.zip", _zip([("ok.yar", RULE), ("bad.yar", b"\xff\xfe rule")]))
    got = {f.path: (f.status, f.reason) for f in b.files}
    assert got["bad.yar"] == ("ignored", "not UTF-8 text")
    with pytest.raises(BundleError, match="no .yar or .yara file"):
        parse_bundle("b.zip", _zip([("bad.yar", b"\xff\xfe rule")]))


def test_canonical_form_is_order_independent():
    one = parse_bundle("a.zip", _zip([("b.yar", RULE), ("a.yar", RULE + b"//")]))
    two = parse_bundle("a.zip", _zip([("a.yar", RULE + b"//"), ("b.yar", RULE)]))
    assert one.canonical() == two.canonical()
    assert one.pack()[0] == two.pack()[0]


def test_nested_and_encrypted_entries_are_refused():
    with pytest.raises(BundleError, match="itself an archive"):
        parse_bundle("b.zip", _zip([("inner.zip", _zip([("r.yar", RULE)]))]))
    with pytest.raises(BundleError, match="archive named as a rule file"):
        parse_bundle("b.zip", _zip([("r.yar", _zip([("x.yar", RULE)]))],
                                   compression=zipfile.ZIP_STORED))
    data = bytearray(_zip([("r.yar", RULE)]))
    cd = data.rfind(b"PK\x01\x02")
    flags = struct.unpack_from("<H", data, cd + 8)[0]
    struct.pack_into("<H", data, cd + 8, flags | 0x1)
    with pytest.raises(BundleError, match="encrypted"):
        parse_bundle("b.zip", bytes(data))


def test_one_member_per_file_so_a_view_decompresses_one_file():
    b = parse_bundle("b.zip", _zip([("a.yar", RULE), ("b.yar", RULE * 3)]))
    gz, meta = b.pack()
    by = {m["path"]: m for m in meta}
    text, cut = yara_rules.member_text(gz, by["b.yar"])
    assert text == (RULE * 3).decode() and not cut
    text, cut = yara_rules.member_text(gz, by["b.yar"], limit=10)
    assert cut and len(text) == 10
    assert yara_rules.stored_canonical(gz, meta) == b.canonical()


def test_settings_are_read_by_one_reader_and_refused_by_name():
    assert yara_rules.yara_settings({})[0] == yara_rules.YaraSettings(60, 32 << 20)
    _s, problem = yara_rules.yara_settings({yara_rules.SCAN_TIMEOUT_ENV: "4"})
    assert problem and yara_rules.SCAN_TIMEOUT_ENV in problem and "4" not in problem.split()
    _s, problem = yara_rules.yara_settings({yara_rules.MAX_UPLOAD_ENV: "2GiB"})
    assert problem and yara_rules.MAX_UPLOAD_ENV in problem

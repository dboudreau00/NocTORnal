"""The archive-expansion child and the parent's reading of it (roadmap
phase 8 "archive expansion", 2026-10-02).

Hostile input, as docs/11 asks for: a zip bomb (by ratio, and as a
compressed tar), a traversal name, an absolute path, a symbolic link, a
hard link, a device, a duplicate and a case-colliding name, a truncated
and a corrupt archive, a lying size field, an encrypted member with and
without the archive-password convention, a member count over the cap, an
unprintable name, an empty member, a gzip that is not a tar, and a child
that lies. Each is refused by name, nothing is dropped silently, and
nothing is ever extracted to a path.

Pure: no database. The walk is driven in process through
`lab_archive_child.expand` for the rules, and through the real child for
the wire, the runner and the parent's checks.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import struct
import sys
import tarfile
import zipfile

import pytest

from noctornal_api import lab_archive, lab_archive_child, lab_triage

CAPS = {"members": 50, "total_bytes": 8 << 20, "member_bytes": 2 << 20,
        "ratio": 100}
PASSWORD = b"infected"


def zip_of(entries, method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        for name, data in entries:
            if isinstance(name, zipfile.ZipInfo):
                zf.writestr(name, data)
            else:
                zf.writestr(name, data)
    return buf.getvalue()


def tar_of(entries, mode="w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for entry in entries:
            if isinstance(entry, tarfile.TarInfo):
                tf.addfile(entry)
                continue
            name, data = entry
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def expand(data: bytes, caps=None, password=PASSWORD):
    return lab_archive_child.expand(data, caps or CAPS, password)


def codes(report) -> dict[str, str]:
    return {r["path"]: r["code"] for r in report["refused"]}


# ---------------------------------------------------------------------------
# The happy paths
# ---------------------------------------------------------------------------

def test_a_zip_expands_into_its_members_and_records_its_directories():
    data = zip_of([("dir/", b""), ("dir/a.bin", b"MZ" + bytes(40)),
                   ("b.txt", b"hello " * 20)])
    report, payloads = expand(data)
    assert report["refusal"] is None and report["family"] == "zip"
    assert [m["path"] for m in report["members"]] == ["dir/a.bin", "b.txt"]
    assert [hashlib.sha256(p).hexdigest() for p in payloads] == [
        m["sha256"] for m in report["members"]]
    assert codes(report) == {"dir": "directory"}
    assert report["counts"] == {"entries": 3, "accepted": 2, "refused": 1}


@pytest.mark.parametrize("mode", ["w", "w:gz", "w:bz2", "w:xz"])
def test_tar_and_its_compressed_forms_expand_alike(mode):
    data = tar_of([("x/one.bin", b"one" * 100), ("two.bin", b"two" * 100)], mode)
    report, payloads = expand(data)
    assert report["refusal"] is None and report["family"] == "tar"
    assert [m["path"] for m in report["members"]] == ["x/one.bin", "two.bin"]
    assert payloads == [b"one" * 100, b"two" * 100]
    assert report["members"][0]["compressed_size"] is None


def test_the_file_type_of_each_archive_kind_is_what_the_parent_expands():
    from noctornal_api.samples import file_type_of
    assert file_type_of(zip_of([("a", b"x")])) == "ZIP or OOXML"
    assert file_type_of(tar_of([("a", b"x")], "w:gz")) == "gzip"
    assert file_type_of(tar_of([("a", b"x")], "w:bz2")) == "bzip2"
    assert file_type_of(tar_of([("a", b"x")], "w:xz")) == "xz"
    assert file_type_of(tar_of([("a", b"x")])) == "tar"
    assert file_type_of(b"Rar!\x1a\x07\x00" + bytes(300)) == "RAR"
    for kind in ("ZIP or OOXML", "gzip", "bzip2", "xz", "tar"):
        assert kind in lab_archive.EXPANDABLE
    assert set(lab_archive.UNSUPPORTED) == {"RAR", "7-Zip"}
    assert "not supported" in lab_archive.UNSUPPORTED["RAR"]
    assert "not supported" in lab_archive.UNSUPPORTED["7-Zip"]


# ---------------------------------------------------------------------------
# Hostile input
# ---------------------------------------------------------------------------

def test_a_zip_bomb_member_is_refused_by_its_ratio_and_the_rest_stand():
    data = zip_of([("bomb.bin", bytes(1 << 20)), ("fine.bin", b"ok" * 300)])
    report, payloads = expand(data)
    assert report["refusal"] is None
    assert codes(report)["bomb.bin"] == "ratio"
    refused = next(r for r in report["refused"] if r["path"] == "bomb.bin")
    assert refused["detail"]["ratio"] > 100 and refused["detail"]["cap"] == 100
    assert [m["path"] for m in report["members"]] == ["fine.bin"]
    assert report["total_bytes"] == 600


def test_a_compressed_tar_bomb_is_refused_whole_by_the_archive_ratio():
    data = tar_of([("zeros.bin", bytes(32 << 20))], "w:gz")
    assert len(data) < 64 << 10
    caps = {**CAPS, "member_bytes": 64 << 20, "total_bytes": 64 << 20}
    report, payloads = expand(data, caps)
    assert report["refusal"]["code"] == "ratio"
    assert report["refusal"]["detail"]["cap"] == 100
    assert report["members"] == [] and payloads == []


def test_too_many_bytes_in_all_refuses_the_whole_archive():
    data = tar_of([(f"m{i}.bin", b"x" * (1 << 20)) for i in range(10)])
    report, payloads = expand(data, {**CAPS, "total_bytes": 4 << 20})
    assert report["refusal"]["code"] == "total_bytes"
    assert report["refusal"]["detail"]["cap"] == 4 << 20
    assert payloads == [] and report["members"] == []


def test_traversal_absolute_and_drive_names_are_refused():
    data = zip_of([("../evil.exe", b"x" * 10), ("/etc/passwd", b"x" * 10),
                   ("C:\\Windows\\evil.dll", b"x" * 10),
                   ("ok/../../evil2", b"x" * 10), ("//server/share", b"x" * 10),
                   ("good/./a.bin", b"x" * 10)])
    report, payloads = expand(data)
    # zipfile itself writes a backslash as a slash, so the drive name
    # arrives as C:/...; the child refuses it by its drive letter.
    assert codes(report) == {"../evil.exe": "parent_traversal",
                             "/etc/passwd": "absolute_path",
                             "C:/Windows/evil.dll": "absolute_path",
                             "ok/../../evil2": "parent_traversal",
                             "//server/share": "absolute_path"}
    assert lab_archive_child.safe_path("C:\\Windows\\evil.dll") == (None, "absolute_path")
    assert lab_archive_child.safe_path("a\\b\\..\\c") == (None, "parent_traversal")
    assert [m["path"] for m in report["members"]] == ["good/a.bin"]


def test_symbolic_links_hard_links_and_devices_are_refused():
    link = zipfile.ZipInfo("link")
    link.external_attr = 0o120777 << 16
    link.create_system = 3
    dev = zipfile.ZipInfo("dev")
    dev.external_attr = 0o020666 << 16
    dev.create_system = 3
    report, _ = expand(zip_of([(link, b"/etc/passwd"), (dev, b""),
                               ("plain", b"x" * 5)]))
    assert codes(report) == {"link": "symlink", "dev": "device"}
    assert [m["path"] for m in report["members"]] == ["plain"]

    sym = tarfile.TarInfo("sym")
    sym.type = tarfile.SYMTYPE
    sym.linkname = "/etc/passwd"
    hard = tarfile.TarInfo("hard")
    hard.type = tarfile.LNKTYPE
    hard.linkname = "plain"
    chr_ = tarfile.TarInfo("chr")
    chr_.type = tarfile.CHRTYPE
    fifo = tarfile.TarInfo("fifo")
    fifo.type = tarfile.FIFOTYPE
    report, _ = expand(tar_of([sym, hard, chr_, fifo, ("plain", b"x" * 5)]))
    assert codes(report) == {"sym": "symlink", "hard": "hardlink",
                             "chr": "device", "fifo": "device"}
    assert [m["path"] for m in report["members"]] == ["plain"]


def test_duplicate_and_case_colliding_names_keep_the_first():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("A.exe", b"first" * 4)
        zf.writestr("A.exe", b"second" * 4)
        zf.writestr("a.exe", b"third" * 4)
        zf.writestr("\ufb01le.txt", b"ligature" * 4)   # NFKC: file.txt
        zf.writestr("file.txt", b"plain" * 4)
        zf.writestr("x\\y.bin", b"back" * 4)
        zf.writestr("x/y.bin", b"forward" * 4)
    report, payloads = expand(buf.getvalue())
    assert [m["path"] for m in report["members"]] == ["A.exe", "\ufb01le.txt",
                                                      "x/y.bin"]
    assert payloads[0] == b"first" * 4
    assert codes(report) == {"A.exe": "duplicate_name", "a.exe": "case_collision",
                             "file.txt": "case_collision", "x/y.bin": "duplicate_name"}
    collision = next(r for r in report["refused"] if r["path"] == "file.txt")
    assert collision["detail"]["collides_with"] == "\ufb01le.txt"


def test_truncated_and_corrupt_archives_are_refused_whole():
    whole = zip_of([("a.bin", b"a" * 1000), ("b.bin", b"b" * 1000)])
    report, payloads = expand(whole[: len(whole) // 2])
    assert report["refusal"]["code"] == "corrupt" and payloads == []
    report, payloads = expand(b"PK\x03\x04" + bytes(range(256)) * 4)
    assert report["refusal"]["code"] == "corrupt" and payloads == []
    whole = tar_of([("a.bin", b"a" * 4000), ("b.bin", b"b" * 4000)])
    report, payloads = expand(whole[: 512 + 1000])
    assert report["refusal"]["code"] == "truncated" and payloads == []
    report, payloads = expand(gzip.compress(b"not a tar at all" * 10))
    assert report["refusal"]["code"] == "not_tar"
    report, payloads = expand(b"neither" * 100)
    assert report["refusal"]["code"] == "unknown_format"


def _patch_central_file_size(data: bytes, name: bytes, size: int) -> bytes:
    """Rewrite the central directory's uncompressed size of `name`."""
    at = data.rfind(b"PK\x01\x02")
    while at >= 0:
        n_len, = struct.unpack("<H", data[at + 28:at + 30])
        if data[at + 46:at + 46 + n_len] == name:
            return data[:at + 24] + struct.pack("<I", size) + data[at + 28:]
        at = data.rfind(b"PK\x01\x02", 0, at)
    raise AssertionError("entry not found")


def test_a_lying_size_field_is_refused():
    body = b"the truth " * 100
    data = zip_of([("lies.bin", body), ("fine.bin", b"ok" * 50)])
    shorter = _patch_central_file_size(data, b"lies.bin", 10)
    report, payloads = expand(shorter)
    assert codes(report)["lies.bin"] in ("corrupt_member", "size_mismatch")
    assert [m["path"] for m in report["members"]] == ["fine.bin"]
    longer = _patch_central_file_size(data, b"lies.bin", len(body) * 4)
    report, payloads = expand(longer)
    assert codes(report)["lies.bin"] in ("corrupt_member", "size_mismatch")
    assert [m["path"] for m in report["members"]] == ["fine.bin"]
    huge = _patch_central_file_size(data, b"lies.bin", 100 << 20)
    report, payloads = expand(huge)
    assert codes(report)["lies.bin"] == "member_bytes"
    assert report["refused"][0]["detail"]["declared"] == 100 << 20


def test_an_encrypted_member_opens_only_with_the_convention():
    from noctornal_api.samples import archive
    body = b"MZ" + bytes(range(256)) * 2
    digest = hashlib.sha256(body).hexdigest()
    convention = archive(body, digest)
    report, payloads = expand(convention)
    assert [m["path"] for m in report["members"]] == [f"{digest}.bin"]
    assert payloads == [body]
    other = archive(body, digest, password=b"not-the-convention")
    report, payloads = expand(other)
    assert codes(report) == {f"{digest}.bin": "encrypted_no_password"}
    assert payloads == []
    report, payloads = expand(convention, password=b"")
    assert codes(report) == {f"{digest}.bin": "encrypted_no_password"}


def test_a_wrong_password_that_passes_zipcrypto_check_byte_is_one_refused_member(
        monkeypatch):
    """The check byte is one byte, so one wrong password in 256 gets past it
    and decrypts to garbage: the member is refused, the archive is not."""
    import zlib

    from noctornal_api.samples import archive
    body = b"MZ" + bytes(range(256)) * 2
    digest = hashlib.sha256(body).hexdigest()
    real_read = zipfile.ZipExtFile.read

    def garbage(self, n=-1):
        raise zlib.error("Error -3 while decompressing data")

    monkeypatch.setattr(zipfile.ZipExtFile, "read", garbage)
    report, payloads = expand(archive(body, digest))
    monkeypatch.setattr(zipfile.ZipExtFile, "read", real_read)
    assert report["refusal"] is None
    assert codes(report) == {f"{digest}.bin": "encrypted_no_password"}
    assert payloads == []


def test_member_count_over_the_cap_is_refused_before_anything_is_read():
    data = zip_of([(f"m{i}", b"x" * 10) for i in range(4)])
    report, payloads = expand(data, {**CAPS, "members": 3})
    assert report["refusal"] == {"code": "member_count",
                                 "detail": {"entries": 4, "cap": 3}}
    assert report["counts"]["entries"] == 0, "the walk never started"
    data = tar_of([(f"m{i}", b"x" * 10) for i in range(4)])
    report, payloads = expand(data, {**CAPS, "members": 3})
    assert report["refusal"]["code"] == "member_count" and payloads == []


def test_an_unprintable_name_is_refused_and_recorded_escaped():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("evil\x01\t.exe", b"x" * 10)
        zf.writestr("fine.exe", b"x" * 10)
    report, _ = expand(buf.getvalue())
    refused = report["refused"][0]
    assert refused["code"] == "unprintable_name"
    assert refused["path"] == "evil\\x01\\t.exe" and refused["path"].isprintable()
    assert [m["path"] for m in report["members"]] == ["fine.exe"]
    report, _ = expand(zip_of([("x" * 600, b"x" * 10)]))
    assert report["refused"][0]["code"] == "name_too_long"


def test_an_empty_member_is_refused_and_a_declared_oversize_is_never_read():
    report, payloads = expand(zip_of([("empty", b""), ("big", b"x" * (3 << 20))]))
    assert codes(report) == {"empty": "empty", "big": "member_bytes"}
    assert payloads == []


@pytest.mark.parametrize("mode", ["w:bz2", "w:gz", "w:xz"])
def test_a_tiny_tar_declaring_a_huge_member_is_refused_by_ratio_before_it_is_skipped(mode):
    """The verifier's 171 byte tar.bz2: a member over the per-member cap used
    to be skipped through tarfile's quadratic stream seek, burning the child's
    whole wall clock and ending as a generic timeout. Its declared size is now
    held to the ratio first, and the archive is refused by name."""
    import time
    data = tar_of([("z.bin", bytes(48 << 20))], mode)
    assert len(data) < 64 << 10
    caps = {**CAPS, "member_bytes": 1 << 20, "total_bytes": 256 << 20}
    started = time.monotonic()
    report, payloads = expand(data, caps)
    assert report["refusal"] is not None and report["refusal"]["code"] == "ratio"
    assert report["refusal"]["detail"]["cap"] == 100
    assert report["members"] == [] and payloads == []
    assert time.monotonic() - started < 30


def test_bytes_skipped_over_the_member_cap_count_against_the_total():
    """A skipped member is decompressed too: the bytes read to get past it
    are held to the total cap as they are read, so no header can make the
    walk decompress more than the caps allow."""
    import os
    data = tar_of([("big.bin", os.urandom(3 << 20)), ("tail.bin", b"x" * 10)])
    caps = {**CAPS, "member_bytes": 1 << 20, "total_bytes": 2 << 20}
    report, payloads = expand(data, caps)
    assert report["refusal"]["code"] == "total_bytes"
    assert report["refusal"]["detail"]["cap"] == 2 << 20
    assert report["members"] == [] and payloads == []
    # Under the caps the over-cap member is still refused alone and the rest stand.
    report, payloads = expand(data, {**CAPS, "member_bytes": 1 << 20,
                                     "total_bytes": 8 << 20})
    assert report["refusal"] is None
    assert codes(report) == {"big.bin": "member_bytes"}
    assert [m["path"] for m in report["members"]] == ["tail.bin"]


# --- members a reader would never have seen (2026-10-07) -------
#
# Each of these left members of the archive unexpanded and unscreened with
# nothing refused, so the archive's card said every member was compared.

def test_a_zip_appended_to_another_zip_is_refused_whole():
    first = zip_of([("payload.exe", b"MZ" + bytes(4000))])
    second = zip_of([("readme.txt", b"nothing to see")])
    report, payloads = expand(first + second)
    assert report["refusal"]["code"] == "corrupt", report
    assert report["members"] == [] and payloads == []


def test_a_zip_link_or_device_mode_on_a_payload_does_not_hide_it():
    link = zipfile.ZipInfo("invoice.exe")
    link.external_attr = 0o120777 << 16
    dev = zipfile.ZipInfo("tool.exe")
    dev.external_attr = 0o020644 << 16
    payload = b"MZ" + bytes(100_000)
    report, payloads = expand(zip_of([(link, payload), (dev, b"MZ" + bytes(10)),
                                      ("plain", b"x" * 5)]))
    assert report["refused"] == []
    assert [m["path"] for m in report["members"]] == ["invoice.exe", "tool.exe", "plain"]
    assert payloads[0] == payload


def test_a_bad_tar_header_after_the_first_does_not_hide_the_members_behind_it():
    head = tar_of([("a.txt", b"a" * 10)])[:1024]  # one member, no end blocks
    rest = tar_of([("hidden.exe", b"MZ" + bytes(100)), ("hidden2.exe", b"MZ" + bytes(9))])
    report, _payloads = expand(head + b"\xff" * 512 + rest)
    assert report["refusal"]["code"] == "corrupt", report
    assert report["refusal"]["detail"]["error"] == "data_after_last_member"


@pytest.mark.parametrize("module", [gzip, __import__("bz2"), __import__("lzma")])
def test_every_stream_of_a_multi_stream_compressed_tar_is_read(module):
    """One tar split across two compressed streams (what `cat a.gz b.gz`
    makes) expands whole, as `tar xzf` reads it."""
    whole = tar_of([("a.txt", b"first " * 20), ("b.exe", b"MZ" + bytes(300))])
    cut = 512 + 512  # a.txt's header and its one block of data
    data = module.compress(whole[:cut]) + module.compress(whole[cut:])
    report, _payloads = expand(data)
    assert report["refusal"] is None, report
    assert [m["path"] for m in report["members"]] == ["a.txt", "b.exe"]


def test_a_second_tar_in_a_second_stream_is_refused_not_dropped():
    data = gzip.compress(tar_of([("a.txt", b"a" * 10)])) + gzip.compress(
        tar_of([("hidden.exe", b"MZ" + bytes(100))]))
    report, _payloads = expand(data)
    assert report["refusal"]["code"] == "corrupt", report


def test_a_tar_member_of_an_unknown_type_is_held_to_the_ratio_before_it_is_skipped():
    info = tarfile.TarInfo("odd")
    info.type = b"Z"
    info.size = 96 << 20
    raw = bytearray(tar_of([]))
    header = info.tobuf(format=tarfile.GNU_FORMAT)
    data = gzip.compress(bytes(header) + bytes(96 << 20) + bytes(raw), compresslevel=9)
    report, _payloads = expand(data, {**CAPS, "total_bytes": 256 << 20,
                                      "member_bytes": 128 << 20})
    assert report["refusal"]["code"] == "ratio", report


def test_nul_padding_after_the_end_of_a_tar_is_not_data():
    data = tar_of([("a.txt", b"a" * 10)]) + bytes(20480)
    report, _payloads = expand(data)
    assert report["refusal"] is None and [m["path"] for m in report["members"]] == ["a.txt"]


@pytest.mark.parametrize("module", [gzip, __import__("bz2"), __import__("lzma")])
def test_a_tiny_honest_compressed_tar_with_a_large_record_is_not_a_ratio_bomb(module):
    """A one-byte member in a tar written with 64 KiB records compresses to
    about a hundred bytes; the record's NUL padding is not held to the ratio."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"x"))
    raw = buf.getvalue()
    raw += bytes(-len(raw) % 65536)
    report, _payloads = expand(module.compress(raw))
    assert report["refusal"] is None, report
    assert [m["path"] for m in report["members"]] == ["a.txt"]


def test_megabytes_of_nul_padding_still_count_against_the_ratio():
    data = gzip.compress(tar_of([("a.txt", b"a" * 10)]) + bytes(64 << 20))
    report, _payloads = expand(data, {**CAPS, "total_bytes": 256 << 20})
    assert report["refusal"]["code"] == "ratio", report


def test_nothing_in_the_child_extracts_to_a_path():
    import ast
    import inspect
    source = inspect.getsource(lab_archive_child)
    # The code, not the docstring that names the forbidden calls.
    tree = ast.parse(source)
    code = source.replace(ast.get_docstring(tree), "")
    for forbidden in ("extractall", ".extract(", "open(path", "os.path.join",
                      "shutil", "tempfile"):
        assert forbidden not in code, forbidden
    assert "extractfile" in code, "the one read is the in-memory stream"
    assert "import os" not in code


# ---------------------------------------------------------------------------
# The wire, the runner and the parent's checks
# ---------------------------------------------------------------------------

@pytest.fixture
def settings():
    s, problem = lab_archive.archive_settings({})
    assert problem is None
    return s


@pytest.fixture
def analysis():
    return lab_triage.analysis_settings({})[0]


def test_the_real_child_answers_through_the_runner_and_the_parent_rehashes(settings, analysis):
    data = zip_of([("a/b.bin", b"MZ" + bytes(60)), ("../no", b"x" * 3),
                   ("c.txt", b"text " * 40)])
    result = lab_archive._expand_child(data, settings, analysis)
    assert result.ok, result.failure
    out = lab_archive._clean(result, settings)
    assert out.failure is None and out.refusal is None
    assert [m.path for m in out.members] == ["a/b.bin", "c.txt"]
    assert out.members[0].data == b"MZ" + bytes(60)
    assert out.refused == [{"path": "../no", "code": "parent_traversal",
                            "reason": lab_archive.MEMBER_SENTENCES["parent_traversal"]}]
    assert out.counts == {"entries": 3, "accepted": 2, "refused": 1}


def test_a_whole_refusal_through_the_child_names_its_limit(settings, analysis):
    data = zip_of([(f"m{i}", b"x" * 10) for i in range(settings.max_members + 1)])
    out = lab_archive._clean(lab_archive._expand_child(data, settings, analysis),
                             settings)
    assert out.failure is None and out.members == []
    assert lab_archive.MEMBERS_ENV in out.refusal
    assert str(settings.max_members + 1) in out.refusal


def test_a_child_that_lies_is_not_believed(tmp_path, settings, analysis, monkeypatch):
    """A report whose members do not hash to the bytes that came back, or a
    frame that is not one, fails the whole expansion; a refusal code or a
    path the child invents never reaches the record."""
    good = {"ok": True, "mode": "archive", "family": "zip", "refusal": None,
            "refused": [], "counts": {"entries": 1, "accepted": 1, "refused": 0},
            "members": [{"index": 0, "path": "x.bin", "size": 4,
                         "sha256": "0" * 64}]}
    script = tmp_path / "liar.py"
    script.write_text(
        "import sys, json, struct\nsys.stdin.buffer.readline()\n"
        "sys.stdin.buffer.read()\nbody = json.dumps(%r).encode()\n"
        "sys.stdout.buffer.write(struct.pack('>Q', len(body)) + body + b'abcd')\n"
        % good)
    monkeypatch.setattr(lab_archive, "CHILD_ARGV", [sys.executable, str(script)])
    out = lab_archive._clean(lab_archive._expand_child(b"PK", settings, analysis),
                             settings)
    assert out.failure == lab_archive.ANSWER_REASON and out.members == []

    script.write_text("import sys\nsys.stdin.buffer.readline()\n"
                      "sys.stdin.buffer.read()\nsys.stdout.write('<html>')\n")
    out = lab_archive._clean(lab_archive._expand_child(b"PK", settings, analysis),
                             settings)
    assert out.failure == lab_triage.CHILD_FAILURES["bad_output"]

    invented = dict(good, members=[], refused=[{"path": "x", "code": "pwned"}])
    script.write_text(
        "import sys, json, struct\nsys.stdin.buffer.readline()\n"
        "sys.stdin.buffer.read()\nbody = json.dumps(%r).encode()\n"
        "sys.stdout.buffer.write(struct.pack('>Q', len(body)) + body)\n"
        % invented)
    out = lab_archive._clean(lab_archive._expand_child(b"PK", settings, analysis),
                             settings)
    assert out.failure == lab_triage.CHILD_FAILURES["bad_output"]

    traversal = dict(good, members=[{"index": 0, "path": "../x", "size": 4,
                                     "sha256": hashlib.sha256(b"abcd").hexdigest()}])
    script.write_text(
        "import sys, json, struct\nsys.stdin.buffer.readline()\n"
        "sys.stdin.buffer.read()\nbody = json.dumps(%r).encode()\n"
        "sys.stdout.buffer.write(struct.pack('>Q', len(body)) + body + b'abcd')\n"
        % traversal)
    out = lab_archive._clean(lab_archive._expand_child(b"PK", settings, analysis),
                             settings)
    assert out.failure == lab_triage.CHILD_FAILURES["bad_output"]


def test_a_child_over_the_wall_clock_is_killed(tmp_path, settings, analysis, monkeypatch):
    script = tmp_path / "sleep.py"
    script.write_text("import time, sys\nsys.stdin.buffer.readline()\n"
                      "time.sleep(60)\n")
    monkeypatch.setattr(lab_archive, "CHILD_ARGV", [sys.executable, str(script)])
    monkeypatch.setattr(lab_archive, "wall_s", lambda *_a, **_k: 1.5)
    out = lab_archive._clean(lab_archive._expand_child(b"PK", settings, analysis),
                             settings)
    # Names the setting that bounded it and its value (2026-10-03), not the generic
    # static-triage sentence.
    assert out.failure != lab_triage.CHILD_FAILURES["timeout"]
    assert lab_archive.WALL_ENV in out.failure
    assert f"{settings.wall_s} seconds" in out.failure


def test_a_child_over_the_output_cap_is_killed_and_names_the_settings(
        tmp_path, settings, analysis, monkeypatch):
    script = tmp_path / "flood.py"
    script.write_text("import sys\nsys.stdin.buffer.readline()\n"
                      "sys.stdout.buffer.write(b'x' * (64 << 20))\n"
                      "sys.stdout.buffer.flush()\n")
    monkeypatch.setattr(lab_archive, "CHILD_ARGV", [sys.executable, str(script)])
    tight = lab_archive.ArchiveSettings(5, 1 << 20, 1 << 20, 100, 2, 60)
    out = lab_archive._clean(lab_archive._expand_child(b"PK", tight, analysis),
                             tight)
    assert out.failure != lab_triage.CHILD_FAILURES["output_too_large"]
    assert lab_archive.TOTAL_ENV in out.failure
    assert lab_archive.MEMBERS_ENV in out.failure


def test_the_child_sees_no_secret_and_the_password_is_the_convention(monkeypatch):
    from noctornal_api.samples import ARCHIVE_PASSWORD
    monkeypatch.setenv("NOCTORNAL_TOTP_KEK", "x" * 44)
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    env = lab_triage.child_env()
    assert not any(k.startswith(("NOCTORNAL_", "DATABASE")) for k in env)
    assert ARCHIVE_PASSWORD == PASSWORD


# ---------------------------------------------------------------------------
# Sentences and settings
# ---------------------------------------------------------------------------

def test_every_refusal_code_has_a_sentence_and_every_limit_is_named():
    assert set(lab_archive.ARCHIVE_SENTENCES) == set(lab_archive_child.ARCHIVE_REFUSALS)
    assert set(lab_archive.MEMBER_SENTENCES) == set(lab_archive_child.MEMBER_REFUSALS)
    assert lab_archive.MEMBERS_ENV in lab_archive.ARCHIVE_SENTENCES["member_count"]
    assert lab_archive.TOTAL_ENV in lab_archive.ARCHIVE_SENTENCES["total_bytes"]
    assert lab_archive.RATIO_ENV in lab_archive.ARCHIVE_SENTENCES["ratio"]
    assert lab_archive.MEMBER_ENV in lab_archive.MEMBER_SENTENCES["member_bytes"]
    assert lab_archive.RATIO_ENV in lab_archive.MEMBER_SENTENCES["ratio"]
    assert lab_archive.DEPTH_ENV in lab_archive.DEPTH_REASON
    for table in (lab_archive.ARCHIVE_SENTENCES, lab_archive.MEMBER_SENTENCES):
        for text in table.values():
            assert "\u2014" not in text and "\u2013" not in text and " -- " not in text
            assert "(s)" not in text
    # A detail the child invents cannot reach a sentence.
    sentence = lab_archive._sentence(lab_archive.MEMBER_SENTENCES, "case_collision",
                                     lab_archive._detail({"collides_with": "../x"}))
    assert "another member" in sentence
    sentence = lab_archive._sentence(lab_archive.MEMBER_SENTENCES, "corrupt_member",
                                     lab_archive._detail({"error": "<script>"}))
    assert "(Error)" in sentence


def test_the_settings_have_one_reader_and_production_refuses_a_problem():
    from noctornal_api.config import verify_environment
    s, problem = lab_archive.archive_settings({})
    assert problem is None
    assert (s.max_members, s.max_ratio, s.max_depth, s.wall_s) == (200, 100, 2, 60)
    assert s.max_member_bytes <= s.max_total_bytes
    for name, value in ((lab_archive.MEMBERS_ENV, "0"),
                        (lab_archive.MEMBERS_ENV, "many"),
                        (lab_archive.TOTAL_ENV, "64GiB"),
                        (lab_archive.MEMBER_ENV, "1TiB"),
                        (lab_archive.RATIO_ENV, "1"),
                        (lab_archive.DEPTH_ENV, "9"),
                        (lab_archive.WALL_ENV, "5")):
        _s, problem = lab_archive.archive_settings({name: value})
        assert problem and name in problem and value not in problem.split(name)[1][:0]
    s, problem = lab_archive.archive_settings({lab_archive.MEMBER_ENV: "4MiB",
                                              lab_archive.TOTAL_ENV: "2MiB"})
    assert problem and lab_archive.MEMBER_ENV in problem
    s, _ = lab_archive.archive_settings({lab_archive.DEPTH_ENV: "1",
                                         lab_archive.WALL_ENV: "30"})
    assert (s.max_depth, s.wall_s) == (1, 30)
    env = {"NOCTORNAL_ENV": "production", lab_archive.MEMBERS_ENV: "many"}
    problems = verify_environment(env)
    assert any(lab_archive.MEMBERS_ENV in p and "archive expansion" in p
               for p in problems), problems


def test_the_tree_cap_is_one_setting_with_a_default_and_never_under_the_archive_cap():
    """2026-10-07: the caps were per archive, so one 4 MB
    upload at depth 2 made about 40,200 samples. A cap over the whole tree is
    the roof, 1000 unless set, and never lower than one archive may hold."""
    s, problem = lab_archive.archive_settings({})
    assert problem is None and s.max_tree_members == 1000
    s, problem = lab_archive.archive_settings({lab_archive.TREE_ENV: "50",
                                               lab_archive.MEMBERS_ENV: "20"})
    assert problem is None and s.max_tree_members == 50
    # A deployment that raised the archive cap above the default roof keeps
    # a roof it can use; nothing refuses it at boot for a setting it never made.
    s, problem = lab_archive.archive_settings({lab_archive.MEMBERS_ENV: "3000"})
    assert problem is None and s.max_tree_members == 3000
    for value in ("0", "many", "-1", "1000001", "1.5"):
        _s, problem = lab_archive.archive_settings({lab_archive.TREE_ENV: value})
        assert problem and lab_archive.TREE_ENV in problem
        assert "many" not in problem  # the problem names the variable, not its value
    # Set under the one-archive cap, it could never be reached: refused, by name.
    _s, problem = lab_archive.archive_settings({lab_archive.TREE_ENV: "100"})
    assert problem and lab_archive.TREE_ENV in problem and lab_archive.MEMBERS_ENV in problem
    env = {"NOCTORNAL_ENV": "production", lab_archive.TREE_ENV: "many"}
    from noctornal_api.config import verify_environment
    assert any(lab_archive.TREE_ENV in p and "archive expansion" in p
               for p in verify_environment(env))
    assert lab_archive.limits_words(lab_archive.archive_settings({})[0])["tree_members"] == 1000


def test_the_tree_sentence_names_its_limit_and_its_numbers():
    text = lab_archive.TREE_SENTENCE.format(total=1100, cap=1000, held=900, new=200)
    assert lab_archive.TREE_ENV in text
    for number in ("1100", "1000", "900", "200"):
        assert number in text
    assert "\u2014" not in text and "\u2013" not in text and " -- " not in text


def test_the_run_budget_counts_the_expansion_child():
    analysis = lab_triage.analysis_settings({})[0]
    assert lab_triage.run_worst_s(analysis, 0) == pytest.approx(
        2 * (analysis.timeout_s + lab_triage.WALL_GRACE_S) + lab_archive.wall_s())


def test_the_wire_frame_round_trips_and_a_bad_one_is_refused():
    report = {"ok": True, "members": []}
    raw = lab_archive_child.frame(report, [b"ab", b"cd"])
    got, blob = lab_archive.unframe(raw)
    assert got == report and blob == b"abcd"
    with pytest.raises(ValueError):
        lab_archive.unframe(b"\x00\x00\x00\x00\x00\x00\x00\xff" + b"{}")
    with pytest.raises(ValueError):
        lab_archive.unframe(b"short")
    with pytest.raises(ValueError):
        lab_archive.unframe(struct.pack(">Q", 2) + b"[]")
    (n,) = struct.unpack(">Q", raw[:8])
    assert json.loads(raw[8:8 + n]) == report and raw[8 + n:] == b"abcd"

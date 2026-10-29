"""The body of a GNU long-name, long-link or pax header counts against the
archive's ratio and total.

tarfile reads such a body whole, before it yields the member it describes,
so the walk never sees those bytes as a member. Uncounted, a few-hundred-byte
gzip could inflate far past the ratio cap and still finish as a clean
expansion. The declared size is held to the caps before the body is read.

Pure: no database.
"""
from __future__ import annotations

import io
import tarfile

from noctornal_api import lab_archive_child

CAPS = {"members": 50, "total_bytes": 8 << 20, "member_bytes": 2 << 20,
        "ratio": 100}
PASSWORD = b"infected"


def _gz_tar(info: tarfile.TarInfo, fmt: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=fmt) as tf:
        tf.addfile(info, io.BytesIO(b"data"))
    return buf.getvalue()


def test_a_gnu_longname_body_over_the_ratio_refuses_the_archive():
    info = tarfile.TarInfo("A" * 200_000)
    info.size = 4
    data = _gz_tar(info, tarfile.GNU_FORMAT)
    assert len(data) * CAPS["ratio"] < 200_000
    report, payloads = lab_archive_child.expand(data, CAPS, PASSWORD)
    assert report["refusal"]["code"] == "ratio", report
    assert payloads == [] and report["members"] == []


def test_a_gnu_longlink_body_over_the_ratio_refuses_the_archive():
    info = tarfile.TarInfo("link")
    info.type = tarfile.SYMTYPE
    info.linkname = "B" * 200_000
    data = _gz_tar(info, tarfile.GNU_FORMAT)
    assert len(data) * CAPS["ratio"] < 200_000
    report, _payloads = lab_archive_child.expand(data, CAPS, PASSWORD)
    assert report["refusal"]["code"] == "ratio", report


def test_a_pax_header_body_over_the_ratio_refuses_the_archive():
    info = tarfile.TarInfo("a.txt")
    info.size = 4
    info.pax_headers = {"comment": "C" * 200_000}
    data = _gz_tar(info, tarfile.PAX_FORMAT)
    assert len(data) * CAPS["ratio"] < 200_000
    report, _payloads = lab_archive_child.expand(data, CAPS, PASSWORD)
    assert report["refusal"]["code"] == "ratio", report


def test_a_pax_header_body_over_the_total_refuses_the_archive():
    info = tarfile.TarInfo("a.txt")
    info.size = 4
    info.pax_headers = {"comment": "C" * 200_000}
    data = _gz_tar(info, tarfile.PAX_FORMAT)
    caps = {**CAPS, "total_bytes": 100_000, "ratio": 1 << 30}
    report, _payloads = lab_archive_child.expand(data, caps, PASSWORD)
    assert report["refusal"]["code"] == "total_bytes", report


def test_an_honest_long_name_still_expands():
    name = "dir/" * 40 + "file.txt"
    info = tarfile.TarInfo(name)
    info.size = 4
    for fmt in (tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
        report, payloads = lab_archive_child.expand(_gz_tar(info, fmt), CAPS, PASSWORD)
        assert report["refusal"] is None, report
        assert payloads == [b"data"]
        assert [m["path"] for m in report["members"]] == [name]

"""A zip entry marked as a symbolic link that holds bytes is read as a member.

In a zip the link mode is a bit beside an entry that carries bytes, and
Windows and most extractors write it out as an ordinary file. Refused as a
content-free link, up to a link target's worth of bytes were never hashed or
compared with a prohibited-content list, while the archive's card said every
member was. Only an empty link-marked entry stays a content-free refusal.

Pure: no database.
"""
from __future__ import annotations

import hashlib
import io
import zipfile

from noctornal_api import lab_archive_child

CAPS = {"members": 50, "total_bytes": 8 << 20, "member_bytes": 2 << 20,
        "ratio": 100}
PASSWORD = b"infected"


def _zip_of(entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def _link(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.external_attr = 0o120777 << 16
    info.create_system = 3
    return info


def test_a_link_marked_entry_with_bytes_is_hashed_and_returned():
    payload = b"prohibited-content-bytes!!"
    report, payloads = lab_archive_child.expand(
        _zip_of([(_link("hidden.bin"), payload), ("plain.bin", b"ok")]), CAPS, PASSWORD)
    assert report["refusal"] is None
    assert report["refused"] == []
    assert payload in payloads
    assert any(m["path"] == "hidden.bin"
               and m["sha256"] == hashlib.sha256(payload).hexdigest()
               for m in report["members"])


def test_a_link_marked_entry_of_a_path_length_is_returned():
    payload = b"x" * 1024
    report, payloads = lab_archive_child.expand(
        _zip_of([(_link("edge.bin"), payload)]), CAPS, PASSWORD)
    assert report["refused"] == [] and payloads == [payload]


def test_an_empty_link_marked_entry_stays_a_content_free_refusal():
    report, payloads = lab_archive_child.expand(
        _zip_of([(_link("empty-link"), b""), ("plain.bin", b"ok")]), CAPS, PASSWORD)
    assert report["refusal"] is None
    assert payloads == [b"ok"]
    assert {r["path"]: r["code"] for r in report["refused"]} == {"empty-link": "symlink"}
    assert "symlink" in lab_archive_child.CONTENT_FREE_REFUSALS

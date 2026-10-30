"""The extension blocks of a GNU sparse header count against the archive's ratio.

tarfile reads a sparse header's chain of extension blocks inside its own member
loop, before it yields the member, so the walk never sees those bytes. A chain
of blocks that each say another follows is a few kilobytes of gzip that
inflates without limit, and every block can add sparse map entries to memory.
Each block read is held to the same caps as a long-name body.

Pure: no database.
"""
from __future__ import annotations

import gzip
import io
import tarfile

from noctornal_api import lab_archive_child

CAPS = {"members": 50, "total_bytes": 8 << 20, "member_bytes": 2 << 20,
        "ratio": 100}
PASSWORD = b"infected"

#: Where the old GNU header keeps the flag that says extension blocks follow.
ISEXTENDED_AT = 482
#: Where each extension block keeps the same flag.
EXTENSION_FLAG_AT = 504


def _sparse_chain(blocks: int) -> bytes:
    """A tar whose one member is a GNU sparse header followed by `blocks` extension blocks, each pointing to
    the next, then the end-of-archive blocks."""
    info = tarfile.TarInfo("sparse.bin")
    info.size = 0
    head = bytearray(info.tobuf(tarfile.GNU_FORMAT))
    head[156] = ord(tarfile.GNUTYPE_SPARSE)
    head[ISEXTENDED_AT] = 1
    head[483:495] = b"00000000000\0"
    # The header checksum covers the bytes just changed.
    head[148:156] = b"        "
    head[148:156] = b"%06o\0 " % sum(head)
    body = bytearray()
    for index in range(blocks):
        block = bytearray(tarfile.BLOCKSIZE)
        block[EXTENSION_FLAG_AT] = 1 if index < blocks - 1 else 0
        body += block
    return bytes(head) + bytes(body) + b"\0" * (2 * tarfile.BLOCKSIZE)


def _gz(raw: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9) as out:
        out.write(raw)
    return buf.getvalue()


def test_a_long_chain_of_sparse_extension_blocks_refuses_the_archive():
    data = _gz(_sparse_chain(20_000))
    assert len(data) * CAPS["ratio"] < 20_000 * tarfile.BLOCKSIZE
    report, payloads = lab_archive_child.expand(data, CAPS, PASSWORD)
    assert report["refusal"] is not None and report["refusal"]["code"] == "ratio", report
    assert payloads == []


def test_a_short_chain_of_sparse_extension_blocks_is_not_refused_for_its_headers():
    data = _gz(_sparse_chain(2))
    report, _payloads = lab_archive_child.expand(data, CAPS, PASSWORD)
    refusal = report["refusal"]
    assert refusal is None or refusal["code"] not in ("ratio", "total_bytes"), report

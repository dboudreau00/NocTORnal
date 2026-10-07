"""The production database's shared memory.

Docker gives a container 64 MB of /dev/shm. Postgres puts a parallel
query's shared memory there, and under load (50 analysts on a case of a
million claims) it ran out: `DiskFull`, an HTTP 500 for a read that is fine
on its own. The compose file sets the size; this pins it.
"""
from __future__ import annotations

import re

from test_egress_topology import COMPOSE, Reader


def _bytes(size: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([kmg]?)b?", size.strip().lower())
    assert m, f"unreadable shm_size {size!r}"
    return int(m.group(1)) * {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}[m.group(2)]


def test_the_database_has_room_for_parallel_queries():
    doc = Reader(COMPOSE.read_text(encoding="utf-8")).document()
    size = doc["services"]["postgres"].get("shm_size")
    assert size, "postgres runs on Docker's 64 MB /dev/shm"
    assert _bytes(str(size)) >= 512 << 20

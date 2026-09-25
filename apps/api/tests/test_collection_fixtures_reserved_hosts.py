"""Collection fixtures name only hosts nobody can own (2026-09-24).

The forum adapters keep captured pages under tests/fixtures/xenforo and
tests/fixtures/mybb, and the Telegram adapter under tests/fixtures/telegram.
A captured page carries its site's links; a fixture that names a
registrable host puts a stranger's domain in the suite as a criminal
forum. Every host a fixture names must be one RFC 2606, 6761 or 7686
reserves, except a board software vendor's own footer host, allowed by
name. The collection foundation tests' own stand-in addresses are held
to the same rule.
Pure: it reads files and runs nothing.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from test_demo_hosts_reserved import _reserved

TESTS = Path(__file__).resolve().parent
FIXTURE_DIRS = ("fixtures/xenforo", "fixtures/mybb", "fixtures/telegram")

#: A vendor's own name in a board's footer ("Forum software by XenForo"),
#: never a site under investigation.
VENDOR_HOSTS = frozenset({"xenforo.com", "www.xenforo.com", "mybb.com",
                          "www.mybb.com", "telegram.org", "core.telegram.org"})

#: A URL's host, past any user name in it (a hostile fixture may carry one).
_URL = re.compile(r"(?i)\b(?:https?|wss?)://(?:[^/@\s'\"]*@)?([A-Za-z0-9.-]+)")
_BARE = re.compile(r"(?i)(?:href|src|action)\s*=\s*[\"']//([A-Za-z0-9.-]+)")


def _hosts(text: str) -> set[str]:
    return {h.lower().rstrip(".") for h in _URL.findall(text) + _BARE.findall(text)}


def _fixture_files() -> list[Path]:
    files = []
    for rel in FIXTURE_DIRS:
        folder = TESTS / rel
        if folder.is_dir():
            files.extend(p for p in sorted(folder.rglob("*")) if p.is_file())
    return files


@pytest.mark.parametrize("path", _fixture_files() or [None])
def test_every_host_a_collection_fixture_names_is_reserved(path):
    if path is None:
        pytest.skip("no forum or Telegram fixtures yet")
    text = path.read_bytes().decode("utf-8", "replace")
    registrable = sorted(h for h in _hosts(text)
                         if not _reserved(h) and h not in VENDOR_HOSTS)
    assert not registrable, f"{path.name} names hosts somebody can register: {registrable}"


@pytest.mark.parametrize("name", [
    "collection_helpers.py", "test_collection_context.py", "test_collection_framework_pg.py",
    "test_collection_ceiling.py", "test_collected_document_retention_pg.py",
    "test_collection_authority_http_e2e.py", "test_collection_context_http.py"])
def test_the_collection_foundation_tests_use_reserved_stand_in_hosts(name):
    path = TESTS / name
    registrable = sorted(h for h in _hosts(path.read_text(encoding="utf-8"))
                         if not _reserved(h))
    assert not registrable, f"{name} names {registrable}"


def test_the_checker_catches_what_it_is_for():
    assert _hosts('<a href="https://carders.cc/threads/1">x</a>') == {"carders.cc"}
    assert not _reserved("carders.cc")
    assert _reserved("board.example.test")

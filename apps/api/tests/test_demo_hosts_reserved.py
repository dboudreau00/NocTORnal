"""The demo estate names only hosts nobody can own (x-nightmarket, 2026-09-24).

`nightmarket` plus the Isle of Man's country code is a domain anyone can
register, and it was the Jabber domain of every persona the demo seeders
wrote and of three tests. A demo that names a registrable host puts a
stranger's domain on screen as a criminal forum, in screenshots and in
the selectors an analyst copies out to try; the README estate already
used `.example` for exactly that reason. RFC 2606 and RFC 6761 reserve
`.example`, `.test`, `.invalid` and `.localhost`, and the three
`example.*` second-level names, for this; RFC 7686 reserves `.onion`.

Pure: it reads files and runs nothing.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]

#: The scripts that write the demo estates.
SEEDERS = ("scripts/bootstrap.py", "scripts/seed_showcase.py",
           "scripts/seed_readme_showcase.py")

#: The tests that carried the demo's Jabber domain.
CARRIERS = ("apps/api/tests/test_entity_entry_pg.py",
            "apps/api/tests/test_search_selectors_pg.py",
            "apps/api/tests/test_search_terms.py")

_RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".onion")
_RESERVED_NAMES = ("example.com", "example.org", "example.net", "localhost",
                   "127.0.0.1")

#: An address or a JID (`local@host`), and a URL's host.
_ADDRESS = re.compile(r"[\w.+{}-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
_URL = re.compile(r"https?://([A-Za-z0-9.-]+)")


def _reserved(host: str) -> bool:
    host = host.lower().rstrip(".")
    return (host.endswith(_RESERVED_SUFFIXES) or host in _RESERVED_NAMES
            or any(host.endswith("." + name) for name in _RESERVED_NAMES))


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


@pytest.mark.parametrize("rel", SEEDERS)
def test_every_host_a_demo_seeder_writes_is_reserved(rel):
    text = _read(rel)
    hosts = set(_ADDRESS.findall(text)) | set(_URL.findall(text))
    assert hosts, f"{rel}: no address or URL found, so this test is blind"
    registrable = sorted(h for h in hosts if not _reserved(h))
    assert not registrable, (
        f"{rel} writes hosts somebody can register: {registrable}")


@pytest.mark.parametrize("rel", SEEDERS + CARRIERS)
def test_the_demo_forum_is_named_on_a_reserved_host(rel):
    """Checked by name as well, because the tests carry the forum in
    shapes the address pattern does not see (a domain fragment built from
    a random token, a docstring)."""
    named = re.findall(r"nightmarket\.([A-Za-z]{2,})", _read(rel), flags=re.I)
    wrong = sorted({tld for tld in named
                    if tld.lower() not in {"example", "onion"}})
    assert not wrong, f"{rel} names the demo forum under .{wrong}"


def test_the_registrable_name_is_gone_from_the_code():
    """Every file that ships code or markup. The planning documents may
    still say what was replaced; nothing that runs may name it."""
    gone = "nightmarket" + ".im"
    suffixes = {".py", ".js", ".html", ".css", ".ps1", ".sh", ".sql",
                ".json", ".yml", ".yaml", ".toml"}
    skip = {".git", ".venv", "node_modules", "__pycache__"}
    carriers = [
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*")
        if path.suffix in suffixes and path.is_file()
        and not skip & set(path.relative_to(ROOT).parts)
        and gone in path.read_text(encoding="utf-8", errors="replace").lower()]
    assert not carriers, carriers

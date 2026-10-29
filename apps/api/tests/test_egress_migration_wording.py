"""What an operator reads when 0085 or 0086 refuses.

Each count is written out so it agrees with its noun ("one row", "3 rows"), never a bracketed plural such
as "row(s)", which this product does not ship. Pure: reads the migration files; the downgrade refusals
themselves are exercised against the database in test_egress_config_pg.py and
test_egress_connection_ledger_pg.py.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
FILES = ("0085_egress_config.py", "0086_egress_connection.py")
RAISE = re.compile(r"RAISE EXCEPTION '((?:[^']|'')*)'", re.S)


@pytest.mark.parametrize("name", FILES)
def test_no_refusal_carries_a_bracketed_plural(name):
    text = (VERSIONS / name).read_text(encoding="utf-8")
    messages = RAISE.findall(text)
    assert messages, "the migration's refusals were not found"
    for message in messages:
        assert not re.search(r"\w\(s\)", message), message
        assert "(es)" not in message and "(ies)" not in message, message


@pytest.mark.parametrize("name", FILES)
def test_every_counted_refusal_agrees_its_count(name):
    text = (VERSIONS / name).read_text(encoding="utf-8")
    counted = text.count("(SELECT CASE count(*) WHEN 1 THEN 'one ")
    bare = len(re.findall(r"\(SELECT count\(\*\) FROM", text))
    assert counted >= 1 and bare == 0

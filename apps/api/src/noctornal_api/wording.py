"""Counts in agreement with their nouns and verbs.

A server sentence that prints a count already knows the number, so a bracketed plural only makes
every reader do the agreement. This is the server's copy of `countOf` and `agree` in app.js;
test_server_copy_no_lazy_plurals.py refuses the hedge in any server string a reader can meet.
"""
from __future__ import annotations


def agree(n: int, one: str, many: str) -> str:
    """The word the count takes: a noun ("edge", "edges") or a verb
    ("is", "are")."""
    return one if n == 1 else many


def count_of(n: int, one: str, many: str) -> str:
    """A count and its noun: "1 fragment", "3 fragments"."""
    return f"{n} {agree(n, one, many)}"

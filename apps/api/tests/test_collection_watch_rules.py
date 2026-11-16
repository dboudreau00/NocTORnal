"""The rules a watch obeys, as the helpers hold them (docs/17, stopping or editing a watch).

`create_watch` and `edit_watch` hold one set of rules: the module-level helpers in `collection.py`.
Pure: no database. What these pin is each helper's sentence and bound, and that the writers call the
helpers and carry no rule of their own, so a rule changed in one place changes for both. The database
half is `test_collection_watch_create_pg.py` and `test_collection_watch_change_pg.py`.
"""
from __future__ import annotations

import inspect

import pytest

from noctornal_api import collection
from noctornal_api.collection import CollectionError, CollectionService

HELPERS = ("_clean_watch_name", "_clean_watch_terms", "_check_watch_terms",
           "_clean_watch_priority", "_clean_watch_window")


def test_a_watch_name_is_a_stripped_line_of_three_to_two_hundred_characters():
    assert collection._clean_watch_name("  night owl  ") == "night owl"
    assert collection._clean_watch_name("abc") == "abc"
    assert collection._clean_watch_name("x" * 200) == "x" * 200
    for bad, said in (("ab", "between 3 and 200"), ("  a  ", "between 3 and 200"),
                      ("x" * 201, "between 3 and 200"), ("two\nlines", "control character"),
                      ("nul\x00byte", "control character"), (None, "between 3 and 200"),
                      (7, "between 3 and 200")):
        with pytest.raises(CollectionError) as refused:
            collection._clean_watch_name(bad)
        assert said in str(refused.value), (bad, str(refused.value))


def test_the_priority_and_the_repeat_window_are_whole_numbers_in_range():
    top = collection.WATCH_MAX_SUPPRESS_S
    assert [collection._clean_watch_priority(p) for p in (1, 3, 5)] == [1, 3, 5]
    assert [collection._clean_watch_window(w) for w in (0, 3600, top)] == [0, 3600, top]
    for bad in (0, 6, -1, True, 2.0, "3", None):
        with pytest.raises(CollectionError, match="priority is a whole number from 1"):
            collection._clean_watch_priority(bad)
    for bad in (-1, top + 1, True, 1.5, "60", None):
        with pytest.raises(CollectionError, match=f"between 0 and {top} seconds"):
            collection._clean_watch_window(bad)


def test_a_watch_other_than_a_chat_watch_needs_a_term():
    none = ([], [], [])
    with pytest.raises(CollectionError, match="needs a keyword, a selector or a pattern"):
        collection._check_watch_terms(False, none)
    collection._check_watch_terms(True, none)
    for terms in ((["a"], [], []), ([], ["a"], []), ([], [], ["a+"])):
        collection._check_watch_terms(False, terms)


def test_the_term_lists_are_cleaned_in_the_order_the_matcher_reads_them():
    assert collection._clean_watch_terms(
        [" ransom ", "kits"], None, ["vesper\\d+"]) == (["ransom", "kits"], [], ["vesper\\d+"])
    assert collection._clean_watch_terms(None, ["a@b.test"], None) == ([], ["a@b.test"], [])
    secret = "AKIAHUNTEDSECRET1234("
    with pytest.raises(CollectionError) as refused:
        collection._clean_watch_terms(["fine"], ["fine"], [secret])
    assert "does not compile" in str(refused.value)
    assert "AKIAHUNTEDSECRET" not in str(refused.value), "a pattern is never echoed back"
    for bad, said in ((["ok", "  "], "A keyword cannot be empty"),
                      ("ransom", "keywords are a list"),
                      (["k"] * 101, "at most 100 keywords"),
                      (["a\tb"], "control character")):
        with pytest.raises(CollectionError) as refused:
            collection._clean_watch_terms(bad, None, None)
        assert said in str(refused.value), (bad, str(refused.value))


def test_create_watch_holds_no_rule_of_its_own():
    """The writer calls the helpers, and the sentences and bounds they carry are not written a second
    time inside it."""
    source = inspect.getsource(CollectionService.create_watch)
    for helper in HELPERS:
        assert helper + "(" in source, f"create_watch no longer calls {helper}"
    for restated in ("between 0 and", "whole number from 1", "needs a keyword",
                     "isinstance(priority", "_watch_line(name"):
        assert restated not in source, f"create_watch restates a rule: {restated}"

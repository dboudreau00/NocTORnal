"""The marking statement says only what the case's withheld-disclosure setting
lets it say (0030, decision 179), and says it the same way for all three
figures.

Beta 1.1 group C (2026-10-08). The setting decides what a reader may learn of
material above the ceiling they asked for: under NONE nothing, under
PRESENCE that there is some, under COUNT how much. The exhibit figure
followed it since 2026-10-07; the entity figure, the relationship figure and
the hypothesis matrix's evidence were still stated exactly under PRESENCE,
the builder never told `Redaction` which setting it had built under, and a
statement built under NONE read "nothing has been withheld" beside a
document that had left material out.

No database: these are the statement's rules on a hand-built `Redaction`.
"""
from __future__ import annotations

import itertools
import re

import pytest

from noctornal_api.reports import Redaction, Report

NONE, PRESENCE, COUNT = "NONE", "PRESENCE", "COUNT"
DASHES = (chr(0x2014), chr(0x2013), "(s)", " -- ")


def _redaction(disclosure=NONE, **fields) -> Redaction:
    base = dict(built_at_tlp="GREEN", ceiling_tlp="GREEN", case_tlp="GREEN",
                nodes_withheld=0, edges_withheld=0, evidence_withheld=0)
    return Redaction(**{**base, "disclosure": disclosure, **fields})


def _digits(text: str) -> list[str]:
    """The numbers in a statement, other than the ones that are part of a
    name ("TLP:GREEN" has none; a figure is the thing under test)."""
    return re.findall(r"\d+", text)


# --- NONE: the same sentence whatever is hidden ---------------------------

def test_a_case_that_discloses_nothing_gives_one_statement_whatever_is_hidden():
    plain = _redaction().statement()
    hidden = _redaction(
        nodes_withheld=3, edges_withheld=4, evidence_withheld=2,
        hypothesis_evidence_withheld=5, evidence_some_withheld=True,
        nodes_some_withheld=True, edges_some_withheld=True,
        hypothesis_evidence_some_withheld=True).statement()
    assert plain == hidden, (
        "the statement told a reader whether anything was above the ceiling "
        "under a setting that says nothing")


def test_under_none_it_never_says_nothing_was_withheld_nor_that_something_was():
    text = _redaction().statement()
    assert "nothing has been withheld" not in text
    assert "have been withheld" not in text
    assert "has been withheld" not in text
    assert "does not say whether any material above it exists" in text
    assert _digits(text) == []


def test_a_statement_built_by_hand_defaults_to_the_setting_that_says_least():
    """A `Redaction` made without a setting is built the way a case that
    discloses nothing is: it does not print a figure it was handed."""
    assert Redaction("GREEN", "GREEN", "GREEN", 7, 8, 9).disclosure == NONE
    text = Redaction("GREEN", "GREEN", "GREEN", 7, 8, 9).statement()
    assert _digits(text) == [] and "withheld" not in text


def test_under_none_the_case_header_is_still_said_to_be_withheld():
    """The requester chose the ceiling and knows the case's own level, so
    saying the header is above it tells them nothing about other material."""
    text = _redaction(header_withheld=True, assumptions_withheld=2,
                      hypotheses_withheld=1).statement()
    assert "identifying detail is above that ceiling" in text
    assert "2 recorded assumptions" in text
    assert "1 competing hypothesis" in text
    assert "does not say whether any material above it exists" in text


# --- PRESENCE: some, never how many ---------------------------------------

@pytest.mark.parametrize("flags, said", [
    (("nodes",), "Some entities are above that level"),
    (("edges",), "Some relationships are above that level"),
    (("evidence",), "Some exhibits are above that level"),
    (("nodes", "edges"),
     "Some entities and some relationships are above that level"),
    (("nodes", "evidence"),
     "Some entities and some exhibits are above that level"),
    (("edges", "evidence"),
     "Some relationships and some exhibits are above that level"),
    (("nodes", "edges", "evidence"),
     "Some entities, some relationships and some exhibits are above that level"),
])
def test_under_presence_each_kind_that_has_something_above_is_named_alone(
        flags, said):
    text = _redaction(PRESENCE, **{f"{k}_some_withheld": True
                                   for k in flags}).statement()
    assert said in text
    assert "have been withheld" in text
    assert _digits(text) == []
    named = [kind for kind in ("entities", "relationships", "exhibits")
             if f"some {kind}" in text.lower()]
    assert len(named) == len(flags), (
        "a kind with nothing above the ceiling was named")


def test_under_presence_a_figure_that_was_handed_in_is_not_printed():
    text = _redaction(PRESENCE, nodes_withheld=3, edges_withheld=4,
                      evidence_withheld=2, nodes_some_withheld=True,
                      edges_some_withheld=True,
                      evidence_some_withheld=True).statement()
    assert _digits(text) == []


def test_under_presence_the_matrix_is_said_to_leave_some_out_not_how_many():
    text = _redaction(PRESENCE, nodes_some_withheld=True,
                      hypothesis_evidence_some_withheld=True).statement()
    assert ("Some items of evidence in the hypothesis matrix rest on that "
            "material, so the hypothesis scores below leave them out") in text
    assert _digits(text) == []


# --- COUNT: the figures, in agreement with their nouns ---------------------

def test_under_count_the_three_figures_are_stated():
    text = _redaction(COUNT, nodes_withheld=3, edges_withheld=4,
                      evidence_withheld=2,
                      hypothesis_evidence_withheld=5).statement()
    assert "3 entities, 4 relationships and 2 exhibits are above that level" in text
    assert "5 items of evidence in the hypothesis matrix rest on that material" in text


def test_under_count_one_of_each_agrees_with_its_noun():
    text = _redaction(COUNT, nodes_withheld=1, edges_withheld=1,
                      evidence_withheld=1,
                      hypothesis_evidence_withheld=1).statement()
    assert "1 entity, 1 relationship and 1 exhibit are above that level" in text
    assert "1 item of evidence in the hypothesis matrix rests on that material" in text
    assert "leave it out" in text


# --- nothing above the ceiling ---------------------------------------------

@pytest.mark.parametrize("mode", [PRESENCE, COUNT])
def test_a_case_that_discloses_says_nothing_was_withheld_only_when_nothing_was(
        mode):
    clean = _redaction(mode).statement()
    assert "Nothing in the case file was above that ceiling" in clean
    assert "nothing has been withheld from it" in clean

    for field in ("nodes_withheld", "edges_withheld", "evidence_withheld",
                  "hypothesis_evidence_withheld"):
        if mode == COUNT:
            text = _redaction(mode, **{field: 1}).statement()
            assert "nothing has been withheld" not in text, field
    for field in ("nodes_some_withheld", "edges_some_withheld",
                  "evidence_some_withheld",
                  "hypothesis_evidence_some_withheld"):
        if mode == PRESENCE:
            text = _redaction(mode, **{field: True}).statement()
            assert "nothing has been withheld" not in text, field


def test_anything_withheld_is_every_field_that_can_make_the_statement_say_so():
    assert not _redaction().anything_withheld
    for field in ("nodes_withheld", "edges_withheld", "evidence_withheld",
                  "assumptions_withheld", "hypotheses_withheld",
                  "hypothesis_evidence_withheld"):
        assert _redaction(**{field: 1}).anything_withheld, field
    for field in ("evidence_some_withheld", "nodes_some_withheld",
                  "edges_some_withheld", "hypothesis_evidence_some_withheld",
                  "header_withheld"):
        assert _redaction(**{field: True}).anything_withheld, field


# --- the words ---------------------------------------------------------------

def test_no_statement_has_a_dash_or_an_optional_plural():
    cases = [_redaction(mode, **fields)
             for mode in (NONE, PRESENCE, COUNT)
             for fields in (
                 {}, dict(header_withheld=True, assumptions_withheld=1,
                          hypotheses_withheld=2),
                 dict(nodes_withheld=1, edges_withheld=2, evidence_withheld=3,
                      hypothesis_evidence_withheld=1),
                 dict(nodes_some_withheld=True, edges_some_withheld=True,
                      evidence_some_withheld=True,
                      hypothesis_evidence_some_withheld=True))]
    for redaction in cases:
        text = redaction.statement()
        for mark in DASHES:
            assert mark not in text, (redaction.disclosure, mark)


def test_every_combination_of_the_flags_gives_a_well_formed_sentence():
    flags = ("nodes_some_withheld", "edges_some_withheld",
             "evidence_some_withheld", "hypothesis_evidence_some_withheld")
    for on in itertools.product((False, True), repeat=len(flags)):
        text = _redaction(PRESENCE, **dict(zip(flags, on, strict=True))).statement()
        assert text.endswith("not a measurement of the case.") or (
            "nothing has been withheld" in text), on
        assert "  " not in text and ", ," not in text, on
        assert " and  " not in text, on


# --- what the document carries ------------------------------------------------

def test_the_documents_redaction_block_carries_the_setting_and_every_flag():
    report = Report(
        case={}, summary={},
        redaction=_redaction(PRESENCE, nodes_some_withheld=True,
                             edges_some_withheld=True,
                             evidence_some_withheld=True,
                             hypothesis_evidence_some_withheld=True))
    block = report.as_dict()["redaction"]
    assert block["disclosure"] == PRESENCE
    for key in ("nodes_some_withheld", "edges_some_withheld",
                "evidence_some_withheld", "hypothesis_evidence_some_withheld"):
        assert block[key] is True, key
    for key in ("nodes_withheld", "edges_withheld", "evidence_withheld",
                "hypothesis_evidence_withheld"):
        assert block[key] == 0, key
    assert block["statement"] == report.redaction.statement()

"""ACH scoring, against hand-computed values.

The test that matters is `test_the_ranking_is_by_inconsistency_not_support`.
Every naive ACH implementation gets that backwards, and getting it backwards
turns the method into confirmation bias with a scoreboard -- which is the
exact failure docs/13 says ACH exists to correct.

Pure: no database, no clock. The HTTP leg is in `test_ach_pg.py`.
"""
from __future__ import annotations

import re
from uuid import uuid4

from noctornal_api.ach import (
    CONSISTENT,
    INCONSISTENT,
    NEUTRAL,
    STRONGLY_CONSISTENT,
    STRONGLY_INCONSISTENT,
    EvidenceItem,
    score,
    source_weight,
)

H1, H2, H3 = uuid4(), uuid4(), uuid4()
HYPOTHESES = [(H1, "The broker is the developer"),
              (H2, "The broker is a reseller"),
              (H3, "The broker is a law-enforcement persona")]


#: The "settles nothing" warning in either number. The warning agrees with
#: its count now (README screenshot set review, 2026-09-23), so a check
#: that it is absent must look for both forms or pass on a singular.
_SETTLES_NOTHING = re.compile(r"\bsettles? nothing\b")


def _item(label, stances, reliability="A", credibility="1"):
    return EvidenceItem(assertion_id=uuid4(), label=label,
                        reliability=reliability, credibility=credibility,
                        stances=dict(stances))


# --- the inversion ------------------------------------------------------

def test_the_ranking_is_by_inconsistency_not_support():
    """Heuer's central move, and the one every naive implementation gets
    backwards.

    H1 has the most support AND some evidence against it. H2 has less
    support and nothing against it. Ranking by support crowns H1 -- which
    is exactly what a team eight months into one theory would want to see.
    ACH crowns H2, because the only question that eliminates anything is
    what a theory fails to explain.
    """
    evidence = [
        _item("PDB path with a build username", {H1: STRONGLY_CONSISTENT,
                                                 H2: CONSISTENT, H3: NEUTRAL}),
        _item("sells other people's builds", {H1: STRONGLY_INCONSISTENT,
                                              H2: STRONGLY_CONSISTENT,
                                              H3: NEUTRAL}),
        _item("posts in developer channels", {H1: STRONGLY_CONSISTENT,
                                              H2: NEUTRAL, H3: NEUTRAL}),
    ]
    m = score(HYPOTHESES, evidence)

    by_id = {h.hypothesis_id: h for h in m.hypotheses}
    assert by_id[H1].support > by_id[H2].support, "H1 has the most support"
    assert m.least_inconsistent == H2, (
        "ACH ranks by what a theory fails to explain, not by how much has "
        "been collected for it")
    assert m.hypotheses[0].hypothesis_id == H2


def test_support_is_reported_but_never_ranks():
    """It is useful to see and must not decide. A hypothesis with no
    support and no contradiction outranks one with heaps of both."""
    evidence = [
        _item("a", {H1: STRONGLY_CONSISTENT, H2: NEUTRAL}),
        _item("b", {H1: INCONSISTENT, H2: NEUTRAL}),
    ]
    m = score([(H1, "loud"), (H2, "quiet")], evidence)
    assert m.hypotheses[0].hypothesis_id == H2
    assert m.hypotheses[0].support == 0.0


def test_support_breaks_a_tie_and_only_a_tie():
    evidence = [
        _item("a", {H1: CONSISTENT, H2: NEUTRAL}),
        _item("b", {H1: NEUTRAL, H2: NEUTRAL}),
    ]
    m = score([(H1, "supported"), (H2, "bare")], evidence)
    assert m.hypotheses[0].inconsistency == m.hypotheses[1].inconsistency
    assert m.hypotheses[0].hypothesis_id == H1, "support only breaks the tie"


# --- diagnosticity ------------------------------------------------------

def test_evidence_consistent_with_everything_is_not_diagnostic():
    """"The actor speaks Russian" against four Russian-speaking hypotheses
    feels like progress and moves no needle. ACH exists to make that
    visible rather than reassuring."""
    evidence = [_item("speaks Russian", {H1: CONSISTENT, H2: CONSISTENT,
                                         H3: CONSISTENT})]
    m = score(HYPOTHESES, evidence)
    assert m.evidence[0].is_diagnostic is False
    assert m.evidence[0].score == 0.0
    # One item, so the warning says it in the singular throughout.
    assert any(w.startswith("The only item says the same thing about every "
                            "hypothesis and settles nothing. It is kept")
               for w in m.warnings), m.warnings


def test_evidence_that_separates_hypotheses_scores_highest():
    evidence = [
        _item("agrees with everything", {H1: CONSISTENT, H2: CONSISTENT,
                                         H3: CONSISTENT}),
        _item("splits them", {H1: STRONGLY_CONSISTENT,
                              H2: STRONGLY_INCONSISTENT, H3: NEUTRAL}),
    ]
    m = score(HYPOTHESES, evidence)
    assert m.evidence[0].label == "splits them", "sorted by diagnosticity"
    assert m.evidence[0].score == 4.0   # spread of 4, weight 1.0
    assert m.evidence[1].score == 0.0


def test_a_row_assessed_against_one_hypothesis_is_not_diagnostic_yet():
    """Scored on what is there rather than by averaging in zeroes for the
    unassessed -- averaging would make a half-finished row look
    diagnostic."""
    evidence = [_item("only judged once", {H1: STRONGLY_CONSISTENT})]
    m = score(HYPOTHESES, evidence)
    assert m.evidence[0].is_diagnostic is False


# --- the Admiralty weighting -------------------------------------------

def test_a_badly_graded_source_is_discounted_not_deleted():
    """A "strongly inconsistent" from an F6 source must not sink a
    hypothesis the way one from an A1 source does, or ACH becomes a way to
    launder a hunch into a matrix cell. But it must still count, because a
    zero would silently delete the fact that somebody offered it."""
    assert source_weight("A", "1") == 1.0
    assert 0 < source_weight("F", "6") < 0.1
    assert source_weight("A", "1") > source_weight("C", "3") > source_weight("F", "6")


def test_an_ungraded_source_is_treated_as_the_worst_not_the_best():
    """A missing grading is an absence of assurance. Defaulting it upward
    is how unsourced material acquires authority."""
    assert source_weight(None, None) == source_weight("F", "6")


def test_the_weighting_changes_the_ranking():
    strong = _item("A1 says H1 is wrong", {H1: STRONGLY_INCONSISTENT, H2: NEUTRAL},
                   reliability="A", credibility="1")
    weak = _item("F6 says H2 is wrong", {H1: NEUTRAL, H2: STRONGLY_INCONSISTENT},
                 reliability="F", credibility="6")
    m = score([(H1, "one"), (H2, "two")], [strong, weak])
    assert m.least_inconsistent == H2, (
        "a well-sourced contradiction outweighs a badly-sourced one")


# --- the warnings that stop it laundering bias -------------------------

def test_one_hypothesis_is_called_out_as_not_being_ACH():
    m = score([(H1, "the only idea we had")],
              [_item("a", {H1: STRONGLY_CONSISTENT})])
    assert any("add the alternative you think is wrong" in w for w in m.warnings)


def test_no_hypotheses_says_so_rather_than_returning_a_winner():
    m = score([], [])
    assert m.least_inconsistent is None
    assert m.warnings


def test_an_undiscriminating_matrix_says_so():
    """Two hypotheses that are equally inconsistent have not been separated,
    and reporting a leader would be a false result."""
    evidence = [_item("hits both", {H1: INCONSISTENT, H2: INCONSISTENT})]
    m = score([(H1, "one"), (H2, "two")], evidence)
    assert any("does not discriminate" in w for w in m.warnings)


def test_a_hypothesis_with_more_unassessed_than_assessed_is_flagged():
    """A low inconsistency score there means untested, not surviving, and
    that distinction is the difference between a result and a rank."""
    evidence = [_item(f"item {i}", {H1: NEUTRAL} if i == 0 else {})
                for i in range(5)]
    m = score([(H1, "barely tested")], evidence)
    assert any("untested, not surviving" in w for w in m.warnings)


def test_nothing_assessed_yields_no_leader():
    m = score(HYPOTHESES, [_item("unjudged", {})])
    assert m.least_inconsistent is None


# --- the next test to run ----------------------------------------------

def test_refute_first_names_the_most_diagnostic_UNASSESSED_item():
    """The cheapest next test. Deliberately not "the item that would most
    support the leader" -- that is the confirming question, and asking it
    is the bias."""
    settled = _item("fully judged", {H1: STRONGLY_CONSISTENT,
                                     H2: STRONGLY_INCONSISTENT, H3: NEUTRAL})
    gap = _item("half judged, and sharp", {H1: STRONGLY_CONSISTENT,
                                           H2: STRONGLY_INCONSISTENT})
    m = score(HYPOTHESES, [settled, gap])
    assert m.refute_first == gap.assertion_id


def test_a_complete_matrix_has_nothing_to_test_next():
    complete = _item("all three", {H1: CONSISTENT, H2: INCONSISTENT,
                                   H3: NEUTRAL})
    m = score(HYPOTHESES, [complete])
    assert m.refute_first is None


# --- an untested hypothesis has not survived; it has not competed -------
#
# docs/17 F20. Three compounding defects, all in the one number the module
# exists to produce, all found by reading the code hostilely rather than by
# any test — and the situation they fire in is precisely the one docs/13
# cites as the reason to build ACH at all.

def test_an_untested_hypothesis_does_not_win():
    """A hypothesis assessed against NOTHING scores inconsistency 0.0,
    which is the lowest value the scale can produce, so it sorted first and
    `least_inconsistent` named it. The guard asked whether ANY hypothesis
    had been assessed, never whether the winner had.

    A team eight months into one theory has assessed everything against
    that theory and nothing against the alternative. The matrix then
    reported the alternative as surviving, on the strength of never having
    been examined: confirmation bias with a scoreboard, in the tool built
    to correct it.
    """
    worked = [_item(f"item {i}", {H1: STRONGLY_INCONSISTENT if i % 3 == 0
                                  else CONSISTENT})
              for i in range(10)]
    m = score([(H1, "tested against ten items"), (H2, "nobody looked")],
              worked)
    assert m.least_inconsistent == H1, "the untested hypothesis won"
    # It still RANKS in the table -- it is part of the picture, and hiding
    # it would be its own distortion. It just cannot be the survivor.
    assert {h.hypothesis_id for h in m.hypotheses} == {H1, H2}


def test_an_untested_hypothesis_is_named_in_the_warnings():
    """The `thin` warning required `h.assessed` to be truthy, so the WORST
    case -- zero assessed -- was the one case it could not fire on."""
    m = score([(H1, "tested"), (H2, "nobody looked")],
              [_item("a", {H1: CONSISTENT})])
    joined = " ".join(m.warnings)
    assert "not competed" in joined
    assert "excluded from the ranking" in joined


def test_an_unfinished_row_is_unknown_not_undiagnostic():
    """"Says the same thing about everything" and "has not been entered
    against everything" are different facts, and reporting the second as
    the first told an analyst their ten good items settled nothing when
    they were merely half-entered."""
    m = score(HYPOTHESES, [_item("only judged against H1", {H1: CONSISTENT})])
    item = m.evidence[0]
    assert item.is_incomplete
    assert item.assessed_against == 1
    joined = " ".join(m.warnings)
    assert "unknown rather than zero" in joined
    assert not _SETTLES_NOTHING.search(joined), joined


def test_a_genuinely_undiagnostic_row_still_says_so():
    """The other side. Closing one hole by silencing the warning entirely
    would be its own defect."""
    m = score(HYPOTHESES, [_item("consistent with everything",
                                 {H1: CONSISTENT, H2: CONSISTENT,
                                  H3: CONSISTENT})])
    assert not m.evidence[0].is_incomplete
    assert not m.evidence[0].is_diagnostic
    assert _SETTLES_NOTHING.search(" ".join(m.warnings)), m.warnings


def test_a_stance_against_a_superseded_hypothesis_does_not_fill_a_gap():
    """`refute_first` counted `len(item.stances)` against
    `len(hypotheses)`. `reports.py` filters the hypothesis list on status
    and does NOT filter the cells, so an item carrying a stance against a
    SUPERSEDED hypothesis looked complete while a real gap remained — and
    the cheapest next test went unnamed."""
    superseded = uuid4()
    item = _item("looks complete, is not",
                 {H1: STRONGLY_CONSISTENT, superseded: INCONSISTENT})
    m = score([(H1, "live"), (H2, "live too")], [item])
    assert m.refute_first == item.assertion_id


def test_a_row_scored_against_only_some_hypotheses_is_unknown_not_undiagnostic():
    """README screenshot review, 2026-09-23. The demo matrix scored one
    item against two of its three hypotheses, the same way both times, and
    left the third blank. `is_incomplete` was a fixed `assessed_against < 2`,
    so with two cells filled the row counted as finished: the pane dimmed it
    as "not diagnostic" and the warning above it said the item says "the
    same thing about every hypothesis and settle[s] nothing", while the
    unassessed cell sat in the same row and `refute_first` named that very
    item as the cheapest next test. The pane contradicted itself.

    Agreement across the hypotheses it HAS been scored against says nothing
    about the one it has not: scored against H3 it could separate H3 from
    the other two. Until then its diagnosticity is unknown, not zero."""
    evidence = [
        _item("same builder", {H1: STRONGLY_CONSISTENT, H2: CONSISTENT,
                               H3: INCONSISTENT}),
        _item("different C2 panels", {H1: STRONGLY_INCONSISTENT,
                                      H2: CONSISTENT, H3: STRONGLY_CONSISTENT}),
        _item("hal_quarry", {H1: CONSISTENT, H2: CONSISTENT}),
    ]
    m = score(HYPOTHESES, evidence)
    quarry = next(d for d in m.evidence if d.label == "hal_quarry")
    assert quarry.assessed_against == 2
    assert quarry.is_incomplete, (
        "two agreeing cells and a blank third is an unfinished row")
    joined = " ".join(m.warnings)
    assert not _SETTLES_NOTHING.search(joined), (
        "the warning claimed an item said the same thing about EVERY "
        "hypothesis while one of them had never been scored")
    assert "unknown rather than zero" in joined
    assert m.refute_first == quarry.assertion_id, (
        "the cheapest next test is the row the warning now calls unfinished")


def test_a_partial_row_that_already_separates_two_hypotheses_is_diagnostic():
    """The other side of the same rule. A row that already puts two
    hypotheses apart DOES discriminate, whatever the blank cell turns out
    to be; calling it unknown would hide a result. Its gap is still the
    next test."""
    gap = _item("half judged, and sharp", {H1: STRONGLY_CONSISTENT,
                                           H2: STRONGLY_INCONSISTENT})
    m = score(HYPOTHESES, [gap])
    row = m.evidence[0]
    assert row.is_diagnostic and not row.is_incomplete
    assert m.refute_first == gap.assertion_id


def test_every_warning_about_a_row_is_true_of_the_rows_it_counts():
    """Held as a property over every shape a three-hypothesis row can take
    with stances drawn from {none, -1, +1}: an item counted as "says the
    same thing about every hypothesis" has a stance against every live
    hypothesis, and they are all the same."""
    from itertools import product
    choices = (None, INCONSISTENT, CONSISTENT)
    for combo in product(choices, repeat=3):
        stances = {h: s for h, s in zip((H1, H2, H3), combo, strict=True)
                   if s is not None}
        row = score(HYPOTHESES, [_item("x", stances)]).evidence[0]
        undiagnostic = not row.is_incomplete and not row.is_diagnostic
        if undiagnostic:
            assert len(stances) == 3 and len(set(stances.values())) == 1, combo
        if len(set(stances.values())) > 1:
            assert row.is_diagnostic and not row.is_incomplete, combo


# --- the response ------------------------------------------------------

def test_the_response_states_the_method_it_used():
    """A number nobody can interpret is a number that gets interpreted
    wrongly. The response says what the ranking means, in the response."""
    from noctornal_api.ach import as_response
    body = as_response(score(HYPOTHESES, [_item("a", {H1: CONSISTENT})]))
    assert "least evidence against it" in body["method"]
    assert "not the most evidence for it" in body["method"]


def test_the_response_round_trips_ids_as_strings():
    from noctornal_api.ach import as_response
    body = as_response(score(HYPOTHESES, [
        _item("a", {H1: CONSISTENT, H2: INCONSISTENT, H3: NEUTRAL})]))
    assert body["least_inconsistent"] == str(H1)
    assert all(isinstance(h["id"], str) for h in body["hypotheses"])


def test_a_warning_agrees_with_the_count_it_states():
    """README screenshot set review, 2026-09-23: the ACH capture was headed
    "1 of 3 items are unfinished". Every count the warnings state takes
    its noun, verb and pronoun from the number, and a count that is the
    whole matrix is said as such."""
    def warning(m, word):
        found = [w for w in m.warnings if word in w]
        assert len(found) == 1, m.warnings
        return found[0]

    sharp = _item("sharp", {H1: STRONGLY_CONSISTENT, H2: STRONGLY_INCONSISTENT,
                            H3: CONSISTENT})
    half = _item("half", {H1: CONSISTENT})
    flat = _item("flat", {H1: CONSISTENT, H2: CONSISTENT, H3: CONSISTENT})

    one = score(HYPOTHESES, [sharp, half, _item("sharp too", {
        H1: INCONSISTENT, H2: CONSISTENT, H3: CONSISTENT})])
    assert warning(one, "unfinished").startswith(
        "1 of 3 items is unfinished: "), one.warnings
    assert "so its diagnosticity is unknown" in warning(one, "unfinished")
    assert "Finishing that row is" in warning(one, "unfinished")

    two = score(HYPOTHESES, [sharp, half, _item("half too", {H2: CONSISTENT})])
    assert warning(two, "unfinished").startswith(
        "2 of 3 items are unfinished: "), two.warnings
    assert "so their diagnosticity is unknown" in warning(two, "unfinished")
    assert "Finishing those rows is" in warning(two, "unfinished")

    both = score(HYPOTHESES, [half, _item("half too", {H2: CONSISTENT})])
    assert warning(both, "unfinished").startswith(
        "Both items are unfinished: "), both.warnings
    every = score(HYPOTHESES, [half, _item("half too", {H2: CONSISTENT}),
                               _item("half three", {H3: CONSISTENT})])
    assert warning(every, "unfinished").startswith(
        "All 3 items are unfinished: "), every.warnings

    flat_one = score(HYPOTHESES, [sharp, flat])
    assert warning(flat_one, "nothing").startswith(
        "1 of 2 items says the same thing about every hypothesis and "
        "settles nothing. It is kept"), flat_one.warnings

    flat_two = score(HYPOTHESES, [sharp, flat, _item("flat too", {
        H1: INCONSISTENT, H2: INCONSISTENT, H3: INCONSISTENT})])
    assert warning(flat_two, "nothing").startswith(
        "2 of 3 items say the same thing about every hypothesis and "
        "settle nothing. They are kept"), flat_two.warnings

    for m in (one, two, both, every, flat_one, flat_two):
        assert not any(re.search(r"\w\((?:s|es)\)", w) for w in m.warnings), (
            m.warnings)

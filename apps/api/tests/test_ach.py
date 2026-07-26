"""ACH scoring, against hand-computed values.

The test that matters is `test_the_ranking_is_by_inconsistency_not_support`.
Every naive ACH implementation gets that backwards, and getting it backwards
turns the method into confirmation bias with a scoreboard -- which is the
exact failure docs/13 says ACH exists to correct.

Pure: no database, no clock. The HTTP leg is in `test_ach_pg.py`.
"""
from __future__ import annotations

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
    assert any("settle nothing" in w for w in m.warnings)


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
    assert "settle nothing" not in joined


def test_a_genuinely_undiagnostic_row_still_says_so():
    """The other side. Closing one hole by silencing the warning entirely
    would be its own defect."""
    m = score(HYPOTHESES, [_item("consistent with everything",
                                 {H1: CONSISTENT, H2: CONSISTENT,
                                  H3: CONSISTENT})])
    assert not m.evidence[0].is_incomplete
    assert not m.evidence[0].is_diagnostic
    assert "settle nothing" in " ".join(m.warnings)


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

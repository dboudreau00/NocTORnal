"""Analysis of Competing Hypotheses (Heuer), scored.

Phase 6. docs/13 puts it in tier 2 and says why:

    Cybercrime attribution is where confirmation bias does the most
    damage; a team eight months into one theory reads every new post as
    support. Putting the competing hypothesis in the same view is a
    structural correction.

Pure and database-free, like `analytics.py` and for the same reason: the
scoring is the part with the reasoning in it, so it should be testable
against hand-computed values rather than against a fixture.

## The inversion that makes it ACH rather than a table

Heuer's central move, and the one every naive implementation gets
backwards:

    **The hypothesis that survives is the one with the LEAST evidence
    against it, not the most evidence for it.**

Counting support ranks whichever hypothesis the team has spent longest
collecting for -- which is confirmation bias with a scoreboard. Ranking by
inconsistency asks the only question that can actually eliminate anything:
what does this theory fail to explain? So `inconsistency` is the primary
sort, `support` is reported but never ranks, and `refute_first` names the
cheapest disconfirming test rather than the next confirming one.

## Diagnosticity

An item of evidence consistent with EVERY hypothesis discriminates
nothing. It feels like progress and is not: "the actor speaks Russian"
against four Russian-speaking hypotheses moves no needle.

`diagnosticity` is the spread of an item's stances across hypotheses --
zero when identical everywhere, maximum when it separates them. It is
reported per item and used to sort, so the evidence that would actually
settle the question rises to the top of the matrix instead of being buried
under forty rows of agreeable background.

## Weighting by the source, not by the analyst's mood

A stance is scored against the Admiralty grading of the assertion behind
it. A "strongly inconsistent" from an F6 source (unreliable, improbable)
must not sink a hypothesis the way one from an A1 source does, or ACH
becomes a way to launder a hunch into a matrix cell. The weight is the
product of two 0..1 ramps over reliability (A..F) and credibility (1..6),
floored so that even the worst-graded source counts for something -- a
zero would silently delete evidence rather than discount it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

# Heuer's stance scale, as stored in core.hypothesis_evidence.stance.
STRONGLY_INCONSISTENT = -2
INCONSISTENT = -1
NEUTRAL = 0
CONSISTENT = 1
STRONGLY_CONSISTENT = 2

STANCE_LABEL = {
    -2: "strongly inconsistent",
    -1: "inconsistent",
    0: "neutral / not applicable",
    1: "consistent",
    2: "strongly consistent",
}

# Admiralty reliability A (completely reliable) .. F (cannot be judged),
# and credibility 1 (confirmed) .. 6 (cannot be judged). Both ramp DOWN to
# a floor rather than to zero: a poorly-graded source is discounted, never
# deleted. Deleting it would hide the fact that somebody offered it.
_RELIABILITY = {"A": 1.0, "B": 0.85, "C": 0.7, "D": 0.5, "E": 0.3, "F": 0.2}
_CREDIBILITY = {"1": 1.0, "2": 0.85, "3": 0.7, "4": 0.5, "5": 0.3, "6": 0.2}
_FLOOR = 0.2


def source_weight(reliability: str | None, credibility: str | None) -> float:
    """0.04 .. 1.0. An ungraded source is treated as the worst graded one,
    not as a good one: a missing grading is an absence of assurance, and
    defaulting it upward is how unsourced material acquires authority."""
    r = _RELIABILITY.get((reliability or "F").upper(), _FLOOR)
    c = _CREDIBILITY.get(str(credibility or "6"), _FLOOR)
    return round(r * c, 4)


@dataclass(frozen=True)
class EvidenceItem:
    """One row of the matrix: an assertion, and how it stands against each
    hypothesis."""

    assertion_id: UUID
    label: str
    reliability: str | None
    credibility: str | None
    #: hypothesis id -> stance in -2..2
    stances: dict[UUID, int] = field(default_factory=dict)

    @property
    def weight(self) -> float:
        return source_weight(self.reliability, self.credibility)


@dataclass(frozen=True)
class HypothesisScore:
    hypothesis_id: UUID
    statement: str
    #: The number that RANKS. Sum of weighted inconsistency, as a positive
    #: quantity: lower is better, and the least-inconsistent hypothesis is
    #: the one ACH says survives.
    inconsistency: float
    #: Reported, never ranked. See the module docstring.
    support: float
    #: How much diagnostic evidence has actually been assessed against this
    #: hypothesis. A hypothesis with a perfect score and two items assessed
    #: has not been tested, and saying so is the difference between a
    #: result and a rank.
    assessed: int
    unassessed: int


@dataclass(frozen=True)
class Diagnosticity:
    assertion_id: UUID
    label: str
    #: 0 when the item says the same thing about every hypothesis, higher
    #: as it separates them. Weighted by the source's grading.
    score: float
    #: True when the item is consistent (or inconsistent) with everything
    #: equally, and therefore settles nothing.
    is_diagnostic: bool
    #: How many of the live hypotheses this item has actually been scored
    #: against. Below two, `is_diagnostic` is not a judgement about the
    #: item at all -- it is a statement that the row is unfinished, and
    #: those are different facts an analyst acts on differently. Conflating
    #: them told an analyst that ten good items "settle nothing" when they
    #: had simply not been entered against the second hypothesis yet.
    assessed_against: int = 0

    @property
    def is_incomplete(self) -> bool:
        return self.assessed_against < 2


@dataclass(frozen=True)
class Matrix:
    hypotheses: list[HypothesisScore]
    evidence: list[Diagnosticity]
    #: The least-inconsistent hypothesis, or None when nothing has been
    #: assessed. NOT "the winner": ACH eliminates, it does not prove.
    least_inconsistent: UUID | None
    #: The highest-diagnosticity item that is not yet assessed against
    #: every hypothesis -- the cheapest next test.
    refute_first: UUID | None
    #: Plain-language warnings. docs/13's point is that ACH is a structural
    #: correction for confirmation bias, and a matrix nobody reads the
    #: caveats on is a matrix that launders the bias instead.
    warnings: list[str] = field(default_factory=list)


def score(hypotheses: list[tuple[UUID, str]],
          evidence: list[EvidenceItem]) -> Matrix:
    """Score a matrix. Pure: same inputs, same numbers, no clock, no DB."""
    warnings: list[str] = []
    if not hypotheses:
        return Matrix([], [], None, None,
                      ["No hypotheses. ACH needs at least two: a single "
                       "hypothesis with evidence gathered for it is what ACH "
                       "exists to correct."])
    if len(hypotheses) == 1:
        warnings.append(
            "Only one hypothesis. ACH cannot discriminate between one thing; "
            "add the alternative you think is wrong -- that is the whole "
            "method.")

    scored: list[HypothesisScore] = []
    for hid, statement in hypotheses:
        inconsistency = 0.0
        support = 0.0
        assessed = 0
        for item in evidence:
            stance = item.stances.get(hid)
            if stance is None:
                continue
            assessed += 1
            if stance < 0:
                inconsistency += abs(stance) * item.weight
            elif stance > 0:
                support += stance * item.weight
        scored.append(HypothesisScore(
            hypothesis_id=hid, statement=statement,
            inconsistency=round(inconsistency, 4), support=round(support, 4),
            assessed=assessed, unassessed=len(evidence) - assessed))

    diagnosticity = [_diagnosticity(item, hypotheses) for item in evidence]

    # THE ranking. Least inconsistency first; support breaks ties only, and
    # only because something has to. Never the other way round.
    ranked = sorted(scored, key=lambda h: (h.inconsistency, -h.support))

    # AN UNTESTED HYPOTHESIS DOES NOT SURVIVE; IT HAS NOT COMPETED.
    #
    # This was the sharpest defect in the module (F20, 2026-07-26). A
    # hypothesis assessed against NOTHING scores inconsistency 0.0, which
    # is the lowest value the scale can produce, so it sorted first and
    # `least_inconsistent` named it. The guard asked whether ANY hypothesis
    # had been assessed, never whether the winner had.
    #
    # The failure lands precisely where the method is supposed to help. A
    # team eight months into one theory has assessed everything against
    # that theory and nothing against the alternative -- which is the
    # situation docs/13 cites as the reason to build ACH at all -- and the
    # matrix then reported the alternative as surviving, on the strength of
    # never having been examined. Confirmation bias with a scoreboard, in
    # the tool built to correct it.
    tested = [h for h in ranked if h.assessed]
    least = tested[0].hypothesis_id if tested else None

    untested = [h for h in ranked if not h.assessed]
    if untested and tested:
        warnings.append(
            f"{len(untested)} hypothes{'is has' if len(untested) == 1 else 'es have'} "
            f"no evidence assessed against "
            f"{'it' if len(untested) == 1 else 'them'} at all, so "
            f"{'it is' if len(untested) == 1 else 'they are'} excluded from "
            f"the ranking. An untested hypothesis has not survived; it has "
            f"not competed. Score the existing evidence against "
            f"{'it' if len(untested) == 1 else 'them'} before reading "
            f"anything into this matrix.")

    if least is not None and len(tested) > 1:
        first, second = tested[0], tested[1]
        if abs(first.inconsistency - second.inconsistency) < 1e-9:
            warnings.append(
                "The top two hypotheses are equally inconsistent, so this "
                "matrix does not discriminate between them yet. Look for "
                "evidence that would be inconsistent with exactly one.")

    # "Says the same thing about everything" and "has not been entered
    # against everything" are DIFFERENT facts, and reporting the second as
    # the first told an analyst their ten good items were worthless when
    # they were merely half-entered.
    undiagnostic = [d for d in diagnosticity
                    if not d.is_incomplete and not d.is_diagnostic]
    incomplete = [d for d in diagnosticity if d.is_incomplete]
    if undiagnostic:
        warnings.append(
            f"{len(undiagnostic)} of {len(diagnosticity)} items say the same "
            f"thing about every hypothesis and settle nothing. They are kept "
            f"in the record and excluded from the ranking.")
    if incomplete:
        warnings.append(
            f"{len(incomplete)} of {len(diagnosticity)} items have been "
            f"scored against fewer than two hypotheses, so their "
            f"diagnosticity is unknown rather than zero. Finishing those "
            f"rows is the cheapest work available here.")

    thin = [h for h in scored if h.assessed and h.unassessed > h.assessed]
    if thin:
        warnings.append(
            "Some hypotheses have more unassessed evidence than assessed. A "
            "low inconsistency score there means untested, not surviving.")

    # The cheapest next test: the most diagnostic item that some LIVE
    # hypothesis has not yet been scored against. Deliberately NOT "the
    # item that would most support the leader".
    #
    # Counted over the live hypotheses rather than over `len(item.stances)`,
    # which includes stances against SUPERSEDED hypotheses -- `reports.py`
    # filters the hypothesis list on status and does not filter the cells,
    # so a row could look complete while a real gap remained.
    live = {hid for hid, _ in hypotheses}
    gaps = [d for d in diagnosticity
            if any(item.assertion_id == d.assertion_id
                   and len(live & set(item.stances)) < len(live)
                   for item in evidence)]
    refute_first = max(gaps, key=lambda d: d.score).assertion_id if gaps else None

    return Matrix(hypotheses=ranked, evidence=sorted(
        diagnosticity, key=lambda d: -d.score),
        least_inconsistent=least, refute_first=refute_first, warnings=warnings)


def _diagnosticity(item: EvidenceItem,
                   hypotheses: list[tuple[UUID, str]]) -> Diagnosticity:
    """How much this item separates the hypotheses.

    The spread of its stances, weighted by the source. An item that is
    +2 against everything scores 0 and is flagged undiagnostic -- it feels
    like strong evidence and discriminates nothing, which is the specific
    illusion ACH exists to break.

    An item assessed against only SOME hypotheses is scored on what is
    there: the unassessed ones are a gap to fill, not a zero to average in,
    because averaging in a zero would make a half-finished row look
    diagnostic.
    """
    stances = [item.stances[hid] for hid, _ in hypotheses if hid in item.stances]
    if len(stances) < 2:
        # Not "undiagnostic". UNKNOWN — the row is unfinished, and
        # `assessed_against` says so rather than letting a caller read the
        # 0.0 as a verdict on the evidence.
        return Diagnosticity(item.assertion_id, item.label, 0.0, False,
                             assessed_against=len(stances))
    spread = max(stances) - min(stances)
    return Diagnosticity(
        assertion_id=item.assertion_id, label=item.label,
        score=round(spread * item.weight, 4), is_diagnostic=spread > 0,
        assessed_against=len(stances))


def as_response(matrix: Matrix) -> dict:
    return {
        "hypotheses": [
            {"id": str(h.hypothesis_id), "statement": h.statement,
             "inconsistency": h.inconsistency, "support": h.support,
             "assessed": h.assessed, "unassessed": h.unassessed}
            for h in matrix.hypotheses],
        "evidence": [
            {"assertion_id": str(d.assertion_id), "label": d.label,
             "diagnosticity": d.score, "is_diagnostic": d.is_diagnostic,
             "assessed_against": d.assessed_against,
             # So the UI can render "unknown" differently from "settles
             # nothing". They look identical at 0.0 and mean opposite
             # things: one is a judgement about the evidence, the other is
             # a gap in the matrix.
             "is_incomplete": d.is_incomplete}
            for d in matrix.evidence],
        "least_inconsistent": (str(matrix.least_inconsistent)
                               if matrix.least_inconsistent else None),
        "refute_first": (str(matrix.refute_first)
                         if matrix.refute_first else None),
        "warnings": matrix.warnings,
        "method": (
            "Ranked by INCONSISTENCY, ascending. The hypothesis that survives "
            "is the one with the least evidence against it, not the most "
            "evidence for it -- counting support ranks whichever theory the "
            "team has collected for longest (Heuer). Evidence consistent with "
            "every hypothesis is kept in the record and excluded from the "
            "ranking, because it discriminates nothing."
        ),
    }

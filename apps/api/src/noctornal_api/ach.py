"""Analysis of Competing Hypotheses (Heuer), scored. Pure and database-free, like `analytics.py`,
so the scoring can be tested against hand-computed values (docs/13).

The hypothesis that survives is the one with the least evidence against it, not the most for it:
`inconsistency` is the primary sort, `support` is reported but never ranks, and `refute_first`
names the cheapest disconfirming test. `diagnosticity` is the spread of an item's stances across
hypotheses, zero when identical everywhere, so evidence consistent with every hypothesis sinks
and the evidence that would settle the question rises. Each stance is weighted by the Admiralty
grading of its assertion, the product of two 0..1 ramps over reliability (A..F) and credibility
(1..6), floored above zero so the worst source is discounted, never deleted.
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
    #: A REJECTED or SUPERSEDED hypothesis, scored for the record and never ranked: as a live
    #: competitor a ruled-out theory with nothing against it could be named least inconsistent, and
    #: its blank cells would keep rows "unfinished" that no live hypothesis needs scored.
    retired: bool = False


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
    #: How many of the live hypotheses this item has been scored against. Below two,
    #: `is_diagnostic` says nothing about the item, only that the row is unfinished, which an
    #: analyst acts on differently.
    assessed_against: int = 0
    #: How many live hypotheses the matrix was scored over, so the row can
    #: tell "agrees everywhere" from "agrees everywhere it has been looked
    #: at". 0 means unknown, and then only the two-cell floor applies.
    live_hypotheses: int = 0
    #: The two factors of `score`, so a reader can do the arithmetic: the spread of the stances
    #: (0..4) and the source weight it is multiplied by.
    spread: int = 0
    weight: float = 0.0

    @property
    def is_incomplete(self) -> bool:
        """True when the row's diagnosticity is UNKNOWN rather than zero.

        Below two cells nothing can be compared. From two cells up, a row that already separates
        two hypotheses is diagnostic whatever its blanks turn out to be; a row that agrees with
        itself so far is unknown until the rest are scored, because the blank one could be the
        hypothesis it separates."""
        if self.assessed_against < 2:
            return True
        return (not self.is_diagnostic
                and self.assessed_against < self.live_hypotheses)


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
    #: Ruled-out hypotheses, scored the same way for the record and kept
    #: out of `hypotheses`, the ranking, the warnings and the next test.
    retired: list[HypothesisScore] = field(default_factory=list)


def _of_items(k: int, total: int) -> str:
    """The subject of a warning about k of the matrix's total items, as a reader would say it:
    "1 of 3 items", "All 3 items", "Both items", "The only item". The caller makes the verb agree
    with k."""
    if total == 1:
        return "The only item"
    if k == total:
        return "Both items" if total == 2 else f"All {total} items"
    return f"{k} of {total} items"


def _sums(hid: UUID, statement: str, evidence: list[EvidenceItem],
          flat: set[UUID], *, retired: bool = False) -> HypothesisScore:
    """One hypothesis's weighted sums over the matrix.

    `flat` holds the rows that say the same thing about every live hypothesis. They count as
    assessed (somebody did look) and add nothing to either sum, as the warning and the method text
    say: Heuer drops non-diagnostic evidence from the tally, because it lifts every hypothesis
    alike."""
    inconsistency = 0.0
    support = 0.0
    assessed = 0
    for item in evidence:
        stance = item.stances.get(hid)
        if stance is None:
            continue
        assessed += 1
        if item.assertion_id in flat:
            continue
        if stance < 0:
            inconsistency += abs(stance) * item.weight
        elif stance > 0:
            support += stance * item.weight
    return HypothesisScore(
        hypothesis_id=hid, statement=statement,
        inconsistency=round(inconsistency, 4), support=round(support, 4),
        assessed=assessed, unassessed=len(evidence) - assessed, retired=retired)


def score(hypotheses: list[tuple[UUID, str]],
          evidence: list[EvidenceItem], *,
          retired: list[tuple[UUID, str]] | tuple = ()) -> Matrix:
    """Score a matrix. Pure: same inputs, same numbers, no clock, no DB.

    `hypotheses` are the live competitors. `retired` are the ones ruled out
    (REJECTED, SUPERSEDED): scored with the same sums for the record, never
    ranked, and never counted when asking whether a row is finished."""
    warnings: list[str] = []
    diagnosticity = [_diagnosticity(item, hypotheses) for item in evidence]
    flat = {d.assertion_id for d in diagnosticity
            if not d.is_incomplete and not d.is_diagnostic}
    ruled_out = sorted(
        (_sums(hid, statement, evidence, flat, retired=True)
         for hid, statement in retired),
        key=lambda h: (h.inconsistency, -h.support))
    if not hypotheses:
        # The rows are kept even when every hypothesis is ruled out, so the grid still records what
        # ruled each one out. With no live hypothesis every row reads unfinished at 0 and none is a
        # next test, so the one warning below is the whole story.
        return Matrix([], sorted(diagnosticity, key=lambda d: -d.score), None, None,
                      ["No hypotheses. ACH needs at least two."],
                      retired=ruled_out)
    if len(hypotheses) == 1:
        warnings.append(
            "Only one hypothesis. ACH needs at least two: add the "
            "alternative you think is wrong.")

    scored = [_sums(hid, statement, evidence, flat)
              for hid, statement in hypotheses]

    # THE ranking. Least inconsistency first; support breaks ties only, and
    # only because something has to. Never the other way round.
    ranked = sorted(scored, key=lambda h: (h.inconsistency, -h.support))

    # An untested hypothesis does not survive; it has not competed. Assessed against nothing it
    # scores inconsistency 0.0, the lowest the scale gives, so only an assessed hypothesis can be
    # `least_inconsistent`: otherwise the alternative a team never examined would be named the
    # survivor, the confirmation bias ACH exists to correct.
    tested = [h for h in ranked if h.assessed]
    least = tested[0].hypothesis_id if tested else None

    untested = [h for h in ranked if not h.assessed]
    if untested and tested:
        warnings.append(
            f"{len(untested)} hypothes{'is has' if len(untested) == 1 else 'es have'} "
            f"no evidence assessed against "
            f"{'it' if len(untested) == 1 else 'them'} at all, so "
            f"{'it is' if len(untested) == 1 else 'they are'} excluded from "
            f"the ranking. Score the existing evidence against "
            f"{'it' if len(untested) == 1 else 'them'} first.")

    if least is not None and len(tested) > 1:
        first, second = tested[0], tested[1]
        if abs(first.inconsistency - second.inconsistency) < 1e-9:
            warnings.append(
                "The top two hypotheses are equally inconsistent, so this "
                "matrix does not discriminate between them yet.")

    # "Says the same thing about everything" and "has not been entered
    # against everything" are DIFFERENT facts, and reporting the second as
    # the first told an analyst their ten good items were worthless when
    # they were merely half-entered.
    undiagnostic = [d for d in diagnosticity
                    if not d.is_incomplete and not d.is_diagnostic]
    incomplete = [d for d in diagnosticity if d.is_incomplete]
    if undiagnostic:
        # True because `_sums` leaves these rows out of every score.
        one = len(undiagnostic) == 1
        warnings.append(
            f"{_of_items(len(undiagnostic), len(diagnosticity))} "
            f"{'says' if one else 'say'} the same thing about every "
            f"hypothesis and {'settles' if one else 'settle'} nothing. "
            f"{'It is' if one else 'They are'} kept in the record and "
            f"left out of every score.")
    if incomplete:
        one = len(incomplete) == 1
        warnings.append(
            f"{_of_items(len(incomplete), len(diagnosticity))} "
            f"{'is' if one else 'are'} unfinished: not scored against enough "
            f"hypotheses to tell whether {'it' if one else 'they'} "
            f"discriminate{'s' if one else ''}, so {'its' if one else 'their'} "
            f"diagnosticity is unknown rather than zero.")

    thin = [h for h in scored if h.assessed and h.unassessed > h.assessed]
    if thin:
        warnings.append(
            "Some hypotheses have more unassessed evidence than assessed. A "
            "low inconsistency score there means untested, not surviving.")

    # The cheapest next test: the most diagnostic item that some live hypothesis has not yet been
    # scored against, never "the item that would most support the leader". Counted over the live
    # hypotheses, not `len(item.stances)`: `reports.py` filters hypotheses on status but not the
    # cells, so stances against superseded ones would hide a real gap.
    live = {hid for hid, _ in hypotheses}
    gaps = [d for d in diagnosticity
            if any(item.assertion_id == d.assertion_id
                   and len(live & set(item.stances)) < len(live)
                   for item in evidence)]
    refute_first = max(gaps, key=lambda d: d.score).assertion_id if gaps else None

    return Matrix(hypotheses=ranked, evidence=sorted(
        diagnosticity, key=lambda d: -d.score),
        least_inconsistent=least, refute_first=refute_first, warnings=warnings,
        retired=ruled_out)


def _diagnosticity(item: EvidenceItem,
                   hypotheses: list[tuple[UUID, str]]) -> Diagnosticity:
    """How much this item separates the hypotheses: its stances' spread, weighted by the source.

    An item +2 against everything scores 0 and is flagged undiagnostic: it feels like strong
    evidence and discriminates nothing. An item assessed against only some hypotheses is scored on
    what is there; an unassessed one is a gap to fill, not a zero to average in, which would make a
    half-finished row look diagnostic.
    """
    stances = [item.stances[hid] for hid, _ in hypotheses if hid in item.stances]
    if len(stances) < 2:
        # Not "undiagnostic". UNKNOWN — the row is unfinished, and
        # `assessed_against` says so rather than letting a caller read the
        # 0.0 as a verdict on the evidence.
        return Diagnosticity(item.assertion_id, item.label, 0.0, False,
                             assessed_against=len(stances),
                             live_hypotheses=len(hypotheses),
                             weight=item.weight)
    spread = max(stances) - min(stances)
    return Diagnosticity(
        assertion_id=item.assertion_id, label=item.label,
        score=round(spread * item.weight, 4), is_diagnostic=spread > 0,
        assessed_against=len(stances), live_hypotheses=len(hypotheses),
        spread=spread, weight=item.weight)


def as_response(matrix: Matrix) -> dict:
    return {
        # The ranked live hypotheses first, then the ruled-out ones marked
        # `retired`, so a reader of the list meets the competitors in rank
        # order and the record after them.
        "hypotheses": [
            {"id": str(h.hypothesis_id), "statement": h.statement,
             "inconsistency": h.inconsistency, "support": h.support,
             "assessed": h.assessed, "unassessed": h.unassessed,
             "retired": h.retired}
            for h in [*matrix.hypotheses, *matrix.retired]],
        "evidence": [
            {"assertion_id": str(d.assertion_id), "label": d.label,
             "diagnosticity": d.score, "is_diagnostic": d.is_diagnostic,
             "assessed_against": d.assessed_against,
             # So the UI can render "unknown" differently from "settles
             # nothing". They look identical at 0.0 and mean opposite
             # things: one is a judgement about the evidence, the other is
             # a gap in the matrix.
             "is_incomplete": d.is_incomplete,
             "spread": d.spread, "weight": d.weight}
            for d in matrix.evidence],
        "least_inconsistent": (str(matrix.least_inconsistent)
                               if matrix.least_inconsistent else None),
        "refute_first": (str(matrix.refute_first)
                         if matrix.refute_first else None),
        "warnings": matrix.warnings,
        # The undiagnostic rule is "the same stance against every hypothesis", which an item
        # inconsistent with everything meets as well as one consistent with everything, and a row
        # with a blank cell does not meet yet. The weighting sentence says what a source grade
        # counts for (a C3 source counts 0.49 of an A1).
        "method": (
            "Ranked by INCONSISTENCY, ascending. The hypothesis that survives "
            "is the one with the least evidence against it, not the most "
            "evidence for it. Counting support ranks whichever theory the "
            "team has collected for longest (Heuer). Evidence that says the "
            "same thing about every hypothesis is kept in the record and "
            "excluded from the ranking, because it discriminates nothing. "
            f"Each stance is weighted by the Admiralty grade of the "
            f"assertion behind it, from {source_weight('A', '1'):.2f} for A1 "
            f"to {source_weight('C', '3'):.2f} for C3 and "
            f"{source_weight('F', '6'):.2f} for F6 (an ungraded source counts "
            f"as F6), so a score is the sum of stance times weight, not a "
            f"count of cells."
        ),
    }

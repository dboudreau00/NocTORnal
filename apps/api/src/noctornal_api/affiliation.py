"""Bipartite to one-mode projection for the forum and wallet families
(F2, 2026-09-24).

docs/03 has always said the proper answer to a two-mode projection is "a
bipartite projection to one-mode with Newman weighting", and
`analytics._mode_warning` recorded it as the open item: the Financial
preset makes WALLET and TRANSACTION first-class vertices, so a wallet with
many controllers scored as a broker. This module is that projection, for
two families of venue only (docs/00 decision 73):

- **forum**: FORUM and CHANNEL. Entities who POST ON the same venue are
  tied, each shared venue counting 1 / (size - 1) under Newman weighting.
- **wallet**: WALLET and TRANSACTION. Entities who CONTROL the same wallet
  are tied the same way (wallet control), and money moving between wallets
  becomes a directed tie from the payer's controller to the payee's
  (wallet flow), one hop only.

The conversation family is NOT built. Over core.edge PARTICIPANT_IN it
would lose decision 58's incidental-party exclusion and the raw room size
the Comms pane's co-participation view keeps (`coparticipation.py`), so
conversations stay that view's job and the Communication preset keeps its
mode warning.

Four rules (2026-09-24):

**Sizes come from everything the caller can see.** A venue's size, the
venue limit, the transaction's |I| and |O| and a wallet's controller count
are taken from EVERY visible live membership, including those the
confidence floor or the accepted-ties scope then leaves out of the drawing.
Filtering first made the scope that is meant to remove doubtful ties the
one that switched the caps off: a 26-in, 25-out CoinJoin with one accepted
leg a side became a 1 x 1 transaction drawing a full-weight money tie, and
a 60-poster board with four accepted posters drew a 4-clique at 1/3.
Pairs and legs are then drawn only from the memberships that pass.

**The limits are checked before anything is built.** `MAX_DERIVED_TIES`
is an upper bound computed by arithmetic (sums of products over the
drawing memberships), so a view that would draw too many ties is refused in
time linear in its rows, before a single derived edge is allocated and
before any leg is enumerated. Legs that cannot draw (an end with no visible
controller, or through an oversized wallet) are counted as products, never
walked one by one. The tie limit bounds pairs, not the dated periods behind
each, so each constituent's rows are merged once into disjoint periods (a
sort of its rows) and `MAX_PERIOD_STEPS` bounds, again by arithmetic, the
steps of every overlap test the transform will then make. Past both
checks, the transform's work is at most the two limits.

**Identity links only ever remove a tie, and only when nobody doubts
them.** Two entities recorded as one identity (SAME_AS, ALIAS_OF,
ATTRIBUTED_TO) sharing a wallet is one actor, not a tie. A link a reviewer
has DISPUTED, or a legacy REJECTED one, no longer suppresses anything: a
contested machine proposal must not keep changing the numbers ("machines
propose, analysts dispose"), so such a pair keeps its tie and is counted
apart.

**Nothing is dropped silently.** Every exclusion is counted in the
coverage dict, which is data only (counts, dicts keyed by type, the
oversized venues named) so `analytics.graph_hash` can fold it into the
cache key: a renamed oversized forum, or one raised above the caller's
clearance, is a different answer and must not be served as the same one.

Pure and database-free, like `analytics.py`. It imports `coparticipation`
for its weighting constants and never imports `projections`, which
imports it.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

from noctornal_api.coparticipation import (
    DEFAULT_MAX_ROOM_SIZE,
    WEIGHT_COUNT,
    WEIGHT_NEWMAN,
)

#: The venue limit, the Comms pane's room limit: Newman weighting makes a
#: big venue's pairs individually negligible, it does not stop there being
#: n (n - 1) / 2 of them.
DEFAULT_MAX_VENUE_SIZE = DEFAULT_MAX_ROOM_SIZE
MAX_VENUE_SIZE_RANGE = (2, 500)
MIN_SHARED_RANGE = (1, 100)

#: Measured on a development host (Python 3.13, the real graph_hash and
#: materialise): 50,225 derived ties cost 0.45 s to transform, 0.14 s to
#: hash and 0.10 s to materialise, peaking at 52 MB; 249,900 cost 2.26 s,
#: 0.61 s and 0.60 s at 249 MB. A read route pays this, so the ceiling is
#: the smaller figure. The pre-count that refuses above it took 0.04 s.
#: This implementation, measured on the build host (2026-09-24): 49,000
#: derived ties from 40 boards of 50 posters cost 0.50 s to transform,
#: 0.11 s to hash and 0.14 s to materialise.
MAX_DERIVED_TIES = 50_000

#: The contemporaneity check's own ceiling, in steps of the linear merge of
#: two constituents' dated periods (`_overlap`, `_last_overlap`). The tie
#: limit bounds PAIRS; a pair costs as many steps as its two members have
#: separate periods, and an analyst can record a membership over as many
#: periods as they like. Undated memberships cost one step a side, so a
#: view at the tie limit uses 100,000 and this never binds on it. Measured
#: on the build host (2026-09-24), worst cases at the limit: 100 posters
#: with 100 dated rows each whose periods never meet (990,000 steps) took
#: 0.16 s to transform, 0.08 s of it before the first merge; a flow of
#: 3 x 3 wallets with 2,200 dated rows on every constituent (1,009,800
#: steps, 52,800 rows) took 0.5 s, nearly all of it reading the rows.
MAX_PERIOD_STEPS = 1_000_000

#: Oversized venues named in the payload. The total is always given, and
#: the count per type, so the partition invariant holds past the list.
OVERSIZED_LISTED = 25

IDENTITY_LINK_TYPES = ("SAME_AS", "ALIAS_OF", "ATTRIBUTED_TO")
#: The review states under which an identity link suppresses a tie. A
#: DISPUTED or REJECTED link is a recorded doubt (2026-09-24).
SUPPRESSING_REVIEW = frozenset({"ACCEPTED", "PROPOSED"})

FORUM_VENUES = ("FORUM", "CHANNEL")
CONTROL_TYPES = ("CONFIRMED_CONTROL_OF", "CONTROLS")


@dataclass(frozen=True)
class Family:
    key: str
    label: str
    venue_types: tuple[str, ...]
    affiliation_types: tuple[str, ...]


FAMILIES: dict[str, Family] = {
    "forum": Family("forum", "Forums and channels", FORUM_VENUES, ("POSTS_ON",)),
    "wallet": Family("wallet", "Wallets and transactions", ("WALLET", "TRANSACTION"),
                     ("CONFIRMED_CONTROL_OF", "CONTROLS", "PAID", "TX_INPUT",
                      "TX_OUTPUT")),
}

#: Lower is stronger. A derived tie takes the WEAKEST review of what it was
#: derived from, as an accepted element is never labelled above its source.
REVIEW_WEAKNESS = {"ACCEPTED": 0, "DISPUTED": 1, "PROPOSED": 2, "SUPERSEDED": 3,
                   "REJECTED": 4}
_UNKNOWN_WEAKNESS = 5
CONFIDENCE_RANK = {"LOW": 0, "MODERATE": 1, "HIGH": 2}

# Prose is kept OUT of the hashed coverage (`one_mode_block` adds it), so a
# copy edit never makes a stored run stale.
SIZE_NOTE = (
    "A venue's size here is what the case records: the entities posting on "
    "a forum or channel (or its recorded member count where that is larger), "
    "the controllers of a wallet, and the wallets into and out of a "
    "transaction. Every membership you can see counts toward a size, "
    "including those this view leaves out of the drawing. It is a lower "
    "bound, so every weight drawn from it is an upper bound.")
READING = (
    "Derived ties: these entities posted on the same forum or channel, "
    "controlled the same wallet, or money moved between wallets they are "
    "recorded as controlling. That is not the same as having been observed "
    "dealing with each other. Newman weighting divides each shared venue by "
    "its size so a large venue cannot manufacture a clique, but a weak tie "
    "from one large venue is still a weak tie.")
METHOD = "one_mode/{family}/{weighting}"

#: The derived families as they are keyed in the coverage and on each edge.
DERIVED_FAMILIES = ("forum", "wallet_control", "wallet_flow")


class OneModeError(Exception):
    """A one-mode parameter out of range (a 400 at the API)."""


class OneModeTooLarge(OneModeError):
    """The pre-count found more derived ties than the limit (a 422)."""

    def __init__(self, bound: int):
        self.bound = bound
        super().__init__(
            f"projecting these venues could draw up to {bound:,} derived ties, "
            f"over the limit of {MAX_DERIVED_TIES:,}. Lower the largest venue, "
            "project fewer families or narrow the view.")


class OneModeTooManyPeriods(OneModeTooLarge):
    """The pre-count found more dated-period comparisons than the limit (a
    422, answered like the derived-tie limit). Its own class so the message
    names the right cause: a view within the tie limit can still record
    each membership over hundreds of separate dated periods (verifier,
    2026-09-24)."""

    def __init__(self, steps: int):
        self.bound = steps
        OneModeError.__init__(
            self,
            f"checking which of these memberships were at the same time could "
            f"take up to {steps:,} comparisons of dated periods, over the limit "
            f"of {MAX_PERIOD_STEPS:,}. Lower the largest venue, project fewer "
            "families or narrow the view.")


@dataclass(frozen=True)
class OneModeParams:
    """Which families to project and how. Part of the projection's name and
    cache key whenever a family is listed; absent from both when none is,
    so every run stored before this existed keeps its name and digest."""

    families: tuple[str, ...] = ()
    weighting: str = WEIGHT_NEWMAN
    max_venue_size: int = DEFAULT_MAX_VENUE_SIZE
    min_shared: int = 1

    def __post_init__(self):
        # Normalised on construction: ('wallet',
        # 'forum', 'forum') and ('forum', 'wallet') are one question and
        # must name one projection row.
        object.__setattr__(self, "families", tuple(sorted(set(self.families))))

    def enabled(self) -> bool:
        return bool(self.families)

    def validate(self) -> None:
        for f in self.families:
            if f not in FAMILIES:
                raise OneModeError(
                    f"unknown family {f!r}; one of {', '.join(sorted(FAMILIES))}")
        if self.weighting not in (WEIGHT_COUNT, WEIGHT_NEWMAN):
            raise OneModeError(
                f"unknown weighting {self.weighting!r}; one of "
                f"{WEIGHT_COUNT}, {WEIGHT_NEWMAN}")
        lo, hi = MAX_VENUE_SIZE_RANGE
        if not isinstance(self.max_venue_size, int) or not lo <= self.max_venue_size <= hi:
            raise OneModeError(f"max_venue_size must be between {lo} and {hi}")
        lo, hi = MIN_SHARED_RANGE
        if not isinstance(self.min_shared, int) or not lo <= self.min_shared <= hi:
            raise OneModeError(f"min_shared must be between {lo} and {hi}")

    def describe(self) -> dict:
        return {"families": list(self.families), "weighting": self.weighting,
                "max_venue_size": self.max_venue_size,
                "min_shared": self.min_shared}


def material_edge_types(families) -> list[str]:
    """The edge types project() fetches beyond the preset when these
    families are projected: their affiliation types and the identity
    links. Empty when no family is listed, which matches nothing, so the
    rows are exactly today's."""
    fams = [FAMILIES[f] for f in families if f in FAMILIES]
    if not fams:
        return []
    out = set(IDENTITY_LINK_TYPES)
    for f in fams:
        out.update(f.affiliation_types)
    return sorted(out)


def venue_types(families) -> set[str]:
    out: set[str] = set()
    for f in families:
        if f in FAMILIES:
            out.update(FAMILIES[f].venue_types)
    return out


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------

def _kind(row: dict, types: dict, fams: set[str]) -> str | None:
    """What a row does in the transform: a forum membership, a wallet
    control, a transaction leg, a wallet payment, or None (not consumed)."""
    et = row["edge_type"]
    s, d = types.get(row["src_node_id"]), types.get(row["dst_node_id"])
    if "forum" in fams and et == "POSTS_ON" and d in FORUM_VENUES:
        return "forum"
    if "wallet" in fams:
        if et in CONTROL_TYPES and d == "WALLET":
            return "control"
        if et == "TX_INPUT" and s == "WALLET" and d == "TRANSACTION":
            return "tx_input"
        if et == "TX_OUTPUT" and s == "TRANSACTION" and d == "WALLET":
            return "tx_output"
        if et == "PAID" and "WALLET" in (s, d):
            return "paid"
    return None


def classify(nodes: list[dict], ties: list[dict], material: list[dict],
             params: OneModeParams) -> tuple[list[dict], list[dict], list[dict]]:
    """Split the fetched rows: (consumable, ties_out, identity_links).

    A consumable row is one the transform replaces with derived ties, and
    it leaves `ties` whether or not the preset had it (CONTROLS to a WALLET
    is in the Financial preset and is consumed). Every identity link, in
    the preset or fetched as material, goes to `identity_links`; one in the
    preset also stays a tie. Material that is neither is discarded WITHOUT
    counting: it was never a tie of this view (CONTROLS to a SELECTOR,
    fetched for the wallet family under the Trust preset).
    """
    types = {n["id"]: n["node_type"] for n in nodes}
    fams = set(params.families)
    consumable: list[dict] = []
    ties_out: list[dict] = []
    links: list[dict] = []
    for row in ties:
        if _kind(row, types, fams):
            consumable.append(row)
            continue
        if row["edge_type"] in IDENTITY_LINK_TYPES:
            links.append(row)
        ties_out.append(row)
    for row in material:
        if _kind(row, types, fams):
            consumable.append(row)
        elif row["edge_type"] in IDENTITY_LINK_TYPES:
            links.append(row)
    return consumable, ties_out, links


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

class _UnionFind:
    """Identity clusters. `same` is asked once per candidate pair, so a
    vertex no link touches is answered without being inserted."""

    def __init__(self):
        self._p: dict = {}

    def find(self, x):
        p = self._p
        if x not in p:
            return x
        root = x
        while p[root] != root:
            root = p[root]
        while p[x] != root:
            p[x], x = root, p[x]
        return root

    def union(self, a, b) -> None:
        self._p.setdefault(a, a)
        self._p.setdefault(b, b)
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Deterministic under any row order: the smaller id is the root.
            lo, hi = sorted((ra, rb), key=str)
            self._p[hi] = lo

    def same(self, a, b) -> bool:
        if not self._p or (a not in self._p and b not in self._p):
            return a == b
        return self.find(a) == self.find(b)


def _utc(t: datetime | None) -> datetime | None:
    if t is None:
        return None
    return t if t.tzinfo is not None else t.replace(tzinfo=timezone.utc)


def _interval(row: dict) -> tuple:
    return (_utc(row.get("valid_from")), _utc(row.get("valid_to")))


# Contemporaneity (F2, 2026-09-24). A constituent (one entity's membership
# of one venue, one wallet's leg of one transaction) may be recorded by
# several parallel rows, each dated: core.edge keeps one live row per
# (src, dst, type, valid_from), and ANY of them may make two members
# contemporaneous, not only the strongest. So a
# constituent's time is the UNION of its rows' closed intervals, None
# meaning unbounded on that side, merged once into a sorted tuple of
# disjoint periods, and two constituents meet where their unions overlap.
#
# An earlier version took one interval from each constituent in every
# combination, which grows as the PRODUCT of the parallel rows: a 4-leg
# flow with 200 dated rows a leg took 4.3 s for one derived tie (verifier,
# 2026-09-24). Merged periods meet in one linear pass, and the cost of
# every pass is bounded before any is made (`_period_steps`).

#: A constituent recorded as undated on both sides: it covers all time, so
#: meeting it changes nothing. The common case, answered without a pass.
_ALWAYS = ((None, None),)


def _periods(intervals) -> tuple:
    """The union of closed intervals as a sorted tuple of disjoint ones.
    Periods that overlap or touch are one period (closed intervals sharing
    an instant overlap). A row dated to end before it starts covers no
    time, as it did when intervals were intersected one by one."""
    ivs = [iv for iv in intervals
           if iv[0] is None or iv[1] is None or iv[0] <= iv[1]]
    if not ivs:
        return ()
    if (None, None) in ivs:
        return _ALWAYS
    # Undated starts first. Two undated starts compare equal on (False,
    # None), so None is never ordered against a datetime.
    ivs.sort(key=lambda iv: (iv[0] is not None, iv[0]))
    out: list[tuple] = [ivs[0]]
    for s, e in ivs[1:]:
        ps, pe = out[-1]
        if pe is None:
            break                       # the last period runs to the end of time
        if s is None or s <= pe:
            out[-1] = (ps, None if e is None else max(pe, e))
        else:
            out.append((s, e))
    return _ALWAYS if out == [(None, None)] else tuple(out)


def _overlap(a: tuple, b: tuple) -> tuple:
    """Where two unions of periods overlap, as a union again, in one pass
    of at most len(a) + len(b) steps."""
    if a is _ALWAYS:
        return b
    if b is _ALWAYS:
        return a
    out: list[tuple] = []
    i = j = 0
    while i < len(a) and j < len(b):
        s1, e1 = a[i]
        s2, e2 = b[j]
        s = s2 if s1 is None else s1 if s2 is None else max(s1, s2)
        e = e2 if e1 is None else e1 if e2 is None else min(e1, e2)
        if s is None or e is None or s <= e:
            out.append((s, e))
        # Step past whichever period ends first; it can meet nothing later.
        if e1 is None:
            j += 1
        elif e2 is None or e1 < e2:
            i += 1
        elif e2 < e1:
            j += 1
        else:
            i += 1
            j += 1
    return tuple(out)


def _last_overlap(a: tuple, b: tuple) -> tuple | None:
    """The latest period in which two unions overlap, or None when they
    never do, walking back from the end in at most len(a) + len(b) steps.

    A period of one that starts after a period of the other ends meets
    nothing left in the other, so it is dropped; the first pair that meets
    is the latest overlap, since every earlier period of either ends before
    the later one starts."""
    if a is _ALWAYS:
        return b[-1] if b else None
    if b is _ALWAYS:
        return a[-1] if a else None
    i, j = len(a) - 1, len(b) - 1
    while i >= 0 and j >= 0:
        s1, e1 = a[i]
        s2, e2 = b[j]
        if s1 is not None and e2 is not None and s1 > e2:
            i -= 1
        elif s2 is not None and e1 is not None and s2 > e1:
            j -= 1
        else:
            return (s2 if s1 is None else s1 if s2 is None else max(s1, s2),
                    e2 if e1 is None else e1 if e2 is None else min(e1, e2))
    return None


def _flow_steps(ins: list[tuple[int, int, int]], outs: list[tuple[int, int, int]]) -> int:
    """An upper bound on the merge steps of one transaction's attributed
    legs, by arithmetic in time linear in its wallets. Each side lists,
    per wallet with a controller, (T, A, S): the periods of its leg, its
    controller count and its controllers' periods.

    The transform merges, per leg (wi, wo), the two legs' periods X (at
    most T_i + T_o steps and periods), then per payer a of wi, X with a's
    (at most T_i + T_o + |a|), then per payee b of wo, that with b's (at
    most T_i + T_o + |a| + |b|). Summed over every wallet, payer and
    payee, that is the expression below."""
    n_i, n_o = len(ins), len(outs)
    t_i = sum(t for t, _, _ in ins)
    a_i = sum(a for _, a, _ in ins)
    s_i = sum(s for _, _, s in ins)
    at_i = sum(t * a for t, a, _ in ins)
    t_o = sum(t for t, _, _ in outs)
    b_o = sum(b for _, b, _ in outs)
    s_o = sum(s for _, _, s in outs)
    bt_o = sum(t * b for t, b, _ in outs)
    legs = t_i * n_o + n_i * t_o
    payers = at_i * n_o + a_i * t_o + s_i * n_o
    payees = at_i * b_o + a_i * bt_o + s_i * b_o + a_i * s_o
    return legs + payers + payees


def _strength(row: dict) -> tuple:
    """Sort key: the strongest row first (least review weakness, then the
    highest confidence, then evidenced, then id)."""
    return (REVIEW_WEAKNESS.get(row.get("review"), _UNKNOWN_WEAKNESS),
            -CONFIDENCE_RANK.get(row.get("confidence"), -1),
            not row.get("has_evidence"), str(row.get("id")))


def _best(rows: list[dict]) -> dict:
    return rows[0] if len(rows) == 1 else min(rows, key=_strength)


def _weakness(state) -> int:
    return REVIEW_WEAKNESS.get(state, _UNKNOWN_WEAKNESS)


def _confidence_rank(c) -> int:
    return CONFIDENCE_RANK.get(c, -1)


def _row_key(row: dict) -> tuple:
    return (str(row.get("id")), str(row["src_node_id"]), str(row["dst_node_id"]),
            str(row["edge_type"]))


def _member_count(node: dict) -> int | None:
    """An analyst-recorded member count, when it is a whole number of at
    least two. A string, a fraction or a bool is not a count."""
    value = (node.get("attrs") or {}).get("member_count")
    if isinstance(value, bool) or not isinstance(value, int) or value < 2:
        return None
    return value


class _Derived:
    """One derived tie being accumulated: the constituents it rests on and
    its weight so far."""

    __slots__ = ("family", "src", "dst", "directed", "weight", "rows", "spans", "venues")

    def __init__(self, family: str, src, dst, directed: bool):
        self.family, self.src, self.dst, self.directed = family, src, dst, directed
        self.weight = 0.0
        self.rows: list[dict] = []
        self.spans: list[tuple] = []
        self.venues: set = set()

    def edge(self) -> dict:
        review = max((r.get("review") for r in self.rows), key=_weakness)
        confidence = min((r.get("confidence") for r in self.rows), key=_confidence_rank)
        starts = [s[0] for s in self.spans]
        ends = [s[1] for s in self.spans]
        return {
            "id": None, "derived": True, "family": self.family,
            "edge_type": "ONE_MODE:" + self.family, "directed": self.directed,
            "src_node_id": self.src, "dst_node_id": self.dst,
            # No valence: a shared venue or a payment is not approval, so a
            # derived tie never enters signed degree, the positive-only
            # eigenvector or balance.
            "sign": 0, "weight": self.weight, "confidence": confidence,
            "is_inferred": True, "review": review,
            "has_evidence": all(bool(r.get("has_evidence")) for r in self.rows),
            # The span of what it rests on: undated on a side when any
            # constituent is.
            "valid_from": None if any(s is None for s in starts) else min(starts),
            "valid_to": None if any(e is None for e in ends) else max(ends),
        }


# --------------------------------------------------------------------------
# The transform
# --------------------------------------------------------------------------

def to_one_mode(nodes: list[dict], ties: list[dict], consumable: list[dict],
                identity_links: list[dict], params: OneModeParams, *,
                drawing: list[dict] | None = None,
                not_drawing: dict | None = None) -> tuple[list[dict], list[dict], dict]:
    """Replace the listed families' venues with derived ties between
    entities. Returns (nodes, edges, coverage); deterministic under any row
    order.

    `consumable` is every visible live consumable row and SIZES the venues;
    `drawing` (default: the same) is the subset that passed the confidence
    floor and the review scope and DRAWS the ties. `not_drawing` is the
    count of rows the caller left out of the drawing, by reason.
    """
    drawing = consumable if drawing is None else drawing
    by_id = {n["id"]: n for n in nodes}
    sid = {nid: str(nid) for nid in by_id}
    types = {nid: n["node_type"] for nid, n in by_id.items()}
    fams = set(params.families)
    removed_types = venue_types(fams)
    newman = params.weighting == WEIGHT_NEWMAN
    limit = params.max_venue_size

    # 1. Identity clusters. Only undoubted links suppress; any link at all
    #    marks a pair whose tie is kept although a link was once proposed.
    strong, anyone = _UnionFind(), _UnionFind()
    for row in sorted(identity_links, key=_row_key):
        a, b = row["src_node_id"], row["dst_node_id"]
        if a not in by_id or b not in by_id:
            continue
        anyone.union(a, b)
        if row.get("review") in SUPPRESSING_REVIEW:
            strong.union(a, b)

    # 2. Memberships: sizing from every consumable row, drawing from the
    #    rows that pass. venue -> actor -> [rows]; transaction -> wallet ->
    #    [rows]; payments listed.
    def gather(rows):
        members: dict = defaultdict(lambda: defaultdict(list))
        tx_in: dict = defaultdict(lambda: defaultdict(list))
        tx_out: dict = defaultdict(lambda: defaultdict(list))
        paid: list[dict] = []
        for row in sorted(rows, key=_row_key):
            s, d = row["src_node_id"], row["dst_node_id"]
            if s not in by_id or d not in by_id:
                continue
            kind = _kind(row, types, fams)
            if kind in ("forum", "control"):
                members[d][s].append(row)
            elif kind == "tx_input":
                tx_in[d][s].append(row)
            elif kind == "tx_output":
                tx_out[s][d].append(row)
            elif kind == "paid":
                paid.append(row)
        return members, tx_in, tx_out, paid

    s_members, s_in, s_out, _s_paid = gather(consumable)
    members, tx_in, tx_out, paid = gather(drawing)

    # 3. Sizes, from the sizing rows.
    def size_of(v) -> tuple[int, int, str]:
        t = types[v]
        if t == "TRANSACTION":
            n = len(s_in.get(v, ())) + len(s_out.get(v, ()))
            return n, n, "case_graph"
        visible = len(s_members.get(v, ()))
        if t in FORUM_VENUES:
            recorded = _member_count(by_id[v])
            if recorded is not None and recorded > visible:
                return recorded, visible, "recorded"
        return visible, visible, "case_graph"

    venues = sorted((nid for nid, t in types.items() if t in removed_types), key=str)
    sizes = {v: size_of(v) for v in venues}
    oversized = {v for v in venues if sizes[v][0] > limit}

    def ctrl(w) -> dict:
        return members.get(w, {})

    def ctrl_size(w) -> int:
        return len(s_members.get(w, ()))

    within = [v for v in venues if v not in oversized]
    co_venues = [v for v in within if types[v] in FORUM_VENUES or types[v] == "WALLET"]
    txs = [v for v in within if types[v] == "TRANSACTION"]

    # 4. The pre-count, by arithmetic over the drawing memberships and
    #    before min_shared pruning: an upper bound, linear in the rows.
    bound = 0
    for v in co_venues:
        k = len(members.get(v, ()))
        bound += k * (k - 1) // 2
    for t in txs:
        ins = sum(len(ctrl(w)) for w in tx_in.get(t, {}) if w not in oversized)
        outs = sum(len(ctrl(w)) for w in tx_out.get(t, {}) if w not in oversized)
        bound += ins * outs
    for row in paid:
        ends = []
        for end in (row["src_node_id"], row["dst_node_id"]):
            if types[end] == "WALLET":
                ends.append(0 if end in oversized else len(ctrl(end)))
            else:
                ends.append(1)
        bound += ends[0] * ends[1]
    if bound > MAX_DERIVED_TIES:
        raise OneModeTooLarge(bound)

    # 4b. Every constituent's dated periods and strongest row, once, not
    #     once per pair or leg; then the cost of every merge the transform
    #     will make, by arithmetic, before it makes any (verifier,
    #     2026-09-24: the tie limit bounds pairs, not the periods behind
    #     each).
    span_of: dict = {}          # venue or wallet -> entity -> periods
    best_of: dict = {}          # venue or wallet -> entity -> strongest row
    for v in co_venues:
        who = members.get(v, {})
        span_of[v] = {a: _periods([_interval(r) for r in rs]) for a, rs in who.items()}
        best_of[v] = {a: _best(rs) for a, rs in who.items()}

    def legs_of(side_rows: dict) -> tuple[dict, dict]:
        within_rows = {w: rs for w, rs in side_rows.items() if w not in oversized}
        return ({w: _periods([_interval(r) for r in rs]) for w, rs in within_rows.items()},
                {w: _best(rs) for w, rs in within_rows.items()})

    tx_legs = {t: (legs_of(tx_in.get(t, {})), legs_of(tx_out.get(t, {}))) for t in txs}

    # Once per venue: a wallet in many transactions is summed once.
    behind = {v: sum(len(p) for p in span_of[v].values()) for v in co_venues}
    steps = 0
    for v in co_venues:
        k = len(span_of[v])
        if k >= 2:
            steps += (k - 1) * behind[v]
    for t in txs:
        (in_span, _), (out_span, _) = tx_legs[t]
        steps += _flow_steps(
            [(len(in_span[w]), len(ctrl(w)), behind[w]) for w in in_span if ctrl(w)],
            [(len(out_span[w]), len(ctrl(w)), behind[w]) for w in out_span if ctrl(w)])
    for row in paid:
        ends = []
        for end in (row["src_node_id"], row["dst_node_id"]):
            if types[end] != "WALLET":
                ends.append((1, 0, False))
            elif end in oversized or not ctrl(end):
                break           # skipped before any merge (step 6)
            else:
                ends.append((len(ctrl(end)), behind[end], True))
        else:
            (n_a, s_a, wallet_a), (n_b, s_b, wallet_b) = ends
            # A payer side merges the row's one period with each payer's;
            # a payee side merges that with each payee's.
            steps += (n_a + s_a if wallet_a else 0)
            steps += (n_a * n_b + s_a * n_b + n_a * s_b) if wallet_b else 0
    if steps > MAX_PERIOD_STEPS:
        raise OneModeTooManyPeriods(steps)

    cov = {
        "families": sorted(fams), "weighting": params.weighting,
        "max_venue_size": limit, "min_shared": params.min_shared,
        "derived_upper_bound": bound,
        "pairs_same_identity": 0, "pairs_identity_disputed": 0,
        "pairs_not_contemporaneous": 0, "pairs_below_min_shared": 0,
        "flow_legs_not_contemporaneous": 0, "transactions_unattributed": 0,
        "transactions_partly_unattributed": 0, "self_transfers": 0,
        "flow_already_paid": 0, "flow_legs_through_oversized_wallets": 0,
        "paid_legs_unattributed": 0,
        "members_not_drawing": {"confidence": int((not_drawing or {}).get("confidence", 0)),
                                "review": int((not_drawing or {}).get("review", 0))},
    }
    derived: dict[tuple, _Derived] = {}

    # 5. Co-affiliation: one derived tie per (pair, venue).
    pair_venues: dict[str, dict] = {"forum": defaultdict(set),
                                    "wallet_control": defaultdict(set)}
    for v in co_venues:
        fam_key = "forum" if types[v] in FORUM_VENUES else "wallet_control"
        size = sizes[v][0]
        spans, best = span_of[v], best_of[v]
        actors = sorted(spans, key=sid.__getitem__)
        if len(actors) < 2:
            continue           # one member draws nothing (and size may be 1)
        weight = 1.0 / (size - 1) if newman else 1.0
        for i, a in enumerate(actors):
            for b in actors[i + 1:]:
                if strong.same(a, b):
                    cov["pairs_same_identity"] += 1
                    continue
                span = _last_overlap(spans[a], spans[b])
                if span is None:
                    cov["pairs_not_contemporaneous"] += 1
                    continue
                if anyone.same(a, b):
                    cov["pairs_identity_disputed"] += 1
                d = _Derived(fam_key, a, b, directed=False)
                d.weight = weight
                d.rows = [best[a], best[b]]
                d.spans = [span]
                d.venues = {v}
                derived[(fam_key, v, a, b)] = d
                pair_venues[fam_key][(a, b)].add(v)
    for fam_key, pv in pair_venues.items():
        for (a, b), vs in sorted(pv.items(), key=lambda kv: (sid[kv[0][0]], sid[kv[0][1]])):
            if len(vs) < params.min_shared:
                cov["pairs_below_min_shared"] += 1
                for v in vs:
                    derived.pop((fam_key, v, a, b), None)

    # 6. Flow, one hop: through a transaction, or a PAID row with a wallet
    #    at either end. PAID between two entities stays the actor-level
    #    summary (decision 22), so a direct PAID tie of this view either way
    #    between two entities suppresses their derived flow.
    paid_pairs = {frozenset((e["src_node_id"], e["dst_node_id"]))
                  for e in ties if e["edge_type"] == "PAID"}

    def add_flow(key, a, b, weight, rows, span, venue_set):
        d = derived.get(key)
        if d is None:
            d = derived[key] = _Derived("wallet_flow", a, b, directed=True)
        # COUNT counts each (transaction, payer, payee) once.
        d.weight = d.weight + weight if newman else 1.0
        d.rows.extend(rows)
        d.spans.append(span)
        d.venues |= venue_set

    def flow_pair(a, b, upto, last, rows, key, weight, venue_set) -> None:
        """One payer to one payee. `upto` is where every constituent but
        the payee's control overlaps, `last` the payee's periods (None for
        an entity end, which is itself and always there)."""
        if a == b or strong.same(a, b):
            cov["self_transfers"] += 1
            return
        span = (upto[-1] if upto else None) if last is None else _last_overlap(upto, last)
        if span is None:
            cov["flow_legs_not_contemporaneous"] += 1
            return
        if frozenset((a, b)) in paid_pairs:
            cov["flow_already_paid"] += 1
            return
        if anyone.same(a, b):
            cov["pairs_identity_disputed"] += 1
        add_flow(key, a, b, weight, rows, span, venue_set)

    # Every wallet's controllers in id order, once: a wallet in many
    # transactions is not sorted again for each.
    controllers_in_order = {v: sorted(span_of[v], key=str)
                            for v in co_venues if types[v] == "WALLET"}
    for t in txs:
        ins, outs = tx_in.get(t, {}), tx_out.get(t, {})
        i_ok = sorted((w for w in ins if w not in oversized), key=str)
        o_ok = sorted((w for w in outs if w not in oversized), key=str)
        i_over = len(ins) - len(i_ok)
        o_over = len(outs) - len(o_ok)
        # Counted as products, never enumerated leg by leg.
        cov["flow_legs_through_oversized_wallets"] += i_over * len(outs) + len(i_ok) * o_over
        i_attr = [w for w in i_ok if ctrl(w)]
        o_attr = [w for w in o_ok if ctrl(w)]
        total_ok, attributed = len(i_ok) * len(o_ok), len(i_attr) * len(o_attr)
        if total_ok and not attributed:
            cov["transactions_unattributed"] += 1
        elif attributed < total_ok:
            cov["transactions_partly_unattributed"] += 1
        denom_io = max(1, len(s_in.get(t, ())) * len(s_out.get(t, ())))
        (in_span, in_best), (out_span, out_best) = tx_legs[t]
        for wi in i_attr:
            payers = controllers_in_order[wi]
            for wo in o_attr:
                weight = 1.0 / (denom_io * max(1, ctrl_size(wi)) * max(1, ctrl_size(wo)))
                # The four constituents meet in the order `_flow_steps`
                # bounds: the two legs, then the payer's control, then the
                # payee's.
                legs = _overlap(in_span[wi], out_span[wo])
                for a in payers:
                    upto = _overlap(legs, span_of[wi][a])
                    for b in controllers_in_order[wo]:
                        flow_pair(a, b, upto, span_of[wo][b],
                                  [best_of[wi][a], in_best[wi], out_best[wo], best_of[wo][b]],
                                  ("tx", t, a, b), weight, {t, wi, wo})

    def side(end) -> tuple[dict, int]:
        # A wallet end pays or is paid through its controllers, each with
        # their periods and strongest row; an entity end is itself.
        if types[end] == "WALLET":
            return ({a: (span_of[end][a], best_of[end][a]) for a in ctrl(end)},
                    max(1, ctrl_size(end)))
        return {end: (None, None)}, 1

    for row in paid:
        s, d = row["src_node_id"], row["dst_node_id"]
        wallets = [w for w in (s, d) if types[w] == "WALLET"]
        if any(w in oversized for w in wallets):
            cov["flow_legs_through_oversized_wallets"] += 1
            continue
        if any(not ctrl(w) for w in wallets):
            cov["paid_legs_unattributed"] += 1
            continue

        payers, n_payers = side(s)
        payees, n_payees = side(d)
        weight = 1.0 / (n_payers * n_payees)
        paid_span = _periods([_interval(row)])
        payee_order = sorted(payees, key=str)
        for a in sorted(payers, key=str):
            span_a, best_a = payers[a]
            upto = paid_span if span_a is None else _overlap(paid_span, span_a)
            for b in payee_order:
                span_b, best_b = payees[b]
                rows = (([best_a] if best_a is not None else []) + [row]
                        + ([best_b] if best_b is not None else []))
                flow_pair(a, b, upto, span_b, rows, ("paid", str(row.get("id")), a, b),
                          weight, set(wallets))

    # 7. Removal: the venues leave the node set, with every tie of the view
    #    that touched one (counted by type) and every consumed row.
    removed = set(venues)
    dropped: dict[str, int] = defaultdict(int)
    edges_out: list[dict] = []
    for e in ties:
        if e["src_node_id"] in removed or e["dst_node_id"] in removed:
            dropped[e["edge_type"]] += 1
            continue
        edges_out.append(e)
    keep_nodes = [n for n in nodes if n["id"] not in removed]

    ordered = sorted(derived.values(),
                     key=lambda x: (x.family, sid[x.src], sid[x.dst],
                                    sorted(sid[v] for v in x.venues)))
    counts = dict.fromkeys(DERIVED_FAMILIES, 0)
    drew: set = set()
    for d in ordered:
        edges_out.append(d.edge())
        counts[d.family] += 1
        drew |= d.venues

    # 8. Coverage. Every removed venue is exactly one of: projected (drew a
    #    surviving derived tie, a flow counting for its transaction and for
    #    both wallets whose controllers it ties), oversized, or without ties.
    def by_type(ids) -> dict:
        out: dict[str, int] = defaultdict(int)
        for v in ids:
            out[types[v]] += 1
        return dict(sorted(out.items()))

    listed = sorted(oversized, key=lambda v: (-sizes[v][0], str(by_id[v].get("label") or ""),
                                              str(v)))
    cov.update({
        "venues_removed": by_type(removed),
        "venues_projected": by_type(v for v in removed if v in drew and v not in oversized),
        "venues_without_ties": by_type(v for v in removed
                                       if v not in drew and v not in oversized),
        "oversized_by_type": by_type(oversized),
        "oversized_total": len(oversized),
        "oversized": [
            {"node_id": str(v), "label": str(by_id[v].get("label") or ""),
             "node_type": types[v], "size": sizes[v][0], "visible_size": sizes[v][1],
             "size_basis": sizes[v][2]}
            for v in listed[:OVERSIZED_LISTED]],
        "derived_ties": counts,
        "edges_dropped_with_venues": dict(sorted(dropped.items())),
    })
    return keep_nodes, edges_out, cov


def is_derived(edge: dict) -> bool:
    return bool(edge.get("derived"))


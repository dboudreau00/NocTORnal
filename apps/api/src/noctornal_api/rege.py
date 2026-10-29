"""Regular equivalence by REGE: the Regular roles card.

CONCOR (`blockmodel.py`, decision 88) places entities with the same ties to the SAME others. Regular
equivalence (White and Reitz 1983) asks for the same KINDS of ties to the same KINDS of others, so two
launderers serving different crews are alike here though they share no contact at all.

The method is White's iterative REGE, in the form Borgatti and Everett (1993) describe and the classic `REGE`
of Ziberna's blockmodeling package implements:

    M0(i, j)   = 1 for every pair
    M+1(i, j)  = [ sum over k of max over m of M(k, m) Match(i, j, k, m)
                 + sum over k of max over m of M(k, m) Match(j, i, k, m) ]
                 / (all the tie value i and j send and receive)
    Match(i, j, k, m) = sum over relations of
                        min(x(i, k), x(j, m)) + min(x(k, i), x(m, j))

For each of i's ties (to or from k) the best counterpart among j's ties is found, weighted by how alike k and
that counterpart were the round before, and the same is done from j's side. The denominator is the most the
two could have matched; a pair with no tie value at all is alike, as in that implementation. The relations are
CONCOR's (positive, negative and ties with no valence, direction kept), so a vouch never matches an accusation
and a tie given never matches one received; the counterpart must match in every relation at once (Wasserman
and Faust's multi-relational form).

- **An approximation.** Three rounds (the UCINET default), stopping early once no similarity moves by more than
  REGE_TOLERANCE. The payload reports the rounds taken, whether they settled and the last change.
- **Sensitive to the weighting, by the analyst's choice.** `presence` counts each relation and direction
  between two entities as present or absent; `weight` sums the stored weights, so a weak tie only partly
  matches a strong one. Decay never moves a role. Under `weight` a tie with no positive weight counts as
  absent, and is counted; an entity left with no counted tie is alike every other such entity, and the payload
  counts those too.
- **Only actors hold roles.** A forum or wallet on a two-mode view takes part in the similarities but is not
  placed.
- **A deterministic cut.** Average linkage, the most alike pair joined first and a tie broken by vertex id
  order, cut to at most the roles asked for. Entities joined at the cut level are never split, so fewer roles
  than asked is an answer, and the payload says why.
- **Refused before it allocates.** At most REGE_MAX_NODES entities with ties, REGE_MAX_PAIRS tied pairs and
  REGE_MAX_TIES tie directions, counted from the tie list before any matrix exists. The service calls
  `precheck` before it writes a RUNNING row, so every refusal known without computing leaves no run behind.

A role is a hypothesis about how entities sit in this view, never an attribution: two entities in one role are
not one person (invariant 2), and nothing here proposes or writes anything.

A round compares every tie direction of i with every one of j for every pair, in chunks of numpy gathers and a
segmented maximum; the pair and direction caps hold the dearest view to the measured budget in
`REGE_MAX_PAIRS`'s comment. Importing `blockmodel` caps numpy's BLAS to one thread per process (decision 88);
the rounds here are elementwise and call no BLAS.

Pure and database-free, like `blockmodel.py`. Every value in the payload is a Python scalar rounded through
`analytics._clean`, so NaN never reaches jsonb.
"""
from __future__ import annotations

import math

import numpy
from noctornal_ontology.definition import NODE_TYPES

# Imported for the BLAS cap its import takes (decision 88) as well as for the relations and the direction rule,
# so the two role cards share one reading of a tie.
from noctornal_api import blockmodel
from noctornal_api.analytics import (
    AnalyticsError,
    AnalyticsParams,
    _clean,
    one_mode_block,
    review_scope_block,
)
from noctornal_api.projections import Projection, Subgraph

REGE_MAX_NODES = 1000
#: Tied pairs, counted once however many ties join a pair, and tie directions (REGE_MAX_TIES): the distinct
#: cells the relation matrices hold, one for each kind of tie (positive, negative, other) running from one
#: entity to another. A tie with no direction fills two cells; ties repeating a cell fill it once; counted by
#: weight a tie with no positive weight fills none, as `build_values` has it. The cost grows with BOTH numbers:
#: the pairs set how many patterns and counterparts there can be, and the directions how many features each
#: comparison reads, so a cap on pairs alone left views of one size far apart.
#:
#: Directions are counted, not the ties behind them, because parallel ties collapse into one cell (a sum under
#: `weight`, 1 under presence) before any round runs. Counting rows would refuse cheap views: a one-mode view
#: has one derived tie per pair and venue, so 40 entities all posting on 15 forums is 11,700 derived ties. The
#: work before the matrices is linear in the rows, about 6 microseconds each.
#:
#: Calibrated on the dearest views the two caps admit. Whole call, CPU seconds, best of three, 1,000 entities,
#: three full rounds, counted by weight with every tie's weight its own: one relation tied both ways on 2,500
#: pairs 2.1 s; two relations in random directions on 2,100 pairs (5,000 directions) 2.1; three, each tie in
#: one direction, on 1,700 pairs 1.7; three tied both ways on 833 pairs 0.9. Counted as present, 0.3 to 1.5.
#: Peak memory 70 to 145 MB.
REGE_MAX_PAIRS = 2500
REGE_MAX_TIES = 5000
REGE_MIN_ROLES = 2
REGE_DEFAULT_ROLES = 4
REGE_MAX_ROLES = 8
#: UCINET's and the blockmodeling package's default. Each round looks one
#: step further out; more rounds change the answer, which the card says.
REGE_ITERATIONS = 3
REGE_TOLERANCE = 1e-6
#: Two levels this close are one level for the cut: the same similarity
#: reached through a different order of floating-point sums.
LEVEL_EPS = 1e-9
WEIGHT_PRESENCE = "presence"
WEIGHT_VALUE = "weight"
WEIGHTINGS = (WEIGHT_PRESENCE, WEIGHT_VALUE)
DEFAULT_WEIGHTING = WEIGHT_PRESENCE
#: Elements per chunk of a round's comparison, about 4 MB of float64. A chunk is live several times over (the
#: rows copied, the kernel, the match), so this sets the peak: 4 MB chunks peak near 160 MB on the dearest view,
#: 16 MB chunks near 200 MB at the same speed.
CHUNK_ELEMENTS = 1 << 19
#: Above this many distinct tie patterns the kernel is computed per chunk
#: rather than looked up in a table (a weighted view can have one pattern
#: per tied pair, and the table is the square of the patterns).
PATTERN_TABLE_MAX = 256

METHOD = (
    "REGE (White's iterative procedure, as Borgatti and Everett describe it): "
    "two entities are alike when, for each tie one has, the other has a tie "
    "of the same kind and direction to an entity that is itself alike. "
    "Every pair starts alike, and each round compares neighbourhoods one "
    "step further out. Positive, negative and other ties are compared "
    "separately. Roles are cut from the similarities by average linkage, "
    "the most alike joined first.")
READING = (
    "Entities in the same role have the same kinds of ties to the same kinds "
    "of others; unlike positions, they need not share a single contact. A "
    "role is a hypothesis about how entities sit in this view, never an "
    "attribution: two entities in one role are not one person, and the "
    "role does not say who is behind either.")

_ACTOR = frozenset(n.key for n in NODE_TYPES if n.category == "ACTOR")


# --------------------------------------------------------------------------
# Refusals and parameters
# --------------------------------------------------------------------------

def _relation_key(e: dict) -> str:
    sign = int(e["sign"])
    return "positive" if sign > 0 else ("negative" if sign < 0 else "neutral")


def _usable(sub: Subgraph, weighting: str = DEFAULT_WEIGHTING
            ) -> tuple[set, list[dict], int, int]:
    """Vertices with a tie to another vertex of the view, those ties, the number of distinct tied pairs, and the
    number of tie directions, from the tie list alone.

    A direction is one cell the relation matrices will hold: a kind of tie running from one entity to another.
    A tie with no direction runs both ways and fills two; ties repeating a cell (parallel ties, one derived tie
    per shared venue, time-sliced edges) fill it once; and counted by weight a tie with no positive weight
    fills none, because `build_values` leaves it out."""
    ids = {n["id"] for n in sub.nodes}
    tied: set = set()
    usable: list[dict] = []
    pairs: set = set()
    cells: set = set()
    by_weight = weighting == WEIGHT_VALUE
    for e in sub.edges:
        a, b = e["src_node_id"], e["dst_node_id"]
        if a == b or a not in ids or b not in ids:
            continue
        tied.update((a, b))
        usable.append(e)
        pairs.add(frozenset((a, b)))
        if by_weight and _positive_weight(e) is None:
            continue
        key = _relation_key(e)
        cells.add((key, a, b))
        if not blockmodel.is_directed(e):
            cells.add((key, b, a))
    return tied, usable, len(pairs), len(cells)


def check_params(*, roles: int, weighting: str) -> None:
    if not isinstance(roles, int) or isinstance(roles, bool) \
            or not REGE_MIN_ROLES <= roles <= REGE_MAX_ROLES:
        raise AnalyticsError(
            f"the number of roles must be between {REGE_MIN_ROLES} and {REGE_MAX_ROLES}")
    if weighting not in WEIGHTINGS:
        raise AnalyticsError(
            f"ties are counted by presence or by weight, not {weighting!r}")


def precheck(sub: Subgraph, *, roles: int = REGE_DEFAULT_ROLES,
             weighting: str = DEFAULT_WEIGHTING) -> None:
    """The refusals that need no matrix, taken first: the parameters, either
    cap, or fewer than two entities with ties. The service calls this before
    it records a run."""
    check_params(roles=roles, weighting=weighting)
    tied, usable_ties, pairs, directions = _usable(sub, weighting)
    if len(tied) > REGE_MAX_NODES:
        raise AnalyticsError(
            f"regular equivalence is capped at {REGE_MAX_NODES} entities with ties; "
            f"this view has {len(tied)}. Narrow the view first.")
    if pairs > REGE_MAX_PAIRS:
        raise AnalyticsError(
            f"regular equivalence is capped at {REGE_MAX_PAIRS} tied pairs; "
            f"this view has {pairs}. Narrow the view first.")
    if directions > REGE_MAX_TIES:
        # The figure the analyst can check is the view's own tie count, which the card and the pane show, so it
        # is named beside the directions they make.
        raise AnalyticsError(
            f"regular equivalence is capped at {REGE_MAX_TIES} tie directions (a tie "
            "with no direction runs both ways, and ties of one kind repeating one "
            f"direction between two entities count once); this view has {directions}, "
            f"from {len(usable_ties)} ties. Narrow the view first.")
    types = {n["id"]: n["node_type"] for n in sub.nodes}
    if sum(1 for v in tied if types.get(v) in _ACTOR) < 2:
        raise AnalyticsError(
            "regular equivalence needs at least two entities with ties in this view")
    # Counted by weight with no positive weight anywhere, every pair would have nothing to match and be called
    # alike (the zero-denominator rule): one role that says nothing, so it is refused.
    if weighting == WEIGHT_VALUE and not any(_positive_weight(e) for e in usable_ties):
        raise AnalyticsError(
            "no tie in this view carries a positive weight; count ties as present "
            "or absent instead")


# --------------------------------------------------------------------------
# Tie values
# --------------------------------------------------------------------------

def _positive_weight(e: dict) -> float | None:
    try:
        w = float(e.get("weight"))
    except (TypeError, ValueError):
        return None
    return w if math.isfinite(w) and w > 0 else None


def build_values(sub: Subgraph, weighting: str = DEFAULT_WEIGHTING):
    """(vertices, relations, weightless, usable): vertices sorted by id, one
    n x n matrix per valence present with X[i, j] the value of the ties from
    i to j (both ways for an undirected tie), how many ties carried no
    positive weight under `weight`, and the ties used. Refused before any
    matrix exists.

    Under `weight` each cell is an exact sum (`math.fsum`), so the answer
    cannot depend on the order the ties arrive in."""
    precheck(sub, weighting=weighting)
    tied, usable, _pairs, _directions = _usable(sub, weighting)
    verts = sorted(tied, key=str)
    index = {v: i for i, v in enumerate(verts)}
    n = len(verts)
    counts: dict[str, int] = {}
    cells: dict[str, dict[tuple[int, int], list[float]]] = {}
    weightless = 0
    for e in usable:
        key = _relation_key(e)
        counts[key] = counts.get(key, 0) + 1
        cell = cells.setdefault(key, {})
        if weighting == WEIGHT_VALUE:
            value = _positive_weight(e)
            if value is None:
                weightless += 1
                continue
        else:
            value = 1.0
        i, j = index[e["src_node_id"]], index[e["dst_node_id"]]
        ends = [(i, j)] if blockmodel.is_directed(e) else [(i, j), (j, i)]
        for at in ends:
            cell.setdefault(at, []).append(value)
    rels = []
    for key, label, _sign in blockmodel.RELATIONS:
        if key not in counts:
            continue
        mat = numpy.zeros((n, n))
        for (i, j), values in cells[key].items():
            mat[i, j] = math.fsum(values) if weighting == WEIGHT_VALUE else 1.0
        numpy.fill_diagonal(mat, 0.0)
        rels.append((key, label, mat, counts[key]))
    return verts, rels, weightless, usable


# --------------------------------------------------------------------------
# REGE
# --------------------------------------------------------------------------

def _kernel_table(patterns: numpy.ndarray) -> numpy.ndarray:
    """Match between every two tie patterns: the sum over features of the
    smaller value."""
    q = patterns.shape[0]
    table = numpy.zeros((q, q))
    for c in range(patterns.shape[1]):
        table += numpy.minimum(patterns[:, c][:, None], patterns[:, c][None, :])
    return table


class _Plan:
    """What every round compares, worked out once.

    The ordered tied pairs (u, v) carry a feature vector: per relation, the value u sends to v and the value v
    sends to u. Three refinements keep a round near the measured budget without changing a single number:

    - **The left side is deduplicated.** i's tie to k enters G only through k and the tie's pattern, so the
      best counterpart is found once for each distinct (k, pattern) and summed into every i that has it.
    - **Only overlapping ties are compared.** Match is the sum, over the features a tie has, of the smaller
      value, so a tie of one relation and direction matches nothing of another. Each left pattern is compared
      only with the ties sharing one of its features, and only over those features. A pair left out would
      score 0, and every score is at least 0, so the best counterpart is unchanged.
    - **Only the rows of M a group reads are taken.** A group's left ties name some of the entities as k, and
      only their rows of M meet the counterparts; taking all n rows for each of up to 63 groups would dominate
      a round."""

    def __init__(self, mats: list[numpy.ndarray]):
        n = mats[0].shape[0]
        self.n = n
        union = numpy.zeros((n, n), dtype=bool)
        for x in mats:
            union |= (x > 0) | (x.T > 0)
        # Row-major, so sorted by u: each vertex's ties are one run.
        self.us, self.vs = numpy.nonzero(union)
        self.groups: list[tuple] = []
        if not len(self.us):
            return
        feat = numpy.stack([col for x in mats for col in (x[self.us, self.vs],
                                                          x[self.vs, self.us])], axis=1)
        patterns, pat = numpy.unique(feat, axis=0, return_inverse=True)
        pat = numpy.asarray(pat).ravel()
        q = len(patterns)
        table = _kernel_table(patterns) if q <= PATTERN_TABLE_MAX else None
        keys, self.key_of = numpy.unique(self.vs.astype(numpy.int64) * q + pat,
                                         return_inverse=True)
        self.key_of = numpy.asarray(self.key_of).ravel()
        self.key_count = len(keys)
        key_k, key_p = keys // q, keys % q
        support = patterns > 0
        bits = (support * (1 << numpy.arange(feat.shape[1]))).sum(axis=1)
        for mask in numpy.unique(bits):
            mine = numpy.nonzero(bits == mask)[0]
            left = numpy.nonzero(bits[key_p] == mask)[0]
            cols = numpy.nonzero(support[mine[0]])[0]
            right = numpy.nonzero(support[pat][:, cols].any(axis=1))[0]
            has, starts = numpy.unique(self.us[right], return_index=True)
            if table is not None:
                # Only this mask's own patterns as rows, so the slices of
                # every mask together hold one table's width of rows.
                local = numpy.searchsorted(mine, key_p[left])
                kernel_r, kp = table[mine][:, pat[right]], local
            else:
                kernel_r, kp = feat[right][:, cols], key_p[left]
            # The rows of M this group reads are the distinct k of its left keys, not all n: taking every row
            # for each of up to 63 masks dominated a round on a view with several relations in random
            # directions.
            need, row_of = numpy.unique(key_k[left], return_inverse=True)
            self.groups.append((left, need, numpy.asarray(row_of).ravel(), kp,
                                self.vs[right], has, starts, cols, kernel_r,
                                table is not None, patterns))

    def best_matches(self, m: numpy.ndarray) -> numpy.ndarray:
        """G[i, j] = sum over i's ties (i, k) of the best M(k, m) Match over
        j's ties (j, m): one half of REGE's numerator for every ordered
        pair. The best counterpart is a segmented maximum over j's run."""
        n = self.n
        g = numpy.zeros((n, n))
        if not len(self.us):
            return g
        h = numpy.zeros((self.key_count, n))
        for (left, need, row_of, kp, right_v, has, starts, cols, kernel_r, tabled,
             patterns) in self.groups:
            # M(k, m) for the k this group reads against its counterparts,
            # taken once per round along M's rows (each row stays in cache),
            # so every chunk then copies whole rows instead of gathering.
            by_k = numpy.take(numpy.take(m, need, axis=0), right_v, axis=1)
            chunk = max(1, CHUNK_ELEMENTS // max(len(right_v), 1))
            for lo in range(0, len(left), chunk):
                hi = min(len(left), lo + chunk)
                w = by_k[row_of[lo:hi]]
                if tabled:
                    w *= kernel_r[kp[lo:hi]]
                else:
                    match = numpy.minimum(patterns[kp[lo:hi], cols[0]][:, None],
                                          kernel_r[:, 0][None, :])
                    for at in range(1, len(cols)):
                        match += numpy.minimum(patterns[kp[lo:hi], cols[at]][:, None],
                                               kernel_r[:, at][None, :])
                    w *= match
                h[numpy.ix_(left[lo:hi], has)] = numpy.maximum.reduceat(w, starts, axis=1)
        total = len(self.us)
        chunk = max(1, CHUNK_ELEMENTS // n)
        for lo in range(0, total, chunk):
            hi = min(total, lo + chunk)
            rows, first = numpy.unique(self.us[lo:hi], return_index=True)
            g[rows] += numpy.add.reduceat(h[self.key_of[lo:hi]], first, axis=0)
        return g


def rege_matrix(mats: list[numpy.ndarray], *, iterations: int | None = None,
                tolerance: float | None = None):
    """REGE over the relations' value matrices: (M, rounds, converged,
    last_change), M symmetric with a unit diagonal and every entry in
    [0, 1]. The rounds and the tolerance default to the module's, read
    when called."""
    iterations = REGE_ITERATIONS if iterations is None else iterations
    tolerance = REGE_TOLERANCE if tolerance is None else tolerance
    n = mats[0].shape[0]
    plan = _Plan(mats)
    strength = sum(x.sum(axis=1) + x.sum(axis=0) for x in mats)
    den = strength[:, None] + strength[None, :]
    has_den = den > 0
    safe = numpy.where(has_den, den, 1.0)
    m = numpy.ones((n, n))
    rounds, change, converged = 0, 0.0, False
    while rounds < iterations:
        g = plan.best_matches(m)
        new = numpy.where(has_den, (g + g.T) / safe, 1.0)
        numpy.minimum(new, 1.0, out=new)
        numpy.fill_diagonal(new, 1.0)
        change = float(numpy.abs(new - m).max()) if n else 0.0
        m = new
        rounds += 1
        if change <= tolerance:
            converged = True
            break
    return m, rounds, converged, change


# --------------------------------------------------------------------------
# The cut
# --------------------------------------------------------------------------

def average_linkage(sim: numpy.ndarray) -> list[tuple[int, int, float]]:
    """Agglomerative clustering by average linkage over a similarity
    matrix: every merge as (kept, joined, level), most alike first.

    The pair joined is the most alike; among equals, the one whose lower
    index is smallest, then whose other index is. A cluster keeps the
    smallest index of its members, so the order is fixed by the vertices'
    order alone. Each row's best partner is cached and refreshed only where
    a merge touched it, so a merge costs a row, not the whole matrix."""
    k = sim.shape[0]
    if k < 2:
        return []
    s = numpy.array(sim, dtype=float)
    numpy.fill_diagonal(s, -numpy.inf)
    size = numpy.ones(k)
    alive = numpy.ones(k, dtype=bool)
    best = s.max(axis=1)
    arg = s.argmax(axis=1)
    merges: list[tuple[int, int, float]] = []
    for _ in range(k - 1):
        cand = numpy.where(alive, best, -numpy.inf)
        a = int(cand.argmax())
        b = int(arg[a])
        merges.append((a, b, float(cand[a])))
        na, nb = size[a], size[b]
        row = (na * s[a] + nb * s[b]) / (na + nb)
        s[a, :] = row
        s[:, a] = row
        s[b, :] = -numpy.inf
        s[:, b] = -numpy.inf
        s[a, a] = -numpy.inf
        alive[b] = False
        size[a] = na + nb
        best[b] = -numpy.inf
        col = s[:, a]
        # A row whose partner was `a` keeps it while the merged value still equals its best (a is still the
        # first column reaching it); a row whose partner was `b` has lost it. Only those are searched again, in
        # one call: with every similarity equal every row points at the pair just merged, and searching each in
        # a loop would make the cut cubic.
        stale = alive & ((arg == b) | ((arg == a) & (col < best)))
        stale[a] = True
        rows = numpy.nonzero(stale)[0]
        best[rows] = s[rows].max(axis=1)
        arg[rows] = s[rows].argmax(axis=1)
        better = alive & ~stale & ((col > best) | ((col == best) & (a < arg)))
        best[better] = col[better]
        arg[better] = a
    return merges


def cut_point(merges: list[tuple[int, int, float]], k: int, roles: int) -> int:
    """How many of the merges to keep for at most `roles` roles among `k`
    entities. Perfectly alike entities are always joined, and a cut never
    falls between two merges at one level, so the answer can be fewer roles
    than asked, never more."""
    alike = 0
    while alike < len(merges) and merges[alike][2] >= 1.0 - LEVEL_EPS:
        alike += 1
    keep = min(len(merges), max(k - roles, alike, 0))
    while 0 < keep < len(merges) and merges[keep][2] >= merges[keep - 1][2] - LEVEL_EPS:
        keep += 1
    return keep


def groups(merges: list[tuple[int, int, float]], k: int, keep: int) -> list[list[int]]:
    members = {i: [i] for i in range(k)}
    for a, b, _level in merges[:keep]:
        members[a].extend(members.pop(b))
    return [sorted(v) for v in members.values()]


# --------------------------------------------------------------------------
# The payload
# --------------------------------------------------------------------------

def _rounds(n: int) -> str:
    return f"{n} {'round' if n == 1 else 'rounds'}"


def _limits(weighting: str, rounds: int, converged: bool, change: float,
            weightless_entities: int = 0) -> list[str]:
    if converged:
        first = (f"REGE is an iterative approximation. Its similarities settled within "
                 f"{_rounds(rounds)}, so more rounds would not move them.")
    else:
        first = (f"REGE is an approximation: it stopped after {_rounds(rounds)}, comparing "
                 f"neighbourhoods {rounds} {'step' if rounds == 1 else 'steps'} out, while "
                 f"similarities were still moving by up to {change:.3f}. More rounds look "
                 "further and can separate more entities.")
    out = [first]
    if weighting == WEIGHT_VALUE:
        out.append("Ties count by weight, so a weak tie only partly matches a strong "
                   "one: REGE is sensitive to how ties are weighted, and the roles can "
                   "change with the weighting.")
        # An entity whose every tie carries no positive weight has nothing to match, and a pair with nothing to
        # match is alike, so they are cut into one role of perfect cohesion.
        if weightless_entities == 1:
            out.append("1 entity has ties but none that count by weight, so it has nothing "
                       "to match: the role it falls in says nothing about how it sits in "
                       "this view.")
        elif weightless_entities > 1:
            out.append(f"{weightless_entities} entities have ties but none that count by "
                       "weight. With nothing to match, they are all called alike and share "
                       "one role: that says nothing about how they sit in this view.")
    else:
        out.append("Ties count as present or absent. REGE is sensitive to how ties are "
                   "weighted: counted by weight, a weak tie only partly matches a strong "
                   "one, and the roles can change.")
    # A tie is not compared when the view filters it, when it is inferred and the view does not opt in, or when
    # it is above the reader's clearance or compartments.
    out.append("Only the ties this view admits are compared: a tie the view leaves out "
               "(by type, confidence, date or review state, or because it is inferred), "
               "or one above your clearance or compartments, shapes no role.")
    out.append("On ties of one kind with no direction, regular equivalence finds nearly "
               "every entity alike: read the direction and valence of the ties before "
               "the roles.")
    # The cut is fixed for a graph but not by its structure alone: among equally good cuts the entities' order
    # decides, and that order is their identifiers'.
    out.append("Where several cuts are equally good, or differ only in the last decimal "
               "places of a similarity, the one kept depends on the order of the "
               "entities' internal identifiers, not on the structure. The same graph "
               "always gives the same roles; the same structure under other identifiers "
               "can be cut differently there.")
    out.append("A role is a hypothesis, never an attribution.")
    return out


def rege(sub: Subgraph, p: Projection, params: AnalyticsParams, *,
         roles: int = REGE_DEFAULT_ROLES, weighting: str = DEFAULT_WEIGHTING) -> dict:
    """Regular roles over one projected subgraph, in the payload the API
    serves and the service stores."""
    check_params(roles=roles, weighting=weighting)
    verts, rels, weightless, usable = build_values(sub, weighting)
    by_id = {n["id"]: n for n in sub.nodes}
    sim, rounds, converged, change = rege_matrix([r[2] for r in rels])

    actors = [i for i, v in enumerate(verts) if by_id[v]["node_type"] in _ACTOR]
    tied = set(verts)
    no_ties = sum(1 for nd in sub.nodes
                  if nd["node_type"] in _ACTOR and nd["id"] not in tied)
    profile_types = sorted({by_id[v]["node_type"] for v in verts
                            if by_id[v]["node_type"] not in _ACTOR})

    k = len(actors)
    # Entities whose ties all carry no positive weight, counted by weight: nothing to match, so every pair of
    # them is alike (the zero-denominator rule) and they come out as one role of cohesion 1. Only possible by
    # weight; by presence every tie counts.
    weightless_entities = 0
    if weighting == WEIGHT_VALUE:
        held = sum(x.sum(axis=1) + x.sum(axis=0) for _key, _label, x, _count in rels)
        weightless_entities = int(sum(1 for i in actors if held[i] <= 0))
    asim = sim[numpy.ix_(actors, actors)]
    merges = average_linkage(asim)
    keep = cut_point(merges, k, roles)

    def sort_key(i: int) -> tuple[str, str]:
        v = verts[actors[i]]
        return (str(by_id[v].get("label") or "").lower(), str(v))

    blocks = [sorted(g, key=sort_key) for g in groups(merges, k, keep)]
    blocks.sort(key=lambda g: (-len(g), sort_key(g[0])))

    def who(i: int) -> dict:
        v = verts[actors[i]]
        nd = by_id[v]
        return {"id": str(v), "label": nd.get("label"), "node_type": nd["node_type"]}

    def mean_between(gx: list[int], gy: list[int], same: bool) -> float | None:
        """The mean similarity between two roles, or within one (its
        members' pairs, so None for a role of one)."""
        cells = asim[numpy.ix_(gx, gy)]
        if same:
            if len(gx) < 2:
                return None
            return _clean(float(cells[~numpy.eye(len(gx), dtype=bool)].mean()))
        return _clean(float(cells.mean()))

    out_roles, node_rows = [], []
    for index, g in enumerate(blocks):
        least = None
        if len(g) > 1:
            cells = asim[numpy.ix_(g, g)]
            least = _clean(float(cells[~numpy.eye(len(g), dtype=bool)].min()))
        out_roles.append({"role": index + 1, "block_index": index, "size": len(g),
                          "members": [who(i) for i in g],
                          "cohesion": mean_between(g, g, True), "least_alike": least})
        # Each member's mean similarity to the others in its role: the row
        # sums less its own unit diagonal, over the others.
        fits = ((asim[numpy.ix_(g, g)].sum(axis=1) - 1.0) / (len(g) - 1)
                if len(g) > 1 else [None])
        for at, i in enumerate(g):
            fit = _clean(float(fits[at])) if len(g) > 1 else None
            node_rows.append({**who(i), "role": index + 1, "block_index": index,
                              "fit": fit})
    similarity = [[mean_between(gx, gy, x == y) for y, gy in enumerate(blocks)]
                  for x, gx in enumerate(blocks)]

    # Role to role, per relation: density as CONCOR's image counts it, ties
    # present or absent whatever the weighting, and whether the block is
    # regular (every member of the row role sends such a tie into the column
    # role and every member of the column role receives one), the pattern
    # regular equivalence looks for.
    density: dict[str, list] = {}
    image: dict[str, list] = {}
    regular: dict[str, list] = {}
    alpha: dict[str, float | None] = {}
    for key, _label, mat, _count in rels:
        ra = mat[numpy.ix_(actors, actors)] > 0
        possible = k * (k - 1)
        a = float(ra.sum()) / possible if possible else None
        alpha[key] = _clean(a) if a is not None else None
        drows, irows, rrows = [], [], []
        for x, gx in enumerate(blocks):
            drow, irow, rrow = [], [], []
            for y, gy in enumerate(blocks):
                cells = ra[numpy.ix_(gx, gy)]
                if x == y:
                    cells = cells & ~numpy.eye(len(gx), dtype=bool)
                    poss = len(gx) * (len(gx) - 1)
                else:
                    poss = len(gx) * len(gy)
                d = float(cells.sum()) / poss if poss else None
                drow.append(_clean(d) if d is not None else None)
                irow.append(1 if (d is not None and d > 0 and a is not None and d >= a)
                            else 0)
                rrow.append(1 if (poss and bool(cells.any(axis=1).all())
                                  and bool(cells.any(axis=0).all())) else 0)
            drows.append(drow)
            irows.append(irow)
            rrows.append(rrow)
        density[key] = drows
        image[key] = irows
        regular[key] = rrows

    held_at = merges[keep - 1][2] if keep > 0 else None
    next_merge = merges[keep][2] if keep < len(merges) else None
    return {
        "projection": p.describe(),
        "params": params.describe(),
        "engine": "numpy " + numpy.__version__,
        "node_count": len(sub.nodes),
        "edge_count": len(sub.edges),
        "truncated": bool(sub.truncated),
        "truncation_note": (
            "the node set was cut off at the projection limit: roles below are "
            "computed over a PARTIAL graph and may move once the omitted "
            "entities are in") if sub.truncated else None,
        # The run service stores the TOP-LEVEL flag on the run row and in its audit event, so it is set here as
        # well as inside `rege`.
        "is_approximate": True,
        "review_scope": review_scope_block(p, sub),
        "one_mode": one_mode_block(sub),
        "rege": {
            "roles_asked": roles,
            "roles_found": len(blocks),
            "weighting": weighting,
            "relations": [{"key": key, "label": label, "ties": int(count)}
                          for key, label, _m, count in rels],
            "roles": out_roles,
            "cut": {"held_at": _clean(held_at) if held_at is not None else None,
                    "next_merge": _clean(next_merge) if next_merge is not None else None,
                    "fewer_than_asked": len(blocks) < min(roles, k)},
            "similarity": similarity,
            "rounds": int(rounds),
            "max_rounds": REGE_ITERATIONS,
            "converged": bool(converged),
            "last_change": _clean(change),
            "tolerance": REGE_TOLERANCE,
            "density": density,
            "image": image,
            "regular": regular,
            "alpha": alpha,
            "no_ties": {"count": int(no_ties)},
            "profile_only": {"count": int(len(verts) - k), "types": profile_types},
            "derived_ties": any(e.get("derived") for e in usable),
            "weightless_ties": int(weightless),
            "weightless_entities": weightless_entities,
            "unaccepted_ties": sum(1 for e in usable if e.get("review") != "ACCEPTED"),
            "is_approximate": True,
            "method": METHOD,
            "reading": READING,
            "limits": _limits(weighting, rounds, converged, change, weightless_entities),
        },
        "nodes": node_rows,
    }

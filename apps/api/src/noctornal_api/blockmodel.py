"""CONCOR structural-equivalence blockmodelling: the Roles card (F1,
2026-09-24).

docs/03 lists CONCOR and blockmodelling for "the second money launderer,
the replacement developer": entities in the same POSITION have the same
pattern of ties to the same others, whether or not they are tied to each
other. Centrality asks who is important; this asks who is
interchangeable, which is the question a takedown that leaves the role
filled has failed to ask.

The method (Breiger, Boorman and Arabie 1975). Each entity's profile is its
ties sent and received, one relation per valence (positive, negative, and
ties with no valence), direction kept. The profiles are correlated pairwise,
LEAVING OUT the entries that describe the pair themselves (Wasserman and
Faust's correction: otherwise a tie between two entities makes them less
alike, since each sees the other and not itself). That matrix is correlated
again and again until every entry settles at plus or minus one, and the
entities are split on its sign. Each half is split the same way, to the
depth asked for.

Four rules shape it:

- **Only actors hold positions.** A forum or wallet on a two-mode view stays
  a column of every profile, so it shapes who is alike, but it is not
  partitioned. The card counts those vertices so none disappears silently.
- **Ties are present or absent.** Weights and decay do not move positions,
  and with venues projected (F2) a derived tie counts as a whole tie; the
  payload says so, because a pair that once shared a 40-member forum then
  counts like a pair who share a wallet.
- **The fit is always said.** CONCOR ALWAYS splits in two, so the number of
  positions is set by the depth and not found in the data. R squared
  between the ties and the block densities is in the payload, and a split
  that did not settle within the round limit is made and reported, as
  UCINET does.
- **Refused before it allocates.** 1,000 vertices with ties at most,
  counted before any matrix exists, and `precheck` is what the service
  calls BEFORE it writes a RUNNING row, so a view with fewer than two tied
  entities is a 422 with no run left behind.

BLAS threads. numpy's OpenBLAS starts one thread per core. Measured on a
16-core development host: four worker processes each running a worst case
took 47 to 51 s apiece uncapped and 6.3 s capped at one thread, while one
thread costs a typical run nothing. So this module caps the process's BLAS
to `CONCOR_BLAS_THREADS` on import, for as long as the process lives: any
later numpy user in the API process inherits the cap, on purpose. It uses
threadpoolctl when it is installed, and otherwise tells the OpenBLAS numpy
bundles directly, through the library's own set_num_threads (the call
threadpoolctl itself makes). Neither caps Apple's Accelerate, which the
macOS arm64 wheels use; production is Linux with OpenBLAS, which is the
platform that matters (2026-09-24). `BLAS_CAP` records which
path took effect and `blas_threads()` reads the count back.

Pure and database-free, like `analytics.py`. Every value in the payload is
a Python scalar rounded through `analytics._clean`, so NaN never reaches
jsonb (the CR8 lesson).
"""
from __future__ import annotations

import ctypes
import glob
import os

import numpy
from noctornal_ontology.definition import EDGE_TYPES, NODE_TYPES

from noctornal_api.analytics import (
    AnalyticsError,
    AnalyticsParams,
    _clean,
    one_mode_block,
    review_scope_block,
)
from noctornal_api.projections import Projection, Subgraph

CONCOR_MAX_NODES = 1000
CONCOR_DEFAULT_DEPTH = 2
CONCOR_MAX_DEPTH = 4
CONCOR_EPS = 1e-6
#: Twice the 13 to 25 rounds a split was observed to take, and half the
#: cap first proposed, which halved the worst case (1.7 s at 1,000
#: vertices and depth 4 with every split at the cap, one BLAS thread).
CONCOR_MAX_ITER = 50
ZERO_VARIANCE = 1e-9
EQUIVALENCE_LEAD_MIN = 0.7
EQUIVALENCE_MIN_TIES = 2
MAX_EQUIVALENT_PAIRS = 50
CONCOR_BLAS_THREADS = 1
RELATIONS = (("positive", "positive ties", 1), ("negative", "negative ties", -1),
             ("neutral", "ties with no valence", 0))
LETTERS = "ABCDEFGHIJKLMNOP"

METHOD = (
    "CONCOR (Breiger, Boorman and Arabie 1975): each pair of entities' ties "
    "to and from everyone else are correlated, the correlations are "
    "correlated again until they settle at plus or minus one, and the "
    "entities are split on the sign. Positive, negative and other ties are "
    "compared separately, and so are ties given and received. Ties count as "
    "present or absent.")
READING = (
    "Entities in the same position have the same pattern of ties to the same "
    "others; they need not be tied to each other. CONCOR always splits in "
    "two, so the number of positions is set by the depth, not found in the "
    "data: read the fit before reading the positions.")

_DIRECTED = {t.key: t.is_directed for t in EDGE_TYPES}
_ACTOR = frozenset(n.key for n in NODE_TYPES if n.category == "ACTOR")


# --------------------------------------------------------------------------
# BLAS threads
# --------------------------------------------------------------------------

_SETTERS = ("scipy_openblas_set_num_threads64_", "scipy_openblas_set_num_threads",
            "openblas_set_num_threads64_", "openblas_set_num_threads")
_GETTERS = ("scipy_openblas_get_num_threads64_", "scipy_openblas_get_num_threads",
            "openblas_get_num_threads64_", "openblas_get_num_threads")


def _bundled_openblas() -> list:
    """numpy's own OpenBLAS, where its wheels put it: `numpy.libs` beside
    the package (Linux and Windows) or `numpy/.dylibs` (macOS x86_64).
    Opening a library the process has already loaded returns the loaded
    one, so these are the copies numpy is using."""
    root = os.path.dirname(os.path.abspath(numpy.__file__))
    out = []
    for folder in (os.path.join(os.path.dirname(root), "numpy.libs"),
                   os.path.join(root, ".dylibs")):
        for path in sorted(glob.glob(os.path.join(folder, "*openblas*"))):
            try:
                out.append(ctypes.CDLL(path))
            except OSError:
                continue
    return out


def _openblas_call(names: tuple[str, ...], *args) -> int | None:
    for lib in _bundled_openblas():
        for name in names:
            fn = getattr(lib, name, None)
            if fn is None:
                continue
            fn.argtypes = [ctypes.c_int] * len(args)
            fn.restype = ctypes.c_int if not args else None
            got = fn(*args)
            return int(got) if not args else 0
    return None


def blas_threads() -> int | None:
    """The thread count numpy's bundled OpenBLAS reports now, or None where
    there is no OpenBLAS to ask."""
    return _openblas_call(_GETTERS)


def _cap_blas() -> str:
    try:
        from threadpoolctl import threadpool_limits
    except ImportError:
        threadpool_limits = None
    if threadpool_limits is not None:
        # Called as a function, not a context manager: the limit then holds
        # for the life of the process.
        threadpool_limits(limits=CONCOR_BLAS_THREADS, user_api="blas")
        return "threadpoolctl"
    if _openblas_call(_SETTERS, CONCOR_BLAS_THREADS) is not None:
        return "openblas"
    return "none"


#: Which path capped BLAS on import: "threadpoolctl", "openblas", or "none"
#: (no OpenBLAS found to tell).
BLAS_CAP = _cap_blas()


def blas_cap_report() -> tuple[bool, str]:
    """`(capped, evidence)` for the readiness register's
    role_analysis_thread_capped row, which fails whenever role analysis
    runs without its cap (2026-09-24).

    Capped means the path taken on import can be read back at one thread
    now: threadpoolctl's own report of every BLAS it controls, or the
    count numpy's OpenBLAS gives. threadpoolctl can be installed and still
    find nothing to cap (Apple's Accelerate), so its path alone is not
    enough."""
    one = CONCOR_BLAS_THREADS
    if BLAS_CAP == "threadpoolctl":
        from threadpoolctl import threadpool_info
        counts = sorted({int(i.get("num_threads") or 0) for i in threadpool_info()
                         if i.get("user_api") == "blas"})
        if not counts:
            return False, ("threadpoolctl is installed but finds no BLAS it can "
                           "cap; Apple's Accelerate cannot be capped")
        if counts != [one]:
            return False, ("capped through threadpoolctl on import, but a BLAS "
                           f"now runs {', '.join(map(str, counts))} threads")
        return True, f"capped to {one} BLAS thread per process through threadpoolctl"
    if BLAS_CAP == "openblas":
        now = blas_threads()
        if now is None:
            return False, ("capped through OpenBLAS's own setting on import, but "
                           "its thread count cannot be read back")
        if now != one:
            return False, ("capped through OpenBLAS's own setting on import, but "
                           f"it now reports {now} threads")
        return True, (f"capped to {one} BLAS thread per process through the "
                      "OpenBLAS numpy bundles (threadpoolctl is not installed)")
    return False, ("threadpoolctl is not installed and numpy bundles no OpenBLAS "
                   "this process can tell, so its BLAS runs a thread per core")


# --------------------------------------------------------------------------
# Relations
# --------------------------------------------------------------------------

def is_directed(edge: dict) -> bool:
    """A derived tie (F2) carries its own flag; a stored one takes its
    type's, and an unknown type counts as directed, the reading that keeps
    more information."""
    if edge.get("derived"):
        return bool(edge.get("directed"))
    return _DIRECTED.get(edge.get("edge_type"), True)


def direction_rows(sub: Subgraph) -> list[tuple[str, str, str, str]]:
    """Every tie's ends, type and direction, for CONCOR's cache key: the
    graph hash carries no edge type, so an undirected tie swapped for a
    directed one of the same sign, weight, dates, review and evidence left
    it unchanged, and CONCOR's relations depend on direction."""
    ids = {n["id"] for n in sub.nodes}
    return sorted((str(e["src_node_id"]), str(e["dst_node_id"]), str(e["edge_type"]),
                   "d" if is_directed(e) else "u")
                  for e in sub.edges
                  if e["src_node_id"] in ids and e["dst_node_id"] in ids)


def _tied(sub: Subgraph) -> tuple[set, list[dict]]:
    """Vertices with at least one tie to another vertex of the view (the
    visibility guard `materialise` applies), and those ties."""
    ids = {n["id"] for n in sub.nodes}
    tied: set = set()
    usable: list[dict] = []
    for e in sub.edges:
        a, b = e["src_node_id"], e["dst_node_id"]
        if a == b or a not in ids or b not in ids:
            continue
        tied.update((a, b))
        usable.append(e)
    return tied, usable


def precheck(sub: Subgraph) -> None:
    """The refusals that need no matrix, taken first: over the cap, or
    fewer than two entities with ties. The service calls this before it
    records a run."""
    tied, _ = _tied(sub)
    if len(tied) > CONCOR_MAX_NODES:
        raise AnalyticsError(
            f"role analysis is capped at {CONCOR_MAX_NODES} entities with ties; "
            f"this view has {len(tied)}. Narrow the view first.")
    types = {n["id"]: n["node_type"] for n in sub.nodes}
    if sum(1 for v in tied if types.get(v) in _ACTOR) < 2:
        raise AnalyticsError(
            "role analysis needs at least two entities with ties in this view")


def build_relations(sub: Subgraph) -> tuple[list, list[tuple[str, str, numpy.ndarray, int]]]:
    """(vertices, relations): vertices sorted by id, and one binary n x n
    matrix per valence present, R[i, j] = 1 for a tie from i to j, both
    ways when the tie is undirected. Refused before any matrix exists."""
    precheck(sub)
    tied, usable = _tied(sub)
    verts = sorted(tied, key=str)
    index = {v: i for i, v in enumerate(verts)}
    n = len(verts)
    mats: dict[str, numpy.ndarray] = {}
    counts: dict[str, int] = {}
    for e in usable:
        sign = int(e["sign"])
        key = "positive" if sign > 0 else ("negative" if sign < 0 else "neutral")
        if key not in mats:
            mats[key] = numpy.zeros((n, n))
            counts[key] = 0
        i, j = index[e["src_node_id"]], index[e["dst_node_id"]]
        mats[key][i, j] = 1.0
        if not is_directed(e):
            mats[key][j, i] = 1.0
        counts[key] += 1
    rels = []
    for key, label, _sign in RELATIONS:
        if key in mats:
            numpy.fill_diagonal(mats[key], 0.0)
            rels.append((key, label, mats[key], counts[key]))
    return verts, rels


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------

def profile_correlation(mats: list[numpy.ndarray]) -> numpy.ndarray:
    """Pearson correlation between every two vertices' tie profiles,
    leaving out the entries that describe the two of them.

    A profile is the vertex's ties sent and received in every relation:
    the rows of R and of R transposed, side by side (a symmetric R once,
    since a copy of every entry does not move a correlation). For the pair
    (i, j) the entries at columns i and j of every block are left out,
    and the sums are taken from whole-matrix products rather than by
    materialising the stack. The diagonal is zero by construction, so the
    left-out cross products are zero too.

    Undefined cases (2026-09-24): two constant left-out
    profiles correlate 1 when they are equal and 0 when not; one constant
    against a varying one is 0; anything else not finite is 0. Two hubs
    tied to every other vertex of an undirected view correlated 0 under a
    naive reading and correlate 1 here, which is what they are.
    """
    blocks: list[numpy.ndarray] = []
    for r in mats:
        blocks.append(r)
        if not numpy.array_equal(r, r.T):
            blocks.append(r.T)
    n = mats[0].shape[0]
    m = len(blocks) * (n - 2)
    if m <= 0:
        # Two vertices and nothing else: with themselves left out their
        # profiles are empty, and empty profiles are alike.
        return numpy.ones((n, n))
    s_x = sum(b.sum(axis=1) for b in blocks)
    s_xx = sum((b * b).sum(axis=1) for b in blocks)
    s_xy = sum(b @ b.T for b in blocks)
    t1 = sum(blocks)
    t2 = sum(b * b for b in blocks)
    sx = s_x[:, None] - t1
    sy = s_x[None, :] - t1.T
    sxx = s_xx[:, None] - t2
    syy = s_xx[None, :] - t2.T
    vx = sxx - sx * sx / m
    vy = syy - sy * sy / m
    cov = s_xy - sx * sy / m
    with numpy.errstate(divide="ignore", invalid="ignore"):
        r = cov / numpy.sqrt(vx * vy)
    zx, zy = vx <= ZERO_VARIANCE, vy <= ZERO_VARIANCE
    r = numpy.where(zx & zy, numpy.where(numpy.abs(sx - sy) < 1e-9, 1.0, 0.0), r)
    r = numpy.where(zx ^ zy, 0.0, r)
    r = numpy.where(numpy.isfinite(r), r, 0.0)
    numpy.fill_diagonal(r, 1.0)
    return numpy.clip(r, -1.0, 1.0)


def _iterate(c: numpy.ndarray) -> tuple[numpy.ndarray, int, bool]:
    """Correlate the columns of `c` until every entry is plus or minus one,
    or the round limit: (c, rounds, converged)."""
    rounds = 0
    while True:
        if numpy.all(numpy.abs(numpy.abs(c) - 1.0) < CONCOR_EPS):
            return c, rounds, True
        if rounds >= CONCOR_MAX_ITER:
            return c, rounds, False
        with numpy.errstate(divide="ignore", invalid="ignore"):
            c = numpy.corrcoef(c, rowvar=False)
        c = numpy.nan_to_num(c, nan=0.0, posinf=0.0, neginf=0.0)
        numpy.fill_diagonal(c, 1.0)
        rounds += 1


def _split(c0: numpy.ndarray, members: list[int]):
    """One bisection: (left, right, rounds, converged), or ("alike",
    rounds, converged) when every member lands on one side."""
    sub = c0[numpy.ix_(members, members)]
    c, rounds, converged = _iterate(sub)
    first = c[0]
    left = [members[k] for k in range(len(members)) if first[k] > 0]
    right = [members[k] for k in range(len(members)) if not first[k] > 0]
    if not left or not right:
        return ("alike", rounds, converged)
    return (left, right, rounds, converged)


# --------------------------------------------------------------------------
# CONCOR
# --------------------------------------------------------------------------

def _pearson_squared(a: numpy.ndarray, b: numpy.ndarray) -> float | None:
    if a.size < 2 or float(a.std()) <= 0.0 or float(b.std()) <= 0.0:
        return None
    r = float(numpy.corrcoef(a, b)[0, 1])
    return _clean(r * r)


def concor(sub: Subgraph, p: Projection, params: AnalyticsParams, *,
           depth: int = CONCOR_DEFAULT_DEPTH) -> dict:
    """Positions by CONCOR over one projected subgraph, in the payload the
    API serves and the service stores."""
    if not isinstance(depth, int) or not 1 <= depth <= CONCOR_MAX_DEPTH:
        raise AnalyticsError(
            f"the number of splits must be between 1 and {CONCOR_MAX_DEPTH}")
    verts, rels = build_relations(sub)
    by_id = {n["id"]: n for n in sub.nodes}
    n = len(verts)
    c0 = profile_correlation([r[2] for r in rels])

    actors = [i for i, v in enumerate(verts) if by_id[v]["node_type"] in _ACTOR]
    tied = set(verts)
    no_ties = sum(1 for nd in sub.nodes
                  if nd["node_type"] in _ACTOR and nd["id"] not in tied)
    profile_types = sorted({by_id[v]["node_type"] for v in verts
                            if by_id[v]["node_type"] not in _ACTOR})
    profile_only = n - len(actors)

    leaves: list[tuple[str, list[int]]] = []
    splits: list[dict] = []
    unsplit: list[dict] = []

    def recurse(path: str, members: list[int], level: int) -> None:
        if level == depth:
            leaves.append((path, members))
            return
        if len(members) < 2:
            leaves.append((path, members))
            unsplit.append({"block": path, "size": len(members), "reason": "single"})
            return
        got = _split(c0, members)
        if got[0] == "alike":
            leaves.append((path, members))
            unsplit.append({"block": path, "size": len(members), "reason": "alike"})
            return
        left, right, rounds, converged = got
        splits.append({"block": path, "sizes": [len(left), len(right)],
                       "iterations": int(rounds), "converged": bool(converged)})
        recurse(path + ".1", left, level + 1)
        recurse(path + ".2", right, level + 1)

    recurse("1", actors, 0)

    def who(i: int) -> dict:
        nd = by_id[verts[i]]
        return {"id": str(verts[i]), "label": nd.get("label"), "node_type": nd["node_type"]}

    block_of: dict[int, int] = {}
    positions = []
    node_rows = []
    for index, (path, members) in enumerate(leaves):
        letter = LETTERS[index]
        ordered = sorted(members, key=lambda i: (str(by_id[verts[i]].get("label") or "").lower(),
                                                 str(verts[i])))
        for i in ordered:
            block_of[i] = index
            node_rows.append({**who(i), "position": letter, "block": path,
                              "block_index": index})
        positions.append({"position": letter, "block": path, "block_index": index,
                          "size": len(members), "members": [who(i) for i in ordered]})

    # Fit, over the partitioned actors only.
    k = len(actors)
    blocks = [members for _path, members in leaves]
    local = {i: pos for pos, i in enumerate(actors)}
    density: dict[str, list] = {}
    image: dict[str, list] = {}
    alpha: dict[str, float | None] = {}
    r_squared: dict[str, float | None] = {}
    observed_all, predicted_all = [], []
    off = ~numpy.eye(k, dtype=bool)
    for key, _label, mat, _count in rels:
        ra = mat[numpy.ix_(actors, actors)]
        possible = k * (k - 1)
        a = float(ra.sum()) / possible if possible else None
        alpha[key] = _clean(a) if a is not None else None
        dmat = numpy.zeros((len(blocks), len(blocks)))
        drows, irows = [], []
        for x, bx in enumerate(blocks):
            drow, irow = [], []
            for y, by in enumerate(blocks):
                cells = ra[numpy.ix_([local[i] for i in bx], [local[i] for i in by])]
                poss = len(bx) * len(by) if x != y else len(bx) * (len(bx) - 1)
                if x == y:
                    ties = float(cells.sum() - numpy.trace(cells))
                else:
                    ties = float(cells.sum())
                d = ties / poss if poss else None
                dmat[x, y] = d if d is not None else 0.0
                drow.append(_clean(d) if d is not None else None)
                irow.append(1 if (d is not None and d > 0 and a is not None and d >= a) else 0)
            drows.append(drow)
            irows.append(irow)
        density[key] = drows
        image[key] = irows
        bidx = numpy.array([block_of[i] for i in actors], dtype=int)
        predicted = dmat[bidx[:, None], bidx[None, :]]
        obs, pred = ra[off], predicted[off]
        r_squared[key] = _pearson_squared(obs, pred)
        observed_all.append(obs)
        predicted_all.append(pred)
    r_squared["overall"] = (_pearson_squared(numpy.concatenate(observed_all),
                                             numpy.concatenate(predicted_all))
                            if observed_all else None)

    # Alike but not tied: the "replacement" lead.
    adj = numpy.zeros((n, n), dtype=bool)
    for _key, _label, mat, _count in rels:
        adj |= (mat > 0) | (mat.T > 0)
    # Vectorised: at 1,000 actors a Python double loop is half a million
    # rounds inside a request.
    act = numpy.array(actors, dtype=int)
    enough = adj.sum(axis=1)[act] >= EQUIVALENCE_MIN_TIES
    sub_c = c0[numpy.ix_(act, act)]
    mask = (numpy.triu(sub_c >= EQUIVALENCE_LEAD_MIN, k=1)
            & ~adj[numpy.ix_(act, act)] & enough[:, None] & enough[None, :])
    xs, ys = numpy.nonzero(mask)
    corrs = sub_c[xs, ys]
    found = int(corrs.size)
    if found > MAX_EQUIVALENT_PAIRS:
        # Only the pairs that can make the list are sorted by name.
        cut = numpy.partition(corrs, -MAX_EQUIVALENT_PAIRS)[-MAX_EQUIVALENT_PAIRS]
        keep = corrs >= cut
        xs, ys, corrs = xs[keep], ys[keep], corrs[keep]

    def label_of(i: int) -> str:
        return str(by_id[verts[i]].get("label") or "")

    pairs = sorted(((float(c), int(act[x]), int(act[y])) for c, x, y in zip(corrs, xs, ys,
                                                                               strict=True)),
                   key=lambda t: (-t[0], label_of(t[1]), label_of(t[2]), t[1], t[2]))
    equivalent = [{"a": who(i), "b": who(j), "correlation": _clean(corr),
                   "same_position": block_of.get(i) == block_of.get(j)}
                  for corr, i, j in pairs[:MAX_EQUIVALENT_PAIRS]]

    iterations = [s["iterations"] for s in splits]
    return {
        "projection": p.describe(),
        "params": params.describe(),
        "engine": "numpy " + numpy.__version__,
        "node_count": len(sub.nodes),
        "edge_count": len(sub.edges),
        "truncated": bool(sub.truncated),
        "truncation_note": (
            "the node set was cut off at the projection limit: positions "
            "below are computed over a PARTIAL graph and may move once the "
            "omitted entities are in") if sub.truncated else None,
        "review_scope": review_scope_block(p, sub),
        "one_mode": one_mode_block(sub),
        "concor": {
            "depth": depth,
            "relations": [{"key": key, "label": label, "ties": int(count)}
                          for key, label, _m, count in rels],
            "positions": positions,
            "splits": splits,
            "unsplit": unsplit,
            "all_converged": all(s["converged"] for s in splits),
            "max_iterations": CONCOR_MAX_ITER,
            "iterations": max(iterations) if iterations else 0,
            "density": density,
            "image": image,
            "alpha": alpha,
            "r_squared": r_squared,
            "equivalent_pairs": equivalent,
            "equivalent_pairs_truncated": found > MAX_EQUIVALENT_PAIRS,
            "equivalence_threshold": EQUIVALENCE_LEAD_MIN,
            "min_ties": EQUIVALENCE_MIN_TIES,
            "no_ties": {"count": int(no_ties)},
            "profile_only": {"count": int(profile_only), "types": profile_types},
            "derived_ties_counted_whole": any(e.get("derived") for e in sub.edges),
            "is_approximate": False,
            "method": METHOD,
            "reading": READING,
        },
        "nodes": node_rows,
    }

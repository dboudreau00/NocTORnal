"""Seed a LARGE, structured demo estate. Development only.

    .venv\\Scripts\\python scripts\\seed_showcase.py --owner-email you@example.com

The other seeders each demonstrate one subsystem with a handful of rows.
This one exists for the different question "what does it look like with a
real case load in it": six cases at different classifications and
lifecycle states, and a flagship network big enough that the sociogram and
the analytics have something to say.

## The network is STRUCTURED, not random

A uniformly random graph is the wrong demo. It renders as a hairball, every
centrality comes out flat, community detection finds nothing, and the
key-player set is indistinguishable from the top-n by degree, which is
precisely the claim docs/03 says this tool beats. So the generator builds:

- **six crews** of unequal size, densely tied inside (`VOUCHED_FOR`,
  `MEMBER_OF`) and sparsely between;
- **brokers** that hold few ties but hold them ACROSS crews, so betweenness
  and Burt's constraint disagree with degree: the broker signature;
- **a redundant pair** of brokers bridging the same two crews, so the
  optimal removal set is NOT simply the top two by betweenness;
- **negative ties** (`ACCUSED_SCAM`, `RIVAL_OF`, `DISPUTED_WITH`) placed to
  produce genuinely unbalanced triads and contested dyads;
- **dates spread over thirty months**, so trust decay visibly changes the
  numbers instead of being a parameter with no effect.

## Everything goes through the services

`GraphWriteService` writes every node and edge, so each one carries its
assertion in the same transaction (invariant 1). Nothing here INSERTs into
`core.node` or `core.edge` directly. A seeder that did would be creating
exactly the unfounded graph the model exists to prevent, and it would be
the first thing a reader copied.

Deterministic: `random.Random(SEED)` rather than `secrets`, because a demo
estate you cannot regenerate identically is one you cannot screenshot
twice. Re-running against a case that already exists is refused rather
than doubled.

## `--regrade`: an estate seeded before migration 0064

    .venv\\Scripts\\python scripts\\seed_showcase.py --owner-email you@example.com --regrade

Until 2026-09-22 this script gave each tie a confidence of its own and
graded the claim under it MODERATE, and 0064's backfill (a tie's confidence
is its claims') turned every seeded NIGHTJAR and CORVID tie MODERATE. A
fresh seed is right. `--regrade` repairs an existing estate in place,
without dropping it: it replays the seed from the RNG, writing nothing, and
supersedes each seed claim whose grade differs with one carrying the grade
this script seeds today. See `regrade` for how and why that way. It is
idempotent, and it touches no other row.

**Every name, wallet, host and victim below is fiction.**
"""
from __future__ import annotations

import argparse
import os
import random
import sys
from collections import Counter
from collections.abc import Callable
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps" / "api" / "src"))

from _env import load_env_local  # noqa: E402

load_env_local()

SEED = 20260730
RNG = random.Random(SEED)
NOW = datetime(2026, 7, 30, tzinfo=timezone.utc)

#: Handle fragments. Combined rather than listed so a few hundred distinct
#: aliases do not need a few hundred lines of literal.
_HEAD = ("spectre lynx null vector cipher ghost quiet ember rust cobalt onyx "
         "vellum harrow drift pale saffron flint marrow tandem quill sable "
         "brack North amber halcyon kestrel nightjar wheatear sandpiper "
         "corvid lupine ferric static umbra tessera oblique candor").split()
_TAIL = ("lynx wolf crane heron finch adder viper koi ram stoat marten otter "
         "shrike raven owl kite merlin hobby gannet skua tern auk grebe").split()

#: Compartments the seeded estate needs. One name, used both to read the
#: owner in (below) and to label OP-HALCYON-25 — two literals would drift
#: and the case would silently lose its compartment.
DEMO_COMPARTMENTS = ["STEALER-2026"]

CREWS = [
    ("Meridian crew", 18), ("Bastion crew", 15), ("Tessera crew", 13),
    ("Oblique crew", 11), ("Candor crew", 9), ("Umbra crew", 7),
]

#: The live cases that get a smaller network of their own, and its size.
SECONDARY = (("OP-KESTREL-26", 22), ("OP-CORVID-26", 30))


def _handle(used: set[str]) -> str:
    while True:
        h = f"{RNG.choice(_HEAD)}_{RNG.choice(_TAIL)}"
        if RNG.random() < 0.35:
            h += str(RNG.randint(2, 99))
        if h not in used:
            used.add(h)
            return h


def _when(months_back_max: int = 30) -> datetime:
    return NOW - timedelta(days=RNG.randint(20, months_back_max * 30))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--owner-email", required=True,
                    help="an existing user, who owns every seeded case")
    ap.add_argument("--code", default="OP-NIGHTJAR-26",
                    help="the flagship case to build the big network in")
    ap.add_argument("--regrade", action="store_true",
                    help="bring an estate this script seeded before migration "
                         "0064 to the tie grades it seeds today, by "
                         "supersession; writes nothing else (see `regrade`)")
    args = ap.parse_args()

    os.environ.setdefault("NOCTORNAL_PROHIBITED_CONTENT_POLICY",
                          "DEV-POLICY-0 (development seed, not a real policy)")
    os.environ.setdefault("NOCTORNAL_DESIGNATED_PERSON", "dev operator")

    from noctornal_api.cases import CaseService
    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.selectors import SelectorStore

    conn = connect_system(SystemPurpose.SCRIPT)
    row = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (args.owner_email,)).fetchone()
    if row is None:
        print(f"no user {args.owner_email!r}", file=sys.stderr)
        return 2
    owner = row[0]
    if args.regrade:
        # Before anything below: a regrade touches the seed's tie claims and
        # nothing else, so it must not register compartments, read anyone
        # in, or create a case that is missing.
        return _regrade_main(conn, owner, args.code)

    cases = CaseService(conn)
    g = GraphWriteService(conn)
    sel = SelectorStore(conn)

    # A compartmented case needs TWO things that a fresh install does not
    # have, and it needs them in this order. Getting either wrong killed the
    # seeder half-way, after the first two cases had already been committed
    # on an autocommit connection — a partial estate that the "already
    # seeded" guard below then refused to finish. That happened twice: once
    # for the read-in, and again on 2026-09-02 for the registry.
    #
    # FIRST, the key must be in the REGISTRY. 0057 made `iam.compartment` a
    # closed vocabulary and `CaseService.create` refuses a key that is not in
    # it. The registry block below survived review only because a developer
    # machine's 0057 backfill had already found STEALER-2026 sitting in an
    # array; on a fresh install — which is every install, and every CI run —
    # there was nothing to find.
    #
    # Guarded with a lookup rather than caught, because `register_compartment`
    # REFUSES a duplicate by design (a re-registration would silently relabel
    # what every case in the compartment is filed under) and this script is
    # re-runnable. Said out loud, because widening the vocabulary the access
    # gate compares against is not something a seed script should do quietly.
    from noctornal_api.iam_admin import IamAdminService
    admin = IamAdminService(conn)
    known = {r["key"] for r in admin.list_compartments()}
    new_keys = [k for k in DEMO_COMPARTMENTS if k not in known]
    for key in new_keys:
        admin.register_compartment(key=key, label=f"{key} (demo seed)",
                                   actor_id=owner)
    if new_keys:
        noun = "compartment" if len(new_keys) == 1 else "compartments"
        print(f"  REGISTERED {noun} {', '.join(new_keys)}. This "
              f"widens the vocabulary every case and read-in is checked "
              f"against, and is audited as COMPARTMENT_REGISTERED.")

    # SECOND, the OWNER must be read into it — `CaseService.create` refuses
    # outright otherwise, and it is right to: a case whose own owner cannot
    # see it is a case nobody can work. Granted rather than skipped, because
    # the compartment is one of the things worth SEEING in a demo, and said
    # out loud, because widening an account's access is not something a seed
    # script should do quietly.
    have = conn.execute(
        "SELECT compartments FROM iam.app_user WHERE id = %s",
        (owner,)).fetchone()[0] or []
    missing = [c for c in DEMO_COMPARTMENTS if c not in have]
    if missing:
        conn.execute(
            "UPDATE iam.app_user SET compartments = %s WHERE id = %s",
            (sorted(set(have) | set(missing)), owner))
        print(f"  READ {args.owner_email} INTO {', '.join(missing)}. This "
              f"widens that account's access and is why the compartmented "
              f"case can exist at all.")

    # ---------------------------------------------------------------- cases
    #
    # Varied on purpose. A case list where every row is AMBER/ACTIVE tells a
    # viewer nothing about how the labels and the lifecycle actually read;
    # this one exercises four classifications, five states, a compartment
    # and a legal hold.
    catalogue = [
        (args.code, "Operation Nightjar",
         "Ransomware affiliate ecosystem: access brokers, laundering and the "
         "crews that buy from them.", "AMBER", "ACTIVE", []),
        ("OP-KESTREL-26", "Operation Kestrel",
         "Imitator using NIGHTJAR's builder. Separate operator or the same "
         "hand? The ACH matrix is on this one.", "GREEN", "ACTIVE", []),
        ("OP-HALCYON-25", "Operation Halcyon",
         "Prior year. Dormant pending a disclosure decision.",
         "RED", "DORMANT", DEMO_COMPARTMENTS),
        ("OP-SANDPIPER-26", "Operation Sandpiper",
         "Closed. Retained for the appeal window.", "AMBER", "CLOSED", []),
        ("OP-WHEATEAR-26", "Operation Wheatear",
         "Opened this week; scoping only.", "CLEAR", "DRAFT", []),
        ("OP-CORVID-26", "Operation Corvid",
         "Money-laundering network feeding several of the above.",
         "AMBER", "ACTIVE", []),
    ]
    ids: dict[str, object] = {}
    for code, title, summary, cls, status, comps in catalogue:
        found = conn.execute('SELECT id FROM core."case" WHERE code = %s',
                             (code,)).fetchone()
        if found:
            ids[code] = found[0]
            continue
        ids[code] = cases.create(
            code=code, title=title, summary=summary,
            legal_basis="Fictional demonstration data. Not a lawful basis.",
            authority_ref="DEMO/2026/001",
            retention_until=date(2028, 12, 31), review_due=date(2026, 12, 31),
            owner_user_id=owner, created_by=owner,
            classification=cls, compartments=comps)
        if status != "DRAFT":
            # DRAFT -> ACTIVE is the first legal move; everything else goes
            # through ACTIVE, so walk it rather than writing the enum.
            cases.transition_status(ids[code], "ACTIVE", actor_id=owner)
            if status in ("DORMANT", "CLOSED"):
                cases.transition_status(ids[code], status, actor_id=owner)
        print(f"  case {code} ({cls}, {status})")

    case_id = ids[args.code]
    if conn.execute("SELECT count(*) FROM core.node WHERE case_id = %s",
                    (case_id,)).fetchone()[0] > 40:
        print(f"{args.code} already has a large network; nothing to do")
        return 0

    build_network(
        g, sel, case_id=case_id, ids=ids, owner=owner,
        make_assertion=AssertionInput,
        populated=lambda cid: conn.execute(
            "SELECT count(*) FROM core.node WHERE case_id = %s",
            (cid,)).fetchone()[0] > 5)

    conn.commit()
    counts = conn.execute(
        """SELECT (SELECT count(*) FROM core."case"),
                  (SELECT count(*) FROM core.node WHERE deleted_at IS NULL),
                  (SELECT count(*) FROM core.edge WHERE deleted_at IS NULL),
                  (SELECT count(*) FROM core.assertion),
                  (SELECT count(*) FROM core.selector)""").fetchone()
    print(f"\n  {counts[0]} cases · {counts[1]} nodes · {counts[2]} edges · "
          f"{counts[3]} assertions · {counts[4]} selectors")
    print("  Every row is fiction and the lawful basis is a placeholder.")
    return 0


def build_network(g, sel, *, case_id, ids: dict, owner, make_assertion,
                  populated: Callable[[object], bool],
                  log: Callable[[str], None] = print) -> None:
    """The flagship network and the two secondary cases' smaller ones.

    Separate from `main` so `--regrade` can run it against `_Replay`, which
    records what it would write instead of writing it. Every RNG draw is
    made HERE, never inside `g` or `sel`, which is what makes a replay draw
    the same handles, pairs, dates and grades as the run that seeded the
    estate. Keep it that way: a draw moved into a service call, or one
    skipped on a condition only the database can answer, would make every
    later draw differ and the regrade would match nothing.

    `populated(case_id)` says whether a secondary case already holds a
    network and should be left alone; the replay answers False, as the
    original run did for a fresh estate.
    """
    RNG.seed(SEED)

    def assertion(rationale: str, *, basis: str = "DIRECT_OBSERVATION",
                  conf: str = "MODERATE", rel: str = "C", cred: str = "3",
                  observed: datetime | None = None):
        return make_assertion(
            basis=basis, created_by=owner, reliability=rel, credibility=cred,
            confidence=conf, rationale=rationale,
            observed_at=observed or _when())

    # ------------------------------------------------------- the big network
    used: set[str] = set()
    crew_nodes: list[list] = []
    log("  building crews")
    for crew_name, size in CREWS:
        grp = g.create_node(
            case_id=case_id, node_type="GROUP", label=crew_name,
            created_by=owner, classification="AMBER",
            assertion=assertion(f"{crew_name} named in three separate "
                                f"forum threads as a distinct crew"))
        members = []
        for i in range(size):
            h = _handle(used)
            n = g.create_node(
                case_id=case_id, node_type="IDENTITY", label=h,
                created_by=owner, classification="AMBER",
                attrs={"crew": crew_name, "first_seen_forum": "exchange"},
                assertion=assertion(f"handle {h} posting in {crew_name} "
                                    f"threads"))
            sel.record(case_id=case_id, selector_type="JABBER",
                       raw_value=f"{h}@nightmarket.example", node_id=n)
            if i % 3 == 0:
                sel.record(case_id=case_id, selector_type="BTC_ADDR",
                           raw_value="bc1q" + "".join(
                               RNG.choice("023456789acdefghjklmnpqrstuvwxyz")
                               for _ in range(38)), node_id=n)
            members.append(n)
            # The leader leads; everyone else is a member.
            g.create_edge(
                case_id=case_id,
                edge_type="LEADS" if i == 0 else "MEMBER_OF",
                src_node_id=n, dst_node_id=grp, created_by=owner,
                valid_from=_when(),
                assertion=assertion(
                    f"{h} {'directing' if i == 0 else 'posting as'} "
                    f"{crew_name}",
                    conf="HIGH" if i == 0 else "MODERATE"))
        crew_nodes.append(members)

    # Dense INSIDE each crew: this is what makes a community detectable.
    log("  weaving intra-crew ties")
    for members in crew_nodes:
        for a in members:
            for b in RNG.sample(members, min(len(members), RNG.randint(3, 6))):
                if a is b:
                    continue
                # Drawn in the order the call used to draw them (weight,
                # grade, then the dates), so the seeded estate is the same
                # one every screenshot and review of it describes. The
                # grade is the ASSERTION's now: a tie's confidence is its
                # assertion's (migration 0064), and the separate edge value
                # this used to pass is how the demo came to hold 259 ties
                # that disagreed with their own claims.
                weight = round(RNG.uniform(0.4, 1.0), 2)
                conf = RNG.choice(["LOW", "MODERATE", "MODERATE", "HIGH"])
                g.create_edge(
                    case_id=case_id, edge_type="VOUCHED_FOR",
                    src_node_id=a, dst_node_id=b, created_by=owner,
                    weight=weight, valid_from=_when(),
                    assertion=assertion("vouch posted in the crew's own thread",
                                        conf=conf))

    # Sparse BETWEEN crews, and only through brokers. This is the whole
    # point: degree stays low on these nodes while betweenness goes high.
    log("  placing brokers")
    brokers = []
    for a_i in range(len(crew_nodes)):
        b_i = (a_i + 1) % len(crew_nodes)
        h = _handle(used)
        br = g.create_node(
            case_id=case_id, node_type="IDENTITY", label=h, created_by=owner,
            classification="AMBER", attrs={"role": "suspected broker"},
            assertion=assertion(f"{h} appears in both "
                                f"{CREWS[a_i][0]} and {CREWS[b_i][0]} threads"))
        for side in (crew_nodes[a_i], crew_nodes[b_i]):
            for peer in RNG.sample(side, 3):
                g.create_edge(
                    case_id=case_id, edge_type="COMMUNICATES_WITH",
                    src_node_id=br, dst_node_id=peer, created_by=owner,
                    weight=round(RNG.uniform(0.5, 1.0), 2),
                    valid_from=_when(),
                    assertion=assertion("co-present in a private channel"))
        brokers.append(br)

    # A REDUNDANT pair across one gap, so the optimal removal set is not the
    # top two by betweenness — docs/03's claim, made visible.
    twin = g.create_node(
        case_id=case_id, node_type="IDENTITY", label=_handle(used),
        created_by=owner, classification="AMBER",
        attrs={"role": "suspected broker", "note": "redundant with another"},
        assertion=assertion("second handle bridging the same two crews"))
    for side in (crew_nodes[0], crew_nodes[1]):
        for peer in RNG.sample(side, 3):
            g.create_edge(
                case_id=case_id, edge_type="COMMUNICATES_WITH",
                src_node_id=twin, dst_node_id=peer, created_by=owner,
                valid_from=_when(),
                assertion=assertion("co-present in a private channel"))
    brokers.append(twin)

    # Negative ties: unbalanced triads and contested dyads.
    log("  seeding conflict")
    flat = [n for crew in crew_nodes for n in crew]
    for _ in range(24):
        a, b = RNG.sample(flat, 2)
        # Same draw order as before the grade moved into the assertion.
        etype = RNG.choice(["ACCUSED_SCAM", "DISPUTED_WITH"])
        conf = RNG.choice(["LOW", "MODERATE"])
        g.create_edge(
            case_id=case_id, edge_type=etype,
            src_node_id=a, dst_node_id=b, created_by=owner,
            valid_from=_when(12),
            assertion=assertion("accusation posted to the arbitration thread",
                                basis="THIRD_PARTY_REPORT", rel="D", cred="4",
                                conf=conf))

    # Infrastructure, money and victims — so the pane is not all people.
    log("  attaching infrastructure, wallets and victims")
    for _ in range(26):
        host = g.create_node(
            case_id=case_id, node_type="INFRA",
            label=f"vps-{RNG.randint(1000, 9999)}.hostmarket.example",
            created_by=owner, classification="AMBER",
            attrs={"asn": RNG.choice([64496, 64497, 64498])},
            assertion=assertion("resolved from a paste in the crew channel",
                                basis="THIRD_PARTY_REPORT"))
        g.create_edge(case_id=case_id, edge_type="CONTROLS",
                      src_node_id=RNG.choice(flat), dst_node_id=host,
                      created_by=owner,
                      valid_from=_when(18),
                      assertion=assertion("host named in their own post"))
    for _ in range(20):
        w = g.create_node(
            case_id=case_id, node_type="WALLET",
            label="bc1q" + "".join(RNG.choice("023456789acdefghjklmnpqrstuvwxyz")
                                   for _ in range(38)),
            created_by=owner, classification="AMBER",
            assertion=assertion("address quoted in an escrow message"))
        g.create_edge(case_id=case_id, edge_type="CONTROLS",
                      src_node_id=RNG.choice(flat), dst_node_id=w,
                      created_by=owner, valid_from=_when(20),
                      assertion=assertion("address posted by that handle",
                                          conf="LOW"))
    for _ in range(14):
        v = g.create_node(
            case_id=case_id, node_type="VICTIM",
            label=RNG.choice(["Latticework Holdings", "Ferrous Freight",
                              "Kestrel Medical", "Brackwater Utilities",
                              "Tandem Logistics", "Quill & Marrow LLP",
                              "Sable Foods"]) + f" ({RNG.randint(100, 999)})",
            created_by=owner, classification="AMBER",
            assertion=assertion("named in a leak-site post",
                                basis="THIRD_PARTY_REPORT", rel="B", cred="2"))
        g.create_edge(case_id=case_id, edge_type="BROKERED_ACCESS",
                      src_node_id=RNG.choice(brokers), dst_node_id=v,
                      created_by=owner,
                      valid_from=_when(10),
                      assertion=assertion("access advertised then withdrawn "
                                          "within a day of the leak post"))

    # Smaller networks in the other live cases, so they are not empty shells.
    log("  populating the secondary cases")
    for code, size in SECONDARY:
        cid = ids[code]
        if populated(cid):
            continue
        local = []
        for _ in range(size):
            h = _handle(used)
            local.append(g.create_node(
                case_id=cid, node_type="IDENTITY", label=h, created_by=owner,
                classification="GREEN" if code == "OP-KESTREL-26" else "AMBER",
                assertion=assertion(f"handle {h} observed on the exchange")))
        for a in local:
            for b in RNG.sample(local, RNG.randint(2, 4)):
                if a is b:
                    continue
                # Same draw order as before the grade moved into the assertion.
                conf = RNG.choice(["LOW", "MODERATE"])
                g.create_edge(
                    case_id=cid, edge_type="COMMUNICATES_WITH",
                    src_node_id=a, dst_node_id=b, created_by=owner,
                    classification="GREEN" if code == "OP-KESTREL-26" else "AMBER",
                    valid_from=_when(14),
                    assertion=assertion("replied in the same thread", conf=conf))


# --------------------------------------------------------------- --regrade

class SeededTie(NamedTuple):
    """One tie as this script writes it, as far as a regrade needs it: the
    key that finds it again and the grade it should carry."""
    case_id: object
    edge_type: str
    src_label: str
    dst_label: str
    valid_from: datetime
    confidence: str
    rationale: str


class _Ref:
    """A node the replay would have written. Identity is all the builder
    uses (`a is b`, `RNG.sample`), and the label is how the regrade finds
    the real node again."""
    __slots__ = ("label",)

    def __init__(self, label: str) -> None:
        self.label = label


class _Replay:
    """Stands in for GraphWriteService AND SelectorStore under --regrade:
    records every tie `build_network` would write and writes nothing."""

    def __init__(self) -> None:
        self.ties: list[SeededTie] = []

    def create_node(self, *, label: str, **_) -> _Ref:
        return _Ref(label)

    def create_edge(self, *, case_id, edge_type, src_node_id, dst_node_id,
                    assertion, valid_from=None, **_) -> None:
        self.ties.append(SeededTie(
            case_id, edge_type, src_node_id.label, dst_node_id.label,
            valid_from, assertion.confidence, assertion.rationale))

    def record(self, **_) -> None:
        return None


def replay(*, case_id, ids: dict, owner) -> list[SeededTie]:
    """Every tie this script seeds, with the grade it seeds today, from the
    RNG alone. No database: `populated` answers False for every case, as it
    did when the estate was first seeded."""
    from noctornal_api.graph import AssertionInput

    rec = _Replay()
    build_network(rec, rec, case_id=case_id, ids=ids, owner=owner,
                  make_assertion=AssertionInput,
                  populated=lambda _cid: False, log=lambda _msg: None)
    return rec.ties


def regrade(conn, owner, ties: list[SeededTie]) -> Counter:
    """Bring each seeded tie's founding claim to the grade in `ties`.

    ## Why this exists

    Until 2026-09-22 this script passed each tie a confidence of its own
    and graded the claim under it MODERATE regardless. Migration 0064 made
    a tie's confidence its claims' (ux06 edge-confidence-not-stored), and
    its backfill, rightly, sided with the claims: every seeded tie in
    NIGHTJAR and CORVID came out MODERATE. A HIGH floor then showed
    nothing, and the canvas drew every tie at one opacity, which hid the
    one encoding (confidence as opacity) the demo exists to show. Found by
    the fix-round verifier. A fresh seed is already right; this repairs an
    estate seeded before the fix without dropping it.

    ## How, and why that way

    Through SUPERSESSION, invariant 5's own mechanism ("superseded, never
    overwritten"): a new assertion carrying the seed's grade and every
    other field of the one it replaces, recorded through the service, and
    the old row stamped `superseded_at` / `superseded_by`, kept, never
    edited otherwise. The 0064 trigger re-derives the tie from what is
    live. Not an UPDATE of the old claim's grade: that is the overwrite the
    invariant forbids, and this file is the first thing a reader copies.

    Only the seed's own claims are touched: the founding assertion by the
    seeding owner, with the seed's rationale and no claim path. A claim an
    analyst added to a demo tie is left alone, and still counts. The key
    is the edge's type, endpoint labels and `valid_from`, which is what
    the unique index on live edges is built on, so it finds one tie.

    Idempotent: a regraded tie's live seed claim already carries its
    grade, so a second run changes nothing. One transaction, so a failure
    leaves the estate as it was.
    """
    from noctornal_api.graph import AssertionInput, GraphWriteService

    g = GraphWriteService(conn)
    outcome: Counter = Counter()
    wanted: dict[tuple, SeededTie] = {}
    for t in ties:
        wanted[(t.case_id, t.edge_type, t.src_label, t.dst_label,
                t.valid_from)] = t
    with conn.transaction():
        found: dict[tuple, object] = {}
        for case_id in {t.case_id for t in ties}:
            for eid, etype, src, dst, valid_from in conn.execute(
                    """SELECT e.id, e.edge_type, s.label, d.label, e.valid_from
                         FROM core.edge e
                         JOIN core.node s ON s.id = e.src_node_id
                         JOIN core.node d ON d.id = e.dst_node_id
                        WHERE e.case_id = %s AND e.deleted_at IS NULL""",
                    (case_id,)):
                found[(case_id, etype, src, dst, valid_from)] = eid
        for key, t in wanted.items():
            edge_id = found.get(key)
            if edge_id is None:
                outcome["not found (deleted, or not this seed's)"] += 1
                continue
            claim = conn.execute(
                """SELECT id, basis::text, reliability::text,
                          credibility::text, confidence::text, observed_at,
                          source_id, document_id, evidence_id, external_ref
                     FROM core.assertion
                    WHERE edge_id = %s AND created_by = %s AND rationale = %s
                      AND claim_path IS NULL AND claim_value IS NULL
                      AND retracted_at IS NULL AND superseded_at IS NULL
                    ORDER BY recorded_at, id
                    LIMIT 1""",
                (edge_id, owner, t.rationale)).fetchone()
            if claim is None:
                outcome["no live seed claim (retracted by hand?)"] += 1
                continue
            if claim[4] == t.confidence:
                outcome["already right"] += 1
                continue
            new_id = g.add_assertion(
                case_id=t.case_id, edge_id=edge_id,
                assertion=AssertionInput(
                    basis=claim[1], created_by=owner, reliability=claim[2],
                    credibility=claim[3], confidence=t.confidence,
                    rationale=t.rationale, observed_at=claim[5],
                    source_id=claim[6], document_id=claim[7],
                    evidence_id=claim[8], external_ref=claim[9]))
            conn.execute(
                """UPDATE core.assertion
                      SET superseded_at = now(), superseded_by = %s
                    WHERE id = %s AND superseded_at IS NULL""",
                (new_id, claim[0]))
            outcome[f"regraded {claim[4]} to {t.confidence}"] += 1
    return outcome


def _regrade_main(conn, owner, code: str) -> int:
    ids = {}
    for c in (code, *(s for s, _ in SECONDARY)):
        row = conn.execute('SELECT id FROM core."case" WHERE code = %s',
                           (c,)).fetchone()
        if row is None:
            print(f"no case {c}: this estate was not seeded by this script, "
                  f"so there is nothing to regrade", file=sys.stderr)
            return 2
        ids[c] = row[0]
    ties = replay(case_id=ids[code], ids=ids, owner=owner)
    outcome = regrade(conn, owner, ties)
    print(f"  {len(ties)} seeded ties replayed")
    for what, n in sorted(outcome.items()):
        print(f"  {n:4d}  {what}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Seed a LARGE, structured demo estate. Development only.

    .venv\\Scripts\\python scripts\\seed_showcase.py --owner-email you@example.com

The other seeders each demonstrate one subsystem with a handful of rows.
This one exists for the different question "what does it look like with a
real case load in it" — six cases at different classifications and
lifecycle states, and a flagship network big enough that the sociogram and
the analytics have something to say.

## The network is STRUCTURED, not random

A uniformly random graph is the wrong demo. It renders as a hairball, every
centrality comes out flat, community detection finds nothing, and the
key-player set is indistinguishable from the top-n by degree — which is
precisely the claim docs/03 says this tool beats. So the generator builds:

- **six crews** of unequal size, densely tied inside (`VOUCHED_FOR`,
  `MEMBER_OF`) and sparsely between;
- **brokers** that hold few ties but hold them ACROSS crews, so betweenness
  and Burt's constraint disagree with degree — the broker signature;
- **a redundant pair** of brokers bridging the same two crews, so the
  optimal removal set is NOT simply the top two by betweenness;
- **negative ties** (`ACCUSED_SCAM`, `RIVAL_OF`, `DISPUTED_WITH`) placed to
  produce genuinely unbalanced triads and contested dyads;
- **dates spread over thirty months**, so trust decay visibly changes the
  numbers instead of being a parameter with no effect.

## Everything goes through the services

`GraphWriteService` writes every node and edge, so each one carries its
assertion in the same transaction (invariant 1). Nothing here INSERTs into
`core.node` or `core.edge` directly — a seeder that did would be creating
exactly the unfounded graph the model exists to prevent, and it would be
the first thing a reader copied.

Deterministic: `random.Random(SEED)` rather than `secrets`, because a demo
estate you cannot regenerate identically is one you cannot screenshot
twice. Re-running against a case that already exists is refused rather
than doubled.

**Every name, wallet, host and victim below is fiction.**
"""
from __future__ import annotations

import argparse
import os
import random
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

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

CREWS = [
    ("Meridian crew", 18), ("Bastion crew", 15), ("Tessera crew", 13),
    ("Oblique crew", 11), ("Candor crew", 9), ("Umbra crew", 7),
]


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
    args = ap.parse_args()

    os.environ.setdefault("NOCTORNAL_PROHIBITED_CONTENT_POLICY",
                          "DEV-POLICY-0 (development seed, not a real policy)")
    os.environ.setdefault("NOCTORNAL_DESIGNATED_PERSON", "dev operator")

    from noctornal_api.cases import CaseService
    from noctornal_api.db import connect
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.selectors import SelectorStore

    conn = connect()
    row = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (args.owner_email,)).fetchone()
    if row is None:
        print(f"no user {args.owner_email!r}", file=sys.stderr)
        return 2
    owner = row[0]

    cases = CaseService(conn)
    g = GraphWriteService(conn)
    sel = SelectorStore(conn)

    def assertion(rationale: str, *, basis: str = "DIRECT_OBSERVATION",
                  conf: str = "MODERATE", rel: str = "C", cred: str = "3",
                  observed: datetime | None = None) -> AssertionInput:
        return AssertionInput(
            basis=basis, created_by=owner, reliability=rel, credibility=cred,
            confidence=conf, rationale=rationale,
            observed_at=observed or _when())

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
         "hand — the ACH matrix is on this one.", "GREEN", "ACTIVE", []),
        ("OP-HALCYON-25", "Operation Halcyon",
         "Prior year. Dormant pending a disclosure decision.",
         "RED", "DORMANT", ["STEALER-2026"]),
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

    # ------------------------------------------------------- the big network
    used: set[str] = set()
    crew_nodes: list[list] = []
    print("  building crews")
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
                       raw_value=f"{h}@nightmarket.im", node_id=n)
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
                confidence="HIGH" if i == 0 else "MODERATE",
                valid_from=_when(),
                assertion=assertion(
                    f"{h} {'directing' if i == 0 else 'posting as'} "
                    f"{crew_name}"))
        crew_nodes.append(members)

    # Dense INSIDE each crew: this is what makes a community detectable.
    print("  weaving intra-crew ties")
    for members in crew_nodes:
        for a in members:
            for b in RNG.sample(members, min(len(members), RNG.randint(3, 6))):
                if a is b:
                    continue
                g.create_edge(
                    case_id=case_id, edge_type="VOUCHED_FOR",
                    src_node_id=a, dst_node_id=b, created_by=owner,
                    weight=round(RNG.uniform(0.4, 1.0), 2),
                    confidence=RNG.choice(["LOW", "MODERATE", "MODERATE", "HIGH"]),
                    valid_from=_when(),
                    assertion=assertion("vouch posted in the crew's own thread"))

    # Sparse BETWEEN crews, and only through brokers. This is the whole
    # point: degree stays low on these nodes while betweenness goes high.
    print("  placing brokers")
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
                    weight=round(RNG.uniform(0.5, 1.0), 2), confidence="MODERATE",
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
                confidence="MODERATE", valid_from=_when(),
                assertion=assertion("co-present in a private channel"))
    brokers.append(twin)

    # Negative ties: unbalanced triads and contested dyads.
    print("  seeding conflict")
    flat = [n for crew in crew_nodes for n in crew]
    for _ in range(24):
        a, b = RNG.sample(flat, 2)
        g.create_edge(
            case_id=case_id,
            edge_type=RNG.choice(["ACCUSED_SCAM", "DISPUTED_WITH"]),
            src_node_id=a, dst_node_id=b, created_by=owner,
            confidence=RNG.choice(["LOW", "MODERATE"]), valid_from=_when(12),
            assertion=assertion("accusation posted to the arbitration thread",
                                basis="THIRD_PARTY_REPORT", rel="D", cred="4"))

    # Infrastructure, money and victims — so the pane is not all people.
    print("  attaching infrastructure, wallets and victims")
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
                      created_by=owner, confidence="MODERATE",
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
                      created_by=owner, confidence="LOW", valid_from=_when(20),
                      assertion=assertion("address posted by that handle"))
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
                      created_by=owner, confidence="MODERATE",
                      valid_from=_when(10),
                      assertion=assertion("access advertised then withdrawn "
                                          "within a day of the leak post"))

    # Smaller networks in the other live cases, so they are not empty shells.
    print("  populating the secondary cases")
    for code, size in (("OP-KESTREL-26", 22), ("OP-CORVID-26", 30)):
        cid = ids[code]
        if conn.execute("SELECT count(*) FROM core.node WHERE case_id = %s",
                        (cid,)).fetchone()[0] > 5:
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
                g.create_edge(
                    case_id=cid, edge_type="COMMUNICATES_WITH",
                    src_node_id=a, dst_node_id=b, created_by=owner,
                    classification="GREEN" if code == "OP-KESTREL-26" else "AMBER",
                    confidence=RNG.choice(["LOW", "MODERATE"]),
                    valid_from=_when(14),
                    assertion=assertion("replied in the same thread"))

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


if __name__ == "__main__":
    raise SystemExit(main())

"""Co-participation: the bipartite projection docs/03 asked for.

Identities participate in conversations (docs/10); this projects that to a one-mode network with
Newman weighting, dividing by room size, so a 500-member forum does not create a spurious clique
(docs/03). It is the conversation half of the fix `analytics._mode_warning` records as open.

It is a projection, not edges in the graph. `projections.PRESETS` excludes co-participation from the
Communication preset because it is not an observation: two people in the same 40-person channel have
not been observed communicating, and a stored edge would be indistinguishable from an observed one
(invariant 4). So this returns a computed network marked `is_inferred`, which a caller may render
dashed and feed to metrics ONLY by opting in. Nothing here writes `core.edge`.

Newman weighting divides each co-participation by (room size - 1), so a 500-member room contributes
1/499 per pair. It does not fix the combinatorial cost (a 5,000-member channel still yields 12.5
million near-zero pairs), so rooms above `max_room_size` are excluded outright and the exclusion is
reported in the result: a cap that silently drops data looks complete. Two restrictive defaults,
both reversible: unresolved handles are excluded (`comms.participant` deliberately does not resolve
most group members, and promoting them to vertices would manufacture actors) and incidental
participants are excluded (docs/08, docs/16 L4: a third party in a group channel is not a subject).
Both counts are reported either way, so an analyst can tell a sparse network from a filtered one, as
with `projections.withheld` (docs/14 U2).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from itertools import combinations
from uuid import UUID

import psycopg

#: Rooms larger than this are excluded from the projection entirely.
#: Newman weighting makes a big room's pairs individually negligible; it
#: does not stop there being n*(n-1)/2 of them.
DEFAULT_MAX_ROOM_SIZE = 50

WEIGHT_NEWMAN = "NEWMAN"
WEIGHT_COUNT = "COUNT"


class CoParticipationError(Exception):
    pass


@dataclass(frozen=True)
class CoParticipationParams:
    """The parameters that make this number reproducible.

    docs/03: show the projection parameters next to the results, always. Each changes every weight,
    so a result quoted without them is not a finding.
    """

    case_id: UUID
    #: Drop pairs seen together fewer times than this. 1 keeps everything.
    min_shared: int = 1
    max_room_size: int = DEFAULT_MAX_ROOM_SIZE
    #: docs/08: a third party in a group channel is not a subject.
    include_incidental: bool = False
    #: Promoting unresolved handles to vertices manufactures actors out of
    #: a member list.
    include_unresolved: bool = False
    weighting: str = WEIGHT_NEWMAN
    #: Restrict to conversations obtained a particular way. Useful because
    #: PERSONA_PARTY and OPEN_GROUP are legally distinct from the rest
    #: (docs/16 L4) and an analyst may need to show a picture built only
    #: from one of them.
    provenance_classes: tuple[str, ...] = ()
    since: datetime | None = None
    until: datetime | None = None

    def describe(self) -> dict:
        return {
            "min_shared": self.min_shared,
            "max_room_size": self.max_room_size,
            "include_incidental": self.include_incidental,
            "include_unresolved": self.include_unresolved,
            "weighting": self.weighting,
            "provenance_classes": list(self.provenance_classes) or None,
            "since": self.since.isoformat() if self.since else None,
            "until": self.until.isoformat() if self.until else None,
            "note": ("weights are NOT comparable across different parameters: "
                     "Newman weighting divides by room size, so changing "
                     "max_room_size changes every weight in the network"),
        }


class CoParticipationService:
    """Projects `comms.conversation` x `comms.participant` to one mode.

    Takes the caller's clearance the way `GraphService` does, because a
    conversation can be classified above its case and an edge derived from
    one the caller cannot see would disclose it.
    """

    def __init__(self, conn: psycopg.Connection, *, clearance: str,
                 compartments: frozenset[str]):
        self._c = conn
        self._clearance = clearance
        self._comp = list(compartments)

    def project(self, p: CoParticipationParams) -> dict:
        if p.weighting not in {WEIGHT_NEWMAN, WEIGHT_COUNT}:
            raise CoParticipationError(f"unknown weighting {p.weighting!r}")
        if p.min_shared < 1:
            raise CoParticipationError("min_shared must be at least 1")
        if p.max_room_size < 2:
            raise CoParticipationError(
                "a room needs at least two participants to project anything")

        rows = self._c.execute(
            """SELECT c.id, c.platform_key, c.is_group, c.provenance_class,
                      p.observed_handle, p.identity_node_id, p.is_incidental,
                      n.label
                 FROM comms.conversation c
                 JOIN comms.participant p ON p.conversation_id = c.id
                 LEFT JOIN core.node n
                        ON n.id = p.identity_node_id
                       AND n.deleted_at IS NULL
                       AND n.merged_into_id IS NULL
                       -- An identity the caller cannot see must not become
                       -- a labelled vertex. The row still counts toward the
                       -- coverage numbers below.
                       AND n.classification <= %s::core.tlp
                       AND n.compartments <@ %s
                WHERE c.case_id = %s
                  -- A conversation can be classified above its case.
                  AND c.classification <= %s::core.tlp
                  AND c.compartments <@ %s
                  AND (%s::text[] IS NULL
                       OR c.provenance_class = ANY(%s))
                  AND (%s::timestamptz IS NULL OR c.last_message_at >= %s)
                  AND (%s::timestamptz IS NULL OR c.started_at <= %s)""",
            (self._clearance, self._comp, p.case_id,
             self._clearance, self._comp,
             list(p.provenance_classes) or None,
             list(p.provenance_classes) or None,
             p.since, p.since, p.until, p.until)).fetchall()

        # -- group by conversation ---------------------------------------
        rooms: dict[UUID, dict] = {}
        for (conv_id, platform, is_group, provenance, handle, identity,
             incidental, label) in rows:
            room = rooms.setdefault(conv_id, {
                "platform": platform, "is_group": is_group,
                "provenance": provenance, "members": [], "raw_size": 0})
            room["raw_size"] += 1
            room["members"].append({
                "handle": handle, "identity": identity,
                "incidental": incidental, "label": label})

        excluded_incidental = 0
        excluded_unresolved = 0
        excluded_invisible = 0
        oversized: list[dict] = []
        singleton_rooms = 0
        considered_rooms = 0

        vertices: dict[str, dict] = {}
        pair_weight: dict[tuple[str, str], float] = {}
        pair_rooms: dict[tuple[str, str], int] = {}

        for conv_id, room in rooms.items():
            eligible = []
            for member in room["members"]:
                if member["incidental"] and not p.include_incidental:
                    excluded_incidental += 1
                    continue
                if member["identity"] is None:
                    if not p.include_unresolved:
                        excluded_unresolved += 1
                        continue
                    key = f"handle:{member['handle']}"
                    vertices.setdefault(key, {
                        "key": key, "kind": "HANDLE",
                        "label": member["handle"], "node_id": None,
                        "note": ("not resolved to an identity: this vertex is "
                                 "a handle, and two handles may be one person "
                                 "or one handle may be several")})
                else:
                    if member["label"] is None:
                        # Resolved to a node this caller may not see.
                        excluded_invisible += 1
                        continue
                    key = f"node:{member['identity']}"
                    vertices.setdefault(key, {
                        "key": key, "kind": "IDENTITY",
                        "label": member["label"],
                        "node_id": str(member["identity"]), "note": ""})
                eligible.append(key)

            # Deduplicate: one person can appear under two handles that
            # both resolve to the same identity, and a self-pair is not a
            # tie.
            eligible = sorted(set(eligible))
            size = len(eligible)
            # THE denominator, and the cap, are properties of the ROOM, not of how much of it this
            # caller can see. Computed from `size`, the count left after incidental, unresolved and
            # invisible participants are dropped, a 500-member channel with two resolved identities
            # would give size == 2, so 1/(size-1) == 1.0 and two people who sat in the same open
            # channel would score exactly as high as a two-party DM (a 499x overstatement), and the
            # room would also escape the oversize cap and never appear in `oversized`. Newman
            # divides by the size of the GROUP: how many members we resolved is a fact about our
            # coverage, and coverage must not inflate a tie.
            room_size = room["raw_size"]
            if size < 2:
                singleton_rooms += 1
                continue
            if room_size > p.max_room_size:
                oversized.append({
                    "conversation_id": str(conv_id),
                    "platform": room["platform"],
                    "participants": room_size,
                    "projectable_participants": size,
                    "provenance_class": room["provenance"]})
                continue

            considered_rooms += 1
            # Newman: 1/(n-1) per pair over the ROOM's size, so a big
            # room's pairs are individually negligible rather than equal
            # to a DM.
            contribution = (1.0 / max(1, room_size - 1)
                            if p.weighting == WEIGHT_NEWMAN else 1.0)
            for a, b in combinations(eligible, 2):
                pair = (a, b)
                pair_weight[pair] = pair_weight.get(pair, 0.0) + contribution
                pair_rooms[pair] = pair_rooms.get(pair, 0) + 1

        edges = [
            {
                "src": a, "dst": b,
                "weight": round(weight, 6),
                "shared_conversations": pair_rooms[(a, b)],
                # Invariant 4. This is derived, it renders dashed, and it
                # stays out of metrics unless a projection opts in.
                "is_inferred": True,
                "inference_method": f"co_participation/{p.weighting}",
            }
            for (a, b), weight in sorted(pair_weight.items())
            if pair_rooms[(a, b)] >= p.min_shared
        ]
        used = {e["src"] for e in edges} | {e["dst"] for e in edges}

        return {
            "projection": {"case_id": str(p.case_id), **p.describe()},
            # Only vertices that ended up in a tie: an isolate would be an artefact of the filters,
            # not a finding, and would sit in the denominator of every density and percentile.
            "nodes": [vertices[k] for k in sorted(used)],
            "edges": edges,
            "coverage": {
                "conversations_seen": len(rooms),
                "conversations_projected": considered_rooms,
                "conversations_too_small": singleton_rooms,
                "conversations_oversized": len(oversized),
                "oversized": oversized,
                "participants_excluded_incidental": excluded_incidental,
                "participants_excluded_unresolved": excluded_unresolved,
                "participants_excluded_not_visible": excluded_invisible,
                "note": (
                    "Every exclusion above is REPORTED rather than applied "
                    "silently, because an analyst who cannot tell a sparse "
                    "network from a filtered one draws confident conclusions "
                    "from an incomplete picture."),
            },
            "reading": (
                "Co-participation is a DERIVED tie: these people were in the "
                "same conversation, which is not the same as having been "
                "observed talking to each other. Newman weighting divides "
                "each tie by room size so a large channel cannot manufacture "
                "a clique, but a weak tie from one big room is still a weak "
                "tie and not evidence of a relationship."),
        }

    def rooms_excluded_for_size(self, p: CoParticipationParams) -> list[dict]:
        """The oversized rooms, on their own.

        Separate because it is the answer to "why is this network smaller
        than I expected", and an analyst asking that should not have to
        read a projection payload to find out.
        """
        return self.project(p)["coverage"]["oversized"]

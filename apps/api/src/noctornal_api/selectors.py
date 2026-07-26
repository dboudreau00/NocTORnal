"""Selector storage — the entity-resolution join key.

A selector is an atomic observable (a jabber, a PGP fingerprint, a BTC
address). This store is the bridge between the ontology package's
normalisers (the ONE source of truth for canonical form) and core.selector:
every write runs the raw value through noctornal_ontology.normalise, so the
norm_value the database matches on can never drift from the ontology
definition. Two observations of the same real-world identifier therefore
collide on (case_id, selector_type, norm_value) and are counted, not
duplicated.

Scope (Phase 1, docs/09 "Selector storage, normalisers per type,
exact-match lookup"):
- record: normalise + upsert with observation counting.
- find: normalise + exact within-case lookup (the join key).
- link_to_node: attribute a selector to its owning node. Because a
  selector is unique per case, attributing a STRONG selector that already
  belongs to a different node is exactly a merge lead — it raises
  SelectorOwnerConflict so the human sees it, rather than silently
  repointing (docs/01: strong selectors are the merge evidence; the merge
  itself, reversible + step-up + dual-control, is Phase 6). force=True
  repoints deliberately.
- pivots: cross-case matches, but ONLY over case ids the caller already
  has access to (passed in), so the undecided cross-case-disclosure policy
  (open question 5) cannot leak through this primitive. Cross-case is also
  where "same observable, different owners" is genuinely expressible — the
  per-case unique constraint makes it impossible within one case.

core.selector.node_id is observation bookkeeping — "this observable was
attributed to this node" — NOT an asserted graph edge. To make ownership a
graph fact that carries provenance and renders in the sociogram, create a
CONTROLS edge via GraphWriteService (which requires an assertion). Keeping
the two distinct is why core.selector is not covered by the invariant-1
triggers: it is the observable index, not a graph element.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg

from noctornal_ontology import SELECTOR_TYPES, normalise

# Types strong enough to be merge evidence (docs/01). Nicknames/handles are
# deliberately excluded — the "admin/support/shop" reuse trap is a weak-type
# problem, and strong-only candidate surfacing sidesteps it.
_STRONG_TYPES = frozenset(s.key for s in SELECTOR_TYPES if s.is_strong)
_VALID_TYPES = frozenset(s.key for s in SELECTOR_TYPES)


class SelectorError(Exception):
    """A selector operation was given an unknown type or bad input."""


class SelectorOwnerConflict(SelectorError):
    """A strong selector already attributed to a different node — a merge
    lead. Carries the existing owner so the caller can surface the
    candidate. Repoint deliberately with link_to_node(..., force=True)."""
    def __init__(self, selector_id: UUID, existing_owner: UUID):
        self.selector_id = selector_id
        self.existing_owner = existing_owner
        super().__init__(
            f"selector {selector_id} is already attributed to node "
            f"{existing_owner} (strong selector — possible merge)"
        )


@dataclass(frozen=True)
class SelectorRow:
    id: UUID
    case_id: UUID
    selector_type: str
    raw_value: str
    norm_value: str
    node_id: UUID | None
    first_seen: datetime | None
    last_seen: datetime | None
    observation_cnt: int


class SelectorStore:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def _norm(self, selector_type: str, raw_value: str) -> str:
        if selector_type not in _VALID_TYPES:
            raise SelectorError(f"unknown selector type: {selector_type!r}")
        return normalise(selector_type, raw_value)

    def record(
        self,
        *,
        case_id: UUID,
        selector_type: str,
        raw_value: str,
        node_id: UUID | None = None,
        observed_at: datetime | None = None,
    ) -> SelectorRow:
        """Upsert an observation. A repeat of the same normalised value in
        the same case bumps observation_cnt and last_seen rather than
        inserting a duplicate; a node link fills an empty owner but never
        overwrites an existing one (re-attribution is a deliberate, audited
        act, not a silent side effect of re-observation)."""
        norm = self._norm(selector_type, raw_value)
        # A node_id must belong to THIS case: an unchecked value either
        # violates the FK (a 500 to the caller) or, if it names a node in
        # another case, silently attributes an observable across a case
        # boundary.
        if node_id is not None:
            owned = self._c.execute(
                "SELECT 1 FROM core.node WHERE id = %s AND case_id = %s",
                (node_id, case_id),
            ).fetchone()
            if owned is None:
                raise SelectorError("node_id does not belong to this case")
        row = self._c.execute(
            """INSERT INTO core.selector
                   (case_id, selector_type, raw_value, norm_value, node_id,
                    first_seen, last_seen, observation_cnt)
               VALUES (%s, %s, %s, %s, %s, %s, %s, 1)
               ON CONFLICT (case_id, selector_type, norm_value) DO UPDATE
                   SET observation_cnt = core.selector.observation_cnt + 1,
                       last_seen = GREATEST(core.selector.last_seen, EXCLUDED.last_seen),
                       node_id = COALESCE(core.selector.node_id, EXCLUDED.node_id)
               RETURNING id, case_id, selector_type, raw_value, norm_value,
                         node_id, first_seen, last_seen, observation_cnt""",
            (case_id, selector_type, raw_value, norm, node_id,
             observed_at, observed_at),
        ).fetchone()
        return _row(row)

    def find(
        self, *, case_id: UUID, selector_type: str, raw_value: str
    ) -> SelectorRow | None:
        """Exact-match lookup within a case: normalise the query the same
        way it was stored, then match on the unique key."""
        norm = self._norm(selector_type, raw_value)
        row = self._c.execute(
            """SELECT id, case_id, selector_type, raw_value, norm_value,
                      node_id, first_seen, last_seen, observation_cnt
                 FROM core.selector
                WHERE case_id = %s AND selector_type = %s AND norm_value = %s""",
            (case_id, selector_type, norm),
        ).fetchone()
        return _row(row) if row else None

    def link_to_node(
        self, selector_id: UUID, node_id: UUID, *, force: bool = False
    ) -> None:
        """Attribute a selector to its owning node. If it already belongs
        to a DIFFERENT node and the type is strong, this is a merge lead:
        raise SelectorOwnerConflict rather than silently repointing. Weak
        selectors (nicknames) repoint freely — a shared 'admin' handle is
        not evidence. force=True repoints a strong selector deliberately."""
        row = self._c.execute(
            "SELECT selector_type, node_id FROM core.selector WHERE id = %s",
            (selector_id,),
        ).fetchone()
        if row is None:
            raise SelectorError(f"selector {selector_id} not found")
        sel_type, current_owner = row
        if (not force and current_owner is not None
                and current_owner != node_id and sel_type in _STRONG_TYPES):
            raise SelectorOwnerConflict(selector_id, current_owner)
        self._c.execute(
            "UPDATE core.selector SET node_id = %s WHERE id = %s",
            (node_id, selector_id),
        )

    def pivots(
        self,
        *,
        selector_type: str,
        raw_value: str,
        allowed_case_ids: list[UUID],
    ) -> list[SelectorRow]:
        """Cross-case matches for the same observable, restricted to cases
        the caller may already see. Requiring allowed_case_ids means this
        primitive cannot leak a match in a case the user has no access to
        (open question 5) — the access-gated pivot endpoint will supply the
        set the five-part gate has cleared."""
        if not allowed_case_ids:
            return []
        norm = self._norm(selector_type, raw_value)
        rows = self._c.execute(
            """SELECT id, case_id, selector_type, raw_value, norm_value,
                      node_id, first_seen, last_seen, observation_cnt
                 FROM core.selector
                WHERE selector_type = %s AND norm_value = %s
                  AND case_id = ANY(%s)""",
            (selector_type, norm, list(allowed_case_ids)),
        ).fetchall()
        return [_row(r) for r in rows]


def _row(r) -> SelectorRow:
    return SelectorRow(
        id=r[0], case_id=r[1], selector_type=r[2], raw_value=r[3],
        norm_value=r[4], node_id=r[5], first_seen=r[6], last_seen=r[7],
        observation_cnt=r[8],
    )

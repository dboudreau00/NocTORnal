"""Selector storage — the entity-resolution join key.

A selector is an atomic observable (a jabber, a PGP fingerprint, a BTC
address). This store is the bridge between the ontology package's
normalisers (the ONE source of truth for canonical form) and core.selector:
every write runs the raw value through noctornal_ontology.normalise, so the
norm_value the database matches on can never drift from the ontology
definition. Two observations of the same real-world identifier therefore
collide on (case_id, selector_type, norm_value, classification,
compartments) and are counted, not duplicated. Since 0134 the labels are
part of the key: a row carries its owner's labels (the floor when it has no
owner), and a reader sees only the rows within their own ceiling, so a value
held above a caller is indistinguishable from one held nowhere
(`record_for_reader`, `find_for_reader`).

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

from noctornal_ontology import SELECTOR_TYPES, normalise, refusal

# Types strong enough to be merge evidence (docs/01). Nicknames/handles are
# deliberately excluded — the "admin/support/shop" reuse trap is a weak-type
# problem, and strong-only candidate surfacing sidesteps it.
_STRONG_TYPES = frozenset(s.key for s in SELECTOR_TYPES if s.is_strong)
_VALID_TYPES = frozenset(s.key for s in SELECTOR_TYPES)

#: The label of an observation nobody has attributed (0134): the lowest, so
#: every reader of the case can read it and an entity attributed later never
#: narrows it.
_FLOOR_CLASSIFICATION = "CLEAR"

_COLUMNS = ("id, case_id, selector_type, raw_value, norm_value, node_id, "
            "first_seen, last_seen, observation_cnt")
_COLUMNS_S = ("s.id, s.case_id, s.selector_type, s.raw_value, s.norm_value, "
              "s.node_id, s.first_seen, s.last_seen, s.observation_cnt")

#: The rows of one value in one case that a caller may read (0134): the
#: row's own labels within their ceiling and, when it has an owner, the owner
#: within it too, so a row written below its owner by a writer that skipped
#: the labels trigger is still never shown. Parameters: case, type, norm,
#: clr (clearance name), held (compartments).
_READABLE = """s.classification <= %(clr)s::core.tlp
                   AND s.compartments <@ %(held)s::text[]
                   AND (s.node_id IS NULL OR EXISTS (
                        SELECT 1 FROM core.node o
                         WHERE o.id = s.node_id
                           AND o.classification <= %(clr)s::core.tlp
                           AND o.compartments <@ %(held)s::text[]))"""
_VISIBLE = ("""s.case_id = %(case)s AND s.selector_type = %(type)s
                   AND s.norm_value = %(norm)s
                   AND """ + _READABLE)
#: One observation at given labels: counted when the key is held, unless the
#: row there is owned by an entity above the caller, which is answered with no
#: row at all (the WHERE of the DO UPDATE) rather than with what it holds.
_UPSERT = f"""INSERT INTO core.selector
        (case_id, selector_type, raw_value, norm_value, node_id,
         classification, compartments, first_seen, last_seen, observation_cnt)
    VALUES (%(case)s, %(type)s, %(raw)s, %(norm)s, %(node)s,
            %(cls)s::core.tlp, %(comps)s::text[], %(seen)s, %(seen)s, 1)
    ON CONFLICT (case_id, selector_type, norm_value, classification,
                 compartments)
    DO UPDATE SET
        observation_cnt = core.selector.observation_cnt + 1,
        last_seen = GREATEST(core.selector.last_seen, EXCLUDED.last_seen),
        node_id = COALESCE(core.selector.node_id, EXCLUDED.node_id)
        WHERE core.selector.node_id IS NULL OR EXISTS (
            SELECT 1 FROM core.node o
             WHERE o.id = core.selector.node_id
               AND o.classification <= %(clr)s::core.tlp
               AND o.compartments <@ %(held)s::text[])
    RETURNING {_COLUMNS}"""
#: Which of several readable rows answers: the strictest, then the oldest.
_STRICTEST = ("s.classification DESC, cardinality(s.compartments) DESC, "
              "s.created_at, s.id")


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
            f"{existing_owner} (strong selector: possible merge)"
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
        norm = normalise(selector_type, raw_value)
        if not norm.strip():
            # An empty canonical form is not a value, and storing it as one
            # is how unrelated observations collide: '' is a value to
            # UNIQUE (case_id, selector_type, norm_value), so every
            # observation that normalised to nothing shared ONE row -- and
            # on a strong type that row is a merge lead between strangers.
            # Refused with the ontology's own reason (a bare positive
            # Telegram id, refused since 2026-09-11, is the case that made
            # this explicit; `comms._durable_or_none` closed the same hole
            # on its side earlier).
            raise SelectorError(refusal(selector_type, raw_value))
        return norm

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
        act, not a silent side effect of re-observation).

        The row is the observation AT its owner's labels (the floor when it
        has none): 0134's trigger sets them, so "the same value" here means
        the same value at the same labels. A request's caller records through
        `record_for_reader`, which never meets a row above them."""
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
               ON CONFLICT (case_id, selector_type, norm_value,
                            classification, compartments) DO UPDATE
                   SET observation_cnt = core.selector.observation_cnt + 1,
                       last_seen = GREATEST(core.selector.last_seen, EXCLUDED.last_seen),
                       node_id = COALESCE(core.selector.node_id, EXCLUDED.node_id)
               RETURNING id, case_id, selector_type, raw_value, norm_value,
                         node_id, first_seen, last_seen, observation_cnt""",
            (case_id, selector_type, raw_value, norm, node_id,
             observed_at, observed_at),
        ).fetchone()
        return _row(row)

    def record_for_reader(
        self,
        *,
        case_id: UUID,
        selector_type: str,
        raw_value: str,
        clearance: str,
        compartments,
        node_id: UUID | None = None,
        observed_at: datetime | None = None,
    ) -> tuple[SelectorRow, str]:
        """`record`, for a request whose caller has `clearance` and
        `compartments`: (the row the sighting was counted on, the canonical
        value). Always a row, and always one the caller may read.

        graph-selector-record-oracle, http_ui-002 and rls-2 (2026-10-03,
        both rounds). `record`'s ON CONFLICT DO UPDATE met the one row for a
        value whoever owned it, bumped it and handed back its owner, so
        POST /selectors told an AMBER analyst which RED entity held an
        email. The first fix answered such a value as a first sighting and
        stored nothing, which left the oracle one request away (a repeat
        post, a read, a second entity, the id as a merge's basis all told a
        held value from an unheld one). Since 0134 a row is keyed by its
        labels as well, so a value held above the caller is not among the
        rows they can read and what they record is simply their own row:

        - named (`node_id`): the sighting is stored at the labels of that
          entity, which the caller must be able to read. Another observation
          of the value at those labels is the row that is counted; its owner
          stays (re-attribution is deliberate, never a side effect).
        - bare: the strictest row the caller can read is counted, and when
          there is none the sighting is stored at the floor (CLEAR, no
          compartments), which every reader of the case can read. Nothing a
          caller records is ever narrowed by an entity attributed later:
          that entity gets a row of its own at its own labels.

        A row above the caller is never read, counted or written."""
        norm = self._norm(selector_type, raw_value)
        held = sorted(compartments)
        if node_id is not None:
            owner = self._c.execute(
                """SELECT classification, compartments FROM core.node
                    WHERE id = %s AND case_id = %s
                      AND classification <= %s::core.tlp
                      AND compartments <@ %s::text[]""",
                (node_id, case_id, clearance, held),
            ).fetchone()
            if owner is None:
                raise SelectorError("node_id does not belong to this case")
            labels = (owner[0], list(owner[1]))
        else:
            target = self._c.execute(
                f"""SELECT s.id FROM core.selector s
                     WHERE {_VISIBLE}
                     ORDER BY {_STRICTEST} LIMIT 1""",
                {"case": case_id, "type": selector_type, "norm": norm,
                 "clr": clearance, "held": held},
            ).fetchone()
            if target is not None:
                row = self._c.execute(
                    f"""UPDATE core.selector
                           SET observation_cnt = observation_cnt + 1,
                               last_seen = GREATEST(last_seen, %s)
                         WHERE id = %s
                     RETURNING {_COLUMNS}""",
                    (observed_at, target[0]),
                ).fetchone()
                return _row(row), norm
            labels = (_FLOOR_CLASSIFICATION, [])
        row = self._c.execute(
            _UPSERT,
            {"case": case_id, "type": selector_type, "raw": raw_value,
             "norm": norm, "node": node_id, "cls": labels[0],
             "comps": labels[1], "seen": observed_at, "clr": clearance,
             "held": held},
        ).fetchone()
        if row is None:
            # The key is held by a row whose owner is above the caller: a row
            # written below its owner's labels, which the labels trigger
            # makes impossible and a restore with triggers off could leave.
            # Counted on nowhere and told to nobody (fail closed).
            raise SelectorError("that selector could not be recorded")
        return _row(row), norm

    def find_for_reader(
        self, *, case_id: UUID, selector_type: str, raw_value: str,
        clearance: str, compartments,
    ) -> SelectorRow | None:
        """The strictest row of this value the caller may read, or None.

        A row above the caller, or owned by an entity above them, is not
        among them (graph-selector-record-oracle, 2026-10-03): the answer is
        what it would be if the value were held nowhere, because the rows
        the caller records are their own (`record_for_reader`)."""
        norm = self._norm(selector_type, raw_value)
        row = self._c.execute(
            f"""SELECT {_COLUMNS_S} FROM core.selector s
                 WHERE {_VISIBLE}
                 ORDER BY {_STRICTEST} LIMIT 1""",
            {"case": case_id, "type": selector_type, "norm": norm,
             "clr": clearance, "held": sorted(compartments)},
        ).fetchone()
        return _row(row) if row else None

    def readable(
        self, selector_id: UUID, *, case_id: UUID, clearance: str, compartments,
    ) -> bool:
        """Whether this row is one of this case's that the caller may read.
        A route that is handed a selector id (a merge's basis) asks this, so
        an id of another case's row, of a row above the caller and of no row
        at all are one answer."""
        return self._c.execute(
            f"""SELECT 1 FROM core.selector s
                 WHERE s.id = %(id)s AND s.case_id = %(case)s AND {_READABLE}""",
            {"id": selector_id, "case": case_id, "clr": clearance,
             "held": sorted(compartments)},
        ).fetchone() is not None

    def other_holder(
        self, *, case_id: UUID, selector_type: str, raw_value: str,
        excluding: UUID, clearance: str, compartments,
    ) -> UUID | None:
        """A live entity other than `excluding` that holds this value and
        that the caller may read, or None: the merge lead a new entity of the
        same value is told about. Only rows the caller may read are asked, so
        a holder above them is never named and, by the same token, never
        missed in a way they could tell."""
        norm = self._norm(selector_type, raw_value)
        row = self._c.execute(
            f"""SELECT s.node_id FROM core.selector s
                  JOIN core.node h ON h.id = s.node_id
                 WHERE {_VISIBLE}
                   AND s.node_id <> %(excluding)s AND h.deleted_at IS NULL
                 ORDER BY {_STRICTEST} LIMIT 1""",
            {"case": case_id, "type": selector_type, "norm": norm,
             "clr": clearance, "held": sorted(compartments),
             "excluding": excluding},
        ).fetchone()
        return row[0] if row else None

    def find(
        self, *, case_id: UUID, selector_type: str, raw_value: str
    ) -> SelectorRow | None:
        """Exact-match lookup within a case: normalise the query the same
        way it was stored, then match on the unique key."""
        norm = self._norm(selector_type, raw_value)
        row = self._c.execute(
            """SELECT id, case_id, selector_type, raw_value, norm_value,
                      node_id, first_seen, last_seen, observation_cnt
                 FROM core.selector s
                WHERE case_id = %s AND selector_type = %s AND norm_value = %s
                ORDER BY classification DESC, cardinality(compartments) DESC,
                         created_at, id
                LIMIT 1""",
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

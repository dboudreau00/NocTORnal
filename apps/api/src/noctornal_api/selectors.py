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

from noctornal_ontology import SELECTOR_TYPES, normalise, refusal
from noctornal_ontology.normalisers import redact_url_credentials

# Types strong enough to be merge evidence (docs/01). Nicknames/handles are
# deliberately excluded — the "admin/support/shop" reuse trap is a weak-type
# problem, and strong-only candidate surfacing sidesteps it.
_STRONG_TYPES = frozenset(s.key for s in SELECTOR_TYPES if s.is_strong)
_VALID_TYPES = frozenset(s.key for s in SELECTOR_TYPES)
#: Types normalised as URLs, whose raw value can carry a password or token.
_URL_NORMALISED = {s.key: s.normaliser == "url_norm" for s in SELECTOR_TYPES}

#: Entity types whose label IS a selector value, so the index follows the
#: label (graph-selector-index-drift, 2026-10-03). The same set as
#: `routers.graph.SELECTOR_NODE_TYPES`, which the create form checks.
LABEL_IS_SELECTOR = frozenset({"SELECTOR", "COMMS_ACCOUNT", "WALLET"})


#: Why a link with a credential is not taken as a selector label
#: (graph-url-selector-keeps-credentials, 2026-10-03).
CREDENTIAL_REFUSAL = ("This link carries a password, token or key, which the "
                      "graph does not record. Enter it without them.")


def is_url_type(selector_type: str | None) -> bool:
    """Whether a selector type is normalised as a URL."""
    return bool(_URL_NORMALISED.get(selector_type or ""))


def carries_credential(selector_type: str | None, value: object) -> bool:
    """Whether a value of a URL selector type carries userinfo or a
    password, token or key parameter, which a label must never hold: it is
    printed on the graph, in search and in reports."""
    return (bool(_URL_NORMALISED.get(selector_type or ""))
            and isinstance(value, str)
            and redact_url_credentials(value) != value)


def label_is_selector(node_type: str | None, attrs: dict | None) -> bool:
    """Whether an entity's label IS a selector value: its type says so, or
    it was accepted from a proposal that named the selector type (a
    capture's SELECTOR, a sample's INFRA or WALLET)."""
    return (node_type in LABEL_IS_SELECTOR
            or bool((attrs or {}).get("selector_type")))


def _norm_or_empty(selector_type: str, raw_value: str) -> str:
    """The canonical form, or '' when the normaliser refuses the value."""
    try:
        return normalise(selector_type, raw_value)
    except (KeyError, ValueError, TypeError):
        return ""


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
        count: bool = True,
    ) -> SelectorRow:
        """Upsert an observation. A repeat of the same normalised value in
        the same case bumps observation_cnt and last_seen rather than
        inserting a duplicate; a node link fills an empty owner but never
        overwrites an existing one (re-attribution is a deliberate, audited
        act, not a silent side effect of re-observation).

        Two exceptions, both graph-selector-index-drift (2026-10-03). An
        owner that has been RETIRED is not an owner: the entity "should
        never have been in the case file", so a live entity recording the
        same value takes the row over (the retired one kept it before, and
        re-creating an entity after retiring a mistyped one recorded
        nothing against it). The check is a positive EXISTS on a retired
        row, so under row security an owner the caller cannot see is never
        taken over. And `count=False` re-points an index entry without
        counting an observation, for a label that changed rather than was
        seen again (`follow_label`)."""
        norm = self._norm(selector_type, raw_value)
        # A URL's userinfo or token is a secret, never an identifier: the
        # index keeps the value as written, so it keeps it without them
        # (graph-url-selector-keeps-credentials, 2026-10-03).
        if _URL_NORMALISED.get(selector_type):
            raw_value = redact_url_credentials(raw_value)
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
                   SET observation_cnt = core.selector.observation_cnt + %s,
                       last_seen = GREATEST(core.selector.last_seen, EXCLUDED.last_seen),
                       node_id = CASE
                         WHEN core.selector.node_id IS NULL THEN EXCLUDED.node_id
                         WHEN EXCLUDED.node_id IS NOT NULL AND EXISTS (
                              SELECT 1 FROM core.node r
                               WHERE r.id = core.selector.node_id
                                 AND r.deleted_at IS NOT NULL)
                           THEN EXCLUDED.node_id
                         ELSE core.selector.node_id END
               RETURNING id, case_id, selector_type, raw_value, norm_value,
                         node_id, first_seen, last_seen, observation_cnt""",
            (case_id, selector_type, raw_value, norm, node_id,
             observed_at, observed_at, 1 if count else 0),
        ).fetchone()
        return _row(row)

    def follow_label(
        self,
        *,
        case_id: UUID,
        node_id: UUID,
        old_label: str,
        new_label: str,
        declared_type: str | None = None,
        strict: bool = True,
    ) -> UUID | None:
        """Keep the index on the label of an entity whose label IS its
        selector, when the label changes, and return another live entity
        that already holds the new value (a merge lead), or None.

        graph-selector-index-drift (2026-10-03). Only `create_node` wrote
        the index, so a corrected label left it on the old value, which
        then pointed at an entity that no longer carried it, while the new
        value was unindexed: selector search missed the live entity and a
        strong duplicate was never surfaced.

        The selector types followed are those of the entity's own rows
        whose value is its OLD label, plus `declared_type` (a Triage
        entity's `attrs.selector_type`, whose value was never indexed
        before this date). Rows the entity holds for any other value (a
        selector recorded against it by hand) are not touched. For each
        type, the old value's row is released and the new value recorded
        against the entity without counting an observation.

        `strict` refuses a new label that is not a selector of that type,
        with the ontology's own reason, as `create_node` does. A
        retraction that restores an older label passes False: the label
        was accepted under the rules of its day, and a withdrawn source
        must never be kept live because a rule has since tightened, so
        the index then simply holds nothing for it."""
        types: list[str] = []
        for sel_type, norm in self._c.execute(
                """SELECT selector_type, norm_value FROM core.selector
                    WHERE case_id = %s AND node_id = %s""",
                (case_id, node_id)).fetchall():
            if sel_type not in types and _norm_or_empty(sel_type, old_label) == norm:
                types.append(sel_type)
        if declared_type in _VALID_TYPES and declared_type not in types:
            types.append(declared_type)
        if not types:
            types = self._types_held_by_others(case_id, old_label)
        lead = None
        for sel_type in types:
            old_norm = _norm_or_empty(sel_type, old_label)
            new_norm = _norm_or_empty(sel_type, new_label)
            if not new_norm.strip() and strict:
                raise SelectorError(refusal(sel_type, new_label))
            if strict and carries_credential(sel_type, new_label):
                raise SelectorError(CREDENTIAL_REFUSAL)
            if old_norm and old_norm != new_norm:
                self._c.execute(
                    """UPDATE core.selector SET node_id = NULL
                        WHERE case_id = %s AND node_id = %s
                          AND selector_type = %s AND norm_value = %s""",
                    (case_id, node_id, sel_type, old_norm))
            if not new_norm.strip():
                continue
            row = self.record(case_id=case_id, selector_type=sel_type,
                              raw_value=new_label, node_id=node_id, count=False)
            if row.node_id is not None and row.node_id != node_id and lead is None:
                lead = row.node_id
        return lead

    def _types_held_by_others(self, case_id: UUID, label: str) -> list[str]:
        """The selector types of an entity that owns no index row for its
        own label: a DUPLICATE, created while another entity held the value
        (the index keeps its first owner and reports the second as a lead).

        The duplicate is the same kind of entity as the first, so the types
        are those of the rows the case's index holds for this label's
        canonical form, whoever owns them (or nobody). Without them its
        label corrections were neither validated nor followed, while the
        owner's were (graph-selector-index-drift, 2026-10-03, verify
        round). A row this reader cannot see under row security is not
        found, and the entity is then followed as it was."""
        pairs = [(t, n) for t in sorted(_VALID_TYPES)
                 if (n := _norm_or_empty(t, label)).strip()]
        if not pairs:
            return []
        found = self._c.execute(
            """SELECT s.selector_type FROM core.selector s
                WHERE s.case_id = %s
                  AND (s.selector_type, s.norm_value) IN
                      (SELECT * FROM unnest(%s::text[], %s::text[]))""",
            (case_id, [t for t, _ in pairs], [n for _, n in pairs])).fetchall()
        return sorted({r[0] for r in found})

    def release_node(self, *, case_id: UUID, node_id: UUID,
                     label: str | None = None) -> int:
        """Let go of every index row a retired entity held, returning how
        many (graph-selector-index-drift, 2026-10-03). A retired entity
        "should never have been in the case file", so a selector recorded
        against it belongs to nobody until a live entity records it.

        With `label` (the retired entity's), a row goes to the oldest live
        entity of the case that holds the same value, a duplicate created
        while the retired one owned it: it was never indexed, and left
        alone it stayed unindexed with the row ownerless (verify round,
        2026-10-03). The duplicate is found by the fold the create form's
        duplicate check uses (case and runs of whitespace), then confirmed
        by the canonical form under the row's own type; one this reader
        cannot see under row security is not handed the row."""
        released = self._c.execute(
            "UPDATE core.selector SET node_id = NULL "
            "WHERE case_id = %s AND node_id = %s "
            "RETURNING id, selector_type, norm_value",
            (case_id, node_id)).fetchall()
        if not released or label is None:
            return len(released)
        twins = self._c.execute(
            """SELECT id, label FROM core.node
                WHERE case_id = %s AND id <> %s AND deleted_at IS NULL
                  AND merged_into_id IS NULL
                  AND (node_type = ANY(%s) OR attrs ? 'selector_type')
                  AND lower(regexp_replace(btrim(label), '\\s+', ' ', 'g'))
                      = lower(regexp_replace(btrim(%s), '\\s+', ' ', 'g'))
                ORDER BY created_at, id LIMIT 20""",
            (case_id, node_id, sorted(LABEL_IS_SELECTOR), label)).fetchall()
        for row_id, sel_type, norm in released:
            for twin_id, twin_label in twins:
                if _norm_or_empty(sel_type, twin_label) == norm:
                    self._c.execute(
                        "UPDATE core.selector SET node_id = %s "
                        "WHERE id = %s AND node_id IS NULL", (twin_id, row_id))
                    break
        return len(released)

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

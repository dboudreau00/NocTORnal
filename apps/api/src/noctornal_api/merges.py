"""Entity merge, and its reversal (docs/01 "Entity resolution", Phase 6).

docs/01 opens the section with a warning worth repeating at the top of the
implementation:

    Merging is the operation most likely to quietly corrupt a case.

Two personas turning out to be one actor is the commonest real correction
in this work, and it is also the commonest way a case quietly becomes
wrong -- because a merge rewrites who did what, and the analyst who made
the call is usually not the one who later discovers it was a coincidence
of nicknames.

So every merge here is a ledger entry, not a state change. The losing node
keeps its row and its history and gains a redirect; every edge that moves
records where it came from; and `unmerge` restores the original endpoints
exactly rather than re-deriving them.

**The rule that is not negotiable: a merge may not cross the
IDENTITY/PERSON boundary.** Collapsing a handle into a human is
ATTRIBUTION, which is an assessment carrying a confidence and is reversible
by design -- that is what `ATTRIBUTED_TO` is for (invariant 2). A merge
asserts the two records were always the same thing, which for a persona and
a person is a category error and destroys exactly the gap the whole model
exists to preserve.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api import notify_events
from noctornal_api.security.access import tlp_from_name

# The identity layer, per the ontology's ACTOR category. A merge within a
# layer is a claim that two records describe one thing; a merge ACROSS this
# particular boundary is an attribution wearing a merge's clothes.
_PERSONA_LAYER = frozenset({"IDENTITY"})
_PERSON_LAYER = frozenset({"PERSON"})


class MergeError(Exception):
    pass


@dataclass(frozen=True)
class MergeRecord:
    id: UUID
    case_id: UUID
    source_node_id: UUID
    target_node_id: UUID
    reason: str
    merged_at: datetime
    merged_by: UUID
    reversed_at: datetime | None
    reversed_by: UUID | None
    reversal_reason: str | None
    edges_repointed: int = 0

    @property
    def is_live(self) -> bool:
        return self.reversed_at is None


class MergeService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def merge(self, *, case_id: UUID, source_node_id: UUID,
              target_node_id: UUID, merged_by: UUID, reason: str,
              basis_selector_id: UUID | None = None) -> MergeRecord:
        """Fold `source` into `target`, reversibly.

        The source keeps its row, its assertions and its history. Its edges
        are re-pointed at the target, and each move is recorded so the
        reversal is a restore rather than a reconstruction.
        """
        if not reason or not reason.strip():
            raise MergeError(
                "a merge must say why: it is the operation most likely to "
                "quietly corrupt a case, and the reason is what a later "
                "reviewer has to work from")
        if source_node_id == target_node_id:
            raise MergeError("a node cannot be merged into itself")

        src = self._node(case_id, source_node_id, "source")
        dst = self._node(case_id, target_node_id, "target")

        if src["merged_into_id"] is not None:
            raise MergeError("the source node is already merged away")
        if dst["merged_into_id"] is not None:
            # Merging into a node that is itself a redirect would build a
            # chain nothing resolves, and the projection excludes merged
            # nodes -- so the result would be an actor that vanished.
            raise MergeError(
                "the target node is itself merged away; merge into the "
                "surviving node instead")
        if src["deleted_at"] is not None or dst["deleted_at"] is not None:
            raise MergeError("a deleted node cannot take part in a merge")

        self._check_layers(src["node_type"], dst["node_type"])

        now = datetime.now(timezone.utc)
        with self._c.transaction():
            merge_id = self._c.execute(
                """INSERT INTO core.node_merge
                       (case_id, source_node_id, target_node_id, reason,
                        basis_selector_id, merged_at, merged_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (case_id, source_node_id, target_node_id, reason.strip(),
                 basis_selector_id, now, merged_by),
            ).fetchone()[0]

            # Record BEFORE moving: after the update nothing in core.edge
            # remembers the original endpoints.
            edges = self._c.execute(
                """SELECT id, src_node_id, dst_node_id FROM core.edge
                    WHERE case_id = %s AND deleted_at IS NULL
                      AND (src_node_id = %s OR dst_node_id = %s)""",
                (case_id, source_node_id, source_node_id),
            ).fetchall()
            moved = 0
            for edge_id, esrc, edst in edges:
                new_src = target_node_id if esrc == source_node_id else esrc
                new_dst = target_node_id if edst == source_node_id else edst
                if new_src == new_dst:
                    # The tie was BETWEEN the two nodes being merged. It
                    # would become a self-loop, which core.edge forbids and
                    # which means nothing anyway -- an actor does not vouch
                    # for themselves. Record it, then soft-delete it, so the
                    # reversal can bring it back.
                    self._c.execute(
                        """INSERT INTO core.node_merge_edge
                               (merge_id, edge_id, original_src_node_id,
                                original_dst_node_id)
                           VALUES (%s, %s, %s, %s)""",
                        (merge_id, edge_id, esrc, edst))
                    self._c.execute(
                        "UPDATE core.edge SET deleted_at = %s WHERE id = %s",
                        (now, edge_id))
                    moved += 1
                    continue
                self._c.execute(
                    """INSERT INTO core.node_merge_edge
                           (merge_id, edge_id, original_src_node_id,
                            original_dst_node_id)
                       VALUES (%s, %s, %s, %s)""",
                    (merge_id, edge_id, esrc, edst))
                self._c.execute(
                    """UPDATE core.edge SET src_node_id = %s, dst_node_id = %s,
                              updated_at = %s
                        WHERE id = %s""",
                    (new_src, new_dst, now, edge_id))
                moved += 1

            self._c.execute(
                """UPDATE core.node
                      SET merged_into_id = %s, merged_at = %s, merged_by = %s,
                          updated_at = %s
                    WHERE id = %s""",
                (target_node_id, now, merged_by, now, source_node_id))

            self._audit(case_id, merge_id, merged_by, "NODE_MERGED", {
                "source_node_id": str(source_node_id),
                "source_label": src["label"],
                "target_node_id": str(target_node_id),
                "target_label": dst["label"],
                "edges_repointed": moved,
                "reason": reason.strip(),
                "basis_selector_id": str(basis_selector_id)
                if basis_selector_id else None,
            })
            # docs/01: "Merges ... generate an audit event AND a case-owner
            # notification." The audit event has existed since decision 41;
            # this is the other half, and it is inside the transaction on
            # purpose -- a merge that succeeded with no notification is a
            # case owner who never finds out.
            notify_events.merge_performed(
                self._c, case_id=case_id, merge_id=merge_id,
                source_label=src["label"], target_label=dst["label"],
                edges_repointed=moved, reason=reason.strip(),
                actor_id=merged_by,
                # The body names both nodes, so the notification is at least
                # as classified as the more restricted of them.
                element_classification=max(
                    (src["classification"], dst["classification"]),
                    key=lambda c: tlp_from_name(c)),
                element_compartments=src["compartments"] | dst["compartments"])
        return self.get(merge_id)

    def unmerge(self, merge_id: UUID, *, reversed_by: UUID,
                reason: str) -> MergeRecord:
        """Undo a merge exactly: restore every edge's original endpoints and
        clear the redirect.

        Reversal is a RESTORE, not a re-derivation. Working out where an
        edge "should" go after the fact is guesswork, and guesswork is what
        made the merge wrong in the first place.
        """
        if not reason or not reason.strip():
            raise MergeError("a reversal must say why")
        record = self.get(merge_id)
        if record is None:
            raise MergeError(f"merge {merge_id} not found")
        if not record.is_live:
            raise MergeError("this merge has already been reversed")

        now = datetime.now(timezone.utc)
        with self._c.transaction():
            rows = self._c.execute(
                """SELECT edge_id, original_src_node_id, original_dst_node_id
                     FROM core.node_merge_edge WHERE merge_id = %s""",
                (merge_id,),
            ).fetchall()
            for edge_id, osrc, odst in rows:
                # Restores endpoints AND undoes the soft-delete applied to a
                # tie that had collapsed into a self-loop.
                self._c.execute(
                    """UPDATE core.edge
                          SET src_node_id = %s, dst_node_id = %s,
                              deleted_at = NULL, updated_at = %s
                        WHERE id = %s""",
                    (osrc, odst, now, edge_id))

            self._c.execute(
                """UPDATE core.node
                      SET merged_into_id = NULL, merged_at = NULL,
                          merged_by = NULL, updated_at = %s
                    WHERE id = %s""",
                (now, record.source_node_id))
            self._c.execute(
                """UPDATE core.node_merge
                      SET reversed_at = %s, reversed_by = %s,
                          reversal_reason = %s
                    WHERE id = %s""",
                (now, reversed_by, reason.strip(), merge_id))
            self._audit(record.case_id, merge_id, reversed_by, "NODE_UNMERGED", {
                "source_node_id": str(record.source_node_id),
                "target_node_id": str(record.target_node_id),
                "edges_restored": len(rows),
                "reason": reason.strip(),
            })
            src = self._node(record.case_id, record.source_node_id, "source")
            dst = self._node(record.case_id, record.target_node_id, "target")
            notify_events.merge_reversed(
                self._c, case_id=record.case_id, merge_id=merge_id,
                edges_restored=len(rows), reason=reason.strip(),
                actor_id=reversed_by,
                element_classification=max(
                    (src["classification"], dst["classification"]),
                    key=lambda c: tlp_from_name(c)),
                element_compartments=src["compartments"] | dst["compartments"])
        return self.get(merge_id)

    def history(self, case_id: UUID, limit: int = 100) -> list[MergeRecord]:
        """Every merge in the case, reversed ones included. A reversed merge
        that vanished from the record would hide the fact that somebody once
        believed these were the same actor."""
        rows = self._c.execute(
            """SELECT m.id, m.case_id, m.source_node_id, m.target_node_id,
                      m.reason, m.merged_at, m.merged_by, m.reversed_at,
                      m.reversed_by, m.reversal_reason,
                      (SELECT count(*) FROM core.node_merge_edge e
                        WHERE e.merge_id = m.id)
                 FROM core.node_merge m
                WHERE m.case_id = %s
                ORDER BY m.merged_at DESC LIMIT %s""",
            (case_id, limit),
        ).fetchall()
        return [_record(r) for r in rows]

    def get(self, merge_id: UUID) -> MergeRecord | None:
        row = self._c.execute(
            """SELECT m.id, m.case_id, m.source_node_id, m.target_node_id,
                      m.reason, m.merged_at, m.merged_by, m.reversed_at,
                      m.reversed_by, m.reversal_reason,
                      (SELECT count(*) FROM core.node_merge_edge e
                        WHERE e.merge_id = m.id)
                 FROM core.node_merge m WHERE m.id = %s""",
            (merge_id,),
        ).fetchone()
        return _record(row) if row else None

    # -- internals --------------------------------------------------------
    def _node(self, case_id: UUID, node_id: UUID, which: str) -> dict:
        row = self._c.execute(
            """SELECT node_type, label, merged_into_id, deleted_at,
                      classification, compartments
                 FROM core.node WHERE id = %s AND case_id = %s""",
            (node_id, case_id),
        ).fetchone()
        if row is None:
            raise MergeError(f"the {which} node is not in this case")
        # The labels come back because the merge NOTIFICATION quotes both
        # node labels in its body, and a node may be classified above its
        # case (the floor trigger only stops it going below). Labelling that
        # notification with the case's classification alone under-labels it.
        return {"node_type": row[0], "label": row[1],
                "merged_into_id": row[2], "deleted_at": row[3],
                "classification": row[4],
                "compartments": frozenset(row[5] or [])}

    def _check_layers(self, src_type: str, dst_type: str) -> None:
        """Invariant 2, at the merge boundary."""
        crosses = (
            (src_type in _PERSONA_LAYER and dst_type in _PERSON_LAYER)
            or (src_type in _PERSON_LAYER and dst_type in _PERSONA_LAYER)
        )
        if crosses:
            raise MergeError(
                "a persona cannot be merged into a person. Saying a handle "
                "IS a human is an attribution, not a merge: record it as an "
                "ATTRIBUTED_TO edge, which carries a confidence and can be "
                "withdrawn without rewriting the graph (invariant 2)")
        if src_type != dst_type:
            raise MergeError(
                f"cannot merge a {src_type} into a {dst_type}: a merge "
                "asserts the two records always described the same thing")

    def _audit(self, case_id: UUID, merge_id: UUID, actor_id: UUID,
               action: str, detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'node_merge', %s, %s, %s)""",
            (actor_id, action, merge_id, case_id, Json(detail)),
        )


def _record(r) -> MergeRecord:
    return MergeRecord(
        id=r[0], case_id=r[1], source_node_id=r[2], target_node_id=r[3],
        reason=r[4], merged_at=r[5], merged_by=r[6], reversed_at=r[7],
        reversed_by=r[8], reversal_reason=r[9], edges_repointed=r[10],
    )

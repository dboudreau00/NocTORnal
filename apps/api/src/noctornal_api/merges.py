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


class MergeCollision(MergeError):
    """The merge would duplicate a live tie both entities hold to one third
    party. The third party's id is in the message for a merger who may read
    that entity; `without_third_party` is the same sentence for one who may
    not (2026-10-03: a refusal named a hidden entity's id and so that two
    ties to it existed, to a merger who was never shown it)."""

    def __init__(self, etype: str, third_party: UUID):
        self.etype = etype
        self.third_party = third_party
        super().__init__(self._text(f" ({third_party})"))

    def _text(self, named: str) -> str:
        return (f"both entities already have a live {self.etype} tie to the "
                f"same third party{named}, so merging them would create a "
                f"duplicate relationship. Retire one of the two ties, or give "
                f"it a validity interval, and merge again.")

    def without_third_party(self) -> str:
        return self._text("")


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
    #: Ties MOVED to the target. Excludes ties between the two entities,
    #: which a merge destroys rather than moves -- counting those here made
    #: the record disagree with its own audit row and told a case owner
    #: that a relationship survived somewhere else.
    edges_repointed: int = 0
    #: Ties BETWEEN the two entities, soft-deleted by the merge. Restored
    #: by a reversal, which is why they are recorded at all.
    edges_self_loop_deleted: int = 0

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
        self._refuse_declassifying(src, dst)

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
                """SELECT id, src_node_id, dst_node_id, edge_type
                     FROM core.edge
                    WHERE case_id = %s AND deleted_at IS NULL
                      AND (src_node_id = %s OR dst_node_id = %s)""",
                (case_id, source_node_id, source_node_id),
            ).fetchall()
            # Counted apart, because they are different things that happened
            # to the graph. `moved` used to be one number covering both, so
            # a merge whose only effect was DELETING the tie between the two
            # entities reported "re-pointed 1 relationship" to the audit
            # log, the case owner's notification and the UI banner. That is
            # a destruction described as a move.
            repointed = 0
            self_loops_deleted = 0
            for edge_id, esrc, edst, etype in edges:
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
                                original_dst_node_id, deleted_by_merge)
                           VALUES (%s, %s, %s, %s, true)""",
                        (merge_id, edge_id, esrc, edst))
                    self._c.execute(
                        "UPDATE core.edge SET deleted_at = %s WHERE id = %s",
                        (now, edge_id))
                    self_loops_deleted += 1
                    continue
                self._c.execute(
                    """INSERT INTO core.node_merge_edge
                           (merge_id, edge_id, original_src_node_id,
                            original_dst_node_id)
                       VALUES (%s, %s, %s, %s)""",
                    (merge_id, edge_id, esrc, edst))
                try:
                    self._c.execute(
                        """UPDATE core.edge
                              SET src_node_id = %s, dst_node_id = %s,
                                  updated_at = %s
                            WHERE id = %s""",
                        (new_src, new_dst, now, edge_id))
                except psycopg.errors.UniqueViolation:
                    # `edge_uniq_active` refused because BOTH entities
                    # already hold a live tie of this type, with the same
                    # `valid_from`, to the same third party -- and two
                    # personas sharing contacts is the topology that most
                    # often PROVES they are one actor, so this is not an
                    # edge case, it is the commonest real merge.
                    #
                    # The database is right to refuse; folding one into the
                    # other would create a duplicate active edge. What was
                    # wrong is that the bare UPDATE let a UniqueViolation
                    # reach the catch-all handler, so the flagship operation
                    # of the product failed as "Internal error: unexpected
                    # failure (ref ...)" -- unactionable, and indexed as a
                    # bug in the product rather than a decision for the
                    # analyst.
                    # The OTHER end of the tie: it named the survivor for an
                    # outgoing tie, which is the merge's own target.
                    other = edst if esrc == source_node_id else esrc
                    # `from None`: an authored sentence, which `safe_detail`
                    # answers verbatim, not the database's refusal behind it
                    # (it replaced this one with "that record already exists").
                    raise MergeCollision(etype, other) from None
                repointed += 1

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
                "edges_repointed": repointed,
                # A tie BETWEEN the two entities is destroyed, not moved.
                # Folded into `edges_repointed` it read as a relationship
                # that survived the merge somewhere else.
                "edges_self_loop_deleted": self_loops_deleted,
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
                edges_repointed=repointed,
                self_loops_deleted=self_loops_deleted, reason=reason.strip(),
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

        ## Reversal is LIFO, and that is now ENFORCED rather than assumed

        A restore writes an edge's recorded originals over wherever that
        edge is NOW. If a later merge has since moved the same edge, those
        recorded originals are stale, and writing them yanks the tie out
        from under a merge that is still live -- leaving the graph
        asserting a relationship that never existed, while the response,
        the audit row, the owner's notification and the UI banner all say
        every tie is back at its original endpoints.

        0055 closed the `deleted_at` half of exactly this: reversing an old
        merge used to resurrect edges an ANALYST had retired in the
        meantime. A later MERGE moving the same edge is the same class of
        "something happened in between" and was still overwritten
        unconditionally, in both branches.

        So a merge whose edges a later live merge also recorded is refused,
        naming the merge to reverse first. The check is scoped to the
        OVERLAPPING edges rather than to merges in general: two unrelated
        merges in one case do not constrain each other's order, and
        refusing those would make the panel's Reverse buttons lie in the
        opposite direction.
        """
        if not reason or not reason.strip():
            raise MergeError("a reversal must say why")
        record = self.get(merge_id)
        if record is None:
            raise MergeError(f"merge {merge_id} not found")
        if not record.is_live:
            raise MergeError("this merge has already been reversed")

        blocker = self._c.execute(
            """SELECT m2.id, m2.merged_at, count(*) AS shared
                 FROM core.node_merge_edge mine
                 JOIN core.node_merge_edge theirs
                      ON theirs.edge_id = mine.edge_id
                     AND theirs.merge_id <> mine.merge_id
                 JOIN core.node_merge m2 ON m2.id = theirs.merge_id
                WHERE mine.merge_id = %s
                  AND m2.reversed_at IS NULL
                  AND m2.merged_at > %s
                GROUP BY m2.id, m2.merged_at
                ORDER BY m2.merged_at DESC
                LIMIT 1""",
            (merge_id, record.merged_at),
        ).fetchone()
        if blocker is not None:
            # Agreed with the shared count, not a bracketed plural (README
            # screenshot set review, 2026-09-23).
            one = blocker[2] == 1
            raise MergeError(
                f"a later merge ({blocker[0]}) is still live and moved "
                f"{'one' if one else blocker[2]} of the same relationships. "
                f"Reversing this one first would write "
                f"{'its' if one else 'their'} old endpoints over "
                f"{'a tie' if one else 'ties'} that "
                f"merge now owns, and the graph would assert a relationship "
                f"that never existed. Reverse the later merge first.")

        now = datetime.now(timezone.utc)
        with self._c.transaction():
            rows = self._c.execute(
                """SELECT me.edge_id, me.original_src_node_id,
                          me.original_dst_node_id, me.deleted_by_merge,
                          x.edge_type
                     FROM core.node_merge_edge me
                     JOIN core.edge x ON x.id = me.edge_id
                    WHERE me.merge_id = %s""",
                (merge_id,),
            ).fetchall()
            # graph-unmerge-loses-ties-after-target-retired (2026-10-03): a
            # tie retired after the merge gets its endpoints back and stays
            # retired, so it is not counted as restored; the audit row says
            # how many stayed out of the graph.
            left_retired = 0
            for edge_id, osrc, odst, deleted_by_merge, etype in rows:
                # Restores the endpoints, and undoes the soft-delete ONLY on
                # the ties this merge deleted -- the ones that collapsed
                # into a self-loop.
                #
                # `deleted_at = NULL` used to be unconditional. Every edge
                # here was live when the merge ran (`merge` selects
                # `WHERE deleted_at IS NULL`), so an edge that is deleted
                # NOW and was not deleted by the merge was retired
                # afterwards, deliberately, for a reason of its own. The
                # reversal was overwriting that: reversing a month-old
                # merge put back edges an analyst had retired in the
                # meantime, silently, leaving `deleted_by` still naming the
                # person who retired them. Invariant 5 -- history is
                # superseded, never overwritten -- and a fact in the graph
                # with no assertion behind it.
                #
                # graph-unmerge-500-and-ties-to-merged-nodes (2026-10-03): a
                # tie recorded after the merge with the same endpoints, type
                # and validity collides on edge_uniq_active, and the bare
                # UPDATE let that reach the catch-all as a 500, which merge()
                # fixed for itself long ago. It is now a MergeError naming
                # what to retire.
                try:
                    if deleted_by_merge:
                        self._c.execute(
                            """UPDATE core.edge
                                  SET src_node_id = %s, dst_node_id = %s,
                                      deleted_at = NULL, deleted_by = NULL,
                                      updated_at = %s
                                WHERE id = %s""",
                            (osrc, odst, now, edge_id))
                    else:
                        still = self._c.execute(
                            """UPDATE core.edge
                                  SET src_node_id = %s, dst_node_id = %s,
                                      updated_at = %s
                                WHERE id = %s
                            RETURNING deleted_at IS NOT NULL""",
                            (osrc, odst, now, edge_id)).fetchone()
                        left_retired += bool(still and still[0])
                except psycopg.errors.UniqueViolation:
                    # `from None` for the reason `merge()` gives.
                    raise _restore_collision(etype) from None

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
                "edges_restored": len(rows) - left_retired,
                # graph-unmerge-loses-ties-after-target-retired (2026-10-03):
                # ties given back their endpoints that stay retired, because
                # someone retired them after the merge.
                "edges_left_retired": left_retired,
                # Broken out because they are different acts. Repointing is
                # the reversal doing its job; bringing an edge back from
                # soft-deletion puts a tie back into the graph, and an
                # auditor asking "where did this edge come from" needs the
                # count to lead them here.
                "edges_undeleted": sum(1 for r in rows if r[3]),
                "reason": reason.strip(),
            })
            src = self._node(record.case_id, record.source_node_id, "source")
            dst = self._node(record.case_id, record.target_node_id, "target")
            notify_events.merge_reversed(
                self._c, case_id=record.case_id, merge_id=merge_id,
                edges_restored=len(rows) - left_retired, reason=reason.strip(),
                actor_id=reversed_by,
                element_classification=max(
                    (src["classification"], dst["classification"]),
                    key=lambda c: tlp_from_name(c)),
                element_compartments=src["compartments"] | dst["compartments"])
        return self.get(merge_id)

    def history(self, case_id: UUID, limit: int = 100) -> list[MergeRecord]:
        """Every merge in the case, reversed ones included. A reversed merge
        that vanished from the record would hide the fact that somebody once
        believed these were the same actor.

        Unfiltered by the reader's labels (2026-10-03): for the system and the
        suite. A route answers a person with `history_for_reader`."""
        rows = self._c.execute(
            """SELECT m.id, m.case_id, m.source_node_id, m.target_node_id,
                      m.reason, m.merged_at, m.merged_by, m.reversed_at,
                      m.reversed_by, m.reversal_reason,
                      -- Repointed ONLY. A tie between the two entities is
                      -- destroyed by the merge, not moved, and counting it
                      -- here made the record disagree with its own audit row.
                      (SELECT count(*) FROM core.node_merge_edge e
                        WHERE e.merge_id = m.id AND NOT e.deleted_by_merge),
                      (SELECT count(*) FROM core.node_merge_edge e
                        WHERE e.merge_id = m.id AND e.deleted_by_merge)
                 FROM core.node_merge m
                WHERE m.case_id = %s
                ORDER BY m.merged_at DESC LIMIT %s""",
            (case_id, limit),
        ).fetchall()
        return [_record(r) for r in rows]

    def get(self, merge_id: UUID) -> MergeRecord | None:
        """One merge as the system sees it; `get_for_reader` is a person's."""
        row = self._c.execute(
            """SELECT m.id, m.case_id, m.source_node_id, m.target_node_id,
                      m.reason, m.merged_at, m.merged_by, m.reversed_at,
                      m.reversed_by, m.reversal_reason,
                      -- Repointed ONLY. A tie between the two entities is
                      -- destroyed by the merge, not moved, and counting it
                      -- here made the record disagree with its own audit row.
                      (SELECT count(*) FROM core.node_merge_edge e
                        WHERE e.merge_id = m.id AND NOT e.deleted_by_merge),
                      (SELECT count(*) FROM core.node_merge_edge e
                        WHERE e.merge_id = m.id AND e.deleted_by_merge)
                 FROM core.node_merge m WHERE m.id = %s""",
            (merge_id,),
        ).fetchone()
        return _record(row) if row else None

    # As one reader sees them (beta review, 2026-10-03).
    #
    # rls-1, graph-merge-ledger-and-approvals-leak and http_ui-001: the
    # history served every merge in the case, its two node ids, the free
    # reason and the reversal's reason, to every case reader, including
    # merges of entities above them. These two answer only for merges whose
    # BOTH entities are within `clearance` and `compartments`, and count only
    # the ties the reader could see on both ends, so a merge's numbers do not
    # localise a tie to a hidden entity either. History reads its labels,
    # not liveness: a merged-away or retired entity is still the reader's.

    def history_for_reader(self, case_id: UUID, limit: int, *,
                           clearance: str, compartments) -> list[MergeRecord]:
        rows = self._c.execute(
            _READER_SQL.format(where="m.case_id = %(key)s")
            + " ORDER BY m.merged_at DESC LIMIT %(limit)s",
            _reader_params(case_id, clearance, compartments, limit=limit),
        ).fetchall()
        return [_record(r) for r in rows]

    def get_for_reader(self, merge_id: UUID, *, clearance: str,
                       compartments) -> MergeRecord | None:
        row = self._c.execute(
            _READER_SQL.format(where="m.id = %(key)s"),
            _reader_params(merge_id, clearance, compartments),
        ).fetchone()
        return _record(row) if row else None

    def count_hidden_from_reader(self, case_id: UUID, *, clearance: str,
                                 compartments) -> int:
        """Merges in the case the reader is not shown: the withheld count.
        Run it on a WITHHELD system connection, since row security hides
        exactly these merges from the reader's own (0132)."""
        return self._c.execute(
            """SELECT count(*) FROM core.node_merge m
                 JOIN core.node s ON s.id = m.source_node_id
                 JOIN core.node t ON t.id = m.target_node_id
                WHERE m.case_id = %(key)s
                  AND NOT (s.classification <= %(clr)s::core.tlp
                           AND s.compartments <@ %(held)s::text[]
                           AND t.classification <= %(clr)s::core.tlp
                           AND t.compartments <@ %(held)s::text[])""",
            _reader_params(case_id, clearance, compartments)).fetchone()[0]

    # -- internals --------------------------------------------------------
    def _refuse_declassifying(self, src: dict, dst: dict) -> None:
        """graph-merge-no-element-label-gate (2026-10-03): the survivor keeps
        its own labels and takes every tie of the merged entity, so merging a
        RED entity into an AMBER one showed the RED entity's ties, attached to
        the survivor, to every AMBER reader. A merge is refused unless the
        survivor is at least as restricted as the entity merged into it."""
        lower = (tlp_from_name(dst["classification"])
                 < tlp_from_name(src["classification"]))
        if lower or not src["compartments"] <= dst["compartments"]:
            raise MergeError(
                "the entity you are merging into is less restricted than the "
                "one merged into it, so its ties would be shown at the "
                "survivor's labels to people the merged entity is hidden "
                "from. Merge the other way round, into the more restricted "
                "entity.")

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
                "withdrawn without rewriting the graph")
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


#: One merge row as a reader sees it (2026-10-03, see `history_for_reader`).
#: Both entities within the reader's labels, and each tie count kept to ties
#: whose own labels and both original endpoints are too. `{where}` is a
#: literal chosen by the caller above, never client input.
_READER_SQL = """
SELECT m.id, m.case_id, m.source_node_id, m.target_node_id,
       m.reason, m.merged_at, m.merged_by, m.reversed_at,
       m.reversed_by, m.reversal_reason,
       (SELECT count(*) FROM core.node_merge_edge e
          JOIN core.edge x ON x.id = e.edge_id
          JOIN core.node a ON a.id = e.original_src_node_id
          JOIN core.node b ON b.id = e.original_dst_node_id
         WHERE e.merge_id = m.id AND NOT e.deleted_by_merge
           AND x.classification <= %(clr)s::core.tlp
           AND x.compartments <@ %(held)s::text[]
           AND a.classification <= %(clr)s::core.tlp
           AND a.compartments <@ %(held)s::text[]
           AND b.classification <= %(clr)s::core.tlp
           AND b.compartments <@ %(held)s::text[]),
       (SELECT count(*) FROM core.node_merge_edge e
          JOIN core.edge x ON x.id = e.edge_id
         WHERE e.merge_id = m.id AND e.deleted_by_merge
           AND x.classification <= %(clr)s::core.tlp
           AND x.compartments <@ %(held)s::text[])
  FROM core.node_merge m
  JOIN core.node s ON s.id = m.source_node_id
  JOIN core.node t ON t.id = m.target_node_id
 WHERE {where}
   AND s.classification <= %(clr)s::core.tlp
   AND s.compartments <@ %(held)s::text[]
   AND t.classification <= %(clr)s::core.tlp
   AND t.compartments <@ %(held)s::text[]"""


def _reader_params(key: UUID, clearance: str, compartments,
                   limit: int | None = None) -> dict:
    return {"key": key, "clr": clearance, "held": sorted(compartments),
            "limit": limit}


def _restore_collision(etype: str) -> MergeError:
    """The refusal for a reversal that would duplicate a live tie
    (graph-unmerge-500-and-ties-to-merged-nodes, 2026-10-03). Names the
    tie's type and what to do; no id or label of the other tie, which may be
    one the person reversing cannot see. Built from what was read before the
    failed statement, because the transaction cannot be read after it."""
    return MergeError(
        f"a live {etype} tie between the same two entities was recorded "
        f"after this merge, so putting the original back would duplicate "
        f"it. Retire the later tie, or give it a validity interval, and "
        f"reverse the merge again.")


def _record(r) -> MergeRecord:
    return MergeRecord(
        id=r[0], case_id=r[1], source_node_id=r[2], target_node_id=r[3],
        reason=r[4], merged_at=r[5], merged_by=r[6], reversed_at=r[7],
        reversed_by=r[8], reversal_reason=r[9], edges_repointed=r[10],
        edges_self_loop_deleted=r[11],
    )

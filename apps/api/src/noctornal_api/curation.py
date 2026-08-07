"""Analyst curation: tags, node sets, and full-text search (docs/09 Phase 1).

Tags are a controlled vocabulary (namespace + name), optionally
case-scoped or a global taxonomy (case_id NULL), hierarchical (parent_id),
and can carry an external id (e.g. a MITRE ATT&CK technique). Node sets are
ad-hoc analyst working sets that are deliberately NOT ontological claims —
they group nodes for a task without becoming edges that would distort
centrality (docs/01). Search runs over the trigger-maintained tsvectors on
node and evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

import psycopg


class CurationError(Exception):
    pass


# --------------------------------------------------------------------- tags
class TagService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def create_tag(
        self, *, namespace: str, name: str, case_id: UUID | None = None,
        colour: str | None = None, description: str | None = None,
        parent_id: UUID | None = None, external_id: str | None = None,
    ) -> UUID:
        """Create a tag. case_id NULL is a global taxonomy entry. Uniqueness
        is (case_id, namespace, name) — or (namespace, name) globally."""
        try:
            return self._c.execute(
                """INSERT INTO core.tag
                       (case_id, namespace, name, colour, description, parent_id, external_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                (case_id, namespace, name, colour, description, parent_id, external_id),
            ).fetchone()[0]
        except psycopg.errors.UniqueViolation as exc:
            raise CurationError(f"tag {namespace}:{name} already exists") from exc

    def assign(
        self, tag_id: UUID, *, assigned_by: UUID, node_id: UUID | None = None,
        edge_id: UUID | None = None, evidence_id: UUID | None = None,
    ) -> None:
        if sum(x is not None for x in (node_id, edge_id, evidence_id)) != 1:
            raise CurationError("exactly one of node_id / edge_id / evidence_id required")
        # Idempotent, now that 0054 has given each target type a unique
        # index to conflict against. Without this the router's pre-check
        # was the only guard, and a pre-check handles the double-click and
        # not the race: two concurrent assigns both SELECT, both find
        # nothing, and the second INSERT is a 500 where the correct answer
        # is "already tagged, nothing to do".
        #
        # The predicate is RESTATED. 0054 deliberately created four PARTIAL
        # indexes rather than one composite, because three of the four
        # target columns are NULL on every row and NULL is not equal to
        # itself — so a composite index would have permitted unlimited
        # duplicates. A partial index is only usable as a conflict target
        # when its WHERE clause is repeated here; omit it and Postgres
        # answers "no unique or exclusion constraint matching".
        target = ("node_id" if node_id is not None
                  else "edge_id" if edge_id is not None
                  else "evidence_id")
        self._c.execute(
            f"""INSERT INTO core.tag_assignment
                    (tag_id, node_id, edge_id, evidence_id, assigned_by)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tag_id, {target}) WHERE {target} IS NOT NULL
                DO NOTHING""",
            (tag_id, node_id, edge_id, evidence_id, assigned_by),
        )

    def tags_on_node(self, node_id: UUID) -> list[tuple[str, str]]:
        rows = self._c.execute(
            """SELECT t.namespace, t.name
                 FROM core.tag_assignment a JOIN core.tag t ON t.id = a.tag_id
                WHERE a.node_id = %s ORDER BY t.namespace, t.name""",
            (node_id,),
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def unassign(self, tag_id: UUID, *, node_id: UUID) -> None:
        self._c.execute(
            "DELETE FROM core.tag_assignment WHERE tag_id = %s AND node_id = %s",
            (tag_id, node_id),
        )


# ---------------------------------------------------------------- node sets
class NodeSetService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def create_set(
        self, *, case_id: UUID, name: str, created_by: UUID,
        purpose: str | None = None, is_pinned: bool = False,
    ) -> UUID:
        return self._c.execute(
            """INSERT INTO core.node_set (case_id, name, purpose, is_pinned, created_by)
               VALUES (%s, %s, %s, %s, %s) RETURNING id""",
            (case_id, name, purpose, is_pinned, created_by),
        ).fetchone()[0]

    def add_member(self, set_id: UUID, node_id: UUID, *, note: str | None = None) -> None:
        """Add a node to a set, or update its note.

        `COALESCE(EXCLUDED.note, existing)` — an OMITTED note leaves the
        existing one alone.

        This used to be a bare `SET note = EXCLUDED.note`, which meant
        re-adding a member without a note wrote NULL over whatever the
        analyst had written there. Adding a node to a set is the kind of
        thing people do twice — a double-click, a drag repeated because the
        first one did not look like it registered, a bulk add that overlaps
        an existing set — and the note is the ONE thing in a working set
        that cannot be reconstructed from the graph. Every other column is
        derivable; "why is this actor in my shortlist" is not.

        To CLEAR a note deliberately, pass an empty string: `''` is not
        NULL, so it survives the COALESCE and overwrites. That keeps
        "leave it alone" and "remove it" distinguishable, which a single
        nullable parameter otherwise cannot express.

        Found 2026-07-26 while writing the router, which was working around
        it by re-reading the current note and passing it back. Fixed here
        instead: a workaround in one caller leaves every other caller —
        a worker, a script, a future endpoint — still destroying notes.
        """
        self._c.execute(
            """INSERT INTO core.node_set_member (set_id, node_id, note)
               VALUES (%s, %s, %s)
               ON CONFLICT (set_id, node_id) DO UPDATE
                   SET note = COALESCE(EXCLUDED.note, core.node_set_member.note)""",
            (set_id, node_id, note),
        )

    def remove_member(self, set_id: UUID, node_id: UUID) -> None:
        self._c.execute(
            "DELETE FROM core.node_set_member WHERE set_id = %s AND node_id = %s",
            (set_id, node_id),
        )

    def members(self, set_id: UUID) -> list[UUID]:
        rows = self._c.execute(
            "SELECT node_id FROM core.node_set_member WHERE set_id = %s", (set_id,)
        ).fetchall()
        return [r[0] for r in rows]


# ------------------------------------------------------------------ search
@dataclass(frozen=True)
class SearchHit:
    id: UUID
    label: str      # node label or evidence title
    rank: float


class SearchService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def search_nodes(
        self, *, case_id: UUID, query: str, limit: int = 50,
        clearance: str, compartments: frozenset[str],
    ) -> list[SearchHit]:
        """Full-text over node label + attrs (trigger-maintained tsvector).

        Elements may be classified ABOVE their case (the TLP floor trigger
        only forbids going below), so results are filtered by the CALLER's
        own clearance and compartments — not the case's. Otherwise a label
        like a real name on a RED node leaks to an AMBER analyst who is
        correctly refused the node itself. The predicates are in SQL so
        LIMIT applies after filtering and cannot truncate visible hits in
        favour of invisible ones.
        """
        rows = self._c.execute(
            """SELECT id, label, ts_rank(search_tsv, plainto_tsquery('simple', %s)) AS rank
                 FROM core.node
                WHERE case_id = %s
                  AND deleted_at IS NULL AND merged_into_id IS NULL
                  AND classification <= %s::core.tlp
                  AND compartments <@ %s
                  AND search_tsv @@ plainto_tsquery('simple', %s)
                ORDER BY rank DESC LIMIT %s""",
            (query, case_id, clearance, list(compartments), query, limit),
        ).fetchall()
        return [SearchHit(r[0], r[1], r[2]) for r in rows]

    def search_evidence(
        self, *, case_id: UUID, query: str, limit: int = 50,
        clearance: str, compartments: frozenset[str],
    ) -> list[SearchHit]:
        """As search_nodes: an exhibit title is filtered by the caller's own
        ceiling, so an over-classified exhibit is invisible rather than
        discoverable-then-403."""
        rows = self._c.execute(
            """SELECT id, title, ts_rank(search_tsv, plainto_tsquery('simple', %s)) AS rank
                 FROM core.evidence
                WHERE case_id = %s
                  AND classification <= %s::core.tlp
                  AND compartments <@ %s
                  AND search_tsv @@ plainto_tsquery('simple', %s)
                ORDER BY rank DESC LIMIT %s""",
            (query, case_id, clearance, list(compartments), query, limit),
        ).fetchall()
        return [SearchHit(r[0], r[1], r[2]) for r in rows]

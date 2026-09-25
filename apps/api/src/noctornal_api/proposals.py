"""Proposals: machines propose, analysts dispose (invariant 3, docs/01).

The third of the three ideas everything follows from, and until now the
only one with no enforcement anywhere. `collect.proposal` has existed since
Phase 0 and nothing has ever written it, because nothing extracts yet — so
the invariant was true by accident rather than by construction.

docs/02 draws the pipeline and marks where it stops:

    extractors -> extraction rows (selectors with offsets)
      -> watch matcher -> watch_hit -> notification
      -> proposal generator -> proposal rows          <- STOPS HERE
      -> ------- human review -------
      -> accepted proposal -> node / edge / assertion

And says why the stop is load-bearing:

    Auto-ingestion into the graph produces a network that looks impressive
    and means nothing, because it is mostly forum boilerplate, quoted text
    and signature blocks.

This module is the "STOPS HERE" line, expressed as code. Two halves:

**`ProposalStore.propose()`** is the ONLY thing an extractor may call. It
writes to `collect.proposal` and physically cannot reach `core.node` or
`core.edge` — it holds no `GraphWriteService` and takes no actor, because
a machine is not an actor who can be accountable for a graph element.

**`ProposalReview.accept()`** is the only path from a proposal into the
graph, and it requires a human `reviewed_by`. It applies the proposal
through `GraphWriteService`, so the element and its assertion commit
together exactly as a hand-built one does (invariant 1) — an accepted
proposal is not a privileged back door into the graph, it is an analyst
making a claim with a machine's suggestion as its basis.

The assertion an accepted proposal creates carries basis
`AUTOMATED_INFERENCE` with the proposer's rationale, so the graph never
forgets that a machine suggested it. docs/03: "A bare 0.87 similarity
score is not [useful], and will be either over-trusted or ignored."
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.cases import CONTENT_READ_ONLY_STATES
from noctornal_api.graph import AssertionInput, GraphWriteError, GraphWriteService
from noctornal_api.wording import agree

# What a proposal can ask for. Deliberately small: anything an extractor
# cannot express as one of these is not something it should be able to do
# to the graph without a person writing it by hand.
KIND_NODE = "NODE"
KIND_EDGE = "EDGE"
KIND_ATTRIBUTE = "ATTRIBUTE"
KINDS = frozenset({KIND_NODE, KIND_EDGE, KIND_ATTRIBUTE})

STATE_PROPOSED = "PROPOSED"
STATE_ACCEPTED = "ACCEPTED"
STATE_REJECTED = "REJECTED"
# DISPUTED is the "not yet" state: a triage queue where the only options are
# yes and no forces a decision on ambiguous items, and forcing a decision on
# an ambiguous item is how junk gets accepted at four in the afternoon.
STATE_DISPUTED = "DISPUTED"


class ProposalError(Exception):
    pass


#: What an accepted NODE or EDGE is labelled when neither the reviewer, the
#: proposal nor the material it came from names a classification.
DEFAULT_CLASSIFICATION = "AMBER"

#: The TLP levels in order, lowest first: `core.tlp`'s enum order, which
#: is what `<=` and GREATEST compare by in SQL.
TLP_ORDER = ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")


def _rank(level: str | None) -> int:
    return TLP_ORDER.index(level) if level in TLP_ORDER else -1


def strictest(*levels: str | None) -> str | None:
    """The highest of the named levels, ignoring the absent ones (as SQL's
    GREATEST ignores NULL). None when none is named."""
    named = [lv for lv in levels if lv in TLP_ORDER]
    return max(named, key=_rank) if named else None


def accepted_classification(payload: dict | None, requested: str | None,
                            *, source: str | None = None,
                            floor: str | None = None) -> str:
    """The label an accepted NODE or EDGE proposal is written at.

    One expression, used by `ProposalReview.accept` to write the element
    AND by the accept route to check it against the reviewer's clearance
    first. They were two copies of nothing: the route checked no label at
    all, so a reviewer could accept at a classification above their own
    and author an element they could then neither see nor correct (final
    review C12, 2026-09-23). Keeping the rule here means the label that is
    checked is the label that is written.

    The default is the label of what the proposal came from, never below
    the case's floor (ux08-triage:accept-downgrades-classification and the
    owner's gap-capture-classification decision, 2026-09-23). An analyst
    who captured a RED thread and pressed Accept got AMBER selectors: the
    capture's classification was stored on the document and never reached
    the proposal, and this fell back to AMBER. `source` is the strictest
    label of the captured document or contact block behind the proposal
    (`ProposalStore.source_labels`), `floor` is the case's own.

    A reviewer may RAISE the label and may not lower it below that
    default. Accepting a RED capture's selector at GREEN is a handling
    downgrade, and one made by a keystroke in a queue is exactly the kind
    nobody would notice, so it is refused rather than written.
    """
    declared = strictest((payload or {}).get("classification"), source)
    base = strictest(declared or DEFAULT_CLASSIFICATION, floor)
    if requested is None:
        return base
    if requested not in TLP_ORDER:
        raise ProposalError(f"unknown classification {requested!r}")
    if _rank(requested) < _rank(base):
        raise ProposalError(
            f"this proposal came from {base} material, so it cannot be "
            f"accepted at {requested}: an accepted element is never "
            f"labelled below what it was found in")
    return requested


def case_compartments(conn: psycopg.Connection,
                      case_id: UUID) -> frozenset[str]:
    """The compartments of a case, read inside the caller's transaction
    when there is one."""
    row = conn.execute('SELECT compartments FROM core."case" WHERE id = %s',
                       (case_id,)).fetchone()
    return frozenset((row[0] if row else None) or [])


def element_compartments(labels: SourceLabels,
                         case_compartments) -> list[str]:
    """The compartments an accepted NODE or EDGE carries: its material's,
    beyond its case's own (L1, 2026-09-24).

    One expression, used by `ProposalReview.accept` to write the element
    and by the accept route to hold the reviewer to it first, as
    `accepted_classification` is for the label. The case's own keys are
    not copied: every read of an element passes its case's gate, and the
    other elements of a compartmented case carry none of them."""
    return sorted(labels.compartments - frozenset(case_compartments or ()))


def _compartment_words(keys) -> str:
    """"compartment X" or "compartments X, Y", for a refusal that names
    them to somebody already read into them."""
    ordered = sorted(keys)
    return (f"{agree(len(ordered), 'compartment', 'compartments')} "
            f"{', '.join(ordered)}")


def attribute_label_problem(payload: dict | None, labels: SourceLabels,
                            entity_classification: str | None,
                            entity_compartments=(), *,
                            case_compartments=()) -> str | None:
    """Why an ATTRIBUTE claim may not be attached to this entity, or None
    when it may.

    Final review c1 (2026-09-24). An ATTRIBUTE accept writes an assertion
    onto an entity that already exists, and `core.assertion` has no labels
    of its own: whoever may read the entity reads the claim, its value and
    its rationale, which quotes where the material was found. The
    gap-capture fix raised NODE and EDGE to what they came from and left
    this kind at the entity's label, so a RED contact block in STEALER-2026
    naming a CLEAR publisher put its Tox ID and forum URL in front of every
    CLEAR reader of that publisher, while the queue hid the same proposal
    from them and the card wore TLP:RED. An accepted element is never
    labelled below what it was found in (owner's rule), and a claim cannot
    raise the entity it lands on, so it is refused instead. One rule, read
    by the accept route, the service and the card, as
    `accepted_classification` is for NODE and EDGE.

    `case_compartments` are the compartments of the case the ENTITY is in
    (L1, 2026-09-24). Every read of an entity passes its case's gate, so
    whoever reads the entity already holds its case's keys
    (security/access.py), and an entity's effective compartments are its
    own and its case's. Once a capture into a compartmented case carries
    the case's keys, comparing with the entity's own alone would refuse
    every claim cited to that case's material onto that case's own
    entities. The service refuses an entity outside the proposal's case,
    so this cannot reach one elsewhere.
    """
    need = strictest((payload or {}).get("classification"), labels.source)
    held = (frozenset(entity_compartments or ())
            | frozenset(case_compartments or ()))
    missing = labels.compartments - held
    below = need is not None and _rank(need) > _rank(entity_classification)
    if not below and not missing:
        return None
    found = f"{need} material" if need else "material"
    if labels.compartments:
        found += f" in {_compartment_words(labels.compartments)}"
    has = _compartment_words(held) if held else "no compartments"
    return (f"This claim was found in {found}, and the entity it would be "
            f"attached to is labelled {entity_classification} with {has}. "
            f"A claim is read by everyone who can read its entity, so it is "
            f"never accepted onto an entity labelled below what it was "
            f"found in.")


@dataclass(frozen=True)
class ProposalRow:
    id: UUID
    case_id: UUID
    kind: str
    payload: dict
    origin: str
    score: float | None
    rationale: str
    state: str
    document_id: UUID | None
    reviewed_by: UUID | None
    reviewed_at: datetime | None
    review_note: str | None
    applied_node_id: UUID | None
    applied_edge_id: UUID | None
    created_at: datetime
    #: The assertion an accept wrote. Not a column: set only on the row
    #: `ProposalReview.accept` returns, so the console can offer an Undo
    #: for an ATTRIBUTE claim, which creates no element to retire
    #: (ux08-triage:triage-keys-fire-on-browser-chords, 2026-09-23).
    applied_assertion_id: UUID | None = None
    #: The lookup answer this proposal was raised from (F15.3, 2026-09-24;
    #: migration 0100). None for every other source.
    lookup_result_id: UUID | None = None


def _row(r) -> ProposalRow:
    return ProposalRow(
        id=r[0], case_id=r[1], kind=r[2], payload=r[3], origin=r[4],
        score=float(r[5]) if r[5] is not None else None, rationale=r[6],
        state=r[7], document_id=r[8], reviewed_by=r[9], reviewed_at=r[10],
        review_note=r[11], applied_node_id=r[12], applied_edge_id=r[13],
        created_at=r[14],
        lookup_result_id=r[15] if len(r) > 15 else None,  # F15.3
    )


_SELECT = """SELECT id, case_id, kind, payload, origin, score, rationale,
                    state, document_id, reviewed_by, reviewed_at, review_note,
                    applied_node_id, applied_edge_id, created_at,
                    lookup_result_id
               FROM collect.proposal"""

#: The live channel `http/routers/live.py` LISTENs on (its `CHANNEL`),
#: spelled here because a service module must not import the HTTP layer.
#: `test_triage_inbox_pg.py` holds the two equal.
CHANGE_CHANNEL = "noctornal_change"

#: The labels of what a proposal came from, joined once for every read
#: that must filter or show them (ux08-triage:accept-downgrades-
#: classification, 2026-09-23). Three sources, the strictest wins, as
#: SQL's GREATEST ignores the absent ones:
#:
#: - the payload's own `classification`, which a capture writes since
#:   this fix and a hand-built proposal may carry;
#: - the captured document's (`collect.document.classification`), which
#:   covers every capture raised before the payload carried it, and its
#:   compartments since L1 (2026-09-24, `_SOURCE_COMPARTMENTS`);
#: - the contact block's, with its compartments, for an ATTRIBUTE claim
#:   parsed from one (`comms.contact_block_entry.proposal_id`).
#:
#: The queue read `collect.proposal` alone, so a RED capture's rationale,
#: which quotes 45 characters either side of each match, was shown to any
#: reader of the case whatever their clearance.
#:
#: The document's and the contact block's labels come from
#: `iam.element_facts` (S1, 2026-09-25), not joins to `collect.document`
#: and `comms.contact_block`: under row-level security a LEFT JOIN to a
#: row the reader may not see reads as no row at all, and the
#: strictest-of below would then LOWER the proposal to what is left.
_SOURCE_FROM = """
    FROM collect.proposal p
    JOIN core."case" c ON c.id = p.case_id
    LEFT JOIN LATERAL iam.element_facts('document', p.document_id) d ON true
    LEFT JOIN LATERAL iam.element_facts('proposal_block', p.id) b ON true
    LEFT JOIN ingest.lookup_result lr ON lr.id = p.lookup_result_id"""

_PAYLOAD_CLS = """CASE WHEN p.payload->>'classification' IN
        ('CLEAR', 'GREEN', 'AMBER', 'AMBER_STRICT', 'RED')
        THEN (p.payload->>'classification')::core.tlp END"""

#: The label a READER must dominate: everything the proposal's text could
#: carry, and the case it sits in.
_READ_LABEL = (f"greatest({_PAYLOAD_CLS}, d.classification, b.classification, "
               f"lr.classification, c.classification)")  # lr: F15.3

#: The compartments of what a proposal came from: its captured document's
#: and its contact block's (L1, 2026-09-24). A capture into a compartmented
#: case now carries the case's keys, and a proposal's rationale quotes the
#: document, so a reader must hold them to see the proposal at all. One
#: expression for every read and for `source_labels`, so the queue, the
#: counts, the source view and the accept default cannot disagree about
#: them. A later source leg (F15.3) extends THIS expression
#: and `_SOURCE_FROM`, never a second join.
_SOURCE_COMPARTMENTS = ("(coalesce(d.compartments, '{}'::text[]) "
                        "|| coalesce(b.compartments, '{}'::text[]))")

_READABLE = (f"({_READ_LABEL} <= %(clearance)s::core.tlp "
             f"AND {_SOURCE_COMPARTMENTS} <@ %(held)s::text[])")


@dataclass(frozen=True)
class SourceLabels:
    """What a proposal came from, for the accept default and the card."""

    #: The strictest of the document's and the contact block's labels, or
    #: None when the proposal names no source material.
    source: str | None
    #: The case's classification: the floor nothing in it may go below.
    floor: str
    compartments: frozenset[str]


def announce(conn: psycopg.Connection, case_id: UUID) -> None:
    """Tell the live channel this case's triage queue changed.

    ux08-triage:stale-badges-and-list (2026-09-23). The Triage badge is
    the one signal that work is waiting, and nothing moved it until the
    case was reopened: migration 0045 put change triggers on node, edge
    and notification and none on `collect.proposal`, and a schema change
    is not this fix's to make. So the two classes that write the queue
    announce it themselves. Like the triggers, the event carries no
    content, only "case X, kind proposal"; the console refetches through
    the gated route. Inside a transaction Postgres folds identical
    notifications into one, which is why a capture raises its proposals
    in one.
    """
    conn.execute(
        "SELECT pg_notify(%s, json_build_object('case_id', %s::uuid, "
        "'kind', 'proposal', 'op', 'CHANGE')::text)",
        (CHANGE_CHANNEL, case_id))


class ProposalStore:
    """The extractor-facing half. Holds NO GraphWriteService, on purpose:
    invariant 3 is enforced by this class being unable to write the graph,
    not by remembering not to."""

    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def propose(
        self,
        *,
        case_id: UUID,
        kind: str,
        payload: dict,
        origin: str,
        rationale: str,
        score: float | None = None,
        document_id: UUID | None = None,
        lookup_result_id: UUID | None = None,  # F15.3
    ) -> UUID:
        """Record a machine's suggestion. Never touches the graph.

        `rationale` is NOT NULL in the schema and that is deliberate: docs/03
        insists every prediction carries a plain-language explanation of the
        signal, because "suggested because these two personas posted within
        90 seconds of each other in 14 separate threads across 3 forums" is
        reviewable and "0.87" is not.
        """
        if kind not in KINDS:
            raise ProposalError(
                f"unknown proposal kind {kind!r}; one of {sorted(KINDS)}")
        if not rationale or not rationale.strip():
            raise ProposalError(
                "a proposal must explain its signal in words; a bare score is "
                "not reviewable")
        if score is not None and not 0.0 <= score <= 1.0:
            raise ProposalError("score must be between 0 and 1")
        if not origin or not origin.strip():
            raise ProposalError("a proposal must name what produced it")
        try:
            made = self._c.execute(
                """INSERT INTO collect.proposal
                       (case_id, kind, payload, origin, score, rationale,
                        document_id, state, lookup_result_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, 'PROPOSED', %s)
                   RETURNING id""",
                (case_id, kind, Json(payload), origin, score,
                 rationale.strip(), document_id, lookup_result_id),
            ).fetchone()[0]
        except psycopg.Error as exc:
            raise ProposalError(str(exc)) from exc
        announce(self._c, case_id)
        return made

    def queue(self, case_id: UUID, *, state: str = STATE_PROPOSED,
              limit: int = 100, clearance: str | None = None,
              compartments: frozenset[str] = frozenset(),
              ) -> list[ProposalRow]:
        """The triage queue. Ordered by score DESC so the most confident
        suggestions surface first — but score is a hint about ordering, not
        about truth, and nothing here is applied without a person.

        With `clearance`, only the proposals whose source labels the reader
        dominates (`_READABLE`, ux08-triage:accept-downgrades-
        classification, 2026-09-23). Filtered in SQL, so a page is never
        short and the LIMIT counts what the reader actually gets."""
        where, params = self._scope(case_id, clearance, compartments)
        params.update(state=state, limit=limit)
        rows = self._c.execute(
            "SELECT p.id, p.case_id, p.kind, p.payload, p.origin, p.score, "
            "p.rationale, p.state, p.document_id, p.reviewed_by, "
            "p.reviewed_at, p.review_note, p.applied_node_id, "
            "p.applied_edge_id, p.created_at, p.lookup_result_id" + _SOURCE_FROM
            + f" WHERE {where} AND p.state = %(state)s::core.review_state"
            " ORDER BY p.score DESC NULLS LAST, p.created_at LIMIT %(limit)s",
            params).fetchall()
        return [_row(r) for r in rows]

    def get(self, proposal_id: UUID) -> ProposalRow | None:
        row = self._c.execute(_SELECT + " WHERE id = %s", (proposal_id,)).fetchone()
        return _row(row) if row else None

    def counts(self, case_id: UUID, *, clearance: str | None = None,
               compartments: frozenset[str] = frozenset()) -> dict[str, int]:
        """Per state, by the same filter as `queue`: a badge that counts
        what the list will not show is a badge that never clears."""
        where, params = self._scope(case_id, clearance, compartments)
        rows = self._c.execute(
            "SELECT p.state, count(*)" + _SOURCE_FROM
            + f" WHERE {where} GROUP BY p.state", params).fetchall()
        return {r[0]: r[1] for r in rows}

    def source_labels(self, proposal_id: UUID) -> SourceLabels:
        """The labels of the material behind one proposal, and its case's
        floor: what an accept writes by default and the least it may."""
        row = self._c.execute(
            "SELECT greatest(d.classification, b.classification, "
            "lr.classification), "  # F15.3
            "c.classification, " + _SOURCE_COMPARTMENTS
            + _SOURCE_FROM + " WHERE p.id = %(id)s", {"id": proposal_id},
        ).fetchone()
        if row is None:
            raise ProposalError(f"proposal {proposal_id} not found")
        return SourceLabels(source=row[0], floor=row[1],
                            compartments=frozenset(row[2] or []))

    def source_labels_many(self, ids: list[UUID]) -> dict[UUID, SourceLabels]:
        """`source_labels` for a page of proposals, in one read rather than
        one per card."""
        if not ids:
            return {}
        rows = self._c.execute(
            "SELECT p.id, greatest(d.classification, b.classification, "
            "lr.classification), "  # F15.3
            "c.classification, " + _SOURCE_COMPARTMENTS
            + _SOURCE_FROM + " WHERE p.id = ANY(%(ids)s)", {"ids": list(ids)},
        ).fetchall()
        return {r[0]: SourceLabels(source=r[1], floor=r[2],
                                   compartments=frozenset(r[3] or []))
                for r in rows}

    def readable(self, proposal_id: UUID, *, clearance: str,
                 compartments: frozenset[str]) -> bool:
        """Whether a reader at this ceiling may see this proposal at all."""
        row = self._c.execute(
            "SELECT " + _READABLE + _SOURCE_FROM + " WHERE p.id = %(id)s",
            {"id": proposal_id, "clearance": clearance,
             "held": sorted(compartments)}).fetchone()
        return bool(row and row[0])

    def lookup_origins(self, ids: list[UUID]) -> dict[UUID, dict]:
        """For proposals raised from a lookup answer (F15.3, 2026-09-24):
        which answer, from which provider, fetched when. One read for a
        page of cards."""
        if not ids:
            return {}
        rows = self._c.execute(
            """SELECT p.id, r.id, pr.display_name, r.fetched_at
                 FROM collect.proposal p
                 JOIN ingest.lookup_result r ON r.id = p.lookup_result_id
                 JOIN ingest.provider pr ON pr.id = r.provider_id
                WHERE p.id = ANY(%s)""", (list(ids),)).fetchall()
        return {r[0]: {"result_id": str(r[1]), "provider_name": r[2],
                       "fetched_at": r[3].isoformat()} for r in rows}

    def pending_by_node(self, case_id: UUID, *, clearance: str,
                        compartments: frozenset[str]) -> dict[str, int]:
        """How many readable PROPOSED claims name each entity.

        ux08-triage:graph-says-unreviewed-triage-says-nothing (2026-09-23).
        The sociogram ringed a node for every incident edge whose
        `review` column was PROPOSED, and nothing ever writes that column
        (it defaults to PROPOSED, and an edge accepted here is created
        PROPOSED too), so every tie in the demo estate was "unreviewed"
        while this queue said nothing was waiting. The ring now means what
        its legend says: a proposal about this entity is waiting in this
        queue. An ATTRIBUTE names its entity, an EDGE names two; a NODE
        proposal names none, because the entity does not exist yet.

        Only entities the reader may see are counted, so the map names no
        id the projection would have hidden."""
        where, params = self._scope(case_id, clearance, compartments)
        rows = self._c.execute(
            "SELECT x.node_id, count(*) FROM ("
            "  SELECT CASE WHEN p.kind = 'ATTRIBUTE' THEN p.payload->>'node_id'"
            "              ELSE p.payload->>'src_node_id' END AS node_id"
            + _SOURCE_FROM + f" WHERE {where} AND p.state = 'PROPOSED'"
            "     AND p.kind IN ('ATTRIBUTE', 'EDGE')"
            "  UNION ALL"
            "  SELECT p.payload->>'dst_node_id'"
            + _SOURCE_FROM + f" WHERE {where} AND p.state = 'PROPOSED'"
            "     AND p.kind = 'EDGE'"
            ") x JOIN core.node n ON n.id::text = x.node_id"
            "  WHERE n.case_id = %(case_id)s AND n.deleted_at IS NULL"
            "    AND n.classification <= %(clearance)s::core.tlp"
            "    AND n.compartments <@ %(held)s::text[]"
            " GROUP BY x.node_id", params).fetchall()
        return {r[0]: r[1] for r in rows}

    def node_refs(self, case_id: UUID, ids: set[str], *, clearance: str,
                  compartments: frozenset[str]) -> dict[str, dict]:
        """Label and type of the entities a page of proposals names, for
        the ones this reader may see (ux08-triage:attribute-proposal-no-
        label-no-value, 2026-09-23). An ATTRIBUTE card read "(no label)"
        and never said which entity would gain which identifier, and an
        EDGE card would have shown two UUIDs. An entity the reader may not
        see is simply absent, and the card says so rather than naming it."""
        wanted = []
        for raw in ids:
            try:
                wanted.append(UUID(str(raw)))
            except ValueError:
                continue
        if not wanted:
            return {}
        rows = self._c.execute(
            """SELECT id, label, node_type FROM core.node
                WHERE id = ANY(%s) AND case_id = %s
                  AND classification <= %s::core.tlp
                  AND compartments <@ %s::text[]""",
            (wanted, case_id, clearance, sorted(compartments))).fetchall()
        return {str(r[0]): {"label": r[1], "node_type": r[2]} for r in rows}

    def documents(self, ids: set[UUID], *,
                  compartments: frozenset[str] = frozenset()
                  ) -> dict[str, dict]:
        """Title and labels of the captured documents a page names, for the
        ones whose compartments the reader holds (L1, 2026-09-24). The
        queue only lists proposals whose source the reader may read, so
        this is a second lock on the same door, not the first: a bare read
        by id was how the source view reached a document before. The
        default is the EMPTY set, which fails closed: a caller that does
        not say what it holds sees no compartmented document."""
        if not ids:
            return {}
        rows = self._c.execute(
            """SELECT id, title, classification, captured_at, external_url,
                      compartments
                 FROM collect.document
                WHERE id = ANY(%s) AND compartments <@ %s::text[]""",
            (list(ids), sorted(compartments))).fetchall()
        return {str(r[0]): {"title": r[1], "classification": r[2],
                            "captured_at": r[3].isoformat() if r[3] else None,
                            "external_url": r[4],
                            "compartments": sorted(r[5] or [])}
                for r in rows}

    def waiting_by_case(self, user_id: UUID, *, clearance: str,
                        compartments: frozenset[str]) -> dict[str, int]:
        """PROPOSED proposals this person would see in each case's queue.

        ux08-triage:no-work-waiting-at-sign-in (2026-09-23): the case list
        said nothing about what needed the analyst, so the first question
        after sign-in was answered by opening every case in turn. Counted
        over the cases the person holds a live assignment on whose role
        carries `case.read`, whose own labels they dominate, by the same
        per-proposal filter the queue uses. The ceiling is the case-less
        one: a case-scoped break-glass grant raises a read of that case
        only, and this read spans them all.

        A read-only case (CLOSED, ARCHIVED, PURGED) counts nothing (final
        review u2, 2026-09-24). Accept, reject and defer are content writes
        and all refuse there, proposals never expire, and an ARCHIVED case
        cannot be reopened, so a case closed with work in its queue said
        "2 proposals to triage" on the case list for good, as a nag nobody
        was allowed to clear. The queue itself still lists them."""
        rows = self._c.execute(
            "SELECT p.case_id, count(*)" + _SOURCE_FROM
            + " WHERE p.state = 'PROPOSED' AND " + _READABLE
            + """ AND c.compartments <@ %(held)s::text[]
                  AND NOT (c.status::text = ANY(%(shut)s::text[]))
                  AND EXISTS (
                      SELECT 1 FROM iam.case_assignment ca
                        JOIN iam.role_permission rp
                          ON rp.role_key = ca.role_key
                         AND rp.permission_key = 'case.read'
                       WHERE ca.case_id = p.case_id
                         AND ca.user_id = %(user)s
                         AND (ca.expires_at IS NULL OR ca.expires_at > now()))
                GROUP BY p.case_id""",
            {"clearance": clearance, "held": sorted(compartments),
             "user": user_id,
             "shut": sorted(CONTENT_READ_ONLY_STATES)}).fetchall()
        return {str(r[0]): r[1] for r in rows}

    def entity_labels(self, case_id: UUID,
                      ids: set[str]) -> dict[str, tuple[str, frozenset[str]]]:
        """Classification and compartments of this case's entities by id.
        For the card's accept check (`attribute_label_problem`) and only
        ever asked about entities `node_refs` has already shown the
        reader, so it names no label the reader could not see."""
        wanted = []
        for raw in ids:
            try:
                wanted.append(UUID(str(raw)))
            except ValueError:
                continue
        if not wanted:
            return {}
        rows = self._c.execute(
            """SELECT id, classification, compartments FROM core.node
                WHERE id = ANY(%s) AND case_id = %s""",
            (wanted, case_id)).fetchall()
        return {str(r[0]): (r[1], frozenset(r[2] or [])) for r in rows}

    @staticmethod
    def _scope(case_id: UUID, clearance: str | None,
               compartments: frozenset[str]) -> tuple[str, dict]:
        params: dict = {"case_id": case_id}
        if clearance is None:
            return "p.case_id = %(case_id)s", params
        params.update(clearance=clearance, held=sorted(compartments))
        return "p.case_id = %(case_id)s AND " + _READABLE, params


class ProposalReview:
    """The analyst-facing half: the ONLY path from a proposal into the
    graph, and it requires a human."""

    def __init__(self, conn: psycopg.Connection):
        self._c = conn
        self._graph = GraphWriteService(conn)

    def accept(self, proposal_id: UUID, *, reviewed_by: UUID,
               note: str | None = None,
               classification: str | None = None) -> ProposalRow:
        """Apply a proposal to the graph, as the reviewing analyst.

        The element is created through `GraphWriteService`, so its assertion
        is written in the same transaction (invariant 1) and the accepted
        proposal is not a privileged path around the model. The assertion's
        basis is AUTOMATED_INFERENCE carrying the proposer's rationale: the
        graph should never forget that a machine suggested this, and docs/03
        wants inference distinguishable from observation forever.
        """
        row = self.get_for_update(proposal_id)
        if row.state != STATE_PROPOSED:
            # Applying twice would create a second element from one
            # suggestion and silently double an actor's degree.
            raise ProposalError(
                f"proposal is {row.state}, not {STATE_PROPOSED}; it has already "
                "been dispositioned")

        # When the material was seen: the post's own date, or failing that
        # when it was captured (final review u6, 2026-09-24). First and
        # last seen are derived from `observed_at` on an entity's live
        # claims (projections.seen_sql), and this claim never set it, so
        # every entity accepted from Triage read "no claim dates an
        # observation" with a blank First seen, and a newer capture's
        # selector attached to a known actor never moved its last seen,
        # although the document it cites holds both dates.
        observed_at = self._observed_at(row.document_id)
        # F15.3 (2026-09-24): a claim raised from a lookup answer cites
        # the provider's anchor source and the stored answer, and is dated
        # by when the answer was fetched.
        lookup_source, lookup_result = None, row.lookup_result_id
        if lookup_result is not None:
            found = self._c.execute(
                """SELECT p.source_id, r.fetched_at FROM ingest.lookup_result r
                     JOIN ingest.provider p ON p.id = r.provider_id
                    WHERE r.id = %s""", (lookup_result,)).fetchone()
            if found is not None:
                lookup_source, observed_at = found[0], found[1]
        assertion = AssertionInput(
            basis="AUTOMATED_INFERENCE",
            created_by=reviewed_by,
            # Graded low by default. A machine's suggestion accepted by a
            # human is not thereby a direct observation, and starting it at
            # anything higher would launder confidence the data never had.
            reliability="F", credibility="6", confidence="LOW",
            rationale=f"[{row.origin}] {row.rationale}",
            document_id=row.document_id,
            observed_at=observed_at,
            source_id=lookup_source, lookup_result_id=lookup_result,  # F15.3
        )
        payload = row.payload or {}
        node_id = edge_id = assertion_id = None
        # The accept default and its floor: what the proposal came from,
        # never below the case (gap-capture-classification, 2026-09-23).
        labels = ProposalStore(self._c).source_labels(proposal_id)
        written_at = None
        if row.kind in (KIND_NODE, KIND_EDGE):
            written_at = accepted_classification(
                payload, classification, source=labels.source,
                floor=labels.floor)
        #: The compartments an accepted element carries (L1, 2026-09-24):
        #: those of its material beyond the case's own. Every read of an
        #: element passes its case's gate, and elements elsewhere in a
        #: compartmented case carry none of the case's keys, so copying
        #: them would only make one case's elements disagree. A key the
        #: material carries that the case does not (a contact block filed
        #: under a stricter compartment) is the element's own lock. Empty
        #: for ATTRIBUTE, which writes a claim, not an element.
        extra: list[str] = []
        try:
            with self._c.transaction():
                # CR10 (2026-07-26): take the row lock INSIDE the writing
                # transaction, and re-check the state under it.
                #
                # `get_for_update` is a plain SELECT despite its name, on
                # an autocommit connection — so it took no lock at all. The
                # graph write then ran BEFORE the state-guarded UPDATE, and
                # that UPDATE's rowcount was never checked. Under READ
                # COMMITTED two concurrent accepts each passed the
                # pre-check, each created an element, and the loser's
                # `WHERE state = 'PROPOSED'` matched zero rows, raised
                # nothing, and committed anyway.
                #
                # Result: two nodes from one suggestion, the second
                # unreferenced by `applied_node_id` — an orphan inflating
                # the actor count with no record of where it came from,
                # which is invariant 3 undone by a race.
                locked = self._c.execute(
                    "SELECT state FROM collect.proposal WHERE id = %s "
                    "FOR UPDATE", (proposal_id,)).fetchone()
                if locked is None:
                    raise ProposalError(f"proposal {proposal_id} not found")
                if locked[0] != STATE_PROPOSED:
                    raise ProposalError(
                        f"proposal is {locked[0]}, not {STATE_PROPOSED}; it "
                        "has already been dispositioned")
                if row.kind in (KIND_NODE, KIND_EDGE):
                    extra = element_compartments(
                        labels, self.case_compartments(row.case_id))
                if row.kind == KIND_NODE:
                    node_id = self._graph.create_node(
                        case_id=row.case_id,
                        node_type=payload["node_type"],
                        label=payload["label"],
                        created_by=reviewed_by,
                        assertion=assertion,
                        attrs=payload.get("attrs") or {},
                        classification=written_at,
                        compartments=extra,
                    )
                elif row.kind == KIND_EDGE:
                    edge_id = self._graph.create_edge(
                        case_id=row.case_id,
                        edge_type=payload["edge_type"],
                        src_node_id=UUID(str(payload["src_node_id"])),
                        dst_node_id=UUID(str(payload["dst_node_id"])),
                        created_by=reviewed_by,
                        assertion=assertion,
                        classification=written_at,
                        compartments=extra,
                        # Invariant 4: an edge born from a machine's
                        # suggestion is INFERRED, renders dashed and stays
                        # out of metrics unless a projection opts in. It
                        # never silently becomes an asserted tie.
                        is_inferred=True,
                        inference_method=row.origin,
                        # Accepting IS the disposal (ux05 review-state-
                        # never-leaves-proposed, 2026-09-23): the claim
                        # keeps the machine's basis, so without this the
                        # tie would be born PROPOSED and ringed as awaiting
                        # the review this click has just given it.
                        review="ACCEPTED",
                    )
                elif row.kind == KIND_ATTRIBUTE:
                    # An attribute claim is an assertion against an existing
                    # element, not a new element -- claim_path/claim_value is
                    # exactly what the assertion model has for this.
                    target = UUID(str(payload["node_id"]))
                    # The entity's labels, held for the write: the claim
                    # is read at them, so they must dominate what it was
                    # found in (final review c1, 2026-09-24). Checked
                    # here as well as on the route because the service
                    # has other callers.
                    #
                    # With its case's compartments, and in the proposal's
                    # case (L1, 2026-09-24): an entity's effective
                    # compartments include its case's, which is only safe
                    # to count once the entity is known to be in the case
                    # whose readers the proposal was raised for. The route
                    # has refused a foreign entity since C12; the service
                    # did not, and it is the one every caller shares.
                    entity = self._c.execute(
                        """SELECT n.classification, n.compartments,
                                  n.case_id, ec.compartments
                             FROM core.node n
                             JOIN core."case" ec ON ec.id = n.case_id
                            WHERE n.id = %s FOR SHARE OF n""",
                        (target,)).fetchone()
                    if entity is None:
                        raise ProposalError(
                            "the entity this proposal makes a claim about "
                            "does not exist; nothing was written")
                    if entity[2] != row.case_id:
                        raise ProposalError(
                            "the entity this proposal makes a claim about "
                            "is not in this case; nothing was written")
                    problem = attribute_label_problem(
                        payload, labels, entity[0], entity[1],
                        case_compartments=entity[3])
                    if problem:
                        raise ProposalError(
                            f"{problem} Nothing was written: reject or "
                            f"defer it.")
                    assertion_id = self._graph.add_assertion(
                        case_id=row.case_id,
                        node_id=target,
                        assertion=AssertionInput(
                            basis="AUTOMATED_INFERENCE", created_by=reviewed_by,
                            reliability="F", credibility="6", confidence="LOW",
                            rationale=f"[{row.origin}] {row.rationale}",
                            document_id=row.document_id,
                            observed_at=observed_at,
                            claim_path=payload["claim_path"],
                            claim_value=payload["claim_value"],
                            source_id=lookup_source,  # F15.3
                            lookup_result_id=lookup_result,
                        ),
                    )
                    node_id = target
                else:
                    raise ProposalError(f"cannot apply kind {row.kind!r}")

                applied = self._c.execute(
                    """UPDATE collect.proposal
                          SET state = 'ACCEPTED', reviewed_by = %s,
                              reviewed_at = %s, review_note = %s,
                              applied_node_id = %s, applied_edge_id = %s
                        WHERE id = %s AND state = 'PROPOSED'""",
                    (reviewed_by, datetime.now(timezone.utc), note,
                     node_id, edge_id, proposal_id),
                )
                # CR10: the rowcount is the last line of defence. With the
                # FOR UPDATE above this should be unreachable — so if it
                # ever fires, the lock is not doing what this code thinks,
                # and rolling back is far better than committing an
                # element nothing points at.
                if applied.rowcount != 1:
                    raise ProposalError(
                        "the proposal changed state while it was being "
                        "applied; nothing was written")
                self._audit(row.case_id, proposal_id, reviewed_by,
                            "PROPOSAL_ACCEPTED",
                            {"kind": row.kind, "origin": row.origin,
                             "node_id": str(node_id) if node_id else None,
                             "edge_id": str(edge_id) if edge_id else None,
                             "classification": written_at,
                             "compartments": extra})
                announce(self._c, row.case_id)
        except KeyError as exc:
            raise ProposalError(
                f"proposal payload is missing {exc} for kind {row.kind}") from exc
        except GraphWriteError as exc:
            raise ProposalError(f"could not apply proposal: {exc}") from exc
        return replace(self.get_for_update(proposal_id),
                       applied_assertion_id=assertion_id)

    def reject(self, proposal_id: UUID, *, reviewed_by: UUID,
               note: str) -> ProposalRow:
        """Dispose of a proposal without applying it. A note is required:
        a rejected proposal with no reason teaches the extractor's owner
        nothing, and parser drift is found by reading these."""
        if not note or not note.strip():
            raise ProposalError("a rejection must say why")
        return self._disposition(proposal_id, STATE_REJECTED, reviewed_by,
                                 note.strip(), "PROPOSAL_REJECTED")

    def defer(self, proposal_id: UUID, *, reviewed_by: UUID,
              note: str) -> ProposalRow:
        """Park an ambiguous proposal as DISPUTED. A queue whose only
        options are yes and no forces a decision on items that do not
        deserve one yet."""
        if not note or not note.strip():
            raise ProposalError("a deferral must say what is unresolved")
        return self._disposition(proposal_id, STATE_DISPUTED, reviewed_by,
                                 note.strip(), "PROPOSAL_DEFERRED")

    # -- internals --------------------------------------------------------
    def case_compartments(self, case_id: UUID) -> frozenset[str]:
        return case_compartments(self._c, case_id)

    def _observed_at(self, document_id: UUID | None) -> datetime | None:
        """The cited document's posted date, else its capture date; None
        when the proposal cites no document (a contact block parsed
        without one), because nothing then says when it was seen."""
        if document_id is None:
            return None
        row = self._c.execute(
            "SELECT coalesce(posted_at, captured_at) FROM collect.document "
            "WHERE id = %s", (document_id,)).fetchone()
        return row[0] if row else None

    def get_for_update(self, proposal_id: UUID) -> ProposalRow:
        row = self._c.execute(_SELECT + " WHERE id = %s",
                              (proposal_id,)).fetchone()
        if row is None:
            raise ProposalError(f"proposal {proposal_id} not found")
        return _row(row)

    def _disposition(self, proposal_id: UUID, state: str, reviewed_by: UUID,
                     note: str, action: str) -> ProposalRow:
        row = self.get_for_update(proposal_id)
        if row.state == STATE_ACCEPTED:
            # An accepted proposal has already produced a graph element;
            # flipping its state would leave that element with no record of
            # where it came from.
            raise ProposalError(
                "an accepted proposal cannot be re-dispositioned; retract the "
                "assertion it created instead")
        with self._c.transaction():
            self._c.execute(
                """UPDATE collect.proposal
                      SET state = %s::core.review_state, reviewed_by = %s,
                          reviewed_at = %s, review_note = %s
                    WHERE id = %s""",
                (state, reviewed_by, datetime.now(timezone.utc), note,
                 proposal_id),
            )
            self._audit(row.case_id, proposal_id, reviewed_by, action,
                        {"kind": row.kind, "origin": row.origin, "note": note})
            announce(self._c, row.case_id)
        return self.get_for_update(proposal_id)

    def _audit(self, case_id: UUID, proposal_id: UUID, actor_id: UUID,
               action: str, detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'proposal', %s, %s, %s)""",
            (actor_id, action, proposal_id, case_id, Json(detail)),
        )

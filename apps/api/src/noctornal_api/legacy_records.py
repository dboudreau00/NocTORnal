"""Records written under a rule that has since changed. Every function here
lists and none writes (L1, L2 and L5, 2026-09-24).

Four kinds, each listed by `scripts/legacy_records.py` on the server and
counted on the readiness register:

- **Undated Triage claims.** Since final review u6 (2026-09-24) an accept
  dates its claim from the cited document. Claims accepted earlier carry
  no `observed_at`, so First seen and Last seen ignore them. Invariant 5
  (CONVENTIONS.md) says a claim's own columns are never written again, so
  nothing here fills the date: amending that invariant is the owner's
  decision, and until it is recorded as one no code path writes
  `observed_at` on an existing claim. The listing gives each claim the
  date its document gives, so an analyst can add a dated claim where it
  matters.
- **ATTRIBUTE claims below their material.** Since final review c1 an
  accept refuses an ATTRIBUTE claim onto an entity labelled below what it
  was found in, and since C12 the route refuses an entity in another case.
  Claims accepted before either are still read by everyone who reads the
  entity. Listed by the one rule the accept applies
  (`proposals.attribute_label_problem`, with the entity's case's
  compartments, as L1 leaves it), and every cross-case claim whatever its
  labels. There is no verb that raises an existing entity's label, so the
  remedy is to retract the claim, which the listing says.
- **Captures no lock fits.** 0071 labelled captured documents from the
  cases that cite them; one cited by an uncompartmented case, or by
  compartmented cases with no key in common, keeps no compartment and is
  listed to every collection reader at its label. Also the captures that
  carry a compartment an ingest feed now uses for victim data, captured
  before a key forced it.
- **URLs whose identity changed.** `url_norm` keeps a fragment that names
  a resource since L5. Stored selectors are not rewritten: a shared row's
  raw value is only its first observation, so no machine can split it.

The output names cases, entities and identifiers (a Tox ID or a social
URL is personal data): it is for the server, never for a ticket. Counts
are what the readiness register shows, because the register's reader
holds `user.manage`, not case content.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

import psycopg

from noctornal_api.cases import CONTENT_READ_ONLY_STATES
from noctornal_api.extraction import VICTIM_DATA_SQL
from noctornal_api.proposals import (
    _SOURCE_COMPARTMENTS,
    _SOURCE_FROM,
    SourceLabels,
    attribute_label_problem,
    strictest,
)

# ---------------------------------------------------------------------------
# Claims accepted from Triage
# ---------------------------------------------------------------------------

#: The claim an accept wrote, joined to the proposal it came from: the join
#: `ProposalReview.accept` makes true (proposals.py), read back. An accepted
#: NODE or EDGE founds its element with an AUTOMATED_INFERENCE claim by the
#: reviewer citing the proposal's document; an ATTRIBUTE adds one with the
#: payload's path and value. Live claims only.
ACCEPT_BORN_SQL = """
  FROM collect.proposal p
  JOIN core.assertion a
    ON a.case_id = p.case_id
   AND a.basis = 'AUTOMATED_INFERENCE'
   AND a.created_by = p.reviewed_by
   AND a.document_id IS NOT DISTINCT FROM p.document_id
   AND ((p.kind = 'NODE' AND a.node_id = p.applied_node_id
         AND a.claim_path IS NULL)
     OR (p.kind = 'EDGE' AND a.edge_id = p.applied_edge_id
         AND a.claim_path IS NULL)
     OR (p.kind = 'ATTRIBUTE' AND a.node_id::text = p.payload->>'node_id'
         AND a.claim_path = p.payload->>'claim_path'
         AND a.claim_value = p.payload->'claim_value'))
 WHERE p.state = 'ACCEPTED'
   AND a.retracted_at IS NULL AND a.superseded_at IS NULL"""

_UNDATED_FROM = """
  JOIN collect.document d ON d.id = p.document_id
  JOIN core."case" c ON c.id = a.case_id"""


def _undated_query(select: str, tail: str = "") -> str:
    """ACCEPT_BORN_SQL with the document and case joined in before its
    WHERE, which is where a JOIN has to go."""
    head, where = ACCEPT_BORN_SQL.split(" WHERE ", 1)
    return (select + head + _UNDATED_FROM + " WHERE " + where
            + " AND a.observed_at IS NULL AND p.document_id IS NOT NULL"
            + tail)


@dataclass(frozen=True)
class UndatedClaim:
    assertion_id: UUID
    case_id: UUID
    case_code: str
    element_kind: str          # 'node' or 'edge'
    element_id: UUID
    proposal_id: UUID
    document_id: UUID
    would_date: datetime
    date_from: str             # 'posted' or 'captured'


def undated_triage_claims(conn: psycopg.Connection) -> list[UndatedClaim]:
    """Claims accepted from Triage before Alpha 6 that cite a document and
    carry no observation date, with the date that document gives. A claim
    citing no document is not listed: nothing says when it was seen, which
    is also what the accept does."""
    rows = conn.execute(_undated_query(
        """SELECT a.id, a.case_id, c.code,
                  CASE WHEN a.edge_id IS NOT NULL THEN 'edge' ELSE 'node' END,
                  coalesce(a.edge_id, a.node_id), p.id, d.id,
                  coalesce(d.posted_at, d.captured_at),
                  CASE WHEN d.posted_at IS NOT NULL THEN 'posted'
                       ELSE 'captured' END""",
        " ORDER BY c.code, a.recorded_at")).fetchall()
    return [UndatedClaim(*r) for r in rows]


def undated_count(conn: psycopg.Connection) -> int:
    return conn.execute(_undated_query("SELECT count(*)")).fetchone()[0]


@dataclass(frozen=True)
class UnderlabelledClaim:
    assertion_id: UUID
    proposal_case_code: str
    entity_case_code: str
    entity_case_status: str
    node_id: UUID
    node_label: str
    node_type: str
    claim_path: str
    claim_value: object
    proposal_id: UUID
    accepted_by_email: str | None
    accepted_at: datetime | None
    material_classification: str | None
    material_compartments: tuple[str, ...]
    entity_classification: str
    entity_compartments: tuple[str, ...]
    reason: str                # 'below' or 'other_case'
    problem: str

    @property
    def closed(self) -> bool:
        """The entity's case takes no content write, so the claim cannot be
        retracted until the case is reopened."""
        return self.entity_case_status in CONTENT_READ_ONLY_STATES


#: Accept-born ATTRIBUTE claims with everything the accept rule reads:
#: the material's labels through `_SOURCE_FROM` (the same legs the queue and
#: the accept join), the entity, the ENTITY's case, and the reviewer.
_UNDERLABELLED_SQL = (
    "SELECT a.id, c.code, ec.code, ec.status::text, n.id, n.label, "
    "n.node_type, a.claim_path, a.claim_value, p.id, u.email, p.reviewed_at, "
    "greatest(d.classification, b.classification), c.classification, "
    + _SOURCE_COMPARTMENTS + ", n.classification, n.compartments, "
    "ec.compartments, p.payload, n.case_id <> p.case_id"
    + _SOURCE_FROM + """
  JOIN core.assertion a
    ON a.case_id = p.case_id
   AND a.basis = 'AUTOMATED_INFERENCE'
   AND a.created_by = p.reviewed_by
   AND a.document_id IS NOT DISTINCT FROM p.document_id
   AND a.node_id::text = p.payload->>'node_id'
   AND a.claim_path = p.payload->>'claim_path'
   AND a.claim_value = p.payload->'claim_value'
  JOIN core.node n ON n.id = a.node_id
  JOIN core."case" ec ON ec.id = n.case_id
  LEFT JOIN iam.app_user u ON u.id = p.reviewed_by
 WHERE p.state = 'ACCEPTED' AND p.kind = 'ATTRIBUTE'
   AND a.retracted_at IS NULL AND a.superseded_at IS NULL
 ORDER BY ec.code, n.label, a.recorded_at""")


def other_case_problem(proposal_case: str, entity_case: str) -> str:
    return (f"This claim was accepted from a proposal in {proposal_case} "
            f"onto an entity of {entity_case}, so whoever reads the entity "
            f"reads a claim found in another case's material.")


def underlabelled_claims(conn: psycopg.Connection
                         ) -> list[UnderlabelledClaim]:
    """ATTRIBUTE claims accepted from Triage that the accept would now
    refuse: readable below the label of what they were found in, or
    attached to an entity in another case (listed whatever its labels,
    since the route refused that only from C12 on)."""
    out: list[UnderlabelledClaim] = []
    for r in conn.execute(_UNDERLABELLED_SQL).fetchall():
        (aid, pcode, ecode, estatus, nid, nlabel, ntype, path, value, pid,
         email, at, source, floor, mcomps, ncls, ncomps, eccomps, payload,
         cross) = r
        labels = SourceLabels(source=source, floor=floor,
                              compartments=frozenset(mcomps or []))
        if cross:
            reason, problem = "other_case", other_case_problem(pcode, ecode)
        else:
            problem = attribute_label_problem(
                payload, labels, ncls, ncomps or (),
                case_compartments=eccomps or ())
            if problem is None:
                continue
            reason = "below"
        out.append(UnderlabelledClaim(
            assertion_id=aid, proposal_case_code=pcode,
            entity_case_code=ecode, entity_case_status=estatus, node_id=nid,
            node_label=nlabel, node_type=ntype, claim_path=path,
            claim_value=value, proposal_id=pid, accepted_by_email=email,
            accepted_at=at,
            material_classification=strictest(
                (payload or {}).get("classification"), source),
            material_compartments=tuple(sorted(mcomps or [])),
            entity_classification=ncls,
            entity_compartments=tuple(sorted(ncomps or [])),
            reason=reason, problem=problem))
    return out


def claim_counts(conn: psycopg.Connection) -> dict:
    """What the register shows: counts, never a case or an entity."""
    listed = underlabelled_claims(conn)
    below = [c for c in listed if c.reason == "below"]
    return {"undated": undated_count(conn),
            "underlabelled": len(below),
            "underlabelled_cases": len({c.entity_case_code for c in below}),
            "other_case": sum(1 for c in listed if c.reason == "other_case"),
            "closed": sum(1 for c in listed if c.closed)}


# ---------------------------------------------------------------------------
# Captures no lock fits (L1)
# ---------------------------------------------------------------------------

#: Captured documents (a MANUAL or PASTE source) that carry no compartment
#: and are cited by at least one compartmented case: 0071's residue, and
#: anything like it since. Starts from those documents and reaches the
#: audit trail through `event_object_id_idx` (`e.object_id = d.id`), never
#: by scanning the trail for an action.
_UNLABELLED_WHERE = """
  FROM collect.document d
  JOIN collect.source s ON s.id = d.source_id
 WHERE s.kind IN ('MANUAL', 'PASTE')
   AND cardinality(d.compartments) = 0
   AND d.purged_at IS NULL
   AND EXISTS (
       SELECT 1 FROM core."case" c
        WHERE cardinality(c.compartments) > 0
          AND (EXISTS (SELECT 1 FROM collect.proposal p
                        WHERE p.document_id = d.id AND p.case_id = c.id)
               OR EXISTS (SELECT 1 FROM core.assertion a
                           WHERE a.document_id = d.id AND a.case_id = c.id)
               OR EXISTS (SELECT 1 FROM comms.contact_block b
                           WHERE b.document_id = d.id AND b.case_id = c.id)
               OR EXISTS (SELECT 1 FROM audit.event e
                           WHERE e.object_id = d.id
                             AND e.action = 'DOCUMENT_CAPTURED'
                             AND e.case_id = c.id)))"""

#: The cases that cite one document, by the same four legs.
_CITING_CASES_SQL = """
SELECT c.code, c.classification::text, c.compartments
  FROM core."case" c
 WHERE EXISTS (SELECT 1 FROM collect.proposal p
                WHERE p.document_id = %(d)s AND p.case_id = c.id)
    OR EXISTS (SELECT 1 FROM core.assertion a
                WHERE a.document_id = %(d)s AND a.case_id = c.id)
    OR EXISTS (SELECT 1 FROM comms.contact_block b
                WHERE b.document_id = %(d)s AND b.case_id = c.id)
    OR EXISTS (SELECT 1 FROM audit.event e
                WHERE e.object_id = %(d)s
                  AND e.action = 'DOCUMENT_CAPTURED' AND e.case_id = c.id)
 ORDER BY c.code"""


@dataclass(frozen=True)
class UnlabelledCapture:
    document_id: UUID
    title: str | None
    classification: str
    captured_at: datetime | None
    #: (code, classification, compartments) of every citing case.
    cases: tuple[tuple[str, str, tuple[str, ...]], ...] = field(
        default_factory=tuple)


def _captures(conn: psycopg.Connection, where: str,
              params=None) -> list[UnlabelledCapture]:
    rows = conn.execute(
        "SELECT d.id, d.title, d.classification::text, d.captured_at"
        + where + " ORDER BY d.captured_at, d.id", params).fetchall()
    out = []
    for doc_id, title, cls, at in rows:
        cases = tuple(
            (code, ccls, tuple(sorted(comps or [])))
            for code, ccls, comps in conn.execute(
                _CITING_CASES_SQL, {"d": doc_id}).fetchall())
        out.append(UnlabelledCapture(doc_id, title, cls, at, cases))
    return out


def unlabelled_captures(conn: psycopg.Connection) -> list[UnlabelledCapture]:
    """Captures a compartmented case cites that carry no compartment."""
    return _captures(conn, _UNLABELLED_WHERE)


def unlabelled_captures_count(conn: psycopg.Connection) -> int:
    return conn.execute("SELECT count(*)" + _UNLABELLED_WHERE).fetchone()[0]


#: Captured documents that carry a compartment an ingest feed uses for
#: victim data: captured before a key forced it, since a capture into such
#: a case is refused (`CaptureService.refusal`).
_VICTIM_WHERE = f"""
  FROM collect.document d
  JOIN collect.source s ON s.id = d.source_id
 WHERE s.kind IN ('MANUAL', 'PASTE')
   AND cardinality(d.compartments) > 0
   AND d.purged_at IS NULL
   AND d.compartments && ARRAY({VICTIM_DATA_SQL})::text[]"""


def victim_data_captures(conn: psycopg.Connection
                         ) -> list[UnlabelledCapture]:
    return _captures(conn, _VICTIM_WHERE)


def victim_data_captures_count(conn: psycopg.Connection) -> int:
    return conn.execute("SELECT count(*)" + _VICTIM_WHERE).fetchone()[0]


# ---------------------------------------------------------------------------
# URLs whose identity changed (L5)
# ---------------------------------------------------------------------------

URL_TYPES = ("URL", "SOCIAL_URL")


@dataclass(frozen=True)
class SelectorChange:
    case_code: str
    selector_id: UUID
    selector_type: str
    raw_value: str
    stored_norm: str
    new_norm: str
    observations: int
    node_id: UUID | None
    #: For a row several observations share: the distinct links captures
    #: recorded under it, each with its new norm.
    behind: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class EntityChange:
    case_code: str
    node_id: UUID
    selector_type: str
    label: str
    new_norm: str


@dataclass(frozen=True)
class ProposalChange:
    case_code: str
    proposal_id: UUID
    selector_type: str
    label: str
    new_norm: str


@dataclass
class UrlIdentityReport:
    selectors: list[SelectorChange] = field(default_factory=list)
    entities: list[EntityChange] = field(default_factory=list)
    proposals: list[ProposalChange] = field(default_factory=list)
    #: Counts only: records of a capture, kept as written; nothing matches
    #: on them.
    deception_captures: int = 0
    deception_hops: int = 0

    @property
    def total(self) -> int:
        return (len(self.selectors) + len(self.entities)
                + len(self.proposals) + self.deception_captures
                + self.deception_hops)


def _renorm(selector_type: str, raw: str | None) -> str | None:
    from noctornal_ontology.normalisers import normalise
    if raw is None:
        return None
    try:
        return normalise(selector_type, raw)
    except (KeyError, ValueError, TypeError):
        return None


def url_identity_changes(conn: psycopg.Connection) -> UrlIdentityReport:
    """Every stored URL identity the current `url_norm` would write
    differently, listed and never rewritten (L5, 2026-09-24)."""
    report = UrlIdentityReport()
    for (code, sid, stype, raw, norm, n, node) in conn.execute(
            """SELECT c.code, s.id, s.selector_type, s.raw_value,
                      s.norm_value, s.observation_cnt, s.node_id
                 FROM core.selector s
                 JOIN core."case" c ON c.id = s.case_id
                WHERE s.selector_type = ANY(%s) AND s.raw_value LIKE '%%#%%'
                ORDER BY c.code, s.norm_value""",
            (list(URL_TYPES),)).fetchall():
        new = _renorm(stype, raw)
        if new is None or new == norm:
            continue
        behind: tuple[tuple[str, str], ...] = ()
        if (n or 0) > 1:
            links = conn.execute(
                """SELECT DISTINCT e.raw_value
                     FROM collect.extraction e
                     JOIN collect.proposal p ON p.document_id = e.document_id
                     JOIN core.selector s ON s.case_id = p.case_id
                    WHERE s.id = %s AND e.selector_type = s.selector_type
                      AND e.norm_value = s.norm_value
                    ORDER BY e.raw_value""", (sid,)).fetchall()
            behind = tuple((link, _renorm(stype, link) or link)
                           for (link,) in links)
        report.selectors.append(SelectorChange(
            code, sid, stype, raw, norm, new, n or 0, node, behind))
    for (code, nid, stype, label, raw) in conn.execute(
            """SELECT c.code, n.id, n.attrs->>'selector_type', n.label,
                      n.attrs->>'raw_value'
                 FROM core.node n JOIN core."case" c ON c.id = n.case_id
                WHERE n.node_type = 'SELECTOR' AND n.deleted_at IS NULL
                  AND n.attrs->>'selector_type' = ANY(%s)
                ORDER BY c.code, n.label""", (list(URL_TYPES),)).fetchall():
        new = _renorm(stype, raw)
        if new is not None and new != label:
            report.entities.append(EntityChange(code, nid, stype, label, new))
    for (code, pid, stype, label, raw) in conn.execute(
            """SELECT c.code, p.id, p.payload->'attrs'->>'selector_type',
                      p.payload->>'label', p.payload->'attrs'->>'raw_value'
                 FROM collect.proposal p JOIN core."case" c ON c.id = p.case_id
                WHERE p.state = 'PROPOSED' AND p.kind = 'NODE'
                  AND p.payload->'attrs'->>'selector_type' = ANY(%s)
                ORDER BY c.code, p.created_at""",
            (list(URL_TYPES),)).fetchall():
        new = _renorm(stype, raw)
        if new is not None and new != label:
            report.proposals.append(
                ProposalChange(code, pid, stype, label, new))
    report.deception_captures = _deception_count(
        conn, """SELECT requested_url, requested_url_norm, final_url,
                        final_url_norm FROM deception.capture""", pairs=2)
    report.deception_hops = _deception_count(
        conn, "SELECT url, url_norm FROM deception.capture_hop", pairs=1)
    return report


def _deception_count(conn: psycopg.Connection, sql: str, *,
                     pairs: int) -> int:
    n = 0
    for row in conn.execute(sql).fetchall():
        for i in range(pairs):
            raw, stored = row[2 * i], row[2 * i + 1]
            if raw is None or stored is None or "#" not in raw:
                continue
            new = _renorm("URL", raw)
            if new is not None and new != stored:
                n += 1
    return n

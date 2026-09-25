"""Report builder with TLP-aware redaction (Phase 6, docs/08 + docs/13).

## Redaction is STRUCTURAL, never textual

The tempting implementation searches the finished report for material above
the target classification and removes it. That is not redaction, it is
hoping -- a name appears in a label, an attribute, a rationale, a selector
value, an evidence title and a URL, and a filter that catches five of those
has still disclosed.

So nothing above the target ever enters the document. The report is built
from a projection computed at the TARGET's clearance, using the same
`GraphService` an analyst at that level would see. If the material is not
in the projection it cannot be in the report, and that property does not
depend on anybody remembering to escape anything.

## A report that silently omits is worse than one that refuses

A redacted report is a disclosure document. One that quietly drops the two
ties that made an actor central, and then presents a centrality figure
computed without them, is not merely incomplete -- it is misleading, and
misleading in the direction of whoever chose the target level.

Every report therefore carries a **redaction statement**: how many elements
were withheld and at what level the document was built. Never which
classification, never which compartment, never where -- the same discipline
as U2 (migration 0030). And every figure in the report is labelled as
computed over the redacted graph, because a number carried across a
classification boundary without that label is a number that will be quoted
without it.

## The evidence register is the prosecution-grade part

decision 13 targets US FRE 902(13)/(14) and Canada Evidence Act ss. 31.1-31.8.
Both turn on the integrity of the electronic record, so the register lists
every exhibit's SHA-256 and BLAKE3 and the custody chain's head hash. That
is what makes a hash-value certification possible later; a report that
describes exhibits without identifying them evidentially is a summary, not
a disclosure.

## The case header is case content

This was the hole (F19, 2026-07-26). The document's mark is DERIVED from
what actually went into it, which is right -- but it was derived from the
graph elements and the exhibits only, while `report.case` copied the case
code, title, summary, legal basis and authority reference in unconditionally
and unfiltered. A RED case with nothing at or below the target therefore
produced a document containing the operation's codename and its summary,
computed a mark of TLP:CLEAR because the graph body was empty, and handed
that laundered value to the egress gate.

So the header is now treated as what it is: material classified at the
case's own level.

- If the case's labels are within the target, the header goes in AND the
  mark is floored at the case's classification. A document quoting an AMBER
  case's title is an AMBER document however empty its graph.
- If they are not, the narrative fields are WITHHELD and the redaction
  statement says so. That still leaves the feature intact -- an
  AMBER_STRICT case can produce a GREEN report -- it just produces one that
  does not name the operation.

A case code IS intelligence. `transports.py` reasons the same way about
putting one in an email subject line: "OP-KESTREL" tells a reader that an
operation by that name exists and that this person works on it.

The same holds for everything written ABOUT the case rather than about one
element: the assumptions (0056) and, since final review C2 (2026-09-23),
the competing hypotheses. A hypothesis statement has no label of its own,
so it went into every document the console prepared, including a RED
case's TLP:CLEAR one. Both now travel with the header and are counted when
it is withheld, and the matrix's evidence is read at the target like
everything else.

## Egress

`can_egress()` decides whether the finished document may leave, and it is
called with the DOCUMENT's classification -- which is the target level, not
the case's. That is the whole point of building at a lower level: an
AMBER_STRICT case can produce a GREEN report, and the GREEN report may
leave when the case never could.

It is also called with the document's COMPARTMENTS, which `check_egress`
used to drop on the floor -- so the two call sites of the one shared gate
disagreed about one of its three arguments, and `DENY_COMPARTMENTED` could
never fire for a report.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

import psycopg

from noctornal_api.assumptions import AssumptionService
from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.egress import Destination, can_egress
from noctornal_api.projections import DISCLOSURE_NONE, GraphService, Projection
from noctornal_api.security.access import Tlp, tlp_from_name


class ReportError(Exception):
    pass


#: What a header field says when the case header is above the document's
#: ceiling. `build` writes it into the text fields; the dates stay None in
#: the report itself (they are dates or nothing), and `render_markdown`
#: prints this for them, so no withheld field reads as a bare "None".
WITHHELD_MARK = "[withheld: above this document's ceiling]"


def _count(n: int, one: str, many: str) -> str:
    """A count and its noun in agreement. The statement is printed at the
    top of every disclosure, and "0 entit(y/ies), 0 relationship(s) and 1
    exhibit(s)" is the first line a reader meets (README screenshot
    review, 2026-09-23)."""
    return f"{n} {one if n == 1 else many}"


@dataclass(frozen=True)
class Redaction:
    """What the document does not contain.

    Reported so a reader knows the picture is partial. NOT broken down by
    classification, compartment or location -- a redaction statement that
    localises what it removed has removed nothing.
    """

    #: What the document is MARKED: the highest classification actually in
    #: it. Derived, never asked for.
    built_at_tlp: str
    #: What the requester was willing to include. A ceiling, not a mark.
    ceiling_tlp: str
    case_tlp: str
    nodes_withheld: int
    edges_withheld: int
    evidence_withheld: int
    #: True when the case's OWN labels are above the ceiling, so its code,
    #: title, summary and authority reference are not in the document. A
    #: reader who is not told this reads an untitled report as an
    #: administrative quirk rather than as a redaction.
    header_withheld: bool = False
    #: How many still-standing assumptions (OPEN or CONFIRMED) went with
    #: the header. An assumption is free text an analyst wrote ABOUT the
    #: case -- "the OP-KESTREL key is the operator's" -- so it is case
    #: content at the case's own level, exactly like the title, and it is
    #: withheld on the same condition. Counted so the statement can say so.
    assumptions_withheld: int = 0
    #: How many live competing hypotheses went with the header. A
    #: hypothesis statement ("OP-KESTREL is run by Ivan Petrov") is free
    #: text about the case with no label of its own, exactly like an
    #: assumption, and until final review C2 (2026-09-23) it went in
    #: whether or not the header did: a RED case prepared at GREEN with the
    #: console's defaults saved a TLP:CLEAR file naming the operation and
    #: its suspect.
    hypotheses_withheld: int = 0
    #: How many items of evidence in the hypothesis matrix rest on material
    #: above the ceiling and were left out of its scores (C2). Counted
    #: apart from the entities because an element the projection does not
    #: count (a deleted node, an inferred tie) can still carry a stance.
    #: Like those counts it follows the case's withheld-disclosure setting,
    #: and is 0 under NONE.
    hypothesis_evidence_withheld: int = 0

    @property
    def anything_withheld(self) -> bool:
        return bool(self.nodes_withheld or self.edges_withheld
                    or self.evidence_withheld or self.header_withheld
                    or self.assumptions_withheld or self.hypotheses_withheld
                    or self.hypothesis_evidence_withheld)

    def statement(self) -> str:
        if not self.anything_withheld:
            return (f"This document is marked TLP:{self.built_at_tlp} and was "
                    f"prepared to include material up to TLP:{self.ceiling_tlp}. "
                    f"Nothing in the case file was above that ceiling, so "
                    f"nothing has been withheld from it.")
        # Every count below agrees with its noun, and the header's aside is
        # a sentence of its own rather than a " -- " clause: the statement
        # is the first thing a disclosure says (README screenshot review,
        # 2026-09-23).
        header = ""
        if self.header_withheld:
            header = (
                " **The case's own identifying detail is above that ceiling "
                "and has been withheld**, so this document does not name the "
                "operation, its subject or the authority it was collected "
                "under. It is therefore not a disclosure document as it "
                "stands.")
            n = self.assumptions_withheld
            if n:
                header += (
                    f" The {_count(n, 'recorded assumption', 'recorded assumptions')} "
                    f"the case rests on {'is' if n == 1 else 'are'} withheld "
                    f"with it, because {'it is' if n == 1 else 'they are'} "
                    f"written about the case at the case's own level; the "
                    f"findings below therefore rest on "
                    f"{'a premise' if n == 1 else 'premises'} this document "
                    f"cannot state.")
            n = self.hypotheses_withheld
            if n:
                header += (
                    f" The {_count(n, 'competing hypothesis', 'competing hypotheses')} "
                    f"recorded against the case {'is' if n == 1 else 'are'} "
                    f"withheld for the same reason.")
        matrix = ""
        n = self.hypothesis_evidence_withheld
        if n:
            matrix = (
                f" {_count(n, 'item', 'items')} of evidence in the hypothesis "
                f"matrix {'rests' if n == 1 else 'rest'} on that material, so "
                f"the hypothesis scores below leave "
                f"{'it' if n == 1 else 'them'} out.")
        withheld = (f"{_count(self.nodes_withheld, 'entity', 'entities')}, "
                    f"{_count(self.edges_withheld, 'relationship', 'relationships')} "
                    f"and {_count(self.evidence_withheld, 'exhibit', 'exhibits')}")
        return (
            f"This document is marked TLP:{self.built_at_tlp} and was prepared "
            f"to include material up to TLP:{self.ceiling_tlp}, from a case "
            f"classified TLP:{self.case_tlp}.{header} "
            f"{withheld} are above that level and have been withheld.{matrix} "
            f"**Every figure below is computed over the redacted graph** and "
            f"is therefore a lower bound, not a measurement of the case.")


@dataclass
class Report:
    case: dict
    redaction: Redaction
    summary: dict
    actors: list[dict] = field(default_factory=list)
    relationships: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    hypotheses: dict = field(default_factory=dict)
    #: The still-standing assumptions (`assumptions.REPORTABLE_STATUSES`):
    #: what the findings rest on, with who made them and who reviewed
    #: them. A document that does not say what it assumes is a document
    #: whose reader cannot tell a finding from a premise.
    assumptions: list[dict] = field(default_factory=list)
    #: The compartments of everything actually in the document. Carried on
    #: the report rather than re-derived at the gate, because the gate is
    #: pure and the thing that knows what went in is the builder.
    compartments: frozenset[str] = field(default_factory=frozenset)
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc))
    generated_by: UUID | None = None

    def as_dict(self) -> dict:
        return {
            "case": self.case,
            "classification": self.redaction.built_at_tlp,
            "compartments": sorted(self.compartments),
            "redaction": {
                "built_at_tlp": self.redaction.built_at_tlp,
                "ceiling_tlp": self.redaction.ceiling_tlp,
                "case_tlp": self.redaction.case_tlp,
                "nodes_withheld": self.redaction.nodes_withheld,
                "edges_withheld": self.redaction.edges_withheld,
                "evidence_withheld": self.redaction.evidence_withheld,
                "statement": self.redaction.statement(),
                "header_withheld": self.redaction.header_withheld,
                "assumptions_withheld": self.redaction.assumptions_withheld,
                "hypotheses_withheld": self.redaction.hypotheses_withheld,
                "hypothesis_evidence_withheld":
                    self.redaction.hypothesis_evidence_withheld,
            },
            "summary": self.summary,
            "assumptions": self.assumptions,
            "actors": self.actors,
            "relationships": self.relationships,
            "evidence": self.evidence,
            "hypotheses": self.hypotheses,
            "generated_at": self.generated_at.isoformat(),
            "generated_by": str(self.generated_by) if self.generated_by else None,
        }


class ReportBuilder:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def build(self, case_id: UUID, *, target_tlp: str,
              generated_by: UUID,
              preset: str = "all",
              include_hypotheses: bool = True,
              compartments: frozenset[str] = frozenset()) -> Report:
        """Build at `target_tlp`. Nothing above it is read at any point.

        The projection is computed with the TARGET as the clearance, which
        means the redaction is done by the same code path that protects a
        live analyst -- not by a second, parallel filter that could drift
        from it. Reusing the enforcement is the point: a redaction routine
        with its own idea of what AMBER means is a redaction routine that
        will one day disagree with the access gate.
        """
        try:
            target = tlp_from_name(target_tlp)
        except Exception as exc:  # noqa: BLE001
            raise ReportError(f"unknown classification {target_tlp!r}") from exc

        case = self._c.execute(
            """SELECT code, title, summary, status, classification, legal_basis,
                      authority_ref, retention_until, review_due, created_at,
                      compartments
                 FROM core."case" WHERE id = %s""", (case_id,)).fetchone()
        if case is None:
            raise ReportError("case does not exist")
        case_tlp = case[4]
        case_compartments = frozenset(case[10] or [])

        # The case header -- code, title, summary, legal basis, authority
        # reference -- is material classified at the case's own level, not
        # free metadata. It goes in only when the case's labels are within
        # what was asked for, on BOTH axes.
        #
        # `compartments` is the requester's read-in, and it is a real
        # parameter rather than a hardcoded empty set. The first version of
        # this fix hardcoded it, which closed the leak and broke the
        # feature: an analyst read into a compartment could not produce a
        # report naming their OWN case, and `report.compartments` was
        # therefore always empty, so `DENY_COMPARTMENTED` remained
        # unreachable on the built path — the exact defect the same fix had
        # just repaired in `check_egress`. Closing a hole by refusing
        # everybody is its own defect.
        header_ok = (tlp_from_name(case_tlp) <= target
                     and case_compartments <= compartments)

        # `target_tlp` is a CEILING on what may be included, not the mark the
        # document gets. The mark is derived below from what actually went
        # in, so asking for a report "up to RED" on a case holding nothing
        # above GREEN produces a GREEN document. Over-classification is then
        # impossible by construction rather than prevented by a check, which
        # matters because over-classification is how material stops reaching
        # the people who need it -- and unlike under-classification, nothing
        # ever alarms about it.

        # The redacted view, from the SAME code path that protects a live
        # analyst.
        redacted = GraphService(self._c, clearance=target.name,
                                compartments=compartments)
        projection = Projection(case_id=case_id, preset=preset,
                                include_inferred=False, min_confidence="LOW",
                                as_of=None)
        sub = redacted.project(projection, limit=5000)
        withheld = redacted.withheld(projection)

        # The compartment filter mirrors the projection, which is built at
        # the requester's read-in. Without it the exhibit register was the
        # one place compartmented material entered a report: the graph
        # filtered it and the evidence query did not.
        # `purged_at` travels with each row so the register can say which
        # exhibits are destroyed. A purged exhibit stays IN the register
        # (the record of it is meant to outlive the bytes, and dropping it
        # would miscount it as withheld above the ceiling), but it no
        # longer makes anything "Evidenced", and until 2026-09-22 the
        # register did not say so: an entity attached only to a purged
        # exhibit printed NO beside an exhibit list that still showed it.
        evidence_rows = self._c.execute(
            """SELECT id, title, sha256, blake3, media_type, byte_size,
                      acquired_at, acquisition_method, classification,
                      compartments, purged_at
                 FROM core.evidence
                WHERE case_id = %s AND classification <= %s::core.tlp
                  AND compartments <@ %s
                ORDER BY acquired_at, id""",
            (case_id, target.name, sorted(compartments))).fetchall()
        # EVERY exhibit in the case, on a system connection, because the
        # difference from what was included is the withheld count the report
        # states; under row-level security the request connection counts only
        # what the requester may read and the report would say nothing was
        # withheld (S1, 2026-09-25).
        with system_connection(SystemPurpose.WITHHELD, reuse=self._c) as counter:
            evidence_total = counter.execute(
                "SELECT count(*) FROM core.evidence WHERE case_id = %s",
                (case_id,)).fetchone()[0]

        # The competing hypotheses (final review C2, 2026-09-23). A
        # statement is free text about the case with no label of its own,
        # so it is case content at the case's level and goes in on the
        # header's condition, exactly like an assumption; when the header
        # is withheld the builder only COUNTS them. The matrix's evidence is
        # read at the TARGET through `ach_cells`, the same filter the live
        # ACH read uses, so a label above the ceiling is never read and an
        # above-ceiling stance does not move a printed score.
        hypotheses: dict = {}
        hypotheses_withheld = 0
        matrix = _Matrix()
        if include_hypotheses:
            if header_ok:
                matrix = self._hypotheses(
                    case_id, target, compartments,
                    count_withheld=withheld.mode != DISCLOSURE_NONE)
                hypotheses = matrix.body
            else:
                hypotheses_withheld = self._c.execute(
                    """SELECT count(*) FROM core.hypothesis
                        WHERE case_id = %s AND status::text <> 'SUPERSEDED'""",
                    (case_id,)).fetchone()[0]

        # The document's own mark: the highest classification of anything
        # actually in it, never the ceiling that was asked for. The case
        # header counts as "in it" -- deriving the mark from the graph body
        # alone is what let a RED case emit a TLP:CLEAR document carrying
        # its own codename and summary. So does every element whose label
        # the hypothesis matrix carries: a stance can rest on an element
        # the projection does not return (a deleted node, an inferred tie).
        included = ([n["classification"] for n in sub.nodes]
                    + [e["classification"] for e in sub.edges]
                    + [r[8] for r in evidence_rows]
                    + ([case_tlp] if header_ok else [])
                    + matrix.classifications)
        marking = (max((tlp_from_name(c) for c in included), default=Tlp.CLEAR)
                   if included else Tlp.CLEAR)

        # The register (0056). An assumption is free text written ABOUT the
        # case -- it names the operation, its subjects, its premises -- so
        # it is case content at the case's own level and goes in on exactly
        # the header's condition. When the header is withheld the builder
        # only COUNTS them, so the text it must not include is never read.
        register = AssumptionService(self._c)
        assumptions = register.for_report(case_id) if header_ok else []
        assumptions_withheld = 0 if header_ok else register.count_reportable(case_id)

        redaction = Redaction(
            built_at_tlp=marking.name, ceiling_tlp=target.name,
            case_tlp=case_tlp,
            nodes_withheld=withheld.nodes or 0,
            edges_withheld=withheld.edges or 0,
            evidence_withheld=evidence_total - len(evidence_rows),
            header_withheld=not header_ok,
            assumptions_withheld=assumptions_withheld,
            hypotheses_withheld=hypotheses_withheld,
            hypothesis_evidence_withheld=matrix.withheld,
        )

        metrics = redacted.metrics(projection) if hasattr(
            redacted, "metrics") else {}

        actors = sorted(
            ({"id": str(n["id"]), "type": n["node_type"], "label": n["label"],
              "classification": n["classification"],
              "has_evidence": n.get("has_evidence", False)}
             for n in sub.nodes),
            key=lambda a: (a["label"].lower(), a["id"]))
        # Ordered by the labels a reader sees, then by id. The projection's
        # edge query has no ORDER BY, so without this two builds of the same
        # case could list the same ties in different orders, and the
        # document an analyst previewed would not be byte-for-byte the one
        # the egress check cleared (ux15-report, 2026-09-22).
        label_of = {a["id"]: a["label"] for a in actors}
        relationships = sorted(
            ({"type": e["edge_type"], "src": str(e["src_node_id"]),
              "dst": str(e["dst_node_id"]), "sign": e["sign"],
              "confidence": e["confidence"], "inferred": e["is_inferred"],
              "has_evidence": e.get("has_evidence", False)}
             for e in sub.edges),
            # Every field is in the key, so two ties that still tie on it
            # render as identical rows and their order cannot show.
            key=lambda r: (label_of.get(r["src"], "").lower(),
                           label_of.get(r["dst"], "").lower(),
                           r["type"], r["src"], r["dst"], r["sign"],
                           r["confidence"], r["inferred"], r["has_evidence"]))

        withheld_mark = WITHHELD_MARK
        report = Report(
            case={
                # The id is not withheld: it identifies nothing to a reader
                # without access, and without it the document cannot be tied
                # back to the file it was drawn from.
                "id": str(case_id),
                "code": case[0] if header_ok else withheld_mark,
                "title": case[1] if header_ok else withheld_mark,
                "summary": case[2] if header_ok else None,
                "status": case[3] if header_ok else None,
                "classification": case_tlp,
                # docs/08: legal basis and retention are NOT NULL for a
                # reason. A disclosure document that does not state the
                # authority it was collected under is not disclosable --
                # which is precisely why withholding them has to be stated
                # in the redaction statement rather than left to look like
                # an empty field. A report built below its case's own
                # classification is a briefing, not a disclosure.
                "legal_basis": case[5] if header_ok else withheld_mark,
                "authority_ref": case[6] if header_ok else withheld_mark,
                "retention_until": case[7].isoformat()
                if header_ok and case[7] else None,
                "review_due": case[8].isoformat()
                if header_ok and case[8] else None,
                "opened": case[9].isoformat()
                if header_ok and case[9] else None,
            },
            # The union of what actually went in: the case header when it
            # is included, plus every exhibit's own. The projection's nodes
            # and edges cannot contribute beyond the requester's read-in
            # because `GraphService` filtered on it, and an exhibit is in
            # the register for the same reason — so this is bounded by
            # `compartments` and is the honest subset of it, not the whole.
            compartments=frozenset(
                (case_compartments if header_ok else frozenset())
                | {c for r in evidence_rows for c in (r[9] or [])}
                | matrix.compartments),
            redaction=redaction,
            summary={
                "entities": len(sub.nodes),
                "relationships": len(sub.edges),
                "exhibits": len(evidence_rows),
                "truncated": sub.truncated,
                "computed_over": "the redacted graph",
                **({"metrics": metrics} if metrics else {}),
            },
            assumptions=assumptions,
            actors=actors,
            relationships=relationships,
            evidence=[{
                "id": str(r[0]), "title": r[1],
                # The prosecution-grade part. decision 13 targets FRE
                # 902(13)/(14) and CEA ss. 31.1-31.8, both of which turn on
                # identifying the record, not describing it.
                "sha256": bytes(r[2]).hex() if r[2] else None,
                "blake3": bytes(r[3]).hex() if r[3] else None,
                "media_type": r[4], "byte_size": r[5],
                "acquired_at": r[6].isoformat() if r[6] else None,
                "acquisition_method": r[7], "classification": r[8],
                "purged_at": r[10].isoformat() if r[10] else None,
            } for r in evidence_rows],
            hypotheses=hypotheses,
            generated_by=generated_by,
        )
        return report

    def _hypotheses(self, case_id: UUID, target: Tlp,
                    compartments: frozenset[str], *,
                    count_withheld: bool) -> _Matrix:
        """The ACH matrix, if the case has one, over what `target` may see.

        Included because a report that states a conclusion without the
        alternatives that were considered and ruled out is the confirmation
        bias ACH exists to correct, delivered on letterhead.

        `count_withheld` is the case's withheld-disclosure setting (0030):
        under NONE the element counts are never computed, so this one is
        not either, and the report says no more than the graph does.
        """
        from noctornal_api.ach import STANCE_LABEL, EvidenceItem, as_response, score

        rows = self._c.execute(
            """SELECT id, statement, status::text FROM core.hypothesis
                WHERE case_id = %s AND status::text <> 'SUPERSEDED'
                ORDER BY created_at""", (case_id,)).fetchall()
        if not rows:
            return _Matrix()
        cells = ach_cells(self._c, case_id, clearance=target.name,
                          compartments=compartments)
        items: dict[UUID, EvidenceItem] = {}
        for cell in cells:
            item = items.setdefault(cell.assertion_id, EvidenceItem(
                assertion_id=cell.assertion_id, label=cell.label,
                reliability=cell.reliability, credibility=cell.credibility))
            item.stances[cell.hypothesis_id] = cell.stance
        # A REJECTED hypothesis is printed for the record and scored as
        # `retired`, never as a live competitor: once the console could
        # reject one, a ruled-out theory could otherwise head the ranking
        # and hold rows "unfinished" (ux11-ach:no-hypothesis-lifecycle-in-
        # console, 2026-09-23).
        body = as_response(score(
            [(r[0], r[1]) for r in rows if r[2] != "REJECTED"],
            list(items.values()),
            retired=[(r[0], r[1]) for r in rows if r[2] == "REJECTED"]))
        body["statuses"] = {str(r[0]): r[2] for r in rows}
        # The reason recorded with each hypothesis's CURRENT status, from
        # the change that set it. Rejecting needs one, and the console says
        # it is printed here; it was kept only in the audit trail and on
        # the card, so a document listing a REJECTED hypothesis never said
        # what ruled it out (verifier of ux11-ach:no-hypothesis-lifecycle-
        # in-console, 2026-09-23). Free text about the case, like the
        # statement beside it, so it goes in on the header's condition,
        # which is the only condition this section is built under.
        current = {r[0]: r[2] for r in rows}
        changes = self._c.execute(
            """SELECT DISTINCT ON (object_id)
                      object_id, detail->>'status', detail->>'note'
                 FROM audit.event
                WHERE case_id = %s AND object_type = 'hypothesis'
                  AND action = 'HYPOTHESIS_STATUS'
                  AND object_id = ANY(%s)
                ORDER BY object_id, seq DESC""",
            (case_id, list(current))).fetchall()
        body["status_notes"] = {
            str(hid): note for hid, status, note in changes
            if note and status == current.get(hid)}
        # The reasoning behind each stance, for every cell that has one
        # (ux11-ach:stance-note-erased-on-rescore, 2026-09-23). Only cells
        # `ach_cells` returned at this target, against a hypothesis the
        # section prints.
        statement = {r[0]: r[1] for r in rows}
        body["reasoning"] = [
            {"evidence": c.label, "hypothesis": statement[c.hypothesis_id],
             "stance": STANCE_LABEL.get(c.stance, str(c.stance)),
             "note": c.note}
            for c in cells if c.note and c.hypothesis_id in statement]
        return _Matrix(
            body=body,
            classifications=[c.classification for c in cells],
            compartments=frozenset(x for c in cells for x in c.compartments),
            withheld=ach_cells_withheld(self._c, case_id, clearance=target.name,
                                        compartments=compartments)
            if count_withheld else 0)


@dataclass
class _Matrix:
    """The hypothesis section as the builder needs it: the scored body, and
    the labels of every element it drew on so the mark and the compartments
    account for them."""

    body: dict = field(default_factory=dict)
    classifications: list[str] = field(default_factory=list)
    compartments: frozenset[str] = field(default_factory=frozenset)
    withheld: int = 0


@dataclass(frozen=True)
class AchCell:
    """One live stance, with the labels of the element its assertion is
    about."""

    assertion_id: UUID
    hypothesis_id: UUID
    stance: int
    reliability: str
    credibility: str
    label: str
    classification: str
    compartments: tuple[str, ...]
    #: Why the analyst put the stance where it is. Read through the same
    #: filter as the rest of the cell, so a note travels only with a cell
    #: the reader may see (ux11-ach:stance-note-erased-on-rescore,
    #: 2026-09-23: the note was written and then never read by anything).
    note: str | None = None


#: Whether a matrix cell's assertion is about something a reader at
#: %(clearance)s, read into %(compartments)s, may see: the projection's own
#: rule (`GraphService.project`), so the matrix and the graph agree. A tie
#: is visible only when both its ends are, because a rationale written
#: about a tie can name either end.
#:
#: Final review C2 (2026-09-23). Both reads of the matrix, the report's and
#: GET /ach, used to label a cell `coalesce(n.label, ...)` with no filter at
#: all, so an AMBER analyst on an AMBER case received a RED node's label as
#: `evidence[].label` while every graph, list and search view hid it, and
#: above-ceiling stances moved the scores a released document printed.
_ACH_CELL_VISIBLE = """
    (   (a.node_id IS NOT NULL
         AND n.classification <= %(clearance)s::core.tlp
         AND n.compartments <@ %(compartments)s)
     OR (a.edge_id IS NOT NULL
         AND e.classification <= %(clearance)s::core.tlp
         AND e.compartments <@ %(compartments)s
         AND EXISTS (SELECT 1 FROM core.node sn
                      WHERE sn.id = e.src_node_id
                        AND sn.classification <= %(clearance)s::core.tlp
                        AND sn.compartments <@ %(compartments)s)
         AND EXISTS (SELECT 1 FROM core.node dn
                      WHERE dn.id = e.dst_node_id
                        AND dn.classification <= %(clearance)s::core.tlp
                        AND dn.compartments <@ %(compartments)s)))"""

_ACH_CELL_FROM = """
      FROM core.hypothesis_evidence he
      JOIN core.hypothesis h ON h.id = he.hypothesis_id
      JOIN core.assertion a ON a.id = he.assertion_id
      LEFT JOIN core.node n ON n.id = a.node_id
      LEFT JOIN core.edge e ON e.id = a.edge_id
      LEFT JOIN core.edge_type et ON et.key = e.edge_type
      -- A tie's ends, for its label and its mark (`ach_cells`). One row
      -- each, so the count in `ach_cells_withheld` is unchanged.
      LEFT JOIN core.node tie_src ON tie_src.id = e.src_node_id
      LEFT JOIN core.node tie_dst ON tie_dst.id = e.dst_node_id
     WHERE h.case_id = %(case_id)s
       -- Only LIVE assertions: a retracted source must not leave its
       -- conclusion standing (decision 24, applied to the matrix).
       AND a.retracted_at IS NULL"""


def ach_cells(conn: psycopg.Connection, case_id: UUID, *, clearance: str,
              compartments: frozenset[str]) -> list[AchCell]:
    """The matrix cells a reader at `clearance`, read into `compartments`,
    may see. The ONE query both the report and GET /ach read the matrix
    through, so the two cannot disagree about what a stance may reveal."""
    # A tie is labelled by both its ends and its type, "vellum_ram → leads →
    # Meridian crew", not by the type alone: "leads" was one of six such
    # ties on the demo case, and the report's reasoning table names each
    # row (ux11-ach:evidence-row-is-a-name-not-a-claim, 2026-09-23). The
    # ends are visible whenever the cell is: `_ACH_CELL_VISIBLE` admits a
    # tie only when both are.
    #
    # So a tie's cell carries its ends' labels as well as its own, and its
    # classification and compartments are the highest and the union of
    # all three. The report marks itself from these and nothing else for
    # an end the projection drops (a deleted, merged or dissolved node):
    # with the tie's own mark alone, a GREEN tie to a deleted AMBER node
    # printed the AMBER label in a document marked GREEN, which the egress
    # check then cleared for a GREEN destination (verifier of ux11-ach,
    # 2026-09-23). A stance note about a tie can name either end too.
    rows = conn.execute(
        """SELECT he.assertion_id, he.hypothesis_id, he.stance,
                  a.reliability, a.credibility,
                  coalesce(n.label,
                           tie_src.label
                           || ' → ' || coalesce(et.display_name, e.edge_type)
                           || ' → ' || tie_dst.label,
                           et.display_name, a.claim_path,
                           a.rationale, 'assertion'),
                  coalesce(n.classification,
                           greatest(e.classification, tie_src.classification,
                                    tie_dst.classification)),
                  coalesce(n.compartments,
                           e.compartments || tie_src.compartments
                           || tie_dst.compartments),
                  he.note"""
        + _ACH_CELL_FROM + " AND " + _ACH_CELL_VISIBLE
        + " ORDER BY he.assertion_id, he.hypothesis_id",
        {"case_id": case_id, "clearance": clearance,
         "compartments": sorted(compartments)}).fetchall()
    return [AchCell(assertion_id=r[0], hypothesis_id=r[1], stance=r[2],
                    reliability=r[3], credibility=r[4], label=r[5],
                    classification=r[6], compartments=tuple(r[7] or ()),
                    note=r[8])
            for r in rows]


def ach_cells_withheld(conn: psycopg.Connection, case_id: UUID, *,
                       clearance: str, compartments: frozenset[str]) -> int:
    """How many live pieces of matrix evidence `ach_cells` leaves out for
    this reader. A count only: never which, never where.

    Counted on a system connection with this reader's ceiling (S1,
    2026-09-25): the stances it counts are the ones row-level security hides
    from the reader's own connection, so counted there it would always be
    zero, and the matrix would say "incomplete: false"."""
    with system_connection(SystemPurpose.WITHHELD, reuse=conn) as counter:
        return counter.execute(
            "SELECT count(DISTINCT he.assertion_id)" + _ACH_CELL_FROM
            + " AND NOT " + _ACH_CELL_VISIBLE,
            {"case_id": case_id, "clearance": clearance,
             "compartments": sorted(compartments)}).fetchone()[0]


def check_egress(report: Report, destination: Destination | str,
                 destination_ceiling: str | None = None):
    """Whether the finished document may leave, judged on the DOCUMENT's
    classification rather than the case's.

    That distinction is the whole reason for building at a lower level: an
    AMBER_STRICT case can produce a GREEN report, and the GREEN report may
    leave when the case never could. Passing the case's classification here
    would make redaction pointless.

    The compartments are the document's too, and they are passed. This
    function used to omit the argument entirely, so the two call sites of
    the one shared gate — here and `transports.dispatch_due` — disagreed
    about one of its three parameters, and `DENY_COMPARTMENTED` could never
    fire on the report path. A gate whose callers each supply a different
    subset of its inputs is not one gate.
    """
    return can_egress(report.redaction.built_at_tlp, destination,
                      compartments=report.compartments,
                      destination_ceiling=destination_ceiling)


def content_digest(report: Report) -> str:
    """A fingerprint of what the document SAYS, so two builds can be shown
    to be the same document.

    ux15-report:report-download-bypasses-egress (2026-09-22): the console's
    preview came from one build, the egress verdict from a second, and the
    downloaded file from a third, and nothing tied them together. "Cleared"
    and "downloaded" could name two different documents: the release built
    with hypotheses on whatever the preview had said, and a write between
    Prepare and Check egress changed the file without changing the screen.
    Build and release both return this; the console offers the file only
    when the release's digest matches the preview's.

    The generation time and author are left out (they differ on every
    build and say nothing about the content), and every list is put in a
    canonical order first, so a query that returns the same rows in a
    different order is not reported as a different document.
    """
    body = report.as_dict()
    body.pop("generated_at", None)
    body.pop("generated_by", None)

    def canon(value):
        if isinstance(value, dict):
            return {k: canon(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            items = [canon(v) for v in value]
            return sorted(items, key=lambda v: json.dumps(
                v, sort_keys=True, default=str))
        # Summed weights depend on the order the edges arrived in, down to
        # the last bit; that is not a different document.
        if isinstance(value, float):
            return round(value, 9)
        return value

    blob = json.dumps(canon(body), sort_keys=True, default=str,
                      separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _line(value) -> str:
    """`value` as ONE line: every character an editor or a renderer may
    end a line on becomes a space.

    Final review U13 (2026-09-23). Labels, exhibit titles, assumptions and
    hypothesis statements went into the document verbatim, and a label is
    only checked for being blank. A collected handle holding a newline
    ended its table row and put text of the forum's choosing on a line of
    its own in the file the egress gate cleared: "\\n\\n**TLP:CLEAR**" is a
    false handling mark partway through an AMBER document. `str()` first so
    a missing value still prints as it always did."""
    return " ".join(str(value).splitlines())


def _cell(value) -> str:
    """`value` as the text of one markdown table cell (U13).

    One line (`_line`), and every "|" escaped, because a "|" in a handle
    moved each later cell one column right: "x | RED" made that entity's
    TLP column read RED. A backslash is doubled only where it stands
    before a "|", so a renderer that counts backslashes and one that looks
    only at the character before the pipe both keep it in the cell, and a
    label without a pipe in it stays byte for byte greppable."""
    return re.sub(r"(\\*)\|", lambda m: m.group(1) * 2 + "\\|", _line(value))


def _cells(row: dict) -> dict:
    """A copy of `row` with every text value made safe for a table cell.
    Numbers, flags and missing values pass through, so a cell prints
    exactly what it printed before whenever there was nothing to escape."""
    return {k: _cell(v) if isinstance(v, str) else v for k, v in row.items()}


def render_markdown(report: Report) -> str:
    """A plain-text rendering, TLP-marked top and bottom.

    Markdown rather than PDF deliberately: this has to be diffable,
    greppable and quotable, and a report whose only form is a binary is a
    report nobody checks against the case file. Marked at BOTH ends because
    a document read from the bottom -- which is how appendices are read --
    must still carry its handling caveat.
    """
    d = report.as_dict()
    # U13: every value is made safe for where it lands ONCE, here, and on
    # copies. `as_dict` hands back the report's own lists, which
    # `content_digest` is computed over, so they are rebound, never edited.
    # The heading and the authority lines are not tables, so a case field
    # only has to stay on its line; every table row is built from `_cells`.
    d["case"] = {k: _line(v) if isinstance(v, str) else v
                 for k, v in d["case"].items()}
    for key in ("assumptions", "actors", "relationships", "evidence"):
        d[key] = [_cells(row) for row in d[key]]
    if d["hypotheses"]:
        d["hypotheses"] = {**d["hypotheses"], "hypotheses": [
            _cells(h) for h in d["hypotheses"]["hypotheses"]],
            "reasoning": [_cells(r) for r in
                          d["hypotheses"].get("reasoning") or []],
            "status_notes": {k: _cell(v) for k, v in
                             (d["hypotheses"].get("status_notes") or {}).items()}}
    tlp = d["classification"]
    # A missing value is said in words, as the console says it, and the
    # mark is set off from the case by the separator the console's case
    # header uses. No dash: an em or en dash in shipped copy is refused
    # (test_server_copy_no_dashes.py).
    #
    # The three dates are NOT NULL on the case, so one is None only when the
    # header is withheld; it then says so in the words the legal basis and
    # authority beside it use, never "None".
    withheld_header = d["redaction"]["header_withheld"]
    dates = {key: d["case"][key]
             or (WITHHELD_MARK if withheld_header else "not recorded")
             for key in ("opened", "retention_until", "review_due")}
    lines = [
        f"# TLP:{tlp} · {d['case']['code']}: {d['case']['title']}",
        "",
        f"> **TLP:{tlp}.** {d['redaction']['statement']}",
        "",
        "## Authority and retention",
        "",
        f"- **Legal basis:** {d['case']['legal_basis']}",
        f"- **Authority reference:** {d['case']['authority_ref'] or 'not recorded'}",
        f"- **Opened:** {dates['opened']}",
        f"- **Retention until:** {dates['retention_until']}",
        f"- **Next review:** {dates['review_due']}",
        "",
        "## Summary",
        "",
        f"- Entities: {d['summary']['entities']}",
        f"- Relationships: {d['summary']['relationships']}",
        f"- Exhibits: {d['summary']['exhibits']}",
        f"- All figures computed over {d['summary']['computed_over']}.",
        "",
        "## Assumptions",
        "",
    ]
    # Before the entities, because a premise is read before the findings
    # that rest on it. An empty register is said out loud: "no assumptions
    # recorded" is a fact about the analysts, not about the case, and a
    # heading that silently disappears reads as "there were none".
    if d["assumptions"]:
        lines += [
            "What the findings below rest on. An assumption is a premise the "
            "analysts chose to work from, not a finding; each is listed with "
            "who made it and whether it has been reviewed.",
            "",
            "| Assumption | Basis | Status | Made by | Reviewed |",
            "|---|---|---|---|---|",
        ]
        for a in d["assumptions"]:
            if a["reviewed_at"]:
                # The note in brackets after the time, as "Made by" gives
                # its time in brackets after the name.
                reviewed = a["reviewed_at"] + (
                    f" ({a['review_note']})" if a["review_note"] else "")
            else:
                reviewed = "not yet"
            basis = a["basis"] or "not recorded"
            lines.append(f"| {a['statement']} | {basis} | {a['status']} | "
                         f"{a['made_by_name']} ({a['made_at']}) | {reviewed} |")
    elif d["redaction"]["assumptions_withheld"]:
        held = d["redaction"]["assumptions_withheld"]
        lines.append(f"_{_count(held, 'recorded assumption', 'recorded assumptions')} "
                     f"withheld with the case header; see the marking "
                     f"statement above._")
    else:
        lines.append("_No assumptions have been recorded against this case. That "
                     "is a statement about the register, not that there are none: "
                     "a finding whose premises are unwritten has premises its "
                     "reader cannot challenge._")

    lines += [
        "",
        "## Entities",
        "",
        # Says what the column means because until 2026-09-22 it meant less
        # than the console implied: it counted exhibits carried by a claim
        # and ignored exhibits linked to the entity, so an entity the
        # analyst had linked an exhibit to printed "NO" (ux07
        # two-evidence-paths-disagree). The rule is projections.evidenced_sql,
        # which also ignores a purged exhibit, so the sentence says that too
        # and the register below marks each purged row (2026-09-22 verifier).
        "Evidenced means at least one exhibit in the register below, not "
        "marked purged, is attached to the entity, either by a live claim "
        "that cites it or by a direct link. A purged exhibit stays in the "
        "register because the record of it outlives the bytes, and it does "
        "not count.",
        "",
        "| Type | Label | TLP | Evidenced |",
        "|---|---|---|---|",
    ]
    for a in d["actors"]:
        lines.append(f"| {a['type']} | {a['label']} | {a['classification']} | "
                     f"{'yes' if a['has_evidence'] else 'NO'} |")

    # The ties themselves, by name. Until 2026-09-22 the document carried
    # only a COUNT of relationships while the console's preview listed them
    # (as "undefined -> undefined", ux15-report), so the one thing a
    # network report is about was neither readable on screen nor present
    # in the file. Every tie here joins two entities listed above: the
    # projection admits an edge only when both endpoints are visible.
    label_of = {a["id"]: a["label"] for a in d["actors"]}
    sign_word = {1: "positive", -1: "negative", 0: "neutral"}
    lines += [
        "",
        "## Relationships",
        "",
        "Asserted ties only: inferred ties are not in a report.",
        "",
        "| From | Relationship | To | Sign | Confidence | Evidenced |",
        "|---|---|---|---|---|---|",
    ]
    for r in d["relationships"]:
        lines.append(
            f"| {label_of.get(r['src'], r['src'])} | {r['type']} | "
            f"{label_of.get(r['dst'], r['dst'])} | "
            f"{sign_word.get(r['sign'], r['sign'])} | {r['confidence']} | "
            f"{'yes' if r['has_evidence'] else 'NO'} |")
    if not d["relationships"]:
        lines.append("| _none at this classification_ | | | | | |")

    lines += ["", "## Exhibits", "",
              "Hashes are given so the record can be identified evidentially "
              "rather than described (decision 13: US FRE 902(13)-(14), Canada "
              "Evidence Act ss. 31.1-31.8).", "",
              "| Title | SHA-256 | Acquired | Method |", "|---|---|---|---|"]
    for e in d["evidence"]:
        # .get: a report serialised before purged_at was added has no key.
        purged = e.get("purged_at")
        title = (f"{e['title']} **(PURGED {purged}: does not count as "
                 f"evidence)**" if purged else e["title"])
        lines.append(f"| {title} | `{(e['sha256'] or '')[:32]}…` | "
                     f"{e['acquired_at']} | {e['acquisition_method']} |")
    if not d["evidence"]:
        lines.append("| _none at this classification_ | | | |")

    if d["hypotheses"]:
        # With its status (README screenshot review, 2026-09-23). The
        # section exists to carry the alternatives that were ruled out
        # beside the one that was not, and without this column a REJECTED
        # hypothesis read exactly like an open one.
        statuses = d["hypotheses"].get("statuses") or {}
        lines += ["", "## Competing hypotheses", "",
                  d["hypotheses"].get("method", ""), "",
                  "| Hypothesis | Status | Inconsistency | Support | Assessed |",
                  "|---|---|---|---|---|"]
        for h in d["hypotheses"]["hypotheses"]:
            status = _cell(statuses.get(str(h.get("id")), "not recorded"))
            lines.append(f"| {h['statement']} | {status} | "
                         f"{h['inconsistency']} | {h['support']} | "
                         f"{h['assessed']} |")
        for warning in d["hypotheses"].get("warnings", []):
            lines.append(f"\n> ⚠ {warning}")
        # The reason recorded with a status, above all what ruled a
        # REJECTED hypothesis out (verifier of ux11-ach:no-hypothesis-
        # lifecycle-in-console, 2026-09-23): "rejected" with no reason is a
        # verdict a reader cannot check.
        reasons = d["hypotheses"].get("status_notes") or {}
        stated = [h for h in d["hypotheses"]["hypotheses"]
                  if reasons.get(str(h.get("id")))]
        if stated:
            lines += ["", "### The reason recorded with each status", "",
                      "| Hypothesis | Status | Reason |", "|---|---|---|"]
            for h in stated:
                hid = str(h.get("id"))
                lines.append(f"| {h['statement']} | "
                             f"{_cell(statuses.get(hid, 'not recorded'))} | "
                             f"{reasons[hid]} |")
        # The analysts' reasons for their stances (ux11-ach:stance-note-
        # erased-on-rescore, 2026-09-23), so a disclosed matrix carries its
        # judgements and not only its arithmetic.
        if d["hypotheses"].get("reasoning"):
            lines += ["", "### Why each stance stands where it does", "",
                      "| Evidence | Hypothesis | Stance | Note |",
                      "|---|---|---|---|"]
            for r in d["hypotheses"]["reasoning"]:
                lines.append(f"| {r['evidence']} | {r['hypothesis']} | "
                             f"{r['stance']} | {r['note']} |")
    elif d["redaction"].get("hypotheses_withheld"):
        # Said where the section would be, as for assumptions: a heading
        # that silently disappears reads as "no alternatives were
        # considered", which is the one thing ACH exists to rule out (C2).
        withheld = d["redaction"]["hypotheses_withheld"]
        lines += ["", "## Competing hypotheses", "",
                  f"_{_count(withheld, 'competing hypothesis', 'competing hypotheses')} "
                  f"withheld with the case header; see the marking statement "
                  f"above._"]

    lines += [
        "",
        "---",
        "",
        f"Generated {d['generated_at']} by {d['generated_by']}. Every element "
        f"above traces to at least one assertion with a source and an "
        f"Admiralty grading; the full provenance is in the case file.",
        "",
        f"**TLP:{tlp}**",
    ]
    return "\n".join(lines)

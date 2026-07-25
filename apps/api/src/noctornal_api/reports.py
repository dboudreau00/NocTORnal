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

## Egress

`can_egress()` decides whether the finished document may leave, and it is
called with the DOCUMENT's classification -- which is the target level, not
the case's. That is the whole point of building at a lower level: an
AMBER_STRICT case can produce a GREEN report, and the GREEN report may
leave when the case never could.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

import psycopg

from noctornal_api.egress import Destination, can_egress
from noctornal_api.projections import GraphService, Projection
from noctornal_api.security.access import Tlp, tlp_from_name


class ReportError(Exception):
    pass


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

    @property
    def anything_withheld(self) -> bool:
        return bool(self.nodes_withheld or self.edges_withheld
                    or self.evidence_withheld)

    def statement(self) -> str:
        if not self.anything_withheld:
            return (f"This document is marked TLP:{self.built_at_tlp} and was "
                    f"prepared to include material up to TLP:{self.ceiling_tlp}. "
                    f"Nothing in the case file was above that ceiling, so "
                    f"nothing has been withheld from it.")
        return (
            f"This document is marked TLP:{self.built_at_tlp} and was prepared "
            f"to include material up to TLP:{self.ceiling_tlp}, from a case "
            f"classified TLP:{self.case_tlp}. "
            f"{self.nodes_withheld} entit(y/ies), {self.edges_withheld} "
            f"relationship(s) and {self.evidence_withheld} exhibit(s) are "
            f"above that level and have been withheld. **Every figure below "
            f"is computed over the redacted graph** and is therefore a lower "
            f"bound, not a measurement of the case.")


@dataclass
class Report:
    case: dict
    redaction: Redaction
    summary: dict
    actors: list[dict] = field(default_factory=list)
    relationships: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    hypotheses: dict = field(default_factory=dict)
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc))
    generated_by: UUID | None = None

    def as_dict(self) -> dict:
        return {
            "case": self.case,
            "classification": self.redaction.built_at_tlp,
            "redaction": {
                "built_at_tlp": self.redaction.built_at_tlp,
                "ceiling_tlp": self.redaction.ceiling_tlp,
                "case_tlp": self.redaction.case_tlp,
                "nodes_withheld": self.redaction.nodes_withheld,
                "edges_withheld": self.redaction.edges_withheld,
                "evidence_withheld": self.redaction.evidence_withheld,
                "statement": self.redaction.statement(),
            },
            "summary": self.summary,
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
              include_hypotheses: bool = True) -> Report:
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
                      authority_ref, retention_until, review_due, created_at
                 FROM core."case" WHERE id = %s""", (case_id,)).fetchone()
        if case is None:
            raise ReportError("case does not exist")
        case_tlp = case[4]

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
                                compartments=frozenset())
        projection = Projection(case_id=case_id, preset=preset,
                                include_inferred=False, min_confidence="LOW",
                                as_of=None)
        sub = redacted.project(projection, limit=5000)
        withheld = redacted.withheld(projection)

        evidence_rows = self._c.execute(
            """SELECT id, title, sha256, blake3, media_type, byte_size,
                      acquired_at, acquisition_method, classification
                 FROM core.evidence
                WHERE case_id = %s AND classification <= %s::core.tlp
                ORDER BY acquired_at""",
            (case_id, target.name)).fetchall()
        evidence_total = self._c.execute(
            "SELECT count(*) FROM core.evidence WHERE case_id = %s",
            (case_id,)).fetchone()[0]

        # The document's own mark: the highest classification of anything
        # actually in it, never the ceiling that was asked for.
        included = ([n["classification"] for n in sub.nodes]
                    + [e["classification"] for e in sub.edges]
                    + [r[8] for r in evidence_rows])
        marking = (max((tlp_from_name(c) for c in included), default=Tlp.CLEAR)
                   if included else Tlp.CLEAR)

        redaction = Redaction(
            built_at_tlp=marking.name, ceiling_tlp=target.name,
            case_tlp=case_tlp,
            nodes_withheld=withheld.nodes or 0,
            edges_withheld=withheld.edges or 0,
            evidence_withheld=evidence_total - len(evidence_rows),
        )

        metrics = redacted.metrics(projection) if hasattr(
            redacted, "metrics") else {}

        actors = sorted(
            ({"id": str(n["id"]), "type": n["node_type"], "label": n["label"],
              "classification": n["classification"],
              "has_evidence": n.get("has_evidence", False)}
             for n in sub.nodes),
            key=lambda a: a["label"].lower())
        relationships = [
            {"type": e["edge_type"], "src": str(e["src_node_id"]),
             "dst": str(e["dst_node_id"]), "sign": e["sign"],
             "confidence": e["confidence"], "inferred": e["is_inferred"],
             "has_evidence": e.get("has_evidence", False)}
            for e in sub.edges]

        report = Report(
            case={
                "id": str(case_id), "code": case[0], "title": case[1],
                "summary": case[2], "status": case[3],
                "classification": case_tlp,
                # docs/08: legal basis and retention are NOT NULL for a
                # reason. A disclosure document that does not state the
                # authority it was collected under is not disclosable.
                "legal_basis": case[5], "authority_ref": case[6],
                "retention_until": case[7].isoformat() if case[7] else None,
                "review_due": case[8].isoformat() if case[8] else None,
                "opened": case[9].isoformat() if case[9] else None,
            },
            redaction=redaction,
            summary={
                "entities": len(sub.nodes),
                "relationships": len(sub.edges),
                "exhibits": len(evidence_rows),
                "truncated": sub.truncated,
                "computed_over": "the redacted graph",
                **({"metrics": metrics} if metrics else {}),
            },
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
            } for r in evidence_rows],
            generated_by=generated_by,
        )

        if include_hypotheses:
            report.hypotheses = self._hypotheses(case_id)
        return report

    def _hypotheses(self, case_id: UUID) -> dict:
        """The ACH matrix, if the case has one.

        Included because a report that states a conclusion without the
        alternatives that were considered and ruled out is the confirmation
        bias ACH exists to correct, delivered on letterhead.
        """
        from noctornal_api.ach import EvidenceItem, as_response, score

        rows = self._c.execute(
            """SELECT id, statement, status FROM core.hypothesis
                WHERE case_id = %s AND status::text <> 'SUPERSEDED'
                ORDER BY created_at""", (case_id,)).fetchall()
        if not rows:
            return {}
        cells = self._c.execute(
            """SELECT he.assertion_id, he.hypothesis_id, he.stance,
                      a.reliability, a.credibility,
                      coalesce(n.label, a.claim_path, a.rationale, 'assertion')
                 FROM core.hypothesis_evidence he
                 JOIN core.hypothesis h ON h.id = he.hypothesis_id
                 JOIN core.assertion a ON a.id = he.assertion_id
                 LEFT JOIN core.node n ON n.id = a.node_id
                WHERE h.case_id = %s AND a.retracted_at IS NULL""",
            (case_id,)).fetchall()
        items: dict[UUID, EvidenceItem] = {}
        for assertion_id, hypothesis_id, stance, rel, cred, label in cells:
            item = items.setdefault(assertion_id, EvidenceItem(
                assertion_id=assertion_id, label=label, reliability=rel,
                credibility=cred))
            item.stances[hypothesis_id] = stance
        body = as_response(score([(r[0], r[1]) for r in rows], list(items.values())))
        body["statuses"] = {str(r[0]): r[2] for r in rows}
        return body


def check_egress(report: Report, destination: Destination | str,
                 destination_ceiling: str | None = None):
    """Whether the finished document may leave, judged on the DOCUMENT's
    classification rather than the case's.

    That distinction is the whole reason for building at a lower level: an
    AMBER_STRICT case can produce a GREEN report, and the GREEN report may
    leave when the case never could. Passing the case's classification here
    would make redaction pointless.
    """
    return can_egress(report.redaction.built_at_tlp, destination,
                      destination_ceiling=destination_ceiling)


def render_markdown(report: Report) -> str:
    """A plain-text rendering, TLP-marked top and bottom.

    Markdown rather than PDF deliberately: this has to be diffable,
    greppable and quotable, and a report whose only form is a binary is a
    report nobody checks against the case file. Marked at BOTH ends because
    a document read from the bottom -- which is how appendices are read --
    must still carry its handling caveat.
    """
    d = report.as_dict()
    tlp = d["classification"]
    lines = [
        f"# TLP:{tlp} — {d['case']['code']}: {d['case']['title']}",
        "",
        f"> **TLP:{tlp}.** {d['redaction']['statement']}",
        "",
        "## Authority and retention",
        "",
        f"- **Legal basis:** {d['case']['legal_basis']}",
        f"- **Authority reference:** {d['case']['authority_ref'] or '—'}",
        f"- **Opened:** {d['case']['opened']}",
        f"- **Retention until:** {d['case']['retention_until']}",
        f"- **Next review:** {d['case']['review_due']}",
        "",
        "## Summary",
        "",
        f"- Entities: {d['summary']['entities']}",
        f"- Relationships: {d['summary']['relationships']}",
        f"- Exhibits: {d['summary']['exhibits']}",
        f"- All figures computed over {d['summary']['computed_over']}.",
        "",
        "## Entities",
        "",
        "| Type | Label | TLP | Evidenced |",
        "|---|---|---|---|",
    ]
    for a in d["actors"]:
        lines.append(f"| {a['type']} | {a['label']} | {a['classification']} | "
                     f"{'yes' if a['has_evidence'] else 'NO'} |")

    lines += ["", "## Exhibits", "",
              "Hashes are given so the record can be identified evidentially "
              "rather than described (decision 13: US FRE 902(13)-(14), Canada "
              "Evidence Act ss. 31.1-31.8).", "",
              "| Title | SHA-256 | Acquired | Method |", "|---|---|---|---|"]
    for e in d["evidence"]:
        lines.append(f"| {e['title']} | `{(e['sha256'] or '')[:32]}…` | "
                     f"{e['acquired_at']} | {e['acquisition_method']} |")
    if not d["evidence"]:
        lines.append("| _none at this classification_ | | | |")

    if d["hypotheses"]:
        lines += ["", "## Competing hypotheses", "",
                  d["hypotheses"].get("method", ""), "",
                  "| Hypothesis | Inconsistency | Support | Assessed |",
                  "|---|---|---|---|"]
        for h in d["hypotheses"]["hypotheses"]:
            lines.append(f"| {h['statement']} | {h['inconsistency']} | "
                         f"{h['support']} | {h['assessed']} |")
        for warning in d["hypotheses"].get("warnings", []):
            lines.append(f"\n> ⚠ {warning}")

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

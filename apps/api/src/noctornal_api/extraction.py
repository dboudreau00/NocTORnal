"""Manual capture: paste text, get selectors, get proposals (docs/14 C2).

docs/14 recommends this before any adapter:

    A paste-a-conversation-export path that lands a document, extracts
    selectors with offsets, and proposes graph changes would exercise the
    whole proposal pipeline without any of the persona-management risk.

Which is the point. Phase 4's collection layer is a large build with real
operational hazard -- personas, egress binding, FLOOD_WAIT, parser drift --
and none of it is needed to prove the part that matters: that machine
output reaches the graph only through a human. Until now `collect.proposal`
had nothing writing it, so invariant 3 was true because nothing existed to
violate it.

The whole path, and where it stops:

    pasted text -> collect.document (hashed, deduped)
      -> regex extractors -> collect.extraction (selectors WITH offsets)
      -> collect.proposal                              <- STOPS HERE
      -> ------- human review (proposals.py) -------
      -> node / edge / assertion

Three things this deliberately does NOT do.

**It does not touch the graph.** It holds a `ProposalStore`, which by
construction cannot (see proposals.py). The extractor is not an actor.

**It does not guess at people.** A selector found in text is evidence that
a string appeared, not that an actor exists. Proposals are for SELECTOR
nodes and their observation, never "this handle is a person" -- that is an
attribution, and attribution is an assessment a human makes (invariant 2).

**It does not pretend precision it lacks.** Every extractor here is a
regex over pasted text. Regexes over prose produce false positives, so
every proposal carries the matched text, its character offsets and a
plain-language rationale, and scores are deliberately modest. docs/03: a
bare 0.87 "will be either over-trusted or ignored".
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

import psycopg

from noctornal_api.proposals import KIND_NODE, TLP_ORDER, ProposalStore, strictest
from noctornal_api.wording import agree
from noctornal_ontology.normalisers import normalise

EXTRACTOR = "paste_selector_regex"
EXTRACTOR_VERSION = "1"

# Selector patterns, ordered most-specific first. Ordering matters: an
# onion address is also a domain, and a Bitcoin address matches loose
# alphanumeric patterns, so the first claim on a span wins and later
# overlapping matches are dropped.
#
# The score attached to each is a statement about how often the PATTERN is
# wrong in prose, not about how important the selector is. A PGP
# fingerprint is 40 hex characters and essentially never appears by
# accident; a bare handle is a word.
_PATTERNS: tuple[tuple[str, re.Pattern, float, str], ...] = (
    ("ONION", re.compile(r"\b([a-z2-7]{56}\.onion)\b", re.I), 0.95,
     "56-character v3 onion address"),
    ("PGP_FPR", re.compile(r"\b((?:[0-9A-F]{4}\s?){10})\b", re.I), 0.9,
     "40 hex characters in PGP fingerprint form"),
    ("HASH_SHA256", re.compile(r"\b([0-9a-f]{64})\b", re.I), 0.85,
     "64 hex characters"),
    ("HASH_SHA1", re.compile(r"\b([0-9a-f]{40})\b", re.I), 0.7,
     "40 hex characters; could also be a git revision"),
    ("HASH_MD5", re.compile(r"\b([0-9a-f]{32})\b", re.I), 0.6,
     "32 hex characters; weak evidence on its own"),
    ("EMAIL", re.compile(r"\b([\w.+-]+@[\w-]+\.[\w.-]+)\b"), 0.9,
     "email address"),
    ("BTC_ADDR", re.compile(r"\b(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
     0.85, "Bitcoin address form"),
    ("ETH_ADDR", re.compile(r"\b(0x[a-fA-F0-9]{40})\b"), 0.9,
     "Ethereum address form"),
    ("XMR_ADDR", re.compile(r"\b([48][0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b"), 0.9,
     "Monero address form"),
    ("TOX_PK", re.compile(r"\b([0-9A-F]{64})\b"), 0.5,
     "64 uppercase hex; indistinguishable from a SHA-256 without context"),
    ("SESSION_ID", re.compile(r"\b(05[0-9a-f]{64})\b", re.I), 0.9,
     "Session ID form"),
    ("JABBER", re.compile(r"\b([\w.+-]+@[\w-]+\.[\w.-]+)\b"), 0.4,
     "XMPP address form; identical to an email address in text"),
    ("TELEGRAM_USER", re.compile(r"(?<![\w@])@([A-Za-z][\w]{4,31})\b"), 0.6,
     "@mention in Telegram username form"),
    ("IPV4", re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b"), 0.75,
     "dotted quad with all octets in range"),
    ("DOMAIN", re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,24})\b", re.I), 0.45,
     "domain form; common in prose, so weak on its own"),
    ("URL", re.compile(r"(https?://[^\s<>\"')]+)", re.I), 0.9, "URL"),
)

# Types whose match is a strict subset of another's span. When both claim
# the same characters, the more specific one is kept.
_SUBSUMED_BY = {"DOMAIN": {"ONION", "URL", "EMAIL", "JABBER"},
                "JABBER": {"EMAIL"},
                "HASH_SHA256": {"TOX_PK", "SESSION_ID"},
                "TOX_PK": {"SESSION_ID"}}


class ExtractionError(Exception):
    pass


class CaptureRefused(ExtractionError):
    """A capture this case cannot hold as things stand. The route answers
    409 (a state of the case, not a malformed request)."""


@dataclass(frozen=True)
class Hit:
    selector_type: str
    raw_value: str
    norm_value: str
    char_start: int
    char_end: int
    score: float
    why: str


@dataclass
class CaptureResult:
    document_id: UUID
    deduplicated: bool
    hits: list[Hit] = field(default_factory=list)
    proposal_ids: list[UUID] = field(default_factory=list)
    skipped_existing: int = 0
    #: The label this capture's proposals carry: never below the case, nor
    #: below an earlier capture of the same text. The triage notice is
    #: labelled with it (final review u12, 2026-09-24).
    classification: str | None = None
    #: The label the document is stored at. A fresh capture's is the same
    #: as `classification`; a re-paste's is the earlier capture's, which a
    #: re-paste never changes (c15 follow-up, 2026-09-24).
    document_classification: str | None = None

    def summary(self) -> dict:
        by_type: dict[str, int] = {}
        for h in self.hits:
            by_type[h.selector_type] = by_type.get(h.selector_type, 0) + 1
        return {
            "document_id": str(self.document_id),
            "deduplicated": self.deduplicated,
            "selectors_found": len(self.hits),
            "by_type": by_type,
            "proposals_created": len(self.proposal_ids),
            "already_known": self.skipped_existing,
            "classification": self.classification,
            "document_classification": self.document_classification,
        }


# Words that precede a dotted number when it is a VERSION rather than an
# address. Not a general solution -- nothing regex-shaped is -- but these
# four cover almost every version string that appears in this material, and
# a queue full of "10.2.14.3" is a queue analysts stop opening.
_VERSION_WORDS = ("build", "version", "release", "v")


def _plausible(selector_type: str, raw: str, text: str, start: int) -> bool:
    """A second look at a regex match, for the cases where the SHAPE is
    right but the meaning is probably not."""
    if selector_type != "IPV4":
        return True
    parts = raw.split(".")
    # 999.1.1.1 has the shape and cannot be an address.
    if any(not p.isdigit() or int(p) > 255 for p in parts):
        return False
    # Leading zeros mean it was written as text, not as an address.
    if any(len(p) > 1 and p.startswith("0") for p in parts):
        return False
    preceding = text[max(0, start - 20):start].strip().lower()
    last = preceding.split()[-1] if preceding.split() else ""
    return last.strip("-_:=") not in _VERSION_WORDS


def find_selectors(text: str) -> list[Hit]:
    """Every selector-shaped span in the text, with offsets, de-overlapped.

    Offsets are the point of doing this at all: docs/04 wants extractions
    to carry them so a reviewer can see the claim IN CONTEXT rather than
    trusting a value lifted out of it. A handle that turns out to be inside
    a quoted signature block is exactly the junk this pipeline exists to
    keep out of the graph.
    """
    claims: list[Hit] = []
    for sel_type, pattern, score, why in _PATTERNS:
        for m in pattern.finditer(text):
            raw = m.group(1)
            if not _plausible(sel_type, raw, text, m.start(1)):
                continue
            try:
                norm = normalise(sel_type, raw)
            except (KeyError, ValueError, TypeError):
                # A value the ontology's own normaliser rejects is not a
                # selector of that type, whatever the regex thought.
                continue
            if not norm:
                continue
            claims.append(Hit(sel_type, raw, norm, m.start(1), m.end(1),
                              score, why))

    # De-overlap: highest score wins a span, ties broken by the earlier
    # pattern (more specific). A span already claimed is not re-claimed.
    claims.sort(key=lambda h: (-h.score, h.char_start))
    kept: list[Hit] = []
    for c in claims:
        clash = False
        for k in kept:
            overlaps = c.char_start < k.char_end and k.char_start < c.char_end
            if not overlaps:
                continue
            if c.selector_type == k.selector_type:
                clash = True
                break
            if k.selector_type in _SUBSUMED_BY.get(c.selector_type, set()):
                clash = True
                break
            # Same span, unrelated types: keep both. "is this an email or a
            # Jabber address" is a real ambiguity and a reviewer should see
            # it rather than have it silently resolved.
            if c.char_start == k.char_start and c.char_end == k.char_end:
                continue
            clash = True
            break
        if not clash:
            kept.append(c)
    kept.sort(key=lambda h: h.char_start)
    return kept


class CaptureService:
    """Land pasted text as a document, extract from it, and propose.

    Holds a ProposalStore, never a GraphWriteService: this class is on the
    machine side of the line and cannot cross it (invariant 3).
    """

    def __init__(self, conn: psycopg.Connection):
        self._c = conn
        self._proposals = ProposalStore(conn)

    def source_id(self, kind: str = "MANUAL",
                  name: str = "Manual capture") -> UUID:
        """The single standing source row every manual capture hangs off.
        `collect.document.source_id` is NOT NULL because a document with no
        provenance is exactly what this system refuses to store."""
        if kind not in ("MANUAL", "PASTE"):
            raise ExtractionError(
                "manual capture may only use the MANUAL or PASTE source kinds")
        row = self._c.execute(
            "SELECT id FROM collect.source WHERE kind = %s::collect.source_kind "
            "AND name = %s", (kind, name),
        ).fetchone()
        if row:
            return row[0]
        return self._c.execute(
            """INSERT INTO collect.source (kind, name, default_reliability, notes)
               VALUES (%s::collect.source_kind, %s, 'F',
                       'Analyst paste. Reliability F because the chain of '
                       'custody is the analyst''s own account of where this '
                       'text came from.')
               RETURNING id""",
            (kind, name),
        ).fetchone()[0]

    def stored_label(self, case_id: UUID, requested: str) -> str:
        """The label a capture into this case is stored at: the one asked
        for, never below the case's own.

        Final review c15 (2026-09-24). `collect.document` hangs off a
        source, not a case: it has no case_id, no compartments and no
        floor trigger, and `/collection/documents` and the combined search
        filter it by its own label alone for every holder of
        `collection.read`. The capture form defaulted to AMBER on every
        case, so a stealer-log thread pasted into RED OP-HALCYON-25 was
        stored at AMBER, and every AMBER collection reader in the
        deployment could list its title, URL and an excerpt. The proposals
        were already raised to the case; the document was not.

        A compartmented case is refused outright. A document cannot carry
        compartments until the schema gives it some, so any label it is
        stored at is readable outside them: the RED document would still
        be listed to RED readers who are not in STEALER-2026. An exhibit
        is read under its case's compartments, so that is where such
        material goes for now."""
        if requested not in TLP_ORDER:
            raise ExtractionError(f"unknown classification {requested!r}")
        row = self._c.execute(
            'SELECT classification FROM core."case" WHERE id = %s',
            (case_id,)).fetchone()
        if row is None:
            raise ExtractionError("no such case")
        refused = self.refusal(case_id)
        if refused:
            raise CaptureRefused(f"{refused} Nothing was captured.")
        return strictest(requested, row[0]) or requested

    def refusal(self, case_id: UUID) -> str | None:
        """Why this case takes no capture, in the words the console shows
        on its capture form, or None when it takes one. The case record
        does not carry its compartments to the console, so the triage
        queue sends this instead (c15, 2026-09-24)."""
        row = self._c.execute(
            'SELECT compartments FROM core."case" WHERE id = %s',
            (case_id,)).fetchone()
        held = sorted((row[0] if row else None) or [])
        if not held:
            return None
        return (f"Capture is off on this case. It is kept in "
                f"{agree(len(held), 'compartment', 'compartments')} "
                f"{', '.join(held)}, and a captured document cannot carry "
                f"compartments yet: stored, its text would be listed and "
                f"searchable in the collection by readers outside "
                f"{agree(len(held), 'it', 'them')}. Upload the material as "
                f"evidence instead: an exhibit is only ever read under the "
                f"case's own compartments.")

    def capture(
        self,
        *,
        case_id: UUID,
        text: str,
        title: str | None = None,
        external_url: str | None = None,
        author_handle: str | None = None,
        posted_at: datetime | None = None,
        classification: str = "AMBER",
        propose: bool = True,
    ) -> CaptureResult:
        """Land the text, extract, and raise proposals for what was found."""
        if not text or not text.strip():
            raise ExtractionError("nothing to capture")
        # Never below the case, and never into a compartmented one (c15,
        # 2026-09-24): see `stored_label`.
        classification = self.stored_label(case_id, classification)

        digest = hashlib.sha256(text.encode("utf-8")).digest()
        source = self.source_id()

        # Dedupe on content hash (docs/02: "dedupe on content_sha256 --
        # edited posts version, not duplicate"). Re-pasting the same text
        # must not manufacture a second document and a second set of
        # proposals for the same observation.
        existing = self._c.execute(
            """SELECT id, classification FROM collect.document
                WHERE source_id = %s AND content_sha256 = %s""",
            (source, digest),
        ).fetchone()
        if existing is not None:
            # The DOCUMENT is deduped globally -- `collect.document` hangs
            # off a source, not a case, because the same forum post is one
            # observation however many cases care about it. But a case's
            # triage queue is its own: pasting the same thread into a second
            # case must still raise proposals THERE, or the second analyst
            # silently gets nothing. Proposals are deduped separately, by
            # value, inside _propose.
            #
            # The stricter of the stored document's label and this
            # paste's: the text is the same, and whichever analyst judged
            # it more sensitive is the one to believe, so the proposals
            # raised HERE carry it.
            #
            # The shared document keeps its own label (c15 follow-up,
            # 2026-09-24). Raising it on a stricter re-paste was tried in
            # this pass and protected nothing: the same text was already
            # stored, and readable, at the lower label, and a document
            # records no case, so the stricter case's interest never
            # reaches it. What the raise did reach was every OTHER case
            # citing the document. A proposal is read at the stricter of
            # its own and its document's label, so an AMBER case's pending
            # proposals and its Open source view vanished from that case's
            # own AMBER reviewers, and the vanishing told them somebody
            # above their clearance had pasted the same thread.
            label = strictest(existing[1], classification) or classification
            result = CaptureResult(existing[0], deduplicated=True,
                                   classification=label,
                                   document_classification=existing[1])
            if propose:
                result.hits = find_selectors(text)
                result.proposal_ids, result.skipped_existing = self._propose(
                    case_id, existing[0], text, result.hits,
                    classification=label)
            return result

        with self._c.transaction():
            document_id = self._c.execute(
                """INSERT INTO collect.document
                       (source_id, title, body_text, content_sha256,
                        external_url, author_handle, posted_at,
                        captured_at, classification)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::core.tlp)
                   RETURNING id""",
                (source, title, text, digest, external_url, author_handle,
                 posted_at, datetime.now(timezone.utc), classification),
            ).fetchone()[0]

            hits = find_selectors(text)
            for h in hits:
                self._c.execute(
                    """INSERT INTO collect.extraction
                           (document_id, selector_type, raw_value, norm_value,
                            char_start, char_end, extractor, extractor_version,
                            score)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (document_id, h.selector_type, h.raw_value, h.norm_value,
                     h.char_start, h.char_end, EXTRACTOR, EXTRACTOR_VERSION,
                     h.score),
                )

        result = CaptureResult(document_id, deduplicated=False, hits=hits,
                               classification=classification,
                               document_classification=classification)
        if propose:
            result.proposal_ids, result.skipped_existing = self._propose(
                case_id, document_id, text, hits,
                classification=classification)
        return result

    def _propose(self, case_id: UUID, document_id: UUID, text: str,
                 hits: list[Hit], *,
                 classification: str) -> tuple[list[UUID], int]:
        """One proposal per NEW selector value.

        A selector already recorded in this case is not proposed again --
        the observation is worth storing as an extraction, but asking an
        analyst to re-triage a handle they accepted last week is how a
        triage queue becomes something people stop opening.

        Each proposal carries the capture's `classification`, and Accept
        writes its element at that label unless the reviewer raises it
        (ux08-triage:accept-downgrades-classification and the owner's
        gap-capture-classification, 2026-09-23). The capture form asked
        for a classification, stored it on the document, and the payload
        never carried it, so a RED capture's selectors were accepted at
        AMBER.

        One transaction for the batch: all of a capture's proposals land
        together or none do, and the live channel folds their
        announcements into one event rather than one per selector.
        """
        with self._c.transaction():
            return self._propose_each(case_id, document_id, text, hits,
                                      classification)

    def _propose_each(self, case_id: UUID, document_id: UUID, text: str,
                      hits: list[Hit],
                      classification: str) -> tuple[list[UUID], int]:
        made: list[UUID] = []
        skipped = 0
        seen: set[tuple[str, str]] = set()
        for h in hits:
            key = (h.selector_type, h.norm_value)
            if key in seen:
                continue
            seen.add(key)
            known = self._c.execute(
                """SELECT 1 FROM core.selector
                    WHERE case_id = %s AND selector_type = %s
                      AND norm_value = %s""",
                (case_id, h.selector_type, h.norm_value),
            ).fetchone()
            if known:
                skipped += 1
                continue
            # Already sitting in this case's queue, or already dispositioned
            # here. Re-pasting a thread to check something must not stack up
            # duplicate suggestions, and re-offering one an analyst already
            # rejected is worse than useless.
            queued = self._c.execute(
                """SELECT 1 FROM collect.proposal
                    WHERE case_id = %s AND kind = %s
                      AND payload->>'label' = %s
                      AND payload->'attrs'->>'selector_type' = %s""",
                (case_id, KIND_NODE, h.norm_value, h.selector_type),
            ).fetchone()
            if queued:
                skipped += 1
                continue
            made.append(self._proposals.propose(
                case_id=case_id,
                kind=KIND_NODE,
                origin=f"{EXTRACTOR}/{EXTRACTOR_VERSION}",
                payload={
                    "node_type": "SELECTOR",
                    "label": h.norm_value,
                    "classification": classification,
                    "attrs": {
                        "selector_type": h.selector_type,
                        "raw_value": h.raw_value,
                        "char_start": h.char_start,
                        "char_end": h.char_end,
                    },
                },
                # Plain language, with the surrounding text, because that is
                # what makes it reviewable (docs/03).
                rationale=(
                    f"{h.why}, found at characters {h.char_start}-{h.char_end} "
                    f"of the captured document. Context: "
                    f"...{_context(text, h.char_start, h.char_end)}..."
                ),
                score=h.score,
                document_id=document_id,
            ))
        return made, skipped


def _context(text: str, start: int, end: int, window: int = 45) -> str:
    """The matched span with its surroundings, whitespace-collapsed. A
    reviewer deciding whether a handle is real needs to see that it came
    from a sentence rather than a quoted signature block."""
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    return " ".join(text[lo:hi].split())

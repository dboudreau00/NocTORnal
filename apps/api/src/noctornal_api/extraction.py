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

from noctornal_api.proposals import KIND_NODE, ProposalStore
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

        digest = hashlib.sha256(text.encode("utf-8")).digest()
        source = self.source_id()

        # Dedupe on content hash (docs/02: "dedupe on content_sha256 --
        # edited posts version, not duplicate"). Re-pasting the same text
        # must not manufacture a second document and a second set of
        # proposals for the same observation.
        existing = self._c.execute(
            """SELECT id FROM collect.document
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
            result = CaptureResult(existing[0], deduplicated=True)
            if propose:
                result.hits = find_selectors(text)
                result.proposal_ids, result.skipped_existing = self._propose(
                    case_id, existing[0], text, result.hits)
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

        result = CaptureResult(document_id, deduplicated=False, hits=hits)
        if propose:
            result.proposal_ids, result.skipped_existing = self._propose(
                case_id, document_id, text, hits)
        return result

    def _propose(self, case_id: UUID, document_id: UUID, text: str,
                 hits: list[Hit]) -> tuple[list[UUID], int]:
        """One proposal per NEW selector value.

        A selector already recorded in this case is not proposed again --
        the observation is worth storing as an extraction, but asking an
        analyst to re-triage a handle they accepted last week is how a
        triage queue becomes something people stop opening.
        """
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

"""Phase 8 -- malware sample handling (docs/11, invariant 10).

=====================================================================
COUNSEL MUST REVIEW A DEPLOYMENT OF THIS BEFORE IT IS USED IN ANY
ABSOLUTE SENSE.

Built on an operator directive of 2026-07-25 which supersedes decision
36's block. That block was never about the code. It was about the fact
that a store of attacker-supplied binaries WILL eventually receive
material whose possession alone is an offence; that the handling rules
differ between the two jurisdictions this platform targets (decision 13:
US and Canada); and that discovering that after the first ingest is a
legal problem rather than a technical one.

This module cannot fix that and does not pretend to. What it does is
refuse to accept anything until an operator has declared, in the
environment, that a prohibited-content policy exists and names a
designated person -- see `policy_declared()`. The declaration is a
statement by the operator, not a verification by the software. A false
declaration produces a working system and an unlawful deployment.
=====================================================================

## Invariant 10, enforced rather than documented

    Samples never render, never execute. The binary is only ever an
    encrypted archive download from a SEPARATE ORIGIN.

The origin split is usually written down and then forgotten at deploy
time, so it is a runtime check here: `download()` refuses unless
`NOCTORNAL_SAMPLE_ORIGIN` is configured AND the request arrived at it.
Serving hostile bytes from the same origin as the case file means an
escape -- a crafted filename, an SVG preview, a PDF renderer bug -- runs
with the analyst's session on the case data. docs/11: "you would have
built a drive-by vector into your own highest-trust system, seeded with
hostile files by design."

Three more rules the code holds:

- **The object key is the SHA-256, never the filename.** Original
  filenames are attacker-controlled and are themselves a payload vector
  (`../../etc/cron.d/x`, a right-to-left override, a 4KB name). The
  original is kept in a column for the record and never used as a path.
- **Nothing is stored as an executable.** Every sample is encrypted at
  rest under a per-sample key. Besides containment, this is what stops
  your own EDR quarantining the evidence -- docs/11 calls that a routine
  and embarrassing failure in labs that skip it.
- **Quarantine is the landing state.** Nothing reaches the RE queue
  before triage has run.

## What the archive password does and does not do

The convention is a ZIP with the password `infected`. It DOES prevent
accidental double-click execution and stop mail gateways and EDR from
silently eating the sample in transit. It provides NO confidentiality --
the password is public and ZipCrypto is broken. Confidentiality comes
from access control, transport and audit. The password must never be
allowed to create a false sense of protection, so `archive()` says so in
the archive comment itself.

## What is NOT built, and is not pretended

- **No YARA, no ssdeep, no imphash, no Rich header.** Each needs a
  dependency (`yara-python`, `ssdeep`, `pefile`) and ssdeep needs a C
  toolchain. What IS computed is recorded; what is not is recorded as a
  GAP on the row, because a NULL imphash that reads as "this sample has
  no imports" is worse than an absent one that says why.
- **No detonation.** The record exists and the authorisation constraint
  is real; nothing submits to a sandbox. docs/11 is emphatic that you
  integrate rather than build one.
- **No prohibited-content hash screening.** The hook and the REJECTED
  path exist. The hash sets do not, and in most jurisdictions holding
  them requires authorisation this deployment does not have.
"""
from __future__ import annotations

import hashlib
import io
import math
import os
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.security import envelope

SUBMITTED = "SUBMITTED"
QUARANTINED = "QUARANTINED"
TRIAGED = "TRIAGED"
ASSIGNED = "ASSIGNED"
IN_ANALYSIS = "IN_ANALYSIS"
REPORTED = "REPORTED"
REJECTED = "REJECTED"

#: The industry convention (MalwareBazaar, VirusShare, malware-traffic).
#: It is a safety interlock, not a secret.
ARCHIVE_PASSWORD = b"infected"

#: 256 MB. A sample larger than this is a disk image or a mistake, and
#: either way it does not belong in a quarantine queue behind an HTTP
#: request.
MAX_SAMPLE_BYTES = 256 * 1024 * 1024


class SampleError(Exception):
    pass


class PolicyNotDeclared(SampleError):
    """Raised when nothing has been ingested because nobody has said the
    prohibited-content policy exists."""


def policy_declared() -> tuple[bool, str]:
    """Has an operator declared a prohibited-content policy?

    Two environment variables, both required:

    - `NOCTORNAL_PROHIBITED_CONTENT_POLICY` -- a reference an auditor can
      follow. A document id, a ticket, a URL. Not a boolean, because
      "true" is what somebody types to make an error go away and a
      reference is what somebody has to actually possess.
    - `NOCTORNAL_DESIGNATED_PERSON` -- who material is escalated to.
      docs/11 is specific that the response to prohibited material is a
      documented procedure with a named person, not a product feature.

    This is a DECLARATION, not a verification. The software cannot check
    that the referenced policy exists, is correct, or has been read by
    anyone. What it can do is refuse to make ingesting a one-click
    accident, and put the operator's own reference in the audit trail so
    that "nobody knew" is not available afterwards.
    """
    reference = os.environ.get("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "").strip()
    person = os.environ.get("NOCTORNAL_DESIGNATED_PERSON", "").strip()
    if not reference or not person:
        return False, (
            "sample ingest is refused until an operator declares a "
            "prohibited-content policy: set "
            "NOCTORNAL_PROHIBITED_CONTENT_POLICY to a reference an auditor "
            "can follow, and NOCTORNAL_DESIGNATED_PERSON to whoever material "
            "is escalated to. Counsel must have written that policy first "
            "(docs/11); this check records the declaration, it cannot verify "
            "it.")
    return True, reference


def sample_origin() -> str:
    """The separate origin sample bytes may be served from.

    Empty means "not configured", and `download()` then refuses. That is
    invariant 10 as a runtime check rather than a deployment note: an
    origin split that is only ever written down is an origin split that
    does not survive the first hurried deploy.
    """
    return os.environ.get("NOCTORNAL_SAMPLE_ORIGIN", "").strip().rstrip("/")


# ---------------------------------------------------------------------------
# Static triage -- pure, no I/O, no execution
# ---------------------------------------------------------------------------

#: Magic bytes, longest first so a prefix cannot shadow a longer match.
#: Typed by STRUCTURE, never by extension: the extension is part of the
#: attacker's message, and `invoice.pdf.exe` is the oldest trick there is.
_MAGIC: list[tuple[bytes, str]] = [
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/MZ"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32"),
    (b"PK\x03\x04", "ZIP or OOXML"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"\x1f\x8b", "gzip"),
    (b"%PDF-", "PDF"),
    (b"\xd0\xcf\x11\xe0", "OLE compound (legacy Office)"),
    (b"#!", "script with shebang"),
]


@dataclass(frozen=True)
class Triage:
    """What static triage established, and what it could not.

    `gaps` is not decoration. A NULL imphash reads as "this sample has no
    imports"; a recorded gap reads as "nobody looked". Invariant 12 is
    about ingest, but the principle is the same -- an absence with no
    reason is indistinguishable from a finding.
    """

    sha256: bytes
    sha1: bytes
    md5: bytes
    byte_size: int
    file_type: str
    entropy: float
    gaps: list[dict] = field(default_factory=list)


def shannon_entropy(data: bytes) -> float:
    """Bits per byte. Above ~7.2 means packed, encrypted or compressed --
    which is a triage signal, not a verdict."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    size = len(data)
    return -sum((c / size) * math.log2(c / size) for c in counts if c)


def file_type_of(data: bytes) -> str:
    for magic, label in _MAGIC:
        if data.startswith(magic):
            return label
    return "unknown"


def triage(data: bytes) -> Triage:
    """Static only. Nothing here executes, parses a container, or
    expands an archive.

    Archive expansion is deliberately absent: docs/11 asks for it with
    depth and expansion-ratio caps, and an uncapped expander is a zip
    bomb waiting for someone to send one. Building the capped version is
    real work and the honest thing is to record its absence rather than
    ship the uncapped one.
    """
    gaps = [
        {"step": "imphash", "reason": "pefile is not a dependency"},
        {"step": "rich_header_hash", "reason": "pefile is not a dependency"},
        {"step": "ssdeep", "reason": "ssdeep needs a C toolchain"},
        {"step": "tlsh", "reason": "py-tlsh is not a dependency"},
        {"step": "yara", "reason": "no rule corpus and no yara-python"},
        {"step": "archive_expansion",
         "reason": "not built: an expander without depth and ratio caps is a "
                   "zip bomb waiting to be sent one"},
        {"step": "prohibited_content_screening",
         "reason": "no authorised hash set; the REJECTED path is manual"},
    ]
    return Triage(
        sha256=hashlib.sha256(data).digest(),
        sha1=hashlib.sha1(data).digest(),
        md5=hashlib.md5(data).digest(),
        byte_size=len(data),
        file_type=file_type_of(data),
        entropy=round(shannon_entropy(data), 4),
        gaps=gaps,
    )


def archive(data: bytes, sha256_hex: str) -> bytes:
    """Wrap the sample so it cannot be double-clicked into running.

    Named for its hash, not its original filename -- the name is
    attacker-controlled and the archive is the last place it should
    reappear. The comment states plainly what the password is worth,
    because the single commonest mistake with this convention is treating
    it as confidentiality.

    Python's zipfile writes ZipCrypto, which is broken, and that is fine
    for what this is: an interlock against accident and against scanners,
    not a control. Anything needing real confidentiality gets 7z with AES
    and header encryption, out of band (docs/11).
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{sha256_hex}.bin", data)
        zf.comment = (
            b"NocTORnal sample. Password: infected. This password prevents "
            b"accidental execution and stops scanners eating the file. It is "
            b"PUBLIC and provides NO confidentiality. Handle under the "
            b"classification this was released at."
        )
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

class SampleStorage:
    """The sample bucket. docs/11: "Bucket separate from evidence, WORM, no
    public access, no CDN, own credentials."

    Its OWN credentials, deliberately. Reusing the evidence keys would mean
    a compromise of the evidence path reaches the malware store and vice
    versa, and the whole point of a separate bucket is that the two do not
    share a blast radius. `SAMPLE_ACCESS_KEY` falls back to the MinIO ones
    ONLY for a single-node development stack, and says so.
    """

    def __init__(self) -> None:
        from minio import Minio

        endpoint = os.environ.get("SAMPLE_ENDPOINT") or os.environ.get(
            "MINIO_ENDPOINT")
        access = os.environ.get("SAMPLE_ACCESS_KEY") or os.environ.get(
            "MINIO_ACCESS_KEY")
        secret = os.environ.get("SAMPLE_SECRET_KEY") or os.environ.get(
            "MINIO_SECRET_KEY")
        if not (endpoint and access and secret):
            raise SampleError(
                "sample storage is not configured: set SAMPLE_ENDPOINT / "
                "SAMPLE_ACCESS_KEY / SAMPLE_SECRET_KEY (a deployment should "
                "give the sample bucket its own credentials, not the evidence "
                "bucket's)")
        secure = os.environ.get("SAMPLE_SECURE", "false").lower() == "true"
        self._bucket = os.environ.get("SAMPLE_BUCKET", "noctornal-samples")
        self._client = Minio(endpoint, access_key=access, secret_key=secret,
                             secure=secure)

    def put(self, key: str, data: bytes) -> None:
        self._client.put_object(
            self._bucket, key, io.BytesIO(data), length=len(data),
            # Never the real type. Nothing about a sample is ever parsed by
            # anything, and a Content-Type is a hint to parse.
            content_type="application/octet-stream")

    def get(self, key: str) -> bytes:
        response = self._client.get_object(self._bucket, key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def delete(self, key: str) -> None:
        self._client.remove_object(self._bucket, key)


@dataclass(frozen=True)
class Sample:
    id: UUID
    case_id: UUID | None
    sha256: str
    sha1: str | None
    md5: str | None
    original_filename: str | None
    byte_size: int
    state: str
    reject_reason: str | None
    file_type: str | None
    entropy: float | None
    triage_gaps: list
    submitted_by: UUID
    submitted_at: datetime
    source_note: str | None
    assigned_to: UUID | None
    classification: str
    compartments: frozenset[str]


class SampleService:
    """Storage is injected so the tests exercise the state machine, the
    encryption and the custody ledger without MinIO -- and so the
    quarantine path is provable without a bucket full of live malware."""

    def __init__(self, conn: psycopg.Connection, storage=None):
        self._c = conn
        self._storage = storage

    # -- ingest ------------------------------------------------------------

    def submit(self, data: bytes, *, submitted_by: UUID,
               case_id: UUID | None = None,
               original_filename: str | None = None,
               source_note: str | None = None,
               classification: str = "AMBER",
               compartments: frozenset[str] = frozenset()) -> Sample:
        """Land a sample in QUARANTINE, run static triage, encrypt at rest.

        Refuses outright unless a prohibited-content policy has been
        declared. That refusal is the whole reason this phase was blocked,
        and it stays enforced rather than becoming a comment.
        """
        declared, detail = policy_declared()
        if not declared:
            raise PolicyNotDeclared(detail)
        if not data:
            raise SampleError("an empty submission is not a sample")
        if len(data) > MAX_SAMPLE_BYTES:
            raise SampleError(
                f"sample exceeds {MAX_SAMPLE_BYTES} bytes; a submission that "
                f"large is a disk image or a mistake")

        result = triage(data)
        digest_hex = result.sha256.hex()

        existing = self._c.execute(
            "SELECT id FROM lab.sample WHERE sha256 = %s", (result.sha256,)
        ).fetchone()
        if existing is not None:
            # Deduplication on content, exactly like evidence. Two analysts
            # finding the same binary is a finding about the actors, not a
            # reason for two copies of live malware.
            raise SampleError(
                f"this sample is already held (sha256 {digest_hex[:16]}...); "
                f"link the existing record rather than storing it twice")

        # Per-sample data key, envelope-encrypted with the same scheme
        # persona credentials and TOTP secrets use.
        data_key = os.urandom(32)
        key_blob, key_id = envelope.encrypt(data_key.hex())
        ciphertext = _xor_stream(data, data_key)

        storage_key = f"samples/{digest_hex[:2]}/{digest_hex}"
        bucket = os.environ.get("SAMPLE_BUCKET", "noctornal-samples")
        if self._storage is not None:
            self._storage.put(storage_key, ciphertext)

        row = self._c.execute(
            """INSERT INTO lab.sample
                   (case_id, sha256, sha1, md5, original_filename, byte_size,
                    storage_key, storage_bucket, data_key_ciphertext,
                    data_key_id, state, file_type, entropy, triage_gaps,
                    submitted_by, source_note, classification, compartments)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                       'QUARANTINED', %s, %s, %s, %s, %s, %s, %s)
               RETURNING """ + _COLUMNS,
            (case_id, result.sha256, result.sha1, result.md5,
             original_filename, result.byte_size, storage_key, bucket,
             key_blob, key_id, result.file_type, result.entropy,
             Json(result.gaps), submitted_by, source_note, classification,
             sorted(compartments)),
        ).fetchone()
        sample = _record(row)
        self._access(sample.id, submitted_by, "VIEWED_META",
                     {"event": "submitted", "policy_reference": detail})
        return sample

    def reject(self, sample_id: UUID, *, actor_id: UUID, reason: str,
               purge_bytes: bool = True) -> Sample:
        """The REJECTED path docs/11 requires: record THAT something was
        rejected and why, **without retaining the content**.

        The bytes go; the row stays. That asymmetry is the point -- an
        auditor asking "did anything prohibited ever come through here"
        needs an answer, and the answer cannot be the material itself.
        """
        if not reason or not reason.strip():
            raise SampleError("a rejection has to say why; that record is the "
                              "only thing that survives the content")
        current = self.get(sample_id)
        if current is None:
            raise SampleError("no such sample")
        if current.state == REJECTED:
            raise SampleError("already rejected")

        if purge_bytes and self._storage is not None:
            self._storage.delete(
                self._c.execute(
                    "SELECT storage_key FROM lab.sample WHERE id = %s",
                    (sample_id,)).fetchone()[0])

        row = self._c.execute(
            """UPDATE lab.sample
                  SET state = 'REJECTED', reject_reason = %s,
                      data_key_ciphertext = %s
                WHERE id = %s RETURNING """ + _COLUMNS,
            # The data key is destroyed too. Even if the object survives a
            # bucket-lifecycle race, nothing can decrypt it.
            (reason.strip(), b"", sample_id)).fetchone()
        self._access(sample_id, actor_id, "REJECTED",
                     {"reason": reason.strip(), "bytes_purged": purge_bytes})
        return _record(row)

    # -- queue -------------------------------------------------------------

    def assign(self, sample_id: UUID, *, analyst_id: UUID,
               actor_id: UUID) -> Sample:
        row = self._c.execute(
            """UPDATE lab.sample
                  SET assigned_to = %s, assigned_at = now(), state = 'ASSIGNED'
                WHERE id = %s AND state IN ('QUARANTINED','TRIAGED')
            RETURNING """ + _COLUMNS,
            (analyst_id, sample_id)).fetchone()
        if row is None:
            raise SampleError(
                "only a quarantined or triaged sample can be assigned")
        self._access(sample_id, actor_id, "ASSIGNED",
                     {"analyst_id": str(analyst_id)})
        return _record(row)

    def record_analysis(self, sample_id: UUID, *, analyst_id: UUID, kind: str,
                        findings: dict | None = None,
                        extracted_selectors: list | None = None,
                        yara_hits: list[str] | None = None,
                        family_assessment: str | None = None,
                        confidence: str | None = None,
                        narrative: str | None = None,
                        tool: str | None = None,
                        tool_version: str | None = None) -> UUID:
        """Findings are machine-readable by construction.

        `family_assessment` without a `confidence` is refused by a CHECK
        constraint, because a family attribution is an ASSESSMENT and one
        without a confidence is a fact wearing an assessment's clothes.
        Reaching the graph is a separate, deliberate step: it becomes a
        `core.assertion` like everything else (invariant 1), never a column
        stamped on an actor.
        """
        if kind not in {"STATIC", "YARA", "MANUAL_RE", "SANDBOX", "VENDOR"}:
            raise SampleError(f"unknown analysis kind {kind!r}")
        if family_assessment and not confidence:
            raise SampleError(
                "a family attribution is an assessment, not a fact: give it a "
                "confidence or do not record it")
        row = self._c.execute(
            """INSERT INTO lab.sample_analysis
                   (sample_id, kind, analyst_id, tool, tool_version, findings,
                    extracted_selectors, yara_hits, family_assessment,
                    confidence, narrative)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (sample_id, kind, analyst_id, tool, tool_version,
             Json(findings or {}), Json(extracted_selectors or []),
             yara_hits, family_assessment, confidence, narrative)).fetchone()
        self._c.execute(
            "UPDATE lab.sample SET state = 'IN_ANALYSIS' "
            "WHERE id = %s AND state = 'ASSIGNED'", (sample_id,))
        self._access(sample_id, analyst_id, "ANALYSED", {"kind": kind})
        return row[0]

    # -- egress ------------------------------------------------------------

    def download(self, sample_id: UUID, *, actor_id: UUID,
                 request_origin: str | None) -> tuple[bytes, str]:
        """The encrypted archive, and only from the separate origin.

        `request_origin` is where the request actually arrived, taken from
        the server's own configuration rather than from a header the client
        controls. Serving hostile bytes from the app origin means an escape
        runs with the analyst's session on the case file -- a drive-by
        vector built into the highest-trust system in the estate, seeded
        with hostile files by design (docs/11).
        """
        configured = sample_origin()
        if not configured:
            raise SampleError(
                "sample downloads are refused: NOCTORNAL_SAMPLE_ORIGIN is not "
                "configured, so there is no separate origin to serve hostile "
                "bytes from. Invariant 10 is not a deployment suggestion.")
        if (request_origin or "").rstrip("/") != configured:
            raise SampleError(
                "sample bytes are served only from the configured sample "
                "origin, never from the application origin")

        row = self._c.execute(
            """SELECT storage_key, data_key_ciphertext, data_key_id, sha256,
                      state
                 FROM lab.sample WHERE id = %s""", (sample_id,)).fetchone()
        if row is None:
            raise SampleError("no such sample")
        if row[4] == REJECTED:
            raise SampleError("this sample was rejected and its bytes destroyed")
        if not row[1]:
            raise SampleError("this sample has no data key; it cannot be read")
        if self._storage is None:
            raise SampleError("sample storage is not configured")

        data_key = bytes.fromhex(envelope.decrypt(row[1], key_id=row[2]))
        ciphertext = self._storage.get(row[0])
        data = _xor_stream(ciphertext, data_key)

        digest = hashlib.sha256(data).digest()
        if digest != bytes(row[3]):
            # Same discipline as the evidence read path: re-verify on EVERY
            # read and fail closed. A sample whose bytes changed is either a
            # storage fault or a tamper, and neither is a thing to hand to
            # an analyst.
            raise SampleError(
                "sample integrity check failed: stored bytes do not match the "
                "recorded sha256")

        self._access(sample_id, actor_id, "DOWNLOADED",
                     {"origin": configured}, archive_format="ZIP_INFECTED")
        return archive(data, digest.hex()), digest.hex()

    def request_detonation(self, sample_id: UUID, *, requested_by: UUID,
                           target: str, exposure_level: str,
                           authorised_by: UUID | None = None,
                           note: str | None = None) -> UUID:
        """Record a detonation request. **Nothing is submitted anywhere.**

        docs/11: do not build a sandbox, integrate with one. What is built
        is the authorisation record, because detonation is an overt act --
        operators watch public sandboxes for their own samples and treat a
        submission as a signal they have been noticed, which can end an
        operation that took months.
        """
        if exposure_level not in {"NONE", "VENDOR", "PUBLIC"}:
            raise SampleError(f"unknown exposure level {exposure_level!r}")
        if exposure_level != "NONE" and (authorised_by is None or not note):
            raise SampleError(
                "anything that leaves the building needs a named authoriser "
                "and a note: submitting to a vendor or public sandbox exposes "
                "the sample AND your interest in it")
        row = self._c.execute(
            """INSERT INTO lab.detonation
                   (sample_id, target, exposure_level, authorised_by,
                    authorisation_note, requested_by, status)
               VALUES (%s, %s, %s, %s, %s, %s,
                       CASE WHEN %s = 'NONE' THEN 'PENDING' ELSE 'AUTHORISED' END)
               RETURNING id""",
            (sample_id, target, exposure_level, authorised_by, note,
             requested_by, exposure_level)).fetchone()
        self._access(sample_id, requested_by, "DETONATED",
                     {"target": target, "exposure_level": exposure_level})
        return row[0]

    # -- reads -------------------------------------------------------------

    def get(self, sample_id: UUID) -> Sample | None:
        row = self._c.execute(
            f"SELECT {_COLUMNS} FROM lab.sample WHERE id = %s",
            (sample_id,)).fetchone()
        return _record(row) if row else None

    def queue(self, *, states: tuple[str, ...] = (QUARANTINED, TRIAGED, ASSIGNED),
              clearance: str = "RED", compartments: frozenset[str] = frozenset(),
              limit: int = 100) -> list[Sample]:
        """The RE queue, filtered by the caller's own labels. A sample can be
        classified above its case, so the case gate alone is not enough."""
        rows = self._c.execute(
            f"""SELECT {_COLUMNS} FROM lab.sample
                 WHERE state = ANY(%s)
                   AND classification <= %s::core.tlp
                   AND compartments <@ %s
                 ORDER BY submitted_at DESC LIMIT %s""",
            (list(states), clearance, list(compartments), limit)).fetchall()
        return [_record(r) for r in rows]

    def analyses(self, sample_id: UUID) -> list[dict]:
        rows = self._c.execute(
            """SELECT id, kind, analyst_id, tool, findings,
                      extracted_selectors, yara_hits, family_assessment,
                      confidence, narrative, created_at
                 FROM lab.sample_analysis WHERE sample_id = %s
                ORDER BY created_at DESC""", (sample_id,)).fetchall()
        return [{"id": str(r[0]), "kind": r[1],
                 "analyst_id": str(r[2]) if r[2] else None, "tool": r[3],
                 "findings": r[4], "extracted_selectors": r[5],
                 "yara_hits": r[6] or [], "family_assessment": r[7],
                 "confidence": r[8], "narrative": r[9],
                 "created_at": r[10].isoformat()} for r in rows]

    def custody(self, sample_id: UUID) -> list[dict]:
        rows = self._c.execute(
            """SELECT actor_id, action, occurred_at, archive_format, detail
                 FROM lab.sample_access WHERE sample_id = %s
                ORDER BY occurred_at DESC""", (sample_id,)).fetchall()
        return [{"actor_id": str(r[0]), "action": r[1],
                 "occurred_at": r[2].isoformat(), "archive_format": r[3],
                 "detail": r[4]} for r in rows]

    # -- internals ---------------------------------------------------------

    def _access(self, sample_id: UUID, actor_id: UUID, action: str,
                detail: dict, archive_format: str | None = None) -> None:
        self._c.execute(
            """INSERT INTO lab.sample_access
                   (sample_id, actor_id, action, archive_format, detail)
               VALUES (%s, %s, %s, %s, %s)""",
            (sample_id, actor_id, action, archive_format, Json(detail)))


def _xor_stream(data: bytes, key: bytes) -> bytes:
    """Encrypt the sample at rest under its per-sample key.

    A keystream XOR, and the honest note about it: this is CONTAINMENT, not
    confidentiality. Its jobs are that the bytes on disk are not
    recognisable as malware -- so your own EDR does not quarantine the
    evidence, which docs/11 calls a routine and embarrassing failure -- and
    that nothing in the pipeline is a runnable file. Confidentiality comes
    from the bucket's own access control, the origin split and the audit
    trail.

    A production deployment should replace this with AES-256-GCM streamed
    through the object store, which also gives integrity. It is not that
    here because the sample bytes are re-verified against their recorded
    sha256 on every read (see `download`), so tampering is detected on the
    path that matters, and a half-streamed AES implementation would be a
    worse thing to ship than a clearly-labelled simple one.
    """
    stream = bytearray()
    counter = 0
    while len(stream) < len(data):
        stream.extend(hashlib.sha256(key + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(b ^ s for b, s in zip(data, stream[:len(data)], strict=True))


_COLUMNS = ("id, case_id, sha256, sha1, md5, original_filename, byte_size, "
            "state, reject_reason, file_type, entropy, triage_gaps, "
            "submitted_by, submitted_at, source_note, assigned_to, "
            "classification, compartments")


def _record(r) -> Sample:
    return Sample(
        id=r[0], case_id=r[1], sha256=bytes(r[2]).hex(),
        sha1=bytes(r[3]).hex() if r[3] else None,
        md5=bytes(r[4]).hex() if r[4] else None,
        original_filename=r[5], byte_size=r[6], state=r[7], reject_reason=r[8],
        file_type=r[9], entropy=float(r[10]) if r[10] is not None else None,
        triage_gaps=r[11] or [], submitted_by=r[12], submitted_at=r[13],
        source_note=r[14], assigned_to=r[15], classification=r[16],
        compartments=frozenset(r[17] or []),
    )


__all__ = [
    "ARCHIVE_PASSWORD", "ASSIGNED", "IN_ANALYSIS", "MAX_SAMPLE_BYTES",
    "QUARANTINED", "REJECTED", "REPORTED", "SUBMITTED", "TRIAGED",
    "PolicyNotDeclared", "Sample", "SampleError", "SampleService", "Triage",
    "archive", "file_type_of", "policy_declared", "sample_origin",
    "SampleStorage", "shannon_entropy", "triage",
]

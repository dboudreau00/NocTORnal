"""Evidence endpoints: upload (WORM), download, integrity check, custody
log, and linking to graph elements.

Element-level authorization: an exhibit may be classified more restrictively
than its case, so these handlers gate on the EVIDENCE row's own
classification/compartments via authorize_object — one complete five-part
decision against the right object.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, File, Form, Query, Request, Response, UploadFile
from pydantic import BaseModel

from noctornal_api import evidence as _evidence
from noctornal_api.config import EVIDENCE_CAP_ENV, cap_is_declared, declared_cap
from noctornal_api.deception import defang_text
from noctornal_api.evidence import (
    DEFAULT_RETENTION,
    EvidenceService,
    EvidenceStorage,
    NotProducible,
    ProductionRefused,
    lock_short_before,
    lock_target,
)
from noctornal_api.db import SystemPurpose, bind_ticket, system_connection
from noctornal_api.http.deps import (
    CurrentUser,
    audit_auth_event,
    authorize_object,
    check_writable_labels,
    counted_at_case_gate,
    current_user,
    effective_labels,
    element_labels,
    get_conn,
    require,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import BodyCappedRoute, body_cap, rate_limit
# The Lab's own door policy for the sample origin, shared by the exhibit
# production so that origin keeps one: the address meter, the peer hash
# and the ticket body's bound (x-hostile-export, 2026-09-24).
from noctornal_api.http.routers.samples import (
    _TICKET_BODY_CAP,
    _ip_hash,
    _meter_download,
)
from noctornal_api.samples import SampleError, origin_split
from noctornal_api.security.access import (
    CHECK_STEP_UP,
    AccessResolutionError,
    evaluate,
)
from noctornal_api.stores import PgAccessResolver
from noctornal_api.wording import count_of

# `route_class=BodyCappedRoute` is what makes the `@body_cap` marker on
# `upload` do anything: the class wraps the ASGI receive that FastAPI's
# multipart parser reads through, and only for endpoints that carry the
# marker. Every other route on this router is untouched by it.
router = APIRouter(prefix="/cases/{case_id}/evidence", tags=["evidence"],
                   route_class=BodyCappedRoute)

#: Declared by NOCTORNAL_MAX_EVIDENCE_BYTES (`config.declared_cap`), 256 MiB
#: when a development deployment leaves it unset; a production boot refuses
#: without the declaration (docs/08, "Exhibit size policy"), because the
#: number is a decision about a permanent commitment and a module constant
#: -- which this was until 2026-09-11 -- is a decision nobody in the
#: deployment took. The same shape as `samples.MAX_SAMPLE_BYTES`. It bounds
#: two things at once. Storage, because every exhibit
#: is written under a COMPLIANCE object lock that no credential can
#: shorten, so an accepted byte is a byte kept for the whole retention
#: period whatever anyone later decides. Memory, because `EvidenceService.
#: ingest` holds the exhibit as one `bytes` and then reads it back whole
#: to verify the store, so one request costs the process roughly twice
#: the upload. There was NO cap here until 2026-09-09.
MAX_EVIDENCE_BYTES = declared_cap(EVIDENCE_CAP_ENV)


def _svc(conn: psycopg.Connection) -> EvidenceService:
    return EvidenceService(conn, EvidenceStorage())


def _authorize_exhibit(
    conn: psycopg.Connection, user: CurrentUser, case_id: UUID,
    evidence_id: UUID, permission_key: str,
) -> None:
    """Authorize an exhibit, deciding access BEFORE revealing existence.

    A caller who fails the case-level gate gets the same 403 whether or not
    the exhibit id is real, so status codes are not an existence oracle for
    someone whose assignment has expired but who still knows old ids. Only
    once the case check passes does a missing row become a 404, and the
    element's own labels then apply on top (authorize_object unions the
    case's compartments and takes the stricter classification).
    """
    authorize_object(conn, user, case_id=case_id, permission_key=permission_key)
    # The element's case and labels as facts (`deps.element_labels`,
    # S1 2026-09-25), so the gate below still answers an element above the
    # caller's labels with its 403 and AUTHZ_DENIED row, not a silent 404 from
    # row-level security. Content is read only after the gate.
    facts = element_labels(conn, "evidence", evidence_id)
    if facts is None or facts[0] != case_id:
        raise Problem(404, "Not found", "evidence does not exist in this case")
    row = (facts[1], facts[2])
    # The second gate: one open is one use of a break-glass grant, not one
    # per gate (sec-breakglass-double-count, 2026-09-23).
    authorize_object(conn, user, case_id=case_id, permission_key=permission_key,
                     after_case_gate=True,
                     classification=row[0], compartments=frozenset(row[1] or []))


#: What a stale sign-in is told when it is the ONLY thing between a caller
#: and an export: the words `routers/reports.py` uses for the same gate, so
#: the console recognises one sentence for both.
STEP_UP_DETAIL = ("re-authenticate with your second factor before "
                  "performing this operation")


def _authorize_export(conn: psycopg.Connection, user: CurrentUser,
                      case_id: UUID, evidence_id: UUID) -> None:
    """`_authorize_exhibit(..., "evidence.export")`, except that a sign-in
    which is the only thing missing is told so.

    `evidence.export` is a step-up permission, and `authorize_object`
    answers a stale sign-in with "missing permission evidence.export on
    this case", so a Lead investigator who holds it would read that they
    do not (ux07-evidence:no-exhibit-export-control, 2026-09-23, the
    report's C15 again). The same shape as `reports._require_export`: one
    five-part decision, reworded only when step-up freshness is the sole
    failed check, which only a caller assigned to the case can reach.
    Case first and exhibit second, as `_authorize_exhibit` orders them, so
    a missing row is a 404 only to a caller the case gate has passed.

    One export is one break-glass use, as one open is in
    `_authorize_exhibit`: the exhibit's gate counts only when the case's
    did not (`counted_at_case_gate`). Until this, each export on a case
    above the caller's clearance wrote two BREAK_GLASS_ACTION rows and
    read as two on the officer's card (r2 c4, 2026-09-24)."""
    def gate(classification=None, compartments=frozenset(), *,
             count_use: bool = True) -> None:
        eff_cls, eff_comp = effective_labels(conn, case_id, classification,
                                             compartments)
        decision = evaluate(PgAccessResolver(conn).resolve(
            user_id=user.user_id, case_id=case_id,
            permission_key="evidence.export",
            object_classification=eff_cls, object_compartments=eff_comp,
            mfa_satisfied_at=user.session_mfa_at, count_use=count_use))
        if decision.allowed:
            return
        if decision.failed_checks == (CHECK_STEP_UP,):
            # The row `authorize_object` would have written, case included.
            audit_auth_event(conn, "AUTHZ_DENIED", user.user_id, case_id,
                             {"permission": "evidence.export",
                              "failed_checks": list(decision.failed_checks)})
            raise Problem(403, "Forbidden", STEP_UP_DETAIL)
        # Reached only on a refusal, which records no use; the flag rides
        # along so this call can never be the one that counts twice.
        authorize_object(conn, user, case_id=case_id,
                         permission_key="evidence.export", count_use=count_use,
                         classification=classification, compartments=compartments)

    gate()
    # The element's case and labels as facts (`deps.element_labels`,
    # S1 2026-09-25), so the gate below still answers an element above the
    # caller's labels with its 403 and AUTHZ_DENIED row, not a silent 404 from
    # row-level security. Content is read only after the gate.
    facts = element_labels(conn, "evidence", evidence_id)
    if facts is None or facts[0] != case_id:
        raise Problem(404, "Not found", "evidence does not exist in this case")
    row = (facts[1], facts[2])
    gate(row[0], frozenset(row[1] or []),
         count_use=not counted_at_case_gate(conn, user, case_id))


#: Why a hostile exhibit's bytes are refused here, in the words the
#: console shows beside the exhibit. It named "the unit's exhibit
#: procedure" as the way out until 2026-09-24, because nothing in the
#: product could produce these bytes (x-hostile-export); the card's
#: production control now does, from the sample origin.
HOSTILE_DETAIL = (
    "this exhibit is attacker-authored markup (an email, a captured page or "
    "a HAR), and its bytes are never served from the application origin. "
    "Produce it from its card instead: the separate sample origin serves it "
    "in a password-protected archive and writes the EXPORTED custody entry.")


class IngestOut(BaseModel):
    evidence_id: str
    sha256: str
    deduplicated: bool


#: Bounds on the typed provenance fields: room for a paragraph of
#: description or a long URL, small enough that a custody row stays a row.
_DESCRIPTION_MAX = 4000
_SOURCE_MAX = 2000
_AUTHORITY_MAX = 200
#: How far ahead of this server's clock a stated acquisition time may run
#: (a workstation clock a little fast) before it is refused as the future.
_CLOCK_SKEW = timedelta(minutes=5)


def _provenance(method: str, description: str | None, source_url: str | None,
                acquired_at: str | None, authority_ref: str | None,
                *, now: datetime | None = None) -> dict:
    """The upload form's provenance fields, checked and normalised.

    Blank means not given. A time with no offset is UTC, the zone every
    time in the console is shown and entered in. Raises the 400 the form
    shows beside itself."""
    def text(value: str | None, limit: int, name: str) -> str | None:
        value = (value or "").strip()
        if len(value) > limit:
            raise Problem(400, "Invalid request",
                          f"{name} is longer than {limit} characters")
        return value or None

    out: dict = {
        "description": text(description, _DESCRIPTION_MAX, "the description"),
        "source_url": text(source_url, _SOURCE_MAX, "the source"),
        "authority_ref": text(authority_ref, _AUTHORITY_MAX,
                              "the authority reference"),
        "acquired_at": None,
    }
    raw = (acquired_at or "").strip()
    if raw:
        try:
            when = datetime.fromisoformat(raw)
        except ValueError:
            raise Problem(400, "Invalid request",
                          f"acquired_at {raw!r} is not a date and time. Give "
                          "it as ISO 8601 in UTC, for example "
                          "2026-09-17T15:18:00Z.") from None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        if when > current + _CLOCK_SKEW:
            raise Problem(400, "Invalid request",
                          "acquired_at is in the future. It is when the "
                          "material was obtained, in UTC; leave it out for "
                          "material obtained just now.")
        out["acquired_at"] = when
    if method == "LEGAL" and not out["authority_ref"]:
        raise Problem(400, "Invalid request",
                      "a legal process acquisition needs its authority "
                      "reference: the warrant, production order or other "
                      "instrument the material was obtained under.")
    return out


# Every ingest writes to object-locked WORM storage. Those bytes cannot be
# deleted before their retention expires, so an upload loop is a permanent
# storage commitment nobody can undo — a limit here is about cost that
# cannot be reclaimed, not about CPU.
@router.post("", response_model=IngestOut, status_code=201,
             dependencies=[Depends(rate_limit("evidence.ingest"))])
@body_cap(lambda: MAX_EVIDENCE_BYTES, what="an evidence upload")
async def upload(
    case_id: UUID,
    file: UploadFile = File(...),
    title: str = Form(...),
    acquisition_method: str = Form("MANUAL_UPLOAD"),
    classification: str = Form("AMBER"),
    description: str | None = Form(None),
    source_url: str | None = Form(None),
    acquired_at: str | None = Form(None),
    authority_ref: str | None = Form(None),
    user: CurrentUser = Depends(require("evidence.upload")),
    conn: psycopg.Connection = Depends(get_conn),
) -> IngestOut:
    """Lodge an exhibit. The request body is capped at `MAX_EVIDENCE_BYTES`.

    The cap is on the multipart BODY, of which the file is the bulk, and it
    is enforced by `BodyCappedRoute` on the bytes as they arrive: a body
    whose declared length exceeds the cap is refused before a byte of it is
    read, and a chunked body is refused on the chunk that crosses the cap.
    The 413 carries the cap in its message. Nothing below this line runs
    for a refused upload, so nothing is written to the bucket or the
    evidence table.

    Until 2026-09-09 there was no cap. `await file.read()` accumulated
    whatever arrived, the service put it in the bucket under a COMPLIANCE
    object lock, and only then was anything about its size recorded. A
    caller could hand the API gigabytes, the "refusal" never came, and the
    object was locked under a retention that no credential can shorten.
    The cap has to be enforced before the parser buffers the upload, which
    is why it lives in the route class rather than in this function --
    FastAPI parses the form before the handler or any dependency runs.

    Provenance (ux07-evidence:upload-drops-provenance, 2026-09-23):
    `acquired_at` is when the material was obtained, ISO 8601, read as UTC
    when it carries no offset; left out, it is the moment of receipt.
    `authority_ref` is REQUIRED for a legal-process acquisition, because a
    seizure recorded without the instrument it rests on is the gap a
    custody challenge lands in. Both are checked before a byte is stored.
    """
    provenance = _provenance(acquisition_method, description, source_url,
                             acquired_at, authority_ref)
    data = await file.read()
    if not data:
        raise Problem(400, "Invalid request", "empty upload")
    check_writable_labels(conn, user, classification=classification)
    res = _svc(conn).ingest(
        case_id=case_id, title=title,
        media_type=file.content_type or "application/octet-stream",
        data=data, acquired_by=user.user_id,
        acquisition_method=acquisition_method, classification=classification,
        **provenance,
    )
    return IngestOut(evidence_id=str(res.evidence_id), sha256=res.sha256_hex,
                     deduplicated=res.deduplicated)


@router.get("/policy", response_model=dict)
def size_policy(case_id: UUID,
                user: CurrentUser = Depends(current_user)) -> dict:
    """What this deployment accepts as one exhibit, so the console can say
    so BEFORE the analyst picks a file rather than after a 413.

    The case in the path is not consulted: the cap is the deployment's,
    not the case's, and knowing it discloses nothing about any case. Any
    signed-in account may read it, which is why `current_user` and not the
    case gate. `max_bytes` is the value `upload` enforces on THIS process
    -- the same module constant -- so the two cannot disagree.
    """
    return {
        "max_bytes": MAX_EVIDENCE_BYTES,
        "declared": cap_is_declared(EVIDENCE_CAP_ENV),
        # The storage lock's length (ux07-evidence:worm-chip-outlives-lock,
        # 2026-09-23): the pane said "locked for the retention period" and
        # never which one. Counted from LODGING, the server's receipt: this
        # said "from acquisition" while the same pass made "acquired" the
        # time the uploader states, so an exhibit obtained twelve days before
        # it was lodged read as locked twelve days short (verifier,
        # 2026-09-23). Since 2026-09-24 (x-lock-extension) that is the
        # SHORTEST lock: it runs to the case's retention date when that is
        # later, at lodging and whenever the date is extended, but never
        # more than `lock_horizon_days` ahead in one step. The flag said
        # True while only an extension moved a lock, and the flagship
        # exhibit was locked a year short of its case (verifier): an
        # exhibit whose lock still ends first now says so on its own
        # (`lock_short_of_case`), and the pane offers to lengthen it.
        "lock_days": DEFAULT_RETENTION.days,
        "lock_follows_case_retention": True,
        # Read from the module when asked, as `lock_target` reads it, so
        # the policy states the horizon the locks are actually set by.
        "lock_horizon_days": _evidence.LOCK_HORIZON.days,
        "notice": (
            "Every accepted byte is written once under an object lock that "
            "runs to the case's retention date, and for at least "
            f"{count_of(DEFAULT_RETENTION.days, 'day', 'days')} from the "
            "moment it is lodged. Extending the date lengthens it, up to "
            f"{count_of(_evidence.LOCK_HORIZON.days, 'day', 'days')} ahead at a time, "
            "and nobody can shorten it. Above the cap there is no partial path: "
            "do not split an exhibit, because the digest of the whole is "
            "what custody attests; either the deployment raises its declared "
            "cap or the object is held under the unit's exhibit procedure "
            "with its hash recorded as a case note."),
    }


# --- the exhibit register -------------------------------------------------
#
# ux07-evidence, 2026-09-23. The pane read `GET /evidence-list?limit=200`,
# which carries the title, a size, a flag and a time, and nothing else, so
# five findings could not be fixed in the console alone: the WORM lock's
# date (worm-chip-outlives-lock), what an exhibit backs (no-forward-trace-
# from-exhibit), when and under what authority it was obtained against when
# it was lodged (upload-drops-provenance), the last verification (verify-
# writes-custody-silently) and how many exhibits there are at all
# (evidence-list-silently-capped: the newest 200 were kept without a word).
# The register below answers all five, one page at a time with the total,
# under the reader's own ceiling, as `/evidence-list` filters.
#
# "Backs" is the projection's rule read backwards (`projections.
# evidenced_sql`): an exhibit backs an element when a live (unretracted)
# assertion carries it or an evidence_link attaches it, and the element is
# one the canvas would draw for this reader: in the case, not deleted, not
# merged away, holding live provenance, within the reader's clearance and
# compartments, and for a tie, both ends so too; and the exhibit itself is
# not purged. Counting the same way is what makes "backs nothing" agree
# with the hollow marks on the canvas.

def _live_node(alias: str) -> str:
    """The projection's node predicate, for `alias`, with named binds."""
    return f"""{alias}.case_id = %(case)s AND {alias}.deleted_at IS NULL
               AND {alias}.merged_into_id IS NULL
               AND {alias}.classification <= %(clr)s::core.tlp
               AND {alias}.compartments <@ %(comp)s
               AND EXISTS (SELECT 1 FROM core.assertion la
                            WHERE la.node_id = {alias}.id
                              AND la.retracted_at IS NULL
                              AND la.superseded_at IS NULL)"""


def _live_edge(alias: str) -> str:
    """The projection's edge predicate: its own labels and provenance, and
    both ends drawable."""
    return f"""{alias}.case_id = %(case)s AND {alias}.deleted_at IS NULL
               AND {alias}.classification <= %(clr)s::core.tlp
               AND {alias}.compartments <@ %(comp)s
               AND EXISTS (SELECT 1 FROM core.assertion le
                            WHERE le.edge_id = {alias}.id
                              AND le.retracted_at IS NULL
                              AND le.superseded_at IS NULL)
               AND EXISTS (SELECT 1 FROM core.node es
                            WHERE es.id = {alias}.src_node_id AND {_live_node('es')})
               AND EXISTS (SELECT 1 FROM core.node ed
                            WHERE ed.id = {alias}.dst_node_id AND {_live_node('ed')})"""


def _attached(column: str, ev: str) -> str:
    """Ids in `column` ('node_id' or 'edge_id') that exhibit `ev` is
    attached to by a link or a live assertion, while `ev` is unpurged.
    Both are literals from this module, never client input.

    The purge leg is the projection's (`evidenced_sql`: `bx.purged_at IS
    NULL`, "an element cannot rest on bytes the record says are gone").
    Without it a purged exhibit's card said "Backs 1 entity" while the
    canvas drew that entity hollow, and the exhibit was missing from the
    "backs nothing" count and filter (ux07-evidence:no-forward-trace-from-
    exhibit, verifier, 2026-09-23)."""
    assert column in ("node_id", "edge_id")
    unpurged = f"""EXISTS (SELECT 1 FROM core.evidence bx
                            WHERE bx.id = {ev} AND bx.purged_at IS NULL)"""
    return f"""SELECT bl.{column} FROM core.evidence_link bl
                WHERE bl.evidence_id = {ev} AND bl.{column} IS NOT NULL
                  AND {unpurged}
               UNION
               SELECT ba.{column} FROM core.assertion ba
                WHERE ba.evidence_id = {ev} AND ba.{column} IS NOT NULL
                  AND ba.retracted_at IS NULL AND {unpurged}"""


def _backs_counts(ev: str) -> str:
    """Two columns, `backs_nodes` and `backs_edges`, for exhibit `ev`."""
    return f"""(SELECT count(*) FROM core.node bn
                 WHERE bn.id IN ({_attached('node_id', ev)})
                   AND {_live_node('bn')}) AS backs_nodes,
               (SELECT count(*) FROM core.edge bg
                 WHERE bg.id IN ({_attached('edge_id', ev)})
                   AND {_live_edge('bg')}) AS backs_edges"""


def _visible_exhibit(alias: str) -> str:
    return f"""{alias}.case_id = %(case)s
               AND {alias}.classification <= %(clr)s::core.tlp
               AND {alias}.compartments <@ %(comp)s"""


def _like(q: str) -> str:
    """`q` as an ILIKE pattern that matches it literally, anywhere."""
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


class LastCheck(BaseModel):
    """The newest integrity check on the custody record: an explicit
    Verify, or a read that found a mismatch."""
    at: datetime
    ok: bool | None
    by_name: str | None = None


class ExhibitOut(BaseModel):
    id: str
    title: str
    media_type: str
    byte_size: int
    sha256: str
    classification: str
    acquisition_method: str
    #: When the material was obtained. Stated by the uploader, or the
    #: moment of receipt when nobody stated one (`acquired_at_stated`).
    acquired_at: datetime
    acquired_at_stated: bool
    acquired_by: str
    acquired_by_name: str | None = None
    #: When the server received the bytes (`core.evidence.created_at`).
    lodged_at: datetime
    #: Typed free text as `defang_text` runs, never raw (`custody_detail`).
    description_segments: list[dict] = []
    source_segments: list[dict] = []
    authority_segments: list[dict] = []
    is_worm_locked: bool
    #: The last day of the storage lock (the object's COMPLIANCE retention),
    #: None on a row that never recorded one. Set when the exhibit was
    #: lodged, to the case's retention date when that is later than the
    #: default period, and moved later when the case's retention is
    #: extended past it (x-lock-extension, 2026-09-24).
    lock_until: date | None = None
    #: The instant the lock ends, from the newest custody row that set it:
    #: ACQUIRED, or LOCK_EXTENDED once the case's retention lengthened it.
    #: None on an exhibit lodged before 2026-09-23 and never extended, whose
    #: record carries only the day.
    lock_ends_at: datetime | None = None
    #: True once the lock can no longer be counted on: from `lock_ends_at`,
    #: or, when only the day is known, from the start of that day. The chip
    #: must stop saying the store refuses a delete.
    lock_lapsed: bool = False
    #: True when the lock ends before the case's retention date, so the
    #: store would accept a delete the case still forbids, and lengthening
    #: it would change that (`evidence.lock_short_before`; x-lock-extension,
    #: verifier, 2026-09-24).
    lock_short_of_case: bool = False
    legal_hold: bool = False
    is_hostile_markup: bool = False
    purged_at: datetime | None = None
    backs_nodes: int = 0
    backs_edges: int = 0
    last_check: LastCheck | None = None


class RegisterOut(BaseModel):
    #: Every exhibit in the case this reader may see.
    total: int
    #: Of those, how many back nothing on the live graph.
    backs_nothing: int
    #: How many the filters match; `items` is one page of them.
    matching: int
    offset: int
    limit: int
    items: list[ExhibitOut]
    #: Whether the reader holds `evidence.export` here, asked as if their
    #: sign-in were fresh (the route asks for one when it is not), and the
    #: global `audit.read` the custody-chain verifier needs. For showing
    #: controls only; every route decides for itself.
    may_export: bool = False
    may_audit: bool = False
    #: Of the exhibits this reader may see, how many hold a lock SHORT of
    #: the case (`ExhibitOut.lock_short_of_case`), across every page; the
    #: instant `POST .../locks` would lengthen them to; and whether the
    #: reader holds `case.update`, the verb that route and the retention
    #: date share (x-lock-extension, verifier, 2026-09-24).
    locks_short: int = 0
    lock_target: datetime | None = None
    may_lock: bool = False


#: The register's page size bounds. 50 is what the pane asks for.
REGISTER_MAX = 200


def _asks(conn: psycopg.Connection, user: CurrentUser, case_id: UUID,
          permission_key: str, *, fresh: bool = False) -> bool:
    """The five-part gate as a question, as `search._allowed_on_case`
    asks it (`count_use=False`: a question is not an access). `fresh`
    asks as if the sign-in were recent, so a step-up verb's control is
    offered and the route then asks for the sign-in itself."""
    try:
        eff_cls, eff_comp = effective_labels(conn, case_id)
        ctx = PgAccessResolver(conn).resolve(
            user_id=user.user_id, case_id=case_id, permission_key=permission_key,
            object_classification=eff_cls, object_compartments=eff_comp,
            mfa_satisfied_at=(datetime.now(timezone.utc) if fresh
                              else user.session_mfa_at),
            count_use=False)
    except AccessResolutionError:
        return False
    return evaluate(ctx).allowed


def _holds_audit_read(conn: psycopg.Connection, user: CurrentUser) -> bool:
    return conn.execute(
        """SELECT 1 FROM iam.user_role ur
             JOIN iam.role_permission rp ON rp.role_key = ur.role_key
             JOIN iam.app_user u ON u.id = ur.user_id
            WHERE ur.user_id = %s AND rp.permission_key = 'audit.read'
              AND u.is_active LIMIT 1""",
        (user.user_id,)).fetchone() is not None


def lock_state(lock_until: date | None, acquired_detail: dict,
               now: datetime) -> tuple[datetime | None, bool]:
    """(the instant the storage lock ends, whether it can no longer be
    counted on), from the day on the row and the ACQUIRED custody detail.

    The store's COMPLIANCE lock ends at the lodging instant plus the lock
    period, part way through the day `retention_until` keeps. This read
    "lapsed" only once that day had passed and the chip said the store
    refused "until the end of" it, which overstated the lock by up to 24
    hours (ux07-evidence:worm-chip-outlives-lock, verifier, 2026-09-23).
    Since then `ingest` records the instant; an exhibit lodged before it
    carries only the day, and its lock is not counted on from the START of
    that day, so the console never claims a lock the store may already
    have released."""
    if lock_until is None:
        return None, False
    ends_at = None
    raw = acquired_detail.get("lock_ends_at")
    if isinstance(raw, str):
        try:
            ends_at = datetime.fromisoformat(raw)
        except ValueError:
            ends_at = None
        if ends_at is not None and ends_at.tzinfo is None:
            ends_at = ends_at.replace(tzinfo=timezone.utc)
        if ends_at is not None and ends_at.astimezone(timezone.utc).date() != lock_until:
            ends_at = None              # not this lock's instant: trust the day
    if ends_at is not None:
        return ends_at, now >= ends_at
    return None, now.astimezone(timezone.utc).date() >= lock_until


def lock_is_short(lock_until: date | None, ends_at: datetime | None,
                  short_before: datetime | None) -> bool:
    """Whether a live, locked exhibit's lock ends before `short_before`
    (`evidence.lock_short_before`), from what `lock_state` read. A record
    that carries only the day is taken to end at the START of it, the
    reading the chip counts on; one with no day at all holds no lock
    anybody can count on, so it is short whenever anything is."""
    if short_before is None:
        return False
    if ends_at is None:
        if lock_until is None:
            return True
        ends_at = datetime.combine(lock_until, datetime.min.time(),
                                   tzinfo=timezone.utc)
    return ends_at < short_before


def case_lock_bounds(conn: psycopg.Connection, case_id: UUID,
                     now: datetime) -> tuple[datetime | None, datetime | None]:
    """(`lock_short_before`, the instant a lengthened lock would reach) for
    the case, or (None, None) when nothing can be lengthened: the case is
    due, or PURGED, whose exhibits are being destroyed and must not have
    their locks moved out of the purge's way."""
    row = conn.execute(
        'SELECT retention_until, status FROM core."case" WHERE id = %s',
        (case_id,)).fetchone()
    if row is None or row[1] == "PURGED":
        return None, None
    short_before = lock_short_before(row[0], now)
    if short_before is None:
        return None, None
    return short_before, lock_target(row[0], now)[0]


#: The newest lock end per exhibit: the ACQUIRED row's, or a later
#: LOCK_EXTENDED row's once the case's retention lengthened it
#: (x-lock-extension, 2026-09-24). The register, its count of short locks
#: and the inspector's list all read it from here, so they cannot disagree.
NEWEST_LOCK_SQL = """LEFT JOIN LATERAL (
                   SELECT c.detail ->> 'lock_ends_at' AS lock_ends_at
                     FROM core.evidence_custody c
                    WHERE c.evidence_id = {ev}.id
                      AND c.action IN ('ACQUIRED', 'LOCK_EXTENDED')
                      AND c.detail ? 'lock_ends_at'
                    ORDER BY c.occurred_at DESC, c.id DESC LIMIT 1) lk ON true"""


def _count_short_locks(conn: psycopg.Connection, binds: dict,
                       short_before: datetime | None, now: datetime) -> int:
    """How many live, locked exhibits the reader may see hold a lock short
    of the case, over the whole case rather than one page. Each is read by
    `lock_state` and `lock_is_short`, the rules the page's own items use."""
    if short_before is None:
        return 0
    rows = conn.execute(
        f"""SELECT e.retention_until, lk.lock_ends_at
              FROM core.evidence e
              {NEWEST_LOCK_SQL.format(ev='e')}
             WHERE {_visible_exhibit('e')}
               AND e.purged_at IS NULL AND e.is_worm_locked""", binds).fetchall()
    short = 0
    for lock_until, raw in rows:
        ends_at, _ = lock_state(lock_until, {"lock_ends_at": raw}, now)
        short += lock_is_short(lock_until, ends_at, short_before)
    return short


#: How far before its lodging an exhibit's recorded acquisition time must
#: sit, on a row with no `acquired_at_stated` flag, to be read as stated.
#: Five minutes, the upload's own allowance for clock skew (`_provenance`).
LEGACY_STATED_MARGIN = timedelta(minutes=5)


def time_was_stated(acquired_detail: dict, acquired_at: datetime,
                    lodged_at: datetime) -> bool:
    """Whether the exhibit's acquisition time is one somebody stated,
    rather than the moment the server received the bytes.

    The ACQUIRED custody row says so for every exhibit lodged since
    2026-09-23. An earlier row has no flag, and reading its absence as
    "not stated" made exhibits ingested with a real, earlier acquisition
    time (the README showcase seeds them thirty days back) read "acquired
    at lodging, no earlier time stated" in warning style, hiding the time
    the record does hold (ux07-evidence:upload-drops-provenance, verifier,
    2026-09-23). Without the flag, a time more than the skew margin before
    the lodging was stated; a default one sits on the lodging instant."""
    flag = acquired_detail.get("acquired_at_stated")
    if isinstance(flag, bool):
        return flag
    if acquired_at is None or lodged_at is None:
        return False
    return lodged_at - acquired_at > LEGACY_STATED_MARGIN


def exhibit_register(conn: psycopg.Connection, *, case_id: UUID, clearance: str,
                     compartments: list[str], offset: int = 0, limit: int = 50,
                     q: str | None = None, backs_nothing: bool = False,
                     evidence_id: UUID | None = None,
                     now: datetime | None = None) -> dict:
    """One page of the register, with the totals the pane states. Public
    so a test can call it without a request."""
    binds = {"case": case_id, "clr": clearance, "comp": list(compartments),
             "q": _like(q) if q else None, "id": evidence_id,
             "nothing": backs_nothing, "off": offset, "lim": limit}
    reg = f"""SELECT e.*, {_backs_counts('e.id')}
                FROM core.evidence e WHERE {_visible_exhibit('e')}"""
    totals = conn.execute(
        f"""SELECT count(*),
                   count(*) FILTER (WHERE r.backs_nodes + r.backs_edges = 0)
              FROM ({reg}) r""", binds).fetchone()
    where = """(%(q)s::text IS NULL OR r.title ILIKE %(q)s
                 OR coalesce(r.description, '') ILIKE %(q)s)
               AND (%(id)s::uuid IS NULL OR r.id = %(id)s)
               AND (NOT %(nothing)s OR r.backs_nodes + r.backs_edges = 0)"""
    matching = conn.execute(
        f"SELECT count(*) FROM ({reg}) r WHERE {where}", binds).fetchone()[0]
    rows = conn.execute(
        f"""SELECT r.id, r.title, r.media_type, r.byte_size, r.sha256,
                   r.classification, r.acquisition_method, r.acquired_at,
                   r.acquired_by, au.display_name, r.created_at,
                   r.description, r.source_url, r.is_worm_locked,
                   r.retention_until, r.legal_hold, r.is_hostile_markup,
                   r.purged_at, r.backs_nodes, r.backs_edges,
                   acq.detail, chk.occurred_at, chk.hash_verified,
                   cu.display_name, lk.lock_ends_at
              FROM ({reg}) r
              LEFT JOIN iam.app_user au ON au.id = r.acquired_by
              LEFT JOIN LATERAL (
                   SELECT c.detail FROM core.evidence_custody c
                    WHERE c.evidence_id = r.id AND c.action = 'ACQUIRED'
                    ORDER BY c.occurred_at, c.id LIMIT 1) acq ON true
              {NEWEST_LOCK_SQL.format(ev='r')}
              LEFT JOIN LATERAL (
                   SELECT c.occurred_at, c.hash_verified, c.actor_id
                     FROM core.evidence_custody c
                    WHERE c.evidence_id = r.id AND c.action = 'HASH_VERIFIED'
                    ORDER BY c.occurred_at DESC, c.id DESC LIMIT 1) chk ON true
              LEFT JOIN iam.app_user cu ON cu.id = chk.actor_id
             WHERE {where}
             ORDER BY r.acquired_at DESC, r.id
             OFFSET %(off)s LIMIT %(lim)s""", binds).fetchall()
    at = now or datetime.now(timezone.utc)
    short_before, target = case_lock_bounds(conn, case_id, at)
    items = []
    for r in rows:
        detail = r[20] or {}
        lock_until = r[14]
        ends_at, lapsed = lock_state(lock_until, {"lock_ends_at": r[24]}, at)
        live_lock = r[13] and r[17] is None
        items.append(ExhibitOut(
            id=str(r[0]), title=r[1], media_type=r[2], byte_size=r[3],
            sha256=bytes(r[4]).hex(), classification=r[5],
            acquisition_method=r[6], acquired_at=r[7],
            acquired_at_stated=time_was_stated(detail, r[7], r[10]),
            acquired_by=str(r[8]), acquired_by_name=r[9], lodged_at=r[10],
            description_segments=defang_text(r[11]),
            source_segments=defang_text(r[12]),
            authority_segments=defang_text(detail.get("authority_ref")),
            is_worm_locked=r[13], lock_until=lock_until,
            lock_ends_at=ends_at, lock_lapsed=lapsed,
            lock_short_of_case=bool(live_lock) and lock_is_short(
                lock_until, ends_at, short_before),
            legal_hold=r[15], is_hostile_markup=r[16], purged_at=r[17],
            backs_nodes=r[18], backs_edges=r[19],
            last_check=(LastCheck(at=r[21], ok=r[22], by_name=r[23])
                        if r[21] is not None else None),
        ))
    locks_short = _count_short_locks(conn, binds, short_before, at)
    return {"total": totals[0], "backs_nothing": totals[1],
            "matching": matching, "offset": offset, "limit": limit,
            "items": items, "locks_short": locks_short,
            "lock_target": target if locks_short else None}


@router.get("", response_model=RegisterOut)
def register(
    case_id: UUID,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=REGISTER_MAX),
    q: str | None = Query(None, max_length=200),
    backs_nothing: bool = Query(False),
    evidence_id: UUID | None = Query(None),
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> RegisterOut:
    """The case's exhibits, a page at a time, with how many there are.

    `q` matches the title or description, `backs_nothing` keeps the
    exhibits nothing on the live graph rests on, and `evidence_id` asks for
    one exhibit (the pane's "show this one" from search or an assertion
    card). Filtered by the reader's own clearance and compartments, as the
    list it replaces was."""
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    page = exhibit_register(
        conn, case_id=case_id, clearance=clearance.name,
        compartments=list(compartments), offset=offset, limit=limit,
        q=(q or "").strip() or None, backs_nothing=backs_nothing,
        evidence_id=evidence_id)
    return RegisterOut(**page,
                       may_export=_asks(conn, user, case_id, "evidence.export",
                                        fresh=True),
                       may_audit=_holds_audit_read(conn, user),
                       may_lock=(bool(page["locks_short"])
                                 and _asks(conn, user, case_id, "case.update")))


class LockExtensionOut(BaseModel):
    """What lengthening did, counted over the exhibits the caller may see
    (`EvidenceService.extend_locks`); every live exhibit was asked."""
    #: Where the locks now end, and whether the horizon stopped them short
    #: of the case's retention date.
    lock_ends_at: datetime
    capped: bool
    exhibits: int
    extended: int
    already_held: int
    failed: int
    date_passed: bool


@router.post("/locks", response_model=LockExtensionOut,
             dependencies=[Depends(rate_limit("request"))])
def lengthen_locks(
    case_id: UUID,
    user: CurrentUser = Depends(require("case.update")),
    conn: psycopg.Connection = Depends(get_conn),
) -> LockExtensionOut:
    """Lengthen every live exhibit's storage lock to the case's retention
    date as it stands, as extending that date would.

    x-lock-extension, verifier, 2026-09-24. A lock followed the case only
    when the date was EXTENDED, so an exhibit lodged into a case already
    retained past its lock stayed deletable at the store for the rest of
    the case's retention, and the console could not fix it: the case
    record refuses to save a date that has not changed. This is that fix,
    offered by the Evidence pane when its register counts a lock short of
    the case. `case.update`, the verb that moves the date, because it
    commits the same thing; governance, so it stays open on a CLOSED or
    ARCHIVED case. Refused on a PURGED case, whose exhibits are being
    destroyed: a lock moved now would stand in the purge's way."""
    row = conn.execute(
        'SELECT retention_until, status FROM core."case" WHERE id = %s',
        (case_id,)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "case does not exist")
    if row[1] == "PURGED":
        raise Problem(409, "Conflict",
                      "this case is marked for destruction, so its exhibits' "
                      "storage locks are not lengthened")
    from noctornal_api.http.routers.cases import _extend_exhibit_locks
    from psycopg.types.json import Json
    report = _extend_exhibit_locks(conn, case_id, row[0], user.user_id)
    # One row for the act itself: each lengthened exhibit has its own, but
    # a press that found every lock already long enough would otherwise
    # leave no trace that it was asked for (invariant 12).
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
           VALUES (%s, 'USER', 'CASE_EXHIBIT_LOCKS_LENGTHENED', 'case', %s, %s, %s)""",
        (user.user_id, case_id, case_id, Json(report)))
    return LockExtensionOut(**report)


class IndexItem(BaseModel):
    id: str
    title: str
    media_type: str


class IndexOut(BaseModel):
    total: int
    items: list[IndexItem]


#: The most exhibits one index answer carries. The pickers are built from
#: it and say so when a case holds more.
INDEX_MAX = 5000


@router.get("/index", response_model=IndexOut)
def index(
    case_id: UUID,
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> IndexOut:
    """Every exhibit's id, title and type, for the attach pickers.

    ux07-evidence:evidence-list-silently-capped (2026-09-23). The pickers
    were built from the pane's list, the newest 200, so an early exhibit
    (often the original seizure) dropped out of every "Supporting exhibit"
    picker without a word. They now read this, which carries every exhibit
    the reader may see up to `INDEX_MAX` and the total, so a picker that
    cannot list them all says so."""
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    binds = {"case": case_id, "clr": clearance.name, "comp": list(compartments)}
    total = conn.execute(
        f"SELECT count(*) FROM core.evidence e WHERE {_visible_exhibit('e')}",
        binds).fetchone()[0]
    rows = conn.execute(
        f"""SELECT e.id, e.title, e.media_type FROM core.evidence e
             WHERE {_visible_exhibit('e')}
             ORDER BY e.acquired_at DESC, e.id LIMIT {INDEX_MAX}""",
        binds).fetchall()
    return IndexOut(total=total, items=[
        IndexItem(id=str(r[0]), title=r[1], media_type=r[2]) for r in rows])


class BackedOut(BaseModel):
    """One element an exhibit backs, and by which route."""
    kind: str                  # 'node' | 'edge'
    id: str
    label: str
    node_type: str | None = None
    edge_type: str | None = None
    src_id: str | None = None
    src_label: str | None = None
    dst_id: str | None = None
    dst_label: str | None = None
    #: 'ASSERTION' (a live claim carries it) and/or 'LINK' (attached).
    via: list[str]


class BacksOut(BaseModel):
    nodes: int
    edges: int
    items: list[BackedOut]
    #: True when `items` stops short of `nodes + edges`.
    truncated: bool


#: The most elements one answer names. The counts are always whole.
BACKS_MAX = 500


@router.get("/{evidence_id}/backs", response_model=BacksOut)
def backs(
    case_id: UUID, evidence_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> BacksOut:
    """What rests on this exhibit: the entities and relationships it
    backs, under the rule the register counts by, each one the console
    opens in the inspector (ux07-evidence:no-forward-trace-from-exhibit,
    2026-09-23: "what do we lose if it is excluded?" had no answer short
    of opening every node)."""
    _authorize_exhibit(conn, user, case_id, evidence_id, "evidence.read")
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    binds = {"case": case_id, "clr": clearance.name, "comp": list(compartments),
             "ev": evidence_id}
    via = """array_remove(ARRAY[
                 CASE WHEN EXISTS (SELECT 1 FROM core.assertion va
                                    WHERE va.evidence_id = %(ev)s
                                      AND va.{col} = {el}.id
                                      AND va.retracted_at IS NULL)
                      THEN 'ASSERTION' END,
                 CASE WHEN EXISTS (SELECT 1 FROM core.evidence_link vl
                                    WHERE vl.evidence_id = %(ev)s
                                      AND vl.{col} = {el}.id)
                      THEN 'LINK' END], NULL)"""
    nodes = conn.execute(
        f"""SELECT n.id, n.label, n.node_type,
                   {via.format(col='node_id', el='n')}
              FROM core.node n
             WHERE n.id IN ({_attached('node_id', '%(ev)s')})
               AND {_live_node('n')}
             ORDER BY lower(n.label), n.id""", binds).fetchall()
    edges = conn.execute(
        f"""SELECT g.id, g.edge_type, s.id, s.label, d.id, d.label,
                   {via.format(col='edge_id', el='g')}
              FROM core.edge g
              JOIN core.node s ON s.id = g.src_node_id
              JOIN core.node d ON d.id = g.dst_node_id
             WHERE g.id IN ({_attached('edge_id', '%(ev)s')})
               AND {_live_edge('g')}
             ORDER BY lower(s.label), g.edge_type, lower(d.label), g.id""",
        binds).fetchall()
    items = [BackedOut(kind="node", id=str(r[0]), label=r[1], node_type=r[2],
                       via=list(r[3])) for r in nodes]
    items += [BackedOut(kind="edge", id=str(r[0]), label=r[1], edge_type=r[1],
                        src_id=str(r[2]), src_label=r[3], dst_id=str(r[4]),
                        dst_label=r[5], via=list(r[6])) for r in edges]
    return BacksOut(nodes=len(nodes), edges=len(edges), items=items[:BACKS_MAX],
                    truncated=len(items) > BACKS_MAX)


@router.get("/{evidence_id}/content")
def download(
    case_id: UUID, evidence_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    """Serve the exhibit bytes. The service re-verifies the hash and fails
    closed, so a tampered object is never served. Attachment + nosniff;
    docs/11 additionally requires a SEPARATE ORIGIN for sample bytes — that
    origin split is a deployment concern, not enforced here.

    Attacker-authored markup is refused with 409 (docs/19 section 1.1: the
    API origin never serves those bytes), after the gate, so the refusal
    says nothing to a caller who may not see the row. It served them until
    2026-09-23; see `EvidenceService.refuse_if_hostile`."""
    _authorize_exhibit(conn, user, case_id, evidence_id, "evidence.read")
    svc = _svc(conn)
    if svc.refuse_if_hostile(evidence_id, user.user_id, purpose="content"):
        raise Problem(409, "Not served from this origin", HOSTILE_DETAIL)
    data = svc.view(evidence_id, user.user_id)
    return Response(
        content=data, media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{evidence_id}"',
                 "X-Content-Type-Options": "nosniff"},
    )


@router.post("/{evidence_id}/export",
             dependencies=[Depends(rate_limit("evidence.export"))])
def export(
    case_id: UUID, evidence_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    """Export for release outside the platform. evidence.export is a
    step-up permission, so the gate's fifth check demands fresh MFA; the
    service additionally refuses AMBER_STRICT/RED (invariant 8).

    The console's "Export for disclosure" calls this (ux07-evidence:no-
    exhibit-export-control, 2026-09-23; nothing did before). A stale
    sign-in is told so in words the console acts on (`_authorize_export`),
    and attacker-authored markup is refused here as on `/content`."""
    _authorize_export(conn, user, case_id, evidence_id)
    svc = _svc(conn)
    if svc.refuse_if_hostile(evidence_id, user.user_id, purpose="export"):
        raise Problem(409, "Not served from this origin", HOSTILE_DETAIL)
    data = svc.export(evidence_id, user.user_id)
    return Response(
        content=data, media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{evidence_id}"',
                 "X-Content-Type-Options": "nosniff"},
    )


# --- attacker markup, produced through the sample origin -----------------
#
# x-hostile-export, 2026-09-24. docs/19 section 1.1: a DOM, HAR or `.eml`
# exhibit leaves only from the separate sample origin, through the gate a
# Lab download passes. Two legs, the Lab's two (routers/samples.py): a
# ticket minted HERE under the ordinary cookie session, its CSRF
# double-submit and the export gate; then that ticket spent THERE, by a
# request that carries no cookie and no header, because none can cross.

class ProductionTicketOut(BaseModel):
    #: Returned once. The row holds its SHA-256 and nothing else (0061).
    ticket: str
    expires_at: str
    #: Absolute, on the SAMPLE origin, so the console never assembles it
    #: from its own origin, which refuses (routers/samples.py says why).
    download_url: str


def production_url(sample_origin: str, case_id: UUID, evidence_id: UUID) -> str:
    """Where a production ticket is spent: the path `app.py` lets through
    on the sample origin (`_EXHIBIT_DOWNLOAD_PATH`), built from the same
    prefix. Deferred import, as `samples._download_url`'s: app.py imports
    this module."""
    from noctornal_api.http.app import API_PREFIX
    return (f"{sample_origin}{API_PREFIX}/cases/{case_id}/evidence/"
            f"{evidence_id}/download")


@router.post("/{evidence_id}/production-ticket",
             response_model=ProductionTicketOut, status_code=201,
             dependencies=[Depends(rate_limit("evidence.export"))])
def mint_production_ticket(
    case_id: UUID, evidence_id: UUID, request: Request,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> ProductionTicketOut:
    """A one-shot, sixty-second authority to produce ONE exhibit of
    attacker markup from the sample origin.

    The gate is `POST /export`'s, the same function: `evidence.export` on
    the case and on the exhibit's own labels, with a sign-in from the last
    fifteen minutes, told as such when that is all that is missing. Then
    the service refuses a split that cannot serve (409, its reason), an
    exhibit that is not attacker markup or was purged (409), and one the
    egress gate keeps in (400, audited), before a row is written. A POST,
    for the reasons the Lab's mint gives: the CSRF double-submit applies
    only to an unsafe method, and a GET minting a credential is one a
    prefetcher can fire."""
    _authorize_export(conn, user, case_id, evidence_id)
    # No store: minting touches no bytes, and must not fail over bucket
    # credentials it never uses (`samples._ticket_svc`'s reason).
    try:
        # A ticket row binds its holder once spent, so the request role
        # may not write one (0109, S1 2026-09-25): minted on a system
        # connection, after the export gate above.
        with system_connection(SystemPurpose.TICKETS, reuse=conn) as sconn:
            ticket = EvidenceService(sconn, storage=None).issue_production_ticket(
                evidence_id, case_id=case_id, actor_id=user.user_id,
                session_id=user.session_id, ip_hash=_ip_hash(request))
    except NotProducible as exc:
        raise Problem(409, "Not producible", safe_detail(exc)) from exc
    except SampleError as exc:
        # `_mint_split`'s refusals: the origin split is off, wrong, or this
        # process is the sample origin.
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return ProductionTicketOut(
        ticket=ticket.raw, expires_at=ticket.expires_at.isoformat(),
        download_url=production_url(origin_split().sample or "", case_id,
                                    evidence_id))


def _production_presented(request: Request) -> None:
    """Refuse, before a connection opens, what needs no database to refuse.

    On a process that is not the sample origin, with the split's own
    sentence, which names where to go: asked FIRST so a ticket presented
    to the application by mistake is not spent there. Then a request with
    no body, which cannot carry a ticket, as the Lab's
    `_credential_presented` refuses one. No session is read on this path
    at all, a cookie or a bearer included: the ticket is the credential."""
    split = origin_split()
    if not split.serves_here:
        raise Problem(409, "Not served from this origin", split.refusal or "")
    if request.headers.get("transfer-encoding"):
        return
    if (request.headers.get("content-length") or "0") != "0":
        return
    raise Problem(401, "Unauthenticated", "no production ticket")


@router.post("/{evidence_id}/download",
             dependencies=[Depends(_meter_download)])
@body_cap(_TICKET_BODY_CAP, what="a production ticket")
def produce(
    case_id: UUID, evidence_id: UUID, request: Request,
    #: In the FORM BODY, never the URL, and form-encoded so the console's
    #: request is a simple cross-origin one (routers/samples.py `download`).
    ticket: str | None = Form(default=None),
    _presented: None = Depends(_production_presented),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    """The exhibit, in the Lab's archive (ZIP, password `infected`),
    served by the sample origin only, on a production ticket only.

    The ticket is spent first, in one statement, and the holder's
    authority re-derived from it (`redeem_production_ticket`); then the
    exhibit's own decision again and the verified bytes
    (`EvidenceService.produce`), which writes the EXPORTED custody row
    naming the ticket. The headers are the Lab download's: an attachment,
    `nosniff`, and a sandboxing CSP, so nothing upstream can turn the
    answer into a page."""
    if not ticket:
        raise Problem(401, "Unauthenticated", "no production ticket")
    try:
        holder, ticket_id = EvidenceService(conn, storage=None).redeem_production_ticket(
            ticket, case_id=case_id, evidence_id=evidence_id,
            ip_hash=_ip_hash(request))
    except ProductionRefused as exc:
        # 401: a spent or expired ticket is an expired credential, and one
        # answer for every reason (the Lab's rule).
        raise Problem(401, "Unauthenticated", safe_detail(exc)) from exc
    # Bound to the spent ticket's holder before the exhibit is read or its
    # custody appended (S1, 2026-09-25). The redemption above ran unbound
    # on purpose.
    bind_ticket(conn, ticket)
    try:
        blob, digest = _svc(conn).produce(
            evidence_id, case_id=case_id, actor_id=holder, ticket_id=ticket_id)
    except NotProducible as exc:
        raise Problem(409, "Not producible", safe_detail(exc)) from exc
    return Response(
        content=blob, media_type="application/octet-stream",
        headers={
            "Content-Disposition":
                f'attachment; filename="exhibit-{digest[:16]}.zip"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "no-store",
            "X-Sample-Archive-Password": "infected",
        },
    )


class VerifyOut(BaseModel):
    ok: bool


@router.post("/{evidence_id}/verify", response_model=VerifyOut)
def verify(
    case_id: UUID, evidence_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> VerifyOut:
    _authorize_exhibit(conn, user, case_id, evidence_id, "evidence.read")
    return VerifyOut(ok=_svc(conn).verify_integrity(evidence_id, user.user_id))


class CustodyOut(BaseModel):
    action: str
    actor_id: str
    occurred_at: datetime
    #: THREE states, and a reader must keep them apart (2026-09-22): True,
    #: the stored bytes matched the recorded digest when this row was
    #: written; False, they did NOT (a HASH_VERIFIED row recording a
    #: mismatch, the tamper alarm); None, this row attests no check.
    hash_verified: bool | None
    #: The actor's display name, so the log names a person rather than an
    #: eight-hex id (README screenshot review, 2026-09-23).
    actor_name: str | None = None
    #: What the row says beyond its action: a re-acquisition of bytes
    #: already held, the method, the stated acquisition time, the source
    #: and authority, what a check found. Without it two ACQUIRED rows read
    #: as one exhibit acquired twice (ux07-evidence:custody-rows-not-court-
    #: legible, 2026-09-23). See `custody_detail` for what leaves.
    detail: dict = {}


#: The custody detail keys a reader is shown, and nothing else, so a key a
#: future writer adds reaches the console only once it is named here.
_CUSTODY_DETAIL_KEYS = ("deduplicated", "acquisition_method",
                        "acquired_at_stated", "acquired_at", "bytes",
                        "lock_ends_at", "sha256_ok", "blake3_ok", "on_read",
                        # How a production left, and what a lock extension
                        # moved (x-hostile-export, x-lock-extension,
                        # 2026-09-24). The ticket id and the origin stay on
                        # the row for whoever audits it; the log a reader
                        # sees says how, not which ticket.
                        "via", "archive_format", "previous_lock_ends_at",
                        "case_retention_until", "capped_at_horizon")


def custody_detail(raw: dict | None) -> dict:
    """A custody row's detail as the console may draw it. Typed free text
    (the source, the authority reference) leaves as `defang_text` runs and
    never raw: a source is often the phishing URL itself, and a live link
    on the custody record is one click from announcing the investigation
    (docs/19 section 5)."""
    raw = raw or {}
    out = {k: raw[k] for k in _CUSTODY_DETAIL_KEYS if k in raw}
    for key, runs in (("source_url", "source_segments"),
                      ("authority_ref", "authority_segments")):
        if raw.get(key):
            out[runs] = defang_text(str(raw[key]))
    return out


@router.get("/{evidence_id}/custody", response_model=list[CustodyOut])
def custody(
    case_id: UUID, evidence_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[CustodyOut]:
    """The chain of custody — 'who touched this exhibit, and when'."""
    _authorize_exhibit(conn, user, case_id, evidence_id, "evidence.read")
    return [
        CustodyOut(action=e.action, actor_id=str(e.actor_id),
                   occurred_at=e.occurred_at, hash_verified=e.hash_verified,
                   actor_name=e.actor_name, detail=custody_detail(e.detail))
        for e in _svc(conn).custody_log(evidence_id)
    ]


class LinkBody(BaseModel):
    node_id: UUID | None = None
    edge_id: UUID | None = None
    relevance: str | None = None
    page_ref: str | None = None


@router.post("/{evidence_id}/links", status_code=204)
def link(
    case_id: UUID, evidence_id: UUID, body: LinkBody,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    if (body.node_id is None) == (body.edge_id is None):
        raise Problem(400, "Invalid request", "exactly one of node_id / edge_id")
    _authorize_exhibit(conn, user, case_id, evidence_id, "evidence.upload")
    # The link target must live in the SAME case: core.evidence_link has no
    # same-case constraint (unlike core.edge), so an unchecked node_id would
    # attach an evidentiary claim to a node in a case the caller has no
    # rights over, audited only under this case.
    target_ok = conn.execute(
        "SELECT 1 FROM core.node WHERE id = %s AND case_id = %s"
        if body.node_id is not None else
        "SELECT 1 FROM core.edge WHERE id = %s AND case_id = %s",
        (body.node_id or body.edge_id, case_id),
    ).fetchone()
    if target_ok is None:
        raise Problem(400, "Invalid request", "link target is not in this case")
    svc = _svc(conn)
    if body.node_id is not None:
        svc.link_to_node(evidence_id=evidence_id, node_id=body.node_id,
                         created_by=user.user_id, relevance=body.relevance,
                         page_ref=body.page_ref)
    else:
        svc.link_to_edge(evidence_id=evidence_id, edge_id=body.edge_id,
                         created_by=user.user_id, relevance=body.relevance,
                         page_ref=body.page_ref)
    return Response(status_code=204)

"""The conformance checks, one function per property, each named after what it holds.

Every check takes a `Ctx` and raises `AssertionError` with a sentence when the store does not hold the property.
They go through `noctornal_api.objectstore` (the real code path, the profile's classification included), never
the client library. Keys are flat (no `/`), so a listing of the bucket sees every one of them.

`REQUIRED` is the list a store must pass for this product to keep evidence on it; `OPTIONAL` needs something a
store may not offer (a second, read-only credential) and is skipped with its reason when that is missing.
"""
from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from noctornal_api.objectstore import classify, errors
from noctornal_api.objectstore.types import COMPLIANCE

#: Over the client library's part size (5 MiB), so the upload is multipart.
MULTIPART_BYTES = 11 * 1024 * 1024


@dataclass
class Ctx:
    """What a check is handed: the store under test, a bucket made with object lock and one made without,
    the lock length a COMPLIANCE object is given, and a recorder for the store's own words."""
    store: object
    locked: str
    plain: str
    lock_seconds: int = 60
    run: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    #: A store on an endpoint nothing listens on, for the unreachable check.
    unreachable: Callable[[], object] | None = None
    #: A second store with credentials that may read and not delete, for the optional check.
    read_only: Callable[[], object] | None = None
    measurements: dict = field(default_factory=dict)
    #: The latest lock end any check asked for, so the clean-up knows how long to wait.
    latest_until: datetime | None = None

    def key(self, name: str) -> str:
        return f"c-{self.run}-{name}-{uuid.uuid4().hex[:6]}"

    def until(self, seconds: int | None = None) -> datetime:
        moment = (datetime.now(timezone.utc) + timedelta(seconds=seconds or self.lock_seconds)
                  ).replace(microsecond=0)
        if self.latest_until is None or moment > self.latest_until:
            self.latest_until = moment
        return moment

    def record(self, what: str, exc: BaseException) -> None:
        """The store's own answer to a refusal class: code, HTTP status and message."""
        self.measurements[what] = {"code": getattr(exc, "code", None),
                                   "status": getattr(exc, "status", None),
                                   "message": getattr(exc, "message", None) or str(exc)[:200],
                                   "type": type(exc).__name__}


def _refused(call: Callable[[], object], what: str, ctx: Ctx) -> errors.StoreRefusal:
    try:
        call()
    except errors.StoreRefusal as exc:
        ctx.record(what, exc)
        return exc
    raise AssertionError(f"the store did not refuse: {what}")


def _same_second(a: datetime | None, b: datetime) -> bool:
    if a is None:
        return False
    a = a if a.tzinfo else a.replace(tzinfo=timezone.utc)
    return abs((a - b).total_seconds()) < 1.0


def _locked_put(ctx: Ctx, name: str, data: bytes = b"conformance") -> tuple[str, str, datetime]:
    key, until = ctx.key(name), ctx.until()
    result = ctx.store.put(ctx.locked, key, data, retain_until=until)
    assert result.version_id, "the store returned no version id for a put to a locked bucket"
    return key, result.version_id, until


# --- versions and retention -------------------------------------------------------------------------

def a_put_returns_a_version_id_and_a_get_by_that_version_returns_the_bytes(ctx: Ctx) -> None:
    key, version, _ = _locked_put(ctx, "version", b"first bytes")
    assert ctx.store.get(ctx.locked, key, version_id=version) == b"first bytes"


def a_second_put_to_a_locked_key_is_a_new_version_and_the_first_stays_readable(ctx: Ctx) -> None:
    key, first, _ = _locked_put(ctx, "second", b"one")
    second = ctx.store.put(ctx.locked, key, b"two", retain_until=ctx.until()).version_id
    assert second and second != first, (first, second)
    assert ctx.store.get(ctx.locked, key, version_id=first) == b"one"
    assert ctx.store.get(ctx.locked, key, version_id=second) == b"two"


def the_retention_reads_back_as_compliance_at_the_requested_instant(ctx: Ctx) -> None:
    key, version, until = _locked_put(ctx, "readback")
    held = ctx.store.get_retention(ctx.locked, key, version)
    assert held is not None, "the store reports no retention on a version written under one"
    assert held.mode == COMPLIANCE, f"the store recorded {held.mode} for a COMPLIANCE request"
    assert _same_second(held.until, until), (held.until, until)


def a_multipart_put_carries_its_retention_and_returns_one_version(ctx: Ctx) -> None:
    data = bytes(range(256)) * (MULTIPART_BYTES // 256)
    key, version, until = _locked_put(ctx, "multipart", data)
    versions = [v for v in ctx.store.list_versions(ctx.locked, key) if v.key == key]
    assert len(versions) == 1, versions
    held = ctx.store.get_retention(ctx.locked, key, version)
    assert held is not None and held.mode == COMPLIANCE and _same_second(held.until, until), held
    assert ctx.store.head(ctx.locked, key, version_id=version).size == len(data)


def a_version_delete_of_a_locked_version_is_refused_and_the_version_survives(ctx: Ctx) -> None:
    """The SeaweedFS 8350 and 11333 check: a store that accepts the lock and deletes the version anyway."""
    key, version, _ = _locked_put(ctx, "worm", b"kept")
    _refused(lambda: ctx.store.delete_version(ctx.locked, key, version),
             "delete of a COMPLIANCE-locked version", ctx)
    assert ctx.store.get(ctx.locked, key, version_id=version) == b"kept"


def a_keyless_delete_only_adds_a_marker_and_the_locked_bytes_remain(ctx: Ctx) -> None:
    key, version, _ = _locked_put(ctx, "keyless", b"still here")
    answer = ctx.store.delete_key(ctx.locked, key)
    assert answer.delete_marker is not False, "a keyless delete on a versioned bucket added no marker"
    assert ctx.store.get(ctx.locked, key, version_id=version) == b"still here"
    markers = [v for v in ctx.store.list_versions(ctx.locked, key)
               if v.key == key and v.is_delete_marker]
    assert markers, "no delete marker is listed after a keyless delete"


def a_keyless_delete_of_an_absent_key_leaves_a_removable_marker(ctx: Ctx) -> None:
    """The s3 profile's permission control rests on this (`objectstore.classify.delete_control`), so a store
    run on that profile must pass it. It is measured on every store; on the minio profile, which reads a
    refusal's own code and words and runs no control, a store that adds no marker is recorded, not failed."""
    key = ctx.key("absent")
    answer = ctx.store.delete_key(ctx.locked, key)
    marker = answer.version_id if answer.delete_marker else None
    if marker is None:
        marker = next((v.version_id for v in ctx.store.list_versions(ctx.locked, key)
                       if v.key == key and v.is_delete_marker), None)
    if marker is None and ctx.store.profile != "s3":
        ctx.measurements["a keyless delete of an absent key"] = {
            "marker": False, "note": "no marker, so this store cannot run the s3 profile's control"}
        return
    assert marker, "a keyless delete of an absent key left no delete marker"
    ctx.measurements["a keyless delete of an absent key"] = {"marker": True}
    ctx.store.delete_version(ctx.locked, key, marker)
    assert not [v for v in ctx.store.list_versions(ctx.locked, key) if v.key == key]


def a_compliance_retention_cannot_be_shortened(ctx: Ctx) -> None:
    key, version, until = _locked_put(ctx, "shorten")
    try:
        earlier = until - timedelta(seconds=max(2, ctx.lock_seconds // 2))
        ctx.store.set_compliance_retention(ctx.locked, key, version, earlier)
    except errors.StoreRefusal as exc:
        ctx.record("shortening a COMPLIANCE retention", exc)
    held = ctx.store.get_retention(ctx.locked, key, version)
    assert held is not None and held.mode == COMPLIANCE, held
    assert not (held.until and _aware(held.until) < until - timedelta(seconds=1)), (
        f"a COMPLIANCE retention until {until} now reads {held.until}")


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def extend_lock_lengthens_every_version_and_reads_back(ctx: Ctx) -> None:
    from noctornal_api.evidence import EvidenceStorage

    key, first, _ = _locked_put(ctx, "extend", b"a")
    second = ctx.store.put(ctx.locked, key, b"b", retain_until=ctx.until()).version_id
    storage = EvidenceStorage.__new__(EvidenceStorage)
    storage.store, storage._bucket = ctx.store, ctx.locked
    target = ctx.until(ctx.lock_seconds + 60)
    storage.extend_lock(key, target)
    for version in (first, second):
        held = ctx.store.get_retention(ctx.locked, key, version)
        assert held is not None and held.mode == COMPLIANCE and _aware(held.until) >= target, held


def an_unlocked_version_in_a_locked_bucket_is_raised_to_compliance(ctx: Ctx) -> None:
    """The seam writes COMPLIANCE only, so a version with no retention (the bucket has no default) stands in
    for the weaker lock an extension must raise."""
    key = ctx.key("raise")
    version = ctx.store.put(ctx.locked, key, b"bare").version_id
    assert version, "no version id on a locked bucket"
    ctx.store.set_compliance_retention(ctx.locked, key, version, ctx.until())
    held = ctx.store.get_retention(ctx.locked, key, version)
    assert held is not None and held.mode == COMPLIANCE, held


# --- legal holds --------------------------------------------------------------------------------------

def a_legal_hold_set_in_the_put_reads_back_on(ctx: Ctx) -> None:
    key = ctx.key("hold")
    version = ctx.store.put(ctx.locked, key, b"held", legal_hold=True).version_id
    assert version and ctx.store.legal_hold_is_on(ctx.locked, key, version)


def a_held_version_cannot_be_deleted_and_survives(ctx: Ctx) -> None:
    key = ctx.key("held")
    version = ctx.store.put(ctx.locked, key, b"held", legal_hold=True).version_id
    _refused(lambda: ctx.store.delete_version(ctx.locked, key, version),
             "delete of a version under a legal hold", ctx)
    assert ctx.store.get(ctx.locked, key, version_id=version) == b"held"


def a_hold_only_object_has_no_retention(ctx: Ctx) -> None:
    key = ctx.key("holdonly")
    version = ctx.store.put(ctx.locked, key, b"held", legal_hold=True).version_id
    held = ctx.store.get_retention(ctx.locked, key, version)
    assert held is None or held.until is None, held


def lifting_the_hold_makes_it_deletable(ctx: Ctx) -> None:
    """Conformance only: the product never lifts a hold (`test_objectstore_boundary.py`)."""
    key = ctx.key("lift")
    version = ctx.store.put(ctx.locked, key, b"held", legal_hold=True).version_id
    ctx.store.set_legal_hold(ctx.locked, key, version, False)
    assert not ctx.store.legal_hold_is_on(ctx.locked, key, version)
    ctx.store.delete_version(ctx.locked, key, version)
    assert not [v for v in ctx.store.list_versions(ctx.locked, key) if v.key == key]


# --- listings, buckets and errors ---------------------------------------------------------------------

def list_versions_returns_every_version_and_flags_markers(ctx: Ctx) -> None:
    key = ctx.key("list")
    a = ctx.store.put(ctx.locked, key, b"1").version_id
    b = ctx.store.put(ctx.locked, key, b"2").version_id
    ctx.store.delete_key(ctx.locked, key)
    listed = [v for v in ctx.store.list_versions(ctx.locked, key) if v.key == key]
    real = {v.version_id for v in listed if not v.is_delete_marker}
    assert real == {a, b}, listed
    assert [v for v in listed if v.is_delete_marker], "the marker is not flagged"
    for v in listed:
        ctx.store.delete_version(ctx.locked, key, v.version_id)


def a_bucket_without_object_lock_refuses_a_retention_put_and_a_held_put(ctx: Ctx) -> None:
    _refused(lambda: ctx.store.put(ctx.plain, ctx.key("noretention"), b"x", retain_until=ctx.until()),
             "a retention put to a bucket without object lock", ctx)
    _refused(lambda: ctx.store.put(ctx.plain, ctx.key("nohold"), b"x", legal_hold=True),
             "a held put to a bucket without object lock", ctx)


def missing_bucket_key_and_version_are_normalised(ctx: Ctx) -> None:
    exc = _refused(lambda: ctx.store.get(ctx.plain, ctx.key("nothing")), "get of an absent key", ctx)
    assert isinstance(exc, errors.ObjectMissing), type(exc)
    key, version, _ = _locked_put(ctx, "nover")
    exc = _refused(lambda: ctx.store.get(ctx.locked, key, version_id=_absent_version(version)),
                   "get of an absent version", ctx)
    assert isinstance(exc, (errors.ObjectMissing, errors.StoreRefusal)), type(exc)
    assert exc.code in ("NoSuchVersion", "NoSuchKey", "InvalidArgument"), exc.code
    exc = _refused(lambda: ctx.store.get(f"absent-{ctx.run}-bucket", "k"), "get from an absent bucket", ctx)
    assert isinstance(exc, errors.BucketMissing), (type(exc), exc.code)


def _absent_version(version: str) -> str:
    """A version id of the store's own shape that names nothing."""
    if len(version) == 36 and version.count("-") == 4:
        return str(uuid.uuid4())
    return version[:-4] + ("0000" if not version.endswith("0000") else "1111")


def an_unreachable_endpoint_is_never_reached(ctx: Ctx) -> None:
    assert ctx.unreachable is not None, "the run gave no unreachable store"
    try:
        ctx.unreachable().head("conformance-unreachable", "k")
    except errors.StoreUnreachable as exc:
        assert exc.never_reached is True, exc
    else:
        raise AssertionError("a store on an endpoint nothing listens on answered")


# --- the product's own paths --------------------------------------------------------------------------

def the_write_once_probe_passes_and_its_tidy_works(ctx: Ctx) -> None:
    from noctornal_api import readiness
    ok, evidence = readiness.prove_write_once(ctx.store, ctx.locked)
    assert ok, evidence
    ok, evidence = readiness.prove_write_once(ctx.store, ctx.locked)
    assert ok and "reused" in evidence, evidence
    assert "not tidied" not in evidence, evidence


def the_hold_probe_passes(ctx: Ctx) -> None:
    from noctornal_api import readiness
    proof = readiness._prove_hold(ctx.store, ctx.locked, writer="the conformance credential",
                                  deleters=[("the conformance credential", lambda: ctx.store)],
                                  deadline=time.monotonic() + readiness._PROBE_BUDGET_S,
                                  clock=time.monotonic)
    assert proof.ok, proof.evidence


def delete_all_versions_on_a_locked_key_reports_locked_and_the_bytes_survive(ctx: Ctx) -> None:
    from noctornal_api.objectstore.versions import delete_every_version
    key, version, _ = _locked_put(ctx, "purge", b"locked")
    result = delete_every_version(ctx.store, ctx.locked, key)
    assert result.versions_locked == 1 and result.versions_removed == 0, result
    assert ctx.store.get(ctx.locked, key, version_id=version) == b"locked"


def delete_all_versions_on_an_unlocked_key_removes_every_version(ctx: Ctx) -> None:
    from noctornal_api.objectstore.versions import delete_every_version
    key = ctx.key("unlocked")
    ctx.store.put(ctx.plain, key, b"1")
    ctx.store.put(ctx.plain, key, b"2")
    result = delete_every_version(ctx.store, ctx.plain, key)
    assert result.versions_locked == 0 and result.versions_removed >= 1, result
    assert not [v for v in ctx.store.list_versions(ctx.plain, key)
                if v.key == key and not v.is_delete_marker]


def the_profiles_rule_reads_this_stores_lock_refusal_as_a_lock(ctx: Ctx) -> None:
    key, version, _ = _locked_put(ctx, "classify")
    exc = _refused(lambda: ctx.store.delete_version(ctx.locked, key, version),
                   "delete of a locked version, as classified", ctx)
    verdict = classify.classify_version_delete_refusal(ctx.store, ctx.locked, key, version, exc)
    assert verdict == classify.LOCKED, (
        f"the {ctx.store.profile} profile reads this store's lock refusal ({exc.code}: {exc.message}) "
        f"as {verdict}; this store needs the other profile")


# --- optional -----------------------------------------------------------------------------------------

def a_read_only_credentials_delete_is_denied_not_locked(ctx: Ctx) -> None:
    assert ctx.read_only is not None, "the run gave no read-only credential"
    key = ctx.key("readonly")
    version = ctx.store.put(ctx.plain, key, b"x").version_id or "null"
    other = ctx.read_only()
    exc = _refused(lambda: other.delete_version(ctx.plain, key, version),
                   "a version delete by a credential that may not delete", ctx)
    verdict = classify.classify_version_delete_refusal(other, ctx.plain, key, version, exc)
    assert verdict != classify.LOCKED, verdict


REQUIRED: tuple[Callable[[Ctx], None], ...] = (
    a_put_returns_a_version_id_and_a_get_by_that_version_returns_the_bytes,
    a_second_put_to_a_locked_key_is_a_new_version_and_the_first_stays_readable,
    the_retention_reads_back_as_compliance_at_the_requested_instant,
    a_multipart_put_carries_its_retention_and_returns_one_version,
    a_version_delete_of_a_locked_version_is_refused_and_the_version_survives,
    a_keyless_delete_only_adds_a_marker_and_the_locked_bytes_remain,
    a_keyless_delete_of_an_absent_key_leaves_a_removable_marker,
    a_compliance_retention_cannot_be_shortened,
    extend_lock_lengthens_every_version_and_reads_back,
    an_unlocked_version_in_a_locked_bucket_is_raised_to_compliance,
    a_legal_hold_set_in_the_put_reads_back_on,
    a_held_version_cannot_be_deleted_and_survives,
    a_hold_only_object_has_no_retention,
    lifting_the_hold_makes_it_deletable,
    list_versions_returns_every_version_and_flags_markers,
    a_bucket_without_object_lock_refuses_a_retention_put_and_a_held_put,
    missing_bucket_key_and_version_are_normalised,
    an_unreachable_endpoint_is_never_reached,
    the_write_once_probe_passes_and_its_tidy_works,
    the_hold_probe_passes,
    delete_all_versions_on_a_locked_key_reports_locked_and_the_bytes_survive,
    delete_all_versions_on_an_unlocked_key_removes_every_version,
    the_profiles_rule_reads_this_stores_lock_refusal_as_a_lock,
)
OPTIONAL: tuple[Callable[[Ctx], None], ...] = (
    a_read_only_credentials_delete_is_denied_not_locked,
)

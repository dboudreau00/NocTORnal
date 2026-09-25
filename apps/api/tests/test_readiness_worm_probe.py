"""The WORM probe: write-once is PROVEN by a refused delete, never read.

docs/17 F24, decided by the owner 2026-09-22: stay on the pinned MinIO
build, accepted in writing, and make the readiness register prove
write-once instead of reading the bucket's lock configuration. Until that
day `evidence_bucket_object_lock` passed on `get_object_lock_config`
answering with a configuration, and research for the decision found two
stores that would have passed it holding nothing: SeaweedFS accepts a
COMPLIANCE retention and has let the delete succeed anyway (seaweedfs
issues 8350 and 11333; the second deleted the locked version BY ITS ID),
and Garage has no object lock at all.

So the probe keeps one canary per bucket under a fixed key, writes it with
a one-day COMPLIANCE retention only when it is absent or about to lapse,
and on every run issues a DELETE naming that canary's VERSION ID. It passes
only on a retention refusal with the version still there afterwards.

The verifier's round of 2026-09-22 added what this file now also holds: a
missing bucket is a sentence, not a raw S3Error; canary versions past their
lock are tidied rather than piling up; credentials that may not read a
retention reuse the canary instead of writing one per probe; a refusal on
the credentials' own permissions is marked as proving nothing, and the
preservation check then proves with the credential that may delete; the
proof has a time budget; and the preservation store is addressed exactly
as `samples.PreservationStorage` addresses it.

The final review of 2026-09-23 added three more. C10: the probe asked for
COMPLIANCE and never read what the store recorded, and a plain DELETE is
refused under GOVERNANCE too, so a store that downgraded passed claiming
COMPLIANCE and gained a locked canary per probe; the mode is now read back.
C9: preserved samples carry a legal hold and no retention, and the
preservation check proved only a retention; it now proves a hold as well.
U6: a transport error while tidying turned a proven check red.

Most of this file drives a FAKE client, because the failure it exists for
(a store that accepts the lock and deletes anyway) is not one the dev
MinIO can be made to commit. The live half at the bottom runs the real
probe against the dev MinIO and is gated on MINIO_ENDPOINT; it leaves one
tiny canary per bucket locked for a day, which is the probe's designed
standing cost and the reason the retention is a day and not a year, and
one held canary in the preservation bucket, kept for good, because a hold
has no expiry.
"""
from __future__ import annotations

import copy
import os
from datetime import datetime, timedelta, timezone

import pytest
import urllib3
from minio.commonconfig import COMPLIANCE, GOVERNANCE
from minio.error import InvalidResponseError, S3Error, ServerError
from minio.retention import Retention

from noctornal_api import readiness

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)
KEY = readiness.WORM_CANARY_KEY
HOLD_KEY = readiness.HOLD_CANARY_KEY

#: What the live MinIO answers for a delete of a COMPLIANCE-locked
#: version, as `test_evidence_lock_live_pg.py` measures on every run.
WORM = ("InvalidRequest", "Object is WORM protected and cannot be overwritten")
DENIED = ("AccessDenied", "Access Denied.")


def _err(code: str, message: str | None = None) -> S3Error:
    return S3Error(code=code, message=message or code, resource="r",
                   request_id="1", host_id="1", response=None)


class _Stat:
    def __init__(self, version_id, last_modified):
        self.version_id = version_id
        self.last_modified = last_modified


class _Written:
    def __init__(self, version_id):
        self.version_id = version_id


class _Listed:
    def __init__(self, version_id, last_modified, is_delete_marker=False,
                 key=KEY):
        self.object_name = key
        self.version_id = version_id
        self.last_modified = last_modified
        self.is_delete_marker = is_delete_marker


class _Backing:
    """What one store holds, shared by every account that reaches it."""

    def __init__(self):
        self.versions: dict[str, Retention | None] = {}
        self.keys: dict[str, str] = {}
        self.written: dict[str, datetime] = {}
        self.holds: set[str] = set()
        self.markers: list[str] = []
        self.latest: dict[str, str | None] = {}
        self.n = 0


#: What an ACCOUNT may do, as opposed to how the store behaves. Each one
#: answers its call with AccessDenied, as a least-privilege policy would.
_PERMISSIONS = ("retention_denied", "retention_put_denied", "hold_put_denied",
                "hold_read_denied", "stat_denied", "list_denied",
                "delete_denied")
#: `applies` default: the store records the retention the PUT asked for.
_AS_ASKED = object()


class FakeStore:
    """An object store with just enough surface for the probe.

    `enforces` decides what a DELETE of a locked version does: True
    refuses it the way MinIO does, False deletes it the way seaweedfs
    11333 reports. A lock is live while its retain-until is after `now`.
    `enforces_hold` is the same for a legal hold, which has no expiry, and
    `records_hold=False` takes a held PUT and reads the hold back OFF.
    `applies` is the retention the store RECORDS whatever the PUT asked
    for (a Retention, or None for none), `locks_unrecorded` refuses every
    versioned DELETE whatever it recorded, `hold_refusal` overrides the
    shape of a hold's refusal. `versioned=False` answers every PUT with no
    version id. `refusal` overrides a retention refusal's shape.
    `retention_error` answers GetObjectRetention with that S3 error, and
    `list_raises` makes the listing raise that exception when iterated.

    The `_PERMISSIONS` flags are the account's. `account()` is another
    credential on the SAME store: the contents and behaviour are shared,
    only the permissions differ, as with PRESERVE_* and MINIO_* on one
    MinIO.
    """

    def __init__(self, *, enforces=True, enforces_hold=True,
                 records_hold=True, applies=_AS_ASKED, locks_unrecorded=False,
                 hold_refusal=None, versioned=True, accepts_lock=True,
                 refusal=WORM, vanish_after_refusal=False, bucket_exists=True,
                 retention_error=None, list_raises=None, now=NOW,
                 on_call=None, **permissions):
        self.enforces = enforces
        self.enforces_hold = enforces_hold
        self.records_hold = records_hold
        self.applies = applies
        self.locks_unrecorded = locks_unrecorded
        self.hold_refusal = hold_refusal
        self.versioned = versioned
        self.accepts_lock = accepts_lock
        self.refusal = refusal
        self.vanish_after_refusal = vanish_after_refusal
        self.bucket_exists = bucket_exists
        self.retention_error = retention_error
        self.list_raises = list_raises
        self.now = now
        self.on_call = on_call
        self._set_permissions(permissions)
        self._b = _Backing()
        self.calls: list[tuple] = []

    def _set_permissions(self, permissions: dict) -> None:
        unknown = set(permissions) - set(_PERMISSIONS)
        assert not unknown, f"not a permission: {unknown}"
        for flag in _PERMISSIONS:
            setattr(self, flag, permissions.get(flag, False))

    def account(self, **permissions) -> FakeStore:
        other = copy.copy(self)
        other.calls = []
        other._set_permissions(permissions)
        return other

    @property
    def versions(self):
        return self._b.versions

    @property
    def markers(self):
        return self._b.markers

    @property
    def holds(self):
        return self._b.holds

    @property
    def latest(self):
        """The latest version of the WORM canary."""
        return self._b.latest.get(KEY)

    def _call(self, *record):
        self.calls.append(record)
        if self.on_call:
            self.on_call()
        if not self.bucket_exists:
            raise _err("NoSuchBucket", "The specified bucket does not exist")

    def seed(self, retention: Retention | None,
             written: datetime | None = None, *, key: str = KEY,
             hold: bool = False) -> str:
        b = self._b
        b.n += 1
        vid = f"v{b.n}"
        b.versions[vid] = retention
        b.keys[vid] = key
        b.written[vid] = written or self.now
        if hold:
            b.holds.add(vid)
        b.latest[key] = vid
        return vid

    def _locked(self, vid) -> bool:
        r = self._b.versions.get(vid)
        return r is not None and r.retain_until_date > self.now

    def stat_object(self, bucket, key, version_id=None):
        self._call("stat", key, version_id)
        if self.stat_denied:
            raise _err(*DENIED)
        b = self._b
        vid = version_id or b.latest.get(key)
        if vid is None or vid not in b.versions or b.keys[vid] != key:
            raise _err("NoSuchKey", "Object does not exist")
        return _Stat(vid if self.versioned else None, b.written[vid])

    def get_object_retention(self, bucket, key, version_id=None):
        self._call("retention", key, version_id)
        if self.retention_denied:
            raise _err(*DENIED)
        if self.retention_error:
            raise _err(*self.retention_error)
        return self._b.versions.get(version_id)

    def is_object_legal_hold_enabled(self, bucket, key, version_id=None):
        self._call("hold?", key, version_id)
        if self.hold_read_denied:
            raise _err(*DENIED)
        return version_id in self._b.holds

    def put_object(self, bucket, key, data, length, content_type=None,
                   retention=None, legal_hold=False):
        self._call("put", key, retention, legal_hold)
        if retention is not None and self.retention_put_denied:
            raise _err(*DENIED)
        if legal_hold and self.hold_put_denied:
            raise _err(*DENIED)
        if (retention is not None or legal_hold) and not self.accepts_lock:
            raise _err("InvalidRequest",
                       "Bucket is missing ObjectLockConfiguration")
        recorded = retention if self.applies is _AS_ASKED else self.applies
        vid = self.seed(recorded, key=key,
                        hold=legal_hold and self.records_hold)
        return _Written(vid if self.versioned else None)

    def remove_object(self, bucket, key, version_id=None):
        self._call("remove", key, version_id)
        assert version_id is not None, (
            "the probe deleted by KEY: on a versioned bucket that adds a "
            "delete marker and succeeds, which proves nothing")
        if self.delete_denied:
            raise _err(*DENIED)
        b = self._b
        if version_id in b.markers:
            b.markers.remove(version_id)
            return
        held = self.enforces_hold and version_id in b.holds
        if held or (self.enforces and self._locked(version_id)) or (
                self.locks_unrecorded and version_id in b.versions):
            if self.vanish_after_refusal:
                b.versions.pop(version_id)
            raise _err(*((held and self.hold_refusal) or self.refusal))
        b.versions.pop(version_id, None)
        b.holds.discard(version_id)
        owner = b.keys.get(version_id)
        if b.latest.get(owner) == version_id:
            b.latest[owner] = None

    def list_objects(self, bucket, prefix=None, include_version=False):
        self._call("list", prefix, include_version)
        if self.list_denied:
            raise _err(*DENIED)
        assert include_version, "a keyless listing hides the versions"
        b = self._b
        listed = [_Listed(v, b.written[v], key=b.keys[v]) for v in b.versions
                  if b.keys[v].startswith(prefix or "")]
        listed += [_Listed(m, self.now - timedelta(days=9), True)
                   for m in b.markers]
        failure = self.list_raises

        def pages():
            # minio's listing is lazy: a transport error arrives on the
            # first next(), inside the caller's loop, not at the call.
            if failure is not None:
                raise failure
            yield from listed
        return pages()

    def removes(self):
        return [c for c in self.calls if c[0] == "remove"]

    def puts(self):
        return [c for c in self.calls if c[0] == "put"]


def _compliance(hours: float) -> Retention:
    return Retention(COMPLIANCE, NOW + timedelta(hours=hours))


# ---------------------------------------------------------------------------
# prove_write_once against a fake store
# ---------------------------------------------------------------------------

def test_a_store_that_refuses_the_versioned_delete_passes():
    store = FakeStore()
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is True, evidence
    assert "PROVEN" in evidence and "refused" in evidence
    # The canary was written under COMPLIANCE for the designed day, and
    # the delete named the version that write returned.
    (_, key, retention, hold), = store.puts()
    assert key == KEY and hold is False
    assert retention.mode == COMPLIANCE
    assert retention.retain_until_date == NOW + readiness.CANARY_RETENTION
    assert store.removes() == [("remove", KEY, "v1")]
    assert "v1" in store.versions, "the refused version must still be there"
    # And the mode the evidence names is the one the store REPORTED for
    # that version, read before the delete (final review C10).
    calls = store.calls
    assert calls.index(("retention", KEY, "v1")) < calls.index(
        ("remove", KEY, "v1"))
    assert "COMPLIANCE until 2026-09-23 12:00 UTC" in evidence
    assert "read back" in evidence


def test_a_store_that_accepts_the_lock_and_deletes_anyway_fails():
    """seaweedfs 11333, as a fake: PutObjectRetention with COMPLIANCE is
    accepted, and a DELETE of the locked version by its id succeeds. A
    configuration read passes this store. The probe must not."""
    store = FakeStore(enforces=False)
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is False
    assert "SUCCEEDED" in evidence
    assert "v1" in evidence, "the evidence must name the version it destroyed"
    assert store.removes() == [("remove", KEY, "v1")]


def test_every_delete_the_probe_issues_names_a_version():
    """The mandatory half of the design. A keyless DELETE on a versioned
    bucket succeeds by adding a delete marker (evidence.py measured it on
    2026-08-10), so a probe that deleted by key would report every
    honest store as broken, and seaweedfs 8350 reads exactly like that."""
    for store in (FakeStore(), FakeStore(enforces=False)):
        readiness.prove_write_once(store, "b", now=NOW)
        assert store.removes(), "the probe never tried to delete anything"
        assert all(vid for _, _, vid in store.removes())


def test_a_policy_denial_is_not_evidence_of_write_once():
    """`AccessDenied` with no lock wording is a permissions refusal, and
    the one classifier the purge uses (`evidence.is_retention_refusal`)
    says so. A key that may not delete would otherwise pass this check on
    any store, locked or not. The proof is marked `denied`, so a caller
    knows it says nothing either way."""
    store = FakeStore(refusal=DENIED)
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is False
    assert "may not delete a version" in evidence
    assert "AccessDenied" in evidence
    proof = readiness._prove(FakeStore(refusal=DENIED), "b", now=NOW,
                             deadline=float("inf"), clock=lambda: 0.0)
    assert proof.denied is True


def test_a_refusal_that_is_neither_a_lock_nor_a_denial_fails_plainly():
    store = FakeStore(refusal=("InvalidRequest", "Something else entirely"))
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is False
    assert "not for retention" in evidence
    assert "Something else entirely" in evidence


def test_an_unversioned_bucket_fails_even_when_it_takes_the_retention():
    store = FakeStore(versioned=False)
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is False
    assert "no version id" in evidence
    assert store.removes() == [], "there was no version to name"


def test_a_bucket_without_object_lock_fails_with_the_stores_own_words():
    store = FakeStore(accepts_lock=False)
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is False
    assert "Bucket is missing ObjectLockConfiguration" in evidence


def test_a_missing_bucket_is_a_sentence_not_a_raw_s3_error():
    """Verifier, 2026-09-22: the HEAD of the canary on a bucket that does
    not exist raised NoSuchBucket out of the probe, so the register showed
    `S3Error: S3 operation failed; code: NoSuchBucket ... request_id ...`
    where the configuration read it replaced had said the bucket does not
    exist. Nothing is written and nothing is deleted."""
    store = FakeStore(bucket_exists=False)
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is False
    assert "does not exist" in evidence and "NoSuchBucket" in evidence
    assert "request_id" not in evidence
    assert store.puts() == [] and store.removes() == []


def test_a_refusal_with_the_version_gone_anyway_fails():
    store = FakeStore(vanish_after_refusal=True)
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is False
    assert "gone anyway" in evidence


def test_a_live_canary_is_reused_rather_than_rewritten():
    """Rewriting on every probe would lock a new object each time the
    register is opened."""
    store = FakeStore()
    vid = store.seed(_compliance(20))
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is True, evidence
    assert store.puts() == []
    assert store.removes() == [("remove", KEY, vid)]
    assert "reused" in evidence


@pytest.mark.parametrize("label, retention", [
    ("about to lapse", _compliance(1 / 6)),
    ("already lapsed", _compliance(-1)),
    ("no retention", None),
])
def test_a_canary_that_cannot_be_tested_is_replaced(label, retention):
    """A canary whose lock lapses between the read and the delete would
    make an honest store look like one that deletes locked objects."""
    store = FakeStore()
    old = store.seed(retention)
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is True, (label, evidence)
    assert len(store.puts()) == 1, label
    tested = store.removes()[0][2]
    assert tested != old, f"{label}: the probe tested the old canary"


# ---------------------------------------------------------------------------
# GOVERNANCE is not COMPLIANCE, and a plain DELETE cannot tell them apart
# ---------------------------------------------------------------------------

def test_a_governance_canary_fails_rather_than_being_replaced():
    """Final review C10, 2026-09-23. GOVERNANCE is lifted by anyone holding
    BypassGovernanceRetention, the root credential included, so it proves
    nothing; this probe is the key's only writer and always asks for
    COMPLIANCE, so a GOVERNANCE canary is the store's answer. Until then
    it was quietly replaced, and the replacement was locked GOVERNANCE too."""
    store = FakeStore()
    old = store.seed(Retention(GOVERNANCE, NOW + timedelta(hours=20)))
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is False
    assert f"recorded GOVERNANCE until 2026-09-23 08:00 UTC on canary {KEY} " \
           f"version {old}" in evidence
    assert "PROVEN" not in evidence
    assert store.puts() == [], "a new canary was locked instead of failing"
    assert store.removes() == [], "a plain DELETE proves nothing here"


def test_a_store_that_records_governance_for_compliance_fails_every_probe():
    """The verifier's reproduction, as a test: a store that records its
    GOVERNANCE 365d default whatever mode the PUT asks for. Three probes
    passed with "write-once PROVEN ... COMPLIANCE until ..." and left
    three versions locked for a year that no tidy could remove. Now every
    probe fails, naming the mode the store recorded, and only the first
    one writes anything."""
    year = Retention(GOVERNANCE, NOW + timedelta(days=365))
    store = FakeStore(applies=year)
    for _ in range(3):
        ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
        assert ok is False, evidence
        assert "recorded GOVERNANCE until 2027-09-22 12:00 UTC" in evidence
        assert "COMPLIANCE until" not in evidence
    later = NOW + timedelta(days=2)
    store.now = later
    ok, evidence = readiness.prove_write_once(store, "b", now=later)
    assert ok is False, evidence
    assert len(store.puts()) == 1, "one locked canary per probe again"
    assert store.removes() == []
    assert list(store.versions) == ["v1"]


def test_a_store_that_records_no_retention_is_not_credited_with_compliance():
    """The store took the COMPLIANCE request and reports no retention on the
    version. If something still refuses the DELETE, it is not a lock this
    probe can name, so it fails; if nothing does, the delete succeeds and
    the familiar SUCCEEDED verdict stands."""
    store = FakeStore(applies=None, locks_unrecorded=True)
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is False, evidence
    assert "no retention recorded" in evidence
    assert "COMPLIANCE requested until" in evidence
    assert "PROVEN" not in evidence

    store = FakeStore(applies=None)
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is False
    assert "SUCCEEDED" in evidence


def test_a_store_that_will_not_say_what_it_recorded_fails():
    """Any answer to the read-back but a permissions refusal is the store
    declining to name the lock, which is the opinion this probe exists not
    to trust."""
    store = FakeStore(retention_error=("NotImplemented",
                                       "A header you provided implies "
                                       "functionality that is not implemented"))
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is False
    assert "would not say what retention it recorded (NotImplemented" in evidence
    assert store.removes() == []


def test_credentials_that_may_not_read_a_retention_reuse_the_canary():
    """Verifier, 2026-09-22: a refused GetObjectRetention used to read as
    "no canary", so every probe wrote another locked version. The lock is
    now taken from the canary's write time (the probe is the key's only
    writer and always asks for a day), which picks the version to test and
    never the verdict."""
    store = FakeStore(retention_denied=True)
    fresh = store.seed(_compliance(22), written=NOW - timedelta(hours=2))
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is True, evidence
    assert store.puts() == []
    assert store.removes()[0] == ("remove", KEY, fresh)
    assert "taken from when it was written" in evidence
    # Final review C10: the mode was asked for and never seen, so the
    # evidence may not assert it.
    assert "COMPLIANCE requested until" in evidence
    assert "not confirmed" in evidence
    assert "(COMPLIANCE until" not in evidence

    # Written 23.5 hours ago: inside the margin, so replaced, not tested,
    # and the fresh one's mode cannot be read back either.
    store = FakeStore(retention_denied=True)
    old = store.seed(_compliance(0.5), written=NOW - timedelta(hours=23.5))
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is True, evidence
    assert len(store.puts()) == 1
    assert store.removes()[0][2] != old
    assert "written by this probe; these credentials may not read a " \
           "retention" in evidence
    assert "(COMPLIANCE until" not in evidence


def test_an_inferred_lock_the_store_never_applied_still_fails():
    """The inference must not be able to turn into a pass: a store that
    ignored the retention deletes the canary, and the check says so."""
    store = FakeStore(retention_denied=True)
    store.seed(None, written=NOW - timedelta(hours=2))
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is False
    assert "SUCCEEDED" in evidence


# ---------------------------------------------------------------------------
# Tidying: canary versions past their lock do not pile up
# ---------------------------------------------------------------------------

def test_canary_versions_past_their_lock_are_removed_after_a_proof():
    """Verifier, 2026-09-22: a new version was written each day and none
    was ever removed, about 365 a year per bucket. Only versions written
    more than a day ago are touched, never the one just tested, and a
    delete marker (which hides nothing) goes too."""
    store = FakeStore()
    lapsed = [store.seed(_compliance(-48), written=NOW - timedelta(days=3)),
              store.seed(_compliance(-24), written=NOW - timedelta(days=2))]
    young = store.seed(_compliance(0.5), written=NOW - timedelta(hours=23.5))
    store.markers.append("m1")
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is True, evidence
    current = store.latest
    for vid in lapsed:
        assert vid not in store.versions, f"{vid} was not tidied"
    assert young in store.versions, "a version inside its day was touched"
    assert current in store.versions
    assert store.markers == []
    assert "2 canary versions past their lock removed" in evidence
    removed = [vid for _, _, vid in store.removes()]
    assert young not in removed, "a version inside its day was deleted"


def test_tidying_is_capped_per_probe():
    store = FakeStore()
    for days in range(3, 12):
        store.seed(_compliance(-24 * days), written=NOW - timedelta(days=days))
    ok, _ = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is True
    # One delete for the proof itself, then at most _TIDY_LIMIT.
    assert len(store.removes()) == 1 + readiness._TIDY_LIMIT


def test_a_version_still_locked_is_kept_and_a_tidy_failure_keeps_the_proof():
    """Clock skew or a longer retention: the store refuses, and the version
    stays. And a listing the credentials may not make is reported beside a
    proof that stands, never instead of it."""
    store = FakeStore()
    skewed = store.seed(_compliance(5), written=NOW - timedelta(days=2))
    current = store.seed(_compliance(20))
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is True, evidence
    assert store.removes()[0] == ("remove", KEY, current)
    assert ("remove", KEY, skewed) in store.removes(), "never tried"
    assert skewed in store.versions
    assert "removed" not in evidence

    store = FakeStore(list_denied=True)
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is True
    assert "not tidied (AccessDenied)" in evidence


@pytest.mark.parametrize("failure", [
    urllib3.exceptions.ProtocolError(
        "Connection aborted.", ConnectionResetError(10054, "reset by peer")),
    urllib3.exceptions.ReadTimeoutError(
        None, "/b?versions", "Read timed out. (read timeout=5.0)"),
    InvalidResponseError(502, "text/html", "<html>Bad Gateway</html>"),
    ServerError("server failed with HTTP status code 503", 503),
], ids=lambda exc: type(exc).__name__)
def test_a_transport_error_while_tidying_keeps_the_proof(failure):
    """Final review U6, 2026-09-23. The tidy runs after the proof passed
    and is best effort, but it caught only S3Error, and the probe's client
    retries nothing. A reset or a slow page during the listing escaped
    through `_guarded`, and the row went red with "start the object store"
    for a store that is running and has just refused a locked delete."""
    store = FakeStore(list_raises=failure)
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is True, evidence
    assert "PROVEN" in evidence
    assert f"not tidied ({type(failure).__name__}" in evidence


# ---------------------------------------------------------------------------
# The time budget
# ---------------------------------------------------------------------------

def test_a_slow_store_fails_inside_the_budget():
    """Verifier, 2026-09-22: the proof is up to six calls where the read
    it replaced was one, each allowed the 5s read timeout. A store that
    answers every call slowly now fails when the budget runs out rather
    than holding the register for most of a minute."""
    ticks = {"t": 0.0}
    store = FakeStore(on_call=lambda: ticks.__setitem__("t", ticks["t"] + 4.0))
    ok, evidence = readiness.prove_write_once(store, "b", now=NOW,
                                              clock=lambda: ticks["t"])
    assert ok is False
    assert f"within {readiness._PROBE_BUDGET_S:g}s" in evidence
    assert len(store.calls) <= 3, store.calls


# ---------------------------------------------------------------------------
# The two register checks, with the fake swapped in for the network
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_store(monkeypatch):
    """`template["store"]` answers every client; `template["by_access"]`
    answers a client built with that access key instead, so the
    preservation account and the MINIO_* account can be different stores
    with different permissions."""
    stores: list[tuple[FakeStore, tuple]] = []
    template: dict = {"store": FakeStore(), "by_access": {}}

    def factory(endpoint, access, secret, secure):
        store = template["by_access"].get(access, template["store"])
        stores.append((store, (endpoint, access, secret, secure)))
        return store

    monkeypatch.setattr(readiness, "_object_store_client", factory)
    for var in ("PRESERVE_ENDPOINT", "PRESERVE_ACCESS_KEY", "PRESERVE_SECRET_KEY",
                "PRESERVE_SECURE", "SAMPLE_ENDPOINT", "SAMPLE_ACCESS_KEY",
                "SAMPLE_SECRET_KEY", "SAMPLE_SECURE", "PRESERVE_BUCKET",
                "MINIO_SECURE", readiness.DISPOSITION_ENV):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("MINIO_ENDPOINT", "store.example:9000")
    monkeypatch.setenv("MINIO_ACCESS_KEY", "evidence-key")
    monkeypatch.setenv("MINIO_SECRET_KEY", "evidence-secret")
    monkeypatch.setenv("EVIDENCE_BUCKET", "ev-bucket")
    return template, stores


def test_the_evidence_check_fails_on_a_store_that_deletes_locked_versions(
        fake_store):
    template, _ = fake_store
    template["store"] = FakeStore(enforces=False)
    check = readiness._evidence_bucket_object_lock(None)
    assert check.ok is False
    assert "ev-bucket" in check.evidence and "SUCCEEDED" in check.evidence
    assert "docs/17 F24" in check.action


def test_the_evidence_check_passes_on_a_store_that_refuses(fake_store):
    check = readiness._evidence_bucket_object_lock(None)
    assert check.ok is True, check
    assert check.action == ""


def test_the_evidence_check_names_a_missing_bucket(fake_store):
    template, _ = fake_store
    template["store"] = FakeStore(bucket_exists=False)
    check = readiness._evidence_bucket_object_lock(None)
    assert check.ok is False
    assert check.evidence.startswith("bucket ev-bucket at store.example:9000: "
                                     "the bucket does not exist")


def test_the_evidence_check_says_its_credentials_need_what_was_denied(
        fake_store):
    template, _ = fake_store
    template["store"] = FakeStore(retention_put_denied=True)
    check = readiness._evidence_bucket_object_lock(None)
    assert check.ok is False
    assert "s3:PutObjectRetention" in check.evidence
    assert "need that permission anyway" in check.evidence


def test_the_preservation_check_probes_its_own_bucket_and_names_a_fallback(
        fake_store):
    """PRESERVE_* falls back to SAMPLE_* then MINIO_*, the preservation
    store's contract. On a production stack a fallback means the rejected
    samples share the evidence credentials, so the evidence says so."""
    template, stores = fake_store
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is True, check
    assert readiness.PRESERVE_BUCKET_DEFAULT in check.evidence
    assert "MINIO_ACCESS_KEY" in check.evidence and "fallback" in check.evidence
    assert stores[-1][1] == ("store.example:9000", "evidence-key",
                             "evidence-secret", False)


def test_preserve_credentials_win_over_the_fallbacks(fake_store, monkeypatch):
    _, stores = fake_store
    monkeypatch.setenv("PRESERVE_ENDPOINT", "preserve.example:9000")
    monkeypatch.setenv("PRESERVE_ACCESS_KEY", "p-key")
    monkeypatch.setenv("PRESERVE_SECRET_KEY", "p-secret")
    monkeypatch.setenv("SAMPLE_ACCESS_KEY", "s-key")
    monkeypatch.setenv("PRESERVE_BUCKET", "held-here")
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is True, check
    assert "held-here" in check.evidence
    assert "fallback" not in check.evidence
    assert stores[-1][1][:3] == ("preserve.example:9000", "p-key", "p-secret")


def _production_preservation(monkeypatch, store: FakeStore,
                             endpoint="store.example:9000") -> FakeStore:
    """The account infra/production/compose.yml mints, on `store`: it may
    write, read, set a hold (ON only) and read one back, and may neither
    read or set a retention nor delete."""
    monkeypatch.setenv("PRESERVE_ENDPOINT", endpoint)
    monkeypatch.setenv("PRESERVE_ACCESS_KEY", "p-key")
    monkeypatch.setenv("PRESERVE_SECRET_KEY", "p-secret")
    return store.account(retention_denied=True, retention_put_denied=True,
                         delete_denied=True)


def test_a_preservation_account_that_may_not_delete_is_proven_with_one_that_may(
        fake_store, monkeypatch):
    """Found in the fix round of 2026-09-22 by reading the policy g04 mints:
    the preservation account's refusal is AccessDenied whatever the store
    would do, so a proof made with it proves nothing, and a check that
    stopped there would be red for ever on a correct deployment. On the
    same store the MINIO_* credentials may delete, and the proof is made
    with those, saying so."""
    template, stores = fake_store
    template["by_access"]["p-key"] = _production_preservation(
        monkeypatch, template["store"])
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is True, check
    assert ("PRESERVE_ACCESS_KEY may not write an object under a retention "
            "(s3:PutObjectRetention) (AccessDenied)") in check.evidence
    assert "as its policy intends" in check.evidence
    assert "proof was made with MINIO_ACCESS_KEY" in check.evidence
    assert "write-once PROVEN" in check.evidence
    assert "legal hold PROVEN" in check.evidence
    assert [s[1][1] for s in stores] == ["p-key", "evidence-key"]


def test_the_second_credential_is_held_to_the_same_proof(fake_store,
                                                         monkeypatch):
    template, _ = fake_store
    template["store"] = FakeStore(enforces=False)
    template["by_access"]["p-key"] = _production_preservation(
        monkeypatch, template["store"])
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is False
    assert "SUCCEEDED" in check.evidence


def test_a_denied_preservation_account_on_another_store_cannot_be_proven(
        fake_store, monkeypatch):
    template, stores = fake_store
    template["by_access"]["p-key"] = _production_preservation(
        monkeypatch, FakeStore(), endpoint="elsewhere.example:9000")
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is False
    assert "cannot be proven from here" in check.evidence
    assert "out of band" in check.action
    assert [s[1][1] for s in stores] == ["p-key"], (
        "MINIO_* credentials were sent to a store they do not belong to")


def test_an_account_that_cannot_reach_the_bucket_is_not_proven_around(
        fake_store, monkeypatch):
    """The SAMPLE_* fallback as production mints it: a policy that does not
    reach the preservation bucket at all. `PreservationStorage` would write
    every rejection with it and be refused, so a row proven green with the
    MINIO_* credentials would hide exactly the failure that matters."""
    template, stores = fake_store
    monkeypatch.setenv("SAMPLE_ACCESS_KEY", "s-key")
    monkeypatch.setenv("SAMPLE_SECRET_KEY", "s-secret")
    template["by_access"]["s-key"] = FakeStore(stat_denied=True)
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is False
    assert "SAMPLE_ACCESS_KEY may not read this bucket (AccessDenied)" in check.evidence
    assert "every rejection is refused" in check.evidence
    assert "fallback" in check.evidence
    assert "PRESERVE_ACCESS_KEY" in check.action
    assert [s[1][1] for s in stores] == ["s-key"]


# ---------------------------------------------------------------------------
# The preservation bucket's samples carry a HOLD, so a hold is proven
# ---------------------------------------------------------------------------

def test_a_store_that_enforces_a_retention_but_not_a_hold_fails(fake_store):
    """Final review C9, 2026-09-23. Retention and legal hold are separate
    S3 mechanisms, and a preserved sample has only the hold. A store that
    refuses a COMPLIANCE delete and merely records a hold passed this
    check, while any credential that may delete a version could remove a
    held copy of prohibited material. The evidence bucket (retention) is
    still proven on that same store; the preservation bucket is not."""
    template, _ = fake_store
    template["store"] = store = FakeStore(enforces_hold=False)
    assert readiness._evidence_bucket_object_lock(None).ok is True
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is False, check
    assert f"hold canary {HOLD_KEY}" in check.evidence
    assert "SUCCEEDED" in check.evidence
    assert "accepts a legal hold and does not enforce it" in check.evidence
    assert "a retention says nothing about a hold" in check.evidence
    assert "docs/17 F2" in check.action
    held_puts = [c for c in store.puts() if c[1] == HOLD_KEY]
    assert held_puts == [("put", HOLD_KEY, None, True)], (
        "the hold canary must carry a hold and NO retention, as a sample does")


def test_the_production_accounts_prove_the_hold_the_way_a_sample_is_held(
        fake_store, monkeypatch):
    """The held PUT and its read-back are the preservation account's, the
    two steps `preserve()` takes; its DELETE is refused on its own policy,
    by design, so the DELETE moves to MINIO_* on the same store. The held
    version is still there afterwards, and the next probe reuses it."""
    template, stores = fake_store
    store = template["store"]
    template["by_access"]["p-key"] = p = _production_preservation(
        monkeypatch, store)
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is True, check
    assert ("legal hold PROVEN: a DELETE of hold canary "
            f"{HOLD_KEY}") in check.evidence
    assert ("written by this probe with PRESERVE_ACCESS_KEY, as a rejected "
            "sample is") in check.evidence
    assert ("PRESERVE_ACCESS_KEY may not delete a version (AccessDenied), so "
            "the DELETE was made with MINIO_ACCESS_KEY") in check.evidence
    (_, _, retention, hold), = [c for c in p.puts() if c[1] == HOLD_KEY]
    assert retention is None and hold is True
    assert not [c for c in store.puts() if c[1] == HOLD_KEY], (
        "the held PUT must be the preservation account's own")
    held = store._b.latest[HOLD_KEY]
    assert ("remove", HOLD_KEY, held) in p.removes()
    assert ("remove", HOLD_KEY, held) in store.removes()
    assert held in store.versions and held in store.holds
    assert [s[1][1] for s in stores] == ["p-key", "evidence-key"]

    again = readiness._preservation_bucket_object_lock(None)
    assert again.ok is True, again
    assert len([c for c in p.puts() if c[1] == HOLD_KEY]) == 1, (
        "a second held canary was written instead of reusing the first")
    assert "legal hold ON and no retention, reused" in again.evidence


def test_a_hold_the_store_does_not_keep_fails(fake_store):
    """`preserve()` refuses a rejection whose hold does not read back ON;
    the canary is held to the same read."""
    template, _ = fake_store
    template["store"] = FakeStore(records_hold=False)
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is False
    assert "reported no hold on it" in check.evidence
    assert "every rejection is refused" in check.evidence


def test_an_account_that_may_not_set_a_hold_is_not_proven_around(
        fake_store, monkeypatch):
    """The held PUT is what every rejection does. If the preservation
    account may not make it, a hold proven with the root credential would
    be green over a deployment that refuses every rejection."""
    template, _ = fake_store
    store = template["store"]
    p = _production_preservation(monkeypatch, store)
    p.hold_put_denied = True
    template["by_access"]["p-key"] = p
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is False
    assert ("PRESERVE_ACCESS_KEY may not write an object under a legal hold "
            "(s3:PutObjectLegalHold)") in check.evidence
    assert "every rejection is refused rather than preserved" in check.evidence
    assert "may set and read a hold" in check.action
    assert not [c for c in store.puts() if c[1] == HOLD_KEY], (
        "the hold was proven around the account that has to set it")


def test_a_hold_nobody_here_may_delete_cannot_be_proven(fake_store):
    """A store whose refusal of a held delete is a bare AccessDenied gives
    no lock words, so it counts as a permissions refusal, never as proof,
    and with no other credential for that store the check says so."""
    template, _ = fake_store
    template["store"] = FakeStore(hold_refusal=DENIED)
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is False
    assert "MINIO_ACCESS_KEY may not delete a version (AccessDenied)" in \
        check.evidence
    assert "the hold cannot be proven from here" in check.evidence
    assert "out of band" in check.action


def test_a_lifted_hold_canary_is_replaced_and_the_held_one_is_never_tidied(
        fake_store):
    """A hold canary whose hold reads OFF (lifted by hand) is not tested,
    because a DELETE of it would succeed on an honest store: a fresh held
    one is written. And the tidy, which lists only the WORM canary's key,
    never touches a held canary however old."""
    template, _ = fake_store
    store = template["store"]
    lifted = store.seed(None, NOW - timedelta(days=30), key=HOLD_KEY)
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is True, check
    assert ("remove", HOLD_KEY, lifted) not in store.removes()
    fresh = store._b.latest[HOLD_KEY]
    assert fresh != lifted and fresh in store.holds

    old_held = store.seed(None, NOW - timedelta(days=40), key=HOLD_KEY,
                          hold=True)
    store.seed(_compliance(-24 * 9), NOW - timedelta(days=9))
    ok, _ = readiness.prove_write_once(store, "b", now=NOW)
    assert ok is True
    assert {c[1] for c in store.calls if c[0] == "list"} == {KEY}
    assert not [c for c in store.removes() if c[2] == old_held]
    assert old_held in store.versions


def test_the_hold_proof_keeps_to_the_budget():
    ticks = {"t": 0.0}
    store = FakeStore(on_call=lambda: ticks.__setitem__("t", ticks["t"] + 4.0))
    proof = readiness._prove_hold(
        store, "b", writer="PRESERVE_ACCESS_KEY",
        deleters=[("PRESERVE_ACCESS_KEY", lambda: store)],
        deadline=readiness._PROBE_BUDGET_S, clock=lambda: ticks["t"])
    assert proof.ok is False
    assert f"within {readiness._PROBE_BUDGET_S:g}s" in proof.evidence
    assert len(store.calls) <= 3, store.calls



@pytest.fixture(autouse=True)
def _no_screening_list(monkeypatch):
    """These checks are called with conn=None; since F13 the bucket
    probe and the policy row also ask whether a screening list is active.
    None is, here (2026-09-25)."""
    monkeypatch.setattr(readiness, "_screening_active", lambda _conn: False)
    monkeypatch.setattr(readiness, "_screening_clause",
                        lambda _conn: "Screening: no hash list is loaded.")


def test_a_destroy_deployment_is_not_probed_and_says_so(fake_store, monkeypatch):
    _, stores = fake_store
    monkeypatch.setenv(readiness.DISPOSITION_ENV, "destroy")
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is True
    assert "not probed" in check.evidence and "destroy" in check.evidence
    assert stores == [], "a deployment that preserves nothing was probed"


def test_an_unknown_disposition_fails_by_name(fake_store, monkeypatch):
    monkeypatch.setenv(readiness.DISPOSITION_ENV, "shred")
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is False
    assert readiness.DISPOSITION_ENV in check.evidence
    assert "'shred'" in check.evidence
    assert readiness.DISPOSITION_ENV in check.action


def test_the_secrets_never_reach_the_evidence(fake_store, monkeypatch):
    """The register is the page an operator screenshots into a ticket."""
    template, _ = fake_store
    for store in (FakeStore(), FakeStore(enforces=False),
                  FakeStore(refusal=DENIED), FakeStore(bucket_exists=False)):
        template["store"] = store
        for probe in (readiness._evidence_bucket_object_lock,
                      readiness._preservation_bucket_object_lock):
            check = probe(None)
            assert "evidence-secret" not in check.evidence + check.action
    template["store"] = FakeStore()
    template["by_access"]["p-key"] = _production_preservation(
        monkeypatch, template["store"])
    check = readiness._preservation_bucket_object_lock(None)
    assert check.ok is True, check
    assert "p-secret" not in check.evidence + check.action
    assert "evidence-secret" not in check.evidence + check.action


# ---------------------------------------------------------------------------
# The preservation store is addressed as samples.PreservationStorage does
# ---------------------------------------------------------------------------

_STORE_VARS = ("PRESERVE_ENDPOINT", "PRESERVE_ACCESS_KEY", "PRESERVE_SECRET_KEY",
               "PRESERVE_SECURE", "PRESERVE_BUCKET", "SAMPLE_ENDPOINT",
               "SAMPLE_ACCESS_KEY", "SAMPLE_SECRET_KEY", "SAMPLE_SECURE",
               "MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY",
               "MINIO_SECURE")


@pytest.mark.parametrize("env, expect", [
    # The dev stack: nothing but MINIO_*, and MINIO_SECURE does NOT carry
    # over. The verifier caught this copy reading it on 2026-09-22 while
    # the store does not, so the probe could pass over TLS while every
    # rejection connected in plain text.
    ({"MINIO_ENDPOINT": "m:9000", "MINIO_ACCESS_KEY": "ma",
      "MINIO_SECRET_KEY": "ms", "MINIO_SECURE": "true"},
     ("m:9000", "ma", "ms", False, "noctornal-preserved")),
    ({"MINIO_ENDPOINT": "m:9000", "MINIO_ACCESS_KEY": "ma",
      "MINIO_SECRET_KEY": "ms", "SAMPLE_ACCESS_KEY": "sa",
      "SAMPLE_SECRET_KEY": "ss", "SAMPLE_SECURE": "TRUE"},
     ("m:9000", "sa", "ss", True, "noctornal-preserved")),
    ({"PRESERVE_ENDPOINT": "p:9000", "PRESERVE_ACCESS_KEY": "pa",
      "PRESERVE_SECRET_KEY": "ps", "PRESERVE_SECURE": "false",
      "SAMPLE_SECURE": "true", "PRESERVE_BUCKET": "held",
      "MINIO_ENDPOINT": "m:9000"},
     ("p:9000", "pa", "ps", False, "held")),
    # An empty value is unset, as the store's `pick` reads it.
    ({"PRESERVE_ENDPOINT": "", "SAMPLE_ENDPOINT": "s:9000",
      "PRESERVE_ACCESS_KEY": "pa", "PRESERVE_SECRET_KEY": "ps",
      "PRESERVE_BUCKET": ""},
     ("s:9000", "pa", "ps", False, "noctornal-preserved")),
])
def test_the_preservation_store_is_addressed_as_the_store_addresses_it(
        monkeypatch, env, expect):
    """The contract, stated here so it holds in a tree without the store,
    and compared against `samples.PreservationStorage` itself wherever that
    class exists, so the two cannot drift after the merge."""
    for var in _STORE_VARS:
        monkeypatch.delenv(var, raising=False)
    for var, value in env.items():
        monkeypatch.setenv(var, value)
    s = readiness.preservation_store_settings()
    assert (s.endpoint[1], s.access[1], s.secret[1], s.secure, s.bucket) == expect

    from noctornal_api import samples
    store_cls = getattr(samples, "PreservationStorage", None)
    if store_cls is not None:
        store = store_cls()
        client = store._client
        assert store.bucket == s.bucket
        assert client._base_url.host == s.endpoint[1]
        assert client._base_url.is_https is s.secure
        assert client._provider.retrieve().access_key == s.access[1]


@pytest.mark.parametrize("raw", [None, "", "  ", "preserve", " Destroy ",
                                 "DESTROY", "shred"])
def test_the_disposition_is_read_as_the_store_reads_it(monkeypatch, raw):
    if raw is None:
        monkeypatch.delenv(readiness.DISPOSITION_ENV, raising=False)
    else:
        monkeypatch.setenv(readiness.DISPOSITION_ENV, raw)
    disposition, _ = readiness.rejected_sample_disposition()
    expect = {None: "preserve", "": "preserve", "  ": "preserve",
              "preserve": "preserve", " Destroy ": "destroy",
              "DESTROY": "destroy", "shred": None}[raw]
    assert disposition == expect

    from noctornal_api import samples
    setting = getattr(samples, "disposition_setting", None)
    if setting is not None:
        assert setting()[0] == disposition


# ---------------------------------------------------------------------------
# docs/16 L1: the evidence states what a rejection does
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value, expect", [
    (None, "PRESERVED into noctornal-preserved"),
    ("preserve", "PRESERVED into noctornal-preserved"),
    ("  Destroy ", "DESTROYED"),
    ("shred", "neither preserve nor destroy"),
])
def test_the_l1_evidence_states_the_rejected_sample_disposition(
        monkeypatch, value, expect):
    monkeypatch.delenv("PRESERVE_BUCKET", raising=False)
    if value is None:
        monkeypatch.delenv(readiness.DISPOSITION_ENV, raising=False)
    else:
        monkeypatch.setenv(readiness.DISPOSITION_ENV, value)
    for declared in (True, False):
        if declared:
            monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-1")
            monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "dp@example.test")
        else:
            monkeypatch.delenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", raising=False)
        check = readiness._prohibited_content_policy(None)
        assert expect in check.evidence, (declared, check.evidence)
        # The verdict stays samples.policy_declared's: one reader per fact.
        assert check.ok is declared


# ---------------------------------------------------------------------------
# Live: the real probe against the dev MinIO
# ---------------------------------------------------------------------------

needs_minio = pytest.mark.skipif(
    not os.environ.get("MINIO_ENDPOINT"),
    reason="MINIO_ENDPOINT not set; the live WORM probe is gated")


@needs_minio
def test_the_dev_minio_proves_write_once_on_both_buckets(monkeypatch):
    """Against the store the product runs on. Both buckets are created
    WITH object lock by the dev compose (the preservation bucket since
    2026-09-22), so a failure here is a store or bucket that does not
    refuse, reported with the store's own words."""
    monkeypatch.delenv(readiness.DISPOSITION_ENV, raising=False)
    for probe in (readiness._evidence_bucket_object_lock,
                  readiness._preservation_bucket_object_lock):
        first = probe(None)
        assert first.ok is True, first
        assert "refused" in first.evidence
        assert "not tidied" not in first.evidence, first.evidence
        # The mode the evidence names was READ from the store, never
        # merely requested (final review C10).
        assert "not confirmed" not in first.evidence, first.evidence
        # And a second probe reuses the canary rather than locking another.
        second = probe(None)
        assert second.ok is True, second
        assert "reused" in second.evidence, second.evidence
    # Final review C9: the preservation bucket's hold, proven on the real
    # store, and the held canary reused rather than one held per probe.
    assert "legal hold PROVEN" in first.evidence, first.evidence
    assert "legal hold ON and no retention, reused" in second.evidence, \
        second.evidence


@needs_minio
def test_the_dev_minio_names_a_bucket_that_does_not_exist():
    """The verifier's missing-bucket case, against the real store: a HEAD
    on a bucket that is not there, so nothing is created."""
    client = readiness._object_store_client(
        os.environ["MINIO_ENDPOINT"], os.environ.get("MINIO_ACCESS_KEY", ""),
        os.environ.get("MINIO_SECRET_KEY", ""),
        os.environ.get("MINIO_SECURE", "false").lower() == "true")
    ok, evidence = readiness.prove_write_once(client, "noctornal-g05-no-such-bucket")
    assert ok is False
    assert evidence.startswith("the bucket does not exist (NoSuchBucket)"), evidence

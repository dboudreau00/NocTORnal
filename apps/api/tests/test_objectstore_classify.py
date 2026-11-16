"""How a refused delete of one version is read, per profile (`objectstore/classify.py`).

The minio profile keeps the code-and-message rule the bundled MinIO was measured with, and makes no extra
call. The s3 profile never reads a message, because AWS and Ceph answer a delete of a locked version with the
same `AccessDenied` a policy denial gets: it reads the version's retention and legal hold back, and calls it a
lock only when one is really there. The permission control (a keyless DELETE of a key nothing holds, and the
removal of its marker by version id) is what lets the register credit a refusal at all on that profile.

No network: a stand-in store.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from noctornal_api.objectstore import classify
from noctornal_api.objectstore.errors import StoreRefusal, StoreUnreachable, refusal
from noctornal_api.objectstore.types import (
    COMPLIANCE,
    KeylessDelete,
    RetentionInfo,
    VersionInfo,
)

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
AWS_LOCKED = ("AccessDenied", "Access Denied")
WORM = ("InvalidRequest", "Object is WORM protected and cannot be overwritten")


class _State:
    """A version's lock state as a store reports it, and what it answers a delete with."""

    host = "stub:9000"

    def __init__(self, profile="s3", *, retention=None, hold=False, retention_error=None,
                 hold_error=None, answer=AWS_LOCKED, versions=("v1",)):
        self.profile = profile
        self.retention, self.hold = retention, hold
        self.retention_error, self.hold_error = retention_error, hold_error
        self.answer = answer
        self.versions = list(versions)
        self.reads = 0
        self.removed: list[str] = []

    def get_retention(self, bucket, key, version_id):
        self.reads += 1
        if self.retention_error is not None:
            raise self.retention_error
        return self.retention

    def legal_hold_is_on(self, bucket, key, version_id=None):
        self.reads += 1
        if self.hold_error is not None:
            raise self.hold_error
        return self.hold

    def list_versions(self, bucket, prefix):
        return iter([VersionInfo(key="k", version_id=v, is_delete_marker=False,
                                 is_latest=False, last_modified=None) for v in self.versions])

    def delete_version(self, bucket, key, version_id):
        raise refusal(*self.answer)


def _locked(hours=24):
    return RetentionInfo(COMPLIANCE, NOW + timedelta(hours=hours))


def _classify(store, exc):
    return classify.classify_version_delete_refusal(store, "b", "k", "v1", exc, NOW)


def test_the_minio_profile_keeps_todays_rule_unchanged():
    store = _State("minio", retention=_locked())
    assert _classify(store, refusal(*WORM)) == classify.LOCKED
    assert _classify(store, refusal(*AWS_LOCKED)) == classify.DENIED
    assert _classify(store, refusal("InternalError", "oops")) == classify.UNKNOWN
    assert store.reads == 0, "the minio profile makes no extra call"


def test_an_aws_style_access_denied_on_a_locked_version_is_a_lock_by_state():
    assert _classify(_State(retention=_locked()), refusal(*AWS_LOCKED)) == classify.LOCKED


def test_an_access_denied_with_no_lock_state_is_a_denial_not_a_lock():
    assert _classify(_State(), refusal(*AWS_LOCKED)) == classify.DENIED


def test_the_s3_profile_never_reads_message_text():
    """MinIO's words for a lock, on a version with no lock: a denial on the s3 profile."""
    assert _classify(_State(), refusal(*WORM)) == classify.DENIED
    words = refusal("AccessDenied", "object lock retention WORM")
    assert _classify(_State(), words) == classify.DENIED


def test_a_state_read_that_is_itself_denied_is_not_called_a_lock():
    store = _State(retention_error=refusal(*AWS_LOCKED))
    assert _classify(store, refusal(*AWS_LOCKED)) == classify.DENIED
    store = _State(retention_error=StoreUnreachable("timed out", never_reached=False))
    assert _classify(store, refusal(*AWS_LOCKED)) == classify.UNKNOWN
    store = _State(hold_error=refusal(*AWS_LOCKED))
    assert _classify(store, refusal(*AWS_LOCKED)) == classify.DENIED


def test_a_hold_with_no_retention_is_locked():
    assert _classify(_State(hold=True), refusal(*AWS_LOCKED)) == classify.LOCKED


def test_a_lapsed_retention_is_not_locked():
    assert _classify(_State(retention=_locked(hours=-1)), refusal(*AWS_LOCKED)) == classify.DENIED


def test_a_refusal_that_cannot_be_a_lock_stays_unknown_on_the_s3_profile():
    store = _State(retention=_locked())
    assert _classify(store, refusal("InternalError", "oops")) == classify.UNKNOWN
    assert store.reads == 0


def test_delete_all_versions_records_locked_on_an_aws_style_store():
    from noctornal_api.objectstore.versions import delete_every_version
    result = delete_every_version(_State(retention=_locked(hours=24 * 365)), "b", "k")
    assert result.versions_locked == 1 and result.outcome == "LOCKED_UNTIL_RETENTION"


def test_delete_all_versions_still_raises_on_a_policy_denial():
    from noctornal_api.objectstore.versions import delete_every_version
    with pytest.raises(StoreRefusal) as info:
        delete_every_version(_State(), "b", "k")
    assert info.value.code == "AccessDenied"


class _Control:
    """A versioned bucket for the permission control."""

    profile = "s3"

    def __init__(self, *, object_denied=False, version_denied=False, marker=True,
                 id_in_answer=True):
        self.object_denied, self.version_denied = object_denied, version_denied
        self.marker, self.id_in_answer = marker, id_in_answer
        self.markers: list[str] = []

    def delete_key(self, bucket, key):
        if self.object_denied:
            raise refusal(*AWS_LOCKED)
        if not self.marker:
            return KeylessDelete(delete_marker=False, version_id=None)
        self.markers.append("m1")
        if not self.id_in_answer:
            return KeylessDelete(delete_marker=None, version_id=None)
        return KeylessDelete(delete_marker=True, version_id="m1")

    def list_versions(self, bucket, prefix):
        return iter([VersionInfo(key=prefix, version_id=m, is_delete_marker=True,
                                 is_latest=True, last_modified=None) for m in self.markers])

    def delete_version(self, bucket, key, version_id):
        if self.version_denied:
            raise refusal(*AWS_LOCKED)
        self.markers.remove(version_id)


def test_the_delete_control_passes_and_leaves_nothing():
    for store in (_Control(), _Control(id_in_answer=False)):
        assert classify.delete_control(store, "b").outcome == classify.CONTROL_ALLOWED
        assert store.markers == []


def test_the_delete_control_says_which_step_was_denied():
    result = classify.delete_control(_Control(object_denied=True), "b")
    assert (result.outcome, result.step) == (classify.CONTROL_DENIED, "delete an object")
    result = classify.delete_control(_Control(version_denied=True), "b")
    assert (result.outcome, result.step) == (classify.CONTROL_DENIED, "delete a version")


def test_a_store_that_adds_no_marker_cannot_run_the_control():
    assert classify.delete_control(_Control(marker=False), "b").outcome == classify.CONTROL_NO_MARKER

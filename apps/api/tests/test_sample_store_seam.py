"""The preservation store's refused held PUT, read through the object store seam.

A held PUT into a bucket with no object lock is refused, and the sentence then has to say the bucket must be
made again with a lock. That used to be decided by the substring "lock" in the store's message, which is not a
portable signal: AWS and Ceph answer a policy denial and a lock problem in the same words. The bucket's own
account of itself (`bucket_capabilities`, advisory) decides now, and the codes a store gives an unlocked bucket
only where it will not say. On the s3 profile the sentence names no MinIO command.

No network and no database: the store is a stand-in.
"""
from __future__ import annotations

import pytest

from noctornal_api.objectstore.errors import refusal
from noctornal_api.objectstore.types import BucketCaps


class _RefusingHeldPut:
    host = "stub:9000"

    def __init__(self, profile, exc, lock):
        self.profile, self.exc, self.lock = profile, exc, lock

    def put(self, bucket, key, data, **_kw):
        raise self.exc

    def bucket_capabilities(self, bucket):
        if isinstance(self.lock, Exception):
            raise self.lock
        return BucketCaps(True, "Enabled", self.lock, None)


def _preserve(profile, exc, lock):
    from noctornal_api.samples import PreservationStorage, SampleError
    pres = PreservationStorage.__new__(PreservationStorage)
    pres.bucket = "noctornal-preserved"
    pres.store = _RefusingHeldPut(profile, exc, lock)
    with pytest.raises(SampleError) as info:
        pres.preserve("preserved/aa/x", b"ciphertext")
    return str(info.value)


def test_the_lock_hint_comes_from_the_buckets_own_account_not_a_message():
    # A denial whose message happens to say "lock", on a bucket that reports its lock: a refusal, no hint.
    text = _preserve("minio", refusal("AccessDenied", "Access Denied by object lock policy"), True)
    assert "refused the copy" in text and "created with object lock" not in text, text
    # A bucket that reports no lock: the hint, whatever the store's words.
    text = _preserve("minio", refusal("AccessDenied", "Access Denied."), False)
    assert "created with object lock (mc mb --with-lock)" in text, text
    # A store that will not say: the codes an unlocked bucket is given decide, as before.
    unknown = refusal("AccessDenied", "Access Denied.")
    text = _preserve("minio", refusal("InvalidRequest", "Bucket is missing ObjectLockConfiguration"),
                     unknown)
    assert "created with object lock" in text, text
    text = _preserve("minio", refusal("AccessDenied", "Access Denied."), None)
    assert "refused the copy" in text, text


def test_the_s3_profile_names_no_mc_command():
    text = _preserve("s3", refusal("InvalidRequest", "no lock"), False)
    assert "mc mb" not in text, text
    assert "object lock enabled and versioning on" in text and "docs/" not in text, text


def test_a_refusal_is_still_a_refusal_and_not_an_unanswered_put():
    """The store answered, so nothing was written: a SampleError, never the 'a copy may exist' failure."""
    text = _preserve("s3", refusal("AccessDenied", "Access Denied."), True)
    assert "may exist" not in text, text
    assert "refused the copy (AccessDenied: Access Denied.)" in text, text

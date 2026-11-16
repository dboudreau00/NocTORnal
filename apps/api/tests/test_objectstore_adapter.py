"""The minio SDK adapter (`objectstore/_minio_sdk.py`), the one module that imports minio.

The first half needs no store: it swaps the SDK client for a stub and holds the translation of every kind
of failure at the boundary (a refusal keeps the store's code, message and status; a missing object and a
missing bucket are their own refusals; a transport failure says whether the request can have reached the
store; an answer that is not S3 is neither), including the failures a lazy listing raises part way through.
It also holds that the caller's pool, the region and the addressing reach the client unchanged.

The second half runs against the development MinIO (gated on MINIO_ENDPOINT, as every live test here is)
and writes nothing that is locked: plain objects in the unlocked samples bucket, and on the locked evidence
bucket only a delete marker for a key nothing holds, removed again by its version id.

This file is the one test allowed to import minio (`test_objectstore_boundary.py`).
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest
import urllib3
from minio.error import InvalidResponseError, S3Error, ServerError

from noctornal_api.objectstore import errors, pools, settings
from noctornal_api.objectstore.store import open_store


def _settings(**extra: str) -> settings.StoreSettings:
    env = {"OBJECT_STORE_ENDPOINT": "127.0.0.1:1", "OBJECT_STORE_ACCESS_KEY": "a",
           "OBJECT_STORE_SECRET_KEY": "not-a-real-one", **extra}
    return settings.resolve("evidence", env)


class _Response:
    def __init__(self, status):
        self.status = status


def _s3(code, message, status=403):
    return S3Error(response=_Response(status), code=code, message=message,
                   resource="/b/k", request_id="1", host_id="1",
                   bucket_name="b", object_name="k")


class _Raising:
    """Every SDK method raises `exc`; `list_objects` raises it on the first step."""

    def __init__(self, exc):
        self.exc = exc

    def list_objects(self, *args, **kwargs):
        def pages():
            raise self.exc
            yield  # pragma: no cover
        return pages()

    def __getattr__(self, name):
        def call(*args, **kwargs):
            raise self.exc
        return call


def _store_raising(exc):
    store = open_store(_settings())
    store._client = _Raising(exc)
    return store


@pytest.mark.parametrize("exc, cls, code, status", [
    (_s3("AccessDenied", "Access Denied."), errors.StoreRefusal, "AccessDenied", 403),
    (_s3("InvalidRequest", "Object is WORM protected", 400), errors.StoreRefusal,
     "InvalidRequest", 400),
    (_s3("NoSuchKey", "Object does not exist", 404), errors.ObjectMissing, "NoSuchKey", 404),
    (_s3("NoSuchVersion", "nope", 404), errors.ObjectMissing, "NoSuchVersion", 404),
    (_s3("NoSuchBucket", "Bucket does not exist", 404), errors.BucketMissing,
     "NoSuchBucket", 404),
])
def test_a_store_refusal_keeps_its_code_message_and_status(exc, cls, code, status):
    store = _store_raising(exc)
    for call in (lambda: store.get("b", "k"), lambda: store.head("b", "k"),
                 lambda: store.delete_version("b", "k", "v1"),
                 lambda: store.put("b", "k", b"x"),
                 lambda: list(store.list_versions("b", "k"))):
        with pytest.raises(cls) as info:
            call()
        assert type(info.value) is cls
        assert (info.value.code, info.value.message, info.value.status) == (
            code, exc.message, status)
        assert "request_id" not in str(info.value)


def test_a_refused_connection_is_unreachable_and_never_reached():
    inner = urllib3.exceptions.NewConnectionError(None, "refused")
    store = _store_raising(urllib3.exceptions.MaxRetryError(None, "/b/k", reason=inner))
    with pytest.raises(errors.StoreUnreachable) as info:
        store.put("b", "k", b"x", retain_until=None)
    assert info.value.never_reached is True
    assert errors.did_not_answer(info.value)


def test_a_read_that_timed_out_may_have_reached_the_store():
    store = _store_raising(urllib3.exceptions.ReadTimeoutError(None, "/b/k", "timed out"))
    with pytest.raises(errors.StoreUnreachable) as info:
        store.get("b", "k")
    assert info.value.never_reached is False


@pytest.mark.parametrize("exc", [
    ServerError("server failed with HTTP status code 503", 503),
    InvalidResponseError(502, "text/html", "<html>Bad Gateway</html>"),
], ids=lambda exc: type(exc).__name__)
def test_an_answer_that_is_not_s3_is_a_bad_answer(exc):
    store = _store_raising(exc)
    with pytest.raises(errors.StoreBadAnswer) as info:
        store.head("b", "k")
    assert info.value.status in (503, 502)
    assert not errors.did_not_answer(info.value)


def test_a_listing_translates_what_it_raises_part_way_through():
    """The SDK's listing is lazy: a reset arrives on a later step, inside the caller's loop."""
    reset = urllib3.exceptions.ProtocolError("aborted", ConnectionResetError(104, "reset"))
    store = _store_raising(reset)
    listing = store.list_versions("b", "k")
    with pytest.raises(errors.StoreUnreachable):
        next(listing)


def test_a_defect_is_not_dressed_as_a_store_answer():
    store = _store_raising(ValueError("a bug, not a store"))
    with pytest.raises(ValueError):
        store.head("b", "k")


def test_a_delete_that_names_no_version_is_never_a_version_delete():
    store = open_store(_settings())
    with pytest.raises(ValueError):
        store.delete_version("b", "k", None)


def test_the_callers_pool_region_and_addressing_reach_the_client():
    pool = pools.bounded_http(resend_writes=False)
    store = open_store(_settings(OBJECT_STORE_REGION="eu-west-2",
                                 OBJECT_STORE_ADDRESSING="virtual"), http=pool)
    client = store._client
    assert client._http is pool
    assert client._base_url.region == "eu-west-2"
    assert client._base_url.virtual_style_flag is True
    path = open_store(_settings(OBJECT_STORE_ADDRESSING="path"))
    assert path._client._base_url.virtual_style_flag is False
    # No region asked for, none passed: the SDK keeps its own rule.
    assert open_store(_settings())._client._base_url.region is None


def test_the_store_says_which_profile_and_host_and_never_a_key():
    store = open_store(_settings(NOCTORNAL_OBJECT_STORE="s3"))
    assert (store.profile, store.host) == ("s3", "127.0.0.1:1")
    assert "not-a-real-one" not in repr(store)


def test_the_sdk_still_has_the_request_method_delete_key_reads():
    """`delete_key` reads the DELETE's own answer through the SDK's request method, because
    `remove_object` returns nothing. A pin bump that removed it must fail here, not in a purge."""
    import inspect

    from minio import Minio
    params = inspect.signature(Minio._execute).parameters
    assert list(params)[:4] == ["self", "method", "bucket_name", "object_name"]


# ---------------------------------------------------------------------------
# Live, against the development MinIO
# ---------------------------------------------------------------------------

needs_minio = pytest.mark.skipif(
    not os.environ.get("MINIO_ENDPOINT"),
    reason="MINIO_ENDPOINT not set; the live adapter test is gated")


@needs_minio
def test_the_live_store_puts_reads_lists_and_deletes_in_an_unlocked_bucket():
    s = settings.resolve("sample")
    store = open_store(s, http=pools.bounded_http())
    key = f"_itest-adapter/{uuid4()}"
    written = store.put(s.bucket, key, b"adapter")
    assert store.get(s.bucket, key, version_id=written.version_id) == b"adapter"
    info = store.head(s.bucket, key)
    assert info.size == len(b"adapter")
    listed = [v for v in store.list_versions(s.bucket, key) if v.key == key]
    assert len(listed) == 1 and listed[0].is_latest and not listed[0].is_delete_marker
    gone = store.delete_key(s.bucket, key)
    # An unversioned bucket removes the object: no marker hides it.
    assert gone.delete_marker is False
    with pytest.raises(errors.ObjectMissing):
        store.head(s.bucket, key)
    with pytest.raises(errors.BucketMissing):
        store.head(f"noctornal-no-such-bucket-{uuid4().hex[:8]}", key)


@needs_minio
def test_a_keyless_delete_on_a_versioned_bucket_reports_the_marker_it_added():
    """What the working-bucket delete and the s3 profile's permission control both read, measured on the
    store the product runs on, in the preservation bucket (versioned, locked, no default retention, so an
    object written without a hold or a retention can be removed again): a DELETE naming no version of a key
    that holds an object hides it behind a marker, says so in its answer and names the marker's version,
    and the marker and the object each come off by their version ids.

    Measured as well: the same DELETE of a key that holds nothing adds no marker on this store, which is
    why the control is made on the canary's own key and never on a fresh one (docs/22)."""
    s = settings.resolve("preserve")
    store = open_store(s, http=pools.bounded_http(resend_writes=False))
    key = f"_itest-adapter/{uuid4()}"
    written = store.put(s.bucket, key, b"plain")
    done = store.delete_key(s.bucket, key)
    assert done.delete_marker is True, done
    listed = [v for v in store.list_versions(s.bucket, key) if v.key == key]
    markers = [v for v in listed if v.is_delete_marker]
    assert [m.version_id for m in markers] == [done.version_id]
    assert markers[0].is_latest
    assert store.get(s.bucket, key, version_id=written.version_id) == b"plain"
    store.delete_version(s.bucket, key, done.version_id)
    store.delete_version(s.bucket, key, written.version_id)
    assert [v for v in store.list_versions(s.bucket, key) if v.key == key] == []

    absent = f"_itest-adapter/{uuid4()}"
    nothing = store.delete_key(s.bucket, absent)
    assert nothing.delete_marker is False, nothing
    assert [v for v in store.list_versions(s.bucket, absent) if v.key == absent] == []

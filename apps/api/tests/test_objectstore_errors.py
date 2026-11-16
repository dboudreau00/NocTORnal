"""The store's answers in the seam's own words (`objectstore/errors.py`).

A caller has to tell four things apart: a refusal (the store said no, in its own code), a missing object or
bucket (a refusal with a meaning), a store that never answered (and whether the request can have reached it
at all), and an answer that is not S3. These tests pin how each is told, because the upload route, the
purge and the readiness register each decide on it. No network.
"""
from __future__ import annotations

import socket

import pytest
import urllib3

from noctornal_api.objectstore import errors


def test_a_denial_is_not_a_missing_object():
    denied = errors.refusal("AccessDenied", "Access Denied.", status=403)
    assert type(denied) is errors.StoreRefusal
    assert not isinstance(denied, errors.ObjectMissing)
    assert (denied.code, denied.message, denied.status) == (
        "AccessDenied", "Access Denied.", 403)


@pytest.mark.parametrize("code, cls", [
    ("NoSuchKey", errors.ObjectMissing),
    ("NoSuchVersion", errors.ObjectMissing),
    ("NoSuchObject", errors.ObjectMissing),
    ("NoSuchBucket", errors.BucketMissing),
    ("InvalidRequest", errors.StoreRefusal),
    ("ObjectLockConfigurationNotFoundError", errors.StoreRefusal),
])
def test_only_no_such_key_object_version_are_missing(code, cls):
    made = errors.refusal(code, "m")
    assert type(made) is cls
    assert isinstance(made, errors.StoreRefusal)


def test_a_refusal_says_code_and_message_and_never_the_key():
    """minio's own error quoted the resource and the object name; a key that contains a lock word must not
    reach a classifier that reads the text."""
    exc = errors.refusal("AccessDenied", "Access Denied.", operation="delete_version")
    assert str(exc) == "AccessDenied: Access Denied."
    assert str(errors.refusal("NoSuchKey")) == "NoSuchKey"


def _refused() -> BaseException:
    inner = urllib3.exceptions.NewConnectionError(None, "refused")
    return urllib3.exceptions.MaxRetryError(None, "/b/k", reason=inner)


@pytest.mark.parametrize("raw, reached", [
    (_refused(), False),
    (ConnectionRefusedError(111, "refused"), False),
    (socket.gaierror(-2, "Name or service not known"), False),
    (urllib3.exceptions.ConnectTimeoutError(None, "connect timed out"), False),
    (urllib3.exceptions.ReadTimeoutError(None, "/b/k", "read timed out"), True),
    (urllib3.exceptions.ProtocolError("aborted", ConnectionResetError(104, "reset")), True),
])
def test_a_refused_connection_is_never_reached_and_a_read_timeout_is_not(raw, reached):
    assert errors.never_reached_by(raw) is (not reached)
    wrapped = errors.StoreUnreachable("x", never_reached=errors.never_reached_by(raw))
    assert errors.never_reached(wrapped) is (not reached)
    assert errors.did_not_answer(wrapped) is True
    # A raw transport error, as a test double raises one, answers the same.
    assert errors.did_not_answer(raw) is True
    assert errors.never_reached(raw) is (not reached)


def test_a_refusal_and_a_bad_answer_were_answered():
    for exc in (errors.refusal("AccessDenied"), errors.refusal("NoSuchBucket"),
                errors.StoreBadAnswer("502 from a proxy", status=502)):
        assert errors.did_not_answer(exc) is False
        assert errors.never_reached(exc) is False
    assert errors.did_not_answer(ValueError("a defect")) is False

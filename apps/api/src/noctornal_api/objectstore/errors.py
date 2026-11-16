"""What went wrong at the store, in words that do not depend on the client library.

Four things can happen to a call, and a caller must be able to tell them apart:

- `StoreRefusal`: the store answered with an S3 error. It keeps the store's own `code` and `message`
  (and the HTTP `status` where there was one), because every classifier in the product reads those, and
  the readiness register quotes them. `ObjectMissing` (NoSuchKey, NoSuchVersion, NoSuchObject) and
  `BucketMissing` (NoSuchBucket) are refusals with a meaning of their own.
- `StoreUnreachable`: no answer came. `never_reached` says whether the request can have reached the
  store at all: a connection refused, a connect timeout or a name that did not resolve sent nothing, so
  nothing was stored; a read timeout or a reset connection may have left the bytes behind.
- `StoreBadAnswer`: something answered that is not an S3 error: a proxy's HTML page, a 5xx with no body.
- Anything else is a defect and is not wrapped.

`str()` of a refusal is `code: message` and never the resource or the key, so an exhibit whose key
contains a word the lock classifier looks for cannot turn a policy denial into a lock
(`evidence.is_retention_refusal`).
"""
from __future__ import annotations

#: What a store answers when nothing is at a key or a version.
MISSING_CODES = frozenset({"NoSuchKey", "NoSuchVersion", "NoSuchObject"})
#: What a store answers when the bucket itself is not there.
BUCKET_MISSING_CODE = "NoSuchBucket"


class StoreError(Exception):
    """Every failure this package reports. `code` is the store's own word, or None where the store gave
    none (an unreachable store)."""

    def __init__(self, detail: str, *, code: str | None = None,
                 message: str | None = None, status: int | None = None,
                 operation: str = "") -> None:
        super().__init__(detail)
        self.code = code
        self.message = message
        self.status = status
        self.operation = operation


class StoreRefusal(StoreError):
    """The store answered with an S3 error."""

    def __init__(self, code: str, message: str | None = None, *,
                 status: int | None = None, operation: str = "") -> None:
        super().__init__(f"{code}: {message}" if message else code, code=code,
                         message=message, status=status, operation=operation)


class ObjectMissing(StoreRefusal):
    """Nothing at the key or the version asked for."""


class BucketMissing(StoreRefusal):
    """The bucket does not exist."""


class StoreUnreachable(StoreError):
    """No answer came. `never_reached` is True only when nothing was sent."""

    def __init__(self, detail: str, *, never_reached: bool,
                 operation: str = "") -> None:
        super().__init__(detail, operation=operation)
        self.never_reached = never_reached


class StoreBadAnswer(StoreError):
    """An answer came and it was not an S3 error: a page from a proxy, a 5xx with nothing in it."""


def refusal(code: str, message: str | None = None, *, status: int | None = None,
            operation: str = "") -> StoreRefusal:
    """The refusal for a store's `code`, as the subclass its meaning calls for. The one constructor, so
    the adapter and every test double build the same thing from the same answer."""
    if code in MISSING_CODES:
        cls: type[StoreRefusal] = ObjectMissing
    elif code == BUCKET_MISSING_CODE:
        cls = BucketMissing
    else:
        cls = StoreRefusal
    return cls(code, message, status=status, operation=operation)


def _transport_classes():
    import urllib3
    return urllib3.exceptions.HTTPError, OSError


def never_reached_by(exc: BaseException) -> bool:
    """Whether a raw transport failure can never have reached the store: a connection refused, a connect
    timeout or a name that did not resolve, anywhere in its chain (urllib3's MaxRetryError keeps what it
    gave up on in `reason`). A read timeout or a reset is not this: the request went out."""
    import socket

    import urllib3

    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, (urllib3.exceptions.NewConnectionError,
                            urllib3.exceptions.ConnectTimeoutError,
                            ConnectionRefusedError, socket.gaierror)):
            return True
        cur = getattr(cur, "reason", None) or cur.__cause__ or cur.__context__
    return False


def did_not_answer(exc: BaseException) -> bool:
    """Whether a call failed because the store did not answer, not because it answered with a refusal.
    A raw transport error counts too, as a test double raises one."""
    if isinstance(exc, StoreUnreachable):
        return True
    if isinstance(exc, StoreError):
        return False
    return isinstance(exc, _transport_classes())


def never_reached(exc: BaseException) -> bool:
    """Whether a failed call can never have reached the store, so nothing was stored."""
    if isinstance(exc, StoreUnreachable):
        return exc.never_reached
    if isinstance(exc, StoreError):
        return False
    return never_reached_by(exc)

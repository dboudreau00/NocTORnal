"""The HTTP pools the object store clients are handed, each bounded for the caller it serves.

The client library's own pool waits five minutes on a connect or a read and retries five times, so one
stalled call could hold a request for about half an hour. These pools give up in seconds. They are the one
place in the product, beside the egress proxy and the pinned client, that opens a connection of its own
(`tests/test_egress_single_exit.py` says why that is allowed): the store is part of the deployment, on its
internal network (docs/17 F41).
"""
from __future__ import annotations

import os

#: Seconds to wait for a TCP connection to the sample or preservation store.
STORE_CONNECT_TIMEOUT_S = 10.0
#: Seconds to wait on any one read from the socket. Per read, not per
#: transfer: a 256 MiB sample streams in many reads, each well inside this.
STORE_READ_TIMEOUT_S = 60.0


def bounded_http(*, resend_writes: bool = True):
    """The HTTP pool the evidence and both sample stores use, which gives up in seconds.

    minio-py's own pool waits five minutes on a connect or a read and retries five times, so one stalled
    call could hold a request for about half an hour. The preserving rejection calls these stores inside a
    transaction that holds the sample's row lock, so the bound matters. It matches
    `readiness._probe_store`, loosened for real transfers.

    Retries: a connection that never opened is retried (nothing was sent). A read that timed out is not:
    the request went out, and retrying a held PUT whose answer was lost writes a second held version that
    nothing can delete. A 5xx answer is retried only where a resend is harmless. For the samples store it
    is (a resent PUT overwrites the same unversioned object, a resent DELETE deletes nothing twice). For
    the preservation store (`resend_writes=False`) only reads are resent: a 502 or 504 can come from a
    proxy after the store took the held PUT, so `preserve()` reports the refusal instead. Certificate
    handling is minio-py's own default, restated because passing a pool replaces it.
    """
    import certifi
    import urllib3

    retry = {"total": 2, "connect": 2, "read": 0, "status": 2,
             "backoff_factor": 0.2, "status_forcelist": [500, 502, 503, 504]}
    if not resend_writes:
        retry["allowed_methods"] = frozenset({"GET", "HEAD"})
    return urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=STORE_CONNECT_TIMEOUT_S,
                                read=STORE_READ_TIMEOUT_S),
        maxsize=10,
        cert_reqs="CERT_REQUIRED",
        ca_certs=os.environ.get("SSL_CERT_FILE") or certifi.where(),
        retries=urllib3.Retry(**retry),
    )

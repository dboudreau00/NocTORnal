"""Final review C7, 2026-09-23: both sample stores give up in seconds.

`SampleStorage` and `PreservationStorage` built their MinIO clients with
minio-py's defaults, a five-minute connect and read timeout and five
retries, so one stalled call could hold a request for about half an hour.
A preserving rejection makes those calls inside a transaction holding the
sample's row lock, and until C7 the working-copy delete also ran while the
audit chain's advisory lock was held, which stalled every audited write in
the deployment behind it.

No network and no database: the clients are only constructed, and what is
read is the pool they were handed.
"""
from __future__ import annotations

import pytest

_VARS = ("SAMPLE_ENDPOINT", "SAMPLE_ACCESS_KEY", "SAMPLE_SECRET_KEY",
         "SAMPLE_SECURE", "PRESERVE_ENDPOINT", "PRESERVE_ACCESS_KEY",
         "PRESERVE_SECRET_KEY", "PRESERVE_SECURE", "MINIO_ENDPOINT",
         "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY")


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    for var in _VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SAMPLE_ENDPOINT", "samples.invalid:9000")
    monkeypatch.setenv("SAMPLE_ACCESS_KEY", "sa")
    monkeypatch.setenv("SAMPLE_SECRET_KEY", "ss")


@pytest.mark.parametrize("which", ["SampleStorage", "PreservationStorage"])
def test_each_store_waits_seconds_not_minutes(which):
    from noctornal_api import samples
    store = getattr(samples, which)()
    pool = store._client._http.connection_pool_kw
    timeout, retries = pool["timeout"], pool["retries"]
    assert timeout.connect_timeout <= 10, timeout
    assert timeout.read_timeout <= 60, timeout
    assert retries.total <= 2, retries


@pytest.mark.parametrize("which", ["SampleStorage", "PreservationStorage"])
def test_a_request_that_went_out_is_never_sent_again(which):
    """A read that timed out means the request reached the store. A retried
    held PUT whose answer was lost writes a second held version that
    nothing can delete, so reads are not retried."""
    from noctornal_api import samples
    store = getattr(samples, which)()
    assert store._client._http.connection_pool_kw["retries"].read == 0


def test_the_preservation_store_never_resends_a_write_on_a_5xx():
    """A 502 or 504 can come from a proxy after the store took the held
    PUT, so a 5xx does not prove nothing was written, and a resent held
    write is a second held version nothing can delete. Only reads are
    resent (final review verifier on C7, 2026-09-23: the stores' docstring
    and docs/11 claimed a 5xx meant nothing had been written)."""
    from noctornal_api import samples
    retries = samples.PreservationStorage()._client._http.connection_pool_kw[
        "retries"]
    for method, status in (("PUT", 502), ("PUT", 504), ("POST", 503)):
        assert not retries.is_retry(method, status), (method, status)
    assert retries.is_retry("GET", 503) and retries.is_retry("HEAD", 502)


def test_the_samples_store_still_resends_on_a_5xx():
    """There a resend is harmless: a PUT overwrites the same unversioned
    object and a DELETE is idempotent, so a transient 5xx is ridden out."""
    from noctornal_api import samples
    retries = samples.SampleStorage()._client._http.connection_pool_kw[
        "retries"]
    for method in ("PUT", "DELETE", "GET"):
        assert retries.is_retry(method, 503), method


def test_certificates_are_still_verified(monkeypatch):
    """Handing minio-py a pool replaces its own, certificate settings
    included, so they are restated rather than lost."""
    from noctornal_api import samples
    monkeypatch.setenv("SAMPLE_SECURE", "true")
    pool = samples.SampleStorage()._client._http.connection_pool_kw
    assert pool["cert_reqs"] == "CERT_REQUIRED"
    assert pool["ca_certs"]

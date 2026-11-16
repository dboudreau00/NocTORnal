"""A store somebody else operates: declared before it is reported green, and kept from AMBER_STRICT and RED until
counsel decides (invariant 8, docs/16 C2, docs/22).

The endpoint is read for what it names, never resolved. The readiness row `object_store_custody_declared` and the
two upload refusals (an exhibit, a sample) are held here; the database-backed halves are in `test_evidence_pg.py`
and `test_samples_pg.py`.
"""
from __future__ import annotations

import pytest

from noctornal_api.objectstore import custody

_STORE_VARS = ("OBJECT_STORE_ENDPOINT", "OBJECT_STORE_ACCESS_KEY", "OBJECT_STORE_SECRET_KEY",
               "MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY",
               "SAMPLE_ENDPOINT", "SAMPLE_ACCESS_KEY", "SAMPLE_SECRET_KEY",
               "PRESERVE_ENDPOINT", "PRESERVE_ACCESS_KEY", "PRESERVE_SECRET_KEY",
               custody.CUSTODY_ENV, custody.COUNSEL_ENV)


@pytest.mark.parametrize("endpoint", [
    "minio:9000", "minio", "localhost:9000", "127.0.0.1:9000", "10.1.2.3:9000",
    "172.16.0.5", "192.168.1.10:443", "[::1]:9000", "[fd00::5]:9000", "169.254.1.1",
    "", "MINIO:9000",
])
def test_a_compose_service_name_is_internal(endpoint):
    assert custody.is_inside(endpoint) is True, endpoint


@pytest.mark.parametrize("endpoint", [
    "s3.amazonaws.com", "s3.eu-west-2.amazonaws.com:443", "objects.vendor.example:443",
    "s3.internal.example", "8.8.8.8:9000", "[2606:4700::1111]:443", "100.64.0.1",
])
def test_an_endpoint_with_a_public_or_dotted_name_is_off_host(endpoint):
    assert custody.is_inside(endpoint) is False, endpoint


def _env(**extra):
    return {"OBJECT_STORE_ENDPOINT": "objects.vendor.example:443", "OBJECT_STORE_ACCESS_KEY": "a",
            "OBJECT_STORE_SECRET_KEY": "not-a-real-one", **extra}


@pytest.mark.parametrize("label", ["AMBER_STRICT", "RED", "red"])
def test_a_vendor_store_refuses_amber_strict_and_red_until_counsel_declares(label):
    refusal = custody.restricted_refusal("evidence", label, _env())
    assert refusal and custody.COUNSEL_ENV in refusal and "never leaves the boundary" in refusal
    assert "vendor.example" not in refusal, "the refusal names no store to the uploader"
    # The operator's custody declaration alone is not counsel's.
    assert custody.restricted_refusal(
        "evidence", label, _env(**{custody.CUSTODY_ENV: "Vendor Ltd, UK, legal@vendor"})) is not None
    assert custody.restricted_refusal(
        "evidence", label, _env(**{custody.COUNSEL_ENV: "counsel memo 2026-14"})) is None


@pytest.mark.parametrize("label", ["CLEAR", "GREEN", "AMBER"])
def test_a_vendor_store_takes_the_labels_that_may_leave(label):
    assert custody.restricted_refusal("evidence", label, _env()) is None


def test_an_internal_store_takes_every_label():
    env = {"MINIO_ENDPOINT": "minio:9000"}
    for label in ("AMBER_STRICT", "RED"):
        assert custody.restricted_refusal("evidence", label, env) is None


def test_each_role_is_read_through_its_own_chain():
    """A sample store of its own on a vendor host is refused for RED while the evidence store is local."""
    env = {"MINIO_ENDPOINT": "minio:9000", "SAMPLE_ENDPOINT": "objects.vendor.example"}
    assert custody.restricted_refusal("evidence", "RED", env) is None
    assert custody.restricted_refusal("sample", "RED", env) is not None
    assert custody.restricted_refusal("preserve", "RED", env) is not None


@pytest.fixture
def clean(monkeypatch):
    for var in _STORE_VARS:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def test_an_off_host_endpoint_fails_until_custody_is_declared(clean):
    from noctornal_api import readiness
    for var, value in _env().items():
        clean.setenv(var, value)
    check = readiness._object_store_custody_declared(None)
    assert check.ok is False
    assert custody.CUSTODY_ENV in check.action
    assert "objects.vendor.example:443" in check.evidence
    assert "refused" in check.evidence and "not-a-real-one" not in check.evidence
    clean.setenv(custody.CUSTODY_ENV, "Vendor Ltd, England and Wales, legal@vendor.example")
    check = readiness._object_store_custody_declared(None)
    assert check.ok is True, check
    assert "Vendor Ltd" in check.evidence and "refused" in check.evidence
    clean.setenv(custody.COUNSEL_ENV, "counsel memo 2026-14")
    check = readiness._object_store_custody_declared(None)
    assert "may hold AMBER_STRICT and RED" in check.evidence


def test_the_bundled_store_passes_without_a_declaration(clean):
    from noctornal_api import readiness
    clean.setenv("MINIO_ENDPOINT", "minio:9000")
    clean.setenv("MINIO_ACCESS_KEY", "a")
    clean.setenv("MINIO_SECRET_KEY", "not-a-real-one")
    check = readiness._object_store_custody_declared(None)
    assert check.ok is True and "inside the deployment (minio:9000)" in check.evidence

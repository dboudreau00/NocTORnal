"""`scripts/object_store_provision.py`: the five buckets made and checked through the S3 API, on any store.

Driven against the in-process store (`objectstore_helpers.FakeS3`), one store shared by every role as one
endpoint would be. The live run of the script is described in docs/22.
"""
from __future__ import annotations

import importlib.util
import io
from pathlib import Path

import pytest
from objectstore_helpers import FakeS3

ROOT = Path(__file__).resolve().parents[3]
SECRET = "not-a-real-store-secret-7f3a"


def _script():
    spec = importlib.util.spec_from_file_location(
        "object_store_provision", ROOT / "scripts" / "object_store_provision.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(store, *argv, **env):
    out = io.StringIO()
    base = {"OBJECT_STORE_ENDPOINT": "objects.example:9000", "OBJECT_STORE_ACCESS_KEY": "runtime-key",
            "OBJECT_STORE_SECRET_KEY": SECRET, **env}
    seen = []

    def store_for(settings):
        seen.append(settings)
        return store
    code = _script().run(list(argv), base, out=out, store_for=store_for)
    return code, out.getvalue(), seen


def _made(store, *, locked=("noctornal-evidence", "noctornal-preserved"),
          plain=("noctornal-raw", "noctornal-collect-raw", "noctornal-samples")):
    for name in locked:
        store.make_bucket(name, object_lock=True)
    for name in plain:
        store.make_bucket(name, object_lock=False)
    return store


def test_check_reports_a_missing_bucket_and_exits_1():
    store = _made(FakeS3(), plain=("noctornal-raw", "noctornal-collect-raw"))
    code, out, _ = _run(store)
    assert code == 1
    assert "noctornal-samples" in out and "does not exist" in out
    assert "noctornal-samples" not in store.buckets, "--check created something"


def test_check_passes_a_correctly_made_set_and_says_it_is_advisory():
    code, out, _ = _run(_made(FakeS3()))
    assert code == 0, out
    assert "advisory" in out and "evidence_bucket_object_lock" in out


def test_check_fails_an_evidence_bucket_with_no_object_lock():
    store = _made(FakeS3(), locked=("noctornal-preserved",),
                  plain=("noctornal-evidence", "noctornal-raw", "noctornal-collect-raw",
                         "noctornal-samples"))
    code, out, _ = _run(store)
    assert code == 1
    [line] = [ln for ln in out.splitlines() if "noctornal-evidence" in ln]
    assert line.startswith("red") and "NO object lock" in line


def test_check_fails_a_samples_bucket_that_has_object_lock():
    """A rejected sample must be destroyable (docs/11), so a locked samples bucket is red."""
    store = _made(FakeS3(), locked=("noctornal-evidence", "noctornal-preserved", "noctornal-samples"),
                  plain=("noctornal-raw", "noctornal-collect-raw"))
    code, out, _ = _run(store)
    assert code == 1
    [line] = [ln for ln in out.splitlines() if "noctornal-samples" in ln]
    assert line.startswith("red") and "must be destroyable" in line


def test_apply_creates_locked_evidence_and_preservation_buckets_and_unlocked_others():
    store = FakeS3()
    code, out, _ = _run(store, "--apply")
    assert code == 0, out
    assert {n: b.lock for n, b in store.buckets.items()} == {
        "noctornal-evidence": True, "noctornal-preserved": True, "noctornal-raw": False,
        "noctornal-collect-raw": False, "noctornal-samples": False}


def test_apply_sets_the_evidence_default_retention_to_compliance_365_days():
    """Equal to EVIDENCE_RETENTION_DAYS' default, as minio-init sets it by hand; the preservation bucket gets
    none, which would keep a sample after counsel lifted its hold."""
    store = FakeS3()
    _run(store, "--apply")
    assert store.buckets["noctornal-evidence"].default_days == 365
    assert store.buckets["noctornal-preserved"].default_days is None
    caps = store.bucket_capabilities("noctornal-evidence")
    assert caps.default_retention.mode == "COMPLIANCE" and caps.default_retention.days == 365


def test_apply_never_alters_an_existing_buckets_lock():
    store = _made(FakeS3(), locked=("noctornal-preserved",),
                  plain=("noctornal-evidence", "noctornal-raw", "noctornal-collect-raw",
                         "noctornal-samples"))
    code, out, _ = _run(store, "--apply")
    assert code == 1
    assert store.buckets["noctornal-evidence"].lock is False
    assert "make the bucket again" in out


def test_apply_in_production_refuses_the_runtime_credential():
    store = FakeS3()
    code, out, seen = _run(store, "--apply", NOCTORNAL_ENV="production")
    assert code == 1 and "OBJECT_STORE_ADMIN_ACCESS_KEY" in out
    assert store.buckets == {} and seen == []
    code, out, seen = _run(store, "--apply", NOCTORNAL_ENV="production",
                           OBJECT_STORE_ADMIN_ACCESS_KEY="admin-key",
                           OBJECT_STORE_ADMIN_SECRET_KEY="not-a-real-admin-secret")
    assert code == 0, out
    assert {s.access_key for s in seen} == {"admin-key"}


def test_the_script_never_prints_a_credential():
    for argv in ((), ("--apply",)):
        _code, out, _ = _run(FakeS3(), *argv, OBJECT_STORE_ADMIN_ACCESS_KEY="admin-key",
                             OBJECT_STORE_ADMIN_SECRET_KEY="not-a-real-admin-secret")
        for value in (SECRET, "runtime-key", "admin-key", "not-a-real-admin-secret"):
            assert value not in out, value


@pytest.mark.parametrize("profile", ["ceph", "gcs"])
def test_an_unknown_profile_is_refused_before_anything_is_asked(profile):
    store = FakeS3()
    code, out, seen = _run(store, "--apply", NOCTORNAL_OBJECT_STORE=profile)
    assert code == 1 and "NOCTORNAL_OBJECT_STORE" in out and seen == []

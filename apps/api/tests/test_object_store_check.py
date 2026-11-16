"""`scripts/object_store_check.py`: the read-only preflight (docs/22), driven against the in-process store.

It prints what the settings resolve to, each bucket's own account and the actions each account needs; with
`--prove` it also runs the register's two write-once proofs. It must never print a key or a secret.
"""
from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path

from objectstore_helpers import FakeS3

ROOT = Path(__file__).resolve().parents[3]
SECRET = "not-a-real-store-secret-7f3a"
ACCESS = "runtime-key-91c2"


def _script():
    spec = importlib.util.spec_from_file_location(
        "object_store_check", ROOT / "scripts" / "object_store_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _made(store):
    for name in ("noctornal-evidence", "noctornal-preserved"):
        store.make_bucket(name, object_lock=True)
    for name in ("noctornal-raw", "noctornal-collect-raw", "noctornal-samples"):
        store.make_bucket(name, object_lock=False)
    return store


def _run(store, *argv, prove_with=None, **env):
    out = io.StringIO()
    base = {"OBJECT_STORE_ENDPOINT": "objects.example:9000", "OBJECT_STORE_ACCESS_KEY": ACCESS,
            "OBJECT_STORE_SECRET_KEY": SECRET, "NOCTORNAL_OBJECT_STORE": "s3",
            "OBJECT_STORE_REGION": "eu-test-1", **env}
    code = _script().run(list(argv), base, out=out, store_for=lambda _s: store, prove_with=prove_with)
    return code, out.getvalue()


def test_the_preflight_prints_the_settings_the_table_and_the_actions():
    code, out = _run(_made(FakeS3()))
    assert code == 0, out
    assert "profile s3, host objects.example:9000, secure false, region eu-test-1, addressing auto" in out
    assert "versioning" in out and "object lock True" in out and "default retention" in out
    assert "advisory" in out and "proofs not run" in out
    assert "s3:PutObjectRetention" in out and "never grant s3:BypassGovernanceRetention" in out


def test_the_preflight_never_prints_a_key_or_a_secret():
    for argv in ((), ("--prove",)):
        _, out = _run(_made(FakeS3()), *argv, prove_with=lambda: [])
        assert SECRET not in out and ACCESS not in out


def test_the_preflight_writes_and_creates_nothing_without_prove():
    store = _made(FakeS3())
    _run(store)
    assert set(store.buckets) == {"noctornal-evidence", "noctornal-preserved", "noctornal-raw",
                                  "noctornal-collect-raw", "noctornal-samples"}
    assert all(not b.objects for b in store.buckets.values()), "the preflight wrote an object"


def test_a_missing_or_unlocked_bucket_exits_1():
    store = FakeS3()
    store.make_bucket("noctornal-evidence", object_lock=False)
    code, out = _run(store)
    assert code == 1
    [line] = [ln for ln in out.splitlines() if "noctornal-evidence" in ln and "exists" in ln]
    assert line.lstrip().startswith("red") and "NO object lock" in line
    assert "does not exist" in out


def test_an_unconfigured_store_exits_1_and_names_the_variable():
    out = io.StringIO()
    code = _script().run([], {}, out=out, store_for=lambda _s: FakeS3())
    assert code == 1 and "OBJECT_STORE_ENDPOINT" in out.getvalue()


def test_a_refused_profile_exits_1_before_reaching_a_store():
    code, out = _run(_made(FakeS3()), NOCTORNAL_OBJECT_STORE="gcs")
    assert code == 1 and "refused:" in out


def test_a_failed_proof_exits_1_and_a_passed_one_exits_0():
    from noctornal_api.readiness import Check

    def passing():
        return [("evidence_bucket_object_lock", Check("evidence_bucket_object_lock", True, "write-once PROVEN", "")),
                ("preservation_bucket_object_lock", None)]

    def failing():
        return [("evidence_bucket_object_lock",
                 Check("evidence_bucket_object_lock", False, "the store deleted a locked version", "x"))]
    code, out = _run(_made(FakeS3()), "--prove", prove_with=passing)
    assert code == 0 and "write-once PROVEN" in out and "skip" in out
    code, out = _run(_made(FakeS3()), "--prove", prove_with=failing)
    assert code == 1 and "the store deleted a locked version" in out


def test_prove_runs_the_register_proofs_on_the_store(monkeypatch):
    """The real path: the register's own checks, against the in-process store, not a stand-in verdict."""
    from noctornal_api import readiness
    store = _made(FakeS3())
    monkeypatch.setattr(readiness, "_probe_store", lambda _settings: store)
    monkeypatch.setattr(readiness, "_screening_active", lambda _conn: False)
    for name, value in (("OBJECT_STORE_ENDPOINT", "objects.example:9000"),
                        ("OBJECT_STORE_ACCESS_KEY", ACCESS), ("OBJECT_STORE_SECRET_KEY", SECRET),
                        ("NOCTORNAL_OBJECT_STORE", "s3")):
        monkeypatch.setenv(name, value)
    out = io.StringIO()
    code = _script().run(["--prove"], dict(os.environ), out=out, store_for=lambda _s: store)
    text = out.getvalue()
    assert "evidence_bucket_object_lock" in text and "preservation_bucket_object_lock" in text
    assert SECRET not in text and ACCESS not in text
    assert code == 0 and "PROVEN" in text, text

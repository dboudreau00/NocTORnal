"""`EvidenceStorage.delete_all_versions` — written, verified, NOT wired.

## Why this exists

The evidence bucket is created `--with-lock`, which forces versioning on.
`remove_object(bucket, key)` with no `version_id` does not remove anything
on a versioned bucket: it inserts a DELETE MARKER and returns success.

Reproduced against a live MinIO before any of this was written -- an
object under a COMPLIANCE lock, then `remove_object(key)` returned
normally, the real version was still listed, and `get_object(version_id)`
returned the original bytes. So `EvidenceStorage.delete()` reports a
destruction while still holding the object, `RetentionService` records
`evidence_purged`, and the tombstone -- the record that is supposed to
outlive the data -- says DESTROYED.

That is the third instance of one defect: `retention._purge_evidence` and
`ingest._with_raw` both reported destructions they had not performed.

These tests use a STUB client. They must never create a real
COMPLIANCE-locked object: that retention cannot be shortened, lifted or
overridden by any credential, so a test that locks something for a year
has added a year of storage to the bucket, permanently. The live
verification was done once, by hand, with a 45-second retention.

Pure -- no MinIO, no database.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from minio.error import S3Error

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"


class _Version:
    def __init__(self, name, version_id, is_delete_marker=False):
        self.object_name = name
        self.version_id = version_id
        self.is_delete_marker = is_delete_marker


def _s3_error(code: str) -> S3Error:
    return S3Error(code=code, message=code, resource="r",
                   request_id="1", host_id="1", response=None)


class _StubClient:
    """Refuses whichever version ids are named as locked."""

    def __init__(self, versions, locked_ids=(), refusal="AccessDenied"):
        self._versions = versions
        self._locked = set(locked_ids)
        self._refusal = refusal
        self.removed: list[str] = []

    def list_objects(self, bucket, prefix=None, include_version=False,
                     recursive=False):
        assert include_version, (
            "the listing did not ask for versions, which hides exactly the "
            "versions that survive a keyless delete")
        return list(self._versions)

    def remove_object(self, bucket, key, version_id=None):
        assert version_id is not None, (
            "deleted by key rather than by version -- that inserts a delete "
            "marker and destroys nothing")
        if version_id in self._locked:
            raise _s3_error(self._refusal)
        self.removed.append(version_id)


def _storage(stub):
    from noctornal_api.evidence import EvidenceStorage

    st = EvidenceStorage.__new__(EvidenceStorage)   # no network in __init__
    st._client = stub
    st._bucket = "b"
    return st


def test_a_locked_version_is_reported_as_locked_not_destroyed():
    """The outcome `delete()` could never produce, because a keyless
    delete on a versioned bucket never fails."""
    stub = _StubClient([_Version("k", "v1")], locked_ids=["v1"])
    r = _storage(stub).delete_all_versions("k")
    assert r.versions_seen == 1
    assert r.versions_removed == 0
    assert r.versions_locked == 1
    assert r.outcome == "LOCKED_UNTIL_RETENTION"
    assert not r.fully_destroyed
    assert stub.removed == []


def test_every_version_is_deleted_not_just_the_current_one():
    """A keyless delete hides older versions behind a marker; they remain
    retrievable by version id. Destruction has to name each one."""
    stub = _StubClient([_Version("k", "v1"), _Version("k", "v2")])
    r = _storage(stub).delete_all_versions("k")
    assert r.versions_removed == 2
    assert r.outcome == "DESTROYED" and r.fully_destroyed
    assert sorted(stub.removed) == ["v1", "v2"]


def test_a_delete_marker_is_cleared_but_never_counted_as_destruction():
    """Markers left by earlier keyless deletes are tidied up. Counting one
    as a destroyed version would restate the original defect inside the
    method written to end it."""
    stub = _StubClient([_Version("k", "m1", is_delete_marker=True),
                        _Version("k", "v1")])
    r = _storage(stub).delete_all_versions("k")
    assert r.versions_removed == 1, "a delete marker was counted as bytes"
    assert "m1" in stub.removed and "v1" in stub.removed


def test_a_partial_refusal_is_not_a_success():
    """One version gone and one locked is NOT a destruction, and the
    tombstone must not be written from it."""
    stub = _StubClient([_Version("k", "v1"), _Version("k", "v2")],
                       locked_ids=["v2"])
    r = _storage(stub).delete_all_versions("k")
    assert (r.versions_removed, r.versions_locked) == (1, 1)
    assert r.outcome == "LOCKED_UNTIL_RETENTION"
    assert not r.fully_destroyed


def test_an_unrecognised_storage_failure_raises_rather_than_being_recorded():
    """A refusal is an outcome to write down. A storage error nobody
    anticipated is not, and swallowing it would be the defect again --
    silence standing in for "the bytes are gone"."""
    stub = _StubClient([_Version("k", "v1")], locked_ids=["v1"],
                       refusal="InternalError")
    with pytest.raises(S3Error):
        _storage(stub).delete_all_versions("k")


def test_only_versions_of_the_requested_key_are_touched():
    """`list_objects(prefix=...)` is a PREFIX match: `evidence/1` also
    matches `evidence/11`. Deleting a neighbour would be destroying an
    exhibit nobody asked about."""
    stub = _StubClient([_Version("k", "v1"), _Version("k-neighbour", "v9")])
    r = _storage(stub).delete_all_versions("k")
    assert stub.removed == ["v1"]
    assert r.versions_seen == 1


# ---------------------------------------------------------------------------
# The "not enabled" half of the contract
# ---------------------------------------------------------------------------

def test_delete_all_versions_has_no_production_caller():
    """It is written and deliberately not wired: enabling it flips
    production purge outcomes, and the DESTROYED tombstones already
    written for still-locked objects are false records in an append-only
    table that enabling cannot repair.

    If this fails, somebody wired it in -- which may well be right, but it
    is a decision that belongs in a commit message and in docs/18, not in
    a passing test. Delete this test in the same change.
    """
    callers = []
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and getattr(node.func, "attr", None)
                    == "delete_all_versions"):
                callers.append(f"{path.name}:{node.lineno}")
    assert not callers, (
        f"delete_all_versions is now called from {callers}; see its "
        f"docstring for what has to be decided first")


def test_the_retention_service_still_calls_the_unversioned_delete():
    """The other side of the same fact, stated positively so the pair
    cannot drift into "neither is called"."""
    retention = (SRC / "retention.py").read_text(encoding="utf-8")
    assert ".delete(" in retention, (
        "RetentionService no longer calls delete() and does not call "
        "delete_all_versions() either -- the purge path deletes nothing")

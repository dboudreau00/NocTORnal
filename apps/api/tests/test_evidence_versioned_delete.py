"""`EvidenceStorage.delete_all_versions` -- written, verified, and since
2026-09-02 the purge's one destruction path.

## Why this exists

The evidence bucket is created `--with-lock`, which forces versioning on.
`remove_object(bucket, key)` with no `version_id` does not remove anything
on a versioned bucket: it inserts a DELETE MARKER and returns success.

Reproduced against a live MinIO before any of this was written -- an
object under a COMPLIANCE lock, then `remove_object(key)` returned
normally, the real version was still listed, and `get_object(version_id)`
returned the original bytes. So `EvidenceStorage.delete()` reported a
destruction while still holding the object, `RetentionService` recorded
`evidence_purged`, and the tombstone -- the record that is supposed to
outlive the data -- said DELETED.

That is the third instance of one defect: `retention._purge_evidence` and
`ingest._with_raw` both reported destructions they had not performed.

## The guard at the bottom was INVERTED on 2026-09-02

Until then the last tests here asserted that NOTHING called
`delete_all_versions` and that the purge still used `delete()` -- a
deliberate hold, because wiring it flipped production outcomes and could
not repair the DELETED tombstones already written for still-locked
objects. That decision was taken that day (the method's docstring records
what was decided, item by item). The guard is inverted rather than
deleted so the pair of facts cannot drift back to "neither is called",
and a second test reads both modules and migration 0032 together: the
purge maps the three COUNTS and never `outcome`, whose words the
tombstone's CHECK would refuse.

These tests use a STUB client. They must never create a real
COMPLIANCE-locked object: that retention cannot be shortened, lifted or
overridden by any credential, so a test that locks something for a year
has added a year of storage to the bucket, permanently. The live
measurement is `tests/test_evidence_lock_live_pg.py`, with locks of
seconds; the refusal shape the stub here raises is what that file
measured.

Pure -- no MinIO, no database.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from minio.error import S3Error

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
MIGRATIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


class _Version:
    def __init__(self, name, version_id, is_delete_marker=False):
        self.object_name = name
        self.version_id = version_id
        self.is_delete_marker = is_delete_marker


#: What MinIO actually says for a COMPLIANCE-locked version, measured
#: against the live stack 2026-09-02 (`tests/test_evidence_lock_live_pg.py`
#: re-measures it every run). Until that day this stub refused with a bare
#: `AccessDenied` and the classifier counted it as a lock -- the same
#: defect `retention._is_retention_refusal` had, seen from the other side:
#: a policy denial recorded as a retention lock.
WORM = ("InvalidRequest", "Object is WORM protected and cannot be overwritten")


def _s3_error(code: str, message: str | None = None) -> S3Error:
    return S3Error(code=code, message=message or code, resource="r",
                   request_id="1", host_id="1", response=None)


class _StubClient:
    """Refuses whichever version ids are named as locked.

    `refusal` is either a bare code (the message is then the code, which
    is what a client with nothing to say looks like) or a (code, message)
    pair for the shapes whose message is what makes them a lock.
    """

    def __init__(self, versions, locked_ids=(), refusal=WORM):
        self._versions = versions
        self._locked = set(locked_ids)
        self._refusal = refusal if isinstance(refusal, tuple) else (refusal, None)
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
            raise _s3_error(*self._refusal)
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


def test_a_bare_access_denied_is_not_a_lock_and_raises():
    """What a read-only key, or a bucket policy denying s3:DeleteObject,
    produces. Until 2026-09-02 the code-only tuple here counted it under
    `versions_locked`, so the purge recorded LOCKED_UNTIL_RETENTION -- "the
    bytes will go when a retention expires" -- for an object nothing is
    retaining. It is neither a deletion nor a lock, so it raises, and the
    purge counts it as FAILED, named per key."""
    stub = _StubClient([_Version("k", "v1")], locked_ids=["v1"],
                       refusal=("AccessDenied", "Access Denied."))
    with pytest.raises(S3Error) as info:
        _storage(stub).delete_all_versions("k")
    assert info.value.code == "AccessDenied"
    assert stub.removed == []


def test_an_access_denied_that_names_the_lock_is_a_lock():
    """The other vendors' shape: AccessDenied WITH the reason. The code
    alone is ambiguous; the message is what makes it a lock."""
    stub = _StubClient(
        [_Version("k", "v1")], locked_ids=["v1"],
        refusal=("AccessDenied",
                 "Object is WORM protected and cannot be overwritten"))
    r = _storage(stub).delete_all_versions("k")
    assert (r.versions_locked, r.versions_removed) == (1, 0)


# ---------------------------------------------------------------------------
# The wiring half of the contract: retention IS the caller, and it maps
# the counts, never the outcome string
# ---------------------------------------------------------------------------

def _attribute_calls(tree: ast.AST, attr: str) -> list[ast.Call]:
    return [node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and getattr(node.func, "attr", None) == attr]


def test_delete_all_versions_is_called_by_retention_and_nothing_else():
    """Inverted 2026-09-02. Until then this asserted that NOTHING called
    `delete_all_versions` -- deliberately, because wiring it flipped
    production purge outcomes and could not repair the DELETED tombstones
    already written for still-locked objects. That decision was taken (the
    method's docstring records what was decided, item by item), and the
    guard is inverted rather than deleted so the pair of facts cannot
    drift back to "neither is called": `retention._purge_evidence` is the
    one production caller, and a second caller would be a second
    destruction path nobody reviewed.
    """
    callers = {}
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        calls = _attribute_calls(tree, "delete_all_versions")
        if calls:
            callers[path.name] = [c.lineno for c in calls]
    assert set(callers) == {"retention.py"}, (
        f"delete_all_versions is called from {callers or 'nowhere'}; the "
        f"purge in retention.py must be its one caller")
    assert len(callers["retention.py"]) == 1, callers


def test_retention_maps_the_counts_and_never_the_outcome_string():
    """Both modules and the migration, read together.

    `VersionedDeleteResult.outcome` says DESTROYED / NOTHING_TO_DELETE /
    LOCKED_UNTIL_RETENTION. The tombstone column takes DELETED /
    LOCKED_UNTIL_RETENTION / FAILED / NOT_APPLICABLE, enforced by a CHECK in
    migration 0032. Until 2026-09-02 the property's docstring claimed the
    two vocabularies matched; one word coincided, which is what made the
    claim look true. Writing `outcome` into the tombstone would fail the
    CHECK on every successful destruction -- a crash that aborts the purge
    transaction -- so retention reads the three counts and never the
    string. This proves the vocabularies really differ (so the rule is not
    vacuous), that retention's words are exactly the CHECK's, and that the
    name retention binds the versioned result to is never read for
    `.outcome`.
    """
    from noctornal_api import retention
    from noctornal_api.evidence import VersionedDeleteResult

    migration = next(MIGRATIONS.glob("0032_*.py")).read_text(encoding="utf-8")
    m = re.search(r"CHECK \(storage_outcome IN \(([^)]*)\)\)", migration)
    assert m, "the storage_outcome CHECK moved; re-read migration 0032"
    allowed = set(re.findall(r"'([A-Z_]+)'", m.group(1)))
    assert allowed == {retention.STORAGE_DELETED, retention.STORAGE_LOCKED,
                       retention.STORAGE_FAILED, retention.STORAGE_NA}

    outcomes = {
        VersionedDeleteResult("k", 1, 0, 1).outcome,   # locked
        VersionedDeleteResult("k", 1, 1, 0).outcome,   # destroyed
        VersionedDeleteResult("k", 0, 0, 0).outcome,   # nothing there
    }
    assert outcomes - allowed == {"DESTROYED", "NOTHING_TO_DELETE"}, (
        "the vocabularies now coincide; if that is deliberate, this test "
        "and the property's docstring both need rewriting")

    tree = ast.parse((SRC / "retention.py").read_text(encoding="utf-8"))
    bound: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and getattr(node.value.func, "attr", None)
                == "delete_all_versions"):
            bound.update(t.id for t in node.targets
                         if isinstance(t, ast.Name))
    assert bound, "retention no longer binds the versioned result to a name"
    reads = [f"retention.py:{n.lineno}" for n in ast.walk(tree)
             if isinstance(n, ast.Attribute) and n.attr == "outcome"
             and isinstance(n.value, ast.Name) and n.value.id in bound]
    assert not reads, (
        f"retention reads VersionedDeleteResult.outcome at {reads}; the "
        f"tombstone CHECK refuses DESTROYED and NOTHING_TO_DELETE")

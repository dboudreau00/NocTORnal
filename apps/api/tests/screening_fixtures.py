"""Shared fixtures for the prohibited-content screening and sandbox suites
(F13 and F14, 2026-09-24). Not a test module: the suites import it.

Nothing here is prohibited material, and no real hash list is used: every
list is built from digests of random bytes the test itself made.

## The scrub, keyed by list

A pass screens EVERY held sample, so a test that imports a list marks the
demo estate's samples NO_MATCH against it. The scrub therefore works from
the LISTS a suite created: it removes every result and review that
consulted one, resets the screening columns of samples the suite did not
create that were screened against one, and deletes the entries and the
lists; then `lab_static_fixtures.teardown` removes the suite's own samples,
people and cases. `assert_scrubbed` holds that nothing a downgrade of 0102
or 0103 refuses on is left behind.
"""
from __future__ import annotations

import hashlib
import io
import os
from uuid import uuid4

from lab_static_fixtures import teardown

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

AUTHORITY = "COUNSEL-2026-0917 hash set determination"


def declare(monkeypatch, *, authority: bool = True) -> None:
    """The ingest policy, and (unless told not to) the hash-set authority."""
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-2026-014")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "the.dp@example.test")
    if authority:
        monkeypatch.setenv("NOCTORNAL_HASH_SET_AUTHORITY", AUTHORITY)
    else:
        monkeypatch.delenv("NOCTORNAL_HASH_SET_AUTHORITY", raising=False)


def payload(tag: str = "") -> bytes:
    """Bytes nobody else holds, with a PE magic so the Lab types them."""
    return b"MZ\x90\x00" + tag.encode() + uuid4().bytes * 8


def listed(*blobs: bytes, algorithm: str = "sha256", header: bool = True) -> bytes:
    """A list file naming the digests of `blobs`."""
    lines = ["# test list"] if header else []
    for blob in blobs:
        lines.append(getattr(hashlib, algorithm)(blob).hexdigest())
    # A random comment so two lists of the same blobs are two files.
    lines.append(f"# {uuid4().hex}")
    return ("\n".join(lines) + "\n").encode()


def import_list(conn, actor, text: bytes, *, samples=None, name=None,
                category="OTHER_PROHIBITED", rescan_budget: float = 20.0):
    from noctornal_api.screening import ScreeningService
    return ScreeningService(conn, samples).import_list(
        io.BytesIO(text), name=name or f"list {uuid4().hex[:6]}",
        provider="Test provider", authority_reference="LIC-2026-001",
        category=category, actor_id=actor, via="console",
        rescan_budget=rescan_budget)


class MemoryPreservation:
    """The preservation store, in memory, with a switch to refuse."""

    bucket = "memory-preserved"

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.objects: dict[str, bytes] = {}

    def preserve(self, key, data):
        from noctornal_api.samples import PreservedObject, SampleError
        if self.fail:
            raise SampleError("the preservation store refused the copy "
                              "(InternalError: simulated)")
        self.objects[key] = bytes(data)
        return PreservedObject(self.bucket, key, "v1", len(data))

    def latest_held(self, key):
        from noctornal_api.samples import PreservedObject
        data = self.objects.get(key)
        return None if data is None else PreservedObject(
            self.bucket, key, "v1", len(data))

    def get(self, key, *, version_id=None, bucket=None):
        return self.objects[key]

    def is_held(self, key, *, version_id=None, bucket=None):
        return key in self.objects


def service(conn, store, preservation=None):
    from noctornal_api.samples import SampleService
    return SampleService(conn, store, preservation)


def notices(conn, recipient, kind):
    return conn.execute(
        """SELECT subject, summary, body, classification, case_id, priority,
                  object_id
             FROM notify.notification WHERE recipient_id = %s AND kind = %s
            ORDER BY created_at""", (recipient, kind)).fetchall()


def _users(prefix: str) -> str:
    return (f"(SELECT id FROM iam.app_user WHERE email LIKE "
            f"'{prefix}%@noctornal.test')")


def scrub(c, prefix: str) -> None:
    """Everything a suite with `prefix` made, keyed by its lists and its
    samples, then the static fixtures' teardown."""
    sub = _users(prefix)
    ssub = f"(SELECT id FROM lab.sample WHERE submitted_by IN {sub})"
    lsub = f"(SELECT id FROM lab.screening_list WHERE imported_by IN {sub})"
    rsub = (f"(SELECT id FROM lab.screening_result WHERE sample_id IN {ssub} "
            f"OR lists_consulted && ARRAY(SELECT id FROM lab.screening_list "
            f"WHERE imported_by IN {sub}))")
    with c.transaction():
        for table in ("screening_review", "screening_result", "screening_hash",
                      "screening_list"):
            c.execute(f"ALTER TABLE lab.{table} DISABLE TRIGGER USER")
        c.execute(f"""DELETE FROM notify.delivery WHERE notification_id IN (
                        SELECT id FROM notify.notification
                         WHERE object_id IN {rsub}
                            OR object_id IN (SELECT id FROM lab.detonation
                                              WHERE sample_id IN {ssub})
                            OR recipient_id IN {sub})""")
        c.execute(f"""DELETE FROM notify.notification
                       WHERE object_id IN {rsub}
                          OR object_id IN (SELECT id FROM lab.detonation
                                            WHERE sample_id IN {ssub})
                          OR recipient_id IN {sub}""")
        c.execute(f"DELETE FROM lab.screening_review WHERE result_id IN {rsub} "
                  f"OR reviewed_by IN {sub}")
        c.execute(f"DELETE FROM lab.screening_result WHERE id IN {rsub}")
        # Samples this suite did not create but screened against its lists.
        c.execute(f"""UPDATE lab.sample SET screening_outcome = 'NOT_SCREENED',
                             screened_at = NULL, screening_list_seq = NULL
                       WHERE submitted_by NOT IN {sub}
                         AND screening_outcome = 'NO_MATCH'
                         AND screening_list_seq IN (
                             SELECT seq FROM lab.screening_list
                              WHERE imported_by IN {sub})""")
        c.execute(f"DELETE FROM lab.screening_hash WHERE list_id IN {lsub}")
        c.execute(f"DELETE FROM lab.screening_list WHERE id IN {lsub}")
        c.execute("ALTER TABLE lab.preservation_authorisation DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.preservation_authorisation "
                  f"WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.preservation_authorisation ENABLE TRIGGER USER")
        for table in ("screening_review", "screening_result", "screening_hash",
                      "screening_list"):
            c.execute(f"ALTER TABLE lab.{table} ENABLE TRIGGER USER")
    teardown(c, prefix)


def assert_scrubbed(c, prefix: str) -> None:
    """Nothing the suite made is left, and nothing a downgrade of 0102 or
    0103 refuses on (a MATCH result, a SUBMIT detonation) survives it."""
    sub = _users(prefix)
    assert c.execute(f"SELECT count(*) FROM {sub} x").fetchone()[0] == 0
    left = c.execute(
        """SELECT (SELECT count(*) FROM lab.screening_list l
                    JOIN iam.app_user u ON u.id = l.imported_by
                   WHERE u.email LIKE %s),
                  (SELECT count(*) FROM lab.screening_result
                    WHERE outcome = 'MATCH'),
                  (SELECT count(*) FROM lab.detonation WHERE mode = 'SUBMIT')""",
        (prefix + "%",)).fetchone()
    assert left == (0, 0, 0), left


__all__ = ["AUTHORITY", "MemoryPreservation", "assert_scrubbed", "declare",
           "import_list", "listed", "notices", "payload", "scrub", "service"]

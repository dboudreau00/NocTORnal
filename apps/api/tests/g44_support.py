"""Fixtures for the evidence, retention and report fixes of unit g44
(2026-10-03): a versioned in-memory object store and the account, case and
exhibit builders the three `test_g44_*` files share.

Nothing here talks to MinIO: an exhibit lodged through the service lands in
`VersionedStore`, so no test adds an object nobody can delete to the dev
bucket (a COMPLIANCE lock cannot be shortened by any credential).

Accounts are `g44t-*@noctornal.test`, cleaned up by `rls_support.cleanup`.
"""
from __future__ import annotations

import os
from datetime import date, timedelta
from uuid import UUID, uuid4

import pytest

import rls_support as s

PREFIX = "g44t-"
GATED = s.GATED

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")


class _Missing(Exception):
    """What the real client raises for a key or version the store lacks."""
    code = "NoSuchKey"


class VersionedStore:
    """An object store with MinIO's shape where it matters here: a put on
    an existing key adds a VERSION and returns its id, a plain get reads the
    latest, a get with a version id reads exactly it, and a delete marker
    makes a plain get fail while every version stays readable by id."""

    bucket = "g44-fake"

    def __init__(self, *, versioned: bool = True) -> None:
        self.versioned = versioned
        self.objects: dict[str, list[tuple[str | None, bytes]]] = {}
        self.puts: list[str] = []
        self.markers: set[str] = set()
        self.deleted: list[str] = []
        #: Called with the key before each delete_all_versions answers.
        self.on_delete = None
        #: Called with the key at each put, before it lands.
        self.on_put = None
        #: Called with (key, version_id) at each get.
        self.on_get = None

    def put(self, key, data, *, media_type, retain_until):  # noqa: ARG002
        if self.on_put is not None:
            self.on_put(key)
        versions = self.objects.setdefault(key, [])
        vid = f"v{len(versions) + 1}-{uuid4().hex[:6]}" if self.versioned else None
        versions.append((vid, data))
        self.puts.append(key)
        self.markers.discard(key)
        return vid

    def get(self, key, version_id=None):
        if self.on_get is not None:
            self.on_get(key, version_id)
        versions = self.objects.get(key, [])
        if version_id is not None:
            for vid, data in versions:
                if vid == version_id:
                    return data
            raise _Missing(key)
        if key in self.markers or not versions:
            raise _Missing(key)
        return versions[-1][1]

    # What an actor with the API's own credentials can do to a locked key.
    def replace(self, key: str, data: bytes) -> None:
        """A newer version on the key (a locked key accepts one)."""
        self.put(key, data, media_type="application/octet-stream",
                 retain_until=None)

    def conceal(self, key: str) -> None:
        """A delete marker: a plain get raises, the versions stay."""
        self.markers.add(key)

    def delete_all_versions(self, key):
        from noctornal_api.evidence import VersionedDeleteResult
        if self.on_delete is not None:
            self.on_delete(key)
        seen = len(self.objects.get(key, []))
        self.deleted.append(key)
        self.objects.pop(key, None)
        return VersionedDeleteResult(key=key, versions_seen=seen,
                                     versions_removed=seen, versions_locked=0)


def owner():
    """The schema owner's connection, as the request role is assumed on
    request connections (production's shape)."""
    from noctornal_api.db import ASSUME_ROLE_ENV  # noqa: F401
    return s.owner_conn()


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    _cleanup_extra(c)
    s.cleanup(c, PREFIX)
    c.close()


def _cleanup_extra(c) -> None:
    """What the ingest and Lab builders leave that `rls_support.cleanup` does
    not know of. Best effort: append-only history stays, and a row that a
    later table still names is left for the next run's unique ids."""
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    ksub = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    bsub = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {ksub})"
    ssub = f"(SELECT id FROM lab.sample WHERE submitted_by IN {sub})"
    statements = (
        # A case these tests aged into expiry holds exhibits that custody
        # rows pin for ever, and every global sweep after this file
        # (`purge_due(case_id=None)` in the document and dead-letter suites)
        # would pick them up and refuse for want of a store. Not expired is
        # not due, so the leftover is left alone.
        f"""UPDATE core."case" SET retention_until = '2099-12-31',
                review_due = '2099-12-30', legal_hold = false,
                legal_hold_reason = NULL
             WHERE owner_user_id IN {sub}""",
        f"DELETE FROM ingest.victim_credential WHERE record_id IN "
        f"(SELECT id FROM ingest.record WHERE batch_id IN {bsub})",
        f"UPDATE ingest.record SET duplicate_of = NULL WHERE batch_id IN {bsub}",
        f"DELETE FROM ingest.record WHERE batch_id IN {bsub}",
        f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {ksub}",
        f"DELETE FROM ingest.batch WHERE api_key_id IN {ksub}",
        f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}",
        f"DELETE FROM lab.download_ticket WHERE sample_id IN {ssub}",
        "ALTER TABLE lab.sample_access DISABLE TRIGGER USER",
        f"DELETE FROM lab.sample_access WHERE sample_id IN {ssub}",
        "ALTER TABLE lab.sample_access ENABLE TRIGGER USER",
        f"DELETE FROM lab.sample_analysis WHERE sample_id IN {ssub}",
        f"DELETE FROM lab.sample WHERE submitted_by IN {sub}",
    )
    for statement in statements:
        try:
            with c.transaction():
                c.execute(statement)
        except Exception:  # noqa: BLE001 - a teardown never fails a test
            pass
    # The collected documents `collected_document` made, their watches and
    # their sources.
    try:
        import collection_helpers as h
        h.teardown(c, PREFIX)
    except Exception:  # noqa: BLE001 - a teardown never fails a test
        pass


def user(conn, clearance="AMBER", compartments=(), roles=()):
    uid = s.user(conn, clearance, compartments, prefix=PREFIX)
    for role in roles:
        s.grant_global(conn, uid, role)
    return uid


def age_case(conn, case_id, retention: date) -> None:
    """Move a case's retention date, as a real one ages. `case_retention_sane`
    ties retention to the creation date and fires on UPDATE as well, so the
    creation date moves with it."""
    conn.execute(
        '''UPDATE core."case"
              SET retention_until = %s, review_due = %s,
                  created_at = least(created_at, %s::date - interval '30 days')
            WHERE id = %s''',
        (retention, retention - timedelta(days=1), retention, case_id))


def case(conn, owner_id, classification="AMBER", compartments=(),
         retention: date | None = None):
    case_id = s.case(conn, owner_id, classification, compartments)
    if retention is not None:
        age_case(conn, case_id, retention)
    return case_id


def expired() -> date:
    return date.today() - timedelta(days=3)


def soon(days: int = 20) -> date:
    return date.today() + timedelta(days=days)


def record_in_case(conn, owner_id, case_id, category="STEALER_LOG",
                   compartment="STEALER-2026"):
    """One ingest record attached to the case, through the real service.
    Returns (record id, retain_until)."""
    import json

    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage
    s.register(conn, compartment)
    svc = IngestService(conn, InMemoryRawStorage())
    key = svc.authenticate(svc.issue_key(
        name="g44 feed", owner_user_id=owner_id, declared_category=category,
        forced_compartment=compartment).secret)
    raw = json.dumps({"passwords": [], "cookies": [], "autofill": [],
                      "machine_id": uuid4().hex}).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw, case_id=case_id)
    return conn.execute(
        "SELECT id, retain_until FROM ingest.record WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()


def collected_document(conn, case_id, *, classification="AMBER",
                       compartments=(), source=None, external_id=None,
                       version=1, supersedes=None, cited=True,
                       purged=False) -> tuple[UUID, UUID]:
    """One collected document at the given labels, due for retention, cited
    by `case_id` through the case's watch (the registered citation
    `collect.document.watch_id`) unless `cited` is false. Returns (document
    id, source id); a second version of a post names the same `source` and
    `external_id`.

    Cited through a watch and not a tag on purpose: a tag assignment per run
    leaves `core.tag_assignment` vacuumed empty, which flips the plan
    `test_collected_document_retention_pg` pins for its document index.
    Rows only: the teardown removes them (`_cleanup_extra`)."""
    import collection_helpers as h

    s.register(conn, *compartments)
    source = source or h.source(conn, PREFIX, kind="RSS", parser="rss", due=False)
    watch = None
    if cited:
        owner = conn.execute('SELECT owner_user_id FROM core."case" WHERE id = %s',
                             (case_id,)).fetchone()[0]
        watch = conn.execute(
            """INSERT INTO collect.watch (case_id, source_id, name, target_kind,
                                          target_ref, owner_user_id)
               VALUES (%s, %s, 'g44 watch', 'FORUM', 'b', %s) RETURNING id""",
            (case_id, source, owner)).fetchone()[0]
    doc = conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, body_text, content_sha256, version,
                supersedes_id, retain_until, category, classification,
                compartments, watch_id)
           VALUES (%s, %s, 'g44 body', %s, %s, %s,
                   now() - interval '1 day', 'CHAT_EXPORT', %s, %s, %s)
           RETURNING id""",
        (source, external_id, os.urandom(32), version, supersedes,
         classification, list(compartments), watch)).fetchone()[0]
    if purged:
        conn.execute("UPDATE collect.document SET purged_at = now(), "
                     "body_text = '' WHERE id = %s", (doc,))
    return doc, source


def service(conn, store):
    from noctornal_api.evidence import EvidenceService
    return EvidenceService(conn, store)


def lodge(conn, store, case_id, actor, data: bytes | None = None,
          classification="AMBER", compartments=None, title="g44 exhibit",
          **kw):
    """An exhibit through the real service. Returns (id, bytes)."""
    data = data if data is not None else b"g44-" + uuid4().hex.encode()
    res = service(conn, store).ingest(
        case_id=case_id, title=title, media_type="text/plain", data=data,
        acquired_by=actor, acquisition_method="MANUAL_UPLOAD",
        classification=classification, compartments=compartments, **kw)
    return res, data


def evidence_row(conn, evidence_id: UUID):
    return conn.execute(
        """SELECT storage_key, storage_version_id, classification::text,
                  purged_at IS NOT NULL, legal_hold, case_id
             FROM core.evidence WHERE id = %s""", (evidence_id,)).fetchone()


def audit_rows(conn, action: str, **where) -> list:
    sql = "SELECT detail, outcome, object_id, case_id FROM audit.event WHERE action = %s"
    params = [action]
    for column, value in where.items():
        sql += f" AND {column} = %s"
        params.append(value)
    return conn.execute(sql + " ORDER BY seq", params).fetchall()


def token(conn, uid) -> dict:
    _, raw = s.session(conn, uid)
    return {"Authorization": f"Bearer {raw}"}

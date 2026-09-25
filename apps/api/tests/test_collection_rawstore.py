"""The collected raw markup store (2026-09-24).

Its own bucket, content-addressed per source, NO object lock (a retention
clock or a deletion order must be able to remove it), and a delete that
says whether an object went. The live leg runs only against a MinIO this
host names in MINIO_ENDPOINT.
"""
from __future__ import annotations

import hashlib
import os
from uuid import uuid4

import pytest


def test_the_in_memory_store_round_trips_and_says_what_it_deleted():
    from noctornal_api.rawstore import InMemoryDocumentRawStorage, MissingObject

    store = InMemoryDocumentRawStorage()
    store.put("collect/aa/x", b"<p>x</p>")
    assert store.get("collect/aa/x") == b"<p>x</p>" and store.exists("collect/aa/x")
    assert store.delete("collect/aa/x") is True
    assert store.delete("collect/aa/x") is False
    with pytest.raises(MissingObject):
        store.get("collect/aa/x")


def test_the_key_is_the_digest_of_the_source_and_the_fragment():
    from noctornal_api.rawstore import document_raw_key

    a, b = uuid4(), uuid4()
    fragment = b"<article>same words</article>"
    key_a = document_raw_key(a, fragment)
    assert key_a == document_raw_key(a, fragment)
    assert key_a != document_raw_key(b, fragment), (
        "identical fragments from two sources never share an object")
    digest = hashlib.sha256(a.bytes + fragment).hexdigest()
    assert key_a == f"collect/{digest[:2]}/{digest}"


def test_no_store_is_configured_without_minio(monkeypatch):
    from noctornal_api.rawstore import default_document_raw_store

    for var in ("MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)
    assert default_document_raw_store() is None, (
        "never the in-memory store, which would lose markup on restart")


def test_the_bucket_name_has_one_default(monkeypatch):
    from noctornal_api.rawstore import COLLECT_RAW_BUCKET_DEFAULT, collect_raw_bucket

    monkeypatch.delenv("COLLECT_RAW_BUCKET", raising=False)
    assert collect_raw_bucket() == COLLECT_RAW_BUCKET_DEFAULT == "noctornal-collect-raw"


def test_the_compose_files_provision_the_bucket_without_a_lock():
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    for compose in ("infra/production/compose.yml", "infra/docker-compose.yml"):
        text = (root / compose).read_text(encoding="utf-8")
        line = next((ln for ln in text.splitlines() if "noctornal-collect-raw" in ln),
                    None)
        assert line is not None, f"{compose} does not create the collected-markup bucket"
        assert "--with-lock" not in line, f"{compose} locks the collected-markup bucket"
    example = (root / "infra/production/secrets.env.example").read_text(encoding="utf-8")
    assert "COLLECT_RAW_BUCKET=noctornal-collect-raw" in example


@pytest.mark.skipif(not os.environ.get("MINIO_ENDPOINT"),
                    reason="no MinIO named; the live leg is skipped")
def test_the_live_store_puts_gets_deletes_and_has_no_object_lock(monkeypatch):
    from minio.error import S3Error

    from noctornal_api.rawstore import DocumentRawStorage

    monkeypatch.setenv("COLLECT_RAW_BUCKET", f"b0raw-{uuid4().hex[:8]}")
    store = DocumentRawStorage()
    try:
        store.ensure_bucket()
    except Exception as exc:  # noqa: BLE001 - a MinIO that is down is a skip
        pytest.skip(f"MinIO did not answer: {type(exc).__name__}")
    try:
        store.put("collect/ab/live", b"<p>live</p>")
        assert store.get("collect/ab/live") == b"<p>live</p>"
        with pytest.raises(S3Error):
            store.client.get_object_lock_config(store.bucket)
        assert store.delete("collect/ab/live") is True
        assert store.exists("collect/ab/live") is False
    finally:
        for obj in store.client.list_objects(store.bucket, recursive=True):
            store.client.remove_object(store.bucket, obj.object_name)
        store.client.remove_bucket(store.bucket)

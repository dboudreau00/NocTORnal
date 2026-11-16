"""The live run's set-up: the store under test, its two scratch buckets, the known gaps and the measurements.

Variables (all `OBJECT_STORE_CONFORMANCE_*`): `ENDPOINT` (host:port, required), `ACCESS_KEY`, `SECRET_KEY`,
`SECURE` (`true` for TLS), `REGION`, `ADDRESSING`, `PROFILE` (`minio` or `s3`, default `s3`), `LOCK_SECONDS`
(default 60; a vendor that refuses short locks needs its minimum), `STORE` (a name for `known_gaps/<STORE>.txt`
and the measurements), `MEASUREMENTS` (where `store-measurements.json` is written, default the current
directory), `RO_ACCESS_KEY` / `RO_SECRET_KEY` (a credential that may read and not delete, for the optional
check), and `ON_LIVE_STORE=1` to run against the endpoint this deployment itself names.

Rules: with no endpoint the run FAILS, saying nothing was run; it makes its OWN two buckets (one with object lock,
one without) and touches no other; every COMPLIANCE object it writes is undeletable until `LOCK_SECONDS` pass,
so the locked bucket is emptied and removed at the end only once its locks have lapsed (and, for the probe's
one-day canary, not at all: the bucket is reported as left behind).
"""
from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from noctornal_api.objectstore import errors
from noctornal_api.objectstore.pools import bounded_http
from noctornal_api.objectstore.settings import resolve
from noctornal_api.objectstore.store import open_store
from store_conformance.checks import Ctx

PREFIX = "OBJECT_STORE_CONFORMANCE_"
GAPS = Path(__file__).resolve().parent / "known_gaps"


def _var(name: str, default: str = "") -> str:
    return os.environ.get(PREFIX + name, default).strip()


def _settings(endpoint: str, access: str, secret: str):
    env = {"OBJECT_STORE_ENDPOINT": endpoint, "OBJECT_STORE_ACCESS_KEY": access,
           "OBJECT_STORE_SECRET_KEY": secret, "OBJECT_STORE_SECURE": _var("SECURE", "false"),
           "OBJECT_STORE_REGION": _var("REGION"), "OBJECT_STORE_ADDRESSING": _var("ADDRESSING"),
           "NOCTORNAL_OBJECT_STORE": _var("PROFILE", "s3")}
    return resolve("evidence", env)


def known_gaps(store_name: str) -> dict[str, str]:
    """`{check name: reason}` from `known_gaps/<store>.txt`: one check name (a function in `checks.py`) per line,
    then `#` and the reason with its upstream link. Each runs as a STRICT xfail, so a store that fixes the bug turns the run red until the
    file is edited."""
    path = GAPS / f"{store_name}.txt"
    if not store_name or not path.is_file():
        return {}
    gaps = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        name, _, reason = line.partition("#")
        if name.strip():
            gaps[name.strip()] = reason.strip() or "declared as a known gap"
    return gaps


def pytest_collection_modifyitems(config, items):
    gaps = known_gaps(_var("STORE"))
    for item in items:
        callspec = getattr(item, "callspec", None)
        reason = gaps.get(callspec.id if callspec else item.name)
        if reason:
            item.add_marker(pytest.mark.xfail(strict=True, reason=reason))


@pytest.fixture(scope="session")
def ctx():
    endpoint = _var("ENDPOINT")
    if not endpoint:
        pytest.fail(f"nothing was run: {PREFIX}ENDPOINT is not set (docs/22)")
    live = {os.environ.get("OBJECT_STORE_ENDPOINT", "").strip(),
            os.environ.get("MINIO_ENDPOINT", "").strip()} - {""}
    if endpoint in live and _var("ON_LIVE_STORE") != "1":
        pytest.fail(f"{PREFIX}ENDPOINT is this deployment's own store; every COMPLIANCE object the run "
                    f"writes is undeletable for {PREFIX}LOCK_SECONDS, so set {PREFIX}ON_LIVE_STORE=1 to "
                    f"run there on purpose")
    settings = _settings(endpoint, _var("ACCESS_KEY"), _var("SECRET_KEY"))
    store = open_store(settings, http=bounded_http(resend_writes=False))
    run = uuid.uuid4().hex[:8]
    locked, plain = f"conformance-{run}-locked", f"conformance-{run}-plain"
    store.make_bucket(locked, object_lock=True)
    store.make_bucket(plain, object_lock=False)
    ro_access, ro_secret = _var("RO_ACCESS_KEY"), _var("RO_SECRET_KEY")
    context = Ctx(
        store=store, locked=locked, plain=plain,
        lock_seconds=int(_var("LOCK_SECONDS", "60")), run=run,
        unreachable=lambda: open_store(
            _settings("127.0.0.1:1", "a", "not-a-real-one"),
            http=__import__("urllib3").PoolManager(retries=False, timeout=2.0)),
        read_only=(lambda: open_store(_settings(endpoint, ro_access, ro_secret)))
        if ro_access and ro_secret else None)
    yield context
    left = _tidy(context)
    out = Path(_var("MEASUREMENTS") or ".") / "store-measurements.json"
    out.write_text(json.dumps({
        "store": _var("STORE") or "unnamed", "profile": store.profile, "host": store.host,
        "refusals": context.measurements, "left_behind": left,
    }, indent=2, sort_keys=True), encoding="utf-8")


def _tidy(context: Ctx) -> list[str]:
    """Empty and remove the two buckets. Holds are lifted (this suite set them); locked versions wait for
    `LOCK_SECONDS` to pass once. Whatever cannot go is named in the measurements, never hidden."""
    store, left = context.store, []
    if context.latest_until is not None:
        wait = (context.latest_until - datetime.now(timezone.utc)).total_seconds() + 2
        if wait > 0:
            time.sleep(min(wait, 300))
    for bucket in (context.plain, context.locked):
        try:
            versions = list(store.list_versions(bucket, ""))
        except errors.StoreError as exc:
            left.append(f"{bucket}: not listed ({exc})")
            continue
        for v in versions:
            try:
                if not v.is_delete_marker and store.legal_hold_is_on(bucket, v.key, v.version_id):
                    store.set_legal_hold(bucket, v.key, v.version_id, False)
            except errors.StoreError:
                pass
            try:
                store.delete_version(bucket, v.key, v.version_id or "null")
            except errors.StoreError:
                left.append(f"{bucket}/{v.key} {v.version_id}")
        try:
            store.remove_bucket(bucket)
        except errors.StoreError as exc:
            left.append(f"{bucket}: kept ({getattr(exc, 'code', exc)})")
    return left

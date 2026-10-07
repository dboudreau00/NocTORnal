"""Release gate 9 (Beta 1, 2026-10-07): cross-cutting consistency fixes,
each pinned here where no existing test covered it."""
from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"


def test_a_lookup_refusal_is_served_as_problem_json():
    """Every error the API emits is application/problem+json (errors.py,
    CONVENTIONS.md). The lookup refusal built the problem body with its
    `code` and `retry_at` members and served it as application/json."""
    from noctornal_api import lookups
    from noctornal_api.http.routers.lookups import _refused

    at = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
    r = _refused(lookups.CoolingDown("cooling_down", "the provider is cooling down",
                                     retry_at=at, status=409))
    assert r.status_code == 409
    assert r.media_type == "application/problem+json"
    assert r.headers["content-type"].startswith("application/problem+json")
    body = json.loads(r.body)
    assert body == {"type": "about:blank", "title": "Conflict", "status": 409,
                    "detail": "the provider is cooling down", "code": "cooling_down",
                    "retry_at": at.isoformat()}


def test_the_legacy_records_script_counts_with_the_one_wording_helper(monkeypatch):
    """scripts/legacy_records.py carried its own copy of `wording.count_of`
    under the name `plural`; one helper now, so the two cannot drift."""
    from noctornal_api.wording import count_of
    monkeypatch.syspath_prepend(str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(
        "legacy_records_gate", SCRIPTS / "legacy_records.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.plural is count_of
    assert module.plural(1, "claim", "claims") == "1 claim"
    assert module.plural(2, "claim", "claims") == "2 claims"

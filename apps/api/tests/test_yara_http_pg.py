"""YARA rule sets over HTTP (F12 I, 2026-09-24).

Every route that names a set or a version answers a set above the
caller's labels exactly as one that does not exist; the officer's list
is filtered by the officer's ceiling;
every write needs a fresh sign-in; the upload is capped as it arrives;
and the router is matched before the samples router, so no path here is
ever read as a sample id.

Email prefix `yht-`. Env-gated on DATABASE_URL; skips without yara-x.
"""
from __future__ import annotations

import io
import os
import zipfile
from uuid import uuid4

import pytest

from lab_static_fixtures import (
    auth,
    client,
    declare_policy,
    left_behind,
    make_user,
    teardown,
    token,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set")

API = "/api/v1/samples/yara"
PREFIX = "yht-"
RULE = b'rule h { strings: $a = "needle" condition: $a }\n'


@pytest.fixture(autouse=True)
def policy(monkeypatch):
    declare_policy(monkeypatch)


@pytest.fixture
def conn():
    pytest.importorskip("yara_x")
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    assert left_behind(c, PREFIX) == {"users": 0, "rulesets": 0}
    c.close()


@pytest.fixture
def http():
    from dataclasses import replace

    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    c = client()
    limits = dict(LIMITS)
    limits["yara.ruleset"] = replace(LIMITS["yara.ruleset"], burst=100, quota=1000)
    c.app.state.limiter = RateLimiter(InProcessBackend(), limits=limits)
    return c


def _person(conn, role, **kw):
    uid = make_user(conn, PREFIX, roles=(role,), **kw)
    return uid, auth(token(conn, uid))


def _red_set_with_version(conn, http, lab_headers):
    r = http.post(f"{API}/rulesets", headers=lab_headers,
                  json={"key": f"yht-{uuid4().hex[:8]}", "display_name": "Red",
                        "classification": "RED"})
    assert r.status_code == 201, r.text
    set_id = r.json()["id"]
    r = http.post(f"{API}/rulesets/{set_id}/versions", headers=lab_headers,
                  files={"file": ("h.yar", RULE, "text/plain")},
                  data={"licence": "MIT"})
    assert r.status_code == 201, r.text
    return set_id, r.json()["id"]


def test_the_yara_router_is_matched_before_the_sample_id_routes(conn, http):
    _uid, headers = _person(conn, "MALWARE_ANALYST")
    r = http.get(f"{API}/rulesets", headers=headers)
    assert r.status_code == 200 and "rulesets" in r.json()
    assert r.json()["you_may"]["manage"] is True


def test_every_yara_route_answers_404_for_a_red_set_to_an_amber_caller(conn, http):
    _lab, lab = _person(conn, "MALWARE_ANALYST")
    set_id, vid = _red_set_with_version(conn, http, lab)
    _amber_lab, amber_lab = _person(conn, "MALWARE_ANALYST", clearance="AMBER")
    _amber_off, amber_off = _person(conn, "SECURITY_OFFICER", clearance="AMBER")
    listing = http.get(f"{API}/rulesets", headers=amber_lab).json()
    assert set_id not in {s["id"] for s in listing["rulesets"]}
    missing = str(uuid4())
    checks = [
        ("post", f"/rulesets/{set_id}/versions", amber_lab,
         {"files": {"file": ("h.yar", RULE)}, "data": {"licence": "MIT"}}),
        ("post", f"/versions/{vid}/adopt", amber_lab, {}),
        ("get", f"/versions/{vid}", amber_lab, {}),
        ("get", f"/versions/{vid}/files/0", amber_lab, {}),
        ("post", f"/versions/{vid}/activate", amber_off, {"json": {}}),
        ("post", f"/versions/{vid}/deactivate", amber_off,
         {"json": {"reason": "because it is wrong"}}),
        ("post", f"/versions/{vid}/retrohunt", amber_lab, {}),
    ]
    for method, path, headers, kw in checks:
        hidden = getattr(http, method)(API + path, headers=headers, **kw)
        absent = getattr(http, method)(API + path.replace(set_id, missing)
                                       .replace(vid, missing),
                                       headers=headers, **kw)
        assert hidden.status_code == 404, (path, hidden.text)
        assert hidden.json()["detail"] == absent.json()["detail"], path


def test_creating_a_key_a_hidden_set_holds_confirms_nothing(conn, http):
    """Found 2026-09-24: an AMBER caller creating a key a RED set
    held got 409 naming it, an oracle for what another unit hunts. The
    key is unique only among sets at the same labels (0080)."""
    _lab, lab = _person(conn, "MALWARE_ANALYST")
    key = f"yht-{uuid4().hex[:8]}"
    r = http.post(f"{API}/rulesets", headers=lab,
                  json={"key": key, "display_name": "Red",
                        "classification": "RED"})
    assert r.status_code == 201, r.text
    _amber, amber = _person(conn, "MALWARE_ANALYST", clearance="AMBER")
    r = http.post(f"{API}/rulesets", headers=amber,
                  json={"key": key, "display_name": "Mine",
                        "classification": "AMBER"})
    assert r.status_code == 201, r.text
    r = http.post(f"{API}/rulesets", headers=amber,
                  json={"key": key, "display_name": "Mine again",
                        "classification": "AMBER"})
    assert r.status_code == 409
    assert r.json()["detail"] == (f"a rule set with the key {key} exists "
                                  f"already at these labels")
    listed = http.get(f"{API}/rulesets", headers=amber).json()["rulesets"]
    assert [s["display_name"] for s in listed if s["key"] == key] == ["Mine"]


def test_the_version_view_reads_one_version(conn, http, monkeypatch):
    """Found 2026-09-24: the version view rebuilt every set's
    listing per request. It reads its own version, and the listing is no
    longer called."""
    from noctornal_api import yara_rules
    _lab, lab = _person(conn, "MALWARE_ANALYST")
    set_id, vid = _red_set_with_version(conn, http, lab)

    def never(*a, **k):
        raise AssertionError("the version view built the whole listing")

    monkeypatch.setattr(yara_rules.RulesetService, "listing", never)
    r = http.get(f"{API}/versions/{vid}", headers=lab)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == vid and body["ruleset_id"] == set_id
    assert body["version"] == 1 and body["open"] is None
    assert body["build"]["status"] in ("compiling", "COMPILED")
    assert body["files"] and all("text" not in f for f in body["files"])


def test_pending_is_filtered_by_the_officers_ceiling(conn, http):
    _lab, lab = _person(conn, "MALWARE_ANALYST")
    set_id, _vid = _red_set_with_version(conn, http, lab)
    _off, red_off = _person(conn, "SECURITY_OFFICER")
    _off2, amber_off = _person(conn, "SECURITY_OFFICER", clearance="AMBER")
    red = http.get(f"{API}/pending", headers=red_off).json()
    assert set_id in {w["ruleset_id"] for w in red["waiting"]}
    amber = http.get(f"{API}/pending", headers=amber_off).json()
    assert set_id not in {w["ruleset_id"] for w in amber["waiting"]}
    # The lab cannot read the officer's list at all.
    assert http.get(f"{API}/pending", headers=lab).status_code == 403


def test_step_up_is_required_on_every_write(conn, http):
    lab_id, lab = _person(conn, "MALWARE_ANALYST")
    set_id, vid = _red_set_with_version(conn, http, lab)
    stale_lab = auth(token(conn, lab_id, fresh=False))
    off_id = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    stale_off = auth(token(conn, off_id, fresh=False))
    writes = [
        ("/rulesets", stale_lab, {"json": {"key": "yht-x", "display_name": "x"}}),
        (f"/rulesets/{set_id}/versions", stale_lab,
         {"files": {"file": ("h.yar", RULE + b"//")}, "data": {"licence": "MIT"}}),
        (f"/versions/{vid}/adopt", stale_lab, {}),
        (f"/versions/{vid}/retrohunt", stale_lab, {}),
        (f"/versions/{vid}/activate", stale_off, {"json": {}}),
        (f"/versions/{vid}/deactivate", stale_off,
         {"json": {"reason": "because it is wrong"}}),
    ]
    for path, headers, kw in writes:
        r = http.post(API + path, headers=headers, **kw)
        assert r.status_code == 403 and "re-authentication" in r.json()["detail"], path


def test_the_upload_body_cap(conn, http, monkeypatch):
    _lab, lab = _person(conn, "MALWARE_ANALYST")
    r = http.post(f"{API}/rulesets", headers=lab,
                  json={"key": f"yht-{uuid4().hex[:8]}", "display_name": "Cap"})
    set_id = r.json()["id"]
    monkeypatch.setenv("NOCTORNAL_YARA_MAX_UPLOAD_BYTES", "1MiB")
    big = io.BytesIO()
    with zipfile.ZipFile(big, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("a.yar", os.urandom(2 << 20))
    r = http.post(f"{API}/rulesets/{set_id}/versions", headers=lab,
                  files={"file": ("b.zip", big.getvalue())},
                  data={"licence": "MIT"})
    assert r.status_code == 413


def test_a_hostile_zip_is_refused_off_the_event_loop(conn, http, monkeypatch):
    """The preflight bypass of 2026-09-24 over HTTP: a zip64 record behind
    a plain end record claiming one entry. It is parsed in a worker thread,
    not on the event loop, and refused in a sentence."""
    import asyncio

    from noctornal_api import yara_rules
    from test_yara_bundle import _lying_zip
    _lab, lab = _person(conn, "MALWARE_ANALYST")
    set_id = http.post(f"{API}/rulesets", headers=lab,
                       json={"key": f"yht-{uuid4().hex[:8]}",
                             "display_name": "Z"}).json()["id"]
    on_loop = []
    real = yara_rules.parse_bundle

    def watched(name, data):
        # A running loop in this thread means the parse blocked it.
        try:
            asyncio.get_running_loop()
            on_loop.append(True)
        except RuntimeError:
            on_loop.append(False)
        return real(name, data)

    monkeypatch.setattr(yara_rules, "parse_bundle", watched)
    r = http.post(f"{API}/rulesets/{set_id}/versions", headers=lab,
                  files={"file": ("b.zip", _lying_zip(6000, zip64=True,
                                                      plain_size=46))},
                  data={"licence": "MIT"})
    assert r.status_code == 400, r.text
    assert "6000 entries" in r.json()["detail"]
    assert on_loop == [False]


def test_retrohunt_counts_only_what_the_caller_can_see_and_needs_an_active_version(conn, http):
    _lab, lab = _person(conn, "MALWARE_ANALYST", clearance="GREEN")
    r = http.post(f"{API}/rulesets", headers=lab,
                  json={"key": f"yht-{uuid4().hex[:8]}", "display_name": "G",
                        "classification": "GREEN"})
    set_id = r.json()["id"]
    vid = http.post(f"{API}/rulesets/{set_id}/versions", headers=lab,
                    files={"file": ("h.yar", RULE)},
                    data={"licence": "MIT"}).json()["id"]
    r = http.post(f"{API}/versions/{vid}/retrohunt", headers=lab)
    assert r.status_code == 409 and "not active" in r.json()["detail"]
    from noctornal_api import lab_triage
    lab_triage.compile_pending(conn, lab_triage.settings_or_default())
    _off, off = _person(conn, "SECURITY_OFFICER", clearance="GREEN")
    r = http.post(f"{API}/versions/{vid}/activate", headers=off, json={})
    assert r.status_code == 200, r.text
    r = http.post(f"{API}/versions/{vid}/retrohunt", headers=lab)
    assert r.status_code == 200
    # GREEN sees nothing of the estate (all AMBER or above): nothing to count.
    assert r.json() == {"queued": 0, "merged": 0,
                        "skipped": {"rejected": 0, "case_read_only": 0,
                                    "too_large": 0}}


def test_the_sponsor_is_refused_in_words_and_the_file_view_is_text(conn, http):
    lab_id, lab = _person(conn, "MALWARE_ANALYST")
    set_id, vid = _red_set_with_version(conn, http, lab)
    from noctornal_api import lab_triage
    lab_triage.compile_pending(conn, lab_triage.settings_or_default())
    # A lab member who is also an officer is refused as the sponsor; the
    # role pairing itself is refused by separated duty, so the second role
    # is granted to the person directly, not to a role.
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES "
                 "(%s, 'SECURITY_OFFICER')", (lab_id,))
    r = http.post(f"{API}/versions/{vid}/activate", headers=lab, json={})
    assert r.status_code == 409
    assert r.json()["detail"] == ("You uploaded or adopted this version; "
                                  "somebody else has to activate it.")
    text = http.get(f"{API}/versions/{vid}/files/0", headers=lab).json()
    assert text == {"path": "h.yar", "text": RULE.decode(), "truncated": False}


def test_the_file_view_and_every_write_are_metered():
    """The file view decompresses stored source, so it has a
    limit of its own; every write is metered by `yara.ruleset`."""
    from noctornal_api.http.routers import lab_yara
    from noctornal_api.ratelimit import LIMITS
    assert "yara.source" in LIMITS and "yara.ruleset" in LIMITS
    src = open(lab_yara.__file__, encoding="utf-8").read()
    view = src[src.index('"/versions/{version_id}/files/{index}"'):][:200]
    assert 'rate_limit("yara.source")' in view
    for route in ('@router.post("/rulesets"', '"/rulesets/{ruleset_id}/versions"',
                  '"/versions/{version_id}/adopt"',
                  '"/versions/{version_id}/activate"',
                  '"/versions/{version_id}/deactivate"',
                  '"/versions/{version_id}/retrohunt"'):
        at = src.index(route)
        assert 'rate_limit("yara.ruleset")' in src[at:at + 250], route

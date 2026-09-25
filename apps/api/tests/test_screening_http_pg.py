"""Prohibited-content screening over HTTP (F13, 2026-09-24).

Every screening route needs its permission and a fresh second factor; no
response carries a list entry that no held sample produced; the label-free
list carries only a hash prefix; the record is a 404 for an officer whose
ceiling does not reach the sample and is audited when opened, and never
carries the filename, source note, rejection reason, analyses or custody;
a matched submission answers 451 with the contact sentence and never names
the list or its category; the list upload is capped; the routes sit ahead
of /{sample_id} and the sample origin answers none of them; /admin/access
reports the two verbs; the policy block carries counts only.

Email prefix `scrh-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import hashlib
import os

import pytest

from lab_static_fixtures import auth, client, make_case, make_user, token
from screening_fixtures import assert_scrubbed, declare, listed, payload, scrub

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

API = "/api/v1"
PREFIX = "scrh-"


@pytest.fixture(autouse=True)
def authorities(monkeypatch):
    declare(monkeypatch)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    scrub(c, PREFIX)
    assert_scrubbed(c, PREFIX)
    c.close()


@pytest.fixture
def store(monkeypatch):
    import noctornal_api.samples as samples
    from lab_static_fixtures import MemoryStore
    memory = MemoryStore()
    monkeypatch.setattr(samples, "SampleStorage", lambda: memory)
    monkeypatch.setattr(samples, "PreservationStorage", lambda: _Held())
    return memory


class _Held:
    """The preservation store the route builds lazily, in memory."""

    objects: dict = {}
    bucket = "memory"

    def preserve(self, key, data):
        from noctornal_api.samples import PreservedObject
        self.objects[key] = bytes(data)
        return PreservedObject(self.bucket, key, "v1", len(data))

    def latest_held(self, key):
        return None

    def get(self, key, **_kw):
        return self.objects[key]


@pytest.fixture
def http():
    """The app, with the import limit's burst widened: the refusal test
    imports more lists in a second than an officer would; the limit itself
    is held by test_the_import_and_the_pass_are_metered."""
    from dataclasses import replace

    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    c = client()
    limits = dict(LIMITS)
    limits["screening.import"] = replace(LIMITS["screening.import"], burst=50,
                                         quota=500)
    c.app.state.limiter = RateLimiter(InProcessBackend(), limits=limits)
    return c


def test_the_import_and_the_pass_are_metered():
    from noctornal_api.http.routers import samples as routes
    from noctornal_api.ratelimit import LIMITS
    assert LIMITS["screening.import"].burst == 3
    assert LIMITS["screening.rescan"].quota == 6
    source = __import__("inspect").getsource(routes)
    assert 'rate_limit("screening.import")' in source
    assert 'rate_limit("screening.rescan")' in source


def _officer(conn, **kw):
    uid = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",), **kw)
    return uid, auth(token(conn, uid))


def _import(http, headers, text: bytes, name="HTTP list", category="OTHER_PROHIBITED"):
    return http.post(f"{API}/samples/screening/lists", headers=headers,
                     files={"file": ("list.txt", text, "text/plain")},
                     data={"name": name, "provider": "Test provider",
                           "authority_reference": "LIC-2026-001",
                           "category": category})


def _submit(http, headers, data: bytes, **form):
    return http.post(f"{API}/samples", headers=headers,
                     files={"file": ("evil-name.exe", data,
                                     "application/octet-stream")},
                     data=form)


def test_every_screening_route_needs_its_permission_and_step_up(conn, http, store):
    analyst = make_user(conn, PREFIX, roles=("ANALYST",))
    plain = auth(token(conn, analyst))
    officer, _h = _officer(conn)
    stale = auth(token(conn, officer, fresh=False))
    rid = "00000000-0000-0000-0000-000000000001"
    calls = [("get", "/samples/screening", {}),
             ("get", f"/samples/screening/results/{rid}", {}),
             ("post", f"/samples/screening/lists/{rid}/retire",
              {"json": {"reason": "a reason long enough"}}),
             ("post", f"/samples/screening/lists/{rid}/purge", {}),
             ("post", "/samples/screening/rescan", {}),
             ("post", f"/samples/screening/results/{rid}/reviews",
              {"json": {"action": "ACKNOWLEDGED"}})]
    for method, path, kw in calls:
        for headers in (plain, stale):
            r = getattr(http, method)(API + path, headers=headers, **kw)
            assert r.status_code == 403, (path, r.status_code)
    r = _import(http, plain, listed(payload()))
    assert r.status_code == 403


def test_the_label_free_list_carries_only_a_hash_prefix_and_no_entry_leaks(conn, http, store):
    officer, headers = _officer(conn)
    submitter = make_user(conn, PREFIX, roles=("ANALYST", "MALWARE_ANALYST"))
    sub_headers = auth(token(conn, submitter))
    held, unheld = payload("held"), payload("unheld")
    r = _import(http, headers, listed(held, unheld))
    assert r.status_code == 201, r.text
    r = _submit(http, sub_headers, held)
    assert r.status_code == 451
    bodies = [http.get(f"{API}/samples/screening", headers=headers)]
    overview = bodies[0].json()
    (match,) = [m for m in overview["matches"] if m["disposition"] == "PRESERVE"
                and hashlib.sha256(held).hexdigest().startswith(m["sha256_prefix"])]
    assert len(match["sha256_prefix"]) == 12
    assert "sha256" not in match and "filename" not in str(match)
    bodies.append(http.get(f"{API}/samples/screening/results/{match['result_id']}",
                           headers=headers))
    bodies.append(http.get(f"{API}/samples/policy", headers=headers))
    for digest in (hashlib.sha256(unheld).hexdigest(),
                   hashlib.sha1(unheld).hexdigest(), hashlib.md5(unheld).hexdigest()):
        for body in bodies:
            assert digest not in body.text


def test_the_detail_is_a_404_for_an_officer_not_cleared_and_is_audited_when_opened(conn, http, store):
    officer, headers = _officer(conn)
    low, low_headers = _officer(conn, clearance="GREEN")
    submitter = make_user(conn, PREFIX, roles=("ANALYST",))
    blob = payload("detail")
    _import(http, headers, listed(blob))
    r = _submit(http, auth(token(conn, submitter)), blob, classification="AMBER",
                source_note="the source note text")
    assert r.status_code == 451
    match = http.get(f"{API}/samples/screening", headers=headers).json()["matches"][0]
    assert match["you_may_open"] is True
    low_view = http.get(f"{API}/samples/screening", headers=low_headers).json()
    assert [m for m in low_view["matches"] if m["result_id"] == match["result_id"]][0][
        "you_may_open"] is False
    assert http.get(f"{API}/samples/screening/results/{match['result_id']}",
                    headers=low_headers).status_code == 404
    r = http.get(f"{API}/samples/screening/results/{match['result_id']}",
                 headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["sample"]["sha256"] == hashlib.sha256(blob).hexdigest()
    for absent in ("evil-name.exe", "the source note text",
                   "Matched a prohibited-content", "custody", "analyses"):
        assert absent not in r.text
    opened = conn.execute(
        """SELECT count(*) FROM audit.event WHERE action = 'SCREENING_RESULT_OPENED'
             AND object_id = %s AND actor_id = %s""",
        (match["result_id"], officer)).fetchone()[0]
    assert opened == 1
    del low


def test_submit_answers_451_with_the_contact_sentence_and_never_names_the_list(conn, http, store):
    officer, headers = _officer(conn)
    submitter = make_user(conn, PREFIX, roles=("ANALYST",))
    blob = payload("451")
    _import(http, headers, listed(blob), name="Secret Provider Hashes",
            category="KNOWN_CSAM")
    r = _submit(http, auth(token(conn, submitter)), blob)
    assert r.status_code == 451
    detail = r.json()["detail"]
    assert "the.dp@example.test" in detail and "POL-2026-014" in detail
    for secret in ("Secret Provider", "KNOWN_CSAM", "child", "Test provider"):
        assert secret not in r.text
    del officer


def test_the_list_body_cap_answers_413_and_names_the_command_line(conn, http, store, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_MAX_SCREENING_LIST_BYTES", "1MiB")
    _officer_id, headers = _officer(conn)
    big = b"# pad\n" * (1024 * 1024 // 6 + 10)
    r = _import(http, headers, big)
    assert r.status_code == 413
    assert "scripts/sample_screen.py import" in r.json()["detail"]


def test_import_refusals_answer_451_409_and_400(conn, http, store, monkeypatch):
    _officer_id, headers = _officer(conn)
    text = listed(payload("dup"))
    assert _import(http, headers, text).status_code == 201
    assert _import(http, headers, text).status_code == 409
    r = _import(http, headers, b"not-a-hash\n")
    assert r.status_code == 400 and "line 1" in r.json()["detail"]
    monkeypatch.delenv("NOCTORNAL_HASH_SET_AUTHORITY")
    r = _import(http, headers, listed(payload("x")))
    assert r.status_code == 451 and "NOCTORNAL_HASH_SET_AUTHORITY" in r.json()["detail"]


def test_retire_purge_rescan_and_review_over_http(conn, http, store):
    _officer_id, headers = _officer(conn)
    made = _import(http, headers, listed(payload("r"))).json()
    r = http.post(f"{API}/samples/screening/lists/{made['id']}/retire",
                  headers=headers, json={"reason": "licence ended for this list"})
    assert r.status_code == 200 and r.json()["purge_requested"] is False
    r = http.post(f"{API}/samples/screening/lists/{made['id']}/purge", headers=headers)
    assert r.status_code == 200
    r = http.post(f"{API}/samples/screening/lists/{made['id']}/purge", headers=headers)
    assert r.status_code == 409
    r = http.post(f"{API}/samples/screening/rescan", headers=headers)
    assert r.status_code == 200
    r = http.post(f"{API}/samples/screening/results/00000000-0000-0000-0000-000000000009/reviews",
                  headers=headers, json={"action": "ACKNOWLEDGED"})
    assert r.status_code == 409


def test_the_screening_routes_are_declared_before_the_sample_id_route():
    from noctornal_api.http.routers.samples import router
    paths = [r.path for r in router.routes]
    first_param = paths.index("/samples/{sample_id}")
    for path in ("/samples/screening", "/samples/screening/results/{result_id}",
                 "/samples/screening/lists", "/samples/screening/rescan",
                 "/samples/detonations/awaiting-signoff"):
        assert paths.index(path) < first_param, path


def test_the_sample_origin_process_answers_404_for_every_screening_route(conn, http, store, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_BASE_URL", "https://app.example")
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", "https://samples.example")
    _officer_id, headers = _officer(conn)
    origin = client()
    for path in ("/samples/screening", "/samples/screening/rescan",
                 "/samples/detonations/awaiting-signoff"):
        r = origin.get(API + path, headers=headers)
        assert r.status_code == 404, (path, r.status_code)


def test_admin_access_reports_the_screening_verbs(conn, http):
    _officer_id, headers = _officer(conn)
    body = http.get(f"{API}/admin/access", headers=headers).json()
    assert body["sample_screening_review"] is True
    assert body["sample_screening_manage"] is True
    analyst = make_user(conn, PREFIX, roles=("ANALYST",))
    body = http.get(f"{API}/admin/access", headers=auth(token(conn, analyst))).json()
    assert body["sample_screening_review"] is False


def test_the_policy_block_carries_counts_only(conn, http, store):
    _officer_id, headers = _officer(conn)
    _import(http, headers, listed(payload("p")), name="Named List Zeta")
    analyst = make_user(conn, PREFIX, roles=("ANALYST",))
    r = http.get(f"{API}/samples/policy", headers=auth(token(conn, analyst)))
    block = r.json()["screening"]
    assert block["active_lists"] >= 1 and block["exact_hash_only"] is True
    assert block["last_pass_at"] is not None    # the import's own pass
    assert "Named List Zeta" not in r.text
    assert r.json()["sandbox"]["configured"] in (True, False)


def test_a_sample_row_says_how_it_was_screened(conn, http, store):
    _officer_id, headers = _officer(conn)
    _import(http, headers, listed(payload("other")))
    submitter = make_user(conn, PREFIX, roles=("ANALYST",))
    case = make_case(conn, submitter)
    r = _submit(http, auth(token(conn, submitter)), payload("clean"),
                case_id=str(case))
    assert r.status_code == 201, r.text
    row = r.json()
    assert row["screening_outcome"] == "NO_MATCH" and row["screened_at"]
    assert row["screening_lists_consulted"] >= 1
    steps = [g["step"] for g in row["triage_gaps"]]
    assert "prohibited_content_perceptual" in steps
    assert "prohibited_content_screening" not in steps


def test_the_import_runs_off_the_event_loop(conn, http, store, monkeypatch):
    """The parse, the COPY and the in-request pass are synchronous work in
    an async route (async for the upload): they run in the thread pool, so
    an import never holds the event loop (2026-09-24)."""
    import asyncio

    from noctornal_api import screening
    real = screening.ScreeningService.import_list
    seen = []

    def spy(self, *args, **kw):
        try:
            asyncio.get_running_loop()
            seen.append("on the event loop")
        except RuntimeError:
            seen.append("in a worker thread")
        return real(self, *args, **kw)

    monkeypatch.setattr(screening.ScreeningService, "import_list", spy)
    _uid, headers = _officer(conn)
    assert _import(http, headers, listed(payload("loop"))).status_code == 201
    assert seen == ["in a worker thread"]

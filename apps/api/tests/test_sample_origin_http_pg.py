"""Invariant 10 over HTTP: the origin split is decided by configuration,
the console can reach the origin the split names, and "unset" is reported
as the control being off.

What was wrong until 2026-09-09, in one sentence each:

- `POST /samples/{id}/download` compared `NOCTORNAL_SAMPLE_ORIGIN` against
  `request.url`, which Starlette builds from the Host header -- so the
  check GRANTED on a value the client sends, under a comment calling it
  "the server's own view of the URL, never a header the client controls";
- the console's CSP was `connect-src 'self'`, so the Lab pane could only
  ever fetch the application origin, and the only configuration under
  which its download button worked was the sample origin BEING the
  application origin -- the configuration the invariant forbids -- while
  every document said "invariant 10 holds";
- the readiness register passed on "the variable is set", which the two
  points above make worthless, and reported an unset variable without
  saying the control was off.

The fix: three configured origins (`samples.origin_split()`), one verdict
read by the download, the CSP, the cross-origin answer, the policy
endpoint and the register; a process configured as the sample origin
serves the download and nothing else; the console fetches the sample
origin with its Bearer token. Every test here fails against the previous
code, and the ones marked "both sides" read two files that must agree.

Email prefix `so-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import io
import os
import re
import time
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; sample-origin e2e is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-10"
API = "/api/v1"
APP = "https://app.example"
SAMPLES = "https://samples.example"
STATIC = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api" / "http"
          / "static")


@pytest.fixture(autouse=True)
def declared_policy(monkeypatch):
    """Ingest refuses until a policy is declared; every test here needs a
    sample to exist, so the declaration is made visibly, once."""
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-2026-014")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "the.dp@example.test")
    # A clean slate for the three origins: the split must be decided by
    # what each test sets, never by a developer's shell.
    for var in ("NOCTORNAL_SAMPLE_ORIGIN", "NOCTORNAL_PUBLIC_ORIGIN",
                "NOCTORNAL_BASE_URL"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'so-%@noctornal.test')"
    ssub = f"(SELECT id FROM lab.sample WHERE submitted_by IN {sub})"
    with c.transaction():
        # The custody ledger is append-only by trigger (docs/11 wants
        # exactly that); the test rows are removed the way
        # test_samples_pg does it, by lifting the trigger for the sweep.
        c.execute("ALTER TABLE lab.sample_access DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_access WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.sample_access ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample WHERE submitted_by IN {sub}")
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'so-%@noctornal.test'")
    c.close()


class MemoryStore:
    """Stands in for the sample bucket so the HTTP path is provable
    without MinIO and without a bucket of live malware."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key, data):
        self.objects[key] = data

    def get(self, key):
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


@pytest.fixture
def store(monkeypatch):
    """One store shared by the service that submits and the router that
    downloads: `_svc` builds `SampleStorage()` at call time, so the class
    is replaced on the module rather than on an instance."""
    import noctornal_api.samples as samples
    memory = MemoryStore()
    monkeypatch.setattr(samples, "SampleStorage", lambda: memory)
    return memory


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


# --- helpers ------------------------------------------------------------

def _user(conn, *, roles=(), clearance="RED"):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"so-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Origin", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _login(client, email, secret) -> str:
    """Login mints the session with `mfa_satisfied=True`, so step-up is
    fresh for the download that follows."""
    from noctornal_api.security import totp
    r = client.post(f"{API}/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _analyst(conn, client):
    """A MALWARE_ANALYST (sample.download, step-up) logged in, plus a
    sample they submitted through the service into the shared store."""
    from noctornal_api.samples import SampleService
    uid, email, secret = _user(conn, roles=("MALWARE_ANALYST",))
    token = _login(client, email, secret)
    import noctornal_api.samples as samples
    sample = SampleService(conn, samples.SampleStorage()).submit(
        b"MZ\x90\x00not-really-malware-" + uuid4().bytes,
        submitted_by=uid, original_filename="x.bin")
    return token, sample


def _download(client, token, sample_id, **kw):
    return client.post(f"{API}/samples/{sample_id}/download",
                       headers={**_auth(token), **kw.pop("headers", {})}, **kw)


def _is_archive(body: bytes) -> bool:
    return zipfile.is_zipfile(io.BytesIO(body))


def _readiness(conn, client, monkeypatch) -> dict:
    """The register as a fresh SYS_ADMIN sees it. The login happens on the
    APPLICATION process -- a process configured as the sample origin
    serves no login route, which is the point of it -- so
    NOCTORNAL_PUBLIC_ORIGIN is lifted for the login and put back for the
    read."""
    _, email, secret = _user(conn, roles=("SYS_ADMIN",))
    public = os.environ.get("NOCTORNAL_PUBLIC_ORIGIN")
    monkeypatch.delenv("NOCTORNAL_PUBLIC_ORIGIN", raising=False)
    token = _login(client, email, secret)
    if public is not None:
        monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", public)
    body = client.get(f"{API}/admin/readiness", headers=_auth(token)).json()
    return {c["check"]: c for c in body["checks"]} | {"__ready__": body["ready"]}


# --- the verdict comes from configuration, never from Host ---------------

def test_the_download_grants_on_configuration_not_on_the_host_header(
        conn, client, store, monkeypatch):
    """The finding, reproduced: with the sample origin configured, a
    request to the APPLICATION process that merely says
    `Host: samples.example` was served the archive, because the check
    compared the configured origin against `request.url`, which is that
    header. Now the process's own configuration decides, and a process
    that has not been configured as the sample origin refuses whatever
    the client writes in Host."""
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "http://samples.example")
    token, sample = _analyst(conn, client)

    r = _download(client, token, sample.id,
                  headers={"Host": "samples.example"})
    assert r.status_code == 409, r.text
    assert not _is_archive(r.content), (
        "the application process served sample bytes because the client "
        "set Host to the sample origin")
    assert "http://samples.example" in r.json()["detail"], (
        "the refusal must name the origin to fetch from")
    assert conn.execute(
        "SELECT count(*) FROM lab.sample_access WHERE sample_id = %s "
        "AND action = 'DOWNLOADED'", (sample.id,)).fetchone()[0] == 0


def test_a_process_configured_as_the_sample_origin_serves_the_archive(
        conn, client, store, monkeypatch):
    """The other half: a process whose NOCTORNAL_PUBLIC_ORIGIN is the
    sample origin serves, with the attachment/nosniff/sandbox headers the
    route already carried, and records custody. Before the change this
    request was refused: the TestClient's Host is `testserver`, which is
    not the sample origin, and nothing else was consulted."""
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)
    token, sample = _analyst(conn, client)   # logged in on the app process
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)

    r = _download(client, token, sample.id)
    assert r.status_code == 200, r.text
    assert _is_archive(r.content)
    assert r.headers["Content-Type"] == "application/octet-stream"
    assert r.headers["Content-Disposition"] == (
        f'attachment; filename="{sample.sha256}.zip"')
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Content-Security-Policy"] == "default-src 'none'; sandbox"
    assert r.headers["Cache-Control"] == "no-store"
    custody = conn.execute(
        "SELECT detail->>'origin' FROM lab.sample_access WHERE sample_id = %s "
        "AND action = 'DOWNLOADED'", (sample.id,)).fetchone()
    assert custody and custody[0] == SAMPLES


def test_the_application_process_refuses_and_names_the_sample_origin(
        conn, client, store, monkeypatch):
    """A process that says nothing about its own origin is the
    application (NOCTORNAL_PUBLIC_ORIGIN defaults to NOCTORNAL_BASE_URL),
    and its refusal tells the caller where the bytes are. The old
    refusal said only "never from the application origin"."""
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)
    token, sample = _analyst(conn, client)

    r = _download(client, token, sample.id)
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert SAMPLES in detail and "never from the application origin" in detail
    assert APP in detail, "the refusal should say which origin this process is"


def test_the_sample_origin_may_not_be_the_application_origin(
        conn, client, store, monkeypatch):
    """The no-op configuration the review found: NOCTORNAL_SAMPLE_ORIGIN
    equal to the application origin passed the old check (the console's
    same-origin request arrived there) and served hostile bytes from the
    origin the invariant forbids. It is refused now, and the register
    fails on it, even on a request whose Host says the configured
    origin."""
    monkeypatch.setenv("NOCTORNAL_BASE_URL", "http://app.example")
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "http://app.example")
    token, sample = _analyst(conn, client)

    r = _download(client, token, sample.id, headers={"Host": "app.example"})
    assert r.status_code == 409, r.text
    assert not _is_archive(r.content)
    assert "not a split" in r.json()["detail"]

    check = _readiness(conn, client, monkeypatch)["sample_origin_configured"]
    assert check["ok"] is False, check
    assert "not a split" in check["evidence"]


# --- unset means OFF, in every place that speaks -------------------------

def test_readiness_reports_the_control_off_when_the_origin_is_unset(
        conn, client, store, monkeypatch):
    """Three readers, one verdict. With no sample origin the register
    FAILS and says the control is off, the policy endpoint carries the
    problem instead of a bare false, and the download refuses. The old
    evidence said the variable was "not set", which is a fact about the
    environment rather than a statement about the invariant."""
    checks = _readiness(conn, client, monkeypatch)
    check = checks["sample_origin_configured"]
    assert check["ok"] is False, check
    assert "CONTROL OFF" in check["evidence"]
    assert "refuses every request" in check["evidence"]
    assert "NOCTORNAL_PUBLIC_ORIGIN" in check["action"]
    assert checks["__ready__"] is False

    token, sample = _analyst(conn, client)
    policy = client.get(f"{API}/samples/policy", headers=_auth(token)).json()
    assert policy["sample_origin_configured"] is False
    assert policy["sample_origin"] is None
    assert "OFF" in policy["sample_origin_problem"]
    r = _download(client, token, sample.id)
    assert r.status_code == 409 and "OFF" in r.json()["detail"], r.text


def test_readiness_says_which_origin_this_process_is(conn, client, monkeypatch):
    """A passing register used to say only that the variable was set. It
    now says whether THIS process is the application (and refuses) or the
    sample origin (and serves), and hands the two facts it cannot see --
    that something serves at the other origin, and that the split is not
    a CNAME -- back to a human in so many words."""
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)

    check = _readiness(conn, client, monkeypatch)["sample_origin_configured"]
    assert check["ok"] is True, check
    assert "application origin" in check["evidence"]
    assert "refuses every download" in check["evidence"]
    assert SAMPLES in check["evidence"] and "human confirmation" in check["evidence"]

    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
    check = _readiness(conn, client, monkeypatch)["sample_origin_configured"]
    assert check["ok"] is True, check
    assert "as the sample origin" in check["evidence"]
    assert "nothing else" in check["evidence"]
    assert "human confirmation" in check["evidence"]


# --- both sides: the console can reach the origin the download names ----

def test_the_console_can_reach_the_origin_the_download_is_served_from(
        conn, client, store, monkeypatch):
    """Reads three things that must name ONE origin: the CSP the console
    is served under, the origin the policy endpoint hands the console,
    and the origin the download compares against. Until 2026-09-09 the
    CSP was `connect-src 'self'` whatever was configured, so the first
    disagreed with the other two and the Lab pane could not download from
    a correctly split deployment at all."""
    from noctornal_api.http.app import _UI_CSP
    from noctornal_api.samples import origin_split

    # Unset: the policy is exactly the constant the UI-invariant tests
    # hold the files to. Nothing is added for an origin nobody configured.
    assert client.get("/ui/").headers["Content-Security-Policy"] == _UI_CSP

    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES + "/")
    csp = client.get("/ui/").headers["Content-Security-Policy"]
    connect = [d for d in csp.split("; ") if d.startswith("connect-src")]
    assert connect == [f"connect-src 'self' {SAMPLES}"], csp
    assert csp.replace(f"connect-src 'self' {SAMPLES}", "connect-src 'self'") == _UI_CSP, (
        "the sample origin is the ONLY thing the configured CSP adds")

    token, _ = _analyst(conn, client)
    policy = client.get(f"{API}/samples/policy", headers=_auth(token)).json()
    assert policy["sample_origin"] == SAMPLES == origin_split().sample
    assert policy["sample_origin_configured"] is True
    assert policy["sample_origin_problem"] is None


def test_the_lab_pane_downloads_from_the_policys_sample_origin():
    """The console's half of the same contract, read from the file.

    `downloadSample` must build its URL from `smpPolicy.sample_origin` --
    the value the policy endpoint reports and the CSP names -- and it is
    the one call in app.js that leaves the page's origin, under its own
    name, exactly once. Until 2026-09-09 it was `fetch(API + ...)` like
    every other call, which is the application origin, which refuses.
    """
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    body = js[js.index("async function downloadSample("):]
    body = body[:body.index("\nasync function loadSamplePolicy(")]
    assert "smpPolicy.sample_origin" in body
    assert re.search(
        r"fetchFromSampleOrigin\(\s*origin \+ API \+ '/samples/'", body), (
        "the download must be rooted at the sample origin the policy "
        "endpoint reported, then the API prefix")
    assert "fetch(API + '/samples/'" not in body, (
        "a same-origin download is one the application process refuses")
    assert js.count("fetchFromSampleOrigin(") == 1, (
        "exactly one call leaves the page's origin, and it is the download")
    assert "const fetchFromSampleOrigin = window.fetch.bind(window);" in js
    # The button is enabled by the ORIGIN, not by a boolean that used to
    # read true for a value the server refused.
    actions = js[js.index("function sampleActions("):js.index("async function downloadSample(")]
    assert "smpPolicy.sample_origin)" in actions
    assert "smpPolicy.sample_origin_configured" not in actions


# --- the sample process answers the console, and serves nothing else -----

def test_the_sample_process_answers_the_consoles_preflight_for_the_app_origin_only(
        conn, client, store, monkeypatch):
    """A CSP that names the sample origin is half of letting the Lab pane
    download; without the cross-origin answer the browser makes the
    request and then withholds the response, and the pane reports "the
    request did not complete" for bytes the server served. The answer is
    given for the CONFIGURED application origin and no other, is never an
    echo of the Origin header, and rides on refusals too, so the console
    can read a 401 as well as an archive."""
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)
    token, sample = _analyst(conn, client)   # logged in on the app process
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
    path = f"{API}/samples/{sample.id}/download"

    pre = client.options(path, headers={
        "Origin": APP, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization"})
    assert pre.status_code == 204, pre.text
    assert pre.headers["Access-Control-Allow-Origin"] == APP
    assert pre.headers["Access-Control-Allow-Methods"] == "POST"
    assert "authorization" in pre.headers["Access-Control-Allow-Headers"]
    assert "Access-Control-Allow-Credentials" not in pre.headers

    other = client.options(path, headers={
        "Origin": "https://evil.example",
        "Access-Control-Request-Method": "POST"})
    assert other.status_code != 204
    assert "Access-Control-Allow-Origin" not in other.headers

    served = _download(client, token, sample.id, headers={"Origin": APP})
    assert served.status_code == 200, served.text
    assert served.headers["Access-Control-Allow-Origin"] == APP
    assert "Content-Disposition" in served.headers["Access-Control-Expose-Headers"]

    refused = client.post(path, headers={"Origin": APP})   # no token: 401
    assert refused.status_code == 401
    assert refused.headers["Access-Control-Allow-Origin"] == APP

    # The application process gives no cross-origin answer at all: nothing
    # on it is meant to be fetched from another origin.
    monkeypatch.delenv("NOCTORNAL_PUBLIC_ORIGIN")
    app_side = _download(client, token, sample.id, headers={"Origin": APP})
    assert app_side.status_code == 409
    assert "Access-Control-Allow-Origin" not in app_side.headers


def test_the_sample_process_serves_downloads_and_nothing_else(
        conn, client, store, monkeypatch):
    """The sample origin exists so that no page with an analyst's session
    runs there. The process is the same codebase as the application, so
    until 2026-09-09 it would have served the console, the login form and
    every case route at the sample hostname -- and docs/16 C9 asked a
    human to confirm a proxy allow-list nobody tests. Now the process
    refuses everything but the download, its preflight, /healthz and the
    readiness register."""
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)
    token, sample = _analyst(conn, client)   # logged in on the app process
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)

    for path in ("/ui/", "/", f"{API}/samples", f"{API}/samples/{sample.id}",
                 f"{API}/cases"):
        r = client.get(path, headers=_auth(token))
        assert r.status_code == 404, (path, r.status_code, r.text)
        assert APP in r.json()["detail"], "the refusal names the application"
    r = client.post(f"{API}/auth/login", json={})
    assert r.status_code == 404, r.text
    assert client.get("/healthz").status_code == 200
    assert _download(client, token, sample.id).status_code == 200
    check = _readiness(conn, client, monkeypatch)["sample_origin_configured"]
    assert "as the sample origin" in check["evidence"], check


# --- the pieces the verdict is built from --------------------------------

def test_the_default_application_origin_is_the_one_email_links_use(monkeypatch):
    """`samples.app_origin()` restates `transports.base_url()`'s default
    rather than importing it. Two copies of one fact are the codebase's
    other signature defect, so this reads both and insists they agree --
    with the variable unset and with it set."""
    from noctornal_api import transports
    from noctornal_api.samples import _DEFAULT_APP_ORIGIN, app_origin

    monkeypatch.delenv("NOCTORNAL_BASE_URL", raising=False)
    assert app_origin() == transports.base_url() == _DEFAULT_APP_ORIGIN
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP + "/")
    assert app_origin() == transports.base_url() == APP


@pytest.mark.parametrize("value, expected", [
    ("https://samples.example", "https://samples.example"),
    ("HTTPS://Samples.Example:443/", "https://samples.example"),
    ("http://samples.example:8001", "http://samples.example:8001"),
    ("http://[::1]:8001", "http://[::1]:8001"),
    ("https://samples.example/lab", None),
    ("https://samples.example/?x=1", None),
    ("https://u:p@samples.example", None),
    ("samples.example", None),
    ("ftp://samples.example", None),
    ("null", None),
    ("", None),
])
def test_normalise_origin_accepts_origins_and_nothing_else(value, expected):
    """The split is decided by string equality, so the one normaliser is
    what "the same origin" means to the download, the CSP and the
    cross-origin answer. A path is refused for the sample origin because
    `app.internal/samples` is the shape docs/11 says is not separate."""
    from noctornal_api.samples import normalise_origin
    assert normalise_origin(value) == expected


def test_a_path_on_the_sample_origin_is_reported_not_silently_dropped(
        conn, client, monkeypatch):
    """A configured value that is not an origin is a third deployment
    problem, distinct from "unset": the register says what was typed and
    why it is refused, rather than reporting the variable as missing."""
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://app.example/samples")
    check = _readiness(conn, client, monkeypatch)["sample_origin_configured"]
    assert check["ok"] is False, check
    assert "https://app.example/samples" in check["evidence"]
    assert "not an origin" in check["evidence"]
    assert "CONTROL OFF" not in check["evidence"]

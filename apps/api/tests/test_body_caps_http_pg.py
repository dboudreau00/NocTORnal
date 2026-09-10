"""Body caps over HTTP: a body one byte over the cap is refused with 413
BEFORE it is read, on both write paths (2026-09-09).

The Alpha 4 review named two unbounded body reads:

- `POST /cases/{id}/evidence` did `await file.read()` with no cap. A caller
  could hand the API gigabytes; nothing refused; the bytes were locked in
  the evidence bucket under a COMPLIANCE retention that no credential can
  shorten.
- `POST /ingest` did `await request.body()` and checked the key's
  `max_bytes_per_request` AFTER the whole body had been accumulated. The
  cap existed and was useless against the thing a cap is for.
- `POST /samples` and `POST /cases/{id}/deception/emails` (added here
  2026-09-09) each read the upload in chunks and stopped at their cap --
  AFTER FastAPI's multipart parser had spooled the whole body to a
  temporary file. Memory was bounded; the bytes had all arrived. Both
  now opt into `BodyCappedRoute` like evidence.

**Why this file drives the app as raw ASGI rather than through TestClient.**
Starlette's TestClient calls `request.read()` on the httpx request before
the app sees a byte, so every body it sends arrives in one message and the
app cannot be told apart from one that buffers everything first. Here the
body comes from a generator that RAISES if the app asks for the byte past
the cap. Before the fix both routes asked -- `file.read()` and
`request.body()` read to the end -- and these tests died on that
AssertionError instead of seeing a 413. After it, the 413 arrives first
and the generator is never asked again.

Two refusal paths are proven for each route, because they are different
code: a body whose `Content-Length` declares more than the cap is refused
before ANY byte is read, and a body with no declared length (chunked) is
refused on the chunk that crosses the cap. A body exactly AT the cap is
the positive control: it proves the cap is not off by one in the other
direction and that the parser still reads through the capped receive.

**The email prefix is `bcap-` and must stay unique.**

Env-gated on DATABASE_URL and MINIO_ENDPOINT: the positive controls write a
real exhibit and a real raw batch, and the refusals look in the bucket to
prove nothing was written.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import time
from datetime import date
from uuid import uuid4

import httpx
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
MINIO = os.environ.get("MINIO_ENDPOINT", "")
pytestmark = pytest.mark.skipif(
    not (DATABASE_URL and MINIO),
    reason="DATABASE_URL and MINIO_ENDPOINT required; body-cap e2e is gated")

PASSWORD = "correct-horse-battery-staple"
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "bcap-%@noctornal.test"

#: Small on purpose. The real evidence cap is 256 MiB; a test that has to
#: send 256 MiB to prove a 413 is a test nobody runs. `MAX_EVIDENCE_BYTES`
#: is read at request time precisely so it can be shrunk here.
EVIDENCE_CAP = 64 * 1024
#: The ingest cap is per key, a column on `ingest.api_key`; the test sets
#: its own key's column.
INGEST_CAP = 4096
#: The sample and email caps are module constants read at request time,
#: shrunk here for the same reason as the evidence cap.
SAMPLE_CAP = 64 * 1024
EML_CAP = 64 * 1024


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    esub = f"(SELECT id FROM core.evidence WHERE case_id IN {csub})"
    keys = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    # Custody rows are never deleted and the chain is never stood down
    # (see test_evidence_pg.py for why: the ledger is produced in court).
    # Everything a custody row points at stays with it, keyed on this
    # suite's uuid-random prefix so the residue cannot collide.
    pinned_evidence = "(SELECT evidence_id FROM core.evidence_custody)"
    pinned_cases = "(SELECT case_id FROM core.evidence WHERE case_id IS NOT NULL)"
    pinned_users = (
        "(SELECT actor_id FROM core.evidence_custody WHERE actor_id IS NOT NULL"
        " UNION SELECT acquired_by FROM core.evidence WHERE acquired_by IS NOT NULL"
        ' UNION SELECT owner_user_id FROM core."case" WHERE owner_user_id IS NOT NULL'
        ' UNION SELECT deputy_user_id FROM core."case" WHERE deputy_user_id IS NOT NULL'
        # The sample the positive control lands: `submit` writes the
        # submission itself into `lab.sample_access`, which is append-only,
        # so neither the sample nor its submitter can ever be deleted. Same
        # residue policy as custody, keyed on this suite's random prefix.
        ' UNION SELECT submitted_by FROM lab.sample WHERE submitted_by IS NOT NULL)'
    )
    with c.transaction():
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {keys}")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN "
                  f"(SELECT id FROM ingest.batch WHERE api_key_id IN {keys})")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {keys}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub} "
                  f"AND id NOT IN {pinned_evidence}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub} '
                  f"AND id NOT IN {pinned_cases}")
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}' "
                  f"AND id NOT IN {pinned_users}")
    c.close()


@pytest.fixture
def app():
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    application = create_app()
    application.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return application


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient
    return TestClient(app)


@pytest.fixture
def evidence_cap(monkeypatch):
    # `raising=False` so that against a router with NO cap constant -- the
    # state before 2026-09-09 -- the test reaches the generator's tripwire
    # and fails on behaviour, not on the fixture. Measured: without it the
    # pre-change run errored here with an AttributeError, which proves
    # nothing about the route.
    monkeypatch.setattr(
        "noctornal_api.http.routers.evidence.MAX_EVIDENCE_BYTES", EVIDENCE_CAP,
        raising=False)
    return EVIDENCE_CAP


@pytest.fixture
def sample_cap(monkeypatch):
    monkeypatch.setattr(
        "noctornal_api.http.routers.samples.MAX_SAMPLE_BYTES", SAMPLE_CAP,
        raising=False)
    # The positive control lands a real row, which the service refuses
    # until an operator has declared a prohibited-content policy (docs/11).
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "TEST-POLICY-BCAP")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "test designated person")
    return SAMPLE_CAP


@pytest.fixture
def eml_cap(monkeypatch):
    monkeypatch.setattr(
        "noctornal_api.http.routers.deception.MAX_EML_BYTES", EML_CAP,
        raising=False)
    return EML_CAP


def _make_user(conn, *, global_roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"bcap-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Cap", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s", (uid,))
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _login(client, email, secret) -> str:
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _create_case(client, token) -> str:
    r = client.post("/api/v1/cases", headers={"Authorization": f"Bearer {token}"},
                    json={"code": f"OP-BCAP-{uuid4().hex[:6]}", "title": "Operation Cap",
                          "legal_basis": "production order 2026-0001",
                          "retention_until": str(date(2028, 1, 1)),
                          "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ---------------------------------------------------------------------------
# The raw ASGI driver and the body generator that refuses to be over-read
# ---------------------------------------------------------------------------

class _Body:
    """The request body as ASGI messages, with a tripwire past the cap.

    `cap=None` is a complete body: chunks, a terminator, then disconnects
    for anything that polls afterwards. With a cap, the chunks stop at the
    byte that crosses it -- every message says `more_body`, so a reader
    that wants the end has to ask again, and asking again is the failure
    this file exists to catch. `refuse_any_read` is the tripwire for the
    declared-length path, where the correct behaviour is to read nothing.
    """

    def __init__(self, body: bytes, *, cap: int | None, chunk: int = 4096,
                 refuse_any_read: bool = False):
        self.refuse_any_read = refuse_any_read
        self.calls = 0
        self.delivered = 0
        if cap is None:
            pieces = [body[i:i + chunk] for i in range(0, len(body), chunk)]
            self.messages = [{"type": "http.request", "body": p, "more_body": True}
                             for p in pieces]
            self.messages.append({"type": "http.request", "body": b"",
                                  "more_body": False})
            self.tripwire = False
        else:
            head, tail = body[:cap], body[cap:]
            pieces = [head[i:i + chunk] for i in range(0, len(head), chunk)]
            if tail:
                pieces.append(tail)
            self.messages = [{"type": "http.request", "body": p, "more_body": True}
                             for p in pieces]
            self.tripwire = True

    async def receive(self) -> dict:
        if self.refuse_any_read:
            raise AssertionError(
                "the app read the body although the declared Content-Length "
                "already exceeded the cap; the refusal should come first")
        if self.calls >= len(self.messages):
            if not self.tripwire:
                return {"type": "http.disconnect"}
            raise AssertionError(
                f"the app asked for the body past the cap: {self.delivered} "
                f"bytes were already delivered and the last of them crossed it")
        message = self.messages[self.calls]
        self.calls += 1
        self.delivered += len(message["body"])
        return message


def _drive(app, *, method: str, path: str, headers: dict[str, str],
           body: _Body) -> tuple[int, dict[str, str], bytes]:
    """One request, straight into the ASGI app, body from `body`."""
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(), "query_string": b"",
        "root_path": "", "server": ("testserver", 80),
        "client": ("127.0.0.1", 41000), "state": {},
        "headers": [(k.lower().encode(), v.encode())
                    for k, v in {"host": "testserver", **headers}.items()],
    }
    sent: list[dict] = []

    async def send(message: dict) -> None:
        sent.append(message)

    asyncio.run(app(scope, body.receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in sent
                       if m["type"] == "http.response.body")
    return (start["status"],
            {k.decode(): v.decode() for k, v in start["headers"]}, payload)


def _multipart(payload: bytes, *, filename: str = "cap.bin") -> tuple[bytes, str]:
    """A multipart body the way a browser or httpx would encode it. The
    `title` field is evidence's; the other two forms ignore it."""
    req = httpx.Request(
        "POST", "http://testserver/", data={"title": "cap test"},
        files={"file": (filename, payload, "application/octet-stream")})
    return req.read(), req.headers["content-type"]


def _multipart_of_total(total: int, *, head: bytes = b"",
                        filename: str = "cap.bin") -> tuple[bytes, str]:
    """A multipart body of EXACTLY `total` bytes. The cap is on the body,
    not the file, so the file is sized to make the body land on the number.
    `head` leads the file's bytes: a message header block, or a nonce for
    a service that deduplicates on content."""
    overhead = len(_multipart(b"", filename=filename)[0])
    fill = total - overhead - len(head)
    assert fill >= 0, (total, overhead, len(head))
    body, content_type = _multipart(head + b"x" * fill, filename=filename)
    assert len(body) == total, (len(body), total)
    return body, content_type


def _evidence_objects(case_id: str) -> list[str]:
    from noctornal_api.evidence import EvidenceStorage
    storage = EvidenceStorage()
    return [o.object_name for o in storage._client.list_objects(
        storage.bucket, prefix=f"{case_id}/")]


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

def test_an_evidence_body_one_byte_over_the_cap_is_refused_before_it_is_read(
        conn, app, client, evidence_cap):
    """Both refusal paths, and nothing written on either.

    Before 2026-09-09 this test failed inside the body generator: the
    multipart parser read to the end of the upload, the handler did
    `await file.read()`, and the object was put in the bucket under a
    COMPLIANCE lock before anything asked how big it was.
    """
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    body, content_type = _multipart_of_total(evidence_cap + 1)
    auth = {"authorization": f"Bearer {token}", "content-type": content_type}
    path = f"/api/v1/cases/{case_id}/evidence"

    # Declared length over the cap: refused before a byte is read.
    declared = _Body(body, cap=evidence_cap, refuse_any_read=True)
    status, headers, payload = _drive(
        app, method="POST", path=path, body=declared,
        headers={**auth, "content-length": str(len(body))})
    assert status == 413, payload
    assert str(evidence_cap) in payload.decode(), payload
    assert headers.get("content-type", "").startswith("application/problem+json")
    assert headers.get("connection") == "close"
    assert declared.delivered == 0

    # No declared length (chunked): refused on the chunk that crosses.
    chunked = _Body(body, cap=evidence_cap)
    status, headers, payload = _drive(
        app, method="POST", path=path, body=chunked, headers=auth)
    assert status == 413, payload
    assert str(evidence_cap) in payload.decode(), payload
    assert chunked.delivered == evidence_cap + 1, (
        "the generator hands over the crossing byte and must not be asked "
        "for anything after it")

    # Nothing was written: no row, and no object under the case prefix in
    # the object-locked bucket -- which is the part nobody could undo.
    assert conn.execute(
        "SELECT count(*) FROM core.evidence WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 0
    assert _evidence_objects(case_id) == []


def test_an_evidence_body_at_the_cap_is_accepted(conn, app, client, evidence_cap):
    """The positive control. A cap that refuses everything also passes the
    refusal test, so the body exactly AT the cap must still lodge an
    exhibit -- through the capped receive, in chunks, with the length
    declared the way a browser declares it."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    body, content_type = _multipart_of_total(evidence_cap)
    status, _headers, payload = _drive(
        app, method="POST", path=f"/api/v1/cases/{case_id}/evidence",
        body=_Body(body, cap=None),
        headers={"authorization": f"Bearer {token}", "content-type": content_type,
                 "content-length": str(len(body))})
    assert status == 201, payload
    assert conn.execute(
        "SELECT count(*) FROM core.evidence WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 1
    assert len(_evidence_objects(case_id)) == 1


@pytest.mark.parametrize("module, path, constant, word", [
    ("evidence", "/cases/{case_id}/evidence", "MAX_EVIDENCE_BYTES", "evidence"),
    ("samples", "/samples", "MAX_SAMPLE_BYTES", "sample"),
    ("deception", "/cases/{case_id}/deception/emails", "MAX_EML_BYTES", "email"),
])
def test_each_upload_route_and_the_cap_helper_are_actually_connected(
        module, path, constant, word):
    """Reads both sides of the contract that crosses two files.

    `body_cap` in http/limits.py leaves a marker; `BodyCappedRoute` reads
    it; each upload router has to opt into BOTH -- the decorator on the
    endpoint and `route_class=` on the router -- or the cap is a docstring.
    The generator tests catch a disconnection too, but they need the
    stack up; this one runs anywhere and names which half went missing.
    Evidence opted in first; samples and deception followed on 2026-09-09.
    """
    import importlib

    from fastapi.routing import APIRoute

    from noctornal_api.http import limits

    mod = importlib.import_module(f"noctornal_api.http.routers.{module}")
    uploads = [r for r in mod.router.routes
               if isinstance(r, APIRoute) and "POST" in r.methods
               and r.path == path]
    assert len(uploads) == 1, [r.path for r in mod.router.routes]
    route = uploads[0]
    assert isinstance(route, limits.BodyCappedRoute), (
        f"routers/{module}.py must build its router with route_class=BodyCappedRoute")
    marker = getattr(route.endpoint, limits._BODY_CAP_ATTR, None)
    assert marker is not None, f"the {module} upload endpoint has lost its @body_cap marker"
    cap_of, what = marker
    assert cap_of() == getattr(mod, constant)
    assert word in what


def test_no_router_keeps_a_private_copy_of_the_chunked_read():
    """The samples and deception routers each carried a `_read_capped`
    that read the upload in chunks and stopped at the cap -- after the
    multipart parser had already spooled the whole body. A copy that
    comes back is a cap that looks enforced and is not."""
    from pathlib import Path

    from noctornal_api.http import routers

    here = Path(routers.__file__).parent
    # A DEFINITION is a copy; the routers may still name the old helper
    # in the comment that says why it is gone.
    offenders = [p.name for p in sorted(here.glob("*.py"))
                 if "def _read_capped(" in p.read_text(encoding="utf-8")]
    assert offenders == [], offenders


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------

def _issue_key(conn, owner, *, cap: int) -> tuple[str, str]:
    """(key row id, bearer secret) for a key capped at `cap` bytes."""
    from noctornal_api.ingest import IngestService
    issued = IngestService(conn).issue_key(
        name="cap feed", owner_user_id=owner, declared_category="UNKNOWN")
    conn.execute("UPDATE ingest.api_key SET max_bytes_per_request = %s WHERE id = %s",
                 (cap, issued.id))
    return str(issued.id), issued.secret


def test_an_ingest_body_one_byte_over_the_keys_cap_is_refused_before_it_is_read(
        conn, app):
    """Before 2026-09-09 `submit` did `await request.body()` and only then
    handed the bytes to `accept()`, whose length check refused with a 400.
    The refusal was real and arrived after the buffering it was meant to
    prevent; this test died in the generator."""
    owner, _e, _s = _make_user(conn, global_roles=("SYS_ADMIN",))
    key_row_id, secret = _issue_key(conn, owner, cap=INGEST_CAP)
    body = (b'{"note": "' + b"x" * INGEST_CAP + b'"}')[:INGEST_CAP + 1]
    assert len(body) == INGEST_CAP + 1
    auth = {"authorization": f"Bearer {secret}", "content-type": "application/json"}

    declared = _Body(body, cap=INGEST_CAP, refuse_any_read=True)
    status, headers, payload = _drive(
        app, method="POST", path="/api/v1/ingest", body=declared,
        headers={**auth, "content-length": str(len(body))})
    assert status == 413, payload
    assert str(INGEST_CAP) in payload.decode(), payload
    assert headers.get("connection") == "close"
    assert declared.delivered == 0

    chunked = _Body(body, cap=INGEST_CAP, chunk=1024)
    status, _headers, payload = _drive(
        app, method="POST", path="/api/v1/ingest", body=chunked, headers=auth)
    assert status == 413, payload
    assert str(INGEST_CAP) in payload.decode(), payload
    assert chunked.delivered == INGEST_CAP + 1

    assert conn.execute(
        "SELECT count(*) FROM ingest.batch WHERE api_key_id = %s",
        (key_row_id,)).fetchone()[0] == 0, "a refused submission must leave no batch"


def test_an_ingest_body_at_the_keys_cap_is_accepted(conn, app):
    """The positive control: exactly the cap is a 202 with a batch row and
    the raw object behind it."""
    from noctornal_api.rawstore import RawBatchStorage
    owner, _e, _s = _make_user(conn, global_roles=("SYS_ADMIN",))
    key_row_id, secret = _issue_key(conn, owner, cap=INGEST_CAP)
    body = (b'{"note": "' + b"y" * INGEST_CAP + b'"}')[:INGEST_CAP]
    storage = RawBatchStorage()
    storage.ensure_bucket()
    try:
        status, _headers, payload = _drive(
            app, method="POST", path="/api/v1/ingest",
            body=_Body(body, cap=None, chunk=1024),
            headers={"authorization": f"Bearer {secret}",
                     "content-type": "application/json",
                     "content-length": str(len(body))})
        assert status == 202, payload
        assert conn.execute(
            "SELECT count(*) FROM ingest.batch WHERE api_key_id = %s",
            (key_row_id,)).fetchone()[0] == 1
        digest = hashlib.sha256(body).hexdigest()
        assert storage.get(f"ingest/{digest[:2]}/{digest}") == body
    finally:
        digest = hashlib.sha256(body).hexdigest()
        # The raw bucket has no lock; leave nothing behind.
        storage._client.remove_object(storage.bucket, f"ingest/{digest[:2]}/{digest}")


def test_the_ingest_docstring_and_the_schema_agree_on_the_default_cap(conn):
    """The `submit` docstring says the key cap defaults to 32 MiB. That
    number lives in migration 0033 as the column default, and a docstring
    that quotes a number the schema no longer holds is exactly the defect
    this pass is answering. Read from the live schema, not the migration
    file, because the schema is what runs."""
    default = conn.execute(
        """SELECT column_default FROM information_schema.columns
            WHERE table_schema = 'ingest' AND table_name = 'api_key'
              AND column_name = 'max_bytes_per_request'""").fetchone()[0]
    assert default is not None and "33554432" in default, default
    assert 33554432 == 32 * 1024 * 1024


# ---------------------------------------------------------------------------
# Samples
# ---------------------------------------------------------------------------

def _sample_rows(conn, submitter) -> int:
    return conn.execute(
        "SELECT count(*) FROM lab.sample WHERE submitted_by = %s",
        (submitter,)).fetchone()[0]


def test_a_sample_body_one_byte_over_the_cap_is_refused_before_it_is_read(
        conn, app, client, sample_cap):
    """Until 2026-09-09 the samples router read the upload in one-megabyte
    chunks and stopped at the cap -- after FastAPI's multipart parser had
    spooled the whole body to a temporary file. The chunked read bounded
    this process's memory; the bytes had all arrived. Before the change
    this test died in the generator, exactly as the evidence one did."""
    uid, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    body, content_type = _multipart_of_total(sample_cap + 1)
    auth = {"authorization": f"Bearer {token}", "content-type": content_type}

    declared = _Body(body, cap=sample_cap, refuse_any_read=True)
    status, headers, payload = _drive(
        app, method="POST", path="/api/v1/samples", body=declared,
        headers={**auth, "content-length": str(len(body))})
    assert status == 413, payload
    assert str(sample_cap) in payload.decode(), payload
    assert headers.get("content-type", "").startswith("application/problem+json")
    assert headers.get("connection") == "close"
    assert declared.delivered == 0

    chunked = _Body(body, cap=sample_cap)
    status, _headers, payload = _drive(
        app, method="POST", path="/api/v1/samples", body=chunked, headers=auth)
    assert status == 413, payload
    assert str(sample_cap) in payload.decode(), payload
    assert chunked.delivered == sample_cap + 1

    assert _sample_rows(conn, uid) == 0, "a refused submission must leave no row"


def test_a_sample_body_at_the_cap_is_accepted(conn, app, client, sample_cap):
    """The positive control, through the capped receive and into
    quarantine. Unique content: the service deduplicates on hash, and a
    fixed payload would fail the second run on the first run's row."""
    uid, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    body, content_type = _multipart_of_total(
        sample_cap, head=b"MZ\x90\x00not-really-malware-" + uuid4().bytes)
    status, _headers, payload = _drive(
        app, method="POST", path="/api/v1/samples", body=_Body(body, cap=None),
        headers={"authorization": f"Bearer {token}", "content-type": content_type,
                 "content-length": str(len(body))})
    assert status == 201, payload
    assert _sample_rows(conn, uid) == 1


# ---------------------------------------------------------------------------
# Deception: the .eml exhibit
# ---------------------------------------------------------------------------

def _eml_of_total(total: int) -> tuple[bytes, str]:
    """A multipart body of exactly `total` bytes whose file part is a
    parseable RFC 5322 message -- headers, then a text body padded to the
    number -- so the positive control records an email, not a gap."""
    head = (b"From: Accounts Payable <ap@victim.example>\r\n"
            b"To: cfo@victim.example\r\n"
            b"Subject: Updated bank details\r\n"
            b"Date: Mon, 20 Jul 2026 09:00:00 +0000\r\n"
            b"Message-ID: <" + uuid4().hex.encode() + b"@lure.example>\r\n"
            b"Content-Type: text/plain; charset=us-ascii\r\n\r\n")
    return _multipart_of_total(total, head=head, filename="lure.eml")


def test_an_email_exhibit_one_byte_over_the_cap_is_refused_before_it_is_read(
        conn, app, client, eml_cap):
    """Same shape as the samples router, same date, same fix."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    body, content_type = _eml_of_total(eml_cap + 1)
    auth = {"authorization": f"Bearer {token}", "content-type": content_type}
    path = f"/api/v1/cases/{case_id}/deception/emails"

    declared = _Body(body, cap=eml_cap, refuse_any_read=True)
    status, headers, payload = _drive(
        app, method="POST", path=path, body=declared,
        headers={**auth, "content-length": str(len(body))})
    assert status == 413, payload
    assert str(eml_cap) in payload.decode(), payload
    assert headers.get("connection") == "close"
    assert declared.delivered == 0

    chunked = _Body(body, cap=eml_cap)
    status, _headers, payload = _drive(
        app, method="POST", path=path, body=chunked, headers=auth)
    assert status == 413, payload
    assert str(eml_cap) in payload.decode(), payload
    assert chunked.delivered == eml_cap + 1

    # Nothing lodged: no exhibit row, no object under the case, no message.
    assert conn.execute(
        "SELECT count(*) FROM core.evidence WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 0
    assert _evidence_objects(case_id) == []
    assert conn.execute(
        "SELECT count(*) FROM deception.email_message WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 0


def test_an_email_exhibit_at_the_cap_is_accepted(conn, app, client, eml_cap):
    """The positive control: the exhibit lands under its lock and the
    message is recorded from it."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    body, content_type = _eml_of_total(eml_cap)
    status, _headers, payload = _drive(
        app, method="POST", path=f"/api/v1/cases/{case_id}/deception/emails",
        body=_Body(body, cap=None),
        headers={"authorization": f"Bearer {token}", "content-type": content_type,
                 "content-length": str(len(body))})
    assert status == 201, payload
    assert conn.execute(
        "SELECT count(*) FROM core.evidence WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 1
    assert len(_evidence_objects(case_id)) == 1
    assert conn.execute(
        "SELECT count(*) FROM deception.email_message WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 1

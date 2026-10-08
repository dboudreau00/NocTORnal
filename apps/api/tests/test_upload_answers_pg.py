"""What an upload answers when it cannot be accepted (2026-10-08).

- An unknown classification is the caller's mistake and is a 400 that names
  the ones there are, before anything else is read. It reached
  `check_writable_labels`, whose refusal to resolve a label is a 403, so a
  typo read as a missing permission.
- The object store gets a pool that gives up in seconds. minio-py's own waits
  five minutes on a connect and retries five times: a store that was down
  held an upload for about 18 seconds and answered a raw 500.
- A store that did not answer is a 503 with a `Retry-After`, the caller may
  try again, and the exhibit was not lodged.
- No "orphaned" audit row when nothing was stored. A put that never reached
  the store (refused, timed out opening, no such name) stored nothing and
  records nothing; one that was sent and not answered may have landed and does.

Accounts `g44t-*`. Nothing is written to the dev bucket: the service is given
`g44_support.VersionedStore`, and the one test that uses the real storage
class points it at a socket on this host that never answers.
"""
from __future__ import annotations

import socket
import threading
from uuid import uuid4

import pytest

import g44_support as g

pytestmark = g.GATED

conn = g.conn

API = "/api/v1"


@pytest.fixture
def store(monkeypatch):
    st = g.VersionedStore()
    import noctornal_api.evidence as ev
    import noctornal_api.http.routers.evidence as evr
    monkeypatch.setattr(ev, "EvidenceStorage", lambda: st)
    monkeypatch.setattr(evr, "EvidenceStorage", lambda: st)
    return st


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app, raise_server_exceptions=False)


def _upload(client, headers, case_id, data, **form):
    form.setdefault("title", "g79 upload")
    form.setdefault("classification", "AMBER")
    return client.post(f"{API}/cases/{case_id}/evidence", headers=headers,
                       files={"file": ("f.bin", data, "application/octet-stream")},
                       data=form)


def _rows(conn, case_id) -> int:
    return conn.execute("SELECT count(*) FROM core.evidence WHERE case_id = %s",
                        (case_id,)).fetchone()[0]


def _orphans(conn, case_id) -> list:
    return g.audit_rows(conn, "EVIDENCE_OBJECT_ORPHANED", case_id=case_id)


def _world(conn):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    return boss, case_id, g.token(conn, boss)


def _body() -> bytes:
    return b"g79-upload-" + uuid4().hex.encode()


# --- an unknown classification ----------------------------------------------------

@pytest.mark.parametrize("label", ["PURPLE", "amber", "TLP:AMBER", " AMBER"])
def test_an_unknown_classification_is_a_400_that_names_the_ones_there_are(
        conn, store, client, label):
    _boss, case_id, headers = _world(conn)
    r = _upload(client, headers, case_id, _body(), classification=label)
    assert r.status_code == 400, (label, r.status_code, r.text)
    detail = r.json()["detail"]
    for name in ("CLEAR", "GREEN", "AMBER", "RED"):
        assert name in detail, detail
    assert store.puts == [] and _rows(conn, case_id) == 0
    assert _orphans(conn, case_id) == []


def test_a_known_classification_above_the_uploader_is_still_a_403(conn, store, client):
    """The new check only recognises the name. Whether the uploader may write
    at it is the access gate's, as before."""
    analyst = g.user(conn, "AMBER", roles=("ANALYST",))
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    import rls_support as s
    s.assign(conn, case_id, analyst, "ANALYST")
    r = _upload(client, g.token(conn, analyst), case_id, _body(),
                classification="RED")
    assert r.status_code == 403, r.text
    assert store.puts == [] and _rows(conn, case_id) == 0


def test_a_known_classification_is_accepted(conn, store, client):
    """Every name there is gets past the new check; the case here is AMBER,
    so an exhibit may be AMBER or above it."""
    _boss, case_id, headers = _world(conn)
    for label in ("AMBER", "RED"):
        r = _upload(client, headers, case_id, _body(), classification=label)
        assert r.status_code == 201, (label, r.text)
    assert len(store.puts) == 2


def test_a_name_below_the_case_is_still_the_exhibit_rule_not_the_new_check(
        conn, store, client):
    """GREEN is a name there is. That an AMBER case's exhibit may not be
    classified below it is the service's own refusal, and keeps its words."""
    _boss, case_id, headers = _world(conn)
    r = _upload(client, headers, case_id, _body(), classification="GREEN")
    assert r.status_code == 400, r.text
    assert "cannot be classified below" in r.json()["detail"]
    assert store.puts == []


# --- a store that did not answer ------------------------------------------------------

def _down(exc):
    def put(_key):
        raise exc
    return put


def _refused():
    import urllib3
    refused = urllib3.exceptions.NewConnectionError(
        None, "Failed to establish a new connection: [Errno 111] Connection refused")
    return urllib3.exceptions.MaxRetryError(None, "/noctornal-evidence/k",
                                            reason=refused)


def _read_timeout():
    import urllib3
    gave_up = urllib3.exceptions.ReadTimeoutError(
        None, "/noctornal-evidence/k", "Read timed out. (read timeout=60.0)")
    return urllib3.exceptions.MaxRetryError(None, "/noctornal-evidence/k",
                                            reason=gave_up)


def test_a_store_that_is_down_is_a_503_and_leaves_nothing_behind(
        conn, store, client):
    _boss, case_id, headers = _world(conn)
    store.on_put = _down(_refused())
    r = _upload(client, headers, case_id, _body())

    assert r.status_code == 503, (r.status_code, r.text)
    assert r.headers["retry-after"] == "5"
    body = r.json()
    assert body["title"] == "Service unavailable"
    assert "did not answer" in body["detail"] and "Try again" in body["detail"]
    assert "Traceback" not in r.text and "urllib3" not in r.text
    assert _rows(conn, case_id) == 0
    assert g.audit_rows(conn, "EVIDENCE_ACQUIRED", case_id=case_id) == []
    # Nothing reached the store, so nothing is stored and nothing is recorded
    # as "may be stored with no row naming it".
    assert _orphans(conn, case_id) == []


def test_a_put_that_was_sent_and_not_answered_is_a_503_and_is_recorded(
        conn, store, client):
    """The request went out and the read timed out: the object may have
    landed under a lock, so the audit log names the key for a sweep."""
    _boss, case_id, headers = _world(conn)
    store.on_put = _down(_read_timeout())
    r = _upload(client, headers, case_id, _body())

    assert r.status_code == 503, (r.status_code, r.text)
    assert _rows(conn, case_id) == 0
    [(detail, outcome, _object, _case)] = _orphans(conn, case_id)
    assert outcome == "FAILED" and detail["reason"] == "StoreUnavailable"
    assert detail["storage_key"].startswith(f"{case_id}/")


@pytest.mark.parametrize("make, sent", [
    (lambda: ConnectionRefusedError(111, "refused"), False),
    (lambda: socket.gaierror(-2, "Name or service not known"), False),
    (lambda: ConnectionResetError(104, "reset by peer"), True),
    (lambda: TimeoutError("timed out"), True),
])
def test_a_plain_socket_error_is_classified_by_whether_the_request_was_sent(
        conn, store, client, make, sent):
    """Refused and unresolvable never reached the store; a reset or a timeout
    may have come after the bytes did."""
    _boss, case_id, headers = _world(conn)
    store.on_put = _down(make())
    r = _upload(client, headers, case_id, _body())
    assert r.status_code == 503, (r.status_code, r.text)
    assert (len(_orphans(conn, case_id)) == 1) is sent
    assert _rows(conn, case_id) == 0


def test_a_refusal_from_the_store_is_not_a_store_that_did_not_answer(
        conn, store, client):
    """The store answered. Its refusal keeps its code and is the server's own
    fault to report as it was: a 503 asking for a retry would be wrong."""
    from minio.error import S3Error
    refusal = S3Error.__new__(S3Error)
    Exception.__init__(refusal, "AccessDenied")
    _boss, case_id, headers = _world(conn)
    store.on_put = _down(refusal)
    r = _upload(client, headers, case_id, _body())
    assert r.status_code == 500, (r.status_code, r.text)
    assert _rows(conn, case_id) == 0


def test_a_program_error_in_the_put_stays_a_500(conn, store, client):
    _boss, case_id, headers = _world(conn)
    store.on_put = _down(ValueError("a bug, not a store"))
    r = _upload(client, headers, case_id, _body())
    assert r.status_code == 500, (r.status_code, r.text)


# --- the classifiers ---------------------------------------------------------------------

def test_the_two_classifiers_agree_on_every_shape_of_failure():
    import urllib3

    from noctornal_api.evidence import store_did_not_answer, store_never_reached
    refused = urllib3.exceptions.NewConnectionError(None, "refused")
    shapes = [
        # exc, did not answer, never reached the store
        (refused, True, True),
        (urllib3.exceptions.MaxRetryError(None, "/k", reason=refused), True, True),
        (urllib3.exceptions.ConnectTimeoutError(None, "connect timed out"),
         True, True),
        (ConnectionRefusedError(), True, True),
        (socket.gaierror(-2, "no such name"), True, True),
        (urllib3.exceptions.ReadTimeoutError(None, "/k", "read timed out"),
         True, False),
        (urllib3.exceptions.ProtocolError("Connection aborted.",
                                          ConnectionResetError()), True, False),
        (_read_timeout(), True, False),
        (ConnectionResetError(), True, False),
        (ValueError("a bug"), False, False),
        (KeyError("k"), False, False),
    ]
    for exc, answered, reached in shapes:
        assert store_did_not_answer(exc) is answered, repr(exc)
        assert store_never_reached(exc) is reached, repr(exc)


def test_a_chain_that_loops_does_not_hang_the_classifier():
    from noctornal_api.evidence import store_never_reached
    a, b = RuntimeError("a"), RuntimeError("b")
    a.__cause__, b.__cause__ = b, a
    assert store_never_reached(a) is False


# --- the pool ---------------------------------------------------------------------------------

def test_the_evidence_store_is_given_a_pool_that_gives_up_in_seconds(monkeypatch):
    from noctornal_api.evidence import EvidenceStorage
    from noctornal_api.samples import STORE_CONNECT_TIMEOUT_S, STORE_READ_TIMEOUT_S

    monkeypatch.setenv("MINIO_ENDPOINT", "127.0.0.1:9")
    monkeypatch.setenv("MINIO_ACCESS_KEY", "g79-access-not-real")
    monkeypatch.setenv("MINIO_SECRET_KEY", "g79-secret-not-real")
    monkeypatch.setenv("MINIO_SECURE", "false")
    pool = EvidenceStorage()._client._http

    kw = pool.connection_pool_kw
    assert kw["timeout"].connect_timeout == STORE_CONNECT_TIMEOUT_S == 10.0
    assert kw["timeout"].read_timeout == STORE_READ_TIMEOUT_S == 60.0
    retries = kw["retries"]
    assert retries.total == 2 and retries.connect == 2
    assert retries.read == 0, "a request that was sent is never sent again"
    assert set(retries.allowed_methods) == {"GET", "HEAD"}, (
        "a held write is never resent after the store answered: a second "
        "version of a locked object cannot be deleted")


def test_an_upload_to_a_store_that_never_answers_is_a_503_in_seconds(
        conn, client, monkeypatch):
    """The real storage class against a socket on this host that accepts and
    says nothing. Nothing leaves the machine and nothing is written to the
    bucket; the read timeout is shortened so the test is quick."""
    import time

    from noctornal_api import samples

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    server.settimeout(0.2)
    held, stop = [], threading.Event()

    def swallow():
        while not stop.is_set():
            try:
                held.append(server.accept()[0])
            except OSError:
                continue

    thread = threading.Thread(target=swallow, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("MINIO_ENDPOINT", f"127.0.0.1:{server.getsockname()[1]}")
        monkeypatch.setenv("MINIO_ACCESS_KEY", "g79-access-not-real")
        monkeypatch.setenv("MINIO_SECRET_KEY", "g79-secret-not-real")
        monkeypatch.setenv("MINIO_SECURE", "false")
        monkeypatch.setattr(samples, "STORE_READ_TIMEOUT_S", 0.5)
        _boss, case_id, headers = _world(conn)

        started = time.monotonic()
        r = _upload(client, headers, case_id, _body())
        took = time.monotonic() - started
    finally:
        stop.set()
        thread.join(2)
        for sock in held:
            sock.close()
        server.close()

    assert r.status_code == 503, (r.status_code, r.text)
    assert took < 10, f"the upload waited {took:.1f}s on a store that never answered"
    assert _rows(conn, case_id) == 0
    assert len(_orphans(conn, case_id)) == 1, (
        "the request may have landed, so the audit log names the key")

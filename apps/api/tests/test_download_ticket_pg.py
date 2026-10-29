"""The Lab download carries a one-shot ticket, not a session credential, to the sample origin (0061).

Sample bytes live on a second origin, and the console's session lives in `__Host-` cookies (`Secure`,
`Path=/`, no `Domain`, `SameSite=strict`) that cannot reach it. That is the point of the split, so the
session token must never be posted there as a Bearer. A ticket is minted on the application origin under
the ordinary cookie session (the `x-csrf-token` double-submit applies), is good for ONE sample, ONE
redemption and sixty seconds, and is audited at issue and at redemption.

What these tests hold:

- the round trip: minted on the app process, spent on the sample process with no Authorization header and
  no cookie;
- one-shot, and atomically so: the second presentation is refused;
- expiry is real, and the CHECK constraint means a row cannot be back-dated into validity without
  back-dating its issue too;
- the mint makes the download's decision, so a sample above the caller's clearance never yields a ticket;
- a live ticket is not an authority on its own: the account is re-read at redemption, so a deactivated
  account and a revoked `sample.download` are both refused inside the sixty-second window. The session is
  not re-read, which is the residual 0061 states;
- a flood of strings that match no ticket is refused by an address-scoped limit and writes nothing to
  `audit.event`: that path needs no credential, so a row per attempt would make the append-only,
  hash-chained table appendable by anyone who can reach the sample origin;
- a cookie mint without the CSRF header is refused, because a page on another origin cannot supply it;
- the sample origin does not mint: a session must never be presented there;
- the ticket is stored as a hash and appears nowhere else, `ingest.api_key`'s rule;
- the custody row names the ticket's user.

Env-gated on DATABASE_URL. Email prefix `dt-`, unique to this file.
"""
from __future__ import annotations

import hashlib
import io
import os
import time
import zipfile
from urllib.parse import urlsplit
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; download-ticket e2e is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-11"
API = "/api/v1"
APP = "https://app.example"
SAMPLES = "https://samples.example"


@pytest.fixture(autouse=True)
def deployment(monkeypatch):
    """A correctly split deployment, declared once.

    The three origin variables are cleared first so a developer's shell cannot decide the split, and the
    prohibited-content policy is declared because nothing may be ingested without one.
    `NOCTORNAL_PUBLIC_ORIGIN` is left unset, which makes this process the application, where tickets are
    minted; the tests that redeem set it to the sample origin for that request.
    """
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-2026-014")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "the.dp@example.test")
    for var in ("NOCTORNAL_SAMPLE_ORIGIN", "NOCTORNAL_PUBLIC_ORIGIN",
                "NOCTORNAL_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'dt-%@noctornal.test')"
    ssub = f"(SELECT id FROM lab.sample WHERE submitted_by IN {sub})"
    with c.transaction():
        # Tickets first: they reference the sample AND the user, and
        # unlike the custody ledger they are ordinary rows -- no trigger
        # to lift, because a redeemed ticket is exhausted state rather
        # than a record of what happened (0061).
        c.execute(f"DELETE FROM lab.download_ticket WHERE sample_id IN {ssub}")
        c.execute(f"DELETE FROM lab.download_ticket WHERE user_id IN {sub}")
        c.execute("ALTER TABLE lab.sample_access DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_access WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.sample_access ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample WHERE submitted_by IN {sub}")
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'dt-%@noctornal.test'")
    c.close()


class MemoryStore:
    """Stands in for the sample bucket, so the whole hand-off is provable
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
    """One store shared by the submitting service and the serving router.

    `_svc` builds `SampleStorage()` at call time, so the class is replaced on the module, not an instance."""
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
    email = f"dt-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Ticket", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _login(client, email, secret):
    """A real sign-in, for the one test that needs the browser's transport: the cookie pair and its CSRF half.

    Login answers 204 with the token only in `__Host-session`, so this returns the response and the caller
    reads the jar out of `Set-Cookie`. Other tests take `_session`, which does not spend a TOTP code.
    """
    from noctornal_api.security import totp
    r = client.post(f"{API}/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 204, r.text
    return r


def _session(conn, email) -> str:
    """A session minted directly, the way `scripts/bootstrap.py session` does.

    `mfa_satisfied=True`, as login passes it: `sample.download` is step-up gated and the ticket inherits
    that assurance. Unbound: no address and no User-Agent, which only `NOCTORNAL_SESSION_STRICT_BINDING`
    refuses (off here, 0058).
    """
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    uid = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()[0]
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _sample(conn, submitted_by, **kw):
    import noctornal_api.samples as samples
    from noctornal_api.samples import SampleService
    return SampleService(conn, samples.SampleStorage()).submit(
        b"MZ\x90\x00not-really-malware-" + uuid4().bytes,
        submitted_by=submitted_by, original_filename="x.bin", **kw)


def _analyst(conn, *, clearance="RED"):
    """A MALWARE_ANALYST (`sample.download`, step-up) signed in on the
    APPLICATION process, plus a sample of their own in the shared store."""
    uid, email, secret = _user(conn, roles=("MALWARE_ANALYST",),
                               clearance=clearance)
    token = _session(conn, email)
    return uid, token, _sample(conn, uid)


def _mint(client, token, sample_id):
    return client.post(f"{API}/samples/{sample_id}/download-ticket",
                       headers=_auth(token))


def _redeem(client, sample_id, ticket):
    """The redemption as the console makes it: no Authorization header, no cookie, the ticket in a form body.

    `application/x-www-form-urlencoded` is CORS-safelisted, so this is a simple cross-origin request with no
    preflight; `application/json` would need `content-type` in `app._preflight`'s
    `Access-Control-Allow-Headers`.
    """
    return client.post(f"{API}/samples/{sample_id}/download",
                       data={"ticket": ticket})


def _is_archive(body: bytes) -> bool:
    return zipfile.is_zipfile(io.BytesIO(body))


def _custody(conn, sample_id):
    return conn.execute(
        """SELECT actor_id, detail FROM lab.sample_access
            WHERE sample_id = %s AND action = 'DOWNLOADED'
            ORDER BY occurred_at""", (sample_id,)).fetchall()


def _ticket_row(conn, raw):
    return conn.execute(
        """SELECT id, sample_id, user_id, session_id, redeemed_at, ip_hash
             FROM lab.download_ticket WHERE token_hash = %s""",
        (hashlib.sha256(raw.encode()).digest(),)).fetchone()


def _audit(conn, action, sample_id):
    return conn.execute(
        """SELECT actor_id, outcome, detail FROM audit.event
            WHERE action = %s AND object_id = %s ORDER BY seq""",
        (action, sample_id)).fetchall()


def _audit_count(conn, sample_id):
    """Every audit row about one sample, whatever the action. The flood
    test asserts on this rather than on one action name: the defect was
    that an unauthenticated caller could cause an append-only write, and a
    fix that merely renamed the row it wrote would pass a narrower check."""
    return conn.execute(
        "SELECT count(*) FROM audit.event WHERE object_id = %s",
        (sample_id,)).fetchone()[0]


def _shrink(client, **overrides):
    """Swap the app's limiter for the real catalogue with entries shrunk,
    so a test can trip a limit in four requests instead of a hundred and
    twenty-one. `test_ratelimit_http._tiny_limiter`'s pattern; the entries
    that are not overridden keep their real numbers, so the blanket
    ceiling still behaves like itself."""
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    catalogue = dict(LIMITS)
    catalogue.update(overrides)
    client.app.state.limiter = RateLimiter(InProcessBackend(), limits=catalogue)


# --- the round trip -----------------------------------------------------

def test_a_ticket_crosses_the_split_that_a_session_cannot(
        conn, client, store, monkeypatch):
    """A ticket minted on the application process is spent on the sample process with no Authorization
    header and no cookie, and the archive comes back with the route's usual headers."""
    _, token, sample = _analyst(conn)

    minted = _mint(client, token, sample.id)
    assert minted.status_code == 201, minted.text
    body = minted.json()
    assert body["download_url"] == f"{SAMPLES}{API}/samples/{sample.id}/download"
    assert body["ticket"]

    row = _ticket_row(conn, body["ticket"])
    assert row is not None and row[4] is None, "minted, unspent"

    # The second process. Nothing else changes -- the split is decided by
    # configuration, which is what makes one codebase two roles.
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
    served = _redeem(client, sample.id, body["ticket"])
    assert served.status_code == 200, served.text
    assert _is_archive(served.content)
    assert served.headers["Content-Disposition"] == (
        f'attachment; filename="{sample.sha256}.zip"')
    assert served.headers["Content-Security-Policy"] == "default-src 'none'; sandbox"

    assert _ticket_row(conn, body["ticket"])[4] is not None, (
        "the redemption must spend the ticket")
    issued = _audit(conn, "SAMPLE_DOWNLOAD_TICKET_ISSUED", sample.id)
    redeemed = _audit(conn, "SAMPLE_DOWNLOAD_TICKET_REDEEMED", sample.id)
    assert len(issued) == 1 and len(redeemed) == 1, (issued, redeemed)


def test_the_url_the_mint_hands_back_is_one_the_sample_process_serves(
        conn, client, store):
    """Three readers of one configuration, held together: the origin the
    policy endpoint reports, the origin in the ticket's `download_url`,
    and `app._DOWNLOAD_PATH` -- the pattern the sample process's
    allow-list and its CORS answer both match on. A ticket whose URL is
    not that path is a ticket the sample process 404s, which would
    surface in the console as "the request did not complete"."""
    from noctornal_api.http.app import _DOWNLOAD_PATH
    _, token, sample = _analyst(conn)

    url = _mint(client, token, sample.id).json()["download_url"]
    policy = client.get(f"{API}/samples/policy", headers=_auth(token)).json()
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}" == policy["sample_origin"] == SAMPLES
    assert _DOWNLOAD_PATH.match(parts.path), url


# --- one shot, and it means one -----------------------------------------

def test_a_second_redemption_is_refused(conn, client, store, monkeypatch):
    """`redeemed_at` is set by the statement that reads it, one `UPDATE ... WHERE redeemed_at IS NULL ...
    RETURNING`, so a second presentation finds nothing. A `SELECT` then an `UPDATE` would serve both halves
    of a race.

    The refusal says only that the ticket is not valid: saying it was already redeemed would confirm to the
    holder of a stolen ticket that the string was real and that someone else got there first.
    """
    _, token, sample = _analyst(conn)
    ticket = _mint(client, token, sample.id).json()["ticket"]
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)

    assert _redeem(client, sample.id, ticket).status_code == 200

    again = _redeem(client, sample.id, ticket)
    assert again.status_code == 401, again.text
    assert not _is_archive(again.content)
    assert "already" not in again.json()["detail"].lower(), (
        "the refusal must not distinguish a spent ticket from an unknown one")
    assert len(_custody(conn, sample.id)) == 1, (
        "the second attempt must not produce a second custody row")
    refused = _audit(conn, "SAMPLE_DOWNLOAD_TICKET_REFUSED", sample.id)
    assert len(refused) == 1 and refused[0][1] == "DENIED"
    assert refused[0][2]["reason"] == "already_redeemed", (
        "the reason belongs in the audit, where the security officer is")


def test_an_expired_ticket_is_refused(conn, client, store, monkeypatch):
    """Sixty seconds, on the database's clock at both ends: `expires_at` is written by `now() + %s` with the
    TTL passed as a `timedelta` (psycopg adapts it to an `interval`) and compared against `now()` at
    redemption, so a skewed API host cannot mint a ticket that is expired on arrival.

    The row is aged rather than the clock moved, and both timestamps move: the
    `download_ticket_expiry_after_issue` constraint refuses a row whose expiry precedes its issue, which
    catches a unit confusion (60 versus 60000).
    """
    _, token, sample = _analyst(conn)
    ticket = _mint(client, token, sample.id).json()["ticket"]
    conn.execute(
        """UPDATE lab.download_ticket
              SET issued_at = now() - interval '5 minutes',
                  expires_at = now() - interval '4 minutes'
            WHERE token_hash = %s""",
        (hashlib.sha256(ticket.encode()).digest(),))
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)

    refused = _redeem(client, sample.id, ticket)
    assert refused.status_code == 401, refused.text
    assert not _is_archive(refused.content)
    assert not _custody(conn, sample.id), "no bytes, so no custody row"
    assert _ticket_row(conn, ticket)[4] is None, (
        "a refused redemption must not mark the row spent")
    audit = _audit(conn, "SAMPLE_DOWNLOAD_TICKET_REFUSED", sample.id)
    assert audit and audit[-1][2]["reason"] == "expired"


def test_a_ticket_is_bound_to_its_sample_and_is_not_spent_by_a_wrong_guess(
        conn, client, store, monkeypatch):
    """`sample_id` is part of the redemption's predicate, not a check
    after it. So a ticket presented on another sample's path matches no
    row: it is refused, and -- deliberately -- not spent, because burning
    it would let anyone who can reach the endpoint invalidate a ticket
    they cannot use by guessing the wrong sample."""
    uid, token, mine = _analyst(conn)
    other = _sample(conn, uid)
    ticket = _mint(client, token, mine.id).json()["ticket"]
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)

    wrong = _redeem(client, other.id, ticket)
    assert wrong.status_code == 401, wrong.text
    assert not _custody(conn, other.id)
    audit = _audit(conn, "SAMPLE_DOWNLOAD_TICKET_REFUSED", other.id)
    assert audit and audit[-1][2]["reason"] == "issued_for_another_sample"

    assert _redeem(client, mine.id, ticket).status_code == 200


# --- the mint makes the download's decision -----------------------------

def test_no_ticket_is_minted_for_a_sample_above_the_callers_clearance(
        conn, client, store):
    """The mint runs `_downloadable`, the same check `download()` runs, so no ticket exists for a sample its
    holder could not download directly. The answer is the 404 a nonexistent id gets, so the status code is
    not an existence oracle for a compartmented case.
    """
    owner, _, _ = _user(conn, clearance="RED")
    red = _sample(conn, owner, classification="RED")
    _, token, _ = _analyst(conn, clearance="AMBER")

    refused = _mint(client, token, red.id)
    assert refused.status_code == 404, refused.text
    assert refused.json()["detail"] == "no such sample"
    assert conn.execute(
        "SELECT count(*) FROM lab.download_ticket WHERE sample_id = %s",
        (red.id,)).fetchone()[0] == 0, "no row, not even a refused one"


def test_minting_with_a_cookie_session_needs_the_csrf_header(
        conn, client, store):
    """The mint is a POST so that `deps.session_token` demands the double-submit: a cookie-authenticated
    unsafe method must carry `x-csrf-token` matching the readable cookie, which a page on another origin
    cannot supply. A GET would be exempt from the mechanism.

    Cookies go in an explicit header: httpx will not send a `Secure` cookie over the test client's plain-http
    base URL, and a test that sent none would pass for the wrong reason.
    """
    from noctornal_api.http.deps import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE
    uid, email, secret = _user(conn, roles=("MALWARE_ANALYST",))
    sample = _sample(conn, uid)
    r = _login(client, email, secret)
    jar = {name: value for name, value in
           (raw.split(";")[0].split("=", 1) for raw in r.headers.get_list("set-cookie"))}
    cookie = f"{SESSION_COOKIE}={jar[SESSION_COOKIE]}; {CSRF_COOKIE}={jar[CSRF_COOKIE]}"
    path = f"{API}/samples/{sample.id}/download-ticket"

    bare = client.post(path, headers={"cookie": cookie})
    assert bare.status_code == 403, bare.text
    assert "CSRF" in bare.json()["detail"]
    assert conn.execute(
        "SELECT count(*) FROM lab.download_ticket WHERE sample_id = %s",
        (sample.id,)).fetchone()[0] == 0

    ok = client.post(path, headers={"cookie": cookie,
                                    CSRF_HEADER: jar[CSRF_COOKIE]})
    assert ok.status_code == 201, ok.text
    assert _ticket_row(conn, ok.json()["ticket"])[3] is not None, (
        "the minting session is recorded, for the audit chain")


def test_the_sample_origin_does_not_mint(conn, client, store, monkeypatch):
    """A ticket is minted where the session already is: minting on the sample origin would put a session
    exactly where the split says none may be.

    Two layers: `app._allowed_on_sample_origin` 404s everything on that process but the download, its
    preflight, `/healthz` and the register, and the service refuses on its own reading of the configuration.
    """
    from noctornal_api.samples import SampleError, SampleService
    _, token, sample = _analyst(conn)
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)

    refused = _mint(client, token, sample.id)
    assert refused.status_code == 404, refused.text
    assert APP in refused.json()["detail"], "the refusal names the application"

    with pytest.raises(SampleError, match="minted on the application origin"):
        SampleService(conn).issue_download_ticket(
            sample.id, actor_id=uuid4(), clearance="RED",
            request_origin=SAMPLES)
    assert conn.execute(
        "SELECT count(*) FROM lab.download_ticket WHERE sample_id = %s",
        (sample.id,)).fetchone()[0] == 0


# --- a live ticket is not an authority on its own -----------------------

def test_a_deactivated_account_cannot_redeem_a_live_ticket(
        conn, client, store, monkeypatch):
    """A disabled account must not pull hostile bytes during the sixty-second window, so redemption
    re-reads the account.

    `_still_authorised` calls `IamAdminService.holds_global_permission`, the same active-account,
    verb-through-a-global-role read `deps.require_global` is built on and the mint used.

    The ticket is spent even though nothing was served: the one-shot property lives in the single atomic
    UPDATE, and a ticket whose holder lost authority must not survive if the deactivation is reversed. The
    refusal does not say which reason applied.
    """
    uid, token, sample = _analyst(conn)
    ticket = _mint(client, token, sample.id).json()["ticket"]
    conn.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s",
                 (uid,))
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)

    refused = _redeem(client, sample.id, ticket)
    assert refused.status_code == 401, refused.text
    assert not _is_archive(refused.content)
    assert not _custody(conn, sample.id), "no bytes, so no custody row"
    assert _ticket_row(conn, ticket)[4] is not None, (
        "the presentation was genuine, so the ticket is spent regardless")
    assert not _audit(conn, "SAMPLE_DOWNLOAD_TICKET_REDEEMED", sample.id), (
        "a redemption that served nothing must not be recorded as one")
    audit = _audit(conn, "SAMPLE_DOWNLOAD_TICKET_REFUSED", sample.id)
    assert audit and audit[-1][1] == "DENIED"
    assert audit[-1][0] == uid, "the audit names the holder"
    assert audit[-1][2]["reason"] == "account_deactivated", (
        "which authority was withdrawn is what a security officer needs, "
        "and it belongs in the audit rather than the answer")
    assert audit[-1][2]["spent"] is True


def test_both_doors_state_the_same_permission(conn):
    """`require_global` gates the mint and the session download on the application origin, and
    `_still_authorised` re-reads `sample.download` at redemption on the sample origin.

    The router spells the key literally because `test_ui_invariants` pins that source line, so an import
    cannot tie them together. This test does: a permission renamed in the seed and updated in one place
    would otherwise ungate one door while the other kept refusing.
    """
    from pathlib import Path

    from noctornal_api.samples import DOWNLOAD_PERMISSION
    src = Path(__file__).resolve().parents[1] / (
        "src/noctornal_api/http/routers/samples.py")
    assert (f'_REQUIRE_DOWNLOAD = require_global("{DOWNLOAD_PERMISSION}")'
            in src.read_text(encoding="utf-8"))

    # And the key is one the seed actually grants, so neither door is
    # gated on a permission no role can ever hold.
    assert conn.execute(
        "SELECT count(*) FROM iam.permission WHERE key = %s",
        (DOWNLOAD_PERMISSION,)).fetchone()[0] == 1


def test_a_revoked_download_permission_cannot_redeem_a_live_ticket(
        conn, client, store, monkeypatch):
    """An account can stay active and lose `sample.download` (a role removed on reassignment), and a ticket
    minted earlier must not outlive it.

    The reason is distinguished from a deactivation because they are two different things to ask somebody
    about, as `_ticket_refusal` does for a replay versus a stale tab.
    """
    uid, token, sample = _analyst(conn)
    ticket = _mint(client, token, sample.id).json()["ticket"]
    conn.execute(
        "DELETE FROM iam.user_role WHERE user_id = %s AND role_key = %s",
        (uid, "MALWARE_ANALYST"))
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)

    refused = _redeem(client, sample.id, ticket)
    assert refused.status_code == 401, refused.text
    assert not _is_archive(refused.content)
    assert not _custody(conn, sample.id)
    audit = _audit(conn, "SAMPLE_DOWNLOAD_TICKET_REFUSED", sample.id)
    assert audit and audit[-1][2]["reason"] == "download_permission_revoked"

    # And the answer is the same one every other refusal gives. A caller
    # who can tell "your account is gone" from "that ticket is spent" has
    # an oracle, and the holder of a stolen ticket is the caller who wants
    # one.
    spent = _redeem(client, sample.id, ticket)
    assert spent.status_code == 401
    assert spent.json()["detail"] == refused.json()["detail"]


# --- the unauthenticated write into the audit chain ---------------------

def test_a_flood_of_unknown_tickets_is_metered_and_audits_nothing(
        conn, client, store, monkeypatch):
    """A flood of unknown tickets is metered and audits nothing.

    `POST /samples/{id}/download` with `ticket=x` needs no credential, and `audit.event` is append-only,
    hash-chained and serialised by an advisory lock, so a row per refusal would let anyone who can reach the
    sample origin grow a table nothing can delete from. Both halves are asserted: a string matching no row
    is counted in a sampled log line and never written, and the route is metered on the peer address.

    The limit is shrunk for the test and its real shape asserted separately: hard-coding 120 would fail on
    a harmless tuning change, and not asserting the scope would pass with the limit keyed on something the
    caller can mint.
    """
    from noctornal_api.ratelimit import LIMITS, Limit, OnBackendFailure, Scope
    real = LIMITS["sample.download"]
    assert real.scope is Scope.IP, (
        "the peer address is the only subject that exists before a ticket "
        "in the body has been looked up")
    assert real.on_backend_failure is OnBackendFailure.DENY, (
        "an unmetered sample origin is the amplifier this limit removes")

    _, _, sample = _analyst(conn)
    before = _audit_count(conn, sample.id)
    _shrink(client, **{"sample.download": Limit(
        "sample.download", quota=3, per_seconds=300, scope=Scope.IP,
        burst=3, on_backend_failure=OnBackendFailure.DENY)})
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)

    codes = [_redeem(client, sample.id, f"not-a-ticket-{n}").status_code
             for n in range(8)]
    assert codes[0] == 401, "an unknown ticket is refused as a credential"
    assert 429 in codes, codes
    assert codes[-1] == 429, (
        "the meter does not recover inside the flood; a denied request "
        "does not advance it either, so hammering cannot extend the wait")
    assert codes.count(401) <= 4, codes

    limited = _redeem(client, sample.id, "not-a-ticket-again")
    assert limited.status_code == 429
    assert "sample.download" in limited.json()["detail"]
    assert limited.headers["Retry-After"], (
        "a 429 without Retry-After makes a well-behaved client behave "
        "like a hammering one")

    assert _audit_count(conn, sample.id) == before, (
        "not one row: a refusal that names no ticket is counted, not "
        "written, and the rate-limit denial takes no connection to audit "
        "with either")


# --- what is stored, and what is not ------------------------------------

def test_the_ticket_itself_is_never_written_down(conn, client, store):
    """The ticket is stored as a hash, never the secret, so a backup, replica or support dump yields
    nothing that can be presented (`ingest.api_key`'s rule). The row names a user, a sample and a live
    authorisation to download it.

    The whole row is cast to text so a column added later that carried the value would fail too, and the
    audit detail is read because it is the other place a credential gets copied by accident.
    """
    _, token, sample = _analyst(conn)
    ticket = _mint(client, token, sample.id).json()["ticket"]

    row = _ticket_row(conn, ticket)
    assert row is not None, "the hash IS the lookup key"
    assert conn.execute(
        "SELECT count(*) FROM lab.download_ticket t WHERE t::text LIKE %s",
        (f"%{ticket}%",)).fetchone()[0] == 0, "the ticket is in the table"
    assert conn.execute(
        "SELECT count(*) FROM audit.event WHERE object_id = %s "
        "AND detail::text LIKE %s", (sample.id, f"%{ticket}%")).fetchone()[0] == 0, (
        "the ticket is in the audit detail")
    assert row[5] is not None, (
        "the minting address is recorded (hashed), for the audit trail")


def test_the_custody_row_names_the_tickets_user(
        conn, client, store, monkeypatch):
    """"Who took a copy of a live binary" is the question
    `lab.sample_access` exists to answer, and the answer must not become
    "nobody" because the request that fetched the bytes carried no
    session. The identity for the whole route is the ticket's holder: the
    labels are checked against their live ceiling, the custody row names
    them, and it records that a ticket is how they proved it.
    """
    uid, token, sample = _analyst(conn)
    ticket = _mint(client, token, sample.id).json()["ticket"]
    ticket_id = _ticket_row(conn, ticket)[0]
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)

    assert _redeem(client, sample.id, ticket).status_code == 200
    rows = _custody(conn, sample.id)
    assert len(rows) == 1, rows
    actor, detail = rows[0]
    assert actor == uid, "the custody row names the ticket's user"
    assert detail["via"] == "ticket"
    assert detail["ticket_id"] == str(ticket_id), (
        "the copy and the authorisation for it can be joined")
    assert detail["origin"] == SAMPLES


def test_the_bearer_path_still_works_and_records_no_ticket(
        conn, client, store, monkeypatch):
    """Wave 2 removes the console's RELIANCE on the Bearer, not the path
    itself: the two land in different releases, and a download that
    stopped working the moment the ticket shipped would be an outage
    rather than a migration. The custody row for a session download
    carries no `via`, so the ledger distinguishes the two without
    anybody having to guess from a timestamp."""
    _, token, sample = _analyst(conn)
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)

    served = client.post(f"{API}/samples/{sample.id}/download",
                         headers=_auth(token))
    assert served.status_code == 200, served.text
    assert _is_archive(served.content)
    rows = _custody(conn, sample.id)
    assert len(rows) == 1 and "via" not in rows[0][1], rows

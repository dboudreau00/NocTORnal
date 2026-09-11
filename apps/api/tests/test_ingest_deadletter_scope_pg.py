"""GET /ingest/dead-letters is scoped to what the caller may read
(2026-09-09).

Until then the listing was gated on the global `ingest.read` verb and
filtered by the caller's clearance ceiling alone, so an ANALYST on one
case read every other case's dead letters: the partner key, the error
class, the classification and the failure rate of feeds into cases they
were never assigned to. The Alpha 4 review named exactly those fields.

`ingest.dead_letter` has no `case_id`; the batch is parsed INTO a case and
the case lands on `ingest.record`. So a dead letter's case is the case its
batch's records went to, and the fixtures here always feed one parseable
record alongside the junk line, because a batch that wholly dead-letters
has no records and is therefore UNATTACHED -- the operator's, not any
case's.

The tests are the refusals:

- each case's reader sees only their own case's dead letters;
- the caller's clearance still bounds every row (this predicate PREDATES
  the change and is pinned here next to the case predicate so the two
  cannot be separated again);
- unattached rows -- no case at all -- are for holders of `ingest.manage`,
  the verb `/quarantine` requires and the console probes to decide whether
  to show the quarantine section, and an operator's stale step-up withholds
  them out loud rather than silently;
- a key filter naming a feed outside the caller's cases is a 404, the
  answer `/records` gives for a case off-scope;
- a caller with neither verb is a 403, which is what the console expects.

**The email prefix is `dls-` and must stay unique.**

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from pathlib import Path
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; dead-letter scope e2e is gated")

PASSWORD = "correct-horse-battery-staple"
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "dls-%@noctornal.test"

#: One record that parses, one line that does not: a batch with a case AND
#: a dead letter. Junk alone would be an unattached batch.
ATTACHED = b'{"note": "parses"}\nthis line is not json\n'
#: Nothing parses, so nothing lands in a case: unattached by construction.
UNATTACHED = b"not json at all\n"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    keys = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    batches = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {keys})"
    with c.transaction():
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {keys}")
        c.execute(f"UPDATE ingest.record SET duplicate_of = NULL WHERE batch_id IN {batches}")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {batches}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {keys}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn, *, clearance="RED", compartments=(), global_roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"dls-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Scope", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    # Since 0059 every compartment column is bound to iam.compartment. This
    # helper writes whatever it is handed, so it registers it first rather
    # than trusting the caller to have done so -- two helpers of this shape
    # were refused on CI's fresh database on 2026-09-09 while passing here.
    for key in compartments:
        conn.execute(
            "INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
            "ON CONFLICT (key) DO NOTHING", (key, f"{key} (test)"))
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s WHERE id = %s",
        (clearance, list(compartments), uid))
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _session(conn, email) -> str:
    """A signed-in caller, minted the way `scripts/bootstrap.py session`
    mints one: the account looked up by email, then `SessionService`
    against the same store the API validates against. Unbound -- no
    address, no User-Agent, because nothing here has one to give -- which
    0058 records and only `NOCTORNAL_SESSION_STRICT_BINDING` refuses; it
    is off in these tests.

    Not `POST /auth/login`, which since 2026-09-10 answers 204 and leaves
    the token only in `__Host-session`. Nothing in this file is about the
    sign-in path, so this takes the short honest route to a session
    rather than driving a login and unpicking a Set-Cookie header for a
    value it would hand straight back as a Bearer. It also drops the
    constraint the login helper carried: TOTP codes are single-use, so
    two sign-ins for one account inside one 30-second step failed on the
    code, not on the thing under test.
    """
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    uid = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()[0]
    # mfa_satisfied=True, as both real mint sites pass: a session that
    # never satisfied MFA is refused by every step-up gated route, which
    # would make this helper quietly narrower than the login it replaces.
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _create_case(client, token) -> str:
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-DLS-{uuid4().hex[:6]}", "title": "Operation Scope",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _feed(conn, owner, raw: bytes, *, case_id=None, ceiling="AMBER",
          name="scope feed") -> tuple[str, str]:
    """Parse `raw` under a fresh key. Returns (key row id, dead letter id).

    Through the service, as the queue tests do, because the write path
    needs object storage; the listing under test is the read path.
    """
    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage
    svc = IngestService(conn, InMemoryRawStorage())
    issued = svc.issue_key(name=name, owner_user_id=owner,
                           declared_category="UNKNOWN",
                           classification_ceiling=ceiling)
    key = svc.authenticate(issued.secret)
    batch = svc.accept(key, raw)
    result = svc.parse_batch(batch.batch_id, raw=raw, case_id=case_id)
    assert result.dead >= 1, result
    dead_id = conn.execute(
        "SELECT id FROM ingest.dead_letter WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()[0]
    return str(issued.id), str(dead_id)


def _listing(client, token, **params) -> dict:
    query = "&".join(f"{k}={v}" for k, v in params.items())
    r = client.get("/api/v1/ingest/dead-letters" + (f"?{query}" if query else ""),
                   headers=_auth(token))
    assert r.status_code == 200, r.text
    return r.json()


def _ids(body: dict) -> set[str]:
    return {d["id"] for d in body["dead_letters"]}


# ---------------------------------------------------------------------------

def test_each_case_reader_sees_only_their_own_cases_dead_letters(conn, client):
    """Two owners, two cases, one dead letter each. Before 2026-09-09 both
    saw both: the listing was bounded by the global verb and the ceiling,
    and nothing in it asked which case a batch had fed."""
    one, one_email, one_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    two, two_email, two_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    one_token = _session(conn, one_email)
    two_token = _session(conn, two_email)
    case_one = _create_case(client, one_token)
    case_two = _create_case(client, two_token)
    _key_one, dead_one = _feed(conn, one, ATTACHED, case_id=case_one, name="feed one")
    _key_two, dead_two = _feed(conn, two, ATTACHED, case_id=case_two, name="feed two")

    seen_by_one = _listing(client, one_token)
    seen_by_two = _listing(client, two_token)
    assert dead_one in _ids(seen_by_one) and dead_two not in _ids(seen_by_one)
    assert dead_two in _ids(seen_by_two) and dead_one not in _ids(seen_by_two)

    # The response says what it covered, and each row says whose it is --
    # naming the feed, which is the intelligence the review named and which
    # this listing had never carried.
    assert seen_by_one["scope"]["cases"] == [case_one]
    assert seen_by_one["scope"]["unattached"] is False
    row = next(d for d in seen_by_one["dead_letters"] if d["id"] == dead_one)
    assert row["case_ids"] == [case_one]
    assert row["feed"] == "feed one" and row["key_id"]
    assert row["unattached"] is False
    assert "raw_fragment" not in str(seen_by_one)


def test_an_amber_holder_does_not_see_a_red_dead_letter_on_their_own_case(conn, client):
    """The ceiling predicate. It was already in the query before
    2026-09-09 -- this pins it beside the new case predicate, on a caller
    who PASSES the case predicate, so a later edit cannot drop one while
    keeping the other. A dead letter inherits the issuing key's ceiling
    (`IngestService._dead_letter`), so a RED key makes a RED row."""
    owner, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner_token = _session(conn, owner_email)
    case_id = _create_case(client, owner_token)
    _key, dead_red = _feed(conn, owner, ATTACHED, case_id=case_id, ceiling="RED")
    assert dead_red in _ids(_listing(client, owner_token)), "RED owner sees RED"

    amber, amber_email, amber_secret = _make_user(
        conn, clearance="AMBER", global_roles=("ANALYST",))
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'ANALYST', %s)""", (case_id, amber, owner))
    amber_token = _session(conn, amber_email)
    seen = _listing(client, amber_token)
    assert seen["scope"]["cases"] == [case_id], "the case predicate passes..."
    assert dead_red not in _ids(seen), "...and the ceiling still hides the row"


def test_unattached_dead_letters_are_for_the_operator_verb(conn, client):
    """A batch that fed no case belongs to no case. `ingest.manage` is the
    verb `/quarantine` requires and the console probes; `ingest.read` on a
    case cannot reach a row with no case. Before 2026-09-09 every holder of
    `ingest.read` saw these, and the operator -- SYS_ADMIN holds
    `ingest.manage` and NOT `ingest.read` -- could not open the listing at
    all."""
    owner, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner_token = _session(conn, owner_email)
    case_id = _create_case(client, owner_token)
    _k1, attached = _feed(conn, owner, ATTACHED, case_id=case_id)
    _k2, unattached = _feed(conn, owner, UNATTACHED)

    by_owner = _listing(client, owner_token)
    assert attached in _ids(by_owner) and unattached not in _ids(by_owner)
    assert by_owner["scope"]["unattached"] is False

    _op, op_email, op_secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    op_token = _session(conn, op_email)     # TOTP login: step-up fresh
    by_operator = _listing(client, op_token)
    assert unattached in _ids(by_operator), "the operator sees the unattached row"
    assert attached not in _ids(by_operator), "and not the case's"
    assert by_operator["scope"] == {"cases": [], "unattached": True,
                                    "unattached_withheld": None}
    row = next(d for d in by_operator["dead_letters"] if d["id"] == unattached)
    assert row["unattached"] is True and row["case_ids"] == []


def test_a_stale_step_up_withholds_the_unattached_rows_out_loud(conn, client):
    """`ingest.manage` requires step-up. An operator who also reads a case
    keeps the case rows and is TOLD the unattached ones were withheld; an
    operator with nothing else is refused the way `/quarantine` refuses.
    Neither gets a listing that looks complete and is not."""
    both, both_email, both_secret = _make_user(
        conn, global_roles=("CASE_OWNER", "SYS_ADMIN"))
    both_token = _session(conn, both_email)
    case_id = _create_case(client, both_token)
    _k1, attached = _feed(conn, both, ATTACHED, case_id=case_id)
    _k2, unattached = _feed(conn, both, UNATTACHED)
    assert {attached, unattached} <= _ids(_listing(client, both_token))

    conn.execute("UPDATE iam.session SET mfa_satisfied_at = now() - interval '1 hour' "
                 "WHERE user_id = %s", (both,))
    stale = _listing(client, both_token)
    assert attached in _ids(stale) and unattached not in _ids(stale)
    assert stale["scope"]["unattached"] is False
    assert stale["scope"]["unattached_withheld"] == "re-authentication required"

    op, op_email, op_secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    op_token = _session(conn, op_email)
    conn.execute("UPDATE iam.session SET mfa_satisfied_at = now() - interval '1 hour' "
                 "WHERE user_id = %s", (op,))
    r = client.get("/api/v1/ingest/dead-letters", headers=_auth(op_token))
    assert r.status_code == 403 and "re-authentication" in r.text, r.text


def test_a_key_filter_for_a_feed_outside_your_cases_is_a_404(conn, client):
    """The per-key rate is the feed's health. It is answered for a key that
    fed one of the caller's cases and is a 404 otherwise -- not a 403,
    because "that key exists but is not yours" describes the deployment's
    feeds (deps.py rule 2), and not an empty 200 with the rate attached."""
    one, one_email, one_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    two, two_email, two_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    one_token = _session(conn, one_email)
    two_token = _session(conn, two_email)
    case_one = _create_case(client, one_token)
    key_one, dead_one = _feed(conn, one, ATTACHED, case_id=case_one)

    mine = _listing(client, one_token, api_key_id=key_one)
    assert dead_one in _ids(mine)
    assert mine["dead_letter_rate_24h"] == 0.5     # one record, one dead letter

    r = client.get(f"/api/v1/ingest/dead-letters?api_key_id={key_one}",
                   headers=_auth(two_token))
    assert r.status_code == 404, r.text
    assert "dead_letter_rate_24h" not in r.text

    # The operator is not bounded by cases and may ask about any key.
    _op, op_email, op_secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    op_token = _session(conn, op_email)
    assert "dead_letter_rate_24h" in _listing(client, op_token, api_key_id=key_one)


def test_the_console_and_the_endpoint_agree_on_the_contract(conn, client):
    """Reads both sides. `loadDeadLetters` in app.js renders
    `body.dead_letters`, counts `body.count`, and on a 403 says the caller
    needs `ingest.read`. The endpoint must keep returning those keys and
    keep answering a holder of neither verb with a 403 -- and a holder of
    `ingest.read` with no case gets an EMPTY 200, not a refusal, because
    the console treats a refusal as a permission fact."""
    app_js = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
              / "http" / "static" / "app.js").read_text(encoding="utf-8")
    start = app_js.index("async function loadDeadLetters()")
    fn = app_js[start:start + 900]
    assert "'/ingest/dead-letters?" in fn
    assert "body.dead_letters" in fn and "body.count" in fn
    assert "err.status === 403" in fn and "ingest.read" in fn

    _, email, secret = _make_user(conn, global_roles=("ANALYST",))
    token = _session(conn, email)
    body = _listing(client, token)
    assert body["dead_letters"] == [] and body["count"] == 0
    assert body["scope"] == {"cases": [], "unattached": False,
                             "unattached_withheld": None}

    _, none_email, none_secret = _make_user(conn, global_roles=())
    none_token = _session(conn, none_email)
    r = client.get("/api/v1/ingest/dead-letters", headers=_auth(none_token))
    assert r.status_code == 403, r.text
    assert "ingest.read" in r.json()["detail"]


# --- the decisions are the gate's (2026-09-11) --------------------------------
#
# Each test below replaces `evaluate` in the router module with a verdict of
# its own. If the SQL predicates were still deciding, the replacement would
# change nothing; the rows appearing and vanishing with the fake verdict is
# the proof that the gate is what answers.


def test_the_verb_is_the_gates_answer(conn, client, monkeypatch):
    from noctornal_api.http.routers import ingest as ingest_router
    from noctornal_api.security.access import CHECK_ROLE, Decision
    owner, owner_email, _ = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _session(conn, owner_email)
    case_id = _create_case(client, token)
    _k, dead = _feed(conn, owner, ATTACHED, case_id=case_id)
    assert dead in _ids(_listing(client, token))

    monkeypatch.setattr(ingest_router, "evaluate",
                        lambda ctx, **kw: Decision(False, (CHECK_ROLE,)))
    r = client.get("/api/v1/ingest/dead-letters", headers=_auth(token))
    assert r.status_code == 403, r.text
    assert "ingest.read" in r.json()["detail"]


def test_each_row_is_the_gates_answer_against_its_own_labels(conn, client, monkeypatch):
    """A RED dead letter in an AMBER case, for a RED-cleared owner: the SQL
    predicate (`classification <= clearance`) passes it, and a gate that
    refuses RED objects hides it while still listing the case. That split
    -- case in scope, row withheld -- can only come from a per-row
    decision."""
    from noctornal_api.http.routers import ingest as ingest_router
    from noctornal_api.security.access import CHECK_CLEARANCE, Decision
    owner, owner_email, _ = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _session(conn, owner_email)
    case_id = _create_case(client, token)
    _k, dead_red = _feed(conn, owner, ATTACHED, case_id=case_id, ceiling="RED")
    real = ingest_router.evaluate
    assert dead_red in _ids(_listing(client, token)), "the real gate allows it"

    def red_refused(ctx, **kw):
        if ctx.object_classification.name == "RED":
            return Decision(False, (CHECK_CLEARANCE,))
        return real(ctx, **kw)

    monkeypatch.setattr(ingest_router, "evaluate", red_refused)
    body = _listing(client, token)
    assert body["scope"]["cases"] == [case_id], "the AMBER case itself is still allowed"
    assert dead_red not in _ids(body), "the RED row is the gate's refusal, not the SQL's"


def test_an_unattached_row_is_the_global_gates_answer(conn, client, monkeypatch):
    """No case to go through: the row is put to `evaluate()` on the global
    `ingest.manage` context, against its own labels."""
    from noctornal_api.http.routers import ingest as ingest_router
    from noctornal_api.security.access import CHECK_CLEARANCE, Decision
    owner, _, _ = _make_user(conn, global_roles=("CASE_OWNER",))
    _k, unattached_red = _feed(conn, owner, UNATTACHED, ceiling="RED")
    _op, op_email, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    op_token = _session(conn, op_email)
    real = ingest_router.evaluate
    assert unattached_red in _ids(_listing(client, op_token))

    def red_refused(ctx, **kw):
        if ctx.object_classification.name == "RED":
            return Decision(False, (CHECK_CLEARANCE,))
        return real(ctx, **kw)

    monkeypatch.setattr(ingest_router, "evaluate", red_refused)
    body = _listing(client, op_token)
    assert body["scope"]["unattached"] is True, "the verb is still held"
    assert unattached_red not in _ids(body)

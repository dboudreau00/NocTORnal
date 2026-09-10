"""The blocking tier of the readiness register, on all three sides.

Until 2026-09-10 `readiness.py` had one tier and one verdict: eleven
checks, a `ready` boolean that was their conjunction, and NOTHING in the
tree that refused on either -- `GET /admin/readiness` served the report
and the admin pane drew it, and that was the entire consequence. An
operator could leave the prohibited-content
policy undeclared, the retention periods on their seeded placeholders,
no security officer and no sample origin, and the product would still
poll a real forum with a covert persona on request -- because the entire
consequence of a failed check was a red row on a pane nobody had to
open. A control that reports rather than refuses is a quiet green.

Four checks now BLOCK (`readiness.BLOCKING_CHECKS`) and
`POST /collection/sources/{id}/run` answers 409 while any of them fails.
That makes the tier a cross-file contract in the shape this codebase has
shipped wrong three times already (the co-participation keys, the
approvals operation key, the watch-hit `matched_on` list): the service
decides the tier, the wire carries it, the console renders it and a
route refuses on it, and every pair of those can be internally
consistent while disagreeing with the rest. So they are read from one
place, here.

Most of this file is PURE -- it reads the shipped source the way
`test_ui_invariants.py` does, and runs with no database, no Redis and no
object store. The behavioural half is gated on DATABASE_URL below, and
is the only part that needs one.

Email prefix `rdyb-`, unique to this file.
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from uuid import uuid4

import pytest

from noctornal_api import readiness

_TESTS = Path(__file__).resolve().parent
SRC = _TESTS.parents[0] / "src" / "noctornal_api"
STATIC = SRC / "http" / "static"

APP_JS = STATIC / "app.js"
INDEX = STATIC / "index.html"
COLLECTION_ROUTER = SRC / "http" / "routers" / "collection.py"

DATABASE_URL = os.environ.get("DATABASE_URL", "")
needs_db = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the database half is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-9"

#: Spelled out rather than imported, for the reason `test_readiness_pg`
#: spells out its own list: a check quietly promoted into or demoted out
#: of the blocking tier must turn this file red instead of redefining the
#: contract to match itself. Adding a fifth blocker is a decision about
#: what the product REFUSES to do, and it should cost somebody an edit
#: here and a moment's thought.
EXPECTED_BLOCKING = (
    "prohibited_content_policy",
    "sample_origin_configured",
    "retention_rules_confirmed",
    "security_officer_present",
)


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _readiness_pane() -> str:
    """The console's readiness code: `loadReadiness`, the banner and the
    row renderer, and nothing else. Sliced rather than grepped over the
    whole file so an assertion about what this pane reads cannot be
    satisfied by an unrelated pane that happens to use the same word."""
    js = _js()
    start = js.index("async function loadReadiness(")
    end = js.index("/* --- the last completed analysis", start)
    return js[start:end]


def _run_once_source() -> str:
    """The body of the collection run route, from its decorator to the
    start of the next one."""
    src = COLLECTION_ROUTER.read_text(encoding="utf-8")
    start = src.index('@router.post("/sources/{source_id}/run"')
    return src[start:src.index("\n@router.", start + 1)]


# ---------------------------------------------------------------------------
# The register's own half
# ---------------------------------------------------------------------------

def test_every_blocking_name_is_a_check_that_exists():
    """A typo in `BLOCKING_CHECKS` does not raise anything: the name
    simply matches no entry in `_CHECKS`, `run_checks` stamps nothing,
    `blocking_failures` returns an empty list, and the collection route
    runs every poll it is asked for. The whole gate fails OPEN and
    silently, which is the failure mode the tier exists to remove.
    """
    unknown = set(readiness.BLOCKING_CHECKS) - set(readiness.CHECK_NAMES)
    assert not unknown, (
        f"BLOCKING_CHECKS names {sorted(unknown)}, which no check in "
        f"_CHECKS produces; the gate would fail open on those")
    assert readiness.BLOCKING_CHECKS == EXPECTED_BLOCKING, (
        "the blocking tier changed; a check was promoted or demoted and "
        "that is a decision about what the product refuses to do")


def test_the_register_names_are_unique_and_in_register_order():
    """`CHECK_NAMES` is what the router test and the console's ordering
    both rest on. A duplicate name would make `_by_name`-style lookups
    silently keep the last one."""
    assert len(readiness.CHECK_NAMES) == len(set(readiness.CHECK_NAMES))
    assert len(readiness.CHECK_NAMES) == 13, readiness.CHECK_NAMES
    # The two added with the tier. `ingest_pepper_set` had no entry at all
    # before, so an unset pepper passed the whole register and failed at
    # the first ingest key operation; `app_db_role_not_owner` reports
    # whether the runtime role can switch off the append-only triggers.
    assert "ingest_pepper_set" in readiness.CHECK_NAMES
    assert "app_db_role_not_owner" in readiness.CHECK_NAMES
    # Blocking names appear in the same order as the register, so the
    # banner, the list under it and the 409's text all read alike.
    order = [n for n in readiness.CHECK_NAMES
             if n in readiness.BLOCKING_CHECKS]
    assert tuple(order) == readiness.BLOCKING_CHECKS


def test_the_wire_carries_the_tier_on_every_check():
    """`blocking` has to reach the client, or the console is left
    re-deriving the tier from a list of its own -- which is precisely the
    two-internally-consistent-halves defect this file exists to prevent.
    """
    keys = set(readiness.Check("x", True, "e").as_dict())
    assert keys == {"check", "ok", "evidence", "action", "blocking"}, keys
    assert readiness.Check("x", True, "e").as_dict()["blocking"] is False, (
        "blocking must default to False: a check added without a tier is "
        "not a blocker, and the safe default for 'may this refuse?' is no")


def test_the_report_lists_the_blocking_failures_it_derived():
    """`report` must return the summary, and must build it from the same
    run as the rows. A second call to the blocking probes could disagree
    with the list printed under it -- somebody confirms the last retention
    rule between the two -- and an operator cannot tell that apart from a
    bug."""
    src = (SRC / "readiness.py").read_text(encoding="utf-8")
    body = src[src.index("def report("):]
    assert '"blocking_failures":' in body, (
        "report() no longer returns blocking_failures; every caller is "
        "back to re-deriving the tier")
    assert "blocking_failures(conn)" not in body, (
        "report() calls the blocking probes a second time; the summary "
        "and the rows can then disagree")
    assert "c.blocking and not c.ok" in body


def test_blocking_failures_runs_only_the_blocking_probes():
    """The reason the helper exists. The other nine checks include a
    Redis PING, a MinIO round trip and an Alembic script scan, and this
    runs on the collection route's request path: a poll that waits on the
    object store to find out whether it may proceed has turned a
    readiness refusal into a latency bug.

    Asserted by replacing every probe with a recorder, which is the only
    way to see what was NOT called.
    """
    called: list[str] = []

    def recorder(name):
        def probe(_conn):
            called.append(name)
            return readiness.Check(name, True, "recorded")
        return probe

    fake = tuple((name, recorder(name), action)
                 for name, _probe, action in readiness._CHECKS)
    original = readiness._CHECKS
    try:
        readiness._CHECKS = fake
        assert readiness.blocking_failures(object()) == []
    finally:
        readiness._CHECKS = original
    assert called == list(readiness.BLOCKING_CHECKS), called


def test_a_probe_that_raises_is_a_blocking_failure_not_an_exception(monkeypatch):
    """`blocking_failures` stands on a request path, so a probe that
    blows up must come back as a name in the list. If it propagated, a
    Postgres hiccup inside `retention_rules_confirmed` would surface as a
    500 from the collection route -- a failure reported as the wrong
    thing, which is the defect the whole module was written against.

    Pure: the environment variables are cleared so the two env-backed
    blockers fail deterministically, and the two database-backed ones
    fail because the connection handed in is not one. Nothing here opens
    a socket -- none of the four blocking probes touches Redis, the
    object store or the migration scripts.
    """
    class NotAConnection:
        pass

    for var in ("NOCTORNAL_PROHIBITED_CONTENT_POLICY",
                "NOCTORNAL_DESIGNATED_PERSON", "NOCTORNAL_SAMPLE_ORIGIN"):
        monkeypatch.delenv(var, raising=False)
    failing = readiness.blocking_failures(NotAConnection())
    assert failing == list(readiness.BLOCKING_CHECKS), failing


# ---------------------------------------------------------------------------
# The route that refuses
# ---------------------------------------------------------------------------

def test_the_collection_run_route_refuses_while_a_blocker_fails():
    """Source-level, so it holds without a database. The run route is the
    ONE route in that file that puts this software in front of somebody
    else's system; every other route reports on what already happened."""
    src = COLLECTION_ROUTER.read_text(encoding="utf-8")
    assert "from noctornal_api.readiness import blocking_failures" in src, (
        "the collection router no longer reads the readiness register")

    route = _run_once_source()
    assert "blocking_failures(conn)" in route, (
        "POST /sources/{id}/run no longer asks whether the deployment is "
        "ready before polling a real target")
    assert re.search(r"Problem\(\s*409", route), (
        "the refusal is not a 409 raised through http/errors.Problem, as "
        "every other refusal in this router is")
    assert '", ".join(unsettled)' in route, (
        "the refusal does not name the failing checks; an operator "
        "cannot act on 'not ready'")
    assert "/admin/readiness" in route, (
        "the refusal does not say where the evidence and the action for "
        "each failing check can be read")

    # Exactly one call site: the register is not a gate on the read
    # paths, and a refusal quietly added to a listing route would change
    # what a RED source's absence means.
    assert src.count("blocking_failures(conn)") == 1, (
        "another route in this file now refuses on readiness; only the "
        "poll was meant to")


def test_the_refusal_happens_before_anything_is_read_about_the_source():
    """Deliberate ordering. The verdict is a fact about the DEPLOYMENT,
    so resolving the caller's ceiling first would spend a query on a
    question that cannot change the answer -- and would make the refusal
    arrive after the route had already begun treating the request as one
    it might serve."""
    route = _run_once_source()
    assert (route.index("blocking_failures(conn)")
            < route.index("user_ceiling(conn")), (
        "the readiness gate now runs after the ceiling lookup")


# ---------------------------------------------------------------------------
# The console
# ---------------------------------------------------------------------------

def test_the_button_that_says_check_readiness_checks_readiness():
    """`#btn-readiness` shipped in the markup with the register and was
    wired to NOTHING: `selectTab('admin')` called `loadReadiness` once and
    the control labelled "Check readiness" did nothing at all when
    pressed. An operator who had just set a variable and restarted the API
    had no way to re-ask short of reloading the console."""
    js = _js()
    assert re.search(
        r"\$\('btn-readiness'\)\.addEventListener\(\s*'click'\s*,\s*"
        r"loadReadiness\s*\)", js), (
        "#btn-readiness has no click handler; the button is decorative")
    assert 'id="btn-readiness"' in INDEX.read_text(encoding="utf-8")


def test_the_console_reads_only_keys_the_register_actually_sends():
    """Both halves of the wire contract, from the one file that reads
    them both. A pane reading `c.is_blocking` or `body.blockers` would be
    internally consistent, silently undefined at runtime, and would draw
    an empty banner over four failing blockers."""
    check_keys = set(readiness.Check("x", True, "e").as_dict())
    src = (SRC / "readiness.py").read_text(encoding="utf-8")
    report_body = src[src.index("def report("):]
    report_keys = set(re.findall(r'"(\w+)":', report_body))

    pane = _readiness_pane()
    read_from_check = set(re.findall(r"\bc\.(\w+)\b", pane))
    read_from_body = set(re.findall(r"\bbody\.(\w+)\b", pane))

    assert read_from_check <= check_keys, (
        f"the pane reads {sorted(read_from_check - check_keys)} off a "
        f"check row and Check.as_dict() sends {sorted(check_keys)}")
    assert read_from_body <= report_keys, (
        f"the pane reads {sorted(read_from_body - report_keys)} off the "
        f"report and report() returns {sorted(report_keys)}")
    # And it reads the tier at all, rather than rendering thirteen
    # identical rows the way it did before 2026-09-10.
    assert "blocking" in read_from_check
    assert "blocking_failures" in read_from_body


def test_the_console_keeps_no_copy_of_the_blocking_list():
    """The tier travels on the wire, per check. A hardcoded list in the
    console is a second copy of a rule the server owns, and the copy is
    the one that goes stale -- the approvals pane and the admin role
    picker both shipped exactly that."""
    js = _js()
    for name in readiness.BLOCKING_CHECKS:
        for literal in (f"'{name}'", f'"{name}"'):
            assert literal not in js, (
                f"app.js names the blocking check {name} as a literal; the "
                f"tier must come from the check row's `blocking` flag")


def test_the_banner_names_every_failing_blocker_with_its_action():
    """A banner that says "3 blocking checks failing" and stops has moved
    the operator's problem, not solved it: the actions are what closes
    them, and they are already in the response."""
    pane = _readiness_pane()
    banner = pane[pane.index("function renderBlockingBanner("):]
    banner = banner[:banner.index("function readinessRow(")]
    assert "c.blocking && !c.ok" in banner, (
        "the banner no longer selects the FAILING blockers")
    assert "c.evidence" in banner and "c.action" in banner, (
        "the banner lists names without the evidence or the action")
    assert "body.blocking_failures" in banner, (
        "the banner ignores the server's own summary, so a name the "
        "server lists and no row explains would appear nowhere")
    # No dismiss control anywhere in it. `.banner-close` is the console's
    # close button class and the corner banner stack is where a dismissible
    # notice belongs; this one's whole job is to still be there.
    assert "banner-close" not in banner


def test_the_banner_is_revealed_before_it_is_filled():
    """`role="alert"` announces a MUTATION inside a live region, and a
    region under `hidden` (`display: none !important` in app.css) is not
    in the accessibility tree to mutate. Building the banner and then
    unhiding it therefore announces nothing: the screen-reader user gets
    the same silence they got before the banner existed, on the one
    notice that says collection is refused. Asserted on the order of the
    two statements because nothing else in the tree would catch it -- the
    banner looks right on screen either way.
    """
    pane = _readiness_pane()
    banner = pane[pane.index("function renderBlockingBanner("):]
    banner = banner[:banner.index("function readinessRow(")]
    reveal = banner.index("show(box, true)")
    assert reveal < banner.index("box.appendChild("), (
        "renderBlockingBanner fills the banner and unhides it afterwards; "
        "the insertions happen while the region is out of the "
        "accessibility tree, so role=\"alert\" announces nothing")


def test_the_blocking_banner_element_exists_and_cannot_be_missed():
    html = INDEX.read_text(encoding="utf-8")
    assert 'id="rdy-blocking"' in html, (
        "the blocking banner has no element in the admin pane")
    start = html.index('id="rdy-blocking"')
    element = html[start:html.index(">", start)]
    assert 'role="alert"' in element, (
        "the blocking banner is not announced; a screen reader user gets "
        "no notice at all that collection is refused")
    assert "hidden" in element, (
        "the banner starts visible and empty, so an unchecked deployment "
        "and a clean one look the same before the first read")


def test_a_refused_read_leaves_no_stale_banner_standing():
    """`refusalText` on the summary and a two-minute-old banner beneath it
    is a claim about a report this pane did not get, and nothing on screen
    distinguishes it from a fresh one."""
    pane = _readiness_pane()
    catch = pane[pane.index("} catch (err) {"):pane.index("const failed =")]
    assert "renderBlockingBanner(null)" in catch, (
        "a refused /admin/readiness leaves the previous banner on screen")
    assert "return;" in catch, (
        "the refusal path falls through into the render below it, which "
        "would draw the rows from whatever `body` was left holding")


def test_the_report_is_not_kept_anywhere_nothing_reads_it():
    """`state.readiness` was written twice and read nowhere. A field like
    that cannot be seen to be wrong -- no operator notices a stale copy
    that reaches no pixel -- so the test over it was green whatever it
    held, which is worse than no test.

    Removed rather than given the consumer that was imagined for it: the
    Feeds pane, explaining a poll's 409 without a second round trip. That
    consumer cannot be honest. The COLLECTOR who gets the 409 does not
    hold `user.manage`, so their copy is null exactly when it is wanted;
    the administrator who does hold it has a snapshot taken before the
    refusal it would sit beside, which is the stale-report defect
    `test_a_refused_read_leaves_no_stale_banner_standing` above is
    written against; and the 409's own detail already names every failing
    check and where to read its evidence.

    Asserted as "written implies read" rather than as "absent", so a pane
    that genuinely consumes the report may bring the field back. Vacuous
    while there are no writes -- and that is the state being guarded.
    """
    js = _js()
    writes = re.findall(r"state\.readiness\s*=(?!=)", js)
    reads = re.findall(r"state\.readiness(?!\s*=(?!=))", js)
    assert not writes or reads, (
        "app.js writes state.readiness and nothing reads it back; either "
        "a pane consumes the last report or the field is dead weight "
        "under a test that cannot fail")


def test_a_failing_blocker_wears_the_banner_s_red_and_not_the_ordinary_amber():
    """One colour rule, three places, and until 2026-09-10 they
    disagreed. app.css argues the banner must be --danger because --alert
    is already carrying the ordinary failed check "and a blocker in the
    same amber would be indistinguishable from an SMTP host nobody has
    set" -- and `readinessRow` then dressed a FAILING blocker's own chip
    in `chip warn`, which resolves to that very amber. The banner said
    collection was refused; the row it summarised said untidy, two inches
    below it.

    Read as tokens rather than as prose: what has to agree is which
    variable each class resolves to, not how either file describes it.
    """
    pane = _readiness_pane()
    row = pane[pane.index("function readinessRow("):]
    chip = row[row.index("if (c.blocking) {"):]
    chip = chip[:chip.index("\n  }")]
    assert "'subtle'" in chip, (
        "a PASSING blocker no longer wears the quiet chip; which four are "
        "the gate is a standing fact, not a warning")
    assert "'bad'" in chip, (
        "a FAILING blocker's chip is not `chip bad`, so it does not carry "
        "the colour of the banner that names it")
    assert "'warn'" not in chip, (
        "the BLOCKING chip is still amber on some path; on this pane "
        "amber means an ordinary check needs attention")

    css = (STATIC / "app.css").read_text(encoding="utf-8")
    for rule, token in ((r"\.chip\.bad", "--danger"),
                        (r"\.chip\.warn", "--alert"),
                        (r"\.rdy-row-blocking", "--danger"),
                        (r"\.rdy-blocking\b", "--danger")):
        assert re.search(rule + r"\s*\{[^}]*var\(" + token + r"\)", css), (
            f"{rule} no longer resolves to {token}; the banner, the row "
            f"rule and the chip are the same claim in three places and "
            f"they have to agree")


def test_the_pane_styles_the_banner_by_class_and_never_by_element_style():
    """The console ships under `style-src 'self'` with no 'unsafe-inline'.
    An inline style is dropped by the browser with nothing in the console
    to say why -- so the banner that must not be missed would render
    unstyled, which is how it gets missed."""
    pane = _readiness_pane()
    assert ".style" not in pane, (
        "the readiness pane writes to element.style; the CSP drops it")
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    for cls in ("rdy-blocking", "rdy-blocking-head", "rdy-blocking-list",
                "rdy-blocking-item", "rdy-blocking-name", "rdy-row-blocking"):
        assert f".{cls}" in css, f"app.css has no rule for .{cls}"


def test_every_value_the_banner_shows_reaches_the_dom_as_text():
    """Evidence strings carry hostnames, role names and error text from
    outside this process. The console builds DOM through `el()` and
    `textContent` and never assigns markup; asserted here for this pane
    as well as globally, because this is the pane that renders the
    deployment's own configuration."""
    pane = _readiness_pane()
    assert not re.search(r"\.(inner|outer)HTML|insertAdjacentHTML", pane)
    # `el(tag, cls, text)` sets textContent; createTextNode is the other
    # admitted route for the fixed prose between the values.
    assert "createTextNode" in pane


# ---------------------------------------------------------------------------
# The behavioural half -- needs a database
# ---------------------------------------------------------------------------

@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'rdyb-%@noctornal.test')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'rdyb-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn, *, global_roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"rdyb-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "RdyB", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
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


@needs_db
def test_blocking_failures_agrees_with_the_report(conn):
    """The cheap answer and the full one are the same fact counted twice.
    They read the same probes but not in the same call, and the reason
    the helper exists at all is that it skips nine of them -- so nothing
    but this test holds the two lists together."""
    cheap = readiness.blocking_failures(conn)
    full = readiness.report(conn)
    assert cheap == full["blocking_failures"], (
        f"blocking_failures says {cheap} and report() says "
        f"{full['blocking_failures']}")
    # And the summary agrees with the rows it summarises.
    from_rows = [c["check"] for c in full["checks"]
                 if c["blocking"] and not c["ok"]]
    assert full["blocking_failures"] == from_rows


@needs_db
def test_the_tier_reaches_the_wire_on_exactly_the_four(conn, client):
    """Read off the HTTP response rather than the dataclass: a field that
    exists on `Check` and is dropped by the router's response model
    reaches nobody, which is how `revoked` was computed on every drain
    and delivered to no one."""
    _, email, secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    r = client.get("/api/v1/admin/readiness",
                   headers=_auth(_session(conn, email)))
    assert r.status_code == 200, r.text
    body = r.json()
    flagged = {c["check"] for c in body["checks"] if c["blocking"]}
    assert flagged == set(readiness.BLOCKING_CHECKS), flagged
    assert isinstance(body["blocking_failures"], list)
    assert set(body["blocking_failures"]) <= flagged
    for check in body["checks"]:
        assert isinstance(check["blocking"], bool), check


@needs_db
def test_the_two_new_checks_answer_with_evidence(conn):
    """Both are new on 2026-09-10 and neither had ever run against a real
    database. `app_db_role_not_owner` in particular is EXPECTED to fail
    here -- the suites own the tables so they can disable the append-only
    triggers -- and what is asserted is that it names the connected role
    either way, because "the role is wrong" without saying which role is
    not something an operator can act on."""
    # The two probes directly rather than `run_checks`, which would also
    # PING Redis and round-trip the object store to answer a question
    # about neither.
    pepper = readiness._ingest_pepper_set(conn)
    assert pepper.evidence.strip()
    assert "ingest_pepper_set" not in readiness.BLOCKING_CHECKS, (
        "an unset pepper stops ingest keys and nothing else; refusing a "
        "collection poll over it would be refusing the wrong thing")

    role = readiness._app_db_role_not_owner(conn)
    assert "app_db_role_not_owner" not in readiness.BLOCKING_CHECKS
    who = conn.execute("SELECT current_user").fetchone()[0]
    assert who in role.evidence, (
        f"the check did not name the connected role {who!r}; its evidence "
        f"is {role.evidence!r}")
    if not role.ok:
        assert "noctornal_app" in role.action
        assert "infra/production/compose.yml" in role.action


@needs_db
def test_the_poll_route_refuses_while_a_blocking_check_fails(
        conn, client, monkeypatch):
    """The end of the quiet green, over HTTP. The policy variables are
    cleared so `prohibited_content_policy` genuinely fails, and the real
    `blocking_failures` -- not a stub -- is what the route consults."""
    monkeypatch.delenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", raising=False)
    monkeypatch.delenv("NOCTORNAL_DESIGNATED_PERSON", raising=False)
    _, email, secret = _make_user(conn, global_roles=("COLLECTOR",))
    token = _session(conn, email)

    r = client.post(f"/api/v1/collection/sources/{uuid4()}/run",
                    json={}, headers=_auth(token))
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert "prohibited_content_policy" in detail, detail
    assert "/admin/readiness" in detail, detail
    # A 409 and not a 403: the caller holds `collection.run`. The
    # deployment is what is not ready, and telling them they lack a
    # permission they hold would send them to the wrong person.
    assert r.json()["status"] == 409


@needs_db
def test_a_ready_deployment_polls_and_the_ceiling_still_decides(
        conn, client, monkeypatch):
    """The other side of the gate, and the one that catches a refusal
    left permanently on. With no blocking failure the route must fall
    through to the behaviour `test_collection_clearance_pg` pins: an
    unknown source id is a 404, indistinguishable from one above the
    caller's ceiling.

    The verdict is stubbed rather than arranged, because arranging it for
    real means confirming every retention rule in a database several
    other suites are using.
    """
    import noctornal_api.http.routers.collection as route_module
    monkeypatch.setattr(route_module, "blocking_failures", lambda conn: [])
    _, email, secret = _make_user(conn, global_roles=("COLLECTOR",))
    token = _session(conn, email)

    r = client.post(f"/api/v1/collection/sources/{uuid4()}/run",
                    json={}, headers=_auth(token))
    assert r.status_code == 404, r.text


@needs_db
def test_the_refusal_names_every_failing_blocker_not_just_the_first(
        conn, client, monkeypatch):
    """An operator who fixes the one check named, restarts, and is
    refused again for a second one has been given a puzzle instead of a
    list. Stubbed so the assertion is about the ROUTE's rendering of the
    list rather than about which checks happen to fail on this database.
    """
    import noctornal_api.http.routers.collection as route_module
    monkeypatch.setattr(
        route_module, "blocking_failures",
        lambda conn: ["retention_rules_confirmed", "security_officer_present"])
    _, email, secret = _make_user(conn, global_roles=("COLLECTOR",))
    token = _session(conn, email)

    r = client.post(f"/api/v1/collection/sources/{uuid4()}/run",
                    json={}, headers=_auth(token))
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert "retention_rules_confirmed" in detail
    assert "security_officer_present" in detail


@needs_db
def test_an_analyst_is_refused_for_the_permission_before_the_readiness(
        conn, client, monkeypatch):
    """Ordering that matters for the caller: someone without
    `collection.run` gets 403, not 409. The permission is a fact about
    them and is theirs to act on; the readiness verdict is a fact about
    the deployment and is not. Reversing these would send every
    unauthorised caller to an administrator with the wrong complaint --
    and would tell them the deployment's configuration state, which
    `/admin/readiness` gates behind `user.manage`.
    """
    monkeypatch.delenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", raising=False)
    _, email, secret = _make_user(conn, global_roles=("ANALYST",))
    token = _session(conn, email)

    r = client.post(f"/api/v1/collection/sources/{uuid4()}/run",
                    json={}, headers=_auth(token))
    assert r.status_code == 403, r.text


# ---------------------------------------------------------------------------
# The source of the register, read as source
# ---------------------------------------------------------------------------

def test_the_tier_is_stamped_in_one_place():
    """`run_checks` sets `blocking` from `BLOCKING_CHECKS`; no probe sets
    it for itself. A probe that decided its own tier would be a second
    copy of the rule, and `_totp_kek_set`'s docstring records at length
    what a second copy of a rule cost this module last time."""
    src = (SRC / "readiness.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if getattr(node.func, "id", None) != "Check":
            continue
        assert not any(kw.arg == "blocking" for kw in node.keywords), (
            "a probe constructs its own Check(blocking=...); the tier is "
            "the register's to decide, in run_checks")
    assert "blocking=name in BLOCKING_CHECKS" in src, (
        "run_checks no longer stamps the tier from the register")

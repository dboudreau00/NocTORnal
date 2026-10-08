"""F53 (docs/17, 2026-10-08): a route and a console form create a watch.

Only a seeding script wrote a watch until now, so a watch of target kind
TELEGRAM_CHAT could be written only by hand, and the rule for its reference
(a typed chat id) was held by the database (0130) and the matcher but by no
writer that could say why in words. `POST /cases/{id}/collection/watches` is
that writer, and `GET` lists a case's watches for the Feeds pane.

What is held here:

- the gate: the global `watch.manage` AND the five-part gate on the case
  (`collection.read`, refused on a read-only case), so a collection manager
  not on the case, an analyst without the verb, an unauthenticated caller and
  a closed case are each refused, and nothing is written;
- the writer's own rules: a source the caller can see (a 404 otherwise), a
  kind from the list, a term for every kind but a Telegram chat, a chat named
  by its typed id and the chat its source reads, patterns that parse, and a
  name the case does not already hold (a 409);
- the stored row is the one the matcher reads (a created watch fires), the
  audit row carries counts and never terms, and the reader of the list does
  not see a watch on a source above them.

DATABASE_URL-gated. Rows are `f53w-`.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

import collection_helpers as h
import telegram_pg as tp

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "f53w-"
FEED = "https://feeds.example.test/a.xml"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    tp.teardown(c, P)
    with c.transaction():
        c.execute(f"DELETE FROM collect.watch WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(
            """DELETE FROM collect.source s WHERE s.name LIKE %s
                 AND NOT EXISTS (SELECT 1 FROM collect.telegram_chat t
                                  WHERE t.source_id = s.id)
                 AND NOT EXISTS (SELECT 1 FROM collect.document d
                                  WHERE d.source_id = s.id)
                 AND NOT EXISTS (SELECT 1 FROM collect.collection_run r
                                  WHERE r.source_id = s.id)""", (f"{P}%",))
    h.retire_users(c, P)
    c.close()


#: The runtime roles exist on this database (CI, and `wt.sh`).
HAS_ROLES = bool(os.environ.get("NOCTORNAL_APP_DB_ROLE", "").strip())


@pytest.fixture(autouse=True)
def _as_the_request_role(monkeypatch):
    """Where the database has the runtime roles, every route here runs as the
    request role, bound to its caller, as production does: the INSERT then
    meets 0124's policy on `collect.watch` and the grants of the role, and the
    list is read through them. Nothing wrote a watch as the request role
    before this route, so a missing grant would only show here."""
    if HAS_ROLES:
        from noctornal_api.db import ASSUME_ROLE_ENV
        monkeypatch.setenv(ASSUME_ROLE_ENV, "1")


def _case(conn, owner, *, classification="AMBER"):
    from noctornal_api.cases import CaseService

    svc = CaseService(conn)
    case = svc.create(
        code=f"OP-F53-{uuid4().hex[:6]}", title="watches", legal_basis="order",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner, classification=classification)
    svc.transition_status(case, "ACTIVE", actor_id=owner)
    return case


def _world(conn, *, clearance="RED", case_class="AMBER", src_class="AMBER",
           roles=("COLLECTOR",)):
    """A collection manager who owns a case, and a feed source to task."""
    uid, email = h.user(conn, P, clearance=clearance, roles=roles)
    return {"user": uid, "email": email,
            "case": _case(conn, uid, classification=case_class),
            "source": h.source(conn, P, kind="RSS", parser="rss",
                               classification=src_class, base_url=FEED,
                               egress=None)}


def _make(conn, w, **over):
    from noctornal_api.collection import CollectionService

    args = {"source_id": w["source"], "name": f"{P}{uuid4().hex[:6]}",
            "target_kind": "FEED", "target_ref": FEED, "keywords": ["ransom"],
            "actor_id": w["user"], "clearance": "RED",
            "compartments": frozenset()}
    args.update(over)
    return CollectionService(conn).create_watch(w["case"], **args)


def _row(conn, watch_id):
    return conn.execute(
        """SELECT case_id, source_id, name, target_kind, target_ref, keywords,
                  selector_watch, regexes, priority, suppress_window_s,
                  is_active, owner_user_id, digest_only, quiet_hours,
                  collection_account_id
             FROM collect.watch WHERE id = %s""", (watch_id,)).fetchone()


def _chat_world(conn):
    """A collection manager, a case, and a Telegram source reading one chat."""
    uid, email = h.user(conn, P, roles=("COLLECTOR",))
    persona, _, _ = tp.persona(conn, P, enrolled=False)
    chat = tp.chat(conn, P, persona_id=persona, resolved_by=uid)
    return {"user": uid, "email": email, "case": _case(conn, uid),
            "source": chat["source"], "chat": chat["durable_id"]}


# --- the service: what a watch is made of ------------------------------------

def test_a_watch_is_stored_as_the_matcher_reads_it_and_is_listed(conn):
    from noctornal_api.collection import CollectionService

    w = _world(conn)
    made = _make(conn, w, name=f"{P}named", keywords=["Ransom", "kits"],
                 selectors=["vesper@example.test"], regexes=[r"vesper\d+"],
                 priority=2, suppress_window_s=600)
    (case, source, name, kind, ref, keywords, selectors, regexes, priority,
     window, active, owner, digest, quiet, account) = _row(conn, made["id"])
    assert (case, source, name, kind, ref) == (w["case"], w["source"],
                                                f"{P}named", "FEED", FEED)
    assert keywords == ["Ransom", "kits"]
    assert selectors == ["vesper@example.test"], "stored in selector_watch"
    assert regexes == [r"vesper\d+"]
    assert (priority, window, active, owner) == (2, 600, True, w["user"])
    assert (digest, quiet, account) == (False, None, None), (
        "the columns nothing reads are not offered, so they keep their defaults")
    assert made["selectors"] == selectors and made["source_name"].startswith(P)
    listed = CollectionService(conn).watches(w["case"], clearance="RED")
    assert [x["id"] for x in listed] == [made["id"]] and listed[0] == made


def test_an_empty_list_is_stored_as_null_as_the_schema_says_capture_everything(conn):
    w = _world(conn)
    made = _make(conn, w, keywords=[], selectors=["only-this"], regexes=None)
    row = _row(conn, made["id"])
    assert (row[5], row[6], row[7]) == (None, ["only-this"], None)
    assert made["keywords"] == [] and made["regexes"] == []


def test_a_watch_made_here_fires_on_the_item_the_matcher_is_given(conn):
    from noctornal_api.collection import CollectionService, Item

    w = _world(conn)
    watch = _make(conn, w, keywords=["Ransom"], selectors=["vesper@example.test"],
                  suppress_window_s=0)
    svc = CollectionService(conn)
    conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, body_text, content_sha256, classification)
           VALUES (%s, 'post:1', '', decode(md5('f53'), 'hex'), 'AMBER')""",
        (w["source"],))
    hits = svc._match_watches(
        w["source"], uuid4(),
        Item(external_id="post:1", body="Selling RANSOM kits, ask vesper@example.test"),
        svc._watches(w["source"]), {})
    assert hits == 1
    matched = conn.execute(
        "SELECT matched_on FROM collect.watch_hit WHERE watch_id = %s",
        (watch["id"],)).fetchone()[0]
    assert matched == ["keyword:Ransom", "selector:vesper@example.test"]


@pytest.mark.parametrize("over, said", [
    ({"name": "ab"}, "name is between 3 and 200"),
    ({"name": "x" * 201}, "name is between 3 and 200"),
    ({"name": "two\nlines"}, "control character"),
    ({"target_kind": "forum"}, "A watch looks at one of BOARD, THREAD, USER"),
    ({"target_kind": "telegram_chat", "target_ref": "c:1"},
     "A watch looks at one of"),
    ({"target_ref": "  "}, "target cannot be empty"),
    ({"target_ref": "x" * 2049}, "target is at most 2048"),
    ({"target_ref": "nul\x00byte"}, "control character"),
    ({"keywords": [], "selectors": [], "regexes": []}, "needs a keyword"),
    ({"keywords": ["ok", "  "]}, "A keyword cannot be empty"),
    ({"keywords": ["k" * 501]}, "A keyword is at most 500"),
    ({"keywords": ["k"] * 101}, "at most 100 keywords"),
    ({"keywords": "ransom"}, "keywords are a list"),
    ({"selectors": ["a\tb"]}, "control character"),
    ({"regexes": ["(unclosed"]}, "A pattern does not compile"),
    ({"regexes": ["a{99999999999}"]}, "A pattern does not compile"),
    ({"regexes": ["(" * 3000 + ")" * 3000]}, "A pattern is at most 500"),
    ({"priority": 0}, "priority is a whole number from 1"),
    ({"priority": 6}, "priority is a whole number from 1"),
    ({"priority": True}, "priority is a whole number from 1"),
    ({"suppress_window_s": -1}, "between 0 and 604800"),
    ({"suppress_window_s": 604801}, "between 0 and 604800"),
])
def test_what_a_watch_cannot_carry_is_refused_in_words(conn, over, said):
    from noctornal_api.collection import CollectionError

    w = _world(conn)
    with pytest.raises(CollectionError) as refused:
        _make(conn, w, **over)
    assert said in str(refused.value), str(refused.value)
    assert conn.execute("SELECT count(*) FROM collect.watch WHERE case_id = %s",
                        (w["case"],)).fetchone()[0] == 0


def test_a_pattern_the_compiler_gives_up_on_is_refused_not_a_500(monkeypatch):
    """Parsing only, and whatever the compiler raises is a refusal: a
    recursion limit or an overflow is the pattern's fault, not the server's."""
    import re
    from types import SimpleNamespace

    from noctornal_api import collection

    for boom in (RecursionError, OverflowError, ValueError):
        def compile_(*_a, _boom=boom, **_k):
            raise _boom("too much")
        with monkeypatch.context() as local:
            local.setattr(collection, "re", SimpleNamespace(
                compile=compile_, IGNORECASE=re.IGNORECASE, error=re.error))
            assert "nested or repeated" in collection._pattern_problem("x")
    assert collection._pattern_problem("a+b") is None
    assert "unterminated" in collection._pattern_problem("[abc")


def test_a_refused_pattern_is_not_echoed_back(conn):
    from noctornal_api.collection import CollectionError

    w = _world(conn)
    secret = "AKIAHUNTEDSECRET1234("
    with pytest.raises(CollectionError) as refused:
        _make(conn, w, regexes=[secret])
    assert "AKIAHUNTEDSECRET" not in str(refused.value)


def test_any_one_term_is_enough_and_a_telegram_chat_needs_none(conn):
    w = _world(conn)
    for terms in ({"keywords": ["a"], "selectors": None, "regexes": None},
                  {"keywords": None, "selectors": ["a"], "regexes": None},
                  {"keywords": None, "selectors": None, "regexes": ["a+"]}):
        assert _make(conn, w, **terms)["id"]
    c = _chat_world(conn)
    chat = _make(conn, c, target_kind="TELEGRAM_CHAT", target_ref=c["chat"],
                 keywords=None)
    assert chat["keywords"] == chat["selectors"] == chat["regexes"] == []


# --- a Telegram chat -----------------------------------------------------------

@pytest.mark.parametrize("ref", ["@somechat", "t.me/somechat", "somechat", "c:0",
                                 "c:01", "c:-1001234", "u:123", "C:123", "c:",
                                 "c:" + "9" * 21, "c:12 3"])
def test_a_chat_is_named_by_its_typed_id_never_by_a_name(conn, ref):
    from noctornal_api.collection import CollectionError

    w = _chat_world(conn)
    with pytest.raises(CollectionError) as refused:
        _make(conn, w, target_kind="TELEGRAM_CHAT", target_ref=ref)
    assert "typed id" in str(refused.value) and "@username" in str(refused.value)


def test_the_typed_id_rule_is_the_one_the_database_holds():
    """The refusal above says why before the CHECK would; the two must agree
    on every spelling, or a ref the writer lets through is a 500 and one it
    refuses is a chat the database would have taken."""
    from noctornal_api.db import connect
    from noctornal_api.collection import _WATCH_CHAT_REF

    refs = ["c:1", "g:1", "c:" + "9" * 20, "g:" + "1" * 20, "c:" + "9" * 21,
            "c:0", "c:01", "c:-5", "u:5", "C:5", "G:5", "c:5 ", " c:5", "c:", ":5",
            "c:5\n", "c:\u0665", "c:5a", "cg:5", "c::5"]
    conn = connect()
    try:
        for ref in refs:
            held = conn.execute("SELECT %s ~ '^[cg]:[1-9][0-9]{0,19}$'",
                                (ref,)).fetchone()[0]
            assert bool(_WATCH_CHAT_REF.fullmatch(ref)) is held, repr(ref)
    finally:
        conn.close()


def test_a_chat_watch_goes_on_a_telegram_source(conn):
    from noctornal_api.collection import CollectionError

    w = _world(conn)
    with pytest.raises(CollectionError, match="goes on a Telegram source"):
        _make(conn, w, target_kind="TELEGRAM_CHAT", target_ref="c:1234567890")


def test_a_chat_watch_names_the_chat_its_source_reads(conn):
    from noctornal_api.collection import CollectionError

    w = _chat_world(conn)
    other = "c:" + str(int(w["chat"][2:]) + 1)
    with pytest.raises(CollectionError) as refused:
        _make(conn, w, target_kind="TELEGRAM_CHAT", target_ref=other)
    assert f"reads Telegram chat {w['chat']}" in str(refused.value)
    assert "has to name that one" in str(refused.value)
    made = _make(conn, w, target_kind="TELEGRAM_CHAT", target_ref=w["chat"],
                 keywords=["wire"])
    assert made["target_ref"] == w["chat"]


def test_a_chat_watch_made_here_fires_only_on_its_chat_and_says_so(conn):
    from noctornal_api.collection import CollectionService, Item

    w = _chat_world(conn)
    watch = _make(conn, w, target_kind="TELEGRAM_CHAT", target_ref=w["chat"],
                  keywords=None, suppress_window_s=0)
    svc = CollectionService(conn)
    for ext in ("m:1", "m:2"):
        conn.execute(
            """INSERT INTO collect.document
                   (source_id, external_id, body_text, content_sha256,
                    classification)
               VALUES (%s, %s, '', decode(md5(%s), 'hex'), 'AMBER')""",
            (w["source"], ext, ext))
    here = Item(external_id="m:1", body="anything at all",
                meta={"telegram_message": {"chat_durable_id": w["chat"]}})
    elsewhere = Item(external_id="m:2", body="anything at all",
                     meta={"telegram_message": {"chat_durable_id": "c:42"}})
    misaimed: dict = {}
    watches = svc._watches(w["source"])
    assert svc._match_watches(w["source"], uuid4(), here, watches, {}, misaimed) == 1
    assert svc._match_watches(w["source"], uuid4(), elsewhere, watches, {},
                              misaimed) == 0
    assert conn.execute(
        "SELECT matched_on FROM collect.watch_hit WHERE watch_id = %s",
        (watch["id"],)).fetchone()[0] == [f"chat:{w['chat']}"]


# --- whose source, whose name -------------------------------------------------------

def test_a_watch_goes_only_on_a_source_its_creator_can_see(conn):
    from noctornal_api.collection import CollectionNotFound, CollectionService

    w = _world(conn, clearance="GREEN", case_class="GREEN", src_class="AMBER")
    with pytest.raises(CollectionNotFound) as above:
        _make(conn, w, clearance="GREEN")
    with pytest.raises(CollectionNotFound) as absent:
        _make(conn, w, clearance="GREEN", source_id=uuid4())
    assert str(above.value) == str(absent.value), "one answer for both"
    assert CollectionService(conn).watches(w["case"], clearance="RED") == []


def test_a_compartmented_source_is_not_visible_without_the_key(conn):
    from noctornal_api.collection import CollectionNotFound

    w = _world(conn)
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES ('F53KEY', 'f53') "
                 "ON CONFLICT DO NOTHING")
    conn.execute("UPDATE collect.source SET compartments = ARRAY['F53KEY'] "
                 "WHERE id = %s", (w["source"],))
    try:
        with pytest.raises(CollectionNotFound):
            _make(conn, w, compartments=frozenset())
        assert _make(conn, w, compartments=frozenset({"F53KEY"}))["id"]
    finally:
        conn.execute("UPDATE collect.source SET compartments = '{}' WHERE id = %s",
                     (w["source"],))
        conn.execute("DELETE FROM collect.watch WHERE case_id = %s", (w["case"],))
        conn.execute("DELETE FROM iam.compartment WHERE key = 'F53KEY'")


def test_the_list_leaves_out_a_watch_on_a_source_above_the_reader(conn):
    from noctornal_api.collection import CollectionService

    w = _world(conn, case_class="GREEN", src_class="AMBER")
    green = h.source(conn, P, kind="RSS", parser="rss", classification="GREEN",
                     base_url=FEED, egress=None)
    above = _make(conn, w)
    below = _make(conn, w, source_id=green, keywords=["other"])
    svc = CollectionService(conn)
    assert {x["id"] for x in svc.watches(w["case"], clearance="RED")} == {
        above["id"], below["id"]}
    assert [x["id"] for x in svc.watches(w["case"], clearance="GREEN")] == [
        below["id"]]
    assert [s["id"] for s in svc.watch_sources(clearance="GREEN")
            if s["name"].startswith(P)] == [str(green)]


def test_a_name_the_case_holds_is_a_conflict_in_any_case_of_letters(conn):
    from noctornal_api.collection import CollectionConflict

    w = _world(conn)
    _make(conn, w, name=f"{P}Dup")
    with pytest.raises(CollectionConflict, match="already has a watch with that name"):
        _make(conn, w, name=f"{P}dUP")
    other = {**w, "case": _case(conn, w["user"])}
    assert _make(conn, other, name=f"{P}Dup")["id"], (
        "another case may use the name")


def test_a_case_carries_a_bounded_number_of_watches(conn, monkeypatch):
    from noctornal_api import collection
    from noctornal_api.collection import CollectionError

    monkeypatch.setattr(collection, "WATCH_MAX_PER_CASE", 2)
    w = _world(conn)
    _make(conn, w)
    _make(conn, w)
    with pytest.raises(CollectionError, match="at most 2 watches"):
        _make(conn, w)


def test_the_audit_row_carries_the_counts_and_never_the_terms(conn):
    w = _world(conn)
    made = _make(conn, w, name=f"{P}audit-name", keywords=["wire-transfer-kit"],
                 selectors=["leaked.handle@example.test"], regexes=["secret[0-9]+"],
                 target_ref="https://board.example.test/hidden-forum/")
    rows = conn.execute(
        """SELECT actor_id, actor_kind, object_type, object_id, case_id,
                  detail, detail::text
             FROM audit.event WHERE action = 'WATCH_CREATED'
              AND object_id = %s""", (made["id"],)).fetchall()
    assert len(rows) == 1
    actor, kind, obj, object_id, case, detail, text = rows[0]
    assert (actor, kind, obj, case) == (w["user"], "USER", "watch", w["case"])
    assert detail == {"source_id": str(w["source"]), "target_kind": "FEED",
                      "keywords": 1, "selectors": 1, "regexes": 1, "priority": 3,
                      "suppress_window_s": 3600}
    for private in ("wire-transfer-kit", "leaked.handle", "secret[0-9]",
                    "hidden-forum", "audit-name"):
        assert private not in text, private


def test_the_write_and_its_audit_row_stand_or_fall_together(conn, monkeypatch):
    from noctornal_api.collection import CollectionService

    w = _world(conn)

    def refuse(self, *args, **kwargs):
        raise RuntimeError("the audit write failed")

    monkeypatch.setattr(CollectionService, "_audit", refuse)
    with pytest.raises(RuntimeError):
        _make(conn, w, name=f"{P}orphan")
    assert conn.execute("SELECT count(*) FROM collect.watch WHERE name = %s",
                        (f"{P}orphan",)).fetchone()[0] == 0


@pytest.mark.skipif(not HAS_ROLES, reason="NOCTORNAL_APP_DB_ROLE not set")
def test_row_security_refuses_a_watch_on_a_case_the_request_role_cannot_read(conn):
    """The route's gate is not the only door shut. A request connection bound
    to somebody with no part in the case is refused by the policy itself, so a
    caller that skipped the gate would still write nothing."""
    import psycopg

    from noctornal_api.collection import CollectionService
    from noctornal_api.db import APP_ROLE, bind_session, connect

    w = _world(conn)
    stranger, email = h.user(conn, P, roles=("COLLECTOR",))
    app = connect()
    try:
        app.execute(f"SET ROLE {APP_ROLE}")
        bind_session(app, h.session(conn, email))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            CollectionService(app).create_watch(
                w["case"], source_id=w["source"], name=f"{P}intruder",
                target_kind="FEED", target_ref=FEED, keywords=["x"],
                actor_id=stranger, clearance="RED", compartments=frozenset())
    finally:
        app.close()
    assert conn.execute("SELECT count(*) FROM collect.watch WHERE name = %s",
                        (f"{P}intruder",)).fetchone()[0] == 0
    assert conn.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'WATCH_CREATED' "
        "AND actor_id = %s", (stranger,)).fetchone()[0] == 0


# --- over HTTP ------------------------------------------------------------------------

def _url(case):
    return f"/api/v1/cases/{case}/collection/watches"


def _body(w, **over):
    body = {"source_id": str(w["source"]), "name": f"{P}{uuid4().hex[:6]}",
            "target_kind": "FEED", "target_ref": FEED, "keywords": ["ransom"],
            "selectors": ["vesper@example.test"], "priority": 2,
            "suppress_window_s": 900}
    body.update(over)
    return body


def _hdr(conn, email):
    return h.auth(h.session(conn, email))


def test_a_collection_manager_on_the_case_adds_a_watch_and_it_is_listed(conn):
    client, _ = h.client()
    w = _world(conn)
    hdr = _hdr(conn, w["email"])
    r = client.post(_url(w["case"]), headers=hdr, json=_body(w, name=f"{P}first"))
    assert r.status_code == 201, r.text
    out = r.json()
    watch = out["watch"]
    assert watch["name"] == f"{P}first" and watch["selectors"] == ["vesper@example.test"]
    assert watch["is_active"] is True and watch["source_active"] is True
    assert "next poll of its source" in out["next"]
    assert "Documents already collected are not matched again" in out["next"]
    row = _row(conn, watch["id"])
    assert row[0] == w["case"] and row[11] == w["user"]

    r = client.get(_url(w["case"]), headers=hdr)
    assert r.status_code == 200, r.text
    listing = r.json()
    assert [x["id"] for x in listing["watches"]] == [watch["id"]]
    assert listing["count"] == 1 and listing["can_create"] is True
    assert listing["kinds"][-1] == "TELEGRAM_CHAT" and "BOARD" in listing["kinds"]
    assert str(w["source"]) in {s["id"] for s in listing["sources"]}


def test_a_paused_source_and_a_termless_chat_watch_are_told_in_the_answer(conn):
    client, _ = h.client()
    w = _chat_world(conn)
    hdr = _hdr(conn, w["email"])
    conn.execute("UPDATE collect.source SET is_active = false WHERE id = %s",
                 (w["source"],))
    r = client.post(_url(w["case"]), headers=hdr, json={
        "source_id": str(w["source"]), "name": f"{P}chat", "target_kind": "TELEGRAM_CHAT",
        "target_ref": w["chat"]})
    assert r.status_code == 201, r.text
    said = r.json()["next"]
    assert "Its source is paused" in said
    assert "fires on every message of that chat" in said
    listing = client.get(_url(w["case"]), headers=hdr).json()
    chat_source = next(s for s in listing["sources"] if s["id"] == str(w["source"]))
    assert chat_source["chat"] == w["chat"] and chat_source["is_active"] is False


def test_an_analyst_lists_watches_but_cannot_add_one(conn):
    client, _ = h.client()
    w = _world(conn)
    analyst, email = h.user(conn, P, roles=("ANALYST",))
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
                 (w["case"], analyst, w["user"]))
    made = _make(conn, w)
    hdr = _hdr(conn, email)
    r = client.get(_url(w["case"]), headers=hdr)
    assert r.status_code == 200, r.text
    listing = r.json()
    assert [x["id"] for x in listing["watches"]] == [made["id"]]
    assert listing["can_create"] is False and listing["sources"] == []
    r = client.post(_url(w["case"]), headers=hdr, json=_body(w))
    assert r.status_code == 403 and "watch.manage" in r.text
    assert conn.execute("SELECT count(*) FROM collect.watch WHERE case_id = %s",
                        (w["case"],)).fetchone()[0] == 1
    denied = conn.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'AUTHZ_DENIED' "
        "AND actor_id = %s AND detail->>'permission' = 'watch.manage'",
        (analyst,)).fetchone()[0]
    assert denied == 1


def test_a_collection_manager_who_is_not_on_the_case_is_told_it_does_not_exist(conn):
    client, _ = h.client()
    w = _world(conn)
    stranger, email = h.user(conn, P, roles=("COLLECTOR",))
    hdr = _hdr(conn, email)
    assert client.post(_url(w["case"]), headers=hdr, json=_body(w)).status_code == 404
    assert client.get(_url(w["case"]), headers=hdr).status_code == 404
    assert client.post(_url(uuid4()), headers=hdr, json=_body(w)).status_code == 404
    assert conn.execute("SELECT count(*) FROM collect.watch WHERE case_id = %s",
                        (w["case"],)).fetchone()[0] == 0
    # The refusal was the case gate's: put on the case, the same caller adds one.
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
                 (w["case"], stranger, w["user"]))
    assert client.post(_url(w["case"]), headers=hdr, json=_body(w)).status_code == 201


def test_an_unauthenticated_caller_is_refused(conn):
    client, _ = h.client()
    w = _world(conn)
    assert client.post(_url(w["case"]), json=_body(w)).status_code == 401
    assert client.get(_url(w["case"])).status_code == 401


def test_a_closed_case_takes_no_new_watch_but_still_lists_them(conn):
    from noctornal_api.cases import CaseService

    client, _ = h.client()
    w = _world(conn)
    hdr = _hdr(conn, w["email"])
    kept = _make(conn, w)
    CaseService(conn).transition_status(w["case"], "CLOSED", actor_id=w["user"])
    r = client.post(_url(w["case"]), headers=hdr, json=_body(w))
    assert r.status_code == 409 and r.json()["title"] == "Case is read-only", r.text
    assert [x["id"] for x in client.get(_url(w["case"]), headers=hdr)
            .json()["watches"]] == [kept["id"]]
    CaseService(conn).transition_status(w["case"], "ACTIVE", actor_id=w["user"])
    assert client.post(_url(w["case"]), headers=hdr, json=_body(w)).status_code == 201


def test_a_source_the_caller_cannot_see_is_the_404_a_random_id_gets(conn):
    client, _ = h.client()
    w = _world(conn, clearance="GREEN", case_class="GREEN", src_class="AMBER")
    hdr = _hdr(conn, w["email"])
    above = client.post(_url(w["case"]), headers=hdr, json=_body(w))
    random = client.post(_url(w["case"]), headers=hdr,
                         json=_body(w, source_id=str(uuid4())))
    assert above.status_code == random.status_code == 404
    assert above.json()["detail"] == random.json()["detail"]
    assert conn.execute("SELECT count(*) FROM collect.watch WHERE case_id = %s",
                        (w["case"],)).fetchone()[0] == 0
    # The refusal was about the source: a source this caller may see is taken.
    visible = h.source(conn, P, kind="RSS", parser="rss", classification="GREEN",
                       base_url=FEED, egress=None)
    assert client.post(_url(w["case"]), headers=hdr,
                       json=_body(w, source_id=str(visible))).status_code == 201


def test_a_refusal_is_a_400_with_the_sentence_and_a_repeat_name_a_409(conn):
    client, _ = h.client()
    w = _world(conn)
    hdr = _hdr(conn, w["email"])
    r = client.post(_url(w["case"]), headers=hdr,
                    json=_body(w, keywords=[], selectors=[]))
    assert r.status_code == 400 and "needs a keyword" in r.json()["detail"], r.text
    r = client.post(_url(w["case"]), headers=hdr, json=_body(w, regexes=["(open"]))
    assert r.status_code == 400 and "does not compile" in r.json()["detail"]
    r = client.post(_url(w["case"]), headers=hdr, json=_body(w, target_kind="PAGE"))
    assert r.status_code == 400 and "looks at one of" in r.json()["detail"]
    name = f"{P}twice"
    assert client.post(_url(w["case"]), headers=hdr,
                       json=_body(w, name=name)).status_code == 201
    r = client.post(_url(w["case"]), headers=hdr, json=_body(w, name=name))
    assert r.status_code == 409 and "already has a watch" in r.json()["detail"]
    r = client.post(_url(w["case"]), headers=hdr, json=_body(w, priority="high"))
    assert r.status_code == 422, "a value of the wrong type is the framework's 422"
    assert conn.execute("SELECT count(*) FROM collect.watch WHERE case_id = %s",
                        (w["case"],)).fetchone()[0] == 1


def test_a_chat_watch_over_http_must_name_the_chat_by_its_typed_id(conn):
    client, _ = h.client()
    w = _chat_world(conn)
    hdr = _hdr(conn, w["email"])
    body = {"source_id": str(w["source"]), "name": f"{P}chat",
            "target_kind": "TELEGRAM_CHAT", "target_ref": "@somechat"}
    r = client.post(_url(w["case"]), headers=hdr, json=body)
    assert r.status_code == 400 and "typed id" in r.json()["detail"]
    r = client.post(_url(w["case"]), headers=hdr, json={**body, "target_ref": "c:7"})
    assert r.status_code == 400 and w["chat"] in r.json()["detail"]
    r = client.post(_url(w["case"]), headers=hdr,
                    json={**body, "target_ref": w["chat"]})
    assert r.status_code == 201, r.text
    assert r.json()["watch"]["target_ref"] == w["chat"]


def test_the_reader_of_a_lower_clearance_does_not_see_the_watch_or_the_form_sources(conn):
    client, _ = h.client()
    w = _world(conn, case_class="GREEN", src_class="AMBER")
    made = _make(conn, w)
    low, email = h.user(conn, P, clearance="GREEN", roles=("ANALYST", "COLLECTOR"))
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
                 (w["case"], low, w["user"]))
    listing = client.get(_url(w["case"]), headers=_hdr(conn, email)).json()
    assert listing["watches"] == [] and listing["can_create"] is True
    assert str(w["source"]) not in {s["id"] for s in listing["sources"]}
    seen = client.get(_url(w["case"]), headers=_hdr(conn, w["email"])).json()
    assert [x["id"] for x in seen["watches"]] == [made["id"]]


def test_adding_a_watch_is_metered_under_collection_config(conn):
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import (
        LIMITS, InProcessBackend, Limit, RateLimiter, Scope)

    limits = dict(LIMITS)
    limits["collection.config"] = Limit(
        "collection.config", quota=2, per_seconds=3600, scope=Scope.USER, burst=2)
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=limits)
    client = TestClient(app)
    w = _world(conn)
    hdr = _hdr(conn, w["email"])
    codes = [client.post(_url(w["case"]), headers=hdr, json=_body(w)).status_code
             for _ in range(3)]
    assert codes == [201, 201, 429]
    assert client.get(_url(w["case"]), headers=hdr).status_code == 200, (
        "reading the list spends no part of the creation meter")


def test_the_route_is_a_content_write_behind_both_gates():
    """What the closed-case route table also holds, stated where the route
    is: the case gate says content_write, and the global verb is a
    dependency of its own, ahead of the meter."""
    from noctornal_api.http.routers.collection import case_router

    route = next(r for r in case_router.routes
                 if r.path.endswith("/watches") and "POST" in r.methods)
    found: list[tuple[str, str]] = []

    def walk(dep) -> None:
        call = dep.call
        name = getattr(call, "__qualname__", "")
        if call is not None and "<locals>" in name:
            cells = dict(zip(call.__code__.co_freevars,
                             (c.cell_contents for c in (call.__closure__ or ())),
                             strict=False))
            for key in ("permission_key", "content_write", "name"):
                if key in cells:
                    found.append((name.split(".")[0], f"{key}={cells[key]}"))
        for sub in dep.dependencies:
            walk(sub)

    walk(route.dependant)
    assert ("require_global", "permission_key=watch.manage") in found
    assert ("require", "permission_key=collection.read") in found
    assert ("require", "content_write=True") in found
    assert ("rate_limit", "name=collection.config") in found
    order = [i for i, f in enumerate(found) if f[0] == "require_global"]
    case_gate = [i for i, f in enumerate(found) if f == ("require", "permission_key=collection.read")]
    assert order and case_gate and order[0] < case_gate[0], (
        "the verb is asked before the case, so a caller without it learns nothing of the case")

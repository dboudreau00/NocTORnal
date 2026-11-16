"""Stopping, resuming and editing a watch (docs/17: stopping or editing a watch).

`POST /cases/{id}/collection/watches/{watch_id}/stop` and `.../resume` take a standing tasking out of
the collector's hands and give it back, and `PATCH /cases/{id}/collection/watches/{watch_id}` changes
what it matches and how it is thinned. All three sit behind the two checks that making a watch sits
behind: the global `watch.manage` first, then the five-part gate on the case with `collection.read`.
They differ in one thing. Stopping is allowed on a read-only case, because the collector keeps
matching a closed case's watches and a closed case could otherwise never be quietened (the reasoning
for acknowledging and suppressing a hit); resuming and editing change or restart a tasking, are
content writes, and a closed case refuses them.

What is held here:

- a stopped watch is not read by the collector or by ingest scoring, a resumed one is, and a stopped
  watch's old hits stay listed: stopping is `is_active = false`, never a delete;
- stopping a stopped watch, resuming an active one and an edit that changes nothing write no row and
  no audit row; each real change writes one audit row, in the transaction that wrote it, that names
  where the watch is aimed or what changed by count and never what it matches or what it is called;
- an edit replaces a list whole and `[]` clears it to NULL, leaves a field it does not name alone,
  obeys every rule a new watch does through the same helpers, cannot change the source, the kind or
  the target, refuses a name another watch holds, and writes by compare-and-set so a watch changed
  under it is a 409 and nothing is written;
- the gate: a collection manager on the case changes any watch of it; an analyst without the verb, a
  collection manager who is not on the case and a caller with no session are each refused and nothing
  moves; a watch on another case, on a source above the caller and a random id all get one 404;
- the three routes are metered under `collection.config`, behind both gates in the stated order, and
  under the request role row security refuses a stranger's change.

DATABASE_URL-gated. Rows are `f53s-`.
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

P = "f53s-"
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


#: The runtime roles exist on this database (CI, and the worktree runner).
HAS_ROLES = bool(os.environ.get("NOCTORNAL_APP_DB_ROLE", "").strip())


@pytest.fixture(autouse=True)
def _as_the_request_role(monkeypatch):
    """Where the database has the runtime roles, every route here runs as the request role, bound to
    its caller, as production does: the UPDATE meets 0124's policy on `collect.watch` and the grants of
    the role, so a missing grant shows here."""
    if HAS_ROLES:
        from noctornal_api.db import ASSUME_ROLE_ENV
        monkeypatch.setenv(ASSUME_ROLE_ENV, "1")


def _case(conn, owner, *, classification="AMBER"):
    from noctornal_api.cases import CaseService

    svc = CaseService(conn)
    case = svc.create(
        code=f"OP-F53S-{uuid4().hex[:6]}", title="watches", legal_basis="order",
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


def _active(conn, watch_id) -> bool:
    return conn.execute("SELECT is_active FROM collect.watch WHERE id = %s",
                        (watch_id,)).fetchone()[0]


def _stop(conn, w, watch_id, **over):
    from noctornal_api.collection import CollectionService

    args = {"actor_id": w["user"], "clearance": "RED", "compartments": frozenset()}
    args.update(over)
    return CollectionService(conn).stop_watch(w["case"], watch_id, **args)


def _resume(conn, w, watch_id, **over):
    from noctornal_api.collection import CollectionService

    args = {"actor_id": w["user"], "clearance": "RED", "compartments": frozenset()}
    args.update(over)
    return CollectionService(conn).resume_watch(w["case"], watch_id, **args)


def _edit(conn, w, watch_id, **changes):
    from noctornal_api.collection import CollectionService

    return CollectionService(conn).edit_watch(
        w["case"], watch_id, changes=changes, actor_id=w["user"], clearance="RED",
        compartments=frozenset())


def _stored(conn, watch_id):
    """The columns an edit writes, as stored: NULL is NULL, not an empty list."""
    return conn.execute(
        """SELECT name, keywords, selector_watch, regexes, priority, suppress_window_s,
                  owner_user_id, xmin::text
             FROM collect.watch WHERE id = %s""", (watch_id,)).fetchone()


def _chat_world(conn):
    """A collection manager, a case, and a Telegram source reading one chat."""
    uid, email = h.user(conn, P, roles=("COLLECTOR",))
    persona, _, _ = tp.persona(conn, P, enrolled=False)
    chat = tp.chat(conn, P, persona_id=persona, resolved_by=uid)
    return {"user": uid, "email": email, "case": _case(conn, uid),
            "source": chat["source"], "chat": chat["durable_id"]}


def _fire(conn, w, external_id: str, body="Selling RANSOM kits, ask vesper@example.test") -> int:
    """What the collector does with one item: read the source's active watches, match the item.
    Returns the hits it wrote."""
    from noctornal_api.collection import CollectionService, Item

    svc = CollectionService(conn)
    conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, body_text, content_sha256, classification)
           VALUES (%s, %s, '', decode(md5(%s), 'hex'), 'AMBER')""",
        (w["source"], external_id, external_id))
    return svc._match_watches(
        w["source"], uuid4(), Item(external_id=external_id, body=body),
        svc._watches(w["source"]), {})


def _audit_rows(conn, action, watch_id):
    return conn.execute(
        """SELECT actor_id, actor_kind, object_type, object_id, case_id, detail,
                  detail::text
             FROM audit.event WHERE action = %s AND object_id = %s""",
        (action, watch_id)).fetchall()


# --- the service: what a stopped watch is ---------------------------------------

def test_a_stopped_watch_is_not_matched_and_a_resumed_one_is(conn):
    w = _world(conn)
    watch = _make(conn, w, keywords=["Ransom"], suppress_window_s=0)
    stopped, changed = _stop(conn, w, watch["id"])
    assert changed is True and stopped["is_active"] is False
    assert _active(conn, watch["id"]) is False
    assert _fire(conn, w, "post:1") == 0, "the collector reads active watches only"
    resumed, changed = _resume(conn, w, watch["id"])
    assert changed is True and resumed["is_active"] is True
    assert _fire(conn, w, "post:2") == 1
    assert conn.execute("SELECT count(*) FROM collect.watch_hit WHERE watch_id = %s",
                        (watch["id"],)).fetchone()[0] == 1


def test_a_stopped_watch_is_not_read_by_ingest_selector_scoring(conn):
    from noctornal_api.ingest import IngestService

    w = _world(conn)
    watch = _make(conn, w, keywords=None, selectors=["vesper@example.test"])
    ingest = IngestService(conn)

    def scoring_watches():
        return [row[0] for row in ingest._watches_for(w["case"], {})]

    assert watch["id"] in {str(x) for x in scoring_watches()}
    _stop(conn, w, watch["id"])
    assert watch["id"] not in {str(x) for x in scoring_watches()}, (
        "a record is no longer scored against a stopped watch's selectors")
    _resume(conn, w, watch["id"])
    assert watch["id"] in {str(x) for x in scoring_watches()}


def test_a_stopped_watch_keeps_its_old_hits_listed(conn):
    from noctornal_api.collection import CollectionService

    w = _world(conn)
    watch = _make(conn, w, keywords=["Ransom"], suppress_window_s=0)
    assert _fire(conn, w, "post:1") == 1
    _stop(conn, w, watch["id"])
    svc = CollectionService(conn)
    hits = svc.watch_hits(w["case"], clearance="RED", compartments=frozenset(),
                          unacknowledged_only=False, limit=50)
    assert len(hits) == 1, "stopping keeps the watch and what it raised"
    listed = svc.watches(w["case"], clearance="RED")
    assert [(x["id"], x["is_active"]) for x in listed] == [(watch["id"], False)]


def test_stop_and_resume_are_idempotent_and_write_one_audit_row_each(conn):
    w = _world(conn)
    watch = _make(conn, w)
    assert _resume(conn, w, watch["id"])[1] is False, "an active watch is already resumed"
    assert _audit_rows(conn, "WATCH_RESUMED", watch["id"]) == []
    assert _stop(conn, w, watch["id"])[1] is True
    again, changed = _stop(conn, w, watch["id"])
    assert changed is False and again["is_active"] is False
    assert len(_audit_rows(conn, "WATCH_STOPPED", watch["id"])) == 1
    assert _resume(conn, w, watch["id"])[1] is True
    assert _resume(conn, w, watch["id"])[1] is False
    assert len(_audit_rows(conn, "WATCH_RESUMED", watch["id"])) == 1
    assert _active(conn, watch["id"]) is True


def test_the_audit_rows_of_a_change_say_where_it_is_aimed_and_never_what_it_matches(conn):
    w = _world(conn)
    watch = _make(conn, w, name=f"{P}audit-name", keywords=["wire-transfer-kit"],
                  selectors=["leaked.handle@example.test"], regexes=["secret[0-9]+"],
                  target_ref="https://board.example.test/hidden-forum/")
    _stop(conn, w, watch["id"])
    _resume(conn, w, watch["id"])
    for action in ("WATCH_STOPPED", "WATCH_RESUMED"):
        rows = _audit_rows(conn, action, watch["id"])
        assert len(rows) == 1, action
        actor, kind, obj, object_id, case, detail, text = rows[0]
        assert (actor, kind, obj, str(object_id), case) == (
            w["user"], "USER", "watch", watch["id"], w["case"])
        assert detail == {"source_id": str(w["source"]), "target_kind": "FEED"}
        for private in ("wire-transfer-kit", "leaked.handle", "secret[0-9]",
                        "hidden-forum", "audit-name"):
            assert private not in text, (action, private)


def test_a_change_and_its_audit_row_stand_or_fall_together(conn, monkeypatch):
    from noctornal_api.collection import CollectionService

    w = _world(conn)
    watch = _make(conn, w)

    def refuse(self, *args, **kwargs):
        raise RuntimeError("the audit write failed")

    monkeypatch.setattr(CollectionService, "_audit", refuse)
    with pytest.raises(RuntimeError):
        _stop(conn, w, watch["id"])
    assert _active(conn, watch["id"]) is True, "no stop without its record"


def test_a_watch_that_is_missing_hidden_or_on_another_case_is_one_not_found(conn):
    from noctornal_api.collection import CollectionNotFound

    w = _world(conn, clearance="GREEN", case_class="GREEN", src_class="AMBER")
    above = _make(conn, w)  # made by a RED caller, on a source above the GREEN manager
    elsewhere = {**w, "case": _case(conn, w["user"], classification="GREEN")}
    said = set()
    for call in (lambda: _stop(conn, w, above["id"], clearance="GREEN"),
                 lambda: _resume(conn, w, above["id"], clearance="GREEN"),
                 lambda: _stop(conn, w, uuid4(), clearance="GREEN"),
                 lambda: _stop(conn, elsewhere, above["id"])):
        with pytest.raises(CollectionNotFound) as refused:
            call()
        said.add(str(refused.value))
    assert len(said) == 1, f"three kinds of absence, one sentence: {said}"
    assert _active(conn, above["id"]) is True
    assert _stop(conn, w, above["id"])[1] is True, "a caller with the clearance can stop it"


def test_a_compartmented_source_is_hidden_without_the_key_and_stoppable_with_it(conn):
    from noctornal_api.collection import CollectionNotFound

    w = _world(conn)
    watch = _make(conn, w)
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES ('F53SKEY', 'f53s') "
                 "ON CONFLICT DO NOTHING")
    conn.execute("UPDATE collect.source SET compartments = ARRAY['F53SKEY'] "
                 "WHERE id = %s", (w["source"],))
    try:
        with pytest.raises(CollectionNotFound):
            _stop(conn, w, watch["id"], compartments=frozenset())
        assert _stop(conn, w, watch["id"], compartments=frozenset({"F53SKEY"}))[1] is True
    finally:
        conn.execute("UPDATE collect.source SET compartments = '{}' WHERE id = %s",
                     (w["source"],))
        conn.execute("DELETE FROM collect.watch WHERE case_id = %s", (w["case"],))
        conn.execute("DELETE FROM iam.compartment WHERE key = 'F53SKEY'")


# --- the service: editing --------------------------------------------------------

def test_an_edit_changes_the_fields_it_names_and_the_collector_reads_the_result(conn):
    w = _world(conn)
    watch = _make(conn, w, name=f"{P}first", keywords=["ransom"], selectors=["keep@x.test"],
                  priority=3, suppress_window_s=0)
    edited, changed = _edit(conn, w, watch["id"], name=f"{P}second", keywords=["wiper", "kit"],
                            priority=1, suppress_window_s=600)
    assert changed == ["name", "keywords", "priority", "suppress_window_s"]
    assert edited["name"] == f"{P}second" and edited["keywords"] == ["wiper", "kit"]
    assert edited["selectors"] == ["keep@x.test"], "a field left out is left alone"
    assert (edited["priority"], edited["suppress_window_s"]) == (1, 600)
    name, keywords, selectors, regexes, priority, window, owner, _ = _stored(
        conn, watch["id"])
    assert (name, keywords, selectors, regexes, priority, window) == (
        f"{P}second", ["wiper", "kit"], ["keep@x.test"], None, 1, 600)
    assert owner == w["user"], "the creator stays the owner"
    assert _fire(conn, w, "post:1", body="selling RANSOM, nothing else") == 0, (
        "the old keyword is gone from what the collector reads")
    assert _fire(conn, w, "post:2", body="a new WIPER for sale") == 1


def test_an_edit_replaces_a_list_and_an_empty_list_clears_it_to_null(conn):
    w = _world(conn)
    watch = _make(conn, w, keywords=["a", "b"], selectors=["s"], regexes=["p+"])
    edited, changed = _edit(conn, w, watch["id"], keywords=["c"], regexes=[])
    assert changed == ["keywords", "regexes"]
    assert edited["keywords"] == ["c"] and edited["regexes"] == [], "replaced, never merged"
    row = _stored(conn, watch["id"])
    assert (row[1], row[2], row[3]) == (["c"], ["s"], None), (
        "an empty list is stored as NULL, as creating a watch stores it")


def test_an_edit_that_changes_nothing_writes_no_row_and_no_audit(conn):
    w = _world(conn)
    watch = _make(conn, w, name=f"{P}same", keywords=["a"], selectors=["s"], priority=2)
    before = _stored(conn, watch["id"])
    for changes in ({"name": f"{P}same"}, {"keywords": ["a"]}, {"selectors": ["s"], "priority": 2},
                    {"regexes": []}, {"suppress_window_s": 3600}):
        edited, changed = _edit(conn, w, watch["id"], **changes)
        assert changed == [], changes
        assert edited["name"] == f"{P}same"
    assert _stored(conn, watch["id"]) == before, (
        "no UPDATE ran: the row is the same version, down to xmin")
    assert _audit_rows(conn, "WATCH_EDITED", watch["id"]) == []


def test_an_edit_may_not_leave_a_non_chat_watch_with_no_term(conn):
    from noctornal_api.collection import CollectionError

    w = _world(conn)
    only = _make(conn, w, keywords=["a"], selectors=None, regexes=None)
    with pytest.raises(CollectionError, match="needs a keyword, a selector or a pattern"):
        _edit(conn, w, only["id"], keywords=[])
    assert _stored(conn, only["id"])[1] == ["a"]
    both = _make(conn, w, keywords=["a"], selectors=["s"])
    edited, changed = _edit(conn, w, both["id"], keywords=[])
    assert changed == ["keywords"] and edited["selectors"] == ["s"], (
        "a watch may drop one list while another still carries a term")
    with pytest.raises(CollectionError, match="needs a keyword"):
        _edit(conn, w, both["id"], selectors=[])
    assert _audit_rows(conn, "WATCH_EDITED", only["id"]) == []


def test_a_telegram_chat_watch_may_be_edited_down_to_no_term(conn):
    w = _chat_world(conn)
    watch = _make(conn, w, target_kind="TELEGRAM_CHAT", target_ref=w["chat"],
                  keywords=["wire"])
    edited, changed = _edit(conn, w, watch["id"], keywords=[])
    assert changed == ["keywords"] and edited["keywords"] == []
    assert _stored(conn, watch["id"])[1] is None


@pytest.mark.parametrize("changes, said", [
    ({"name": "ab"}, "name is between 3 and 200"),
    ({"name": "x" * 201}, "name is between 3 and 200"),
    ({"name": "two\nlines"}, "control character"),
    ({"name": None}, "name is between 3 and 200"),
    ({"keywords": ["ok", "  "]}, "A keyword cannot be empty"),
    ({"keywords": ["k" * 501]}, "A keyword is at most 500"),
    ({"keywords": ["k"] * 101}, "at most 100 keywords"),
    ({"keywords": "ransom"}, "keywords are a list"),
    ({"keywords": None}, "Send a list, [] to clear it, not null."),
    ({"selectors": None}, "Send a list, [] to clear it, not null."),
    ({"regexes": None}, "Send a list, [] to clear it, not null."),
    ({"selectors": ["a\tb"]}, "control character"),
    ({"regexes": ["a{99999999999}"]}, "A pattern does not compile"),
    ({"priority": 0}, "priority is a whole number from 1"),
    ({"priority": 6}, "priority is a whole number from 1"),
    ({"priority": True}, "priority is a whole number from 1"),
    ({"priority": None}, "priority is a whole number from 1"),
    ({"suppress_window_s": -1}, "between 0 and 604800"),
    ({"suppress_window_s": 604801}, "between 0 and 604800"),
    ({"suppress_window_s": None}, "between 0 and 604800"),
    ({}, "Say what to change"),
    ({"source_id": "x"}, "cannot be changed"),
    ({"target_kind": "FEED"}, "cannot be changed"),
    ({"target_ref": "x"}, "cannot be changed"),
    ({"is_active": False}, "cannot be changed"),
])
def test_an_edit_obeys_every_rule_a_new_watch_does_and_writes_nothing_when_refused(
        conn, changes, said):
    from noctornal_api.collection import CollectionError

    w = _world(conn)
    watch = _make(conn, w, keywords=["a"])
    before = _stored(conn, watch["id"])
    with pytest.raises(CollectionError) as refused:
        _edit(conn, w, watch["id"], **changes)
    assert said in str(refused.value), str(refused.value)
    assert _stored(conn, watch["id"]) == before
    assert _audit_rows(conn, "WATCH_EDITED", watch["id"]) == []


def test_an_edit_refuses_a_pattern_that_does_not_compile_without_echoing_it(conn):
    from noctornal_api.collection import CollectionError

    w = _world(conn)
    watch = _make(conn, w)
    with pytest.raises(CollectionError) as refused:
        _edit(conn, w, watch["id"], regexes=["AKIAHUNTEDSECRET1234("])
    assert "does not compile" in str(refused.value)
    assert "AKIAHUNTEDSECRET" not in str(refused.value)


def test_a_rule_a_watch_was_made_before_does_not_stop_an_edit_that_leaves_it_alone(conn):
    """A field left out of a change is not read again. A watch with a pattern that no longer parses
    (the poll reports it) can still have its priority changed, and its patterns replaced."""
    from noctornal_api.collection import CollectionError

    w = _world(conn)
    legacy = conn.execute(
        """INSERT INTO collect.watch (case_id, source_id, name, target_kind, target_ref,
                                      keywords, regexes, owner_user_id)
           VALUES (%s, %s, %s, 'FEED', %s, ARRAY['a'], ARRAY['(unclosed'], %s)
        RETURNING id""", (w["case"], w["source"], f"{P}legacy", FEED, w["user"])).fetchone()[0]
    assert _edit(conn, w, legacy, priority=1)[1] == ["priority"]
    with pytest.raises(CollectionError, match="does not compile"):
        _edit(conn, w, legacy, regexes=["(still-open"])
    assert _edit(conn, w, legacy, regexes=["fixed+"])[1] == ["regexes"]


def test_an_edit_may_not_take_another_watchs_name_in_any_case_of_letters_but_may_keep_its_own(conn):
    from noctornal_api.collection import CollectionConflict

    w = _world(conn)
    first = _make(conn, w, name=f"{P}Dup")
    second = _make(conn, w, name=f"{P}other")
    for name in (f"{P}Dup", f"{P}dUP"):
        with pytest.raises(CollectionConflict, match="already has a watch with that name"):
            _edit(conn, w, second["id"], name=name)
    assert _stored(conn, second["id"])[0] == f"{P}other"
    assert _edit(conn, w, first["id"], name=f"{P}Dup")[1] == [], "its own name is not a clash"
    edited, changed = _edit(conn, w, first["id"], name=f"{P}dup")
    assert changed == ["name"] and edited["name"] == f"{P}dup", (
        "a watch may change the case of its own name")
    elsewhere = {**w, "case": _case(conn, w["user"])}
    assert _make(conn, elsewhere, name=f"{P}dup")["id"], "another case may use it"


def test_a_stale_edit_is_a_409_and_writes_nothing(conn, monkeypatch):
    """The write is a compare-and-set on the columns the edit read. A watch changed after it was
    read, by another manager in the same instant, is a conflict and nothing is written."""
    from noctornal_api.collection import CollectionConflict, CollectionService

    w = _world(conn)
    watch = _make(conn, w, keywords=["a"], priority=3)
    svc = CollectionService(conn)
    stale = svc._watch_for_change(w["case"], watch["id"], "RED", frozenset())
    conn.execute("UPDATE collect.watch SET priority = 5 WHERE id = %s", (watch["id"],))
    monkeypatch.setattr(CollectionService, "_watch_for_change",
                        lambda self, *args, **kwargs: stale)
    with pytest.raises(CollectionConflict, match="changed by someone else"):
        _edit(conn, w, watch["id"], keywords=["b"])
    row = _stored(conn, watch["id"])
    assert (row[1], row[4]) == (["a"], 5), "the other manager's change stands, ours is not written"
    assert _audit_rows(conn, "WATCH_EDITED", watch["id"]) == []


def test_a_null_list_and_an_empty_one_are_the_same_thing_to_the_guard(conn):
    """Creating a watch stores an empty list as NULL, and a row written another way can hold `{}`.
    Either way an edit that reads it must not meet a conflict with itself."""
    w = _world(conn)
    watch = _make(conn, w, keywords=["a"], selectors=None, regexes=None)
    assert _stored(conn, watch["id"])[2] is None
    assert _edit(conn, w, watch["id"], priority=2)[1] == ["priority"]
    assert _edit(conn, w, watch["id"], selectors=[])[1] == []
    conn.execute("UPDATE collect.watch SET selector_watch = '{}' WHERE id = %s", (watch["id"],))
    assert _edit(conn, w, watch["id"], priority=4)[1] == ["priority"]
    assert _edit(conn, w, watch["id"], selectors=["s"])[1] == ["selectors"]


def test_the_audit_row_of_an_edit_carries_counts_and_never_the_terms_or_the_name(conn):
    w = _world(conn)
    watch = _make(conn, w, name=f"{P}audit-name", keywords=["wire-transfer-kit", "two"],
                  selectors=["leaked.handle@example.test"], regexes=None, priority=3,
                  suppress_window_s=3600)
    _edit(conn, w, watch["id"], name=f"{P}renamed-secretly", keywords=["one"],
          regexes=["secret[0-9]+"], priority=1)
    rows = _audit_rows(conn, "WATCH_EDITED", watch["id"])
    assert len(rows) == 1
    actor, kind, obj, object_id, case, detail, text = rows[0]
    assert (actor, kind, obj, str(object_id), case) == (
        w["user"], "USER", "watch", watch["id"], w["case"])
    assert detail == {
        "changed": ["name", "keywords", "regexes", "priority"],
        "before": {"keywords": 2, "selectors": 1, "regexes": 0, "priority": 3,
                   "suppress_window_s": 3600},
        "after": {"keywords": 1, "selectors": 1, "regexes": 1, "priority": 1,
                  "suppress_window_s": 3600}}
    for private in ("wire-transfer-kit", "leaked.handle", "secret[0-9]", "audit-name",
                    "renamed-secretly"):
        assert private not in text, private


def test_an_edit_and_its_audit_row_stand_or_fall_together(conn, monkeypatch):
    from noctornal_api.collection import CollectionService

    w = _world(conn)
    watch = _make(conn, w, keywords=["a"])

    def refuse(self, *args, **kwargs):
        raise RuntimeError("the audit write failed")

    monkeypatch.setattr(CollectionService, "_audit", refuse)
    with pytest.raises(RuntimeError):
        _edit(conn, w, watch["id"], keywords=["b"])
    assert _stored(conn, watch["id"])[1] == ["a"], "no edit without its record"


def test_a_watch_that_is_missing_hidden_or_on_another_case_cannot_be_edited(conn):
    from noctornal_api.collection import CollectionNotFound, CollectionService

    w = _world(conn, clearance="GREEN", case_class="GREEN", src_class="AMBER")
    above = _make(conn, w)
    elsewhere = {**w, "case": _case(conn, w["user"], classification="GREEN")}
    said = set()
    for case, watch_id in ((w["case"], above["id"]), (w["case"], uuid4()),
                           (elsewhere["case"], above["id"])):
        with pytest.raises(CollectionNotFound) as refused:
            CollectionService(conn).edit_watch(
                case, watch_id, changes={"priority": 1}, actor_id=w["user"],
                clearance="GREEN", compartments=frozenset())
        said.add(str(refused.value))
    assert len(said) == 1
    assert _stored(conn, above["id"])[4] == 3


@pytest.mark.skipif(not HAS_ROLES, reason="NOCTORNAL_APP_DB_ROLE not set")
def test_row_security_refuses_a_change_to_a_watch_on_a_case_the_request_role_cannot_read(conn):
    """The route's gate is not the only door shut. A request connection bound to somebody with no
    part in the case reads no such watch, and an UPDATE it sends itself touches no row, so a caller
    that skipped the gate would still change nothing and leave no audit row."""
    from noctornal_api.collection import CollectionNotFound, CollectionService
    from noctornal_api.db import APP_ROLE, bind_session, connect

    w = _world(conn)
    watch = _make(conn, w)
    stranger, email = h.user(conn, P, roles=("COLLECTOR",))
    app = connect()
    try:
        app.execute(f"SET ROLE {APP_ROLE}")
        bind_session(app, h.session(conn, email))
        with pytest.raises(CollectionNotFound):
            CollectionService(app).stop_watch(
                w["case"], watch["id"], actor_id=stranger, clearance="RED",
                compartments=frozenset())
        with pytest.raises(CollectionNotFound):
            CollectionService(app).edit_watch(
                w["case"], watch["id"], changes={"priority": 1}, actor_id=stranger,
                clearance="RED", compartments=frozenset())
        touched = app.execute(
            "UPDATE collect.watch SET is_active = false, priority = 1 WHERE id = %s "
            "RETURNING id", (watch["id"],)).fetchall()
        assert touched == [], "the policy gives the stranger no row to update"
    finally:
        app.close()
    assert _active(conn, watch["id"]) is True
    assert _stored(conn, watch["id"])[4] == 3
    assert conn.execute(
        "SELECT count(*) FROM audit.event WHERE action IN "
        "('WATCH_STOPPED', 'WATCH_RESUMED', 'WATCH_EDITED') AND actor_id = %s",
        (stranger,)).fetchone()[0] == 0


# --- over HTTP ------------------------------------------------------------------------

#: The three routes, in the order the docs give them.
VERBS = ("stop", "resume", "edit")


def _url(case, watch=None, verb=None):
    base = f"/api/v1/cases/{case}/collection/watches"
    if watch is None:
        return base
    return f"{base}/{watch}" if verb in (None, "edit") else f"{base}/{watch}/{verb}"


def _hdr(conn, email):
    return h.auth(h.session(conn, email))


def _send(client, case, watch, verb, headers=None, body=None):
    """One of the three routes: stop and resume are POSTs, an edit is a PATCH whose body, when the
    test does not give one, changes the priority."""
    url = _url(case, watch, verb)
    if verb == "edit":
        return client.patch(url, headers=headers, json={"priority": 1} if body is None else body)
    return client.post(url, headers=headers)


def test_a_collection_manager_on_the_case_stops_and_resumes(conn):
    client, _ = h.client()
    w = _world(conn)
    hdr = _hdr(conn, w["email"])
    watch = _make(conn, w)
    r = _send(client, w["case"], watch["id"], "stop", hdr)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["changed"] is True and out["watch"]["is_active"] is False
    assert out["watch"]["id"] == watch["id"] and out["watch"]["name"] == watch["name"]
    assert "next poll of its source" in out["next"]
    assert "a poll already under way may still raise hits" in out["next"]
    assert "Its old hits stay listed" in out["next"]
    assert "until they are rescored" in out["next"]
    listing = client.get(_url(w["case"]), headers=hdr).json()
    assert [(x["id"], x["is_active"]) for x in listing["watches"]] == [(watch["id"], False)]
    again = _send(client, w["case"], watch["id"], "stop", hdr).json()
    assert again["changed"] is False and again["next"] == "It was already stopped."
    r = _send(client, w["case"], watch["id"], "resume", hdr)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["changed"] is True and out["watch"]["is_active"] is True
    assert "next poll of its source" in out["next"]
    assert _active(conn, watch["id"]) is True
    again = _send(client, w["case"], watch["id"], "resume", hdr).json()
    assert again["changed"] is False and again["next"] == "It was already active."
    assert _stored(conn, watch["id"])[6] == w["user"]


def test_a_collection_manager_on_the_case_edits_and_the_listing_shows_it(conn):
    client, _ = h.client()
    w = _world(conn)
    hdr = _hdr(conn, w["email"])
    watch = _make(conn, w, keywords=["ransom"], selectors=["s@x.test"], priority=3)
    r = client.patch(_url(w["case"], watch["id"]), headers=hdr, json={
        "name": f"{P}renamed", "keywords": ["wiper", "kit"], "priority": 1,
        "suppress_window_s": 120})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["changed"] == ["name", "keywords", "priority", "suppress_window_s"]
    assert out["watch"]["name"] == f"{P}renamed"
    assert out["watch"]["keywords"] == ["wiper", "kit"]
    assert out["watch"]["selectors"] == ["s@x.test"], "a field left out is left alone"
    assert "next poll of its source" in out["next"]
    assert "Hits already raised keep the reasons they were raised with" in out["next"]
    assert "until they are rescored" in out["next"]
    listing = client.get(_url(w["case"]), headers=hdr).json()["watches"]
    assert [(x["name"], x["keywords"], x["priority"], x["suppress_window_s"])
            for x in listing] == [(f"{P}renamed", ["wiper", "kit"], 1, 120)]
    same = client.patch(_url(w["case"], watch["id"]), headers=hdr, json={"priority": 1})
    assert same.status_code == 200 and same.json()["changed"] == []
    assert same.json()["next"] == "Nothing changed."
    cleared = client.patch(_url(w["case"], watch["id"]), headers=hdr, json={"selectors": []})
    assert cleared.status_code == 200 and cleared.json()["watch"]["selectors"] == []


def test_a_stopped_watch_can_still_be_edited_and_stays_stopped(conn):
    client, _ = h.client()
    w = _world(conn)
    hdr = _hdr(conn, w["email"])
    watch = _make(conn, w)
    _stop(conn, w, watch["id"])
    r = client.patch(_url(w["case"], watch["id"]), headers=hdr, json={"keywords": ["fixed"]})
    assert r.status_code == 200 and r.json()["watch"]["is_active"] is False, r.text
    assert _active(conn, watch["id"]) is False, "an edit does not resume a watch"


def test_any_collection_manager_on_the_case_may_stop_and_edit_a_watch_it_did_not_make(conn):
    """Any manager on the case, the same two checks as making one: `owner_user_id` stays the
    creator and the audit row names who acted."""
    client, _ = h.client()
    w = _world(conn)
    watch = _make(conn, w)
    other, email = h.user(conn, P, roles=("COLLECTOR",))
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
                 (w["case"], other, w["user"]))
    hdr = _hdr(conn, email)
    assert _send(client, w["case"], watch["id"], "edit", hdr, {"priority": 2}).status_code == 200
    assert _send(client, w["case"], watch["id"], "stop", hdr).status_code == 200
    assert _stored(conn, watch["id"])[6] == w["user"]
    assert _audit_rows(conn, "WATCH_STOPPED", watch["id"])[0][0] == other
    assert _audit_rows(conn, "WATCH_EDITED", watch["id"])[0][0] == other


def test_a_telegram_chat_watch_edited_down_to_no_term_says_it_fires_on_every_message(conn):
    client, _ = h.client()
    w = _chat_world(conn)
    hdr = _hdr(conn, w["email"])
    watch = _make(conn, w, target_kind="TELEGRAM_CHAT", target_ref=w["chat"],
                  keywords=["wire"])
    r = client.patch(_url(w["case"], watch["id"]), headers=hdr, json={"keywords": []})
    assert r.status_code == 200, r.text
    assert "fires on every message of that chat" in r.json()["next"]
    conn.execute("UPDATE collect.source SET is_active = false WHERE id = %s", (w["source"],))
    r = client.patch(_url(w["case"], watch["id"]), headers=hdr, json={"priority": 1})
    assert "Its source is paused" in r.json()["next"]


def test_a_field_a_watch_cannot_change_is_refused_by_name(conn):
    """A 422 that names the field, so a caller who sends it learns it did nothing. To aim a watch
    somewhere else, stop it and add a new one."""
    client, _ = h.client()
    w = _world(conn)
    hdr = _hdr(conn, w["email"])
    watch = _make(conn, w)
    before = _stored(conn, watch["id"])
    for field, value in (("source_id", str(uuid4())), ("target_kind", "BOARD"),
                         ("target_ref", "https://elsewhere.example.test/"),
                         ("is_active", False), ("owner_user_id", str(uuid4())),
                         ("case_id", str(uuid4()))):
        r = client.patch(_url(w["case"], watch["id"]), headers=hdr,
                         json={"priority": 1, field: value})
        assert r.status_code == 422 and r.json()["title"] == "Validation failed", (field, r.text)
        assert field in r.json()["detail"], (field, r.json())
    assert _stored(conn, watch["id"]) == before
    assert conn.execute("SELECT source_id, target_kind, target_ref, is_active FROM collect.watch "
                        "WHERE id = %s", (watch["id"],)).fetchone() == (
        w["source"], "FEED", FEED, True)


def test_an_empty_or_null_patch_and_a_refused_value_are_a_400_in_words(conn):
    client, _ = h.client()
    w = _world(conn)
    hdr = _hdr(conn, w["email"])
    watch = _make(conn, w, keywords=["a"])
    url = _url(w["case"], watch["id"])
    r = client.patch(url, headers=hdr, json={})
    assert r.status_code == 400 and "Say what to change" in r.json()["detail"], r.text
    r = client.patch(url, headers=hdr, json={"keywords": None})
    assert r.status_code == 400 and "[] to clear it, not null" in r.json()["detail"], r.text
    r = client.patch(url, headers=hdr, json={"name": None})
    assert r.status_code == 400 and "between 3 and 200" in r.json()["detail"], r.text
    r = client.patch(url, headers=hdr, json={"keywords": [], "selectors": []})
    assert r.status_code == 400 and "needs a keyword" in r.json()["detail"], r.text
    r = client.patch(url, headers=hdr, json={"regexes": ["(open"]})
    assert r.status_code == 400 and "does not compile" in r.json()["detail"], r.text
    r = client.patch(url, headers=hdr, json={"priority": "high"})
    assert r.status_code == 422, "a value of the wrong type is the framework's 422"
    assert _stored(conn, watch["id"])[1] == ["a"]


def test_a_name_another_watch_holds_is_a_409_over_http(conn):
    client, _ = h.client()
    w = _world(conn)
    hdr = _hdr(conn, w["email"])
    _make(conn, w, name=f"{P}Taken")
    mine = _make(conn, w, name=f"{P}mine")
    r = client.patch(_url(w["case"], mine["id"]), headers=hdr, json={"name": f"{P}tAKEN"})
    assert r.status_code == 409 and "already has a watch" in r.json()["detail"], r.text


def test_an_analyst_without_watch_manage_is_refused_all_three_and_the_denial_is_audited(conn):
    client, _ = h.client()
    w = _world(conn)
    analyst, email = h.user(conn, P, roles=("ANALYST",))
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
                 (w["case"], analyst, w["user"]))
    watch = _make(conn, w)
    before = _stored(conn, watch["id"])
    hdr = _hdr(conn, email)
    for verb in VERBS:
        r = _send(client, w["case"], watch["id"], verb, hdr)
        assert r.status_code == 403 and "watch.manage" in r.text, (verb, r.text)
    assert _stored(conn, watch["id"]) == before and _active(conn, watch["id"]) is True
    denied = conn.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'AUTHZ_DENIED' "
        "AND actor_id = %s AND detail->>'permission' = 'watch.manage'",
        (analyst,)).fetchone()[0]
    assert denied == 3
    for action in ("WATCH_STOPPED", "WATCH_RESUMED", "WATCH_EDITED"):
        assert _audit_rows(conn, action, watch["id"]) == []


def test_a_collection_manager_who_is_not_on_the_case_gets_the_case_404_on_all_three(conn):
    client, _ = h.client()
    w = _world(conn)
    watch = _make(conn, w)
    before = _stored(conn, watch["id"])
    stranger, email = h.user(conn, P, roles=("COLLECTOR",))
    hdr = _hdr(conn, email)
    for verb in VERBS:
        assert _send(client, w["case"], watch["id"], verb, hdr).status_code == 404, verb
        assert _send(client, uuid4(), watch["id"], verb, hdr).status_code == 404, verb
    assert _stored(conn, watch["id"]) == before
    # The refusal was the case gate's: put on the case, the same caller edits it.
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
                 (w["case"], stranger, w["user"]))
    assert _send(client, w["case"], watch["id"], "edit", hdr).status_code == 200


def test_an_unauthenticated_caller_is_refused(conn):
    client, _ = h.client()
    w = _world(conn)
    watch = _make(conn, w)
    before = _stored(conn, watch["id"])
    for verb in VERBS:
        assert _send(client, w["case"], watch["id"], verb).status_code == 401, verb
    assert _stored(conn, watch["id"]) == before


def test_a_watch_of_another_case_is_the_404_a_random_id_gets(conn):
    client, _ = h.client()
    w = _world(conn)
    hdr = _hdr(conn, w["email"])
    other = {**w, "case": _case(conn, w["user"])}
    elsewhere = _make(conn, other)
    before = _stored(conn, elsewhere["id"])
    for verb in VERBS:
        mine = _send(client, w["case"], elsewhere["id"], verb, hdr)
        random = _send(client, w["case"], uuid4(), verb, hdr)
        assert mine.status_code == random.status_code == 404, verb
        assert mine.json()["detail"] == random.json()["detail"], verb
    assert _stored(conn, elsewhere["id"]) == before
    assert _send(client, other["case"], elsewhere["id"], "stop", hdr).status_code == 200


def test_a_watch_on_a_source_above_the_caller_is_the_404_a_random_id_gets_for_all_three(conn):
    client, _ = h.client()
    w = _world(conn, clearance="GREEN", case_class="GREEN", src_class="AMBER")
    hdr = _hdr(conn, w["email"])
    above = _make(conn, w)
    before = _stored(conn, above["id"])
    for verb in VERBS:
        refused = _send(client, w["case"], above["id"], verb, hdr)
        random = _send(client, w["case"], uuid4(), verb, hdr)
        assert refused.status_code == random.status_code == 404, verb
        assert refused.json()["detail"] == random.json()["detail"], verb
    assert _stored(conn, above["id"]) == before and _active(conn, above["id"]) is True
    # The refusal was about the source: a manager who may see it changes the watch.
    high, email = h.user(conn, P, clearance="RED", roles=("COLLECTOR",))
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
                 (w["case"], high, w["user"]))
    assert _send(client, w["case"], above["id"], "edit", _hdr(conn, email)).status_code == 200


def test_a_closed_case_still_stops_a_watch_but_refuses_edit_and_resume(conn):
    from noctornal_api.cases import CaseService

    client, _ = h.client()
    w = _world(conn)
    hdr = _hdr(conn, w["email"])
    watch = _make(conn, w)
    CaseService(conn).transition_status(w["case"], "CLOSED", actor_id=w["user"])
    r = _send(client, w["case"], watch["id"], "stop", hdr)
    assert r.status_code == 200 and r.json()["changed"] is True, r.text
    assert _active(conn, watch["id"]) is False
    before = _stored(conn, watch["id"])
    for verb in ("resume", "edit"):
        r = _send(client, w["case"], watch["id"], verb, hdr)
        assert r.status_code == 409 and r.json()["title"] == "Case is read-only", (verb, r.text)
    assert _active(conn, watch["id"]) is False and _stored(conn, watch["id"]) == before
    assert client.get(_url(w["case"]), headers=hdr).status_code == 200, "the list still reads"
    CaseService(conn).transition_status(w["case"], "ACTIVE", actor_id=w["user"])
    assert _send(client, w["case"], watch["id"], "edit", hdr).status_code == 200
    assert _send(client, w["case"], watch["id"], "resume", hdr).status_code == 200
    assert _active(conn, watch["id"]) is True


@pytest.mark.parametrize("verb", VERBS)
def test_the_three_routes_are_metered_under_collection_config(conn, verb):
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
    watch = _make(conn, w)
    codes = [_send(client, w["case"], watch["id"], verb, hdr).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert client.get(_url(w["case"]), headers=hdr).status_code == 200, (
        "reading the list spends no part of the meter")


def _gates(route) -> list[tuple[str, str]]:
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
    return found


@pytest.mark.parametrize("method, suffix, writes_content", [
    ("POST", "/stop", False), ("POST", "/resume", True), ("PATCH", "", True)])
def test_the_change_routes_are_behind_both_gates_in_the_stated_order(
        method, suffix, writes_content):
    """What the closed-case route table also holds, stated where the routes are: the global verb is
    a dependency of its own, ahead of the case gate and the meter, and only the routes that change or
    restart a tasking say content_write, so a read-only case still lets a watch be stopped."""
    from noctornal_api.http.routers.collection import case_router

    route = next(r for r in case_router.routes
                 if r.path.endswith("/watches/{watch_id}" + suffix) and method in r.methods)
    found = _gates(route)
    assert ("require_global", "permission_key=watch.manage") in found
    assert ("require", "permission_key=collection.read") in found
    assert ("rate_limit", "name=collection.config") in found
    assert (("require", "content_write=True") in found) is writes_content
    order = [i for i, f in enumerate(found) if f[0] == "require_global"]
    case_gate = [i for i, f in enumerate(found)
                 if f == ("require", "permission_key=collection.read")]
    assert order and case_gate and order[0] < case_gate[0], (
        "the verb is asked before the case, so a caller without it learns nothing of the case")


def test_the_edit_body_names_only_what_an_edit_may_change():
    from noctornal_api.http.routers.collection import WatchCreate, WatchEdit

    assert set(WatchEdit.model_fields) == {"name", "keywords", "selectors", "regexes",
                                           "priority", "suppress_window_s"}
    assert set(WatchEdit.model_fields) < set(WatchCreate.model_fields), (
        "an edit takes no field a new watch does not")
    assert WatchEdit.model_config.get("extra") == "forbid"

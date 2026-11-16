"""A binding and its audit row, and a message and its side rows, are each written in one transaction
(review INTEGRITY, AREA-04).

The request connection commits every statement as it runs, so `CommsService.bind` committed the
binding and then wrote its audit row, and `add_message` committed the message and then wrote the
participant and the counts. A failure between two of those statements left a binding the audit chain
never recorded (the analyst's retry stored the identifier a second time) or a message whose sender
the contact graph never saw: the retry met the message's content key, took it as already held and
returned, so the half-write stuck.

What is held here:

- a failure at any statement of either write leaves none of its rows, and the retry stores one binding
  or one message with everything that goes with it;
- a message that is already held is not taken as complete: a message stored with no participant, or with
  a count that never took it in, is settled by the second store, and the state a first complete store
  leaves is the state every later store of it leaves;
- the settling raises counts and never lowers one, adds nothing for a message the caller cannot see,
  and does not make two stores of one message wait on each other;
- minimising a conversation drops the bodies and audits the drop in one transaction, so an audit
  row that fails leaves the bodies in place and the retry drops and audits them;
- a message that is already held and complete is stored again without writing a row, so it takes
  no lock and leaves no new tuple, and a content key another sender's message shares settles no
  participant for the sender who did not store it.

DATABASE_URL-gated. Rows are `atw-`.
"""
from __future__ import annotations

import hashlib
import os
import threading
from datetime import date, datetime, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; comms tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "atw-"
WHEN = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
TOX_ID = "b" * 64 + "11111111" + "2222"


@pytest.fixture
def conn():
    from noctornal_api.db import connect

    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM comms.message WHERE conversation_id IN "
                  f"(SELECT id FROM comms.conversation WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM comms.participant WHERE conversation_id IN "
                  f"(SELECT id FROM comms.conversation WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM comms.conversation WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM comms.channel_binding WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{P}%@noctornal.test'")
    c.close()


class _Failing:
    """The connection, except that a statement containing `needle` raises as the database would
    if that statement failed: the service sees a refusal at exactly that point."""

    def __init__(self, real, needle: str):
        self._real = real
        self._needle = needle
        self.hit = False

    def execute(self, query, *args, **kwargs):
        if self._needle in str(query):
            self.hit = True
            raise RuntimeError("injected failure")
        return self._real.execute(query, *args, **kwargs)

    def transaction(self, *args, **kwargs):
        return self._real.transaction(*args, **kwargs)


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{P}{uuid4().hex[:8]}@noctornal.test", "Atomic", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s", (uid,))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-ATW-{uuid4().hex[:6]}", title="Atomic",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


def _service(conn):
    from noctornal_api.comms import CommsService
    return CommsService(conn, clearance="RED")


def _room(conn, svc):
    from noctornal_api.comms import OPEN_GROUP
    actor = _user(conn)
    case_id = _case(conn, actor)
    convo = svc.open_conversation(case_id=case_id, platform_key="MATRIX",
                                  provenance_class=OPEN_GROUP, external_ref=f"#{P}{uuid4().hex[:6]}:s",
                                  is_group=True)
    return actor, case_id, convo


def _digest(handle: str, sent_at, body: str) -> bytes:
    """The content key `add_message` stores a message under."""
    return hashlib.sha256(f"{handle}\x1f{sent_at}\x1f{body or ''}".encode()).digest()


def _store_without_side_rows(conn, convo, handle, body, sent_at=WHEN):
    """A message as an earlier build could leave it: the row, and nothing else."""
    conn.execute(
        """INSERT INTO comms.message (conversation_id, sender_handle, sent_at, body, content_sha256)
           VALUES (%s, %s, %s, %s, %s)""",
        (convo, handle, sent_at, body, _digest(handle, sent_at, body)))


def _participants(conn, convo):
    return conn.execute(
        """SELECT observed_handle, message_count, first_seen, last_seen, is_incidental
             FROM comms.participant WHERE conversation_id = %s ORDER BY observed_handle""",
        (convo,)).fetchall()


def _conversation(conn, convo):
    return conn.execute(
        "SELECT message_count, last_message_at FROM comms.conversation WHERE id = %s",
        (convo,)).fetchone()


def _messages(conn, convo) -> int:
    return conn.execute("SELECT count(*) FROM comms.message WHERE conversation_id = %s",
                        (convo,)).fetchone()[0]


# --- a binding and its audit row ------------------------------------------------------

def test_a_binding_whose_audit_row_fails_is_not_stored_and_the_retry_stores_one(conn):
    svc = _service(conn)
    actor = _user(conn)
    case_id = _case(conn, actor)
    failing = _Failing(conn, "INSERT INTO audit.event")
    with pytest.raises(RuntimeError, match="injected failure"):
        _service_on(failing).bind(case_id=case_id, platform_key="TOX", observed=TOX_ID,
                                  created_by=actor)
    assert failing.hit, "the failure must land on the audit insert, or the test says nothing"
    assert conn.execute("SELECT count(*) FROM comms.channel_binding WHERE case_id = %s",
                        (case_id,)).fetchone()[0] == 0, "a binding the chain never recorded"

    made = svc.bind(case_id=case_id, platform_key="TOX", observed=TOX_ID, created_by=actor)
    hits = svc.correlate(platform_key="TOX", observed=TOX_ID, case_id=case_id)
    assert len(hits) == 1, "the retry is the identifier's first binding, not its second"
    assert conn.execute(
        """SELECT count(*) FROM audit.event
            WHERE action = 'CHANNEL_BOUND' AND object_id = %s AND case_id = %s""",
        (made["id"], case_id)).fetchone()[0] == 1


def _service_on(connection):
    from noctornal_api.comms import CommsService
    return CommsService(connection, clearance="RED")


def test_minimising_whose_audit_row_fails_drops_no_body_and_the_retry_drops_and_audits_them(conn):
    svc = _service(conn)
    actor, _case_id, convo = _room(conn, svc)
    svc.add_message(convo, sender_handle="@a:s", body="one", sent_at=WHEN)
    svc.add_message(convo, sender_handle="@b:s", body="two", sent_at=WHEN)
    failing = _Failing(conn, "INSERT INTO audit.event")
    with pytest.raises(RuntimeError, match="injected failure"):
        _service_on(failing).minimise(convo, actor_id=actor, authority="order 7")
    assert failing.hit
    assert conn.execute(
        "SELECT count(*) FROM comms.message WHERE conversation_id = %s AND body IS NOT NULL",
        (convo,)).fetchone()[0] == 2, "bodies gone with no record of who dropped them"

    assert svc.minimise(convo, actor_id=actor, authority="order 7") == 2
    assert conn.execute(
        """SELECT detail->>'messages' FROM audit.event
            WHERE action = 'CONVERSATION_MINIMISED' AND object_id = %s""",
        (convo,)).fetchall() == [("2",)]


# --- a message and its side rows ------------------------------------------------------

@pytest.mark.parametrize("needle", ["INSERT INTO comms.participant", "UPDATE comms.conversation"])
def test_a_message_whose_side_rows_fail_is_not_stored_and_the_retry_stores_it_whole(conn, needle):
    svc = _service(conn)
    _actor, case_id, convo = _room(conn, svc)
    failing = _Failing(conn, needle)
    with pytest.raises(RuntimeError, match="injected failure"):
        _service_on(failing).add_message(convo, sender_handle="@a:s", body="hello", sent_at=WHEN)
    assert failing.hit
    assert _messages(conn, convo) == 0, "a message whose sender the contact graph never saw"
    assert _participants(conn, convo) == []
    assert _conversation(conn, convo)[0] == 0

    assert svc.add_message(convo, sender_handle="@a:s", body="hello", sent_at=WHEN) is not None
    assert [(h, n) for h, n, *_ in _participants(conn, convo)] == [("@a:s", 1)]
    assert _conversation(conn, convo) == (1, WHEN)


# --- a message that is already held ---------------------------------------------------

def test_storing_a_message_again_leaves_the_state_the_first_store_left(conn):
    svc = _service(conn)
    _actor, _case_id, convo = _room(conn, svc)
    assert svc.add_message(convo, sender_handle="@a:s", body="hello", sent_at=WHEN) is not None
    svc.add_message(convo, sender_handle="@b:s", body="hi", sent_at=WHEN)
    svc.mark_incidental(convo, "@b:s")
    before = (_participants(conn, convo), _conversation(conn, convo))
    assert svc.add_message(convo, sender_handle="@a:s", body="hello", sent_at=WHEN) is None
    assert svc.add_message(convo, sender_handle="@b:s", body="hi", sent_at=WHEN) is None
    assert (_participants(conn, convo), _conversation(conn, convo)) == before
    assert before[1][0] == 2 and _messages(conn, convo) == 2


def test_a_message_with_no_sent_time_is_as_stable_when_stored_again(conn):
    svc = _service(conn)
    _actor, _case_id, convo = _room(conn, svc)
    # Its time is the moment it was captured, which the conversation's last message takes.
    assert svc.add_message(convo, sender_handle="@a:s", body="undated") is not None
    before = (_participants(conn, convo), _conversation(conn, convo))
    assert svc.add_message(convo, sender_handle="@a:s", body="undated") is None
    assert (_participants(conn, convo), _conversation(conn, convo)) == before


def test_a_message_stored_with_no_participant_is_settled_by_its_second_store(conn):
    """What a failure between the message and its participant left in an earlier build: the
    sender is missing from the contact graph and the conversation does not count the message."""
    svc = _service(conn)
    _actor, case_id, convo = _room(conn, svc)
    _store_without_side_rows(conn, convo, "@a:s", "hello")
    assert svc.contact_graph(case_id) == []

    assert svc.add_message(convo, sender_handle="@a:s", body="hello", sent_at=WHEN) is None, \
        "still the message already held"
    assert _participants(conn, convo) == [("@a:s", 1, WHEN, WHEN, False)]
    assert _conversation(conn, convo) == (1, WHEN)
    assert svc.contact_graph(case_id)[0]["participants"] == ["@a:s"]
    # and a third store changes nothing further
    svc.add_message(convo, sender_handle="@a:s", body="hello", sent_at=WHEN)
    assert _participants(conn, convo) == [("@a:s", 1, WHEN, WHEN, False)]
    assert _conversation(conn, convo) == (1, WHEN)


def test_a_participant_written_without_its_count_is_settled_and_keeps_what_it_had(conn):
    """The order of the old statements: the participant, then the conversation's count. A failure
    between them left a sender who was seen and a conversation that had not counted the message."""
    svc = _service(conn)
    _actor, _case_id, convo = _room(conn, svc)
    _store_without_side_rows(conn, convo, "@a:s", "hello")
    first = datetime(2026, 4, 1, tzinfo=timezone.utc)
    conn.execute(
        """INSERT INTO comms.participant (conversation_id, observed_handle, first_seen, last_seen,
                                          message_count, is_incidental)
           VALUES (%s, '@a:s', %s, %s, 1, true)""", (convo, first, WHEN))
    svc.add_message(convo, sender_handle="@a:s", body="hello", sent_at=WHEN)
    assert _participants(conn, convo) == [("@a:s", 1, first, WHEN, True)], \
        "its count stays one, its first sighting and its incidental flag stay"
    assert _conversation(conn, convo) == (1, WHEN)


def test_settling_a_held_message_never_lowers_a_count(conn):
    """A participant can carry a count the stored messages do not show (a roster kept without its
    bodies): the second store of a message settles up, never down."""
    svc = _service(conn)
    _actor, _case_id, convo = _room(conn, svc)
    _store_without_side_rows(conn, convo, "@a:s", "hello")
    conn.execute(
        """INSERT INTO comms.participant (conversation_id, observed_handle, message_count)
           VALUES (%s, '@a:s', 7)""", (convo,))
    conn.execute("UPDATE comms.conversation SET message_count = 9 WHERE id = %s", (convo,))
    svc.add_message(convo, sender_handle="@a:s", body="hello", sent_at=WHEN)
    assert _participants(conn, convo)[0][1] == 7
    assert _conversation(conn, convo)[0] == 9


def _row_versions(conn, convo):
    """The version of the participant rows and of the conversation row: it moves when a row is
    written, even to the value it had."""
    return (conn.execute(
        "SELECT observed_handle, xmin::text FROM comms.participant "
        "WHERE conversation_id = %s ORDER BY observed_handle", (convo,)).fetchall(),
        conn.execute("SELECT xmin::text FROM comms.conversation WHERE id = %s",
                     (convo,)).fetchone())


def test_a_complete_message_stored_again_writes_no_row(conn):
    """A re-poll of a room stores every message of its window again. Nothing is missing, so no row
    is written (and none locked): writing the same values back made a new tuple of two rows for each
    message and made the stores of one room wait on each other."""
    svc = _service(conn)
    _actor, _case_id, convo = _room(conn, svc)
    for handle, body in (("@a:s", "one"), ("@b:s", "two"), ("@a:s", "three")):
        assert svc.add_message(convo, sender_handle=handle, body=body, sent_at=WHEN) is not None
    before = _row_versions(conn, convo)
    for handle, body in (("@a:s", "one"), ("@b:s", "two"), ("@a:s", "three")):
        assert svc.add_message(convo, sender_handle=handle, body=body, sent_at=WHEN) is None
    assert _row_versions(conn, convo) == before


def test_a_content_key_another_sender_shares_settles_nothing_for_the_other_sender(conn):
    """The key joins handle, time and body with U+001F, which any of them may hold, so two senders'
    messages can share one. The second is dropped as held, as before, and the handle that stored
    nothing is not made a participant of the room with a count of none."""
    svc = _service(conn)
    _actor, case_id, convo = _room(conn, svc)
    assert svc.add_message(convo, sender_handle="x", body="None\x1fb") is not None
    assert hashlib.sha256("x\x1fNone\x1fNone\x1fb".encode()).digest() ==         _digest("x\x1fNone", None, "b"), "the fixture must make the two keys one"
    before = (_participants(conn, convo), _conversation(conn, convo))
    assert svc.add_message(convo, sender_handle="x\x1fNone", body="b") is None
    assert (_participants(conn, convo), _conversation(conn, convo)) == before
    assert [h for h, *_ in _participants(conn, convo)] == ["x"]
    assert svc.contact_graph(case_id)[0]["participants"] == ["x"]


def test_a_message_for_a_conversation_nobody_can_see_is_none_and_adds_nothing(conn):
    svc = _service(conn)
    gone = uuid4()
    assert svc.add_message(gone, sender_handle="@a:s", body="x", sent_at=WHEN) is None
    assert conn.execute("SELECT count(*) FROM comms.participant WHERE conversation_id = %s",
                        (gone,)).fetchone()[0] == 0


def test_stores_of_the_same_messages_from_many_connections_neither_deadlock_nor_miscount(conn):
    """Each store takes the sender's participant row and then the conversation's, and the settling
    of a held message takes them in the same order, so the stores of one message cannot wait on
    each other. Six connections store the same six messages, in their own orders."""
    from noctornal_api.db import connect

    svc = _service(conn)
    _actor, _case_id, convo = _room(conn, svc)
    messages = [("@a:s", f"a{n}") for n in range(3)] + [("@b:s", f"b{n}") for n in range(3)]
    errors: list[BaseException] = []
    barrier = threading.Barrier(6)

    def worker(seed: int) -> None:
        c = connect()
        try:
            mine = _service_on(c)
            order = messages[seed:] + messages[:seed]
            barrier.wait(timeout=30)
            for handle, body in order:
                mine.add_message(convo, sender_handle=handle, body=body, sent_at=WHEN)
        except BaseException as exc:                      # noqa: BLE001 - reported below
            errors.append(exc)
        finally:
            c.close()

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert not any(t.is_alive() for t in threads), "a store is still waiting: a deadlock"
    assert errors == []
    assert _messages(conn, convo) == 6
    assert [(h, n) for h, n, *_ in _participants(conn, convo)] == [("@a:s", 3), ("@b:s", 3)]
    assert _conversation(conn, convo)[0] == 6

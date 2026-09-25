"""Legal hold and the purge for Telegram documents (roadmap F5.3,
2026-09-24; docs/00 decision 74).

The hold itself is the collection foundation's (proven there across
every citation path); these are the Telegram-named cases: a Telegram
document cited in a held case survives the deployment-wide purge with its
capture record, and an uncited expired one goes with the identities its
capture record held. DATABASE_URL-gated.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

import collection_helpers as h
import telegram_fake as tf
import telegram_pg as tp

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-tgret-"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    tf.guard_sockets(monkeypatch)
    tf.patch_routes(monkeypatch)
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%')"
    with c.transaction():
        c.execute(f"""UPDATE core."case" SET legal_hold = false, legal_hold_reason = NULL
                       WHERE owner_user_id IN {sub}""")
    tp.teardown(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def world(conn):
    from noctornal_api.collection import CollectionService, RssAdapter
    from noctornal_api.telegram import TelegramAdapter

    recorder, _ = h.user(conn, P, roles=("COLLECTOR", "CASE_OWNER"))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    pid, _e, uid = tp.persona(conn, P)
    ch = tp.chat(conn, P, persona_id=pid, resolved_by=recorder)
    h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                source_ids=[ch["source"]])
    msgs = [{"id": 1, "date": "2026-09-24T10:00:00+00:00", "text": "kept by a court",
             "from": {"type": "user", "id": 700000041}, "sender_handle": "@heldvendor"},
            {"id": 2, "date": "2026-09-24T10:01:00+00:00", "text": "nobody cites this",
             "from": {"type": "user", "id": 700000042}, "sender_handle": "@loosevendor",
             "fwd": {"from": {"type": "channel", "id": 1300000043}, "name": None}}]
    adapter = TelegramAdapter(tf.FakeFactory(tp.fixture_for(ch["spec"], uid, msgs)),
                              sleep=tf._no_sleep)
    result = CollectionService(conn, {"rss": RssAdapter(), "telegram": adapter},
                               sleep=lambda _s: None).run_once(ch["source"], actor_id=None)
    assert result.status == "OK", result.error
    docs = dict(conn.execute(
        """SELECT m.message_id, d.id FROM collect.document d
             JOIN collect.telegram_message m ON m.document_id = d.id
            WHERE d.source_id = %s""", (ch["source"],)).fetchall())
    conn.execute("UPDATE collect.document SET retain_until = now() - interval '1 day' "
                 "WHERE source_id = %s", (ch["source"],))
    return {"owner": recorder, "docs": docs, "source": ch["source"]}


def _held_case(conn, owner):
    from noctornal_api.cases import CaseService

    case = CaseService(conn).create(
        code=f"OP-TGR-{uuid4().hex[:6]}", title="tg retention", legal_basis="order",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner)
    conn.execute('UPDATE core."case" SET legal_hold = true, '
                 "legal_hold_reason = 'court order 2026-91' WHERE id = %s", (case,))
    return case


def _cite(conn, case, owner, doc):
    node = uuid4()
    with conn.transaction():
        conn.execute("""INSERT INTO core.node (id, case_id, node_type, label, created_by)
                        VALUES (%s, %s, 'IDENTITY', %s, %s)""",
                     (node, case, f"tgret-{node.hex[:6]}", owner))
        conn.execute("""INSERT INTO core.assertion
                            (case_id, node_id, basis, created_by, document_id, retracted_at)
                        VALUES (%s, %s, 'DIRECT_OBSERVATION', %s, %s, now())""",
                     (case, node, owner, doc))


def test_a_telegram_document_cited_in_a_held_case_is_not_purged(conn, world):
    from noctornal_api.retention import RetentionService

    case = _held_case(conn, world["owner"])
    _cite(conn, case, world["owner"], world["docs"][1])
    result = RetentionService(conn).purge_due(actor_id=world["owner"],
                                              authority="retention schedule")
    assert result.held_back >= 1
    kept = conn.execute(
        """SELECT d.purged_at, d.body_text, d.author_uid, m.sender_uid,
                  m.sender_handle_at_capture
             FROM collect.document d JOIN collect.telegram_message m ON m.document_id = d.id
            WHERE d.id = %s""", (world["docs"][1],)).fetchone()
    assert kept == (None, "kept by a court", "u:700000041", "u:700000041", "@heldvendor")


def test_an_uncited_expired_telegram_document_is_purged_with_its_identifiers(conn, world):
    from noctornal_api.retention import RetentionService

    case = _held_case(conn, world["owner"])
    _cite(conn, case, world["owner"], world["docs"][1])
    RetentionService(conn).purge_due(actor_id=world["owner"],
                                     authority="retention schedule")
    gone = conn.execute(
        """SELECT d.purged_at IS NOT NULL, d.body_text, d.author_handle, d.author_uid,
                  m.sender_uid, m.sender_handle_at_capture, m.fwd_from_uid,
                  m.message_id, m.chat_durable_id
             FROM collect.document d JOIN collect.telegram_message m ON m.document_id = d.id
            WHERE d.id = %s""", (world["docs"][2],)).fetchone()
    assert gone[:7] == (True, "", None, None, None, None, None)
    assert gone[7] == 2 and gone[8].startswith("c:"), "the capture record itself stays"
    found = conn.execute(
        """SELECT count(*) FROM collect.document
            WHERE search_tsv @@ plainto_tsquery('simple', 'loosevendor')
              AND source_id = %s""", (world["source"],)).fetchone()[0]
    assert found == 0


def test_the_telegram_side_table_is_registered_for_the_catalogue_and_the_scrub():
    from noctornal_api import retention

    key = "collect.telegram_message.document_id"
    assert key in retention.DOCUMENT_REFERENCES_NOT_CASE_MATERIAL
    assert "UPDATE collect.telegram_message" in retention.DOCUMENT_PURGE_SCRUBS[key]

"""The Telegram suite's database helpers (roadmap F5.2 and F5.3,
2026-09-24). Importable, no test functions.

Telegram rows are never deleted (the chat and message guards, 0082's
platform-bound personas, the authorities), and the chat's durable id and a
persona's account id are unique, so every id here is drawn per run from a
uuid and `teardown` follows the collection
foundation's no-delete pattern: what may not be deleted is purged or
deactivated, so no later test reads it.
"""
from __future__ import annotations

import uuid

from psycopg.types.json import Jsonb

import collection_helpers as h
import telegram_fake as tf


def rand_id(low: int = 10 ** 9, high: int = 10 ** 12) -> int:
    return low + uuid.uuid4().int % (high - low)


def persona(conn, prefix: str, *, egress=None, enrolled: bool = True,
            uid: str | None = None, session: str | None = None,
            fingerprint: dict | None = None) -> tuple:
    """(persona id, egress profile id, account uid): a Telegram persona with
    its device, and, when enrolled, a sealed session and an account id."""
    egress = egress or h.egress_profile(conn, prefix)
    uid = uid or f"u:{rand_id()}"
    pid = h.persona(conn, prefix, egress=egress,
                    fingerprint=dict(fingerprint if fingerprint is not None else tf.DEVICE),
                    secret=tf.secret_json(session=session) if enrolled else None)
    if enrolled:
        conn.execute(
            """UPDATE collect.collection_account
                  SET platform_uid = %s, session_enrolled_at = now()
                WHERE id = %s""", (uid, pid))
    return pid, egress, uid


def chat(conn, prefix: str, *, persona_id, peer_type: str = "CHANNEL",
         access_mode: str = "PUBLIC_READ", classification: str = "AMBER",
         username: str | None = "auto", peer_id: int | None = None,
         member_since: bool = False, resolved_by, access_hash: int | None = 55,
         hash_owner=True, max_rps: float = 1.0, active: bool = True) -> dict:
    """A Telegram source read by `persona_id` and its chat row. Returns the
    spec a FakeTransport fixture uses for the same chat."""
    peer_id = peer_id or rand_id()
    if username == "auto":
        username = f"tg{uuid.uuid4().hex[:10]}" if peer_type != "CHAT" else None
    durable = ("g:" if peer_type == "CHAT" else "c:") + str(peer_id)
    source_id = h.source(conn, prefix, kind="TELEGRAM", parser="telegram",
                         classification=classification, base_url=None,
                         persona=persona_id, max_rps=max_rps, active=active)
    conn.execute("UPDATE collect.source SET parser_config = %s WHERE id = %s",
                 (Jsonb({"access_mode": access_mode}), source_id))
    has_hash = access_hash is not None and peer_type != "CHAT"
    conn.execute(
        """INSERT INTO collect.telegram_chat
               (source_id, peer_type, peer_id, durable_id, access_mode,
                provenance_class, username_at_resolve, title_at_resolve,
                resolved_by, access_hash, access_hash_account_id,
                member_since_observed)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                   CASE WHEN %s THEN now() END)""",
        (source_id, peer_type, peer_id, durable, access_mode,
         "PERSONA_PARTY" if access_mode == "MEMBER" else "OPEN_GROUP",
         username, "A test chat", resolved_by,
         access_hash if has_hash else None,
         persona_id if has_hash and hash_owner else (h.persona(
             conn, prefix, platform=None, egress=h.egress_profile(conn, prefix))
             if has_hash else None),
         member_since))
    return {"source": source_id, "durable_id": durable,
            "spec": {"peer_type": peer_type, "peer_id": peer_id,
                     "access_hash": access_hash, "username": username,
                     "title": "A test chat",
                     "is_member": bool(access_mode == "MEMBER")}}


def fixture_for(spec: dict, uid: str, messages: list[dict] | None = None, **extra) -> dict:
    fx = {"me": uid, "chat": dict(spec), "messages": list(messages or [])}
    fx.update(extra)
    return fx


def messages(first: int, count: int, *, sender: int | None = None,
             text: str = "message {id}") -> list[dict]:
    return [{"id": i, "date": f"2026-09-2{i % 5}T10:{i % 60:02d}:00+00:00",
             "text": text.format(id=i),
             "from": {"type": "user", "id": sender or 700000000 + i}}
            for i in range(first, first + count)]


def teardown(conn, prefix: str) -> None:
    """Delete what may be deleted; purge the collected documents of this
    run's sources (a capture record keeps its document from deletion); and
    deactivate the sources, so no later due list, readiness row or
    document listing meets them."""
    like = f"{prefix}%"
    ssub = "(SELECT id FROM collect.source WHERE name LIKE %(like)s)"
    with conn.transaction():
        mine = """(SELECT id FROM notify.notification
                    WHERE (object_type = 'collection_account' AND object_id IN (
                             SELECT id FROM collect.collection_account
                              WHERE handle LIKE %(like)s))
                       OR (object_type = 'collection_authority' AND object_id IN (
                             SELECT a.id FROM collect.collection_authority a
                               JOIN iam.app_user u ON u.id = a.recorded_by
                              WHERE u.email LIKE %(like)s)))"""
        conn.execute(f"DELETE FROM notify.delivery WHERE notification_id IN {mine}",
                     {"like": like})
        conn.execute(f"DELETE FROM notify.notification WHERE id IN {mine}",
                     {"like": like})
        conn.execute(f"""DELETE FROM collect.watch_hit WHERE document_id IN (
                            SELECT id FROM collect.document WHERE source_id IN {ssub})""",
                     {"like": like})
        conn.execute(f"DELETE FROM collect.watch_hit WHERE watch_id IN "
                     f"(SELECT id FROM collect.watch WHERE source_id IN {ssub})",
                     {"like": like})
        conn.execute(f"DELETE FROM collect.watch WHERE source_id IN {ssub}",
                     {"like": like})
        conn.execute(f"""UPDATE core.assertion SET document_id = NULL
                          WHERE document_id IN (
                            SELECT id FROM collect.document WHERE source_id IN {ssub})""",
                     {"like": like})
        conn.execute(
            f"""UPDATE collect.document
                   SET purged_at = now(), body_text = '', title = NULL,
                       external_url = NULL, author_handle = NULL,
                       author_uid = NULL, search_tsv = NULL,
                       content_sha256 = sha256(convert_to('purged:' || id::text, 'UTF8'))
                 WHERE source_id IN {ssub} AND purged_at IS NULL""", {"like": like})
        conn.execute(
            f"""UPDATE collect.telegram_message
                   SET sender_uid = NULL, sender_handle_at_capture = NULL,
                       post_author = NULL, fwd_from_uid = NULL,
                       fwd_from_name = NULL, via_bot_uid = NULL
                 WHERE source_id IN {ssub}""", {"like": like})
        conn.execute("UPDATE collect.source SET is_active = false WHERE name LIKE %(like)s",
                     {"like": like})

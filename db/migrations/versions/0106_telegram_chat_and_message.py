"""The identity of a Telegram chat source and the capture record of each
Telegram message (roadmap F5.3, 2026-09-24).

## collect.telegram_chat

One row per Telegram source: which chat it is (peer type, positive peer
id, the typed durable id `c:<id>` or `g:<id>`), how it is read
(PUBLIC_READ without joining, provenance OPEN_GROUP; or MEMBER, provenance
PERSONA_PARTY), who resolved it and when, the access hash the reading
persona was given, and what membership has been SEEN. A confirmed
authority target names the source, so the source's chat must never change
under it: the identity columns are fixed, the row is never deleted or
truncated, and the only change of reading mode allowed is public to
member, never back. A chat that became a supergroup records `migrated_to`
once, and the supergroup is added as a new source with a new target.

## collect.telegram_message

One row per stored Telegram document: the chat and message id, which
persona account saw it (`seen_via_uid`), the typed sender, forward and
via-bot ids, the reply and topic, whether it is a service message (and the
TL action's class name, never an id), whether the persona itself acted,
the media kind (media is never downloaded), the edit time, and when a
deletion upstream was first seen. It has no label of its own and is read
only joined to its document, whose classification, compartments and
source's classification gate it. The record is fixed: a deletion is
marked once and never cleared, and the identifiers are cleared only by the
retention purge, for a purged document.

Every id column holds the typed forms `telegram_id_norm` produces, so the
bare-positive rule of Alpha 6 is held by the database on every id this
adapter stores; telegram.py holds the same patterns (test_telegram_ids).

## No CHECK on collect.source

A CHECK `source_telegram_is_a_persona_chat` (an active TELEGRAM source is
bound to a persona and read by parser_key 'telegram') is not added. The
collection foundation's refusal_cause already refuses, before any lock or
run row, a TELEGRAM source whose parser does not require authority, reads
another kind, or takes no persona; and the collection foundation's and the
egress proxy's suites create TELEGRAM sources read by their stub
parsers, which that CHECK would refuse. So the rule stays where the poll
enforces it (2026-09-25).

## Privileges

The runtime role keeps SELECT, INSERT and UPDATE on both tables and loses
the DELETE 0060's default privileges handed it (`GUARDED_TABLES`).

## Downgrade

Refuses while any chat row exists: Telegram sources would lose the only
record of which chat they are. Otherwise drops both tables and guards.
"""
from alembic import op

revision = "0106"
down_revision = "0105"
branch_labels = None
depends_on = None

#: The least-privilege runtime role, spelled as 0060's `APP_ROLE` spells it.
APP_ROLE = "noctornal_app"

#: Guarded against deletion without being append-only: the table and the
#: privileges the runtime role KEEPS on it (test_app_role_privileges_pg).
GUARDED_TABLES = {
    "collect.telegram_chat": ("SELECT", "INSERT", "UPDATE"),
    "collect.telegram_message": ("SELECT", "INSERT", "UPDATE"),
}

#: The typed forms, as telegram.py spells them (test_telegram_ids holds
#: these equal to the module's patterns).
CHAT_PATTERN = r"^[cg]:[1-9][0-9]{0,19}$"
CHANNEL_PATTERN = r"^c:[1-9][0-9]{0,19}$"
UID_PATTERN = r"^u:[1-9][0-9]{0,19}$"
PEER_PATTERN = r"^[ucg]:[1-9][0-9]{0,19}$"
SERVICE_ACTION_PATTERN = r"^[A-Za-z]{1,64}$"


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(f"""
CREATE TABLE collect.telegram_chat (
  source_id              uuid PRIMARY KEY REFERENCES collect.source(id),
  peer_type              text NOT NULL,
  peer_id                bigint NOT NULL,
  durable_id             text NOT NULL,
  access_mode            text NOT NULL,
  provenance_class       text NOT NULL,
  username_at_resolve    text,
  title_at_resolve       text,
  resolved_at            timestamptz NOT NULL DEFAULT now(),
  resolved_by            uuid NOT NULL REFERENCES iam.app_user(id),
  access_hash            bigint,
  access_hash_account_id uuid REFERENCES collect.collection_account(id),
  member_since_observed  timestamptz,
  joined_by              uuid REFERENCES iam.app_user(id),
  joined_at              timestamptz,
  is_forum               boolean NOT NULL DEFAULT false,
  noforwards             boolean NOT NULL DEFAULT false,
  migrated_to            text,
  CONSTRAINT telegram_chat_peer_known
    CHECK (peer_type IN ('CHANNEL', 'MEGAGROUP', 'GIGAGROUP', 'CHAT')),
  CONSTRAINT telegram_chat_peer_positive CHECK (peer_id > 0),
  CONSTRAINT telegram_chat_durable_typed
    CHECK (durable_id = CASE WHEN peer_type = 'CHAT' THEN 'g:' ELSE 'c:' END
                        || peer_id::text),
  CONSTRAINT telegram_chat_access_known
    CHECK (access_mode IN ('PUBLIC_READ', 'MEMBER')),
  CONSTRAINT telegram_chat_provenance_follows_access
    CHECK ((access_mode = 'PUBLIC_READ' AND provenance_class = 'OPEN_GROUP')
           OR (access_mode = 'MEMBER' AND provenance_class = 'PERSONA_PARTY')),
  CONSTRAINT telegram_chat_basic_groups_are_never_public
    CHECK (peer_type <> 'CHAT' OR access_mode = 'MEMBER'),
  CONSTRAINT telegram_chat_member_reads_as_member
    CHECK (member_since_observed IS NULL OR access_mode = 'MEMBER'),
  CONSTRAINT telegram_chat_hash_has_owner
    CHECK ((access_hash IS NULL) = (access_hash_account_id IS NULL)),
  CONSTRAINT telegram_chat_join_complete
    CHECK ((joined_by IS NULL) = (joined_at IS NULL)
           AND (joined_at IS NULL OR member_since_observed IS NOT NULL)),
  CONSTRAINT telegram_chat_migrated_typed
    CHECK (migrated_to IS NULL OR migrated_to ~ '{CHANNEL_PATTERN}'),
  CONSTRAINT telegram_chat_names_capped
    CHECK (coalesce(length(username_at_resolve), 0) <= 32
           AND coalesce(length(title_at_resolve), 0) <= 256),
  CONSTRAINT telegram_chat_one_source UNIQUE (durable_id)
);

COMMENT ON TABLE collect.telegram_chat IS
  'Which Telegram chat a source is, and how it is read. The identity is fixed and the row is never deleted, so a confirmed authority target never silently changes chat.';
COMMENT ON COLUMN collect.telegram_chat.member_since_observed IS
  'When Telegram last reported the reading persona a member. Only a member chat carries it; cleared when the persona is seen to have left.';

CREATE FUNCTION collect.guard_telegram_chat() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION USING MESSAGE =
      'a Telegram chat source is never deleted: stop reading it';
  END IF;
  IF NEW.source_id IS DISTINCT FROM OLD.source_id
     OR NEW.peer_type IS DISTINCT FROM OLD.peer_type
     OR NEW.peer_id IS DISTINCT FROM OLD.peer_id
     OR NEW.durable_id IS DISTINCT FROM OLD.durable_id
     OR NEW.username_at_resolve IS DISTINCT FROM OLD.username_at_resolve
     OR NEW.title_at_resolve IS DISTINCT FROM OLD.title_at_resolve
     OR NEW.resolved_at IS DISTINCT FROM OLD.resolved_at
     OR NEW.resolved_by IS DISTINCT FROM OLD.resolved_by
     OR (OLD.migrated_to IS NOT NULL
         AND NEW.migrated_to IS DISTINCT FROM OLD.migrated_to) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a chat source''s identity is fixed: add the new chat as a new source, so a confirmed authority target never silently changes chat';
  END IF;
  IF (NEW.access_mode IS DISTINCT FROM OLD.access_mode
      OR NEW.provenance_class IS DISTINCT FROM OLD.provenance_class)
     AND NOT (OLD.access_mode = 'PUBLIC_READ' AND OLD.provenance_class = 'OPEN_GROUP'
              AND NEW.access_mode = 'MEMBER'
              AND NEW.provenance_class = 'PERSONA_PARTY') THEN
    RAISE EXCEPTION USING MESSAGE =
      'a chat read in public can become a member chat, and never back';
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER telegram_chat_identity_guarded
  BEFORE UPDATE OR DELETE ON collect.telegram_chat
  FOR EACH ROW EXECUTE FUNCTION collect.guard_telegram_chat();
CREATE TRIGGER telegram_chat_no_truncate
  BEFORE TRUNCATE ON collect.telegram_chat
  FOR EACH STATEMENT EXECUTE FUNCTION collect.guard_telegram_chat();

CREATE TABLE collect.telegram_message (
  document_id             uuid PRIMARY KEY
                          REFERENCES collect.document(id) ON DELETE RESTRICT,
  source_id               uuid NOT NULL REFERENCES collect.source(id),
  chat_durable_id         text NOT NULL,
  message_id              bigint NOT NULL,
  seen_via_uid            text NOT NULL,
  sender_uid              text,
  sender_handle_at_capture text,
  post_author             text,
  fwd_from_uid            text,
  fwd_from_name           text,
  fwd_from_message_id     bigint,
  reply_to_message_id     bigint,
  topic_id                bigint,
  grouped_id              bigint,
  via_bot_uid             text,
  is_service              boolean NOT NULL DEFAULT false,
  service_action          text,
  is_self                 boolean NOT NULL DEFAULT false,
  media_kind              text,
  noforwards              boolean NOT NULL DEFAULT false,
  edit_date               timestamptz,
  views_at_capture        integer,
  forwards_at_capture     integer,
  deleted_seen_at         timestamptz,
  captured_at             timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT telegram_message_chat_typed CHECK (chat_durable_id ~ '{CHAT_PATTERN}'),
  CONSTRAINT telegram_message_id_positive CHECK (message_id > 0),
  CONSTRAINT telegram_message_via_typed CHECK (seen_via_uid ~ '{UID_PATTERN}'),
  CONSTRAINT telegram_message_sender_typed
    CHECK (sender_uid IS NULL OR sender_uid ~ '{PEER_PATTERN}'),
  CONSTRAINT telegram_message_fwd_typed
    CHECK (fwd_from_uid IS NULL OR fwd_from_uid ~ '{PEER_PATTERN}'),
  CONSTRAINT telegram_message_bot_typed
    CHECK (via_bot_uid IS NULL OR via_bot_uid ~ '{UID_PATTERN}'),
  CONSTRAINT telegram_message_service_named
    CHECK (is_service = (service_action IS NOT NULL)),
  CONSTRAINT telegram_message_service_action_is_a_class_name
    CHECK (service_action IS NULL OR service_action ~ '{SERVICE_ACTION_PATTERN}'),
  CONSTRAINT telegram_message_media_known
    CHECK (media_kind IS NULL OR media_kind ~ '^[a-z_]{{1,32}}$'),
  CONSTRAINT telegram_message_names_capped
    CHECK (coalesce(length(sender_handle_at_capture), 0) <= 256
           AND coalesce(length(post_author), 0) <= 256
           AND coalesce(length(fwd_from_name), 0) <= 256)
);
CREATE INDEX telegram_message_source_msg_idx
  ON collect.telegram_message (source_id, message_id DESC);
CREATE INDEX telegram_message_recheck_idx
  ON collect.telegram_message (source_id, captured_at DESC)
  WHERE deleted_seen_at IS NULL AND NOT is_service;
CREATE INDEX telegram_message_sender_idx
  ON collect.telegram_message (sender_uid) WHERE sender_uid IS NOT NULL;
CREATE INDEX telegram_message_fwd_idx
  ON collect.telegram_message (fwd_from_uid) WHERE fwd_from_uid IS NOT NULL;

COMMENT ON TABLE collect.telegram_message IS
  'The capture record of one stored Telegram message. It has no label of its own and is read only joined to its document, whose classification, compartments and source''s classification gate it. Media is never downloaded by this adapter (docs/16 L1).';
COMMENT ON COLUMN collect.telegram_message.service_action IS
  'The TL action''s class name for a service message (who joined or left is in the document body), never an id.';

CREATE FUNCTION collect.guard_telegram_message() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION USING MESSAGE =
      'a Telegram message''s capture record is never deleted';
  END IF;
  IF (NEW.document_id, NEW.source_id, NEW.chat_durable_id, NEW.message_id,
      NEW.seen_via_uid, NEW.fwd_from_message_id, NEW.reply_to_message_id,
      NEW.topic_id, NEW.grouped_id, NEW.is_service, NEW.service_action,
      NEW.is_self, NEW.media_kind, NEW.noforwards, NEW.edit_date,
      NEW.views_at_capture, NEW.forwards_at_capture, NEW.captured_at)
     IS DISTINCT FROM
     (OLD.document_id, OLD.source_id, OLD.chat_durable_id, OLD.message_id,
      OLD.seen_via_uid, OLD.fwd_from_message_id, OLD.reply_to_message_id,
      OLD.topic_id, OLD.grouped_id, OLD.is_service, OLD.service_action,
      OLD.is_self, OLD.media_kind, OLD.noforwards, OLD.edit_date,
      OLD.views_at_capture, OLD.forwards_at_capture, OLD.captured_at)
     OR (OLD.deleted_seen_at IS NOT NULL
         AND NEW.deleted_seen_at IS DISTINCT FROM OLD.deleted_seen_at) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a Telegram message''s capture record is fixed; only the purge clears its identifiers';
  END IF;
  IF (NEW.sender_uid, NEW.sender_handle_at_capture, NEW.post_author,
      NEW.fwd_from_uid, NEW.fwd_from_name, NEW.via_bot_uid)
     IS DISTINCT FROM
     (OLD.sender_uid, OLD.sender_handle_at_capture, OLD.post_author,
      OLD.fwd_from_uid, OLD.fwd_from_name, OLD.via_bot_uid) THEN
    IF NOT EXISTS (SELECT 1 FROM collect.document d
                    WHERE d.id = NEW.document_id AND d.purged_at IS NOT NULL)
       OR NEW.sender_uid IS NOT NULL OR NEW.sender_handle_at_capture IS NOT NULL
       OR NEW.post_author IS NOT NULL OR NEW.fwd_from_uid IS NOT NULL
       OR NEW.fwd_from_name IS NOT NULL OR NEW.via_bot_uid IS NOT NULL THEN
      RAISE EXCEPTION USING MESSAGE =
        'a Telegram message''s capture record is fixed; only the purge clears its identifiers';
    END IF;
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER telegram_message_guarded
  BEFORE UPDATE OR DELETE ON collect.telegram_message
  FOR EACH ROW EXECUTE FUNCTION collect.guard_telegram_message();
CREATE TRIGGER telegram_message_no_truncate
  BEFORE TRUNCATE ON collect.telegram_message
  FOR EACH STATEMENT EXECUTE FUNCTION collect.guard_telegram_message();
""")

    # After the CREATE TABLEs, never before: the DELETE being taken back is
    # the one 0060's default privileges handed out at creation. A no-op
    # where the role does not exist, for the reason 0060 gives.
    run(f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON collect.telegram_chat FROM %I', '{APP_ROLE}');
    EXECUTE format('REVOKE DELETE ON collect.telegram_message FROM %I', '{APP_ROLE}');
  END IF;
END
$noc$;
""")


def downgrade() -> None:
    run("""
DO $pre$
DECLARE
  n bigint;
BEGIN
  IF to_regclass('collect.telegram_chat') IS NOT NULL THEN
    SELECT count(*) INTO n FROM collect.telegram_chat;
    -- A capture record without its chat row is still a record: counted
    -- as one source, so the sentence stays true.
    IF n = 0 AND EXISTS (SELECT 1 FROM collect.telegram_message) THEN
      n := 1;
    END IF;
    IF n > 0 THEN
      RAISE EXCEPTION USING MESSAGE =
        'refusing to downgrade 0106: ' || n
        || CASE WHEN n = 1 THEN ' Telegram source records' ELSE ' Telegram sources record' END
        || ' which chat '
        || CASE WHEN n = 1 THEN 'it is' ELSE 'they are' END
        || ', and dropping the table loses the only record of it';
    END IF;
  END IF;
END
$pre$;

DROP TABLE IF EXISTS collect.telegram_message;
DROP FUNCTION IF EXISTS collect.guard_telegram_message();
DROP TABLE IF EXISTS collect.telegram_chat;
DROP FUNCTION IF EXISTS collect.guard_telegram_chat();
""")

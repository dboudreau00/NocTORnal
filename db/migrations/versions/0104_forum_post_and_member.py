"""What a forum post or member carries beside its text (F3 and F4,
the forum adapters, 2026-09-24).

## Why

The collector stores a post's quote-stripped, signature-stripped text as a
`collect.document`; everything else a forum shows about it was thrown away.
docs/04 names two of those things as intelligence: the signature (the same
contact address repeated on every post an author writes: one fact about
the author, never 4,000 observations) and the reactions (cheap, informative
edges). A quote's source is a third: which post a post answers.

- `collect.forum_post`: one row per post document version. The signature
  text (at most 4,000 characters), the posts it quotes ('post:<id>', at most
  50) and its reactions (a JSON object of at most 8 KiB: a count, up to 50
  reactor names, up to 10 reaction kinds).
- `collect.forum_member`: one row per member profile document version
  (category FORUM_MEMBER): the profile's labelled fields and the member's
  title, a JSON object of at most 16 KiB.

## Labels

Neither table carries a label of its own. Each row hangs off one document
version (the primary key IS the document id, ON DELETE CASCADE), and is
read only joined to it, under the document's label, its source's label and
its compartments, as the documents themselves are read
(forum_adapters.forum_details). A member row follows its document's
versions, so a profile's history is its documents' history.

## Retention

The retention purge empties a document and deletes its forum_post or
forum_member row in the same transaction (retention.DOCUMENT_PURGE_SCRUBS),
because a signature, reactor names and profile fields are the author's
personal data. A document under legal hold, or cited by a case under hold,
is not purged, and neither is its row (docs/00 decision 74).

## Downgrade

Refuses while either table holds a row, and names the counts: these rows
are collected intelligence, some of it under legal hold, and a schema
rollback does not destroy it. With both empty it drops them.
"""
from alembic import op

revision = "0104"
down_revision = "0103"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE TABLE collect.forum_post (
  document_id uuid PRIMARY KEY
    REFERENCES collect.document(id) ON DELETE CASCADE,
  signature_text text,
  quoted_post_refs text[] NOT NULL DEFAULT '{}',
  reactions jsonb NOT NULL DEFAULT '{}'::jsonb,
  observed_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT forum_post_signature_capped
    CHECK (signature_text IS NULL OR char_length(signature_text) <= 4000),
  CONSTRAINT forum_post_quotes_capped
    CHECK (cardinality(quoted_post_refs) <= 50
           AND array_position(quoted_post_refs, NULL) IS NULL),
  CONSTRAINT forum_post_reactions_object
    CHECK (jsonb_typeof(reactions) = 'object'
           AND octet_length(reactions::text) <= 8192)
);

COMMENT ON TABLE collect.forum_post IS
  'What a collected forum post carries beside its text: its signature, the posts it quotes and its reactions. No label of its own: read only joined to its document, under the document''s and the source''s labels and compartments. Deleted by the retention purge with its document''s text.';
COMMENT ON COLUMN collect.forum_post.signature_text IS
  'The signature printed under the post: repeated on every post its author writes, so it describes the author and is not an observation per post.';
COMMENT ON COLUMN collect.forum_post.quoted_post_refs IS
  'The posts this post quotes, typed post:<id>. The quoted text itself is never stored as this post''s.';
COMMENT ON COLUMN collect.forum_post.reactions IS
  'A count, up to 50 reactor names as the forum shows them, and up to 10 reaction kinds.';
COMMENT ON COLUMN collect.forum_post.observed_at IS
  'When the side row was last written: a signature or reactions that changed without the text refresh it.';

CREATE TABLE collect.forum_member (
  document_id uuid PRIMARY KEY
    REFERENCES collect.document(id) ON DELETE CASCADE,
  profile jsonb NOT NULL DEFAULT '{}'::jsonb,
  observed_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT forum_member_profile_object
    CHECK (jsonb_typeof(profile) = 'object'
           AND octet_length(profile::text) <= 16384)
);

COMMENT ON TABLE collect.forum_member IS
  'A collected forum member profile''s fields (title, joined, contact and custom fields, counters), one row per member document version (category FORUM_MEMBER). No label of its own: read only joined to its document. Deleted by the retention purge with its document''s text.';
""")


def downgrade() -> None:
    run("""
DO $pre$
DECLARE
  posts bigint;
  members bigint;
BEGIN
  SELECT count(*) INTO posts FROM collect.forum_post;
  SELECT count(*) INTO members FROM collect.forum_member;
  IF posts > 0 OR members > 0 THEN
    RAISE EXCEPTION USING MESSAGE =
      'refusing to downgrade 0104: ' || posts
      || CASE WHEN posts = 1 THEN ' forum post row and ' ELSE ' forum post rows and ' END
      || members
      || CASE WHEN members = 1 THEN ' forum member row hold' ELSE ' forum member rows hold' END
      || ' collected intelligence, some of it possibly under legal hold, and '
      || 'a schema rollback does not destroy it';
  END IF;
END
$pre$;

DROP TABLE IF EXISTS collect.forum_member;
DROP TABLE IF EXISTS collect.forum_post;
""")

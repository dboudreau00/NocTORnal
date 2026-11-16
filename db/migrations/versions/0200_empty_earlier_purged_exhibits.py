"""Empty the exhibits that were purged before a purge emptied them (independent review of Beta 1.6, AREA-03,
2026-11-15).

## Why

A purge deleted an exhibit's bytes and marked the row `purged_at`, and left the row's description, source
address, extracted text and the full-text vector built from them, so a later reader of the register read
them from an exhibit the product reports destroyed, and the search found it by words only its body held.
The purge now empties those four in the transaction that marks the row (the update in
`RetentionService.purge_due` and `purge_out_of_schedule`), and keeps the title with the hashes, the size,
the media type and the storage key as the tombstone's name for the exhibit. That change reaches only the
exhibits a purge destroys from now on. This revision does the same, once, to every exhibit destroyed
before it.

## What it does

For every `core.evidence` row with `purged_at` set, in two statements:

1. `description`, `source_url` and `extracted_text` to NULL.
2. `search_tsv` to NULL.

They are two statements because `evidence_tsv_update` (BEFORE INSERT OR UPDATE) rebuilds the vector from
the title, the description and the text whenever one of the three changes, so a NULL set in the first
statement would be overwritten with a title-only vector. In the second statement none of the three
changes, the trigger leaves the vector alone, and the NULL stays. A row that says nothing but still holds
a vector (a bare exhibit's title) is reached by the second statement alone, and a row that is already
empty matches neither, so a second run changes nothing and writes nothing.

## What it keeps

The title, the hashes, the size, the media type, the storage key and version, `purged_at` and every other
column of the row, and every row that is not purged: the statements name `purged_at IS NOT NULL` and a
live exhibit is not selected. What was made from an exhibit (a parsed e-mail, a contact block) is the
case's analysis and is not touched (docs/17, "A purged exhibit keeps its title").

## The guards on core.evidence, and why none is passed

None is disabled and none refuses these two statements; the revision's tests update real rows with all of
them in place.

- `evidence_anchors_fixed` refuses a change to the hashes, the size, the case or the stored object: none
  is written.
- `evidence_hold_purge_exclusive` fires on a change of `purged_at` or `legal_hold` only: neither moves.
- `evidence_hold_lift_guarded` fires on the hold's columns only.
- `evidence_tlp` returns at once for an update that moves neither the classification nor the case.
- `compartments_registered` fires on `compartments` only.
- `evidence_vectors_follow` (AFTER) deletes the exhibit's similarity vectors and queue entry when the
  description or the text changes. A purge already deleted them (it fires on `purged_at`), so for an
  exhibit purged normally it finds nothing; for one whose purge was recorded another way it removes what
  was derived from the content it is emptying, which is the point.
- `evidence_tsv_update` is the order above.

## Run as the schema owner

Alembic connects as the owner, and row-level security is enabled on the table and not forced, so the owner
sees every row. `SET LOCAL row_security = off` makes that a stated condition: a role that policies would
filter gets an error from the first statement and not a silent run over the rows it happens to see (the
setting's documented purpose, for a job where limited visibility could give a wrong answer). It ends with
the revision's transaction. The revision then counts the purged rows that still carry any of the four and
refuses to finish, rolling the whole revision back, if the count is not zero; the message holds the count
and no value.

## What it records

One SYSTEM audit event, `PURGED_EXHIBITS_EMPTIED`, when it changed anything, with the number of exhibits
and no value, and the same count on the console of the migration job (a plain print, as 0137). An empty
database, or one with nothing to do, writes neither.

## Downgrade

Nothing, deliberately. What was emptied is kept nowhere to be put back, and being able to restore what a
purge destroyed would defeat it: a purged exhibit's content is gone and must not be restorable by running
a downgrade. The way back, for an operator who wants it, is a backup taken before 0200 (`db/README.md`).
Upgrading again changes nothing.
"""
from alembic import op
from psycopg.types.json import Json

revision = "0200"
down_revision = "0199"
branch_labels = None
depends_on = None

#: The `by` of the summary event.
BY = "the upgrade that emptied exhibits purged before a purge emptied them"

#: A purged row that still says something, in any of the four places it can.
SAYS_SOMETHING = """purged_at IS NOT NULL
                   AND (description IS NOT NULL OR source_url IS NOT NULL
                        OR extracted_text IS NOT NULL OR search_tsv IS NOT NULL)"""

#: Frozen text. The two statements are separate on purpose, see the docstring.
EMPTY_THE_WORDS = """
UPDATE core.evidence
   SET description = NULL, source_url = NULL, extracted_text = NULL
 WHERE purged_at IS NOT NULL
   AND (description IS NOT NULL OR source_url IS NOT NULL OR extracted_text IS NOT NULL)
RETURNING id
"""

EMPTY_THE_VECTOR = """
UPDATE core.evidence
   SET search_tsv = NULL
 WHERE purged_at IS NOT NULL AND search_tsv IS NOT NULL
RETURNING id
"""


def empty(conn) -> int:
    """Empty every purged exhibit; returns how many rows changed. Idempotent: a second run finds no row
    that says anything and changes none."""
    with conn.transaction():
        conn.execute("SET LOCAL row_security = off")
        words = {r[0] for r in conn.execute(EMPTY_THE_WORDS).fetchall()}
        vector = {r[0] for r in conn.execute(EMPTY_THE_VECTOR).fetchall()}
        left = conn.execute(
            f"SELECT count(*) FROM core.evidence WHERE {SAYS_SOMETHING}").fetchone()[0]
        if left:
            raise RuntimeError(
                f"refusing to finish 0200: {left} purged exhibits still carry content after the "
                f"update, so nothing was changed")
        changed = len(words | vector)
        if changed:
            conn.execute(
                """INSERT INTO audit.event
                       (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
                   VALUES (NULL, 'SYSTEM', 'PURGED_EXHIBITS_EMPTIED', 'deployment', NULL, NULL, %s)""",
                (Json({"exhibits": changed, "by": BY}),))
    return changed


def upgrade() -> None:
    changed = empty(op.get_bind().connection.driver_connection)
    if changed:
        # A plain print, as 0137: said out loud, with a count and no value.
        print(f"[0200] purged exhibits emptied of what they said: {changed}")


def downgrade() -> None:
    # Deliberately a no-op, see the docstring: the content is kept nowhere and must not be restorable.
    pass

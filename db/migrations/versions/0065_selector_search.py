"""Entities findable by the selectors attributed to them, and by fragments.

## What the review found (ux09-search, 2026-09-22)

Pasting ember_hobby's own wallet or Jabber id into Search answered "No
matches." (selectors-unsearchable). The node search vector is label plus
attrs (0016) and selectors live in `core.selector`, which no search query
joined. The same review found whole-token matching missing harrow_skua2
for "skua", every vps-*.hostmarket.example host for "hostmarket" and the
exhibit remittance-change.eml for "remittance" (whole-token-false-negatives):
the 'simple' parser keeps a host or a file name as ONE lexeme, so only the
whole string matched.

## Why a join and not a wider tsvector

Folding selector values into `core.node.search_tsv` would need a trigger
on `core.selector` rewriting the owning node's vector on every observation,
and it would lose the one thing the analyst needs next to the hit: WHICH
selector matched. `SearchService` joins `core.selector` instead, gated by
the owning node's visibility exactly as `GET /selectors` and
`GET /nodes/{id}/selectors` gate it, and reports the matching selector as
the hit's `via`.

## What this migration adds

Fragment matching is `ILIKE '%fragment%'`, which a trigram GIN index
serves. Four columns are searched that way. Two already had one from
0005 (`core.node.label`, `core.selector.norm_value`); this adds the
other two:

- `core.selector.raw_value`: the value as observed. A normaliser can
  rewrite the form an analyst copies from a chat log or a chain trace (a
  phone number's punctuation, a Gmail address's dots), so a fragment of
  what was observed has to match as well as a fragment of the canonical
  form.
- `core.evidence.title`: an exhibit title is usually a file name, which
  the parser keeps whole.

Both statements are guarded (IF NOT EXISTS / IF EXISTS) because every
database the review pass touched was stamped 0065 by a no-op stub first:
the first downgrade from that stamp runs THIS downgrade against indexes
that were never built, and must not fail on it.

`victim_credential` is deliberately not touched: decision 52 keeps that
table with no tsvector and no trigram index, and a test reads
`pg_indexes` to hold it there.
"""
from __future__ import annotations

from alembic import op

revision = "0065"
down_revision = "0064"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE INDEX IF NOT EXISTS selector_raw_value_trgm_idx
    ON core.selector USING gin (raw_value public.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS evidence_title_trgm_idx
    ON core.evidence USING gin (title public.gin_trgm_ops);
""")


def downgrade() -> None:
    run("""
DROP INDEX IF EXISTS core.evidence_title_trgm_idx;
DROP INDEX IF EXISTS core.selector_raw_value_trgm_idx;
""")

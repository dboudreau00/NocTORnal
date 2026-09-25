"""Drop `collect.document.embedding` (F6.1, embeddings, 2026-09-24).

0011 gave every collected document a vector(768) column with an HNSW
index, and nothing ever wrote it: the only statement that named it was
the retention purge, setting it to NULL. Vectors now live in
`collect.document_embedding` (0092), one row per similarity space, with
the labels a reader is checked against. A single column could hold one
space only and could not carry the source's label for partitioning, so it
goes, with its index. No data is lost: every value it ever held was NULL.

`retention.py` stops naming the column in the same change: a purge that
still assigned `embedding = NULL` would abort the whole purge
transaction, evidence and records included, once this runs.
`core.node.embedding` is left as it is (entities are not embedded).

## Downgrade

Adds the column back, empty, with 0011's index. The retention code of
this revision no longer names it, which is harmless on the old schema.
"""
from __future__ import annotations

from alembic import op

revision = "0094"
down_revision = "0093"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("ALTER TABLE collect.document DROP COLUMN embedding;")


def downgrade() -> None:
    run("""
ALTER TABLE collect.document ADD COLUMN embedding vector(768);
CREATE INDEX document_embedding_idx ON collect.document
  USING hnsw (embedding vector_cosine_ops);
""")

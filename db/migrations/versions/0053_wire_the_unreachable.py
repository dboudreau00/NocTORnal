"""Two missing verbs and one missing accountability column, so that four
built-but-unreachable subsystems can ship.

A code-level audit on 2026-07-26 checked CALL SITES rather than existence
and found several subsystems that are fully built, tested, green — and
that no user can reach:

- `TagService` and `NodeSetService` (`curation.py`, schema 0009, five green
  tests) have no router, no endpoint and no UI. The only callers in the
  repo are their own tests.
- `graph.node.update`, `graph.node.delete` and `graph.edge.update` were
  seeded as permissions in 0017 and granted in 0021 — and nothing has ever
  checked them, because `GraphWriteService` had no update or delete at all.
  A mistyped node label was permanent.
- `case.update`, `case.close` and `case.grant` are likewise seeded, granted
  and unchecked: `cases.py` has the service methods, no router exposed
  them.
- `audit.read` is granted to SECURITY_OFFICER and had zero call sites.
  Nothing in the product ever read `audit.event`, and nothing ever
  re-computed its hash chain — so Phase 0's "verifiable audit chain" was
  written and never verifiable.

**Very little is needed here.** That is the finding: the verbs mostly
existed already and nothing called them.

## 1. `core.edge.deleted_by`

`core.node` (0005) has `deleted_at` AND `deleted_by`. `core.edge` (0006)
has only `deleted_at`. So a soft-deleted node records who did it and a
soft-deleted edge does not — "who removed this tie?" was unanswerable, on
the half of the graph where a removal changes the analysis most (dropping
an edge can dissolve a broker).

Nullable, no backfill: rows deleted before this migration genuinely have
no recorded actor and inventing one would be worse than leaving it NULL.

## 2. `graph.edge.delete`

0017 seeded `graph.node.delete` with no edge counterpart, so retiring an
edge had no verb to check even in principle.

## 3. `curation.manage`

One verb covering tags and node sets together. They are the same act: an
analyst's organisational overlay on a case, carrying no assertion and no
evidential weight. Splitting them would imply a difference in consequence
that does not exist.

Granted to CASE_OWNER and ANALYST only. Deliberately NOT to CONTRIBUTOR or
READ_ONLY: a tag renders next to the entity and a misleading one
("CONFIRMED LAUNDERER") reads with the authority of the case file while
resting on nobody's assertion.

## Why `deleted_at` and not `valid_to`

Both columns exist on both tables and they mean different things. This one
took a wrong turn before it took the right one, so it is worth writing
down:

- `valid_to` is TEMPORAL VALIDITY — when the thing stopped being true in
  the world. An account closed in March has `valid_to = March`, and an
  as-of query into February must still show it live.
- `deleted_at` is SOFT DELETION — we removed it from the case, because it
  was wrong, or a duplicate, or should never have been recorded.

Retiring an element by setting `valid_to` would silently rewrite history:
an as-of query into last week would stop showing something that WAS in the
case last week. `deleted_at` is what every read path in `projections.py`
already filters on, and both tables already carry partial indexes
`WHERE deleted_at IS NULL`, so the mechanism was fully built — it simply
had no writer.

Nothing here destroys a row. The permission keeps the key
`graph.node.delete` because 0017 named it that and renaming a seeded
permission would break any deployment that has granted it; its description
said "Soft-delete nodes" from the start, which is exactly what this is.
"""
from alembic import op

revision = "0053"
down_revision = "0052"
branch_labels = None
depends_on = None

NEW_PERMISSIONS = [
    ("graph.edge.delete", "Soft-delete edges (sets deleted_at; never destroys)"),
    ("curation.manage", "Create and assign tags and node sets"),
]

#: Both go to the two roles that already hold the rest of the graph-write
#: verbs. Nothing here reaches SYS_ADMIN or SECURITY_OFFICER: 0021's
#: separation of duties keeps case-content permissions away from both.
NEW_GRANTS = [
    ("CASE_OWNER", "graph.edge.delete"),
    ("CASE_OWNER", "curation.manage"),
    ("ANALYST", "graph.edge.delete"),
    ("ANALYST", "curation.manage"),
]


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    perms = ",\n".join(
        f"('{key}','{desc}', false, false)" for key, desc in NEW_PERMISSIONS)
    grants = ",\n".join(f"('{role}','{perm}')" for role, perm in NEW_GRANTS)
    run(f"""
SET search_path = iam, core, public;

ALTER TABLE core.edge ADD COLUMN IF NOT EXISTS deleted_by uuid;

INSERT INTO permission (key, description, requires_step_up, requires_dual_control)
VALUES
{perms}
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permission (role_key, permission_key) VALUES
{grants}
ON CONFLICT (role_key, permission_key) DO NOTHING;
""")


def downgrade() -> None:
    # Grants first: role_permission references permission.
    keys = ",".join(f"'{k}'" for k, _ in NEW_PERMISSIONS)
    run(f"""
SET search_path = iam, core, public;
DELETE FROM role_permission WHERE permission_key IN ({keys});
DELETE FROM permission WHERE key IN ({keys});
ALTER TABLE core.edge DROP COLUMN IF EXISTS deleted_by;
""")

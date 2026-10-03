"""A sample can be a member of an archive sample (roadmap phase 8
"archive expansion", 2026-10-02).

## What this adds

- `lab.sample.parent_sample_id`, the archive this sample was cut from,
  and `lab.sample.archive_path`, its path inside that archive as the
  expansion child normalised it (forward slashes, no `.` or `..`
  components, printable). Both set or both null
  (`sample_member_names_its_path`), a member never names itself, and the
  path is bounded and holds no slash at either end.
- One index on the parent link, which the tree reads walk.
- `lab.guard_member_labels`, a BEFORE INSERT OR UPDATE trigger that
  refuses a member labelled below its parent: a member's classification
  is at least the parent's and its compartments hold the parent's. An
  accepted element is never labelled below the material it came from.
  The function reads `lab.sample`, which is under a policy (0121), so it
  is SECURITY DEFINER with its search path pinned (0113's rule): as the
  writer it would see only the writer's view of the parent, and a parent
  above the writer would read as absent and the guard would fail open.

Row-level security: both columns live on `lab.sample`, which keeps its
CUSTOM_SAMPLE policy (0121, rls_registry.py); no table is added. A member
is read at its own labels composed with its case's like every sample, and
because its labels are never below its parent's, nobody sees a member
without seeing the archive it came from.

## Downgrade

Drops the trigger, the function, the index, the constraints and the two
columns. A member row then stands as a sample with no parent, which is
what it is; nothing is deleted.
"""
from __future__ import annotations

from alembic import op

revision = "0158"
down_revision = "0157"
branch_labels = None
depends_on = None

#: The longest member path recorded (lab_archive_child.MAX_PATH_CHARS).
MAX_PATH_CHARS = 512

UPGRADE_SQL = f"""
SET search_path = lab, core, public;

ALTER TABLE sample
  ADD COLUMN parent_sample_id uuid REFERENCES lab.sample(id),
  ADD COLUMN archive_path text,
  ADD CONSTRAINT sample_member_names_its_path
    CHECK ((parent_sample_id IS NULL) = (archive_path IS NULL)),
  ADD CONSTRAINT sample_member_is_not_its_own_parent
    CHECK (parent_sample_id IS NULL OR parent_sample_id <> id),
  ADD CONSTRAINT sample_archive_path_shape
    CHECK (archive_path IS NULL
           OR (length(archive_path) BETWEEN 1 AND {MAX_PATH_CHARS}
               AND archive_path NOT LIKE '/%'
               AND archive_path NOT LIKE '%/'
               AND position(E'\\\\' IN archive_path) = 0));

COMMENT ON COLUMN sample.parent_sample_id IS
  'The archive sample this one was expanded from (phase 8, 2026-10-02). '
  'A member carries its parent''s case and labels, never below them.';
COMMENT ON COLUMN sample.archive_path IS
  'The member''s path inside its parent archive, as the expansion child '
  'normalised it. Never used as a filesystem path.';

CREATE INDEX sample_parent_idx ON sample (parent_sample_id)
  WHERE parent_sample_id IS NOT NULL;

-- A member is never labelled below the archive it came from. Reads
-- lab.sample, a policied table, so it runs as the definer with its
-- search path pinned (0113).
CREATE FUNCTION lab.guard_member_labels() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, lab, core, pg_temp AS $$
DECLARE
  parent_tlp core.tlp;
  parent_comps text[];
BEGIN
  IF NEW.parent_sample_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT classification, compartments INTO parent_tlp, parent_comps
    FROM lab.sample WHERE id = NEW.parent_sample_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'sample %: its parent archive % does not exist',
      NEW.id, NEW.parent_sample_id;
  END IF;
  IF NEW.classification < parent_tlp THEN
    RAISE EXCEPTION 'sample %: a member is never labelled below its archive '
      '(member %, archive %)', NEW.id, NEW.classification, parent_tlp;
  END IF;
  IF NOT (parent_comps <@ NEW.compartments) THEN
    RAISE EXCEPTION 'sample %: a member carries every compartment of its '
      'archive', NEW.id;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER sample_member_never_below_its_archive
  BEFORE INSERT OR UPDATE OF parent_sample_id, classification, compartments
  ON sample FOR EACH ROW EXECUTE FUNCTION lab.guard_member_labels();
"""

DOWNGRADE_SQL = """
SET search_path = lab, core, public;
DROP TRIGGER sample_member_never_below_its_archive ON sample;
DROP FUNCTION lab.guard_member_labels();
DROP INDEX sample_parent_idx;
ALTER TABLE sample
  DROP CONSTRAINT sample_archive_path_shape,
  DROP CONSTRAINT sample_member_is_not_its_own_parent,
  DROP CONSTRAINT sample_member_names_its_path,
  DROP COLUMN archive_path,
  DROP COLUMN parent_sample_id;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)

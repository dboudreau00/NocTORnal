"""Permissions for the governance surfaces that are about to get routers.

Phases 4, 6 and 9 have had services and tests since 2026-07-25 and no HTTP
interface at all, so nothing has ever needed a permission to reach them.
Wiring the routers without these would mean gating them on something
adjacent -- `evidence.purge` for retention, `audit.read` for a break-glass
review -- and a permission that means two things is a permission that
cannot be revoked for one of them.

## The three that are step-up, and why

`retention.purge` DESTROYS data on a schedule. `retention.manage` sets the
schedule, which is the same power one remove away, and a confirmed
retention rule is what makes a purge run without a warning. Both re-prompt.

`break_glass.review` is the control that makes break-glass acceptable at
all -- docs/05 wants emergency access "available, loud and short", and the
loudness IS the mandatory review. It is step-up because a review recorded
by a session somebody walked away from is exactly the failure the review
exists to catch.

## `break_glass.review` goes to SECURITY_OFFICER only

The role already holds `audit.read` and `victim_pii.authorise` and
deliberately holds no case access. `BreakGlassService.invoke` refuses to
grant when no active user holds it, and `review()` refuses a reviewer who
is the invoker -- the same two-distinct-humans rule as four-eyes approval.
Granting the review permission to anyone else would let a team review its
own emergencies, which is the one thing the separation is for.

`retention.read` is deliberately broad: an analyst who cannot see when
their case's material expires cannot plan around it, and the failure mode
of hiding it is that somebody discovers a deadline by missing it.
"""
from alembic import op

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None

_NEW_PERMISSIONS = [
    ("retention.read", False,
     "See retention rules, deadlines and purge tombstones"),
    ("retention.manage", True,
     "Confirm a retention rule or set a legal hold"),
    ("retention.purge", True,
     "Run a purge, or purge out of schedule under a stated authority"),
    ("break_glass.review", True,
     "Record the mandatory post-hoc review of a break-glass grant"),
    ("collection.run", False,
     "Poll a collection source and record the run"),
    ("collection.read", False,
     "See collection sources, runs and their health"),
]

_ROLE_GRANTS = [
    # Reading a deadline is not a privilege; missing one is a problem.
    ("CASE_OWNER", "retention.read"), ("ANALYST", "retention.read"),
    ("REVIEWER", "retention.read"), ("CONTRIBUTOR", "retention.read"),
    ("READ_ONLY", "retention.read"), ("LIAISON", "retention.read"),
    ("COLLECTOR", "retention.read"),
    # Setting the schedule and running the destruction are not.
    ("CASE_OWNER", "retention.manage"), ("CASE_OWNER", "retention.purge"),
    ("SYS_ADMIN", "retention.manage"), ("SYS_ADMIN", "retention.purge"),
    # The review is the security officer's, and only theirs.
    ("SECURITY_OFFICER", "break_glass.review"),
    # `break_glass.invoke` was seeded by 0032 and granted to NO ROLE, so
    # the whole feature was unreachable: the permission existed, the
    # service enforced its controls, and nothing could call it. Found by
    # the first e2e test that tried.
    #
    # Which roles get emergency access is genuinely an operator decision
    # (docs/17 F14) -- this is the narrowest defensible default, not a
    # recommendation. SYS_ADMIN because operational emergencies are theirs,
    # CASE_OWNER because the commonest real case is the owner locked out
    # of their own case at 3am. Deliberately NOT ANALYST: docs/05 wants
    # break-glass available, and "available to everyone" is a different
    # property from "available".
    ("SYS_ADMIN", "break_glass.invoke"),
    ("CASE_OWNER", "break_glass.invoke"),
    # Collection.
    ("COLLECTOR", "collection.run"), ("COLLECTOR", "collection.read"),
    ("CASE_OWNER", "collection.read"), ("ANALYST", "collection.read"),
    ("REVIEWER", "collection.read"),
]


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    perms = ",\n".join(
        f"('{k}', {str(s).lower()}, '{d}')" for k, s, d in _NEW_PERMISSIONS)
    grants = ",\n".join(f"('{r}', '{p}')" for r, p in _ROLE_GRANTS)
    run(f"""
SET search_path = iam, core, public;
INSERT INTO permission (key, requires_step_up, description) VALUES
{perms}
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permission (role_key, permission_key) VALUES
{grants}
ON CONFLICT (role_key, permission_key) DO NOTHING;
""")


def downgrade() -> None:
    keys = ",".join(f"'{k}'" for k, _, _ in _NEW_PERMISSIONS)
    run(f"""
DELETE FROM iam.role_permission WHERE permission_key IN ({keys});
DELETE FROM iam.permission WHERE key IN ({keys});
-- The break-glass grants this migration ADDED to an existing permission,
-- named explicitly so the downgrade removes what it created and leaves
-- anything an operator granted afterwards alone.
DELETE FROM iam.role_permission
 WHERE permission_key = 'break_glass.invoke'
   AND role_key IN ('SYS_ADMIN', 'CASE_OWNER');
""")

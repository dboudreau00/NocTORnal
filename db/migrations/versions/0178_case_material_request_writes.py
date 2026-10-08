"""The request role writes only what a request writes on exhibits and
cases, and deletes no case material it never deletes (hold and purge
columns, and soft-delete tables, Beta 1.1, 2026-10-08).

## Why

0060 handed `noctornal_app` UPDATE and DELETE on every table. On
`core.evidence` and `core."case"` that reached the columns a destruction
turns on: one statement injected as that role, on a row its policy lets it
reach, could set an exhibit's `legal_hold` false, its `purged_at`,
`retention_until` or `is_worm_locked`, and a case's `legal_hold`. 0142
refuses a row both held and destroyed and 0140 fixes an exhibit's hashes,
storage, version and case; nothing stopped a hold going to false. And the
role held DELETE on the case tables whose rows the product never deletes,
only marks: an entity, a tie, an exhibit, a case, a sample, a proposal, a
conversation. The class of F52: a process holding the request role's
credentials could do what the application refrains from.

## What the request role keeps

Every write a request makes on these tables (every UPDATE and DELETE of
them in apps/api/src, by the connection it runs on):

- `core.evidence`: UPDATE of `storage_version_id` only, which an upload
  stamps once, in its own transaction (0140 holds it to once, from NULL).
  A legal hold, its lift and a purge run on the RETENTION system
  connection and a lock extension on EVIDENCE_LOCKS, so `legal_hold`,
  `legal_hold_reason`, `purged_at`, `retention_until` and `is_worm_locked`
  are the system role's alone.
- `core."case"`: UPDATE of the columns the case routes write as the request
  role: the governance record (`title`, `summary`, `authority_ref`,
  `review_due`, `retention_until`, `classification`,
  `CaseService.update_metadata`), the lifecycle (`status`, `closed_at`,
  `transition_status`) and the two policy switches
  (`dual_control_merge`, `withheld_disclosure`; 0076's trigger moves the
  epoch with the first). A case's `legal_hold` and `legal_hold_reason` are
  written on RETENTION, its `compartments` on COMPARTMENTS: the system
  role's alone.
- DELETE on a policied table (`rls_registry.POLICY`, every table that
  carries a case or a label) only where a request deletes:
  `core.hypothesis_evidence` (an ACH stance cleared),
  `core.node_set_member` and `core.tag_assignment` (curation), and
  `notify.case_route_block` (a case owner's Jira veto lifted). Every other
  policied table loses DELETE: what is removed from them (a purge, a
  retention sweep, an embedding pass) runs on a system connection. A
  foreign key's cascade runs as the table's owner, so a delete the request
  role still makes is unchanged.

Table-level UPDATE comes off the request role on the two tables and the
column grants above go on: a `SELECT ... FOR UPDATE` needs UPDATE on one
column, which each keeps.

## What remains

A request that reaches SQL can still change a case's retention date and
its governance text without the route's CASE_UPDATED row, on a case its
policy lets it update: those are columns the route writes as the request
role. Nothing it can write destroys material: a purge takes
`retention.manage`, a second factor and a person, on a system connection.

## The system role

`noctornal_worker` keeps table UPDATE on both tables (`SYSTEM_KEEPS_UPDATE`)
and DELETE everywhere it had it: the purge, a hold, a lock extension and a
compartment rename are its writes. `test_worker_role_privileges_pg.py`
reads both constants.

`GRANTS_SQL` is repeatable and `scripts/runtime_roles.py ensure` replays
it after 0108's blanket grant, which hands UPDATE and DELETE back. A
policied table a LATER revision creates inherits DELETE from 0060's
default privileges; its own revision decides whether a request deletes
from it.

## No-op without the role; downgrade

Guarded on `pg_roles` as 0060 and 0155 are. The downgrade takes the column
grants back and gives table UPDATE and DELETE again, as 0060 left them.
"""
from alembic import op

revision = "0178"
down_revision = "0177"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

#: Every column a request writes on these tables, and so all the request
#: role may UPDATE there. `test_app_role_privileges_pg.py` reads it, with
#: 0109's and 0155's constants of the same name.
RUNTIME_COLUMN_UPDATES: dict[str, tuple[str, ...]] = {
    "core.evidence": ("storage_version_id",),
    "core.case": ("title", "summary", "authority_ref", "review_due",
                  "retention_until", "classification", "status", "closed_at",
                  "dual_control_merge", "withheld_disclosure"),
}

#: Where the system role keeps table-level UPDATE.
SYSTEM_KEEPS_UPDATE: tuple[str, ...] = ("core.evidence", "core.case")

#: The policied tables a request deletes from. Every other table under row
#: security holds no DELETE for the request role after this revision;
#: `test_case_material_writes_pg.py` asks the catalog.
REQUEST_DELETES: tuple[str, ...] = ("core.hypothesis_evidence", "core.node_set_member",
                                    "core.tag_assignment", "notify.case_route_block")

#: The policied tables the request role held DELETE on when this revision
#: was written, but for REQUEST_DELETES: what it revokes, and what the
#: downgrade gives back. The others had lost it to their own revisions
#: (the ledgers to 0060, the claims to 0135, the lookups, the Lab's YARA and
#: screening records, the persona act queue and the rest to theirs).
NO_LONGER_DELETED: tuple[str, ...] = (
    "analytics.community_assignment", "analytics.layout_position",
    "analytics.metric_run", "analytics.node_metric", "analytics.projection",
    "collect.document", "collect.document_embedding", "collect.extraction",
    "collect.forum_member", "collect.forum_post", "collect.proposal",
    "collect.watch", "collect.watch_hit",
    "comms.channel_binding", "comms.contact_block", "comms.contact_block_entry",
    "comms.conversation", "comms.device_fingerprint", "comms.message",
    "comms.participant", "comms.service_selector",
    "core.approval_request", "core.assertion_embedding", "core.assumption",
    'core."case"', "core.edge", "core.evidence", "core.evidence_embedding",
    "core.evidence_link", "core.hypothesis", "core.node", "core.node_merge",
    "core.node_merge_edge", "core.node_set", "core.selector", "core.tag",
    "deception.call_record", "deception.capture", "deception.capture_hop",
    "deception.email_attachment", "deception.email_hop", "deception.email_message",
    "ingest.dead_letter", "ingest.pii_authorisation", "ingest.record",
    "ingest.victim_credential",
    "lab.sample", "lab.sample_analysis", "lab.static_run",
    "notify.delivery", "notify.notification",
)

_TABLE_SQL = {"core.evidence": "core.evidence", "core.case": 'core."case"'}


def _columns(verb: str, preposition: str) -> str:
    return "\n".join(
        f"    EXECUTE format('{verb} UPDATE ({', '.join(cols)}) ON "
        f"{_TABLE_SQL[table]} {preposition} %I', app);"
        for table, cols in RUNTIME_COLUMN_UPDATES.items())


def _whole(verb: str, preposition: str) -> str:
    return "\n".join(
        f"    EXECUTE format('{verb} UPDATE ON {_TABLE_SQL[table]} {preposition} %I', app);"
        for table in RUNTIME_COLUMN_UPDATES)


def _deletes(verb: str, preposition: str) -> str:
    return "\n".join(
        f"    EXECUTE format('{verb} DELETE ON {table} {preposition} %I', app);"
        for table in NO_LONGER_DELETED)


def _block(body: str) -> str:
    return f"""
DO $noc$
DECLARE
  app text := '{APP_ROLE}';
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
{body}
  END IF;
END
$noc$;
"""


#: Repeatable: `scripts/runtime_roles.py ensure` replays it.
GRANTS_SQL = _block("\n".join((_whole("REVOKE", "FROM"), _columns("GRANT", "TO"),
                               _deletes("REVOKE", "FROM"))))

DOWNGRADE_SQL = _block("\n".join((_columns("REVOKE", "FROM"), _whole("GRANT", "TO"),
                                  _deletes("GRANT", "TO"))))


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(GRANTS_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)

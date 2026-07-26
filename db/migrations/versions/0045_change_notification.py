"""LISTEN/NOTIFY so the console can be told a case changed.

Phase 2's last named gap. The sociogram has never updated when somebody
else wrote to the case — there is no timer in `app.js` at all, so two
analysts on one case each see the graph as it was when they opened it.

## Why Postgres and not Redis

Redis is already in the stack and would work. Postgres wins on one
property that matters more than convenience: **`pg_notify` inside a
trigger is part of the writing transaction.** A notification only reaches
a listener if the write it describes committed. Publishing to Redis from
application code after a commit means a crash between the two silently
drops the event, and publishing before means a rolled-back write announces
itself — a sociogram that redraws to show an element that does not exist.

## The payload carries NO case content

Deliberately, and it is the whole reason this design is safe:

    {"case_id": "...", "kind": "node", "op": "INSERT"}

An id, a table name and an operation. The client's response is to refetch
through the ordinary gated REST endpoints, which already apply the
five-part access check and the label filter. So the socket is a *hint to
refetch*, never a data channel, and the WebSocket layer never has to
re-implement label filtering — which is the thing this codebase has got
wrong in five separate places (docs/17 F19) and would certainly get wrong
a sixth time in a new layer.

`case_id` is not itself content: a subscriber has already passed the gate
for that case before any event for it is delivered, and no other case's
events reach them.

## Statement-level, not row-level

A bulk write of four hundred edges should wake a client once, not four
hundred times. `FOR EACH STATEMENT` gives that for free, and the client is
refetching the whole projection anyway.

The cost is that `case_id` is not available at statement level, so it is
taken from a transition table. `REFERENCING NEW TABLE` needs Postgres 10+;
this project targets 16.
"""
from alembic import op

revision = "0045"
down_revision = "0044"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


CHANNEL = "noctornal_change"


def upgrade() -> None:
    # One function for every table. `TG_ARGV[0]` names the kind so the
    # client can decide what to refetch: a notification does not need the
    # projection recomputed, and recomputing it is the expensive half.
    run(f"""
        CREATE OR REPLACE FUNCTION core.announce_change() RETURNS trigger AS $$
        DECLARE
          affected uuid;
        BEGIN
          -- DELETE has no NEW TABLE, and an INSERT has no OLD TABLE, so
          -- each branch reads the one that exists. A statement that
          -- touched nothing announces nothing.
          IF TG_OP = 'DELETE' THEN
            SELECT case_id INTO affected FROM oldrows LIMIT 1;
          ELSE
            SELECT case_id INTO affected FROM newrows LIMIT 1;
          END IF;
          IF affected IS NULL THEN
            RETURN NULL;
          END IF;
          PERFORM pg_notify(
            '{CHANNEL}',
            json_build_object('case_id', affected,
                              'kind', TG_ARGV[0],
                              'op', TG_OP)::text);
          RETURN NULL;
        END $$ LANGUAGE plpgsql;
    """)

    for table, kind in (("core.node", "node"), ("core.edge", "edge")):
        name = kind
        run(f"""
            CREATE TRIGGER {name}_announce_ins
            AFTER INSERT ON {table}
            REFERENCING NEW TABLE AS newrows
            FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('{kind}')
        """)
        run(f"""
            CREATE TRIGGER {name}_announce_upd
            AFTER UPDATE ON {table}
            REFERENCING NEW TABLE AS newrows
            FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('{kind}')
        """)
        run(f"""
            CREATE TRIGGER {name}_announce_del
            AFTER DELETE ON {table}
            REFERENCING OLD TABLE AS oldrows
            FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('{kind}')
        """)

    # Notifications carry a nullable case_id, and one with none is an
    # oversight alert to a security officer (break-glass). Those still wake
    # the badge, so the function above cannot be reused verbatim — it bails
    # on a NULL case.
    run(f"""
        CREATE OR REPLACE FUNCTION notify.announce_notification()
        RETURNS trigger AS $$
        DECLARE
          who uuid;
        BEGIN
          SELECT recipient_id INTO who FROM newrows LIMIT 1;
          IF who IS NULL THEN
            RETURN NULL;
          END IF;
          -- The RECIPIENT, not the case: a client subscribes to its own
          -- badge regardless of which case the notification belongs to,
          -- and the read filter decides whether it may actually see it.
          PERFORM pg_notify(
            '{CHANNEL}',
            json_build_object('recipient_id', who,
                              'kind', 'notification',
                              'op', TG_OP)::text);
          RETURN NULL;
        END $$ LANGUAGE plpgsql;
    """)
    run("""
        CREATE TRIGGER notification_announce
        AFTER INSERT ON notify.notification
        REFERENCING NEW TABLE AS newrows
        FOR EACH STATEMENT EXECUTE FUNCTION notify.announce_notification()
    """)


def downgrade() -> None:
    for kind in ("node", "edge"):
        table = f"core.{kind}"
        for suffix in ("ins", "upd", "del"):
            run(f"DROP TRIGGER IF EXISTS {kind}_announce_{suffix} ON {table}")
    run("DROP TRIGGER IF EXISTS notification_announce ON notify.notification")
    run("DROP FUNCTION IF EXISTS notify.announce_notification()")
    run("DROP FUNCTION IF EXISTS core.announce_change()")

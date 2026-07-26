"""Repair the durable values 0036 did not reach.

Migration 0036 fixed Tox, Matrix and Telegram. An adversarial review then
found the same class of defect on five more platforms, each producing a
different flavour of wrong answer:

**Discord and ICQ -- an empty string that collides with everything.**
`DISCORD_ID` and `ICQ` normalise with `digits`, which keeps digits only.
Discord dropped the `#0000` discriminator in 2023, so a current handle
contains no digits at all and normalises to `''`. That is not "no value"
to a database: `correlate()` short-circuits on None and NOT on `''`, so a
query for `durable_value = ''` returned EVERY Discord binding whose handle
had no digits -- an unbounded set of unrelated actors reported as one
person.

**Signal and Wire -- promoting exactly what the platform seed says is not
durable.** Both use `lower_trim`, which is right for a UUID and wrong for
anything else. `comms.platform` says plainly that the Signal ACI is
durable and the phone number is not, and that the Wire account UUID is
durable and the handle is not -- and the normaliser promoted the displayed
form anyway. One phone number yielded three different durable values
depending on spacing: a false split and a false merge at once. Numbers are
recycled by carriers exactly as Telegram usernames are, which is the
failure this system refuses for Telegram and was performing here.

**Wickr -- absent from the map entirely**, so it fell through to a raw
passthrough that preserved case. `VendorX` and `vendorx` were two people.

## Why this backfill is Python and 0036's was SQL

0036 reimplemented three rules in SQL and they were diffed against the
Python normaliser over 17 probes before being trusted. Five rules across
five platforms -- two of them Unicode-sensitive -- is past the point where
that is the safer option: `digits` uses `\\D`, which is Unicode-aware in
Python and not reliably so in Postgres, and a divergence here recreates
the exact bug being repaired.

So the rules are written LITERALLY in this file, in Python, and applied
row by row. That is as frozen as SQL would be -- a migration must not
import application code, because a later refactor would silently change
what an already-applied migration did -- while being far easier to get
right.

Recomputed from `observed_value`, which is stored verbatim precisely so
that what the actor published survives our processing of it. Idempotent.
"""
import re
from uuid import UUID

from alembic import op

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None

#: Frozen copy of `noctornal_ontology.normalisers._NON_DIGIT` as of
#: 2026-07-25. Unicode-aware, matching the live normaliser exactly.
_NON_DIGIT = re.compile(r"\D+")


def _digits(value: str) -> str | None:
    cleaned = _NON_DIGIT.sub("", value)
    return cleaned or None


def _uuid_only(value: str) -> str | None:
    """A durable value ONLY when it really is the UUID the platform says
    is durable. A phone number or an @handle is not one."""
    cleaned = (value or "").strip()
    try:
        UUID(cleaned)
    except (ValueError, AttributeError, TypeError):
        return None
    return cleaned.lower()


def _case_folded(value: str) -> str | None:
    cleaned = (value or "").strip().lower()
    return cleaned or None


#: platform_key -> the rule, frozen as of this migration.
_RULES = {
    "DISCORD": _digits,
    "ICQ": _digits,
    "SIGNAL": _uuid_only,
    "WIRE": _uuid_only,
    "WICKR": _case_folded,
}


def upgrade() -> None:
    conn = op.get_bind().connection.driver_connection
    changed: dict[str, int] = {}
    for platform_key, rule in _RULES.items():
        rows = conn.execute(
            "SELECT id, observed_value, durable_value "
            "  FROM comms.channel_binding WHERE platform_key = %s",
            (platform_key,)).fetchall()
        for binding_id, observed, durable in rows:
            recomputed = rule(observed or "")
            if recomputed == durable:
                continue
            conn.execute(
                "UPDATE comms.channel_binding SET durable_value = %s "
                " WHERE id = %s", (recomputed, binding_id))
            changed[platform_key] = changed.get(platform_key, 0) + 1

    if changed:
        # Said out loud. A repair that changes attribution and reports
        # nothing is how an analyst finds a different answer next week
        # with no reason for it in any log.
        summary = ", ".join(f"{k}={v}" for k, v in sorted(changed.items()))
        # A plain print, NOT a RAISE NOTICE with a bind parameter.
        #
        # `%s` inside a dollar-quoted DO body is not a placeholder psycopg
        # can bind -- it rewrites parameters server-side, the statement
        # then takes none, and Postgres raises IndeterminateDatatype. That
        # aborted the transaction and rolled back every UPDATE above.
        #
        # The failure was invisible on a clean database, because the whole
        # block is guarded by `if changed:` and there was nothing to
        # change. It would have fired on exactly the deployments that hold
        # the rows this migration exists to repair.
        print(f"[0038] renormalised durable values: {summary} "
              f"(correlation results for these platforms may change)")


def downgrade() -> None:
    # Deliberately a no-op, for the reason 0036 gives. The old forms were
    # WRONG -- an empty durable value collided with every other one -- so
    # re-applying them would reintroduce a false-merge defect on the way
    # down, and the change is lossy in reverse anyway: a row that now
    # holds NULL had an empty string before, and there is no record of
    # which rows those were.
    pass

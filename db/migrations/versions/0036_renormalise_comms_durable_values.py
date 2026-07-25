"""Repair durable values written by the normalisers 0034 shipped.

`comms.normalise` hand-rolled canonical forms that `noctornal_ontology`
already owned, and the two drifted. `selectors.py` states the rule this
broke -- the ontology is "the ONE source of truth for canonical form" --
and the code fix is to delegate. This migration repairs the rows written
before it, because a fixed normaliser and stale rows is worse than either
alone: new observations stop matching old ones, and the graph shows two
actors.

Three divergences, in descending order of how much damage they do:

**Matrix -- a merge nobody performed.** `comms` lowercased the WHOLE MXID.
The ontology folds only the server part, because an MXID localpart is
case-sensitive: `@Alice:example.org` and `@alice:example.org` can be two
accounts on a historical homeserver. Folding gave them one durable value,
so `correlate()` returned them as the same actor -- confident false
attribution produced by the module written to prevent it. Repaired by
recomputing from `observed_value`, which is stored verbatim precisely so
that what the actor published survives our processing of it.

**Tox -- a match that silently stops matching.** `comms` lowercased;
the ontology uppercases. Self-consistent inside comms, so nothing broke
until something joined a binding to `core.selector` -- which is entity
resolution, i.e. the product. The join would have returned nothing and
read as "no correlation", which is the failure mode docs/10 spends a page
warning about.

**Telegram -- a refusal with a wrong reason.** A numeric supergroup or
channel id (`-100…`) was rejected as though it were a username, with an
error saying so. Recomputed here: the Bot-API `-100` prefix is stripped so
the MTProto form of one channel matches, and a bare minus survives so a
chat id never collides with a user id.

`comms.device_fingerprint` is NOT touched, and that is a finding rather
than an omission: it stripped whitespace and lowercased, which is exactly
`lower_hex_nospace`. It agreed by luck, not by construction, and the code
fix makes it agree by construction.

The three UPDATEs are recomputations from `observed_value` and are
idempotent, so a re-run is harmless. They are the only destructive-looking
statements in this file and they touch a DERIVED column: `observed_value`,
the evidence of what was published, is never written.
"""
from alembic import op

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
DO $$
DECLARE
  tox_rows int; mx_rows int; tg_rows int;
BEGIN
  -- Tox: the durable value is the 64-hex public key, uppercase.
  UPDATE comms.channel_binding
     SET durable_value = upper(durable_value)
   WHERE platform_key = 'TOX'
     AND durable_value IS NOT NULL
     AND durable_value <> upper(durable_value);
  GET DIAGNOSTICS tox_rows = ROW_COUNT;

  -- Matrix: recomputed from what was observed. The localpart keeps its
  -- case; everything from the first colon on is the server and folds.
  -- (An MXID localpart cannot contain a colon, so the first one is always
  -- the separator; a ':8448' port lives in the server part and folds with
  -- it, which is correct.)
  UPDATE comms.channel_binding
     SET durable_value = CASE
           WHEN btrim(observed_value) ~ '^@[^:]+:.+$' THEN
             substring(btrim(observed_value)
                       from 1 for position(':' in btrim(observed_value)) - 1)
             || ':' ||
             lower(substring(btrim(observed_value)
                             from position(':' in btrim(observed_value)) + 1))
           -- A Matrix display name is not durable. 0034 stored it as one.
           ELSE NULL END
   WHERE platform_key = 'MATRIX'
     AND durable_value IS DISTINCT FROM CASE
           WHEN btrim(observed_value) ~ '^@[^:]+:.+$' THEN
             substring(btrim(observed_value)
                       from 1 for position(':' in btrim(observed_value)) - 1)
             || ':' ||
             lower(substring(btrim(observed_value)
                             from position(':' in btrim(observed_value)) + 1))
           ELSE NULL END;
  GET DIAGNOSTICS mx_rows = ROW_COUNT;

  -- Telegram: numeric ids, including the negative ones 0034 refused.
  UPDATE comms.channel_binding
     SET durable_value = CASE
           -- Bot-API supergroup/channel: strip '-100' so the MTProto form
           -- of the same channel collapses onto it.
           WHEN btrim(observed_value) ~ '^-100[0-9]+$'
             THEN substring(btrim(observed_value) from 5)
           -- Basic-group chat id: the minus SURVIVES, or a chat id and an
           -- unrelated user id share a value.
           WHEN btrim(observed_value) ~ '^-[0-9]+$' THEN btrim(observed_value)
           WHEN btrim(observed_value) ~ '^[0-9]+$'  THEN btrim(observed_value)
           -- A @username is still not durable. This is the one case 0034
           -- got right.
           ELSE NULL END
   WHERE platform_key = 'TELEGRAM'
     AND durable_value IS DISTINCT FROM CASE
           WHEN btrim(observed_value) ~ '^-100[0-9]+$'
             THEN substring(btrim(observed_value) from 5)
           WHEN btrim(observed_value) ~ '^-[0-9]+$' THEN btrim(observed_value)
           WHEN btrim(observed_value) ~ '^[0-9]+$'  THEN btrim(observed_value)
           ELSE NULL END;
  GET DIAGNOSTICS tg_rows = ROW_COUNT;

  -- Said out loud. A repair that changes attribution and reports nothing
  -- is how an analyst finds a different answer next week with no reason
  -- for it in any log.
  IF tox_rows + mx_rows + tg_rows > 0 THEN
    RAISE NOTICE 'renormalised durable values: tox=% matrix=% telegram=% '
                 '(correlation results for these platforms may change)',
                 tox_rows, mx_rows, tg_rows;
  END IF;
END $$;
""")


def downgrade() -> None:
    # Deliberately a no-op, and not out of laziness. The old forms were
    # WRONG -- the Matrix one merged distinct accounts -- so re-applying
    # them would reintroduce a false-attribution defect on the way down.
    # The new values are also lossy in reverse: a Telegram id 0034 refused
    # now has a value, and there is no record of which rows those were.
    # Downgrading past this migration leaves correct data behind, which is
    # the right direction for the one that cannot be undone.
    pass

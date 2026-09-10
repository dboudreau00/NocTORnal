"""A one-shot ticket for the Lab download, so the console stops carrying a
session credential to the sample origin.

## Why the console carried one

Invariant 10 puts sample bytes on a SECOND origin, and the session cookie
pair is `__Host-` prefixed: `Secure`, `Path=/`, no `Domain`,
`SameSite=strict`. None of that reaches another host, and that is the
POINT of the split rather than a limitation of it. So `downloadSample()`
sent the token the login response handed the page, as `Authorization:
Bearer`, with `credentials: 'omit'` -- the session credential itself,
held in page memory, posted to a second origin, on the one path in this
system that puts working malware on somebody's disk.

That was not a defect in the console; it was the only credential the
console had for that origin. It was also one of the two reasons the login
response returned a token in its body at all, which was a standing
invitation for any script that got a foothold in the page to read it.
This ticket is what made deleting that token possible: minted on the
APPLICATION origin under the cookie session (so the `x-csrf-token`
double-submit applies, which is the one thing an injected script on
another origin cannot forge), it is good for ONE sample, ONE redemption
and sixty seconds, and it confers no standing authority of any kind.
Stealing one buys the archive the analyst was already downloading;
stealing the session token buys the case file.

Written the same day as its two other halves and landing with them, so
the past tense above is not a prediction: the console stopped sending a
Bearer to the sample origin (`downloadSample`), the websocket started
reading `__Host-session` off the upgrade (the other path that needed a
readable token), and `POST /auth/login` now answers 204 with the cookie
pair and no body. That order was load-bearing -- deleting the body token
first would have taken every Lab download with it.

## Only the hash is stored, for `ingest.api_key`'s reason

`ingest.api_key` keeps `secret_hmac` and never the secret, so a read of
the table -- a backup, a replica, a support dump, a SELECT by anyone with
the connection string -- yields nothing that can be presented. The same
argument applies here and is if anything sharper: this row names a user,
a sample and a live authorisation to download it.

The hash is a plain SHA-256 rather than that table's peppered HMAC, and
the difference is deliberate. `ingest.api_key`'s pepper exists so a
stolen table cannot be attacked offline; the ticket is 256 bits from
`secrets.token_urlsafe(32)`, which has no candidate list to attack, and
it stops being useful sixty seconds after it is minted. Against that,
peppering costs a MANDATORY new secret in the environment -- and
`ingest._pepper()` is explicit that reusing one secret for a second
purpose is how rotating it silently breaks the other -- so a peppered
ticket would mean every existing deployment's downloads failing closed on
an unset variable. `iam.session.token_hash` makes the same trade for the
same reason, in `security/tokens.hash_token`, and that credential is
worth far more than this one.

## Not append-only, and that is the whole design

`redeemed_at` is written by the redemption, and the redemption is an
`UPDATE ... WHERE redeemed_at IS NULL ... RETURNING`: one statement, so
two simultaneous presentations of the same ticket cannot both find it
unredeemed. A row here is EXHAUSTED STATE, not a record of what happened
-- `lab.sample_access` is the custody record for a download and stays
append-only by trigger, and the audit chain carries the issue, the
redemption and every refusal that names a real ticket. Making this table
append-only too would mean the one-shot property had nowhere to live.

The qualifier is load-bearing. A presented string matching NO row is
counted in a sampled log line and never written to `audit.event`,
because that refusal needs no credential of any kind: an unauthenticated
caller could otherwise append to an append-only, hash-chained,
advisory-locked table at will, one `ticket=x` at a time, and nothing
could remove what they wrote. The `sample.download` rate limit bounds how
many strings one source may present at all.

That also settles what 0060 warns about. Its `ALTER DEFAULT PRIVILEGES`
hands `noctornal_app` SELECT/INSERT/UPDATE/DELETE on every table a later
migration creates, and 0060's docstring says a future append-only ledger
must revoke UPDATE and DELETE from itself because it will inherit them
silently. This is not that table: the runtime role NEEDS the UPDATE, so
nothing is revoked and the inheritance is correct rather than overlooked.

## The indexes, and the one that is deliberately absent

The redemption looks the ticket up by `token_hash`, and there is no
separate index for it: `UNIQUE` already builds one, and a second btree on
the same column would be a write cost with no reader. The uniqueness is
not itself a control -- a SHA-256 collision is not the threat -- it is
there so a repeated INSERT of one hash is impossible by construction.

`download_ticket_live_idx` is the sweep's index, in the shape
`api_key_live_idx` uses: unredeemed rows by expiry. Nothing sweeps them
today. Said plainly rather than left to be discovered: a redeemed or
expired ticket is inert (both halves of the redemption predicate exclude
it) but it is a row that names a user and a sample, so it belongs in a
retention pass, and this is the index that pass will want.

## `session_id` carries no foreign key, and is the ONE thing not re-read

It records WHICH session asked for the ticket, so the audit chain can put
the issue, the redemption and the sign-in together. It is not a foreign
key because sessions are deleted -- by logout, by revocation, by any
future sweep -- and a ticket's record of which session asked must not
disappear with them, nor block their deletion.

A minted ticket is not an authority on its own, so the redemption
re-derives what the mint decided rather than trusting the row. Precisely,
on the sample origin, before a byte moves:

- the ticket is live, unspent, and issued for THIS sample -- one atomic
  `UPDATE ... RETURNING` (below);
- the holder's ACCOUNT is still active and still holds `sample.download`
  through a global role -- `SampleService._still_authorised`, which calls
  the same `holds_global_permission` read `deps.require_global` is built
  on. Until 2026-09-10 this was missing, so an account deactivated inside
  the window, or one whose download permission had just been revoked,
  still received the archive;
- the SAMPLE's labels compose against that holder's LIVE clearance and
  compartments -- `user_ceiling` then `_downloadable`, the same predicate
  the mint ran.

What is NOT re-derived is the session in `session_id`: whether it still
exists, has been revoked or has expired, and whether it would satisfy
step-up freshness now. The residual is therefore narrow and exact -- **a
ticket minted under a session that is revoked in the following sixty
seconds can still be redeemed, by a holder whose ACCOUNT is still active
and still permitted, for a sample they may still read.** Nothing wider
than that survives.

The session is the one left because it is the one this origin cannot
answer: deciding session validity here would be a THIRD copy of a check
`http/deps.py` keeps in exactly two places (the HTTP path and the
websocket) and says so about, on the process the split exists to keep
sessions away from. The account, by contrast, is one join from the row
the caller just presented, and its check was already written.

`ip_hash` is the minting address, hashed the way `routers/auth.py` hashes
one for the sign-in audit. It is recorded, never compared: the mint and
the redemption are two requests to two different hosts, and a dual-stack
client can reach one over IPv6 and the other over IPv4 from the same
browser in the same second. Binding on it would refuse legitimate
downloads intermittently, which is the failure mode nobody debugs.
"""
from alembic import op

revision = "0061"
down_revision = "0060"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = lab, core, public;

CREATE TABLE download_ticket (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- SHA-256 of the ticket. The ticket itself is returned to the caller
  -- once and is never written anywhere -- not here, not in the audit
  -- detail, and not in a URL (a query parameter reaches the access log,
  -- the Referer and the history, and this one is a credential).
  token_hash   bytea NOT NULL UNIQUE,
  -- The authority is over ONE sample. The redemption matches on this as
  -- well as on the hash, so a ticket minted for a sample the caller may
  -- read cannot be presented on the path of one they may not -- and a
  -- presentation against the wrong sample matches no row, so it does not
  -- burn the ticket either.
  sample_id    uuid NOT NULL REFERENCES sample(id),
  user_id      uuid NOT NULL REFERENCES iam.app_user(id),
  -- Correlation only: no FK, and the one part of the mint the redemption
  -- does not re-derive. The account and the labels are. See the docstring.
  session_id   uuid,
  issued_at    timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  -- NULL means live. Written by the redemption's single atomic UPDATE,
  -- which is what makes the ticket one-shot.
  redeemed_at  timestamptz,
  ip_hash      bytea,

  -- A ticket that expires at or before it was issued is not a short
  -- ticket, it is an unusable one, and the mistake that produces it is a
  -- unit confusion (60 vs 60000) that would otherwise ship as "downloads
  -- stopped working".
  CONSTRAINT download_ticket_expiry_after_issue CHECK (expires_at > issued_at)
);

-- The redemption's lookup is served by the UNIQUE index on token_hash.
-- These two have other readers: the audit trail for one sample, and the
-- retention sweep the docstring describes.
CREATE INDEX download_ticket_sample_idx ON download_ticket (sample_id, issued_at DESC);
CREATE INDEX download_ticket_live_idx ON download_ticket (expires_at)
  WHERE redeemed_at IS NULL;

COMMENT ON TABLE download_ticket IS
  'One-shot, sixty-second authority to download ONE sample from the '
  'sample origin, minted on the application origin under a cookie '
  'session. Exhausted state, not a ledger: lab.sample_access is the '
  'custody record and audit.event carries the issue and the redemption.';
""")


def downgrade() -> None:
    run("DROP TABLE lab.download_ticket;")

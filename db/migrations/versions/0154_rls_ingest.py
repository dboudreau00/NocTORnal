"""Row-level security on the ingest records, the victims' credentials, the
dead letters and the reveal authorisations (F51, 2026-10-02).

## What this enforces, and for whom

`noctornal_app`, bound per request (0111), now sees and writes:

- `ingest.record` (CUSTOM_RECORD): a record ATTACHED to a case where the
  case is readable and the record's own labels are within the user's
  ceiling for that case (the ELEMENT test); a QUARANTINED record (no case)
  where the user holds `ingest.manage` globally, through an initplan, and
  the record's labels are within their case-less ceiling. That is the
  queue's own rule (`routers/ingest._authorise_record`): a case reader
  reads their case's records, the operator reads quarantine, and nobody
  reads a record above them. A SELECT and an UPDATE policy: the request
  role attaches a quarantined record to a case and corrects a category,
  and inserts and deletes no record. With no INSERT policy an INSERT is
  refused before any key or constraint is compared, so no request learns
  from a duplicate primary key or a dangling `duplicate_of` that a record
  it may not read exists. The policy says which rows; 0155 says which
  columns (the two verbs' five) and which values (a case set once, from
  quarantine; an expiry never brought forward).
- `ingest.victim_credential` (CHILD of the record): read where its record
  is visible, and updated there (the reveal counts itself on the row). A
  SELECT and an UPDATE policy: credentials are stored and destroyed only
  on system connections (the seeding script, the retention purge), so an
  injected statement can neither plant a credential under a visible record
  nor delete one. 0155 leaves that UPDATE the reveal's two counters, and
  only as a reveal writes them.
- `ingest.dead_letter` (CUSTOM_DEAD_LETTER): READ ONLY, through 0153's one
  definer predicate, `iam.ingest_dead_letter_visible`, with its compartments
  held: visible through a case its batch fed, at that case's ceiling, or,
  for a batch that fed no case, to a holder of `ingest.manage` at their
  case-less ceiling. That is the dead-letter listing's rule without the
  verb. Every write (the parse, the replay, the redaction script, the
  purge) runs on a system connection.
- `ingest.pii_authorisation` (CUSTOM_PII_AUTHORISATION): read in a case
  the user may read (the CASE template), which is where the Lead
  investigator's reveal looks for their live authorisation; granted
  (INSERT) only by its grantor, in a case they may read, holding
  `victim_pii.authorise` globally, which is the GLOBAL half of the route's
  gate (its other half, the same permission on the case, read off the
  caller's one role there, is not asked at the database: see below), and
  dated at the moment it is made (`granted_at = now()`, as the route's
  INSERT leaves it), so the 30-day CHECK bounds the window from then;
  counted (UPDATE) only by its grantee, on a live authorisation. No
  DELETE. This policy says which rows the count may touch, not which
  columns: until 0155 (the verification of 2026-10-02) the grantee could
  move the window, whose CHECK is counted from a `granted_at` they could
  move too, re-attribute it and retarget its case. 0155 leaves the request
  role `query_count` alone, raised by one, and the system role no other
  column either. With both, an injected statement cannot forge an
  authorisation in somebody else's name, raise one for a Lead
  investigator without holding `victim_pii.authorise` globally, date one
  into the future, or revive, extend, re-attribute or retarget one: the
  officer who grants and the grantee who reveals stay two people, and the
  window stays the one that was granted, at the database too.

  What this does NOT hold (2026-10-03): the case half
  of the route's gate. The route asks `authorize_object` for
  `victim_pii.authorise` on the case, which reads the permission off the
  caller's one role on that case (0062), and no SQL helper answers that, so
  the policy reads only `iam.user_role`. A person who holds SECURITY_OFFICER
  globally and a content role on the case (the documented first-run
  operator's shape) is refused by the route and admitted by an injected
  INSERT, which still needs a grantee other than themselves (a CHECK) and
  a grantee who holds `victim_pii.reveal` on the case to be any use. The
  base let every reader do it. Recorded in docs/17.

The officer who grants an authorisation is ASSIGNED to the case: the
grant route runs the case-scoped gate on `victim_pii.authorise`, which
reads the permission off the officer's assignment (0062: "an officer
assigned to the case as SECURITY_OFFICER holds `authorise` and not
`reveal`"), so the CASE term admits them and no term admitting an
unassigned holder is needed. Such a term would let every officer read
every authorisation in the deployment, scope notes included, for cases
they are not on, with no reader asking for it.

## Who must see every row, and runs as a system purpose

`db.SystemPurpose.INGEST`, which ingest scoring already ran as: a batch's
parse and a dead letter's replay (each dedupes against every record,
writes records at the feed key's label, which may sit above the operator,
and writes dead letters), every scoring pass (it reads and writes the
record whatever its caller may read, scores against every watch, and tells
the case's owner, whose case the caller may not be on), and the
fingerprint correlation (it answers across the corpus at the caller's
labels, and the route then narrows it to the caller's cases and
quarantine, as before). RETENTION counts the live records per category on
the officer's cases; WITHHELD counts a record's folded copies, which the
queue shows as a total including copies the reader cannot see.

`POST /ingest` (the unauthenticated submit) touches neither table: it
reads the exempt `ingest.api_key` and writes the exempt `ingest.batch`,
so it stays on the request role, unbound, and no system connection is
handed to a route nobody signed in to.

## What the dead-letter policy costs

Measured 2026-10-02 on a development clone holding 3,001 dead letters,
one per batch, 2,500 of them from batches that fed one of 51 cases and
500 from batches that fed none, plus one batch of 5,000 records:

- Every read of `ingest.dead_letter` evaluates the predicate on every dead
  letter in the table: the listing sorts on `occurred_at` after the filter
  (`dead_letter_open_idx` is partial), so neither the sort nor a LIMIT
  stops it early. The cost is linear in the dead letters the table holds,
  not in the page asked for.
- A dead letter the reader may not see costs the walk and an array test,
  about 20 microseconds (the whole table, nothing visible: 60 ms). One
  seen through a case costs the walk plus the confirmation, three reads of
  the actor's reach, about 0.9 ms (100 visible: 147 ms); one seen by the
  operator in quarantine about 1.1 ms (500 visible: 617 ms).
- The listing (`routers/ingest.dead_letters`) asks `iam.ingest_batch_reach`
  for every visible row on top: `GET /ingest/dead-letters?limit=200` took
  a median of 140 ms for a reader who sees none, 280 ms for one who sees
  100, and 1.4 s for the operator who sees 500. Filtered to one key, a
  caller none of whose cases that key fed walks every batch of the key
  before its 404: 545 ms for 3,001 batches.

So a deployment holding tens of thousands of live dead letters (the
default rule keeps one 90 days) pays seconds per listing, most of it for
the operator. Making the confirmation cheaper means computing the actor's
reach once per statement, which a function called per row cannot do.

## Downgrade

Drops every policy and disables row security on the four tables.
"""
from alembic import op

revision = "0154"
down_revision = "0153"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"
_CLR = "(SELECT iam.rls_clearance())"
_CEIL = "(SELECT iam.rls_ceilings())"
_HELD = "(SELECT iam.rls_compartments())"
_ACTOR = "(SELECT iam.rls_actor())"
_MANAGES = "(SELECT iam.rls_holds_global('ingest.manage'))"

#: A record: attached and within reach for its case, or quarantined and the
#: operator's at their case-less ceiling. Unqualified columns: no subquery
#: here reads a table a column could bind into. Frozen text.
RECORD = (f"compartments <@ {_HELD} AND ("
          f"(case_id = ANY ({_CASES}) AND (classification <= {_CLR} OR "
          f"classification <= iam.rls_ceiling_for({_CEIL}, case_id))) OR "
          f"(case_id IS NULL AND {_MANAGES} AND classification <= {_CLR}))")

CREDENTIAL = ("EXISTS (SELECT 1 FROM ingest.record p "
              "WHERE p.id = victim_credential.record_id)")

DEAD_LETTER = (f"dead_letter.compartments <@ {_HELD} AND "
               f"iam.ingest_dead_letter_visible(dead_letter.batch_id, "
               f"dead_letter.classification, {_CASES}, {_CLR}, {_CEIL}, {_MANAGES})")

_PII_CASE = f"pii_authorisation.case_id = ANY ({_CASES})"
#: Dated now (2026-10-02, finding 1): the 30-day CHECK is
#: counted from granted_at, so a grant dated in the future would be live,
#: and unbounded, from the moment it was inserted.
PII_GRANT = (f"{_PII_CASE} AND pii_authorisation.granted_by = {_ACTOR} AND "
             f"(SELECT iam.rls_holds_global('victim_pii.authorise')) AND "
             f"pii_authorisation.granted_at = pg_catalog.now()")
PII_COUNT = (f"{_PII_CASE} AND pii_authorisation.granted_to = {_ACTOR} AND "
             f"pii_authorisation.revoked_at IS NULL")

#: table -> [(policy, command, USING, WITH CHECK)].
POLICIES: dict[str, list[tuple[str, str, str | None, str | None]]] = {
    "ingest.record": [
        ("rls_read", "SELECT", RECORD, None),
        ("rls_update", "UPDATE", RECORD, RECORD),
    ],
    "ingest.victim_credential": [
        ("rls_read", "SELECT", CREDENTIAL, None),
        ("rls_update", "UPDATE", CREDENTIAL, CREDENTIAL),
    ],
    "ingest.dead_letter": [
        ("rls_read", "SELECT", DEAD_LETTER, None),
    ],
    "ingest.pii_authorisation": [
        ("rls_read", "SELECT", _PII_CASE, None),
        ("rls_grant", "INSERT", None, PII_GRANT),
        ("rls_count", "UPDATE",
         f"{PII_COUNT} AND pii_authorisation.expires_at > pg_catalog.now()",
         PII_COUNT),
    ],
}


def _create(table: str, name: str, command: str, using: str | None,
            check: str | None) -> str:
    parts = [f"CREATE POLICY {name} ON {table} FOR {command}"]
    if using is not None:
        parts.append(f"  USING ({using})")
    if check is not None:
        parts.append(f"  WITH CHECK ({check})")
    return "\n".join(parts) + ";"


def upgrade_sql() -> str:
    out = []
    for table, policies in POLICIES.items():
        out.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        for name, command, using, check in policies:
            out.append(_create(table, name, command, using, check))
    return "\n".join(out)


def downgrade_sql() -> str:
    out = []
    for table, policies in reversed(list(POLICIES.items())):
        for name, *_ in reversed(policies):
            out.append(f"DROP POLICY {name} ON {table};")
        out.append(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
    return "\n".join(out)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(upgrade_sql())


def downgrade() -> None:
    run(downgrade_sql())

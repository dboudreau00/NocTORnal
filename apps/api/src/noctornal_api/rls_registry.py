"""Which tables row-level security covers, and why each other one is not.

S1, 2026-09-25 (docs/00 decision 76). Every table in the ten product
schemas is in exactly one of three maps:

- `POLICY`: under row-level security in this build, with the template its
  policy follows (migrations 0114, 0116 and 0118 onwards hold the SQL,
  each as frozen text). Every reader of the table
  has been converted: gate inputs read facts (`iam.case_facts`,
  `iam.element_facts`, `iam.lookup_result_facts`), work that must see
  every row runs on a system connection (`db.SystemPurpose`).
- `EXEMPT`: never under a policy, with the reason. The IAM plane is the
  policies' own input and is read-only to the request role instead (0109);
  the collection plane is read by the egress proxy's role, which is subject
  to row security and must not be given a bypass; the rest is reference
  vocabulary or deployment configuration with no case and no label.
- `DEFERRED`: will carry a policy, and does not yet, because its readers
  have not all been converted. The reason names the reader work still
  owed. A table is either fully enforced or not enforced at all: never
  half.

`test_rls_registry_pg.py` holds the database to this module: a table that
carries case_id, classification, compartments, read_compartments,
visibility_clearance or visibility_compartments, or a foreign key to a
policied table, and is in none of the three maps fails by name; the set of
tables with relrowsecurity equals `POLICY` exactly. The readiness row
`row_level_security_enforced` reads `POLICY` and `POLICY_FLOOR`.

## Adding a table

A migration that creates a case-scoped table either puts it under a
policy (ENABLE ROW LEVEL SECURITY and one of the templates below, as 0114
does) and adds it to `POLICY`, or adds it to `DEFERRED` or `EXEMPT` here
with a reason. The templates, with CASES = `(SELECT iam.rls_cases())::uuid[]`,
CLR = `(SELECT iam.rls_clearance())`, CEIL = `(SELECT iam.rls_ceilings())`,
HELD = `(SELECT iam.rls_compartments())`:

- ELEMENT (case_id, classification, compartments):
  `case_id = ANY (CASES) AND (classification <= CLR OR classification <=
  iam.rls_ceiling_for(CEIL, case_id)) AND compartments <@ HELD`, FOR ALL,
  as USING and WITH CHECK.
- CASE (case_id only): `case_id = ANY (CASES)`.
- CASE_LABELLED (case_id, classification): the ELEMENT test without the
  compartments term.
- CHILD: `EXISTS (SELECT 1 FROM <parent> p WHERE p.id = <table>.<fk>)`
  for each parent (nullable keys as `<fk> IS NULL OR EXISTS ...`); outer
  columns always table-qualified inside the subquery.
- LEDGER_CHILD: the CHILD test as a SELECT policy and an INSERT policy
  only; the table keeps no UPDATE or DELETE privilege.
- CUSTOM_RUN (a stored analysis run, 0120): its projection visible and
  `visibility_clearance` within the ceiling for the projection's case,
  `visibility_compartments` held (decision 31).
- CUSTOM_SAMPLE (a Lab sample, 0121): its own labels within the case-less
  ceiling and, when it has a case, that case within the same reach
  (`iam.rls_cases_in_reach()`): the Lab is global under sample.read, so
  no assignment is asked for.
- CUSTOM_MESSAGE (0122): its own labels within the ceiling for its
  conversation's case, inside a visible conversation.
- CUSTOM_STOPLIST (0122): a case's entries in a readable case; the
  global ones (no case) to every bound user.
- CUSTOM_TOMBSTONE (0123, read only): a case's tombstones in a readable
  case; a case-less one under a global retention.read.
- CUSTOM_TAG (0123): a case's own tags in a readable case; the global
  taxonomy to every bound user.
- CUSTOM_APPROVAL (0123): a case's requests in a readable case; the
  deployment-wide ones (no case) to every bound user, whose routes decide
  who may list, sign or apply them.
- CUSTOM_WATCH (0124): a case's watches in a readable case; a case-less
  one to every bound user.
- CUSTOM_MERGE (0132, 2026-10-03): the CASE term AND an EXISTS over
  `core.node` for the merge's source and for its target, so a merge is
  visible only where both of its entities are.
- CUSTOM_NOTICE (a notification, 0126): the recipient's own
  (`recipient_id = (SELECT iam.rls_actor())`), its classification within
  CLR, its compartments held, and when it names a case, that case
  readable; a SELECT and an UPDATE policy only. A notice is written for
  someone else, so its one writer is the definer `notify.enqueue` (0125),
  which checks the recipient instead of the writer and answers an id,
  never the row.
- CUSTOM_DOCUMENT (a case-less row with its own labels, 0118):
  `classification <= CLR AND compartments <@ HELD`. No case term, so no
  case-scoped grant raises it: a row that belongs to no case is held to
  the reader's case-less ceiling, as every collection view holds it.
- CUSTOM_SOURCE_CHILD (a row of an exempt `collect.source`, 0129, restated
  by 0164): `EXISTS (SELECT 1 FROM collect.source p WHERE p.id =
  <table>.source_id AND p.classification <= CLR AND p.compartments <@
  HELD)`. The CHILD test with the source's label and compartments inline,
  because the source is exempt (the egress proxy reads it) and so carries
  no policy for a CHILD test to lean on; the same reading as
  `collection._SOURCE_VISIBLE_HELD`, held to the case-less ceiling.
- CUSTOM_RECORD (an ingest record, 0154): compartments held, and either
  attached (the ELEMENT test on its case) or quarantined (no case,
  `ingest.manage` held globally through an initplan, its classification
  within CLR); a SELECT and an UPDATE policy.
- CUSTOM_DEAD_LETTER (0154, read only): compartments held and 0153's one
  definer predicate `iam.ingest_dead_letter_visible`, which reads the cases
  the dead letter's batch fed over `record_batch_case_idx` (0152): visible
  through any of them the reader may read, at that case's ceiling, or, for
  a batch that fed none, to an `ingest.manage` holder within CLR. Its reach
  arguments are the caller's initplans and only narrow: every yes is
  confirmed against the bound actor.
- CUSTOM_PII_AUTHORISATION (0154): read in a readable case (CASE); granted
  only by its grantor holding `victim_pii.authorise` globally, in a
  readable case, dated at the moment it is made; counted only by its
  grantee, on a live, unrevoked row. The grant is the GLOBAL half of the
  route's gate: the case half (the permission read off the grantor's one
  role on that case) is not asked at the database (docs/17, 2026-10-03).
- CUSTOM_ACT (a persona act, 0156, 2026-10-02): the requester's own
  (`requested_by = (SELECT iam.rls_actor())`) and its label within CLR, a
  SELECT policy and an INSERT policy that admits only a fresh PENDING row
  (attempts zero, no claimant, no claim time, no result; 2026-10-03). No
  UPDATE or DELETE policy: the collector and the inline runner claim and
  finish an act as the PERSONA_ACTS system purpose.
- CUSTOM_AUDIT (the audit log, 0168): a SELECT policy, `case_id = ANY
  (CASES)`, or a case-less row the reader wrote, or `audit.read` held
  globally, or a case-less `ingest` row under a global `ingest.manage`;
  and an INSERT policy `WITH CHECK (true)`: every writer appends, whatever
  case the row names, because the log is append-only and a writer that may
  read none of it still has to write to it. What a request may NAME is not
  the policy's to say: 0150's BEFORE INSERT trigger `audit_attribution` pins
  it (an actor must be the user the connection is bound to, or the holder
  of a ticket it spent; a claim from a connection bound to nobody is kept
  in `detail` with `actor_id` NULL; the time is the database's), and it
  fires before the policy's check. No UPDATE or DELETE privilege or policy
  (invariant 6).
- CUSTOM_CUSTODY (the custody ledger, 0114 and 0151): the LEDGER_CHILD
  SELECT policy and an INSERT policy that adds `actor_id = (SELECT
  iam.rls_actor())` to the child test, so a custody row names the user who
  wrote it. The column is NOT NULL, so there is no unattributed row to allow.

A table the request role writes only by UPDATE carries its template as a
SELECT and an UPDATE policy and nothing else, so no INSERT of the request
role reaches its keys and no DELETE reaches a row: `ingest.record` and
`ingest.victim_credential` (0154), whose rows are made and destroyed on
system connections (F51, 2026-10-02).

A policy says which rows, never which columns or values. On
`ingest.record`, `ingest.victim_credential` and `ingest.pii_authorisation`
the request role holds UPDATE only on the columns a request writes, and a
guard trigger holds what those columns may become, as 0109 and 0112 do for
the session (0155, F51, 2026-10-02).

A table the request role never writes carries its template as a SELECT
policy alone (`rls_read`), so no INSERT of the request role reaches its
unique keys and no UPDATE or DELETE reaches a row: `notify.delivery`,
`notify.jira_link` and `notify.jira_event` (0126), which only
`notify.enqueue` and the NOTIFY and NOTIFY_ADMIN system purposes write
(F51, 2026-10-02).

A trigger function that reads a policied table must be SECURITY DEFINER
with `SET search_path = pg_catalog, <its schemas>, pg_temp` (0113), or it
reads only the writer's view and an invariant fails open.
"""
from __future__ import annotations

#: Tables under row-level security in this build -> template.
POLICY: dict[str, str] = {
    "core.case": "CUSTOM_CASE",
    "core.node": "ELEMENT",
    "core.edge": "ELEMENT",
    "core.evidence": "ELEMENT",
    "core.assertion": "CUSTOM_ASSERTION",
    "core.evidence_link": "CHILD",
    "core.evidence_custody": "CUSTOM_CUSTODY",
    # 0116: the analysis built on them.
    "core.hypothesis": "CASE",
    "core.assumption": "CASE",
    "core.node_set": "CASE",
    # 0132 (2026-10-03): and both of its entities visible.
    "core.node_merge": "CUSTOM_MERGE",
    "core.hypothesis_evidence": "CHILD",
    "core.node_set_member": "CHILD",
    # 0118 (S1, 2026-09-25): collected documents and what hangs off them,
    # and Triage's proposals. A document is case-less, so its policy is the
    # case-less ceiling (CUSTOM_DOCUMENT); a proposal's label is derived and
    # read by the application through fact functions, so its policy is the
    # case term alone.
    "collect.document": "CUSTOM_DOCUMENT",
    "collect.extraction": "CHILD",
    "collect.forum_post": "CHILD",
    "collect.forum_member": "CHILD",
    "collect.telegram_message": "CHILD",
    "collect.document_embedding": "CHILD",
    "collect.proposal": "CASE",
    # 0119: the deception records, whose readers all apply the composed
    # labels already (`deception._labels_clause`).
    "deception.capture": "ELEMENT",
    "deception.email_message": "ELEMENT",
    "deception.call_record": "ELEMENT",
    "deception.capture_hop": "CHILD",
    "deception.email_hop": "CHILD",
    "deception.email_attachment": "CHILD",
    # 0120: stored analysis runs, their per-entity scores and the saved
    # canvas. A run is cached at one reader's exact visibility (decision 31).
    "analytics.projection": "CASE",
    "analytics.metric_run": "CUSTOM_RUN",
    "analytics.node_metric": "CHILD",
    "analytics.community_assignment": "CHILD",
    "analytics.layout_position": "CHILD",
    # 0121: the Lab. A sample is read at its labels composed with its
    # case's against the case-less ceiling (samples.lab_gate); the
    # officer's label-free screening readers run as a system purpose.
    "lab.sample": "CUSTOM_SAMPLE",
    "lab.sample_access": "LEDGER_CHILD",
    "lab.sample_analysis": "CHILD",
    "lab.preservation_authorisation": "CHILD",
    "lab.detonation": "CHILD",
    "lab.static_run": "CHILD",
    "lab.screening_result": "CHILD",
    "lab.screening_review": "CHILD",
    "lab.yara_ruleset": "CUSTOM_DOCUMENT",
    "lab.yara_ruleset_version": "CHILD",
    "lab.yara_activation": "CHILD",
    "lab.yara_compiled": "CHILD",
    "lab.yara_compiled_rejected": "CHILD",
    # 0122: the communications records. Minimisation and the incidental
    # flag it relies on run as a system purpose (MINIMISATION).
    "comms.channel_binding": "ELEMENT",
    "comms.contact_block": "ELEMENT",
    "comms.conversation": "ELEMENT",
    "comms.pgp_key_acquisition": "ELEMENT",
    "comms.contact_block_entry": "CHILD",
    "comms.participant": "CHILD",
    "comms.pgp_key": "CHILD",
    "comms.message": "CUSTOM_MESSAGE",
    "comms.device_fingerprint": "CASE",
    "comms.pgp_verification": "CASE",
    "comms.pgp_key_lookup": "CASE_LABELLED",
    "comms.service_selector": "CUSTOM_STOPLIST",
    # 0123: the rest of the case record. A merge's re-pointed ties are
    # counted at the reader's view (the conservative reading).
    # core.selector has carried its own labels since 0134 (its owner's, the
    # floor when it has none) and keys on them; the policy stays the case term
    # alone (decision 147) and every reader applies the labels itself
    # (SelectorStore.find_for_reader, the owner test of the others).
    "core.selector": "CASE",
    "core.assertion_embedding": "CHILD",
    "core.evidence_embedding": "CHILD",
    "core.node_merge_edge": "CHILD",
    "core.purge_tombstone": "CUSTOM_TOMBSTONE",
    "core.tag": "CUSTOM_TAG",
    "core.tag_assignment": "CHILD",
    "core.approval_request": "CUSTOM_APPROVAL",
    # 0124: watches and their hits. The collector and ingest scoring read
    # every watch as system purposes (COLLECTION, INGEST).
    "collect.watch": "CUSTOM_WATCH",
    "collect.watch_hit": "CHILD",
    # 0126 (F51, 2026-10-02): notifications and what they reached. Every
    # notice is raised through notify.enqueue (0125); the drain runs as
    # NOTIFY, and the delivery ledger and Jira's administration as
    # NOTIFY_ADMIN.
    "notify.notification": "CUSTOM_NOTICE",
    "notify.delivery": "CHILD",
    "notify.case_route_block": "CASE",
    "notify.jira_link": "CASE_LABELLED",
    "notify.jira_event": "CHILD",
    # 0128 (F51, 2026-10-02): the lookup ledger. An interactive send, a
    # sign-off and the provider test run from the gates on as LOOKUPS, as
    # the drain does, and what the requester is shown is read back at their
    # labels; the answer's label is read through iam.lookup_result_facts
    # (0127). A provider test's canary has no case, so no request role sees
    # it. The attempts are append-only, so their CHILD test is a ledger's.
    "ingest.lookup": "CASE_LABELLED",
    "ingest.lookup_result": "CASE_LABELLED",
    "ingest.lookup_attempt": "LEDGER_CHILD",
    "ingest.lookup_batch": "CASE",
    # 0129 (F51, 2026-10-02): which Telegram chat a source is. A new chat's
    # duplicate check runs as a system purpose (TELEGRAM_INTAKE), and the
    # attended acts refuse a write that changed no chat. 0164 (F43) restates
    # the policy with the source's compartments held.
    "collect.telegram_chat": "CUSTOM_SOURCE_CHILD",
    # 0154 (F51, 2026-10-02): the ingest records and what hangs off them. A
    # parse, a replay, every scoring pass and the fingerprint correlation
    # run as INGEST; the routes read a record's labels and a batch's cases
    # as facts (0153), and the queue's copy total is a WITHHELD count.
    "ingest.record": "CUSTOM_RECORD",
    "ingest.victim_credential": "CHILD",
    "ingest.dead_letter": "CUSTOM_DEAD_LETTER",
    "ingest.pii_authorisation": "CUSTOM_PII_AUTHORISATION",
    # 0156 (A collector process, 2026-10-02): the persona act queue. The
    # API enqueues on the request connection; claims and outcomes are
    # written as PERSONA_ACTS.
    "collect.persona_act": "CUSTOM_ACT",
    # 0168 (F51, 2026-10-02): the audit log. The countersign rule reads it as
    # the definer (0166), the Lab's last screening pass is a fact (0167), and
    # every other reader is classified by function in test_rls_audit_paths.py.
    "audit.event": "CUSTOM_AUDIT",
}

#: The readiness row fails below this many policied tables: a registry
#: that shrank (a downgraded database, a lost migration) is not "enforced".
POLICY_FLOOR = len(POLICY)

#: The columns that make a table case- or label-carrying.
LABEL_COLUMNS = ("case_id", "classification", "compartments", "read_compartments",
                 "visibility_clearance", "visibility_compartments")

_IAM = ("the IAM plane: the policies' own input (who is bound, their clearance, "
        "compartments, roles, assignments and grants). Read-only to the request "
        "role instead of filtered (0109); written only on a system connection")
_EGRESS = ("the collection plane the egress proxy reads as noctornal_egress, which "
           "is subject to row security and must not be given a bypass; holds "
           "configuration and ceilings, no case content")
_VOCAB = "reference vocabulary: no case, no label, the same for every reader"
_CONFIG = "deployment configuration with no case and no label"

EXEMPT: dict[str, str] = {
    # By named column since 0143 (rls-6, 2026-10-03): the password hash, the
    # sealed TOTP secret and its key id, the recovery hashes and the replay
    # counter are not granted to the request role at all.
    "iam.app_user": _IAM + "; the request role reads it by named column, and "
                           "never the credential columns (0143)",
    "iam.session": _IAM + "; the request role keeps UPDATE of three columns on "
                          "its OWN bound session only, the idle window moving "
                          "forward and a revocation, never step-up "
                          "(0109, 0112, 0144)",
    "iam.webauthn_credential": _IAM,
    "iam.user_role": _IAM,
    "iam.case_assignment": _IAM,
    "iam.break_glass": _IAM + "; uses are counted through "
                              "iam.rls_record_break_glass_use",
    "iam.role": _IAM,
    "iam.permission": _IAM,
    "iam.role_permission": _IAM,
    "iam.separated_duty": _IAM,
    "iam.compartment": _IAM,
    "iam.dual_control_operation": _IAM,
    "iam.dual_control_policy_change": _IAM + "; the policy tables' guard reads "
                                             "this ledger as the writer, so it "
                                             "must stay readable (F9)",
    "lab.download_ticket": ("a credential read before any user is bound (the sample "
                            "origin spends it unbound); read-only to the request "
                            "role but for spending, which 0112 confines"),
    "core.edge_type": _VOCAB,
    "core.node_type": _VOCAB,
    "core.selector_type": _VOCAB,
    "comms.platform": _VOCAB,
    "core.retention_rule": _CONFIG,
    "core.embedding_space": _CONFIG,
    "core.embedding_pending": _CONFIG + " (a queue of item ids for the embedding "
                                       "pass, which runs as the system role)",
    "ingest.api_key": _CONFIG + " (partner keys, read by the unauthenticated "
                                "ingest route before any user exists)",
    "ingest.category_rule": _CONFIG,
    "ingest.batch": _CONFIG + " (a raw upload's envelope, written by the "
                              "unauthenticated ingest route)",
    "ingest.provider": _CONFIG,
    "ingest.provider_exposure_change": _CONFIG,
    "notify.preference": _CONFIG + " (per person, no case)",
    "notify.jira_destination": _CONFIG,
    "lab.screening_list": _CONFIG + " (the officer's label-free view, F13)",
    "lab.screening_hash": _CONFIG + " (read only by the screening worker)",
    "lab.yara_compile_job": _CONFIG + " (a queue the triage worker drains)",
    # 0157 (2026-10-03): when each collector was last seen and
    # whether its persona key ring opened what it sampled; key ids and
    # counts, never key material, a person or a source.
    "collect.collector_heartbeat": _CONFIG + " (the collector's heartbeat, "
                                             "read by the readiness register)",
    "collect.source": _EGRESS,
    "collect.collection_account": _EGRESS,
    "collect.collection_authority": _EGRESS,
    "collect.collection_authority_target": _EGRESS,
    "collect.collection_run": _EGRESS,
    "collect.egress_profile": _EGRESS,
    "collect.egress_integration_route": _EGRESS,
    "collect.egress_destination": _EGRESS,
    "collect.egress_binding": _EGRESS,
    "collect.egress_connection": _EGRESS,
}

#: Will carry a policy; not yet. Each reason names what is owed first. Empty
#: since 0168 put the audit log under its policy, the last table that was
#: waiting on its readers (F51, 2026-10-03): a new entry is a table that is
#: not enforced, and a reason that says what is owed before it can be.
DEFERRED: dict[str, str] = {}

#: Trigger functions that read a policied table and stay SECURITY INVOKER,
#: with the reason. Each fires only on a write the request role cannot make.
INVOKER_TRIGGER_FUNCTIONS: dict[str, str] = {
    "iam.refuse_compartment_removal": (
        "fires on iam.compartment writes, which only a system connection "
        "makes (0109); iam.compartment_in_use then sees every row"),
    # S1, 2026-09-25: two guards that name their own table only in the
    # sentence they raise, and read no row of anything.
    "lab.block_access_mutation": (
        "refuses every change to the custody ledger; reads nothing"),
    "lab.guard_preservation_authorisation": (
        "compares the row with itself (OLD against NEW); reads nothing"),
    "core.block_tombstone_mutation": (
        "refuses every change to a tombstone; reads nothing"),
    "iam.check_dual_control_change": (
        "fires on iam.dual_control_policy_change writes, which only a system "
        "connection makes (0109), so it reads every approval as it is"),
    # F51, 2026-10-02: names the audit log only in the sentence it raises.
    "audit.block_mutation": (
        "refuses every change to the audit log; reads nothing"),
}


def classified() -> dict[str, str]:
    """Every table in the registry -> which map it is in."""
    out: dict[str, str] = {}
    for kind, table_map in (("POLICY", POLICY), ("EXEMPT", EXEMPT),
                            ("DEFERRED", DEFERRED)):
        for table in table_map:
            out[table] = kind
    return out

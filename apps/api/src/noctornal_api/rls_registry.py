"""Which tables row-level security covers, and why each other one is not.

S1, 2026-09-25 (docs/00 decision 76). Every table in the ten product
schemas is in exactly one of three maps:

- `POLICY`: under row-level security in this build, with the template its
  policy follows (migrations 0114, 0116 and 0118 onwards hold the SQL,
  each as frozen text). Every reader of the table
  has been converted: gate inputs read facts (`iam.case_facts`,
  `iam.element_facts`), work that must see every row runs on a system
  connection (`db.SystemPurpose`).
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
- CUSTOM_DOCUMENT (a case-less row with its own labels, 0118):
  `classification <= CLR AND compartments <@ HELD`. No case term, so no
  case-scoped grant raises it: a row that belongs to no case is held to
  the reader's case-less ceiling, as every collection view holds it.

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
    "core.evidence_custody": "LEDGER_CHILD",
    # 0116: the analysis built on them.
    "core.hypothesis": "CASE",
    "core.assumption": "CASE",
    "core.node_set": "CASE",
    "core.node_merge": "CASE",
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
    "iam.app_user": _IAM,
    "iam.session": _IAM + "; the request role keeps UPDATE of four columns on "
                          "its OWN bound session only (0109, 0112)",
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

#: Will carry a policy; not yet. Each reason names what is owed first.
DEFERRED: dict[str, str] = {
    "audit.event": (
        "CUSTOM, not system-only (S1, 2026-09-25): a case member reads the "
        "case's timeline, review history and ingest triage state from it on "
        "the request connection, so a system-only read would move every one "
        "of those readers off row security rather than under it. The policy: "
        "SELECT where the case is readable, or the row is the actor's own "
        "case-less row, or audit.read is held globally (the officer's "
        "search), or it is an ingest row and ingest.manage is held; INSERT "
        "always (append-only, every writer appends). Owed first: about 100 "
        "readers in 53 modules; audit_verify and custody_verify move to "
        "AUDIT_VERIFY (the chain walk must see every row); "
        "IngestService.attach_record copies the latest triage state onto a "
        "case-scoped row (quarantine rows carry no case); "
        "iam.countersign_blocked_by reads it inside a trigger and becomes "
        "SECURITY DEFINER; the out-of-band audit writers keep working as "
        "appends"),
    "collect.telegram_chat": (
        "CHILD of source with the source's label inline (the source is exempt), "
        "once three readers move: TelegramChats.create's duplicate check must "
        "see a chat under a source above the caller (it audits "
        "TELEGRAM_CHAT_DUPLICATE_HIDDEN and the unique durable_id would "
        "otherwise raise), so it runs as a system purpose; attach_target_chats "
        "reads the chats of an officer's authority targets, whose sources the "
        "officer may be below; and the acts (join, check_membership, "
        "mark_member, rebind) update by source id after _chat_row and must "
        "check the rowcount"),
    "ingest.record": (
        "CUSTOM (attached: case readable and labels within reach; "
        "quarantined: ingest.manage held and labels within reach, through "
        "an initplan). Owed first: the unauthenticated submit "
        "(routers/ingest.submit, bound to no user), parse_batch, replay, "
        "score_records and rescore run as a system purpose (they dedupe "
        "against every record, score against every watch and write rows "
        "their caller may be below); the queue's triage state, read from "
        "audit.event, moves with that table"),
    "ingest.victim_credential": (
        "CHILD of record, after record; reveal_credential and "
        "credentials_masked are gated on ingest.pii_authorisation first"),
    "ingest.dead_letter": (
        "CUSTOM through one definer predicate backed by an index on "
        "ingest.record (batch_id, case_id), after record; "
        "scripts/redact_dead_letters.py is a system purpose already"),
    "ingest.pii_authorisation": (
        "CASE template for the Lead investigator's reveal "
        "(_live_authorisation), and a term admitting a global holder of "
        "victim_pii.authorise: the Security Officer who grants it holds no "
        "case assignment (Security Officers read no case content), so "
        "grant_pii_authorisation and its listing would otherwise be "
        "refused; with ingest.record"),
    "ingest.lookup": (
        "CASE_LABELLED, with case-less canary rows for the provider test. "
        "Owed first: an interactive request (routers/lookups.request) sends, "
        "stores the answer at a label the provider decides (up to RED) and "
        "raises proposals on the REQUEST connection, and the answer row's "
        "INSERT ... RETURNING would be refused for a requester below it; "
        "that path runs as the LOOKUPS purpose, as the drain does. Its "
        "entity and sample label joins read facts since 2026-09-25"),
    "ingest.lookup_attempt": "CHILD of lookup, with it",
    "ingest.lookup_batch": "CASE template, with ingest.lookup",
    "ingest.lookup_result": "CASE_LABELLED, with ingest.lookup",
    "notify.notification": (
        "CUSTOM (the recipient's own, within their labels). Owed first: "
        "NotificationService.notify writes a row for SOMEONE ELSE with "
        "INSERT ... RETURNING, reads the recipient's unread rows to coalesce "
        "(notify_events._open_alert) and inserts its deliveries, all inside "
        "the caller's transaction; under a recipient policy each is refused "
        "or blind. The write moves into one SECURITY DEFINER enqueue "
        "function (recipient eligibility checked in SQL, no RETURNING of "
        "the row), or onto the NOTIFY purpose with the caller's atomicity "
        "given up on purpose; the transports and the Jira sender are the "
        "drain's (NOTIFY, JIRA) already"),
    "notify.delivery": "CHILD of notification, with it",
    "notify.case_route_block": (
        "CASE template, with notify.notification: the transports read it "
        "on the drain"),
    "notify.jira_link": (
        "CASE_LABELLED, with notify.notification: the Jira sender writes it "
        "on the drain, and the case's Integrations view reads it"),
    "notify.jira_event": "CHILD of jira_link, with it",
}

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
}


def classified() -> dict[str, str]:
    """Every table in the registry -> which map it is in."""
    out: dict[str, str] = {}
    for kind, table_map in (("POLICY", POLICY), ("EXEMPT", EXEMPT),
                            ("DEFERRED", DEFERRED)):
        for table in table_map:
            out[table] = kind
    return out

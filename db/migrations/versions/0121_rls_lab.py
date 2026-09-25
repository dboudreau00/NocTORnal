"""Row-level security on the Lab: samples, what hangs off them, and the
YARA rule sets (S1, 2026-09-25).

## What this enforces, and for whom

`noctornal_app`, bound per request (0111), now sees and writes:

- `lab.sample` (CUSTOM): a sample whose own classification is within the
  user's CASE-LESS ceiling and whose compartments they hold, and whose
  case, when it has one, is within the same reach
  (`iam.rls_cases_in_reach()`, 0117). That is `samples.lab_gate`, the
  one Lab gate every Lab read applies: the sample's labels composed with
  its case's, against the reader's own ceiling, with no case assignment,
  because the Lab is global under `sample.read`. The gate's exclusions
  (a prohibited-content match is gone from the Lab for everyone) stay in
  the application, since the Security Officer's two screening readers
  opt out of them on purpose.
- `lab.sample_access` (LEDGER CHILD of the sample: read and append only),
  `lab.sample_analysis`, `lab.preservation_authorisation`,
  `lab.detonation`, `lab.static_run`, `lab.screening_result` (CHILD of
  the sample) and `lab.screening_review` (CHILD of the result): never
  more visible than the sample.
- `lab.yara_ruleset` (CUSTOM, like a collected document: labelled, no
  case): its classification within the case-less ceiling, its
  compartments held (`yara_rules.ruleset_gate`). `lab.yara_ruleset_version`
  and `lab.yara_activation` (CHILD of the rule set), `lab.yara_compiled`
  (CHILD of the version) and `lab.yara_compiled_rejected` (CHILD of the
  build) follow it.

## What must see every sample, and runs as a system purpose

A submission's duplicate check (`SAMPLE_INTAKE`: a duplicate the
submitter may not see must still refuse the upload, without saying why);
the Security Officer's label-free match list, the section's counts, a
review and the console's screening pass (`SCREENING`: by an explicit
owner decision the officer governs every match whatever its labels); the
lookup refusal for the hash of never-screened material (`LOOKUPS`); and
the workers, which were system purposes already.

`lab.yara_activation_rules`, the one trigger function that reads a table
this revision policies (the version an activation names), becomes
SECURITY DEFINER with its search path pinned, as 0113 did.

## Downgrade

Drops every policy, disables row security on the thirteen tables, and
restores the trigger function to SECURITY INVOKER with no search path.
"""
from alembic import op

revision = "0121"
down_revision = "0120"
branch_labels = None
depends_on = None

_CLR = "(SELECT iam.rls_clearance())"
_HELD = "(SELECT iam.rls_compartments())"
_REACH = "(SELECT iam.rls_cases_in_reach())"


def _child(table: str, parent: str, fk: str) -> str:
    return f"EXISTS (SELECT 1 FROM {parent} p WHERE p.id = {table}.{fk})"


#: table -> (USING and WITH CHECK), one FOR ALL policy named rls_gate.
#: Frozen text: a later revision that changes one restates it.
POLICIES: dict[str, str] = {
    "lab.sample": (f"sample.classification <= {_CLR} AND "
                   f"sample.compartments <@ {_HELD} AND "
                   f"(sample.case_id IS NULL OR {_REACH} ? sample.case_id::text)"),
    "lab.sample_analysis": _child("sample_analysis", "lab.sample", "sample_id"),
    "lab.preservation_authorisation": _child("preservation_authorisation",
                                             "lab.sample", "sample_id"),
    "lab.detonation": _child("detonation", "lab.sample", "sample_id"),
    "lab.static_run": _child("static_run", "lab.sample", "sample_id"),
    "lab.screening_result": _child("screening_result", "lab.sample", "sample_id"),
    "lab.screening_review": _child("screening_review", "lab.screening_result",
                                   "result_id"),
    "lab.yara_ruleset": (f"yara_ruleset.classification <= {_CLR} AND "
                         f"yara_ruleset.compartments <@ {_HELD}"),
    "lab.yara_ruleset_version": _child("yara_ruleset_version", "lab.yara_ruleset",
                                       "ruleset_id"),
    "lab.yara_activation": _child("yara_activation", "lab.yara_ruleset",
                                  "ruleset_id"),
    "lab.yara_compiled": _child("yara_compiled", "lab.yara_ruleset_version",
                                "version_id"),
    "lab.yara_compiled_rejected": _child("yara_compiled_rejected",
                                         "lab.yara_compiled", "compiled_id"),
}

#: function -> its search_path before this revision (None: it had none).
#: The one trigger function that reads a table this revision policies:
#: an activation's rules read the version it activates.
PRIOR_CONFIG: dict[str, str | None] = {
    "lab.yara_activation_rules()": None,
}

#: The ledger child: a read policy and an append policy, nothing else. It
#: keeps no UPDATE or DELETE privilege (0060's ledger revoke).
LEDGER: dict[str, str] = {
    "lab.sample_access": _child("sample_access", "lab.sample", "sample_id"),
}


def pinned_path(prior: str | None) -> str:
    """0113's rule: pg_catalog first, the function's own schemas (public
    where it had none), pg_temp last."""
    names = [n.strip() for n in (prior or "public").split(",")]
    names = [n for n in names if n not in ("pg_catalog", "pg_temp")]
    return ", ".join(["pg_catalog", *names, "pg_temp"])


def upgrade_sql() -> str:
    out = [f"ALTER FUNCTION {fn} SECURITY DEFINER SET search_path = {pinned_path(prior)};"
           for fn, prior in PRIOR_CONFIG.items()]
    for table, qual in POLICIES.items():
        out.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        out.append(f"CREATE POLICY rls_gate ON {table} FOR ALL "
                   f"USING ({qual}) WITH CHECK ({qual});")
    for table, qual in LEDGER.items():
        out.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        out.append(f"CREATE POLICY rls_read ON {table} FOR SELECT USING ({qual});")
        out.append(f"CREATE POLICY rls_append ON {table} FOR INSERT "
                   f"WITH CHECK ({qual});")
    return "\n".join(out)


def downgrade_sql() -> str:
    out = []
    for table in reversed(list(LEDGER)):
        out.append(f"DROP POLICY rls_append ON {table};")
        out.append(f"DROP POLICY rls_read ON {table};")
        out.append(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
    for table in reversed(list(POLICIES)):
        out.append(f"DROP POLICY rls_gate ON {table};")
        out.append(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
    for fn, prior in PRIOR_CONFIG.items():
        if prior is None:
            out.append(f"ALTER FUNCTION {fn} SECURITY INVOKER RESET search_path;")
        else:
            out.append(f"ALTER FUNCTION {fn} SECURITY INVOKER SET search_path = {prior};")
    return "\n".join(out)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(upgrade_sql())


def downgrade() -> None:
    run(downgrade_sql())

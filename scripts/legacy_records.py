"""List the records written under a rule that has since changed. Report
only: nothing here writes, and there is no --apply.

    python scripts/legacy_records.py                 every section
    python scripts/legacy_records.py --section undated --section captures

Sections (noctornal_api/legacy_records.py says why each exists):

  undated          claims accepted from Triage before Alpha 6 with no
                   observation date, and the date their document gives
  underlabelled    ATTRIBUTE claims readable below what they were found in,
                   or attached to an entity in another case
  captures         captured documents a compartmented case cites that no
                   compartment could be given
  victim-captures  captured documents carrying a compartment an ingest feed
                   now uses for third-party personal data
  url-fragments    stored URLs the current url_norm would write differently

The output names cases, entities and identifiers, some of them personal
data. Run it on the server and never paste it into a ticket. Every time is
UTC.

Exit 0 when nothing was listed, 1 when anything was, 2 when the database
could not be reached or read.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "apps", "api", "src"))

from _env import load_env_local  # noqa: E402

load_env_local()

SECTIONS = ("undated", "underlabelled", "captures", "victim-captures",
            "url-fragments")

UNDATED_FOOTER = (
    "Each claim above was accepted from Triage before Alpha 6 and carries no "
    "observation date, so First seen and Last seen ignore it. The date shown "
    "is its document's posting time, or its capture time when the post had "
    "none. Nothing here writes it: an analyst who wants it counted adds a "
    "claim to the entity or tie with Observed at set to that date (the "
    "inspector's Add claim form); the undated claim stays as it was "
    "recorded.")

UNDERLABELLED_FOOTER = (
    "Each claim is read by everyone who can read its entity. Retract it from "
    "the entity's inspector (Retract, which needs assertion.retract), saying "
    "why; if the identifier is still wanted, record it on an entity labelled "
    "at least as high as the material, in the case it was found in. Nothing "
    "here changes a label: there is no verb that raises an existing entity's "
    "label.")

CLOSED_FOOTER = (
    "These claims are in cases that are closed or archived, which take no "
    "content write. A Lead investigator reopens the case (case.update), "
    "retracts the claim, and closes it again; an archived case cannot be "
    "reopened, and its claims stay listed here.")

CAPTURES_FOOTER = (
    "Each document above was captured before captures carried compartments, "
    "into a case that cites it along with a case outside its compartments, "
    "so no lock fits every case that cites it, and it is listed in the "
    "collection to every reader at its TLP. Decide with the cases that cite "
    "it whether it should be read under a compartment; nothing here changes "
    "it.")

VICTIM_FOOTER = (
    "Each document above carries a compartment an ingest feed now uses to "
    "wall off third-party personal data, so its text is in the collection's "
    "free-text index. It was captured before a feed forced that compartment. "
    "Decide with the case whether it belongs in the case as an exhibit "
    "instead; nothing here changes it.")

URL_FOOTER = (
    "Record each link again where it matters: it now gets its own selector, "
    "and a capture raises it as a new proposal. A shared row is corrected "
    "the way any wrong record is (correct the entity's label with a reason, "
    "or retract its claim); nothing here deletes or rewrites a row.")


def utc(value: datetime | None) -> str:
    """A time as the console prints it: UTC, and saying so."""
    if value is None:
        return "no time recorded"
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%MZ")


def plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _labels(cls: str | None, keys) -> str:
    keys = list(keys or [])
    return (cls or "no label") + (f" in {', '.join(keys)}" if keys else "")


def undated(conn) -> int:
    from noctornal_api.legacy_records import undated_triage_claims
    rows = undated_triage_claims(conn)
    print(f"Undated Triage claims: {plural(len(rows), 'claim', 'claims')}")
    for r in rows:
        print(f"  {r.case_code:14} {r.element_kind} {r.element_id} claim "
              f"{r.assertion_id} <- {utc(r.would_date)} ({r.date_from}) "
              f"document {r.document_id}")
    if rows:
        print(UNDATED_FOOTER)
    return len(rows)


def underlabelled(conn) -> int:
    from noctornal_api.legacy_records import underlabelled_claims
    rows = underlabelled_claims(conn)
    print(f"Triage claims below their material: "
          f"{plural(len(rows), 'claim', 'claims')}")
    for closed in (False, True):
        group = [r for r in rows if r.closed == closed]
        if not group:
            continue
        if closed:
            print("  In closed cases:")
        case = None
        for r in group:
            if r.entity_case_code != case:
                case = r.entity_case_code
                print(f"  {case} ({r.entity_case_status})")
            print(f"    entity {r.node_type} {r.node_label!r} {r.node_id}")
            print(f"      {r.claim_path} = {r.claim_value!r}")
            print(f"      material {_labels(r.material_classification, r.material_compartments)}; "
                  f"entity {_labels(r.entity_classification, r.entity_compartments)}")
            print(f"      accepted by {r.accepted_by_email or 'an account since removed'} "
                  f"at {utc(r.accepted_at)}; claim {r.assertion_id}")
            print(f"      {r.problem}")
        print(CLOSED_FOOTER if closed else UNDERLABELLED_FOOTER)
    return len(rows)


def _capture_rows(title: str, rows, footer: str) -> int:
    print(f"{title}: {plural(len(rows), 'document', 'documents')}")
    for r in rows:
        print(f"  document {r.document_id} {r.title or '(untitled)'!r} at "
              f"{r.classification}, captured {utc(r.captured_at)}")
        for code, cls, keys in r.cases:
            print(f"    cited by {code} ({_labels(cls, keys)})")
    if rows:
        print(footer)
    return len(rows)


def captures(conn) -> int:
    from noctornal_api.legacy_records import unlabelled_captures
    return _capture_rows("Captures no compartment fits",
                         unlabelled_captures(conn), CAPTURES_FOOTER)


def victim_captures(conn) -> int:
    from noctornal_api.legacy_records import victim_data_captures
    return _capture_rows("Captures under a victim-data compartment",
                         victim_data_captures(conn), VICTIM_FOOTER)


def url_fragments(conn) -> int:
    from noctornal_api.legacy_records import url_identity_changes
    rep = url_identity_changes(conn)
    print(f"URLs whose identity changed: "
          f"{plural(rep.total, 'record', 'records')}")
    for s in rep.selectors:
        shared = ("one observation: record it again and it gets its own row"
                  if s.observations <= 1 else
                  f"{s.observations} observations share this row")
        print(f"  {s.case_code:14} selector {s.selector_id} {s.selector_type} "
              f"{s.raw_value!r}")
        print(f"    stored {s.stored_norm!r}, now {s.new_norm!r}; {shared}")
        for link, norm in s.behind:
            print(f"    behind it: {link!r} -> {norm!r}")
    for e in rep.entities:
        print(f"  {e.case_code:14} entity {e.node_id} labelled {e.label!r}, "
              f"now {e.new_norm!r}")
    for p in rep.proposals:
        print(f"  {p.case_code:14} pending proposal {p.proposal_id} "
              f"{p.label!r}, accepting it writes the old form; now "
              f"{p.new_norm!r}")
    if rep.deception_captures or rep.deception_hops:
        print(f"  {plural(rep.deception_captures, 'deception capture URL', 'deception capture URLs')} "
              f"and {plural(rep.deception_hops, 'redirect hop', 'redirect hops')} "
              f"are kept as captured; nothing matches on them.")
    if rep.total:
        print(URL_FOOTER)
    return rep.total


RUNNERS = {"undated": undated, "underlabelled": underlabelled,
           "captures": captures, "victim-captures": victim_captures,
           "url-fragments": url_fragments}


def main(argv: list[str] | None = None, *, connect=None) -> int:
    parser = argparse.ArgumentParser(
        description="List records written under a rule that has since "
                    "changed. Report only.")
    parser.add_argument("--section", action="append", choices=SECTIONS,
                        help="a section to list (repeatable; default all)")
    args = parser.parse_args(argv)
    wanted = args.section or list(SECTIONS)
    if connect is None:
        from noctornal_api.db import SystemPurpose, connect_system

        def connect():
            return connect_system(SystemPurpose.SCRIPT)
    try:
        conn = connect()
    except Exception as exc:  # noqa: BLE001 - any failure is exit 2
        print(f"the database could not be reached: {type(exc).__name__}: "
              f"{str(exc)[:300]}", file=sys.stderr)
        return 2
    listed = 0
    try:
        for name in SECTIONS:
            if name in wanted:
                listed += RUNNERS[name](conn)
                print()
    except Exception as exc:  # noqa: BLE001 - any failure is exit 2
        print(f"the database could not be read: {type(exc).__name__}: "
              f"{str(exc)[:300]}", file=sys.stderr)
        return 2
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001 - closing is best effort
            pass
    print(f"{plural(listed, 'record', 'records')} listed; nothing was "
          f"changed.")
    return 1 if listed else 0


if __name__ == "__main__":
    raise SystemExit(main())

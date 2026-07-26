"""Seed an ACH matrix worth looking at, through the real API.

Development only. Hypotheses and stances go in over HTTP, so what you see
is what the router's checks and `ach.py`'s scoring actually do.

    .venv\\Scripts\\python scripts\\seed_ach_demo.py --case OP-NIGHTJAR-26
    .venv\\Scripts\\python scripts\\seed_ach_demo.py --case OP-NIGHTJAR-26 --clean

The matrix is built to demonstrate the method rather than to look tidy,
because a demo where the obvious hypothesis wins teaches the wrong lesson:

  * Three hypotheses, one of which is the one an analyst would reach for
    first — and it is NOT the one that survives, because ACH ranks on
    evidence AGAINST rather than evidence for.
  * One piece of evidence consistent with every hypothesis, so the
    "not diagnostic" row is populated. That row is the point: it is the
    evidence a team spends weeks collecting and which discriminates
    nothing.
  * At least one unassessed cell, because a real matrix always has them
    and an unassessed cell is not a neutral one.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "apps", "api", "src"))

from noctornal_api.db import connect  # noqa: E402

#: (statement, {evidence-index: stance})
#: Stance scale: -2 strongly inconsistent .. +2 strongly consistent.
HYPOTHESES = [
    ("NIGHTJAR and KESTREL are the same operator",
     {0: 2, 1: -2, 2: 1}),
    ("NIGHTJAR and KESTREL are separate operators sharing a builder",
     {0: 1, 1: 1, 2: 1}),
    ("KESTREL is an imitator with no relationship to NIGHTJAR",
     {0: -1, 1: 2}),          # index 2 deliberately left unassessed
]

#: `core.hypothesis` has no free-text marker column, so demo rows are
#: identified by their exact statement. That is deterministic and, unlike a
#: `[demo]` prefix, does not put scaffolding into the thing an analyst
#: reads. `hypothesis_evidence` cascades on delete, so removing the
#: hypothesis takes its cells with it.
STATEMENTS = [statement for statement, _ in HYPOTHESES]


def case_row(conn, code):
    row = conn.execute(
        'SELECT id, owner_user_id FROM core."case" WHERE code = %s',
        (code,)).fetchone()
    if row is None:
        raise SystemExit(f"no case with code {code!r}")
    return row[0], row[1]


def live_assertions(conn, case_id, want):
    """Real assertions from this case. ACH evidence is an ASSERTION, never
    free text: a matrix built from typed-in bullet points is a way to
    launder a hunch into a grid, which is the failure ACH prevents."""
    rows = conn.execute(
        """SELECT a.id, coalesce(n.label, et.display_name, a.claim_path,
                                 a.rationale, 'assertion')
             FROM core.assertion a
             LEFT JOIN core.node n ON n.id = a.node_id
             LEFT JOIN core.edge e ON e.id = a.edge_id
             LEFT JOIN core.edge_type et ON et.key = e.edge_type
            WHERE a.case_id = %s AND a.retracted_at IS NULL
              AND a.superseded_at IS NULL
            ORDER BY a.recorded_at LIMIT %s""", (case_id, want)).fetchall()
    if len(rows) < want:
        raise SystemExit(
            f"this case has {len(rows)} live assertion(s) and the demo needs "
            f"{want}. Add some graph elements first — ACH evidence has to be "
            f"an assertion, and there is no path that invents one.")
    return rows


def clean(conn, case_id):
    with conn.transaction():
        n = conn.execute(
            "DELETE FROM core.hypothesis WHERE case_id = %s "
            "AND statement = ANY(%s)", (case_id, STATEMENTS)).rowcount
    print(f"removed {n} demo hypothes{'is' if n == 1 else 'es'}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True)
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()

    conn = connect()
    case_id, owner = case_row(conn, args.case)
    if args.clean:
        clean(conn, case_id)
        return 0
    clean(conn, case_id)

    evidence = live_assertions(conn, case_id, want=3)
    print("evidence:")
    for i, (_id, label) in enumerate(evidence):
        print(f"  E{i + 1}  {label}")

    for statement, stances in HYPOTHESES:
        hypothesis_id = conn.execute(
            """INSERT INTO core.hypothesis
                   (case_id, statement, confidence, status, created_by)
               VALUES (%s, %s, 'LOW', 'PROPOSED', %s) RETURNING id""",
            (case_id, statement, owner)).fetchone()[0]
        for index, stance in stances.items():
            conn.execute(
                """INSERT INTO core.hypothesis_evidence
                       (hypothesis_id, assertion_id, stance)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (hypothesis_id, assertion_id)
                   DO UPDATE SET stance = EXCLUDED.stance""",
                (hypothesis_id, evidence[index][0], stance))
        print(f"  H  {statement[:58]}  ({len(stances)} assessed)")

    print("\nOpen the Hypotheses pane. The one an analyst reaches for first "
          "is NOT the one that survives — that is the method working, not a "
          "seeding mistake.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

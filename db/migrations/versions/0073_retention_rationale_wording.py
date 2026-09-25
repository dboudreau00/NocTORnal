"""Reword the two seeded retention rationales that cite design documents on
screen (L6, 2026-09-24).

## What was wrong

0032 seeds six placeholder retention rules, and the Retention pane prints
each rule's rationale verbatim. Two of them cite documents an operator
does not have: STEALER_LOG's names "docs/12" and CHAT_EXPORT's "docs/16
L4". The citation was for the people who wrote the seed, and the pane is
read by the people who confirm the rule.

## What this changes

Those two rationales, and only while a rule is exactly as 0032 seeded it:
the same text byte for byte, the same period, and unconfirmed. A rule
somebody has confirmed or edited is theirs, even if it cites a document,
and is left alone. The other four seeded rationales cite nothing and are
not touched. No period changes, so nothing about purge moves: the rules
stay placeholders until a person confirms them (docs/16 D3).

The new words state the exposure and leave the legal question to
counsel; neither states a legal determination.

Every rule it rewords gets `updated_at` and a RETENTION_RULE_REWORDED
audit row (actor SYSTEM, from, to, the period unchanged), as a governance
change should. `object_id` is NULL because a rule's key is its category,
which the detail carries, as RETENTION_RULE_CONFIRMED's does. One
statement, so it commits whole; run again it changes nothing. On a fresh
install it writes two audit rows (0032 seeds the old text, this rewords
it), which is true and harmless.

## Downgrade

The same statement the other way: a rule still carrying the new text,
unconfirmed and at its seeded period, gets the seeded text back, with an
audit row saying so.
"""
from __future__ import annotations

from alembic import op

revision = "0073"
down_revision = "0072"
branch_labels = None
depends_on = None

#: 0032's seed for the two rules this rewords: (period, text). Held to
#: 0032's `_DEFAULT_RULES` by test_retention_wording_pg.py.
SEEDED: dict[str, tuple[int, str]] = {
    "STEALER_LOG": (90, "Third-party personal data at scale. docs/12: the "
                        "most likely route by which this platform becomes a "
                        "data protection incident."),
    "CHAT_EXPORT": (730, "May contain uninvolved third parties in group "
                         "channels (docs/16 L4)."),
}

REWORDED: dict[str, str] = {
    "STEALER_LOG": ("Third-party personal data at scale: the stolen "
                    "credentials, cookies and documents of people who are "
                    "not the subject. This is the likeliest way for the "
                    "platform to become a data protection incident."),
    "CHAT_EXPORT": ("May contain the messages of uninvolved third parties in "
                    "group channels. Whether those may be kept at all, and "
                    "for how long, is for counsel to settle."),
}


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def reword_sql(*, forward: bool) -> str:
    """One statement: reword each untouched rule and audit each change.
    `forward=False` is the downgrade: the new text back to the seed."""
    rows = []
    for category, (days, seeded) in SEEDED.items():
        old, new = ((seeded, REWORDED[category]) if forward
                    else (REWORDED[category], seeded))
        rows.append(f"({_lit(category)}, {days}, {_lit(old)}, {_lit(new)})")
    by = ("the upgrade that reworded the seeded retention rationales"
          if forward else
          "the downgrade of the reworded retention rationales")
    return f"""
WITH wording (category, retain_days, was, now_reads) AS (
  VALUES {", ".join(rows)}),
changed AS (
  UPDATE core.retention_rule r
     SET rationale = w.now_reads, updated_at = now()
    FROM wording w
   WHERE r.category = w.category
     AND r.rationale = w.was
     AND r.retain_days = w.retain_days
     AND r.confirmed_at IS NULL AND r.confirmed_by IS NULL
  RETURNING r.category, w.was, w.now_reads)
INSERT INTO audit.event
       (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
SELECT NULL, 'SYSTEM', 'RETENTION_RULE_REWORDED', 'retention_rule', NULL,
       NULL,
       jsonb_build_object('category', category, 'from', was, 'to', now_reads,
                          'period', 'unchanged', 'by', {_lit(by)})
  FROM changed;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(reword_sql(forward=True))


def downgrade() -> None:
    run(reword_sql(forward=False))

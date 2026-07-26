"""Some exhibits are attacker-authored code, and the schema must say so.

docs/19. Invariant 10 — "samples never render, never execute" — was
written about malware. A saved phishing page is the same hazard with a
different extension: attacker-authored HTML and JavaScript, held in
evidence, one careless render away from executing inside an authenticated
analyst's session on the case system. So is a `.eml` with an HTML body,
and so is a HAR, which is a JSON envelope around the same bytes.

`lab.sample` solved this with a whole subsystem — encryption at rest, a
separate origin, an explicit policy gate. That is right for malware and
far too heavy for a captured login page, which an analyst legitimately
needs to look at (the screenshot) while never being served the code (the
DOM). The split has to be per-exhibit, so it lives on the exhibit.

`is_hostile_markup` marks bytes that may be downloaded and may never be
rendered by the API origin. `EvidenceService` sets it from a media-type
allowlist at ingest, and the read paths consult the column rather than
re-deriving the judgement — one rule, one place, per the lesson from F19
where a rule enforced in application code held only until somebody wrote
the second caller.

## Why the default is false, and why that is safe

Every existing row predates any capture subsystem: they arrived through
`EvidenceService.ingest` from an analyst upload or a collector, and the
only route that serves them is `/content`, which already forces
`application/octet-stream`, `Content-Disposition: attachment` and
`nosniff`. Nothing in the system renders an exhibit inline today. The
flag is therefore not retrofitting a missing defence onto old rows; it is
the gate on the NEW inline path (`/captures/{id}/screenshot`), which is
the first code in this platform that will ever serve an exhibit for the
browser to interpret.

The backfill still marks the obvious historical cases by media type, so
that if an inline path is ever pointed at an older exhibit the answer is
already correct.
"""
from alembic import op

revision = "0046"
down_revision = "0045"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
        ALTER TABLE core.evidence
          ADD COLUMN is_hostile_markup boolean NOT NULL DEFAULT false
    """)
    run("""
        COMMENT ON COLUMN core.evidence.is_hostile_markup IS
        'Attacker-authored markup/code (DOM, HAR, .eml, SVG). Download-only, '
        'and only from the separate sample origin. Never rendered inline by '
        'the API origin. See docs/19 and invariant 10.'
    """)

    # Backfill by media type. Deliberately broad: over-marking costs an
    # analyst one extra click, under-marking costs a stored-XSS in the
    # highest-trust session in the estate. SVG is in the list because an
    # SVG is a script container that happens to draw — it is the one
    # "image" type that must never reach an <img> render path.
    run("""
        UPDATE core.evidence
           SET is_hostile_markup = true
         WHERE lower(media_type) = ANY (ARRAY[
                 'text/html','application/xhtml+xml','image/svg+xml',
                 'application/xml','text/xml','message/rfc822',
                 'application/mbox','text/x-mail',
                 'application/x-har','application/json+har'])
            OR lower(media_type) LIKE 'text/html;%'
            OR lower(media_type) LIKE 'message/rfc822;%'
    """)

    # A partial index: the interesting query is always "is this one
    # hostile", answered by the row itself, but the audit question
    # "what hostile bytes does this case hold" wants the small side.
    run("""
        CREATE INDEX evidence_hostile_idx ON core.evidence (case_id)
         WHERE is_hostile_markup
    """)


def downgrade() -> None:
    run("DROP INDEX IF EXISTS core.evidence_hostile_idx")
    run("ALTER TABLE core.evidence DROP COLUMN IF EXISTS is_hostile_markup")

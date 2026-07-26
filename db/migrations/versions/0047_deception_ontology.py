"""Vocabulary for social-engineering evidence: LURE, IMPERSONATES, four
selectors, and one widened edge.

docs/19 §3.4. `CONVENTIONS.md` says to ask before adding a node or edge type
that duplicates an existing one, so this is deliberately two additions and
not twelve. A phishing host is already `INFRA`, a kit is `TOOL`, a victim
is `VICTIM`, a call is an `EVENT`. Two things had no home:

`LURE` — the pretext itself. Distinct from `TOOL` (the kit that generates
it) and from `CAMPAIGN` (time-bounded, actor-scoped). Lures outlive both.

`IMPERSONATES` — a FALSE identity claim. `ALIAS_OF` and `SAME_AS` both
assert the subjects *are* the same entity; impersonation asserts the
opposite. Nothing existing could carry "this page claims to be Microsoft".

## The two flags on IMPERSONATES are the whole point

`is_social_tie = false`, `default_sign = 0`. If impersonation counted as
an affiliation, the impersonated brand would become the highest-degree,
highest-betweenness node in every phishing case in the system — Microsoft
brokering the entire criminal underworld — and every centrality ranking
downstream would be quietly wrong. Invariant 4's concern ("inferred edges
stay structurally distinct") arriving through a new edge type rather than
through inference.

## TARGETED is widened rather than duplicated

`{IDENTITY,GROUP,CAMPAIGN} -> {VICTIM,ORGANISATION}` becomes
`{IDENTITY,GROUP,CAMPAIGN,LURE,INFRA} -> {VICTIM,ORGANISATION,PERSON}`.
"This pretext was aimed at that victim" is the same relation as "this
actor was aimed at that victim" with a different subject; a parallel
`DELIVERED_TO` would have split one question across two edge types
forever. `PERSON` joins the destination set because BEC targets a named
finance officer, not an abstract org.

Widening a source/destination set can only ADMIT edges that were
previously rejected, so no existing row can be invalidated. The check
runs on write, and every stored edge already satisfied a subset of the
new rule.

## Why this is a migration and not a re-run of the seed

`packages/ontology/generated/seed_ontology.sql` is `ON CONFLICT DO
NOTHING`, so re-applying it over a CHANGED row silently keeps the old
one — which is exactly the case for `TARGETED` here. The generated seed
bootstraps an empty database; vocabulary changes ship as data migrations.
"""
from alembic import op

revision = "0047"
down_revision = "0046"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
        INSERT INTO core.node_type (key, display_name, category, colour_token, sort_order)
        VALUES ('LURE', 'Lure / pretext', 'ARTEFACT', 'artefact.lure', 125)
        ON CONFLICT (key) DO NOTHING
    """)

    run("""
        INSERT INTO core.edge_type
            (key, display_name, inverse_name, is_directed, default_sign,
             src_node_types, dst_node_types, is_social_tie)
        VALUES
            ('IMPERSONATES', 'impersonates', 'is impersonated by', true, 0,
             '{IDENTITY,LURE,COMMS_ACCOUNT}', '{ORGANISATION,PERSON,SERVICE}', false)
        ON CONFLICT (key) DO NOTHING
    """)

    # DO UPDATE, not DO NOTHING: this row exists and must change.
    run("""
        UPDATE core.edge_type
           SET src_node_types = '{IDENTITY,GROUP,CAMPAIGN,LURE,INFRA}',
               dst_node_types = '{VICTIM,ORGANISATION,PERSON}'
         WHERE key = 'TARGETED'
    """)

    run("""
        INSERT INTO core.selector_type (key, display_name, is_strong, is_pii, normaliser)
        VALUES
            ('TLS_SPKI',     'TLS public-key hash', true,  false, 'lower_hex'),
            ('SIP_URI',      'SIP URI',             true,  true,  'sip_norm'),
            ('EMAIL_MSGID',  'Email Message-ID',    false, false, 'msgid_norm'),
            ('FAVICON_MMH3', 'Favicon hash',        false, false, 'trim')
        ON CONFLICT (key) DO NOTHING
    """)


def downgrade() -> None:
    # Vocabulary rows are only removable while nothing references them.
    # A DELETE that silently took graph elements with it would be a
    # migration destroying case data, so this fails loudly on the FK
    # instead — the operator can see what is still using the type.
    run("""
        UPDATE core.edge_type
           SET src_node_types = '{IDENTITY,GROUP,CAMPAIGN}',
               dst_node_types = '{VICTIM,ORGANISATION}'
         WHERE key = 'TARGETED'
    """)
    run("DELETE FROM core.selector_type WHERE key IN "
        "('TLS_SPKI','SIP_URI','EMAIL_MSGID','FAVICON_MMH3')")
    run("DELETE FROM core.edge_type WHERE key = 'IMPERSONATES'")
    run("DELETE FROM core.node_type WHERE key = 'LURE'")

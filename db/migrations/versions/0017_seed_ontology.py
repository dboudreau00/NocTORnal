"""Seed ontology: node/edge/selector vocabularies, roles, permissions.

Data migration, idempotent (ON CONFLICT DO NOTHING on the key PKs) so a
manual re-run is safe. Downgrade deletes exactly the seeded keys and
nothing an analyst added — and fails loudly if seeded rows are in use.
Mirrors db/seed_ontology.sql, which stays as the readable reference.
"""
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


NODE_TYPE_KEYS = (
    "'IDENTITY','PERSON','GROUP','SUBGROUP','ORGANISATION','VICTIM',"
    "'SELECTOR','WALLET','SERVICE','FORUM','CHANNEL','MALWARE','INFRA',"
    "'CREDENTIAL_SET','DATASET','TOOL','EVENT','CAMPAIGN','INCIDENT',"
    "'LOCATION','TRANSACTION','COMMS_ACCOUNT','DEVICE','CONVERSATION',"
    "'SAMPLE','BUILDER'"
)

EDGE_TYPE_KEYS = (
    "'SAME_AS','ALIAS_OF','ATTRIBUTED_TO','CONTROLS','MEMBER_OF','LEADS',"
    "'AFFILIATE_OF','SPLINTER_OF','REBRAND_OF','RIVAL_OF','VOUCHED_FOR',"
    "'GUARANTOR_FOR','ESCROW_FOR','ACCUSED_SCAM','DISPUTED_WITH','BANNED_BY',"
    "'COMMUNICATES_WITH','CO_POSTED_IN','REPLIED_TO','MET_WITH','POSTS_ON',"
    "'SOLD_TO','BROKERED_ACCESS','LAUNDERED_FOR','RECRUITED','MENTORED',"
    "'PAID','DEVELOPED','USED','TARGETED','HOSTED_ON','PART_OF','SHARED_INFRA',"
    "'LOCATED_IN','PARTICIPATED_IN','USES_ACCOUNT','ON_DEVICE','SAME_DEVICE_AS',"
    "'PARTICIPANT_IN','CO_DECLARED_WITH','CONFIRMED_CONTROL_OF','SAMPLE_OF',"
    "'BUILT_WITH','CLUSTERS_WITH','CONTACTS_C2','SUBMITTED_SAMPLE'"
)

SELECTOR_TYPE_KEYS = (
    "'HANDLE','FORUM_UID','TELEGRAM_ID','TELEGRAM_USER','DISCORD_ID','JABBER',"
    "'SESSION_ID','ICQ','EMAIL','PHONE','PGP_FPR','SSH_KEY','BTC_ADDR',"
    "'ETH_ADDR','XMR_ADDR','TRON_ADDR','DOMAIN','ONION','IPV4','IPV6','ASN',"
    "'URL','HASH_MD5','HASH_SHA1','HASH_SHA256','IMEI','BANK_ACCT',"
    "'LICENCE_PLATE','DOC_NUMBER','SOCIAL_URL','TOX_PK','TOX_ID_FULL',"
    "'OMEMO_FPR','MATRIX_MXID','MATRIX_DEVKEY','WIRE_HANDLE','WIRE_UUID',"
    "'THREEMA_ID','SIGNAL_ACI','BRIAR_LINK','SKYPE_ID','IMPHASH','RICH_HEADER',"
    "'SSDEEP','TLSH','MUTEX','PDB_PATH','CODESIGN_CN','USER_AGENT'"
)

ROLE_KEYS = (
    "'SYS_ADMIN','SECURITY_OFFICER','CASE_OWNER','ANALYST','COLLECTOR',"
    "'REVIEWER','CONTRIBUTOR','READ_ONLY','LIAISON','SERVICE'"
)

PERMISSION_KEYS = (
    "'case.create','case.read','case.update','case.close','case.delete',"
    "'case.grant','graph.node.create','graph.node.update','graph.node.delete',"
    "'graph.edge.create','graph.edge.update','graph.merge','graph.unmerge',"
    "'assertion.create','assertion.retract','proposal.review','evidence.upload',"
    "'evidence.read','evidence.export','evidence.purge','source.manage',"
    "'watch.manage','collection_account.manage','collection_account.reveal',"
    "'analytics.run','report.generate','report.export','user.manage',"
    "'role.manage','audit.read','integration.manage','break_glass.invoke'"
)


def upgrade() -> None:
    run("""
SET search_path = core, public;

INSERT INTO node_type (key, display_name, category, colour_token, sort_order) VALUES
-- ACTOR layer. The critical split: IDENTITY is what you observe, PERSON is
-- what you assess. Never collapse them.
('IDENTITY',   'Persona',            'ACTOR',   'actor.persona',  10),
('PERSON',     'Assessed person',    'ACTOR',   'actor.person',   20),
('GROUP',      'Group',              'ACTOR',   'actor.group',    30),
('SUBGROUP',   'Cell / sub-unit',    'ACTOR',   'actor.group',    35),
('ORGANISATION','Legal entity',      'ACTOR',   'actor.org',      40),
('VICTIM',     'Victim entity',      'ACTOR',   'actor.victim',   50),
-- ARTEFACT layer
('SELECTOR',   'Selector',           'ARTEFACT','artefact.selector', 60),
('WALLET',     'Crypto wallet',      'ARTEFACT','artefact.finance',  70),
('SERVICE',    'Service / shop',     'ARTEFACT','artefact.service',  80),
('FORUM',      'Forum / board',      'ARTEFACT','artefact.venue',    85),
('CHANNEL',    'Channel / group chat','ARTEFACT','artefact.venue',   86),
('MALWARE',    'Malware family',     'ARTEFACT','artefact.malware',  90),
('INFRA',      'Infrastructure',     'ARTEFACT','artefact.infra',   100),
('CREDENTIAL_SET','Credential set',  'ARTEFACT','artefact.data',    110),
('DATASET',    'Leaked dataset',     'ARTEFACT','artefact.data',    115),
('TOOL',       'Tool / kit',         'ARTEFACT','artefact.malware', 120),
-- CONTEXT layer
('EVENT',      'Event',              'CONTEXT', 'context.event',   130),
('CAMPAIGN',   'Campaign',           'CONTEXT', 'context.campaign',140),
('INCIDENT',   'Incident',           'CONTEXT', 'context.incident',150),
('LOCATION',   'Location',           'CONTEXT', 'context.location',160),
('TRANSACTION','Transaction',        'CONTEXT', 'context.finance', 170),
-- Comms / malware additions (docs 10-11)
('COMMS_ACCOUNT','Comms account',  'ARTEFACT','artefact.comms',   62),
('DEVICE',       'Device',         'ARTEFACT','artefact.device',  64),
('CONVERSATION', 'Conversation',   'CONTEXT', 'context.comms',   135),
('SAMPLE',       'Malware sample', 'ARTEFACT','artefact.malware', 92),
('BUILDER',      'Builder / kit',  'ARTEFACT','artefact.malware', 94)
ON CONFLICT (key) DO NOTHING;

INSERT INTO edge_type (key, display_name, inverse_name, is_directed, default_sign, src_node_types, dst_node_types, is_social_tie) VALUES
-- Identity resolution (structural, NOT social)
('SAME_AS',        'is the same as',      'is the same as',   false,  0, '{IDENTITY,PERSON}','{IDENTITY,PERSON}', false),
('ALIAS_OF',       'is an alias of',      'has alias',        true,   0, '{IDENTITY}','{IDENTITY}',              false),
('ATTRIBUTED_TO',  'attributed to',       'has persona',      true,   0, '{IDENTITY}','{PERSON}',               false),
('CONTROLS',       'controls',            'controlled by',    true,   0, '{IDENTITY,PERSON,GROUP}','{SELECTOR,WALLET,INFRA,SERVICE,CHANNEL}', false),
-- Membership & structure
('MEMBER_OF',      'is a member of',      'has member',       true,   1, '{IDENTITY,PERSON,SUBGROUP}','{GROUP,SUBGROUP}', true),
('LEADS',          'leads',               'is led by',        true,   1, '{IDENTITY,PERSON}','{GROUP,SUBGROUP}',  true),
('AFFILIATE_OF',   'is an affiliate of',  'has affiliate',    true,   1, '{IDENTITY,PERSON,GROUP}','{GROUP}',     true),
('SPLINTER_OF',    'split from',          'spawned',          true,   0, '{GROUP}','{GROUP}',                    false),
('REBRAND_OF',     'is a rebrand of',     'rebranded as',     true,   0, '{GROUP}','{GROUP}',                    false),
('RIVAL_OF',       'is a rival of',       'is a rival of',    false, -1, '{GROUP,IDENTITY}','{GROUP,IDENTITY}',  true),
-- Trust layer. This is what makes it a trust network.
('VOUCHED_FOR',    'vouched for',         'was vouched by',   true,   1, '{IDENTITY}','{IDENTITY}',              true),
('GUARANTOR_FOR',  'acted as guarantor',  'used guarantor',   true,   1, '{IDENTITY}','{IDENTITY}',              true),
('ESCROW_FOR',     'held escrow for',     'used escrow',      true,   1, '{IDENTITY}','{IDENTITY}',              true),
('ACCUSED_SCAM',   'accused of ripping',  'was accused by',   true,  -1, '{IDENTITY}','{IDENTITY}',              true),
('DISPUTED_WITH',  'in dispute with',     'in dispute with',  false, -1, '{IDENTITY}','{IDENTITY}',              true),
('BANNED_BY',      'was banned by',       'banned',           true,  -1, '{IDENTITY}','{FORUM,CHANNEL,IDENTITY}',false),
-- Interaction
('COMMUNICATES_WITH','communicates with', 'communicates with',false,  1, '{IDENTITY,PERSON}','{IDENTITY,PERSON}',true),
('CO_POSTED_IN',   'co-posted in',        'co-posted in',     false,  1, '{IDENTITY}','{IDENTITY}',              true),
('REPLIED_TO',     'replied to',          'was replied to by',true,   1, '{IDENTITY}','{IDENTITY}',              true),
('MET_WITH',       'met with',            'met with',         false,  1, '{PERSON}','{PERSON}',                  true),
('POSTS_ON',       'posts on',            'has poster',       true,   0, '{IDENTITY}','{FORUM,CHANNEL}',         false),
-- Commercial / criminal function
('SOLD_TO',        'sold to',             'bought from',      true,   1, '{IDENTITY}','{IDENTITY}',              true),
('BROKERED_ACCESS','brokered access to',  'access brokered by',true,  1, '{IDENTITY}','{VICTIM,ORGANISATION}',   true),
('LAUNDERED_FOR',  'laundered for',       'used launderer',   true,   1, '{IDENTITY,SERVICE}','{IDENTITY,GROUP}',true),
('RECRUITED',      'recruited',           'was recruited by', true,   1, '{IDENTITY}','{IDENTITY}',              true),
('MENTORED',       'mentored',            'was mentored by',  true,   1, '{IDENTITY}','{IDENTITY}',              true),
('PAID',           'paid',                'was paid by',      true,   1, '{IDENTITY,WALLET}','{IDENTITY,WALLET}',true),
-- Operational
('DEVELOPED',      'developed',           'developed by',     true,   0, '{IDENTITY,PERSON,GROUP}','{MALWARE,TOOL,SERVICE}', false),
('USED',           'used',                'used by',          true,   0, '{IDENTITY,PERSON,GROUP}','{MALWARE,TOOL,INFRA,SERVICE}', false),
('TARGETED',       'targeted',            'was targeted by',  true,   0, '{IDENTITY,GROUP,CAMPAIGN}','{VICTIM,ORGANISATION}', false),
('HOSTED_ON',      'is hosted on',        'hosts',            true,   0, '{SERVICE,INFRA,FORUM}','{INFRA}',      false),
('PART_OF',        'is part of',          'includes',         true,   0, '{INCIDENT,EVENT}','{CAMPAIGN}',        false),
('SHARED_INFRA',   'shares infrastructure with','shares infrastructure with', false, 1, '{IDENTITY,GROUP,SERVICE}','{IDENTITY,GROUP,SERVICE}', true),
-- Context
('LOCATED_IN',     'is located in',       'contains',         true,   0, '{PERSON,ORGANISATION,INFRA}','{LOCATION}', false),
('PARTICIPATED_IN','participated in',     'had participant',  true,   0, '{IDENTITY,PERSON,GROUP}','{EVENT,INCIDENT,CAMPAIGN}', false),
-- Comms plumbing — structural, not social (docs 10)
('USES_ACCOUNT',      'uses account',        'account used by',   true, 0, '{IDENTITY,PERSON,GROUP}','{COMMS_ACCOUNT}', false),
('ON_DEVICE',         'observed on device',  'has account',       true, 0, '{COMMS_ACCOUNT}','{DEVICE}',               false),
('SAME_DEVICE_AS',    'shares a device with','shares a device with',false,0,'{COMMS_ACCOUNT,IDENTITY}','{COMMS_ACCOUNT,IDENTITY}', true),
('PARTICIPANT_IN',    'participates in',     'has participant',   true, 1, '{COMMS_ACCOUNT,IDENTITY}','{CONVERSATION}', true),
('CO_DECLARED_WITH',  'declared alongside',  'declared alongside',false,1, '{SELECTOR,COMMS_ACCOUNT}','{SELECTOR,COMMS_ACCOUNT}', false),
('CONFIRMED_CONTROL_OF','confirmed control of','control confirmed by',true,0,'{IDENTITY,PERSON}','{SELECTOR,COMMS_ACCOUNT,WALLET}', false),
-- Sample and builder lineage (docs 11)
('SAMPLE_OF',         'is a sample of',      'has sample',        true, 0, '{SAMPLE}','{MALWARE}',                     false),
('BUILT_WITH',        'was built with',      'built',             true, 0, '{SAMPLE}','{BUILDER,TOOL}',                false),
('CLUSTERS_WITH',     'clusters with',       'clusters with',     false,0, '{SAMPLE}','{SAMPLE}',                      false),
('CONTACTS_C2',       'contacts',            'contacted by',      true, 0, '{SAMPLE,MALWARE}','{INFRA}',               false),
('SUBMITTED_SAMPLE',  'submitted sample',    'submitted by',      true, 0, '{IDENTITY,PERSON}','{SAMPLE}',             false)
ON CONFLICT (key) DO NOTHING;

INSERT INTO selector_type (key, display_name, is_strong, is_pii, normaliser) VALUES
('HANDLE',        'Handle / nickname',      false, false, 'lower_trim'),
('FORUM_UID',     'Forum user ID',          true,  false, 'exact'),
('TELEGRAM_ID',   'Telegram numeric ID',    true,  false, 'digits'),
-- @usernames are recycled by Telegram after release. Treat as weak; the
-- numeric ID is the durable identifier.
('TELEGRAM_USER', 'Telegram @username',     false, false, 'lower_strip_at'),
('DISCORD_ID',    'Discord snowflake',      true,  false, 'digits'),
('JABBER',        'XMPP / Jabber',          true,  false, 'lower_trim'),
('SESSION_ID',    'Session ID',             true,  false, 'exact'),
('ICQ',           'ICQ number',             true,  false, 'digits'),
('EMAIL',         'Email address',          true,  true,  'email_norm'),
('PHONE',         'Phone number',           true,  true,  'e164'),
('PGP_FPR',       'PGP fingerprint',        true,  false, 'upper_hex_nospace'),
('SSH_KEY',       'SSH public key',         true,  false, 'ssh_norm'),
('BTC_ADDR',      'Bitcoin address',        true,  false, 'btc_norm'),
('ETH_ADDR',      'Ethereum address',       true,  false, 'eip55'),
('XMR_ADDR',      'Monero address',         true,  false, 'exact'),
('TRON_ADDR',     'Tron address',           true,  false, 'exact'),
('DOMAIN',        'Domain',                 false, false, 'punycode_lower'),
('ONION',         'Onion service',          true,  false, 'lower_trim'),
('IPV4',          'IPv4 address',           false, false, 'ip_norm'),
('IPV6',          'IPv6 address',           false, false, 'ip_norm'),
('ASN',           'Autonomous system',      false, false, 'asn_norm'),
('URL',           'URL',                    false, false, 'url_norm'),
('HASH_MD5',      'MD5',                    true,  false, 'lower_hex'),
('HASH_SHA1',     'SHA-1',                  true,  false, 'lower_hex'),
('HASH_SHA256',   'SHA-256',                true,  false, 'lower_hex'),
('IMEI',          'IMEI',                   true,  true,  'digits'),
('BANK_ACCT',     'Bank account',           true,  true,  'exact'),
('LICENCE_PLATE', 'Vehicle plate',          true,  true,  'upper_nospace'),
('DOC_NUMBER',    'Identity document',      true,  true,  'upper_nospace'),
('SOCIAL_URL',    'Social profile URL',     false, true,  'url_norm'),
-- Comms selectors (docs 10). TOX_PK is the durable 64-hex public key
-- (invariant 9); TOX_ID_FULL is the weak as-observed 76-hex form.
('TOX_PK',        'Tox public key (64 hex)', true,  false, 'tox_pubkey'),
('TOX_ID_FULL',   'Tox ID as observed (76)', false, false, 'upper_hex'),
('OMEMO_FPR',     'OMEMO device fingerprint',true,  false, 'lower_hex_nospace'),
('MATRIX_MXID',   'Matrix MXID',             true,  false, 'lower_trim'),
('MATRIX_DEVKEY', 'Matrix device key',       true,  false, 'exact'),
('WIRE_HANDLE',   'Wire handle',             false, false, 'lower_strip_at'),
('WIRE_UUID',     'Wire account UUID',       true,  false, 'lower_trim'),
('THREEMA_ID',    'Threema ID',              true,  false, 'upper_nospace'),
('SIGNAL_ACI',    'Signal ACI',              true,  true,  'lower_trim'),
('BRIAR_LINK',    'Briar contact link',      true,  false, 'exact'),
('SKYPE_ID',      'Skype name',              true,  true,  'lower_trim'),
-- Build-environment clustering (docs 11)
('IMPHASH',       'Import hash',             false, false, 'lower_hex'),
('RICH_HEADER',   'Rich header hash',        false, false, 'lower_hex'),
('SSDEEP',        'ssdeep fuzzy hash',       false, false, 'exact'),
('TLSH',          'TLSH fuzzy hash',         false, false, 'upper_nospace'),
('MUTEX',         'Mutex name',              false, false, 'exact'),
('PDB_PATH',      'PDB path',                true,  false, 'lower_trim'),
('CODESIGN_CN',   'Code-signing subject',    true,  false, 'trim'),
('USER_AGENT',    'User agent string',       false, false, 'trim')
ON CONFLICT (key) DO NOTHING;

SET search_path = iam, core, public;

-- Note SECURITY_OFFICER: can read the audit trail but NOT case content.
INSERT INTO role (key, display_name, description, is_system) VALUES
('SYS_ADMIN',        'System administrator', 'Platform config, users, integrations. No default case access.', true),
('SECURITY_OFFICER', 'Security officer',     'Audit review, break-glass review, key rotation. Cannot read case content.', true),
('CASE_OWNER',       'Case owner',           'Full control of assigned cases including access grants.', true),
('ANALYST',          'Analyst',              'Create and edit graph, evidence, assertions on assigned cases.', true),
('COLLECTOR',        'Collection manager',   'Manage sources, watches, collection accounts.', true),
('REVIEWER',         'Reviewer',             'Approve proposals and merges; cannot originate.', true),
('CONTRIBUTOR',      'Contributor',          'Upload evidence and propose changes; cannot accept them.', true),
('READ_ONLY',        'Read only',            'View assigned cases.', true),
('LIAISON',          'External liaison',     'Time-boxed, TLP-capped, export-disabled view of one case.', true),
('SERVICE',          'Service account',      'Machine identity for collectors and integrations.', true)
ON CONFLICT (key) DO NOTHING;

INSERT INTO permission (key, description, requires_step_up, requires_dual_control) VALUES
('case.create',        'Create a case', false, false),
('case.read',          'Read case content', false, false),
('case.update',        'Edit case metadata', false, false),
('case.close',         'Close a case', false, false),
('case.delete',        'Delete a case and its content', true, true),
('case.grant',         'Grant case access to a user', true, false),
('graph.node.create',  'Create nodes', false, false),
('graph.node.update',  'Edit nodes', false, false),
('graph.node.delete',  'Soft-delete nodes', false, false),
('graph.edge.create',  'Create edges', false, false),
('graph.edge.update',  'Edit edges', false, false),
('graph.merge',        'Merge two identities', true, false),
('graph.unmerge',      'Reverse a merge', true, false),
('assertion.create',   'Record an assertion', false, false),
('assertion.retract',  'Retract an assertion', false, false),
('proposal.review',    'Accept or reject machine proposals', false, false),
('evidence.upload',    'Upload evidence', false, false),
('evidence.read',      'View evidence', false, false),
('evidence.export',    'Export evidence outside the platform', true, false),
('evidence.purge',     'Destroy evidence', true, true),
('source.manage',      'Create and edit sources', false, false),
('watch.manage',       'Create and edit watches', false, false),
('collection_account.manage', 'Manage collection personas', true, false),
('collection_account.reveal', 'Decrypt persona credentials', true, true),
('analytics.run',      'Run SNA metrics', false, false),
('report.generate',    'Generate a report', false, false),
('report.export',      'Export a report', true, false),
('user.manage',        'Create and edit users', true, false),
('role.manage',        'Change role definitions', true, true),
('audit.read',         'Read the audit trail', false, false),
('integration.manage', 'Configure SMTP, Jira, webhooks', true, false),
('break_glass.invoke', 'Emergency access to an unassigned case', true, false)
ON CONFLICT (key) DO NOTHING;
""")


def downgrade() -> None:
    run(f"""
DELETE FROM iam.permission WHERE key IN ({PERMISSION_KEYS});
DELETE FROM iam.role WHERE key IN ({ROLE_KEYS});
DELETE FROM core.selector_type WHERE key IN ({SELECTOR_TYPE_KEYS});
DELETE FROM core.edge_type WHERE key IN ({EDGE_TYPE_KEYS});
DELETE FROM core.node_type WHERE key IN ({NODE_TYPE_KEYS});
""")

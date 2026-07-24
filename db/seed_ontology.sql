-- =====================================================================
-- NocTORnal — seed ontology
-- This is the vocabulary of the domain. Get it right and the product
-- feels native to analysts; get it wrong and every case fights the tool.
-- Extend freely — these are rows, not migrations.
--
-- REFERENCE ONLY since 2026-07-24: the authoritative seed is Alembic
-- revision 0017 in db/migrations/versions/ (idempotent). Keep in sync.
-- =====================================================================
SET search_path = core, public;

-- ---------------------------------------------------------------------
-- NODE TYPES
-- ---------------------------------------------------------------------
INSERT INTO node_type (key, display_name, category, colour_token, sort_order) VALUES
-- ACTOR layer -------------------------------------------------------
-- The critical split. IDENTITY is what you observe. PERSON is what you
-- assess. Never collapse them: the whole discipline of attribution lives
-- in the gap between the two.
('IDENTITY',   'Persona',            'ACTOR',   'actor.persona',  10),
('PERSON',     'Assessed person',    'ACTOR',   'actor.person',   20),
('GROUP',      'Group',              'ACTOR',   'actor.group',    30),
('SUBGROUP',   'Cell / sub-unit',    'ACTOR',   'actor.group',    35),
('ORGANISATION','Legal entity',      'ACTOR',   'actor.org',      40),
('VICTIM',     'Victim entity',      'ACTOR',   'actor.victim',   50),

-- ARTEFACT layer ------------------------------------------------------
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

-- CONTEXT layer -------------------------------------------------------
('EVENT',      'Event',              'CONTEXT', 'context.event',   130),
('CAMPAIGN',   'Campaign',           'CONTEXT', 'context.campaign',140),
('INCIDENT',   'Incident',           'CONTEXT', 'context.incident',150),
('LOCATION',   'Location',           'CONTEXT', 'context.location',160),
('TRANSACTION','Transaction',        'CONTEXT', 'context.finance', 170);

-- ---------------------------------------------------------------------
-- EDGE TYPES
-- is_social_tie = false for identity plumbing. If SAME_AS edges enter a
-- centrality calculation, your most "central" node becomes whichever
-- persona you happened to research hardest. This flag prevents that.
-- ---------------------------------------------------------------------
INSERT INTO edge_type (key, display_name, inverse_name, is_directed, default_sign, src_node_types, dst_node_types, is_social_tie) VALUES

-- Identity resolution (structural, NOT social) -------------------------
('SAME_AS',        'is the same as',      'is the same as',   false,  0, '{IDENTITY,PERSON}','{IDENTITY,PERSON}', false),
('ALIAS_OF',       'is an alias of',      'has alias',        true,   0, '{IDENTITY}','{IDENTITY}',              false),
('ATTRIBUTED_TO',  'attributed to',       'has persona',      true,   0, '{IDENTITY}','{PERSON}',               false),
('CONTROLS',       'controls',            'controlled by',    true,   0, '{IDENTITY,PERSON,GROUP}','{SELECTOR,WALLET,INFRA,SERVICE,CHANNEL,DATASET,CREDENTIAL_SET}', false),

-- Membership & structure ----------------------------------------------
('MEMBER_OF',      'is a member of',      'has member',       true,   1, '{IDENTITY,PERSON,SUBGROUP}','{GROUP,SUBGROUP}', true),
('LEADS',          'leads',               'is led by',        true,   1, '{IDENTITY,PERSON}','{GROUP,SUBGROUP}',  true),
('AFFILIATE_OF',   'is an affiliate of',  'has affiliate',    true,   1, '{IDENTITY,PERSON,GROUP}','{GROUP}',     true),
('SPLINTER_OF',    'split from',          'spawned',          true,   0, '{GROUP}','{GROUP}',                    false),
('REBRAND_OF',     'is a rebrand of',     'rebranded as',     true,   0, '{GROUP}','{GROUP}',                    false),
('RIVAL_OF',       'is a rival of',       'is a rival of',    false, -1, '{GROUP,IDENTITY}','{GROUP,IDENTITY}',  true),

-- Trust layer. This is what makes it a trust network. -----------------
('VOUCHED_FOR',    'vouched for',         'was vouched by',   true,   1, '{IDENTITY}','{IDENTITY}',              true),
('GUARANTOR_FOR',  'acted as guarantor',  'used guarantor',   true,   1, '{IDENTITY}','{IDENTITY}',              true),
('ESCROW_FOR',     'held escrow for',     'used escrow',      true,   1, '{IDENTITY}','{IDENTITY}',              true),
('ACCUSED_SCAM',   'accused of ripping',  'was accused by',   true,  -1, '{IDENTITY}','{IDENTITY}',              true),
('DISPUTED_WITH',  'in dispute with',     'in dispute with',  false, -1, '{IDENTITY}','{IDENTITY}',              true),
('BANNED_BY',      'was banned by',       'banned',           true,  -1, '{IDENTITY}','{FORUM,CHANNEL,IDENTITY}',false),

-- Interaction ----------------------------------------------------------
('COMMUNICATES_WITH','communicates with', 'communicates with',false,  1, '{IDENTITY,PERSON}','{IDENTITY,PERSON}',true),
('CO_POSTED_IN',   'co-posted in',        'co-posted in',     false,  1, '{IDENTITY}','{IDENTITY}',              false),
('REPLIED_TO',     'replied to',          'was replied to by',true,   1, '{IDENTITY}','{IDENTITY}',              true),
('MET_WITH',       'met with',            'met with',         false,  1, '{PERSON}','{PERSON}',                  true),
('POSTS_ON',       'posts on',            'has poster',       true,   0, '{IDENTITY}','{FORUM,CHANNEL}',         false),

-- Commercial / criminal function --------------------------------------
('SOLD_TO',        'sold to',             'bought from',      true,   1, '{IDENTITY}','{IDENTITY}',              true),
('BROKERED_ACCESS','brokered access to',  'access brokered by',true,  1, '{IDENTITY}','{VICTIM,ORGANISATION}',   true),
('LAUNDERED_FOR',  'laundered for',       'used launderer',   true,   1, '{IDENTITY,SERVICE}','{IDENTITY,GROUP}',true),
('RECRUITED',      'recruited',           'was recruited by', true,   1, '{IDENTITY}','{IDENTITY}',              true),
('MENTORED',       'mentored',            'was mentored by',  true,   1, '{IDENTITY}','{IDENTITY}',              true),
('PAID',           'paid',                'was paid by',      true,   1, '{IDENTITY,WALLET}','{IDENTITY,WALLET}',true),

-- Finance & data provenance (0019). TRANSACTION is a proven on-chain event
-- with wallet inputs/outputs; DATASET/CREDENTIAL_SET carry breach
-- provenance. All structural (not social ties).
('TX_INPUT',         'is an input to',      'has input',        true,   0, '{WALLET}','{TRANSACTION}',           false),
('TX_OUTPUT',        'is an output of',     'has output',       true,   0, '{TRANSACTION}','{WALLET}',           false),
('EXFILTRATED_FROM', 'was exfiltrated from','source of',        true,   0, '{DATASET,CREDENTIAL_SET}','{VICTIM,ORGANISATION}', false),

-- Operational ----------------------------------------------------------
('DEVELOPED',      'developed',           'developed by',     true,   0, '{IDENTITY,PERSON,GROUP}','{MALWARE,TOOL,SERVICE}', false),
('USED',           'used',                'used by',          true,   0, '{IDENTITY,PERSON,GROUP}','{MALWARE,TOOL,INFRA,SERVICE}', false),
('TARGETED',       'targeted',            'was targeted by',  true,   0, '{IDENTITY,GROUP,CAMPAIGN}','{VICTIM,ORGANISATION}', false),
('HOSTED_ON',      'is hosted on',        'hosts',            true,   0, '{SERVICE,INFRA,FORUM}','{INFRA}',      false),
('PART_OF',        'is part of',          'includes',         true,   0, '{INCIDENT,EVENT}','{CAMPAIGN}',        false),
('SHARED_INFRA',   'shares infrastructure with','shares infrastructure with', false, 0, '{IDENTITY,GROUP,SERVICE}','{IDENTITY,GROUP,SERVICE}', false),

-- Context ---------------------------------------------------------------
('LOCATED_IN',     'is located in',       'contains',         true,   0, '{PERSON,ORGANISATION,INFRA}','{LOCATION}', false),
('PARTICIPATED_IN','participated in',     'had participant',  true,   0, '{IDENTITY,PERSON,GROUP}','{EVENT,INCIDENT,CAMPAIGN}', false);

-- ---------------------------------------------------------------------
-- SELECTOR TYPES
-- is_strong drives auto-merge candidacy. Be conservative: a false merge
-- is far more damaging than a missed one, because it silently invents
-- relationships between two real people.
-- ---------------------------------------------------------------------
INSERT INTO selector_type (key, display_name, is_strong, is_pii, normaliser) VALUES
('HANDLE',        'Handle / nickname',      false, false, 'lower_trim'),
-- NOT strong until venue-scoped: UID 42 exists on every forum (0018).
('FORUM_UID',     'Forum user ID',          false, false, 'trim'),
('TELEGRAM_ID',   'Telegram numeric ID',    true,  false, 'telegram_id_norm'),
-- @usernames are recycled by Telegram after release. Treat as weak; the
-- numeric ID is the durable identifier. Analysts get this wrong daily.
('TELEGRAM_USER', 'Telegram @username',     false, false, 'lower_strip_at'),
('DISCORD_ID',    'Discord snowflake',      true,  false, 'digits'),
('JABBER',        'XMPP / Jabber',          true,  false, 'jid_norm'),
-- Tox lives in the wave-2 block below: TOX_PK (64-hex public key) is the
-- strong, durable selector; TOX_ID_FULL is the weak as-observed 76-hex
-- form (invariant 9 — the nospam is user-rotatable). A duplicate TOX_ID
-- key was collapsed into TOX_ID_FULL pre-Phase-0 (2026-07-24).
('SESSION_ID',    'Session ID',             true,  false, 'lower_hex'),
('ICQ',           'ICQ number',             true,  false, 'digits'),
('EMAIL',         'Email address',          true,  true,  'email_norm'),
('PHONE',         'Phone number',           true,  true,  'e164'),
('PGP_FPR',       'PGP fingerprint',        true,  false, 'upper_hex_nospace'),
('SSH_KEY',       'SSH public key',         true,  false, 'ssh_norm'),
('BTC_ADDR',      'Bitcoin address',        true,  false, 'btc_norm'),
('ETH_ADDR',      'Ethereum address',       true,  false, 'eip55'),
('XMR_ADDR',      'Monero address',         true,  false, 'trim'),
('TRON_ADDR',     'Tron address',           true,  false, 'trim'),
('DOMAIN',        'Domain',                 false, false, 'punycode_lower'),
('ONION',         'Onion service',          true,  false, 'onion_norm'),
('IPV4',          'IPv4 address',           false, false, 'ip_norm'),
('IPV6',          'IPv6 address',           false, false, 'ip_norm'),
('ASN',           'Autonomous system',      false, false, 'asn_norm'),
('URL',           'URL',                    false, false, 'url_norm'),
('HASH_MD5',      'MD5',                    true,  false, 'lower_hex'),
('HASH_SHA1',     'SHA-1',                  true,  false, 'lower_hex'),
('HASH_SHA256',   'SHA-256',                true,  false, 'lower_hex'),
('IMEI',          'IMEI',                   true,  true,  'digits'),
('BANK_ACCT',     'Bank account',           true,  true,  'upper_nospace'),
('LICENCE_PLATE', 'Vehicle plate',          true,  true,  'upper_nospace'),
('DOC_NUMBER',    'Identity document',      true,  true,  'upper_nospace'),
('SOCIAL_URL',    'Social profile URL',     false, true,  'url_norm');

-- ---------------------------------------------------------------------
-- ROLES
-- Note SECURITY_OFFICER: can read the audit trail but NOT case content.
-- Separation of duties means the person watching the watchers is not
-- also an analyst.
-- ---------------------------------------------------------------------
SET search_path = iam, core, public;

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
('SERVICE',          'Service account',      'Machine identity for collectors and integrations.', true);

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
('break_glass.invoke', 'Emergency access to an unassigned case', true, false);


-- ---------------------------------------------------------------------
-- ROLE -> PERMISSION MATRIX (RBAC verbs). Mirror of Alembic 0021.
-- SYS_ADMIN/SECURITY_OFFICER hold no case-content permissions.
-- ---------------------------------------------------------------------
INSERT INTO role_permission (role_key, permission_key) VALUES
('SYS_ADMIN','user.manage'),
('SYS_ADMIN','role.manage'),
('SYS_ADMIN','integration.manage'),
('SECURITY_OFFICER','audit.read'),
('CASE_OWNER','case.create'),
('CASE_OWNER','case.read'),
('CASE_OWNER','case.update'),
('CASE_OWNER','case.close'),
('CASE_OWNER','case.delete'),
('CASE_OWNER','case.grant'),
('CASE_OWNER','graph.node.create'),
('CASE_OWNER','graph.node.update'),
('CASE_OWNER','graph.node.delete'),
('CASE_OWNER','graph.edge.create'),
('CASE_OWNER','graph.edge.update'),
('CASE_OWNER','graph.merge'),
('CASE_OWNER','graph.unmerge'),
('CASE_OWNER','assertion.create'),
('CASE_OWNER','assertion.retract'),
('CASE_OWNER','proposal.review'),
('CASE_OWNER','evidence.upload'),
('CASE_OWNER','evidence.read'),
('CASE_OWNER','evidence.export'),
('CASE_OWNER','evidence.purge'),
('CASE_OWNER','analytics.run'),
('CASE_OWNER','report.generate'),
('CASE_OWNER','report.export'),
('ANALYST','case.read'),
('ANALYST','graph.node.create'),
('ANALYST','graph.node.update'),
('ANALYST','graph.node.delete'),
('ANALYST','graph.edge.create'),
('ANALYST','graph.edge.update'),
('ANALYST','graph.merge'),
('ANALYST','graph.unmerge'),
('ANALYST','assertion.create'),
('ANALYST','assertion.retract'),
('ANALYST','evidence.upload'),
('ANALYST','evidence.read'),
('ANALYST','analytics.run'),
('ANALYST','report.generate'),
('COLLECTOR','source.manage'),
('COLLECTOR','watch.manage'),
('COLLECTOR','collection_account.manage'),
('COLLECTOR','collection_account.reveal'),
('REVIEWER','case.read'),
('REVIEWER','evidence.read'),
('REVIEWER','proposal.review'),
('REVIEWER','graph.merge'),
('REVIEWER','graph.unmerge'),
('CONTRIBUTOR','case.read'),
('CONTRIBUTOR','evidence.read'),
('CONTRIBUTOR','evidence.upload'),
('READ_ONLY','case.read'),
('READ_ONLY','evidence.read'),
('LIAISON','case.read'),
('LIAISON','evidence.read'),
('SERVICE','evidence.upload')
ON CONFLICT (role_key, permission_key) DO NOTHING;

-- =====================================================================
-- CONCEPT ADDITIONS  (docs 10, 11, 12)
-- Draft alongside db/schema_concept.sql. Ontology rows are cheap to
-- change, so these are safer to land early than the tables are.
-- =====================================================================
SET search_path = core, public;

INSERT INTO node_type (key, display_name, category, colour_token, sort_order) VALUES
-- An account is not an identity: one persona may run several accounts,
-- and one account may be shared (shop support, group admin).
('COMMS_ACCOUNT','Comms account',  'ARTEFACT','artefact.comms',   62),
-- Derived from crypto material. Links personas WITHOUT merging them,
-- which is what you want when two JIDs share a device but you cannot
-- yet say they share an operator.
('DEVICE',       'Device',         'ARTEFACT','artefact.device',  64),
-- Bipartite anchor: identities participate in conversations, which
-- projects to a co-participation network — often the cleanest social
-- graph available.
('CONVERSATION', 'Conversation',   'CONTEXT', 'context.comms',   135),
-- A specific binary, distinct from MALWARE which is the family.
('SAMPLE',       'Malware sample', 'ARTEFACT','artefact.malware', 92),
('BUILDER',      'Builder / kit',  'ARTEFACT','artefact.malware', 94);

INSERT INTO edge_type (key, display_name, inverse_name, is_directed, default_sign, src_node_types, dst_node_types, is_social_tie) VALUES
-- Comms plumbing — structural, not social.
('USES_ACCOUNT',      'uses account',        'account used by',   true, 0, '{IDENTITY,PERSON,GROUP}','{COMMS_ACCOUNT}', false),
('ON_DEVICE',         'observed on device',  'has account',       true, 0, '{COMMS_ACCOUNT}','{DEVICE}',               false),
('SAME_DEVICE_AS',    'shares a device with','shares a device with',false,0,'{COMMS_ACCOUNT,IDENTITY}','{COMMS_ACCOUNT,IDENTITY}', false),
('PARTICIPANT_IN',    'participates in',     'has participant',   true, 1, '{COMMS_ACCOUNT,IDENTITY}','{CONVERSATION}', false),

-- Co-declaration: the actor themselves asserts these identifiers belong
-- together. Stronger than co-occurrence, weaker than crypto proof, and
-- only valid for entries parsed as SELF within a contact block.
('CO_DECLARED_WITH',  'declared alongside',  'declared alongside',false,1, '{SELECTOR,COMMS_ACCOUNT}','{SELECTOR,COMMS_ACCOUNT}', false),
-- Cryptographic proof of control (verified signature), as opposed to a
-- bare claim. Only this one should feed automatic identity resolution.
('CONFIRMED_CONTROL_OF','confirmed control of','control confirmed by',true,0,'{IDENTITY,PERSON}','{SELECTOR,COMMS_ACCOUNT,WALLET}', false),

-- Sample and builder lineage. The cluster points at a DEVELOPER, who is
-- usually more interesting and less replaceable than any affiliate.
('SAMPLE_OF',         'is a sample of',      'has sample',        true, 0, '{SAMPLE}','{MALWARE}',                     false),
('BUILT_WITH',        'was built with',      'built',             true, 0, '{SAMPLE}','{BUILDER,TOOL}',                false),
('CLUSTERS_WITH',     'clusters with',       'clusters with',     false,0, '{SAMPLE}','{SAMPLE}',                      false),
('CONTACTS_C2',       'contacts',            'contacted by',      true, 0, '{SAMPLE,MALWARE}','{INFRA}',               false),
('SUBMITTED_SAMPLE',  'submitted sample',    'submitted by',      true, 0, '{IDENTITY,PERSON}','{SAMPLE}',             false);

INSERT INTO selector_type (key, display_name, is_strong, is_pii, normaliser) VALUES
-- THE Tox nuance. The 4-byte nospam is user-rotatable, which changes the
-- 76-hex Tox ID string while the identity stays the same. Index the
-- 64-hex public key or you silently lose the actor after they rotate.
('TOX_PK',        'Tox public key (64 hex)', true,  false, 'tox_pubkey'),
('TOX_ID_FULL',   'Tox ID as observed (76)', false, false, 'upper_hex'),
-- Two JIDs publishing the same OMEMO fingerprint is the same physical
-- device. Far stronger than a shared nickname, almost never collected.
('OMEMO_FPR',     'OMEMO device fingerprint',true,  false, 'lower_hex_nospace'),
('MATRIX_MXID',   'Matrix MXID',             true,  false, 'mxid_norm'),
('MATRIX_DEVKEY', 'Matrix device key',       true,  false, 'trim'),
('WIRE_HANDLE',   'Wire handle',             false, false, 'lower_strip_at'),
('WIRE_UUID',     'Wire account UUID',       true,  false, 'lower_trim'),
('THREEMA_ID',    'Threema ID',              true,  false, 'upper_nospace'),
('SIGNAL_ACI',    'Signal ACI',              true,  true,  'lower_trim'),
('BRIAR_LINK',    'Briar contact link',      true,  false, 'trim'),
('SKYPE_ID',      'Skype name',              true,  true,  'lower_trim'),
-- Build-environment clustering. imphash and Rich header are strong
-- developer-level linkage; ssdeep and TLSH are fuzzy and cluster kits.
('IMPHASH',       'Import hash',             false, false, 'lower_hex'),
('RICH_HEADER',   'Rich header hash',        false, false, 'lower_hex'),
('SSDEEP',        'ssdeep fuzzy hash',       false, false, 'trim'),
('TLSH',          'TLSH fuzzy hash',         false, false, 'tlsh_norm'),
('MUTEX',         'Mutex name',              false, false, 'exact'),
-- Attacker-controlled free text; clustering signal, never auto-merge (0018).
('PDB_PATH',      'PDB path',                false, false, 'lower_trim'),
-- Self-asserted cert text; the unique thing is the fingerprint (0018).
('CODESIGN_CN',   'Code-signing subject',    false, false, 'trim'),
('USER_AGENT',    'User agent string',       false, false, 'trim');

-- The comms.platform seed lives in db/concept/seed_platform_concept.sql:
-- the platform table itself is concept-layer (schema_concept.sql), which
-- does not auto-load, so its rows cannot live in the decided seed.

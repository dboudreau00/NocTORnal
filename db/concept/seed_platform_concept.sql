-- =====================================================================
-- CONCEPT SEED — comms.platform  (docs/10-comms-channels.md)
-- Moved out of db/seed_ontology.sql: the platform table only exists in
-- db/concept/schema_concept.sql, which deliberately does not auto-load.
-- Load this manually, after the doc-10 open questions are answered and
-- schema_concept.sql (or its successor migration) has been applied.
-- =====================================================================

-- Realistic collection routes per platform. An actor on a platform with
-- no viable route reads as UNMONITORED in the UI, never as inactive —
-- absence of data is not absence of activity.
SET search_path = comms, core, public;

INSERT INTO platform (key, display_name, durable_selector_type, display_selector_type, is_e2ee, has_server_history, collection_routes, notes) VALUES
('SESSION', 'Session',  'SESSION_ID',   'SESSION_ID',   true,  false, '{PARTY,PUBLIC_ROOM,LEGAL}',      'Session ID is an X25519 public key. Communities (SOGS) hold room history.'),
('TOX',     'Tox/qTox', 'TOX_PK',       'TOX_ID_FULL',  true,  false, '{PARTY,DISCLOSURE,LEGAL}',       'Index the 64-hex public key, never the 76-hex ID. Nospam is rotatable.'),
('XMPP',    'XMPP',     'JABBER',       'JABBER',       true,  true,  '{PARTY,PUBLIC_ROOM,LEGAL}',      'OMEMO fingerprints are device selectors. MAM archives may exist server-side.'),
('WIRE',    'Wire',     'WIRE_UUID',    'WIRE_HANDLE',  true,  true,  '{PARTY,LEGAL}',                  'MLS protocol. On-prem deployments exist.'),
('MATRIX',  'Matrix',   'MATRIX_MXID',  'MATRIX_MXID',  true,  true,  '{PARTY,PUBLIC_ROOM,LEGAL}',      'Federated; homeserver operator matters. Room state widely replicated.'),
('SIGNAL',  'Signal',   'SIGNAL_ACI',   'PHONE',        true,  false, '{PARTY,DISCLOSURE,LEGAL}',       'Legal process returns registration date and last connect, essentially nothing else.'),
('SIMPLEX', 'SimpleX',  NULL,           NULL,           true,  false, '{PARTY,DISCLOSURE}',             'No persistent identifier by design. Model as CHANNEL with no selector; coverage is inherently poor.'),
('THREEMA', 'Threema',  'THREEMA_ID',   'THREEMA_ID',   true,  false, '{PARTY,LEGAL}',                  'Swiss, minimal retention.'),
('BRIAR',   'Briar',    'BRIAR_LINK',   'BRIAR_LINK',   true,  false, '{PARTY}',                        'P2P over Tor, no server at all.'),
('TELEGRAM','Telegram', 'TELEGRAM_ID',  'TELEGRAM_USER',false, true,  '{PARTY,PUBLIC_ROOM,LEGAL}',      'Numeric ID is durable; @username is recycled after release.'),
('DISCORD', 'Discord',  'DISCORD_ID',   'DISCORD_ID',   false, true,  '{PARTY,PUBLIC_ROOM,LEGAL}',      'Snowflake IDs. Common in lower-tier and marketplace activity.'),
('ICQ',     'ICQ',      'ICQ',          'ICQ',          false, true,  '{LEGAL}',                        'Service closed June 2024. Historical value in old threads.'),
('WICKR',   'Wickr',    NULL,           NULL,           true,  false, '{DISCLOSURE,LEGAL}',             'Consumer service shut down 2023. Historical.'),
('SKYPE',   'Skype',    'SKYPE_ID',     'SKYPE_ID',     false, true,  '{LEGAL}',                        'Legacy, appears in older artefacts.'),
('FORUM_PM','Forum PM', NULL,           'FORUM_UID',    false, true,  '{PARTY,LEAK,SEIZURE,DISCLOSURE}','XenForo Conversations, MyBB/phpBB PM. Provenance class is mandatory.'),
('SHOP_CHAT','Shop chat',NULL,          NULL,           false, true,  '{PARTY,LEAK,SEIZURE}',           'Marketplace, escrow and vendor support chat.');

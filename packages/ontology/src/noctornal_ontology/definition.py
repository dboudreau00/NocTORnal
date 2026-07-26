"""THE single source of truth for the NocTORnal graph vocabulary.

Every node type, edge type and selector type lives here and nowhere else.
The SQL seed (db/migrations 0017 + db/seed_ontology.sql) and the
TypeScript types are generated from this file; if you change a row here,
regenerate (python -m noctornal_ontology.generate) and ship the change as
a new data migration.

Field semantics mirror the DB columns exactly — see db/schema.sql
section 1 for the reasoning behind each flag (is_social_tie keeps
identity plumbing out of centrality; is_strong drives auto-merge
candidacy and a false merge is worse than a missed one).
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class NodeType:
    key: str
    display_name: str
    category: str  # ACTOR | ARTEFACT | CONTEXT
    colour_token: str
    sort_order: int


@dataclass(frozen=True)
class EdgeType:
    key: str
    display_name: str
    inverse_name: str
    is_directed: bool
    default_sign: int  # -1 | 0 | 1
    src_node_types: tuple[str, ...]
    dst_node_types: tuple[str, ...]
    is_social_tie: bool


@dataclass(frozen=True)
class SelectorType:
    key: str
    display_name: str
    is_strong: bool
    is_pii: bool
    normaliser: str


NODE_TYPES: tuple[NodeType, ...] = (
    # ACTOR layer. The critical split: IDENTITY is what you observe,
    # PERSON is what you assess. Never collapse them (invariant 2).
    NodeType("IDENTITY", "Persona", "ACTOR", "actor.persona", 10),
    NodeType("PERSON", "Assessed person", "ACTOR", "actor.person", 20),
    NodeType("GROUP", "Group", "ACTOR", "actor.group", 30),
    NodeType("SUBGROUP", "Cell / sub-unit", "ACTOR", "actor.group", 35),
    NodeType("ORGANISATION", "Legal entity", "ACTOR", "actor.org", 40),
    NodeType("VICTIM", "Victim entity", "ACTOR", "actor.victim", 50),
    # ARTEFACT layer
    NodeType("SELECTOR", "Selector", "ARTEFACT", "artefact.selector", 60),
    NodeType("COMMS_ACCOUNT", "Comms account", "ARTEFACT", "artefact.comms", 62),
    NodeType("DEVICE", "Device", "ARTEFACT", "artefact.device", 64),
    NodeType("WALLET", "Crypto wallet", "ARTEFACT", "artefact.finance", 70),
    NodeType("SERVICE", "Service / shop", "ARTEFACT", "artefact.service", 80),
    NodeType("FORUM", "Forum / board", "ARTEFACT", "artefact.venue", 85),
    NodeType("CHANNEL", "Channel / group chat", "ARTEFACT", "artefact.venue", 86),
    NodeType("MALWARE", "Malware family", "ARTEFACT", "artefact.malware", 90),
    NodeType("SAMPLE", "Malware sample", "ARTEFACT", "artefact.malware", 92),
    NodeType("BUILDER", "Builder / kit", "ARTEFACT", "artefact.malware", 94),
    NodeType("INFRA", "Infrastructure", "ARTEFACT", "artefact.infra", 100),
    NodeType("CREDENTIAL_SET", "Credential set", "ARTEFACT", "artefact.data", 110),
    NodeType("DATASET", "Leaked dataset", "ARTEFACT", "artefact.data", 115),
    NodeType("TOOL", "Tool / kit", "ARTEFACT", "artefact.malware", 120),
    # CONTEXT layer
    # The pretext itself (docs/19): the fake O365 login, the invoice-
    # redirect story, the "IT support" script. Distinct from TOOL, which
    # is the kit that GENERATES it, and from CAMPAIGN, which is time-
    # bounded and actor-scoped. Lures outlive both and recur across
    # actors — "the same pretext hit six victims via three senders" is
    # the question this platform exists to answer.
    NodeType("LURE", "Lure / pretext", "ARTEFACT", "artefact.lure", 125),

    NodeType("EVENT", "Event", "CONTEXT", "context.event", 130),
    NodeType("CONVERSATION", "Conversation", "CONTEXT", "context.comms", 135),
    NodeType("CAMPAIGN", "Campaign", "CONTEXT", "context.campaign", 140),
    NodeType("INCIDENT", "Incident", "CONTEXT", "context.incident", 150),
    NodeType("LOCATION", "Location", "CONTEXT", "context.location", 160),
    NodeType("TRANSACTION", "Transaction", "CONTEXT", "context.finance", 170),
)


EDGE_TYPES: tuple[EdgeType, ...] = (
    # Identity resolution (structural, NOT social)
    EdgeType("SAME_AS", "is the same as", "is the same as", False, 0,
             ("IDENTITY", "PERSON"), ("IDENTITY", "PERSON"), False),
    EdgeType("ALIAS_OF", "is an alias of", "has alias", True, 0,
             ("IDENTITY",), ("IDENTITY",), False),
    EdgeType("ATTRIBUTED_TO", "attributed to", "has persona", True, 0,
             ("IDENTITY",), ("PERSON",), False),
    EdgeType("CONTROLS", "controls", "controlled by", True, 0,
             ("IDENTITY", "PERSON", "GROUP"),
             ("SELECTOR", "WALLET", "INFRA", "SERVICE", "CHANNEL",
              "DATASET", "CREDENTIAL_SET"), False),
    # Membership & structure
    EdgeType("MEMBER_OF", "is a member of", "has member", True, 1,
             ("IDENTITY", "PERSON", "SUBGROUP"), ("GROUP", "SUBGROUP"), True),
    EdgeType("LEADS", "leads", "is led by", True, 1,
             ("IDENTITY", "PERSON"), ("GROUP", "SUBGROUP"), True),
    EdgeType("AFFILIATE_OF", "is an affiliate of", "has affiliate", True, 1,
             ("IDENTITY", "PERSON", "GROUP"), ("GROUP",), True),
    EdgeType("SPLINTER_OF", "split from", "spawned", True, 0,
             ("GROUP",), ("GROUP",), False),
    EdgeType("REBRAND_OF", "is a rebrand of", "rebranded as", True, 0,
             ("GROUP",), ("GROUP",), False),
    EdgeType("RIVAL_OF", "is a rival of", "is a rival of", False, -1,
             ("GROUP", "IDENTITY"), ("GROUP", "IDENTITY"), True),
    # Trust layer. This is what makes it a trust network.
    EdgeType("VOUCHED_FOR", "vouched for", "was vouched by", True, 1,
             ("IDENTITY",), ("IDENTITY",), True),
    EdgeType("GUARANTOR_FOR", "acted as guarantor", "used guarantor", True, 1,
             ("IDENTITY",), ("IDENTITY",), True),
    EdgeType("ESCROW_FOR", "held escrow for", "used escrow", True, 1,
             ("IDENTITY",), ("IDENTITY",), True),
    EdgeType("ACCUSED_SCAM", "accused of ripping", "was accused by", True, -1,
             ("IDENTITY",), ("IDENTITY",), True),
    EdgeType("DISPUTED_WITH", "in dispute with", "in dispute with", False, -1,
             ("IDENTITY",), ("IDENTITY",), True),
    EdgeType("BANNED_BY", "was banned by", "banned", True, -1,
             ("IDENTITY",), ("FORUM", "CHANNEL", "IDENTITY"), False),
    # Interaction
    EdgeType("COMMUNICATES_WITH", "communicates with", "communicates with", False, 1,
             ("IDENTITY", "PERSON"), ("IDENTITY", "PERSON"), True),
    # Pre-materialised co-affiliation; docs/01 wants the projection
    # computed at analysis time, so this never feeds default metrics.
    EdgeType("CO_POSTED_IN", "co-posted in", "co-posted in", False, 1,
             ("IDENTITY",), ("IDENTITY",), False),
    EdgeType("REPLIED_TO", "replied to", "was replied to by", True, 1,
             ("IDENTITY",), ("IDENTITY",), True),
    EdgeType("MET_WITH", "met with", "met with", False, 1,
             ("PERSON",), ("PERSON",), True),
    EdgeType("POSTS_ON", "posts on", "has poster", True, 0,
             ("IDENTITY",), ("FORUM", "CHANNEL"), False),
    # Commercial / criminal function
    EdgeType("SOLD_TO", "sold to", "bought from", True, 1,
             ("IDENTITY",), ("IDENTITY",), True),
    EdgeType("BROKERED_ACCESS", "brokered access to", "access brokered by", True, 1,
             ("IDENTITY",), ("VICTIM", "ORGANISATION"), True),
    EdgeType("LAUNDERED_FOR", "laundered for", "used launderer", True, 1,
             ("IDENTITY", "SERVICE"), ("IDENTITY", "GROUP"), True),
    EdgeType("RECRUITED", "recruited", "was recruited by", True, 1,
             ("IDENTITY",), ("IDENTITY",), True),
    EdgeType("MENTORED", "mentored", "was mentored by", True, 1,
             ("IDENTITY",), ("IDENTITY",), True),
    EdgeType("PAID", "paid", "was paid by", True, 1,
             ("IDENTITY", "WALLET"), ("IDENTITY", "WALLET"), True),
    # Finance & data provenance. A TRANSACTION is a specific proven
    # on-chain event (decision 22); wallets are its inputs/outputs, so the
    # money network stays two-mode (actor -CONTROLS-> wallet -> tx ->
    # wallet <- actor) and is projected at analysis time, never counted as
    # a direct social tie. PAID remains the actor-level summary edge.
    EdgeType("TX_INPUT", "is an input to", "has input", True, 0,
             ("WALLET",), ("TRANSACTION",), False),
    EdgeType("TX_OUTPUT", "is an output of", "has output", True, 0,
             ("TRANSACTION",), ("WALLET",), False),
    EdgeType("EXFILTRATED_FROM", "was exfiltrated from", "source of", True, 0,
             ("DATASET", "CREDENTIAL_SET"), ("VICTIM", "ORGANISATION"), False),
    # Operational
    EdgeType("DEVELOPED", "developed", "developed by", True, 0,
             ("IDENTITY", "PERSON", "GROUP"), ("MALWARE", "TOOL", "SERVICE"), False),
    EdgeType("USED", "used", "used by", True, 0,
             ("IDENTITY", "PERSON", "GROUP"),
             ("MALWARE", "TOOL", "INFRA", "SERVICE"), False),
    # LURE and INFRA widen the source set rather than minting a near-
    # duplicate DELIVERED_TO: "this pretext was aimed at that victim" and
    # "this actor aimed at that victim" are the same relation with
    # different subjects (docs/19 §3.4).
    EdgeType("TARGETED", "targeted", "was targeted by", True, 0,
             ("IDENTITY", "GROUP", "CAMPAIGN", "LURE", "INFRA"),
             ("VICTIM", "ORGANISATION", "PERSON"), False),
    # A FALSE identity claim — the opposite of ALIAS_OF/SAME_AS, which
    # both assert the subjects ARE the same. Nothing existing could carry
    # "this page claims to be Microsoft".
    #
    # is_social_tie=False and default_sign=0 are load-bearing, not
    # defaults. If impersonation counted as affiliation, the impersonated
    # brand would become the most central node in every phishing case in
    # the system and every centrality ranking would be garbage. Invariant
    # 4's concern arriving via a new edge.
    EdgeType("IMPERSONATES", "impersonates", "is impersonated by", True, 0,
             ("IDENTITY", "LURE", "COMMS_ACCOUNT"),
             ("ORGANISATION", "PERSON", "SERVICE"), False),
    EdgeType("HOSTED_ON", "is hosted on", "hosts", True, 0,
             ("SERVICE", "INFRA", "FORUM"), ("INFRA",), False),
    EdgeType("PART_OF", "is part of", "includes", True, 0,
             ("INCIDENT", "EVENT"), ("CAMPAIGN",), False),
    # Technical co-occurrence, not a positive social tie: two rivals on
    # one bulletproof host are not allies. Hypothesis channel per docs/01.
    EdgeType("SHARED_INFRA", "shares infrastructure with",
             "shares infrastructure with", False, 0,
             ("IDENTITY", "GROUP", "SERVICE"), ("IDENTITY", "GROUP", "SERVICE"), False),
    # Context
    EdgeType("LOCATED_IN", "is located in", "contains", True, 0,
             ("PERSON", "ORGANISATION", "INFRA"), ("LOCATION",), False),
    EdgeType("PARTICIPATED_IN", "participated in", "had participant", True, 0,
             ("IDENTITY", "PERSON", "GROUP"), ("EVENT", "INCIDENT", "CAMPAIGN"), False),
    # Comms plumbing — structural, not social (docs/10)
    EdgeType("USES_ACCOUNT", "uses account", "account used by", True, 0,
             ("IDENTITY", "PERSON", "GROUP"), ("COMMS_ACCOUNT",), False),
    EdgeType("ON_DEVICE", "observed on device", "has account", True, 0,
             ("COMMS_ACCOUNT",), ("DEVICE",), False),
    EdgeType("SAME_DEVICE_AS", "shares a device with", "shares a device with",
             False, 0,
             ("COMMS_ACCOUNT", "IDENTITY"), ("COMMS_ACCOUNT", "IDENTITY"), False),
    # Bipartite affiliation like POSTS_ON: the social signal is the
    # analysis-time co-participation projection, never the raw edge.
    EdgeType("PARTICIPANT_IN", "participates in", "has participant", True, 1,
             ("COMMS_ACCOUNT", "IDENTITY"), ("CONVERSATION",), False),
    EdgeType("CO_DECLARED_WITH", "declared alongside", "declared alongside",
             False, 1,
             ("SELECTOR", "COMMS_ACCOUNT"), ("SELECTOR", "COMMS_ACCOUNT"), False),
    EdgeType("CONFIRMED_CONTROL_OF", "confirmed control of",
             "control confirmed by", True, 0,
             ("IDENTITY", "PERSON"), ("SELECTOR", "COMMS_ACCOUNT", "WALLET"), False),
    # Sample and builder lineage (docs/11)
    EdgeType("SAMPLE_OF", "is a sample of", "has sample", True, 0,
             ("SAMPLE",), ("MALWARE",), False),
    EdgeType("BUILT_WITH", "was built with", "built", True, 0,
             ("SAMPLE",), ("BUILDER", "TOOL"), False),
    EdgeType("CLUSTERS_WITH", "clusters with", "clusters with", False, 0,
             ("SAMPLE",), ("SAMPLE",), False),
    EdgeType("CONTACTS_C2", "contacts", "contacted by", True, 0,
             ("SAMPLE", "MALWARE"), ("INFRA",), False),
    EdgeType("SUBMITTED_SAMPLE", "submitted sample", "submitted by", True, 0,
             ("IDENTITY", "PERSON"), ("SAMPLE",), False),
)


SELECTOR_TYPES: tuple[SelectorType, ...] = (
    SelectorType("HANDLE", "Handle / nickname", False, False, "lower_trim"),
    # NOT strong until the norm form is venue-scoped: UID 42 exists on
    # every monitored forum, and unscoped it is a wrong-merge factory.
    SelectorType("FORUM_UID", "Forum user ID", False, False, "trim"),
    # Telegram: the numeric ID is durable; @usernames are recycled after
    # release, so TELEGRAM_USER is weak (invariant 9).
    SelectorType("TELEGRAM_ID", "Telegram numeric ID", True, False, "telegram_id_norm"),
    SelectorType("TELEGRAM_USER", "Telegram @username", False, False, "lower_strip_at"),
    SelectorType("DISCORD_ID", "Discord snowflake", True, False, "digits"),
    SelectorType("JABBER", "XMPP / Jabber", True, False, "jid_norm"),
    SelectorType("SESSION_ID", "Session ID", True, False, "lower_hex"),
    SelectorType("ICQ", "ICQ number", True, False, "digits"),
    SelectorType("EMAIL", "Email address", True, True, "email_norm"),
    SelectorType("PHONE", "Phone number", True, True, "e164"),
    SelectorType("PGP_FPR", "PGP fingerprint", True, False, "upper_hex_nospace"),
    SelectorType("SSH_KEY", "SSH public key", True, False, "ssh_norm"),
    SelectorType("BTC_ADDR", "Bitcoin address", True, False, "btc_norm"),
    SelectorType("ETH_ADDR", "Ethereum address", True, False, "eip55"),
    SelectorType("XMR_ADDR", "Monero address", True, False, "trim"),
    SelectorType("TRON_ADDR", "Tron address", True, False, "trim"),
    SelectorType("DOMAIN", "Domain", False, False, "punycode_lower"),
    SelectorType("ONION", "Onion service", True, False, "onion_norm"),
    SelectorType("IPV4", "IPv4 address", False, False, "ip_norm"),
    SelectorType("IPV6", "IPv6 address", False, False, "ip_norm"),
    SelectorType("ASN", "Autonomous system", False, False, "asn_norm"),
    SelectorType("URL", "URL", False, False, "url_norm"),
    SelectorType("HASH_MD5", "MD5", True, False, "lower_hex"),
    SelectorType("HASH_SHA1", "SHA-1", True, False, "lower_hex"),
    SelectorType("HASH_SHA256", "SHA-256", True, False, "lower_hex"),
    SelectorType("IMEI", "IMEI", True, True, "digits"),
    SelectorType("BANK_ACCT", "Bank account", True, True, "upper_nospace"),
    SelectorType("LICENCE_PLATE", "Vehicle plate", True, True, "upper_nospace"),
    SelectorType("DOC_NUMBER", "Identity document", True, True, "upper_nospace"),
    SelectorType("SOCIAL_URL", "Social profile URL", False, True, "url_norm"),
    # Comms selectors (docs/10). TOX_PK is the durable 64-hex public key
    # (invariant 9); TOX_ID_FULL is the weak as-observed 76-hex form whose
    # embedded nospam the actor can rotate at will.
    SelectorType("TOX_PK", "Tox public key (64 hex)", True, False, "tox_pubkey"),
    SelectorType("TOX_ID_FULL", "Tox ID as observed (76)", False, False, "upper_hex"),
    SelectorType("OMEMO_FPR", "OMEMO device fingerprint", True, False, "lower_hex_nospace"),
    SelectorType("MATRIX_MXID", "Matrix MXID", True, False, "mxid_norm"),
    SelectorType("MATRIX_DEVKEY", "Matrix device key", True, False, "trim"),
    SelectorType("WIRE_HANDLE", "Wire handle", False, False, "lower_strip_at"),
    SelectorType("WIRE_UUID", "Wire account UUID", True, False, "lower_trim"),
    SelectorType("THREEMA_ID", "Threema ID", True, False, "upper_nospace"),
    SelectorType("SIGNAL_ACI", "Signal ACI", True, True, "lower_trim"),
    SelectorType("BRIAR_LINK", "Briar contact link", True, False, "trim"),
    SelectorType("SKYPE_ID", "Skype name", True, True, "lower_trim"),
    # Build-environment clustering (docs/11)
    SelectorType("IMPHASH", "Import hash", False, False, "lower_hex"),
    SelectorType("RICH_HEADER", "Rich header hash", False, False, "lower_hex"),
    SelectorType("SSDEEP", "ssdeep fuzzy hash", False, False, "trim"),
    SelectorType("TLSH", "TLSH fuzzy hash", False, False, "tlsh_norm"),
    SelectorType("MUTEX", "Mutex name", False, False, "exact"),
    # Attacker-controlled free text; default VS paths recur across
    # unrelated builds. Clustering signal, never auto-merge.
    SelectorType("PDB_PATH", "PDB path", False, False, "lower_trim"),
    # Self-asserted cert text (anyone can mint a CN); the unique thing
    # would be the cert fingerprint, which this selector is not.
    SelectorType("CODESIGN_CN", "Code-signing subject", False, False, "trim"),
    SelectorType("USER_AGENT", "User agent string", False, False, "trim"),
    # Social-engineering evidence (docs/19). The theme is invariant 9:
    # index what the infrastructure proves, not what the victim was shown.
    #
    # The certificate public-key hash survives domain rotation, which is
    # exactly what phishing infrastructure does — so it is the durable
    # web identifier in the way the domain is not.
    SelectorType("TLS_SPKI", "TLS public-key hash", True, False, "lower_hex"),
    SelectorType("SIP_URI", "SIP URI", True, True, "sip_norm"),
    # Attacker-generated for attacker-sent mail, so it identifies the KIT,
    # not the sender. A pivot, never an identity — weak on purpose.
    SelectorType("EMAIL_MSGID", "Email Message-ID", False, False, "msgid_norm"),
    # The standard phishing-infra clustering pivot (Shodan-style favicon
    # hash). Weak: a collision on a stock framework favicon would merge
    # half the internet. Clustering signal, never auto-merge.
    SelectorType("FAVICON_MMH3", "Favicon hash", False, False, "trim"),
)

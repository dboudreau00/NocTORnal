"""Per-selector normalisers.

A normaliser produces the canonical matching form (selector.norm_value):
two observations of the same real-world identifier must normalise to the
same string, and two DIFFERENT identifiers must never be made to collide.
Normalisers are total, best-effort functions str -> str — VALIDATION is a
separate concern (selector_type.validator_regex); a normaliser never
raises on weird input, it returns its best canonical attempt.
norm(norm(x)) == norm(x) is a tested invariant.

Registry keys match selector_type.normaliser in the DB seed exactly;
tests assert the two sets are identical.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

import idna as idna_lib

_WS = re.compile(r"\s+")
_NON_DIGIT = re.compile(r"\D+")
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
_PHONE_JUNK = re.compile(r"[\s\-().]+")
# Trailing extension: 'ext 89', 'ext. 89', 'extension 89', 'x89', '#89'.
_PHONE_EXT = re.compile(r"(?i)[\s,;]*(?:ext\.?|extension|x|#)\s*\d{1,7}\s*$")
_SSH_KEY_TYPE = re.compile(r"^(ssh|ecdsa|sk-ssh|sk-ecdsa)[\w@.-]*$")
_ASDOT = re.compile(r"^(\d+)\.(\d+)$")

# Gmail treats dots in the local part as insignificant and everything
# after '+' as a tag. ONLY Gmail domains get this treatment — for other
# providers dots and plus-tags are (or may be) significant.
_GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}

# Default ports stripped during URL normalisation.
_DEFAULT_PORTS = {"http": "80", "https": "443"}


def exact(v: str) -> str:
    """Identity: the observed bytes ARE the canonical form. Reserved for
    identifiers where even surrounding whitespace could be significant
    (mutex names); everything else at least trims."""
    return v


def trim(v: str) -> str:
    return v.strip()


def lower_trim(v: str) -> str:
    return v.strip().lower()


def upper_nospace(v: str) -> str:
    """Also the IBAN treatment for BANK_ACCT: IBANs are printed in groups
    of four and are defined case-insensitive uppercase."""
    return _WS.sub("", v).upper()


def digits(v: str) -> str:
    """Keep digits only (unsigned numeric IDs: Discord, ICQ, IMEI)."""
    return _NON_DIGIT.sub("", v)


def lower_strip_at(v: str) -> str:
    """Handles quoted as @name: lowercase and strip the leading @."""
    s = v.strip().lower()
    return s[1:] if s.startswith("@") else s


def upper_hex(v: str) -> str:
    """Uppercase hex, outer whitespace only (see *_nospace for internal)."""
    return v.strip().upper()


def lower_hex(v: str) -> str:
    return v.strip().lower()


def upper_hex_nospace(v: str) -> str:
    """PGP fingerprints are conventionally printed in spaced groups."""
    return _WS.sub("", v).upper()


def lower_hex_nospace(v: str) -> str:
    """OMEMO fingerprints are conventionally printed in spaced groups."""
    return _WS.sub("", v).lower()


def email_norm(v: str) -> str:
    """Lowercase; strip dots and +tags in the local part for Gmail ONLY."""
    s = v.strip().lower()
    local, sep, domain = s.rpartition("@")
    if not sep:
        return s
    if domain in _GMAIL_DOMAINS:
        local = local.split("+", 1)[0].replace(".", "")
        domain = "gmail.com"  # googlemail.com is the same mailbox space
    return f"{local}@{domain}"


def e164(v: str) -> str:
    """Best-effort E.164: drop a trailing extension, strip separators,
    map the 00 international prefix to +.

    Without a country-code hint a bare national number cannot be
    completed to E.164; it is returned digits-only and full inference is
    the app layer's job (libphonenumber) — see package README.
    """
    s = _PHONE_EXT.sub("", v.strip())
    s = _PHONE_JUNK.sub("", s)
    plus = s.startswith("+")
    d = _NON_DIGIT.sub("", s)
    # The 00 international prefix is detected on the DIGITS, after junk
    # removal, so the function is idempotent on its own output.
    if not plus and d.startswith("00"):
        plus, d = True, d[2:]
    return ("+" + d) if plus else d


def ssh_norm(v: str) -> str:
    """'<type> <base64> [comment]' -> '<type> <base64>' (comment dropped:
    the key material is the identifier, the comment is a label)."""
    parts = _WS.split(v.strip())
    if len(parts) >= 2 and _SSH_KEY_TYPE.match(parts[0]):
        return f"{parts[0]} {parts[1]}"
    return v.strip()


def btc_norm(v: str) -> str:
    """Bech32/bech32m (bc1/tb1/bcrt1) is case-insensitive -> lowercase.
    Base58 is case-SENSITIVE -> never touch its case."""
    s = v.strip()
    if s.lower().startswith(("bc1", "tb1", "bcrt1")):
        return s.lower()
    return s


def eip55(v: str) -> str:
    """Canonical matching form for an Ethereum address: 0x + lowercase hex.

    EIP-55 mixed-case is a display checksum, not an identity: the same
    address arrives checksummed, all-lower and all-upper in the wild, and
    they must all match. Recomputing the checksum (for validation or
    display) needs keccak256 and belongs to the validator/UI layer.
    """
    s = v.strip()
    if s.lower().startswith("0x"):
        return "0x" + s[2:].lower()
    if _HEX_RE.match(s) and len(s) == 40:
        return "0x" + s.lower()
    return s


def jid_norm(v: str) -> str:
    """Bare JID (RFC 7622): the account is localpart@domain; the
    /resourcepart names a session or device and changes per login, so it
    is stripped — otherwise the same vendor account observed in a MUC
    (full JID) and in a contact block (bare JID) never merges."""
    s = v.strip()
    at = s.find("@")
    slash = s.find("/", at + 1 if at >= 0 else 0)
    if slash != -1:
        s = s[:slash]
    return s.lower()


def mxid_norm(v: str) -> str:
    """Matrix @localpart:server — the localpart is case-SENSITIVE (two
    different accounts may differ only by case on historical
    homeservers); only the server name is DNS and case-folds."""
    s = v.strip()
    if s.startswith("@") and ":" in s:
        local, _, server = s.partition(":")
        return f"{local}:{server.lower()}"
    return s


def telegram_id_norm(v: str) -> str:
    """Telegram numeric IDs: user IDs are positive; Bot-API prefixes
    supergroups/channels with -100 (strip it — the MTProto form of the
    same channel has no prefix) and basic-group chat IDs with a bare
    minus (KEEP it — a chat id and an unrelated user id must never share
    a norm_value)."""
    s = v.strip()
    neg = s.startswith("-")
    d = _NON_DIGIT.sub("", s)
    if neg and d.startswith("100") and len(d) > 3:
        return d[3:]
    if neg and d:
        return "-" + d
    return d


def tlsh_norm(v: str) -> str:
    """TLSH digests circulate 'T1'-prefixed (tlsh >= 4.0, VirusTotal) and
    as the legacy raw 70-hex form. Canonical form is prefixless so the
    same sample hashed by two toolchains clusters. (The stripped body is
    hex, which cannot begin with 'T', so this is idempotent.)"""
    s = _WS.sub("", v).upper()
    if s.startswith("T1") and len(s) > 2:
        s = s[2:]
    return s


def onion_norm(v: str) -> str:
    """Bare onion host: strip scheme, path, port and the trailing root
    dot, then lowercase (v3 onions are case-insensitive base32)."""
    s = v.strip().lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    return s


def punycode_lower(v: str) -> str:
    """Canonical wire form of a domain: lowercase, trailing root dot
    stripped, every label in punycode via IDNA2008/UTS-46 (the rules
    registries and browsers actually use — stdlib IDNA2003 would merge
    separately-registrable pairs like faß.de / fass.de). xn-- labels
    are round-tripped so Unicode and punycode observations of the same
    domain collide."""
    s = v.strip().lower().rstrip(".")
    out: list[str] = []
    for label in s.split("."):
        try:
            if label.startswith("xn--"):
                label = idna_lib.encode(
                    idna_lib.decode(label), uts46=True, transitional=False
                ).decode("ascii")
            elif label and not label.isascii():
                label = idna_lib.encode(
                    label, uts46=True, transitional=False
                ).decode("ascii")
        except (idna_lib.IDNAError, UnicodeError):
            pass  # best effort: keep the label as observed
        out.append(label)
    return ".".join(out)


def ip_norm(v: str) -> str:
    """Canonical text form via the stdlib: compresses IPv6, lowercases
    hex, unwraps ::ffff: IPv4-mapped addresses to plain IPv4."""
    s = v.strip()
    candidate = s[1:-1] if s.startswith("[") and s.endswith("]") else s
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return s
    if addr.version == 6:
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return str(mapped)
    return str(addr)


def asn_norm(v: str) -> str:
    """'AS13335', 'as 13335', '013335' -> '13335'; RFC 5396 asdot
    ('AS1.10') converts to asplain (65546) rather than colliding with an
    unrelated 16-bit ASN."""
    s = v.strip()
    if s[:2].lower() == "as":
        s = s[2:].strip()
    m = _ASDOT.match(s)
    if m:
        return str(int(m.group(1)) * 65536 + int(m.group(2)))
    d = _NON_DIGIT.sub("", s)
    return str(int(d)) if d else d


def url_norm(v: str) -> str:
    """Lowercase scheme+host, strip default port and fragment; path and
    query stay byte-exact (they are case- and encoding-sensitive)."""
    s = v.strip()
    try:
        parts = urlsplit(s)
    except ValueError:
        return s
    if not parts.scheme or not parts.netloc:
        return s
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not parts.hostname:
        return s
    netloc = host
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None and str(port) != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    if parts.username:
        cred = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{cred}@{netloc}"
    return urlunsplit((scheme, netloc, parts.path, parts.query, ""))


def tox_pubkey(v: str) -> str:
    """THE Tox nuance (invariant 9): the 76-hex Tox ID is
    <64-hex public key><8-hex nospam><4-hex checksum>, and the actor can
    rotate the nospam at will. The durable identity is the first 64 hex.
    A rotated nospam MUST normalise to the same value."""
    s = _WS.sub("", v).upper()
    if len(s) == 76 and _HEX_RE.match(s):
        return s[:64]
    return s


NORMALISERS: dict[str, Callable[[str], str]] = {
    "exact": exact,
    "trim": trim,
    "lower_trim": lower_trim,
    "upper_nospace": upper_nospace,
    "digits": digits,
    "lower_strip_at": lower_strip_at,
    "upper_hex": upper_hex,
    "lower_hex": lower_hex,
    "upper_hex_nospace": upper_hex_nospace,
    "lower_hex_nospace": lower_hex_nospace,
    "email_norm": email_norm,
    "e164": e164,
    "ssh_norm": ssh_norm,
    "btc_norm": btc_norm,
    "eip55": eip55,
    "jid_norm": jid_norm,
    "mxid_norm": mxid_norm,
    "telegram_id_norm": telegram_id_norm,
    "tlsh_norm": tlsh_norm,
    "onion_norm": onion_norm,
    "punycode_lower": punycode_lower,
    "ip_norm": ip_norm,
    "asn_norm": asn_norm,
    "url_norm": url_norm,
    "tox_pubkey": tox_pubkey,
}


def normalise(selector_type_key: str, raw_value: str) -> str:
    """Normalise a raw observation for the given selector type key."""
    from noctornal_ontology.definition import SELECTOR_TYPES

    for st in SELECTOR_TYPES:
        if st.key == selector_type_key:
            return NORMALISERS[st.normaliser](raw_value)
    raise KeyError(f"unknown selector type: {selector_type_key!r}")

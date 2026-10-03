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
from urllib.parse import unquote, urlsplit, urlunsplit

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
    """Telegram numeric IDs, decoded arithmetically and namespaced by type.

    Three Telegram id spaces overlap numerically and must never collide in
    `norm_value`, because `TELEGRAM_ID` is `is_strong` and a collision
    therefore raises a MERGE LEAD an analyst is asked to confirm (the
    automatic merge on a strong match was designed and never built)
    — where a false merge is worse than a missed one:

        u:<id>   user
        c:<id>   channel / supergroup
        g:<id>   basic group

    ## CR3 (2026-07-26) — the old version string-stripped a leading "100"

    The Bot-API encoding is ARITHMETIC: `chat_id = -(10**12 + channel_id)`.
    Dropping the characters `100` from the front happens to invert that
    only when the channel id is exactly ten digits, which is why the one
    test covering the ten-digit case passed while the function was wrong.

    - A NINE-digit channel id encodes to `-1000123456789`; stripping three
      characters leaves `0123456789`, with a spurious leading zero that
      matches nothing.
    - An ELEVEN-digit id (common since the 64-bit migration) encodes to
      `-112345678901`, which does not begin `100` after the sign, so the
      strip never fires and the two observations of one channel never
      meet.
    - A ten-digit channel id normalised to bare digits equal to an
      unrelated USER id — and with a strong selector, that is a channel
      and a person offered to an analyst as one row to merge.

    Namespacing also removes a whole class of collision the arithmetic
    alone would not: a user id and a channel id may be the same number and
    are not the same thing.

    ## A bare positive integer is genuinely ambiguous, and is REFUSED

    In MTProto, user ids and channel ids are separate spaces and both
    positive, so `1234567890` alone cannot be resolved — it is a user id
    or a channel id and nothing in the string says which. Until
    2026-09-11 this function assumed `u:`, on the reasoning that a bare
    positive in the wild is overwhelmingly a user. On a strong selector
    that is the wrong trade in the same way the string-strip was: a
    missed merge is an analyst's afternoon, a false merge is a channel
    and a person fused into one actor, and "overwhelmingly" is a guess
    written into a merge lead. So a bare positive now normalises to ''
    -- nothing durable -- and `refusal()` says why in a sentence a caller
    may show. A caller that knows the type says so with an explicit
    `u:`/`c:`/`g:` prefix: a scraper recording an MTProto channel passes
    `c:1234567890` and meets the Bot-API observation `-1001234567890` on
    the same `c:` row; an analyst typing a user id passes `u:1234567890`.
    The Bot-API negative encodings carry their own type and decode as
    before.
    """
    s = v.strip()
    for prefix in ("u:", "c:", "g:"):
        if s.lower().startswith(prefix):
            rest = _NON_DIGIT.sub("", s[2:])
            return prefix + str(int(rest)) if rest else ""
    negative = s.startswith("-")
    digits_only = _NON_DIGIT.sub("", s)
    if not digits_only:
        return ""
    if not negative:
        # Refused, not guessed (2026-09-11): see the docstring, and
        # `refusal()` for the sentence a caller shows.
        return ""

    value = int(digits_only)
    # Bot-API supergroup/channel: -(10**12 + id). The MTProto form of the
    # same channel is the bare id, so both must land on c:<id>.
    if value > 1_000_000_000_000:
        return "c:" + str(value - 1_000_000_000_000)
    # A bare negative is a basic-group chat id. Distinct space, kept
    # distinct — it is not a channel and it is not a user.
    return "g:" + str(value)


#: Why a bare positive Telegram id yields nothing. One sentence, shared by
#: the selector store, `comms.normalise` and the contact-block parser, so
#: an analyst reads the same reason at every door.
TELEGRAM_BARE_POSITIVE = (
    "a bare positive Telegram id is ambiguous: MTProto user ids and channel "
    "ids are separate spaces and both positive, so the number alone does not "
    "say which it is. Record it as u:<id> for a user or c:<id> for a channel "
    "or supergroup (a Bot-API chat id, -100..., decodes on its own).")

_BARE_POSITIVE = re.compile(r"^\s*\+?\d[\d\s]*$")


def is_bare_positive_telegram_id(v: str) -> bool:
    return bool(_BARE_POSITIVE.match(v))


def refusal(selector_type_key: str, raw_value: str) -> str:
    """Why `normalise(selector_type_key, raw_value)` returned '' -- one
    sentence a caller may show. Meaningful only when it did. Normalisers
    stay total and silent (README: they never raise); this is the reason
    kept beside the rule, so the three places that refuse an empty
    canonical form do not each invent their own."""
    if selector_type_key == "TELEGRAM_ID" and is_bare_positive_telegram_id(raw_value):
        return TELEGRAM_BARE_POSITIVE
    shown = raw_value.strip()
    if len(shown) > 60:
        shown = shown[:57] + "..."
    return f"{shown!r} cannot be reduced to a canonical {selector_type_key} value"


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


# --- url_norm's fragment rules (L5, 2026-09-24) ----------------------------
#
# A MEGA handle: the file or folder id, never the key after it.
_MEGA_HANDLE = r"[A-Za-z0-9_-]+"
_MEGA_PATH = re.compile(rf"/(file|folder|embed|chat|collection)/({_MEGA_HANDLE})/?")
_MEGA_IN_FOLDER = re.compile(rf"[^/]*/(file|folder)/({_MEGA_HANDLE})")
_MEGA_LEGACY_FILE = re.compile(rf"!({_MEGA_HANDLE})")
_MEGA_LEGACY_FOLDER = re.compile(
    rf"F!({_MEGA_HANDLE})(?:!{_MEGA_HANDLE})?(?:([!?])({_MEGA_HANDLE}))?")
_MEGA_PASSWORD = re.compile(rf"P!({_MEGA_HANDLE})")
# matrix.to decodes only these escapes, never %25 or %3F, so decoding
# cannot mint a '%' escape or a '?' and a second pass changes nothing.
_MATRIX_SAFE = re.compile(r"%(40|3[Aa]|21|24|2[Bb]|23)")
_MATRIX_CHARS = {"40": "@", "3a": ":", "21": "!", "24": "$", "2b": "+", "23": "#"}
_MATRIX_VIA = re.compile(r"via=[^&]*(?:&via=[^&]*)*")
_TWITTER_ROUTE = re.compile(r"!(/[^?#]*)")
# web.telegram.org's chat shapes: letters, digits and '_' only, so none of
# them can carry a login token or a start parameter.
_TG_NAME = r"@[A-Za-z0-9_]{1,64}"
_TG_CHAT = re.compile(rf"{_TG_NAME}|-?\d{{1,20}}(?:_\d{{1,20}}){{0,2}}")
_TG_LEGACY_IM = re.compile(rf"/im\?p=(?:{_TG_NAME}|[ucg]\d{{1,20}}(?:_-?\d{{1,20}})?)")
_TG_ADDR = re.compile(r"\?tgaddr=([^&]+)")
_TG_RESOLVE = re.compile(
    r"tg://resolve\?domain=[A-Za-z0-9_]{1,64}(?:&(?:post|thread|comment)=\d{1,20})*")


def _mega(path: str, frag: str) -> tuple[str, str]:
    """A MEGA link in its current form, and never its key.

    The legacy `#!<handle>!<key>` and `#F!<handle>!<key>` forms and the
    current `/file/<handle>#<key>` name the same file, so they collide; two
    different files never do, which the fragment-dropping rule broke
    (every legacy link was `https://mega.nz/`). Handles are read as a
    PREFIX, so prose punctuation after a link cannot defeat the rule, and
    a fragment of a shape this does not know is dropped: MEGA's account
    routes (confirmation, recovery) carry secrets and name no resource."""
    m = _MEGA_PATH.fullmatch(path)
    if m:
        kind, handle = m.groups()
        kind = "file" if kind == "embed" else kind
        canon = f"/{kind}/{handle}"
        if kind == "folder" and frag:
            sub = _MEGA_IN_FOLDER.match(frag)
            if sub:
                return f"{canon}/{sub.group(1)}/{sub.group(2)}", ""
        return canon, ""
    if path in ("", "/"):
        if not frag:
            return path, ""
        m = _MEGA_LEGACY_FOLDER.match(frag)
        if m:
            base = f"/folder/{m.group(1)}"
            if m.group(2) == "!":
                return f"{base}/folder/{m.group(3)}", ""
            if m.group(2) == "?":
                return f"{base}/file/{m.group(3)}", ""
            return base, ""
        m = _MEGA_LEGACY_FILE.match(frag)
        if m:
            return f"/file/{m.group(1)}", ""
        m = _MEGA_PASSWORD.match(frag)
        if m:
            # A password-protected link: the blob IS the encrypted link,
            # not a key, and is the only thing that names the resource.
            return "/", f"P!{m.group(1)}"
        return path, ""
    return path, ""


def _matrix_to(path: str, frag: str) -> tuple[str, str]:
    """matrix.to names its user or room in the fragment (`#/@alice:x`),
    with an optional `?via=` routing hint that is not identity."""
    if not frag.startswith("/") or len(frag) < 2:
        return path, ""
    ident, sep, query = frag.partition("?")
    if sep and not _MATRIX_VIA.fullmatch(query):
        ident = ident + "?" + query     # a foreign query is kept as written
    ident = _MATRIX_SAFE.sub(lambda m: _MATRIX_CHARS[m.group(1).lower()], ident)
    if len(ident) < 2:
        return path, ""                 # an empty route names nothing
    return "/", ident


def _web_telegram(path: str, frag: str) -> tuple[str, str]:
    """web.telegram.org names the chat in the fragment, and it also carries
    secrets there: its login link is `#tgWebAuthToken=<token>&...`, and a
    `tgaddr` can hold a tg://login token or a bot's start parameter. So the
    fragment is kept, as written, only in a shape that names a chat and
    cannot hold a token (L5, 2026-09-24):
    `@name`, a numeric peer id with at most two numeric suffixes, the old
    client's `/im?p=<peer>`, and a `?tgaddr=` whose address is a public
    tg://resolve. Any other fragment is dropped, which at worst misses a
    distinction and never puts a token into a norm_value."""
    if _TG_CHAT.fullmatch(frag) or _TG_LEGACY_IM.fullmatch(frag):
        return path, frag
    m = _TG_ADDR.fullmatch(frag)
    if m and _TG_RESOLVE.fullmatch(unquote(m.group(1))):
        return path, frag
    return path, ""


def _twitter(path: str, frag: str) -> tuple[str, str]:
    """The legacy hashbang form `twitter.com/#!/name` is `twitter.com/name`
    written another way. Any other fragment is dropped."""
    if path in ("", "/"):
        m = _TWITTER_ROUTE.match(frag)
        if m and len(m.group(1)) > 1:
            return m.group(1), ""
    return path, ""


#: Hosts whose fragment can name the resource, after lowercasing, dropping
#: one trailing '.' and one leading 'www.': host -> (canonical host or None
#: to keep the host, rule). A registered host's rule always decides the path
#: and the fragment. Every other host drops its fragment, as url_norm always
#: did: a single-page app's route can carry a token or a key (a reset link,
#: a CryptPad pad, a Send link), and a token in a norm_value is a secret in
#: a selector label on the graph, in search and in reports. A generic
#: keep-the-route rule does exactly that, so only routes known to be
#: identities are kept.
_FRAGMENT_HOSTS: dict[str, tuple[str | None, Callable[[str, str], tuple[str, str]]]] = {
    "mega.nz": ("mega.nz", _mega),
    "mega.co.nz": ("mega.nz", _mega),
    "mega.io": ("mega.nz", _mega),
    "matrix.to": ("matrix.to", _matrix_to),
    "web.telegram.org": ("web.telegram.org", _web_telegram),
    "twitter.com": ("twitter.com", _twitter),
}

#: Every host under these is MEGA's: its own host is kept, and the MEGA rule
#: decides the fragment, so no MEGA key survives on any of them.
_MEGA_DOMAINS = (".mega.nz", ".mega.co.nz", ".mega.io")


def _fragment_rule(host: str):
    key = host[:-1] if host.endswith(".") else host
    key = key[4:] if key.startswith("www.") else key
    rule = _FRAGMENT_HOSTS.get(key)
    if rule is not None:
        return rule
    if key.endswith(_MEGA_DOMAINS):
        return (None, _mega)
    return None


#: Query parameter names that carry a credential rather than name a
#: resource, compared lowercased with everything but letters and digits
#: removed (`api_key`, `API-Key` and `apiKey` are one name). A name in the
#: set, or ending in one of the suffixes, is a secret
#: (graph-url-selector-keeps-credentials, 2026-10-03).
_SECRET_QUERY_KEYS = frozenset({
    "key", "apikey", "pass", "passwd", "password", "pwd", "pw", "secret",
    "token", "auth", "authorization", "sig", "signature", "jwt", "otp",
    "sid", "sessid", "phpsessid", "session", "sessionid", "sessionkey",
    "credential", "credentials", "authkey", "passphrase", "passcode",
    "bearer",
    # An OAuth authorisation code is a one-time credential
    # (graph-url-selector-keeps-credentials, 2026-10-03, verify round).
    "code", "authcode", "oauthcode",
})
_SECRET_QUERY_SUFFIXES = ("token", "secret", "password", "passwd", "apikey",
                          "accesskey", "secretkey", "privatekey", "signature",
                          "sessionid", "credential")
_NOT_ALNUM = re.compile(r"[^a-z0-9]")
#: A URL with a scheme, as it sits in running text. A quote or a closing
#: bracket does not end it: `'` and `)` are legal in a password, and a
#: pattern that stopped at one would leave the rest of the password outside
#: the URL it belongs to (the sentence's own punctuation is given back by
#: `_URL_TAIL`). The scheme is bounded and possessive so the scan is linear:
#: an unbounded one is quadratic on a long run of scheme characters with no
#: `://` after it (40,000 characters of `a-` took seconds), and a capture
#: may be a million characters long (2026-10-03, verify round).
URL_IN_TEXT = re.compile(r"\b[a-z][a-z0-9+.-]{0,63}+://[^\s<>\"]+", re.I)
#: What stands in for a removed password, token or key in text a person
#: reads (a Triage rationale, a raw value).
REDACTED = "REDACTED"


def _secret_query_key(name: str) -> bool:
    key = _NOT_ALNUM.sub("", unquote(name.replace("+", " ")).lower())
    return key in _SECRET_QUERY_KEYS or key.endswith(_SECRET_QUERY_SUFFIXES)


def _split_authority(s: str) -> tuple[str, str, str] | None:
    """(scheme and '://', authority, rest) of a URL string, or None when it
    has no '://'. The authority ends at the first '/', '?' or '#', as
    urlsplit reads it."""
    scheme, sep, rest = s.partition("://")
    if not sep or not scheme:
        return None
    end = len(rest)
    for ch in "/?#":
        i = rest.find(ch)
        if i != -1:
            end = min(end, i)
    return scheme + sep, rest[:end], rest[end:]


def _userinfo_end(authority: str, rest: str) -> int | None:
    """Where the userinfo of a URL ends, as an offset into authority+rest
    (the index of its '@'), or None when it has none.

    The ordinary case is an '@' inside the authority. The other is a
    password holding '/', '?' or '#', which ends the authority early for
    urlsplit: `https://alice:pa/ss@bank.example/` reads as host `alice`
    with port `pa`, and the rest of the password lands in the path. A
    port that is not a number, followed by an '@' later in the URL, is
    read as that password, so it never survives into a norm_value."""
    if "@" in authority:
        return authority.rindex("@")
    # Exactly one ':' only: an IPv6 literal (bracketed, or as url_norm
    # writes it back) is a host, not a password.
    if authority.startswith("[") or authority.count(":") != 1:
        return None
    port = authority.rsplit(":", 1)[1]
    # An empty port (`host:/path@x`) is a valid port, not a password.
    if port == "" or port.isdigit() or "@" not in rest:
        return None
    return len(authority) + rest.index("@")


def strip_url_userinfo(v: str) -> str:
    """The URL without its userinfo (`user:password@`). A credential is
    never an identifier, and in a norm_value it is a secret in a selector
    label on the graph (graph-url-selector-keeps-credentials,
    2026-10-03)."""
    parts = _split_authority(v)
    if parts is None:
        return v
    head, authority, rest = parts
    at = _userinfo_end(authority, rest)
    if at is None:
        return v
    return head + (authority + rest)[at + 1:]


_PAIR_SEP = re.compile(r"([&;])")
#: A path parameter (`/app;jsessionid=ABC/page`): `;name=value` up to the
#: next `;` or `/`.
_PATH_PARAM = re.compile(r";([^;/=]*)=[^;/]*")
#: A `login:password` pair written onto the end of a link, the stealer-log
#: and combo-list layout `url:login:password`: the first path segment that
#: holds a ':' with an '@' after it, so the login is an e-mail address. Group
#: 1 is everything up to the ':'. A plain login (`/login:alice:pw`) cannot be
#: told from a path, and is not found (docs/17).
_LOGIN_TAIL = re.compile(r"(/[^/?#:@]*):[^/?#]*@")


def _first_of(s: str, chars: str) -> int:
    """The offset of the first of `chars` in `s`, or its length."""
    return min((i for i in (s.find(c) for c in chars) if i != -1),
               default=len(s))


def _piece_name_is_secret(piece: str) -> bool:
    """Whether one `name=value` piece of a query or a fragment names a
    credential: as written, or with a percent-encoded `=` (`token%3dabc`)
    that hid the name."""
    if _secret_query_key(piece.partition("=")[0]):
        return True
    plain = unquote(piece)
    return plain != piece and "=" in plain and _secret_query_key(
        plain.partition("=")[0])


def _nested_credential(text: str) -> bool:
    """Whether a value carries a link with a credential of its own
    (`next=https://carol:pw@evil.example/`), written plainly or percent-
    encoded."""
    if redact_url_credentials(text, 1) != text:
        return True
    plain = unquote(text)
    return plain != text and redact_url_credentials(plain, 1) != plain


def _piece_is_secret(piece: str) -> bool:
    name, eq, value = piece.partition("=")
    return _piece_name_is_secret(piece) or _nested_credential(
        value if eq else piece)


def _drop_secret_query(query: str) -> str:
    """The query without its credential-bearing parameters; every other
    parameter is kept byte-exact and in order. Parameters end at `&` or `;`
    (the older separator); a dropped one takes the separator before it."""
    if not query:
        return query
    parts = _PAIR_SEP.split(query)
    out = []
    for i in range(0, len(parts), 2):
        if not _piece_is_secret(parts[i]):
            out.append((parts[i - 1] if i else "", parts[i]))
    return "".join((sep if n else "") + piece
                   for n, (sep, piece) in enumerate(out))


def _drop_secret_path_params(path: str) -> str:
    """The path without its credential-bearing parameters
    (`/app;jsessionid=ABC` becomes `/app`)."""
    if ";" not in path:
        return path
    return _PATH_PARAM.sub(
        lambda m: "" if _secret_query_key(m.group(1)) else m.group(0), path)


def _clean_path_part(s: str) -> str:
    """`s`, a URL, without a credential in its path: the userinfo of a link
    written inside it (`/redir/https://carol:pw@evil.example/`), and a
    `:login:password` pair written after it, which takes the rest of the
    string with it (it was the end of the line it came from)."""
    parts = _split_authority(s)
    if parts is None:
        return s
    head, authority, rest = parts
    cut = _first_of(rest, "?#")
    path, after = rest[:cut], rest[cut:]
    path = URL_IN_TEXT.sub(lambda m: strip_url_userinfo(m.group(0)), path)
    tail = _LOGIN_TAIL.search(path)
    if tail is not None:
        return head + authority + path[:tail.end(1)]
    return head + authority + path + after


def _scrub_text(s: str) -> str:
    """A URL as text, without any credential, and with every other byte as
    written: what `url_norm` returns for a value it cannot parse, and the
    form 0137 rewrites a stored one to."""
    s = _clean_path_part(strip_url_userinfo(s))
    f = s.find("#")
    body, fragment = (s, "") if f == -1 else (s[:f], s[f:])
    q = body.find("?")
    path, query = (body, "") if q == -1 else (body[:q], body[q + 1:])
    kept = _drop_secret_query(query)
    bare = _drop_secret_path_params(path)
    if kept == query and bare == path:
        return s      # nothing to take out: exactly as written
    return bare + ("?" + kept if kept else "") + fragment


def _redact_piece(piece: str, depth: int) -> str:
    name, eq, value = piece.partition("=")
    if eq and value and _secret_query_key(name):
        return name + "=" + REDACTED
    if not eq:
        # a percent-encoded `=` hid the name: `token%3dabc`
        plain = unquote(piece)
        if plain != piece and "=" in plain and _secret_query_key(
                plain.partition("=")[0]):
            return REDACTED
    body = value if eq else piece
    inner = redact_url_credentials(body, depth + 1)
    if inner != body:
        return (name + "=" if eq else "") + inner
    plain = unquote(body)
    if plain != body and redact_url_credentials(plain, depth + 1) != plain:
        return (name + "=" if eq else "") + REDACTED
    return piece


def _redact_pairs(pairs: str, depth: int) -> str:
    """`a=b&c=d` with the value of every credential-bearing name replaced
    by REDACTED, a link inside a value redacted the same way, and a piece
    without a value, and every other pair, as written."""
    parts = _PAIR_SEP.split(pairs)
    for i in range(0, len(parts), 2):
        parts[i] = _redact_piece(parts[i], depth)
    return "".join(parts)


def _redact_path(path: str, depth: int) -> str:
    """A path with the credentials in it replaced: path parameters, the
    userinfo of a link inside it, and a `:login:password` pair after it."""
    path = _PATH_PARAM.sub(
        lambda m: (m.group(0).partition("=")[0] + "=" + REDACTED
                   if _secret_query_key(m.group(1)) else m.group(0)), path)
    path = redact_url_credentials(path, depth + 1)
    tail = _LOGIN_TAIL.search(path)
    if tail is not None:
        path = path[:tail.end(1)] + ":" + REDACTED
    return path


#: What a URL in running text does not own at its end: the sentence's own
#: punctuation, kept after the redaction instead of swallowed by it.
_URL_TAIL = ".,;:!?)]}>'\""
#: How many links inside links `redact_url_credentials` reads.
_MAX_NESTING = 6


def redact_url_credentials(text: str, _depth: int = 0) -> str:
    """`text` with every URL's userinfo and every credential-bearing query
    or fragment value replaced by REDACTED. For text a person reads that
    quotes a URL: a Triage rationale's context, an index row's raw value.
    Everything else is left exactly as written, so offsets into the
    surrounding text stay meaningful to a reader.

    A link inside a link (a value that is itself a URL) is read the same
    way, to `_MAX_NESTING` levels. Deeper than that is not read at all and
    is shown as REDACTED: a crafted run of nested links would otherwise
    cost a frame per level and end in a RecursionError in a capture."""
    if _depth > _MAX_NESTING:
        return REDACTED if URL_IN_TEXT.search(text) else text

    def one(m: re.Match) -> str:
        found = m.group(0)
        url = found.rstrip(_URL_TAIL)
        tail = found[len(url):]
        parts = _split_authority(url)
        if parts is None:
            return found
        head, authority, rest = parts
        at = _userinfo_end(authority, rest)
        if at is not None:
            # `head` holds the '://', so the split always succeeds.
            _, host, rest = _split_authority(head + (authority + rest)[at + 1:])
            authority = REDACTED + "@" + host
        f = rest.find("#")
        fragment = "" if f == -1 else "#" + _redact_pairs(rest[f + 1:], _depth)
        body = rest if f == -1 else rest[:f]
        q = body.find("?")
        path = body if q == -1 else body[:q]
        query = "" if q == -1 else "?" + _redact_pairs(body[q + 1:], _depth)
        return (head + authority + _redact_path(path, _depth) + query
                + fragment + tail)
    return URL_IN_TEXT.sub(one, text)


def credential_spans(text: str) -> list[tuple[int, int]]:
    """Where, in running text, a URL of ANY scheme holds a credential, as
    (start, end) offsets: its userinfo with the '@' that closes it
    (`mysql://root:Secret123@db.example/app` gives `root:Secret123@`), and a
    `:login:password` pair written after its path. The selector extractor
    reads nothing out of these spans: a password is not an identifier, and
    only http and https links are URL selectors, so the userinfo of an
    `ftp://`, `smtp://` or `mysql://` link was read as an e-mail address
    (graph-url-selector-keeps-credentials, 2026-10-03, verify round)."""
    spans: list[tuple[int, int]] = []
    for m in URL_IN_TEXT.finditer(text):
        url = m.group(0).rstrip(_URL_TAIL)
        parts = _split_authority(url)
        if parts is None:
            continue
        head, authority, rest = parts
        origin = m.start() + len(head)
        at = _userinfo_end(authority, rest)
        remainder = authority + rest
        if at is not None:
            spans.append((origin, origin + at + 1))
            remainder = remainder[at + 1:]
            origin += at + 1
        host_end = _first_of(remainder, "/?#")
        path = remainder[host_end:]
        path = path[:_first_of(path, "?#")]
        tail = _LOGIN_TAIL.search(path)
        if tail is not None:
            spans.append((origin + host_end + tail.end(1), m.start() + len(url)))
    return spans


def url_norm(v: str) -> str:
    """Lowercase scheme+host, strip the default port; path and query stay
    byte-exact (they are case- and encoding-sensitive), except that a
    credential never stays: the userinfo (`user:password@`) is dropped,
    and so is every query parameter whose name says it carries a password,
    token, key, signature or session (`_SECRET_QUERY_KEYS`;
    graph-url-selector-keeps-credentials, 2026-10-03). The same goes for a
    path parameter of that kind (`;jsessionid=...`), a parameter set off by
    `;` or with a percent-encoded `=`, a parameter whose value holds a link
    with a credential of its own, the userinfo of a link written inside the
    path, and a `:login:password` pair written after the path (the
    `url:login:password` layout of a stealer log), which ends the link
    there. Like a dropped
    fragment, that at worst misses a distinction, and never puts a secret
    into a selector label. The fragment is dropped unless the host is one
    whose fragment names the resource (L5, 2026-09-24):

    - MEGA (mega.nz, mega.co.nz, mega.io and their subdomains): the link
      in its current path form, WITHOUT the decryption key. A legacy
      `#!<handle>!<key>` link and a current `/file/<handle>#<key>` link to
      one file collide; two files never do. A key is not identity, and in
      a norm_value it would be a secret in a selector label.
    - matrix.to: the user or room, with a `?via=` hint removed and only
      the escapes that cannot change meaning decoded.
    - web.telegram.org: the chat (`@name`, a numeric peer id, the old
      client's `/im?p=` form, a `tgaddr` public resolve), kept as written.
      Its login token, and any fragment of another shape, is dropped.
    - twitter.com: the legacy `#!/name` form becomes `/name`.

    Every other fragment (an anchor such as `#post-9`, and any route on an
    unregistered host) is dropped, as before, so no host outside this list
    can put a token into a norm_value. The first rule of this module is
    that two different identifiers never collide; dropping the fragment
    broke it for every link above, and the registry mends exactly those.
    norm(norm(x)) == norm(x) holds for every rule, including on hostile
    input (tested)."""
    s = _clean_path_part(strip_url_userinfo(v.strip()))
    # A value that does not parse is returned as written, but never with a
    # credential in it (2026-10-03, verify round).
    try:
        parts = urlsplit(s)
    except ValueError:
        return _scrub_text(s)
    if not parts.scheme or not parts.netloc:
        return _scrub_text(s)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not parts.hostname:
        return _scrub_text(s)
    path, frag = parts.path, ""
    rule = _fragment_rule(host)
    if rule is not None:
        canon, fn = rule
        host = canon or (host[:-1] if host.endswith(".") else host)
        path, frag = fn(parts.path, parts.fragment)
    netloc = host
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None and str(port) != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    # No userinfo: `strip_url_userinfo` took it, and netloc is rebuilt from
    # the host and port alone (graph-url-selector-keeps-credentials).
    # Cleaned once more as written back: a fragment rule can make a path
    # (`twitter.com/#!/:@` becomes `/:@`), and the form must be a fixed point.
    return _clean_path_part(urlunsplit(
        (scheme, netloc, _drop_secret_path_params(path),
         _drop_secret_query(parts.query), frag)))


def tox_pubkey(v: str) -> str:
    """THE Tox nuance (invariant 9): the 76-hex Tox ID is
    <64-hex public key><8-hex nospam><4-hex checksum>, and the actor can
    rotate the nospam at will. The durable identity is the first 64 hex.
    A rotated nospam MUST normalise to the same value."""
    s = _WS.sub("", v).upper()
    if len(s) == 76 and _HEX_RE.match(s):
        return s[:64]
    return s


def sip_norm(v: str) -> str:
    """Bare SIP AOR: scheme lowercased, user part kept BYTE-EXACT, host
    lowercased, and the parameters dropped.

    Two deliberate asymmetries, both from RFC 3261 §19.1.4:

    - The user part is case-SENSITIVE. `sip:Alice@x` and `sip:alice@x`
      are different AORs, and folding them would merge two subscribers.
      (Contrast `email_norm`, where the local part is folded because
      every mailbox provider in practice treats it that way.)
    - `;user=phone`, `;transport=tls` and friends are transport
      decisions, not identity — the same AOR observed over UDP and over
      TLS must collide, so the parameters go.

    A trailing `;tag=` never belongs to an AOR at all; it is dialogue
    state that only appears if someone pasted a raw From: header.
    """
    s = v.strip()
    if "<" in s and ">" in s:                     # a name-addr: "Bob" <sip:b@x>
        s = s[s.find("<") + 1:s.find(">")].strip()
    scheme, sep, rest = s.partition(":")
    if not sep or scheme.lower() not in ("sip", "sips", "tel"):
        return s
    rest = rest.split(";", 1)[0].split("?", 1)[0]
    user, at, host = rest.rpartition("@")
    if not at:                                    # tel: or a hostless AOR
        return f"{scheme.lower()}:{rest.lower()}"
    return f"{scheme.lower()}:{user}@{host.lower()}"


def msgid_norm(v: str) -> str:
    """RFC 5322 Message-ID without its angle brackets.

    The id-left is case-sensitive per the grammar and is left alone; only
    the domain-ish id-right folds. This is a WEAK selector by design
    (docs/19) — a Message-ID on attacker-sent mail is attacker-generated,
    so it fingerprints the sending KIT, never the sender.
    """
    s = v.strip()
    if s.startswith("<") and s.endswith(">"):
        s = s[1:-1].strip()
    left, at, right = s.rpartition("@")
    return f"{left}@{right.lower()}" if at else s


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
    "sip_norm": sip_norm,
    "msgid_norm": msgid_norm,
}


def normalise(selector_type_key: str, raw_value: str) -> str:
    """Normalise a raw observation for the given selector type key."""
    from noctornal_ontology.definition import SELECTOR_TYPES

    for st in SELECTOR_TYPES:
        if st.key == selector_type_key:
            return NORMALISERS[st.normaliser](raw_value)
    raise KeyError(f"unknown selector type: {selector_type_key!r}")

"""Every normaliser is tested here; the registry tests at the bottom fail
if the definition references a normaliser that does not exist or a
normaliser exists that nothing references.

Source is deliberately ASCII-only: non-ASCII test inputs (Cyrillic
homoglyphs, emoji) are written as escape sequences.
"""
import pytest

from noctornal_ontology.definition import SELECTOR_TYPES
from noctornal_ontology.normalisers import NORMALISERS, normalise

# apple.com homoglyph with Cyrillic a/r/palochka/e, and an owl emoji.
CYRILLIC_APPLE = "аррӏе.com"
OWL = "\U0001f989"


def test_exact_is_identity():
    assert NORMALISERS["exact"](" AbC  ") == " AbC  "


def test_trim():
    assert NORMALISERS["trim"]("  Sectigo RSA Code Signing CA  ") == "Sectigo RSA Code Signing CA"


def test_lower_trim():
    assert NORMALISERS["lower_trim"](" KillNet@Exploit.IM ") == "killnet@exploit.im"


def test_upper_nospace():
    assert NORMALISERS["upper_nospace"](" ab 12 cd ") == "AB12CD"
    assert NORMALISERS["upper_nospace"]("ec4f 2d8a") == "EC4F2D8A"  # Threema style


def test_digits():
    assert NORMALISERS["digits"]("ID: 123 456 789") == "123456789"
    assert NORMALISERS["digits"]("777000") == "777000"


def test_lower_strip_at():
    assert NORMALISERS["lower_strip_at"]("@DarkSeller") == "darkseller"
    assert NORMALISERS["lower_strip_at"]("DarkSeller") == "darkseller"
    # only a LEADING @ is an @-handle sigil
    assert NORMALISERS["lower_strip_at"]("a@b") == "a@b"


def test_upper_hex_and_lower_hex():
    assert NORMALISERS["upper_hex"](" deadBEEF ") == "DEADBEEF"
    assert NORMALISERS["lower_hex"](" DEADbeef ") == "deadbeef"


def test_hex_nospace_variants():
    # PGP fingerprints are printed in groups of four
    assert (
        NORMALISERS["upper_hex_nospace"]("59d3 4c99 8672 8b1a 0aeb  1f2c a41f 9dc7 6f08 6f5b")
        == "59D34C9986728B1A0AEB1F2CA41F9DC76F086F5B"
    )
    assert NORMALISERS["lower_hex_nospace"]("AB CD ef 01") == "abcdef01"


class TestEmailNorm:
    def test_case_and_trim(self):
        assert NORMALISERS["email_norm"](" John.Doe@Example.COM ") == "john.doe@example.com"

    def test_gmail_dots_and_plus_stripped(self):
        assert NORMALISERS["email_norm"]("j.o.h.n+spam@gmail.com") == "john@gmail.com"

    def test_googlemail_is_same_mailbox_space(self):
        assert NORMALISERS["email_norm"]("John.Doe@googlemail.com") == "johndoe@gmail.com"

    def test_non_gmail_dots_kept(self):
        assert NORMALISERS["email_norm"]("john.doe+tag@proton.me") == "john.doe+tag@proton.me"

    def test_not_an_email_passes_through(self):
        assert NORMALISERS["email_norm"]("not-an-email") == "not-an-email"


class TestE164:
    def test_separators_stripped(self):
        assert NORMALISERS["e164"]("+1 (416) 555-0199") == "+14165550199"

    def test_double_zero_prefix(self):
        assert NORMALISERS["e164"]("0049 30 123456") == "+4930123456"

    def test_bare_national_number_stays_digits(self):
        # no country context - cannot invent one
        assert NORMALISERS["e164"]("416 555 0199") == "4165550199"


class TestSshNorm:
    def test_comment_dropped(self):
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJx7 someone@host"
        assert NORMALISERS["ssh_norm"](key) == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJx7"

    def test_no_comment_unchanged(self):
        key = "ssh-rsa AAAAB3NzaC1yc2E="
        assert NORMALISERS["ssh_norm"](key) == key

    def test_non_key_text_trimmed_only(self):
        assert NORMALISERS["ssh_norm"](" random text here ") == "random text here"


class TestBtcNorm:
    def test_bech32_lowercased(self):
        assert (
            NORMALISERS["btc_norm"]("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
            == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        )

    def test_base58_case_preserved(self):
        addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        assert NORMALISERS["btc_norm"](addr) == addr


class TestEip55:
    def test_checksummed_and_lower_collide(self):
        checksummed = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        assert NORMALISERS["eip55"](checksummed) == NORMALISERS["eip55"](checksummed.lower())

    def test_missing_prefix_added(self):
        assert (
            NORMALISERS["eip55"]("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
            == "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
        )


class TestPunycodeLower:
    def test_ascii_lower_and_root_dot(self):
        assert NORMALISERS["punycode_lower"]("Example.COM.") == "example.com"

    def test_cyrillic_homoglyph_becomes_wire_form(self):
        # Must normalise to the punycode actually seen on the wire, not
        # hide behind Unicode.
        assert NORMALISERS["punycode_lower"](CYRILLIC_APPLE) == "xn--80ak6aa92e.com"


class TestIpNorm:
    def test_ipv4_passthrough(self):
        assert NORMALISERS["ip_norm"]("203.0.113.7") == "203.0.113.7"

    def test_ipv6_compressed_and_lowered(self):
        assert (
            NORMALISERS["ip_norm"]("2001:0DB8:0000:0000:0000:0000:0000:0001")
            == "2001:db8::1"
        )

    def test_bracketed_ipv6(self):
        assert NORMALISERS["ip_norm"]("[2001:db8::1]") == "2001:db8::1"

    def test_v4_mapped_unwrapped(self):
        assert NORMALISERS["ip_norm"]("::ffff:203.0.113.7") == "203.0.113.7"

    def test_garbage_passes_through(self):
        assert NORMALISERS["ip_norm"]("not-an-ip") == "not-an-ip"


def test_asn_norm():
    assert NORMALISERS["asn_norm"]("AS13335") == "13335"
    assert NORMALISERS["asn_norm"]("as 13335") == "13335"
    assert NORMALISERS["asn_norm"]("13335") == "13335"
    # leading zeros collapse to the same ASN
    assert NORMALISERS["asn_norm"]("AS013335") == "13335"
    # RFC 5396 asdot converts to asplain instead of colliding with AS110
    assert NORMALISERS["asn_norm"]("AS1.10") == "65546"
    assert NORMALISERS["asn_norm"]("AS1.10") != NORMALISERS["asn_norm"]("AS110")


class TestUrlNorm:
    def test_host_and_scheme_lowered_path_kept(self):
        assert (
            NORMALISERS["url_norm"]("HTTPS://Forum.Example.COM/Thread/42?Page=2#post-9")
            == "https://forum.example.com/Thread/42?Page=2"
        )

    def test_default_port_stripped(self):
        assert NORMALISERS["url_norm"]("https://example.com:443/x") == "https://example.com/x"
        assert NORMALISERS["url_norm"]("http://example.com:8080/x") == "http://example.com:8080/x"

    def test_schemeless_passthrough(self):
        assert NORMALISERS["url_norm"]("example.com/path") == "example.com/path"


class TestToxPubkey:
    # 64-hex public key + 8-hex nospam + 4-hex checksum = 76-hex Tox ID
    PK = "56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE51855"

    def test_full_id_truncated_to_pubkey(self):
        assert NORMALISERS["tox_pubkey"](self.PK + "D34714D6" + "43BB") == self.PK

    def test_rotated_nospam_same_norm_value(self):
        """Invariant 9: the nospam is user-rotatable; the identity is not.
        The same actor before and after rotation MUST collide."""
        before = NORMALISERS["tox_pubkey"](self.PK + "D34714D6" + "43BB")
        after = NORMALISERS["tox_pubkey"](self.PK + "00000000" + "9A21")
        assert before == after == self.PK

    def test_bare_pubkey_unchanged(self):
        assert NORMALISERS["tox_pubkey"](self.PK.lower()) == self.PK

    def test_spaced_and_cased_input(self):
        spaced = self.PK[:32].lower() + " " + self.PK[32:] + "D34714D6" + "43BB"
        assert NORMALISERS["tox_pubkey"](spaced) == self.PK

    def test_non_tox_length_left_alone(self):
        assert NORMALISERS["tox_pubkey"]("abc123") == "ABC123"


def test_every_definition_normaliser_exists():
    missing = {s.normaliser for s in SELECTOR_TYPES} - set(NORMALISERS)
    assert not missing, f"definition references unknown normalisers: {missing}"


def test_no_orphan_normalisers():
    used = {s.normaliser for s in SELECTOR_TYPES}
    orphans = set(NORMALISERS) - used
    assert not orphans, f"normalisers not referenced by any selector type: {orphans}"


@pytest.mark.parametrize("name", sorted(NORMALISERS))
def test_normaliser_is_total_on_awkward_input(name):
    """Normalisers never raise - validation is a separate concern."""
    fn = NORMALISERS[name]
    for awkward in ("", "   ", " ", OWL, "a" * 10_000, "%s", "'; DROP TABLE--"):
        assert isinstance(fn(awkward), str)


def test_normalise_helper_dispatches():
    assert normalise("TELEGRAM_USER", "@SomeBody") == "somebody"
    with pytest.raises(KeyError):
        normalise("NOT_A_TYPE", "x")


def test_normalise_helper_idempotent_for_all_types():
    """norm(norm(x)) == norm(x): storing a norm_value and re-normalising
    it on a later observation must not change it."""
    sample = "  Mixed CASE @Value 00 49 (30) 123-456 xn--test  "
    for st in SELECTOR_TYPES:
        once = normalise(st.key, sample)
        assert normalise(st.key, once) == once, st.key


class TestE164Extension:
    def test_extension_dropped(self):
        assert NORMALISERS["e164"]("+1 (416) 555-0199 ext. 89") == "+14165550199"
        assert NORMALISERS["e164"]("416-555-0199 x22") == "4165550199"

    def test_same_line_with_and_without_ext_merges(self):
        assert NORMALISERS["e164"]("+1 416 555 0199 ext 4") == NORMALISERS["e164"]("+14165550199")


class TestJidNorm:
    def test_resourcepart_stripped(self):
        assert NORMALISERS["jid_norm"]("vendor@thesecure.biz/Psi+") == "vendor@thesecure.biz"

    def test_muc_and_contact_block_forms_merge(self):
        full = NORMALISERS["jid_norm"]("Vendor@TheSecure.biz/mobile-3f2a")
        bare = NORMALISERS["jid_norm"]("vendor@thesecure.biz")
        assert full == bare

    def test_bare_jid_lowercased(self):
        assert NORMALISERS["jid_norm"](" Vendor@Exploit.IM ") == "vendor@exploit.im"


class TestMxidNorm:
    def test_localpart_case_preserved(self):
        assert NORMALISERS["mxid_norm"]("@Alice:matrix.org") == "@Alice:matrix.org"
        assert NORMALISERS["mxid_norm"]("@Alice:matrix.org") != NORMALISERS["mxid_norm"]("@alice:matrix.org")

    def test_server_name_case_folded(self):
        assert NORMALISERS["mxid_norm"]("@alice:Matrix.ORG") == "@alice:matrix.org"

    def test_port_kept(self):
        assert NORMALISERS["mxid_norm"]("@bob:Example.COM:8448") == "@bob:example.com:8448"


class TestTelegramIdNorm:
    """CR3 (2026-07-26): the Bot-API encoding is arithmetic, not textual.

    `chat_id = -(10**12 + channel_id)`. The old implementation dropped the
    characters "100" from the front, which inverts that only for a
    ten-digit channel id — and the single test here covered exactly that
    case, so a wrong function stayed green.
    """

    # NOT a class attribute: a plain function stored on a class becomes a
    # bound method, so `self.N(x)` would pass `self` as the argument.
    N = staticmethod(NORMALISERS["telegram_id_norm"])

    def test_user_id_digits(self):
        assert self.N(" 777000 ") == "u:777000"

    def test_bot_api_supergroup_decoded_arithmetically(self):
        assert self.N("-1001234567890") == "c:1234567890"

    def test_a_nine_digit_channel_does_not_gain_a_leading_zero(self):
        """The old string-strip left "0123456789", matching nothing."""
        assert self.N("-1000123456789") == "c:123456789"

    def test_an_eleven_digit_channel_decodes_at_all(self):
        """Common since the 64-bit migration. "-1012345678901" does not
        begin "100" after the sign, so the old strip never fired and the
        two observations of one channel never met."""
        assert self.N("-1012345678901") == "c:12345678901"

    def test_a_channel_and_a_user_with_the_same_number_stay_apart(self):
        """TELEGRAM_ID is is_strong, so a collision here is an auto-merge
        of a channel and a person onto one actor."""
        assert self.N("-1001234567890") != self.N("1234567890")

    def test_basic_group_keeps_its_own_namespace(self):
        assert self.N("-987654321") == "g:987654321"
        assert self.N("-987654321") != self.N("987654321")
        assert self.N("-987654321") != self.N("-1000987654321")

    def test_an_explicit_type_prefix_is_honoured(self):
        """A scraper that KNOWS it recorded an MTProto channel says so, and
        then meets the Bot-API observation of the same channel."""
        assert self.N("c:1234567890") == self.N("-1001234567890")
        assert self.N("C: 1234567890") == "c:1234567890"
        assert self.N("u:777000") == self.N("777000")

    def test_empty_input_is_empty_not_a_crash(self):
        assert self.N("") == ""
        assert self.N("   ") == ""
        assert self.N("not a number") == ""


class TestTlshNorm:
    BODY = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3"

    def test_t1_and_legacy_forms_merge(self):
        assert NORMALISERS["tlsh_norm"]("T1" + self.BODY) == NORMALISERS["tlsh_norm"](self.BODY)

    def test_lowercase_uppercased(self):
        assert NORMALISERS["tlsh_norm"]("t1" + self.BODY.lower()) == self.BODY


class TestOnionNorm:
    HOST = "vendorxyzabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnop.onion"

    def test_bare_host_lowercased(self):
        assert NORMALISERS["onion_norm"](self.HOST.upper()) == self.HOST

    def test_url_and_fqdn_wrappers_stripped(self):
        assert NORMALISERS["onion_norm"](f"http://{self.HOST}/market/login") == self.HOST
        assert NORMALISERS["onion_norm"](self.HOST + ".") == self.HOST
        assert NORMALISERS["onion_norm"](f"{self.HOST}:8080") == self.HOST


class TestPunycodeIdna2008:
    def test_eszett_not_merged_with_ss(self):
        # faß.de and fass.de are separately registrable .de domains
        assert NORMALISERS["punycode_lower"]("faß.de") == "xn--fa-hia.de"
        assert NORMALISERS["punycode_lower"]("faß.de") != NORMALISERS["punycode_lower"]("fass.de")

    def test_unicode_and_wire_form_merge(self):
        assert NORMALISERS["punycode_lower"]("faß.de") == NORMALISERS["punycode_lower"]("xn--fa-hia.de")

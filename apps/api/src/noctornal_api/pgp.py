"""Phase 7 -- PGP signature verification (docs/10).

docs/10, on why this is worth building at all:

    PGP signed messages are the strong case. A message signed by a key
    whose fingerprint appears in the contact block is real cryptographic
    evidence of control, not a claim. Verify signatures where you can and
    record the verification as its own assertion.

Everything else in Phase 7 produces CLAIMS. This is the one path that
produces a CONFIRMATION, which is why it is also the one place where
getting it wrong is worst: a CONFIRMED binding is what docs/10 says may
carry weight in automatic identity resolution.

## No cryptography is implemented here

Verification is delegated to the `gpg` binary. This module parses its
machine-readable `--status-fd` output and nothing else -- never the
human-readable text, which is localised, reformatted between versions,
and has historically been spoofable by crafted user IDs.

If `gpg` is absent or unusable, the outcome is `NO_VERIFIER` and the
binding stays CLAIMED. A missing verifier is a failure to LOOK, and it is
recorded as distinct from a failure of the evidence so that "nobody has
checked these" is a query rather than a guess. There is no code path in
which an absent verifier produces a confirmation.

## The two traps, and why the schema holds them rather than this file

**Trap 1 -- the wrong key.** A signature that verifies proves control of
whatever key signed it. That is only interesting if it is the key the
actor CLAIMED. Verifying against "some key in our keyring" and reporting
success is evidence about a stranger.

**Trap 2 -- the replayed message.** A valid signature over some other
text says nothing about an identifier appended afterwards. Any signed
message a vendor ever published can be reposted with an attacker's Tox ID
pasted below it, and a naive `value in message` check passes -- because
the value IS in the message, just not in the part that was signed.

So the payload compared against is **gpg's own output of the verified
region**, obtained with `--output`, never the text we were handed. In a
clearsigned message everything after `-----END PGP SIGNATURE-----` is
unsigned and gpg does not emit it.

Both traps are ALSO CHECK constraints on `comms.pgp_verification`. That is
deliberate duplication: these are exactly the checks that survive review
and then get refactored away, and a constraint does not get refactored
away by accident.

## There is no TRUSTED outcome

GnuPG's web of trust answers "do I trust this key's owner", which is a
different question from "did this key sign this text". Only the second is
evidence here, so `--trust-model always` is passed and trust is never
consulted or reported. An investigator's keyring trust has no bearing on
whether a vendor controls a key.

## Expired and revoked keys

Both still prove the key signed the text, so both are recorded with their
own outcome rather than as failures. Neither is `VERIFIED`, so neither
upgrades a binding to CONFIRMED: a signature from a key revoked before
the message was published is a fact that needs a person to interpret, not
one a parser should convert into an attribution.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from uuid import UUID

import psycopg
from psycopg.types.json import Json

VERIFIED = "VERIFIED"
BAD_SIGNATURE = "BAD_SIGNATURE"
KEY_MISMATCH = "KEY_MISMATCH"
VALUE_NOT_IN_PAYLOAD = "VALUE_NOT_IN_PAYLOAD"
KEY_UNAVAILABLE = "KEY_UNAVAILABLE"
EXPIRED_KEY = "EXPIRED_KEY"
REVOKED_KEY = "REVOKED_KEY"
EXPIRED_SIGNATURE = "EXPIRED_SIGNATURE"
MALFORMED = "MALFORMED"
NO_VERIFIER = "NO_VERIFIER"

#: Outcomes for which gpg reported a good signature over the payload, so
#: the payload really is "the exact bytes that were signed". For anything
#: else the file gpg produced is attacker plaintext nobody signed, and
#: digesting it under that column's name would be a false record.
_SIGNED_PAYLOAD_OUTCOMES = frozenset({
    "VERIFIED", "KEY_MISMATCH", "VALUE_NOT_IN_PAYLOAD",
    "EXPIRED_KEY", "REVOKED_KEY", EXPIRED_SIGNATURE,
})

_FPR = re.compile(r"^[0-9A-F]{40}$|^[0-9A-F]{64}$")
_WS = re.compile(r"\s+")
#: How long gpg gets. A signature check is milliseconds; anything near
#: this is a hang, and a hang in an API worker is an outage.
GPG_TIMEOUT_SECONDS = 20
#: Refuse absurd input before handing it to a subprocess.
MAX_MESSAGE_BYTES = 1_000_000
MAX_KEY_BYTES = 1_000_000
#: Cap on what gpg may PRODUCE, not just what it is given. An armored
#: compressed message a few hundred KB long expands to hundreds of MB --
#: measured at 760x from a naive zeros bomb at half the input limit -- and
#: the result was previously read into memory whole. Bounded in two places
#: because either alone is insufficient: `--max-output` stops gpg writing
#: it, and the capped read stops US reading a file some other path created.
MAX_PAYLOAD_BYTES = 4_000_000
#: How much of the status stream to retain on the row. Kept from the FRONT:
#: the verdict is decided by the first VALIDSIG, and keeping the tail would
#: let a long user ID push the line that produced the verdict out of the
#: record that exists to justify it.
MAX_STATUS_CHARS = 8_000

#: A value shorter than this is never confirmed by containment. Short
#: strings appear inside longer numbers by coincidence, and a coincidence
#: that reads as cryptographic proof is worse than no answer.
MIN_CONFIRMABLE_LENGTH = 4
#: A value at least this long may match as a PREFIX of a longer token --
#: which is the normal Tox case, where the actor prints the full 76-hex ID
#: and the durable value is its 64-hex head. Below it, both ends must be
#: delimited.
PREFIX_MATCH_LENGTH = 32


class PgpError(Exception):
    pass


def normalise_fingerprint(value: str) -> str:
    """Uppercase hex, no spaces. Not cryptography -- formatting.

    Fingerprints circulate printed in groups of four. A comparison between
    the spaced and unspaced forms fails, and the failure looks like a key
    mismatch, which is the one outcome that must never be produced by a
    formatting difference.
    """
    cleaned = _WS.sub("", value or "").upper()
    # "0x" prefixes appear in profile fields and mail headers.
    if cleaned.startswith("0X"):
        cleaned = cleaned[2:]
    if not _FPR.match(cleaned):
        raise PgpError(
            f"{value!r} is not a PGP fingerprint: expected 40 hex characters "
            f"(v4) or 64 (v5), with or without spacing")
    return cleaned


@dataclass(frozen=True)
class VerificationResult:
    """What a verifier concluded, and the raw evidence for it."""

    outcome: str
    #: The fingerprint that ACTUALLY signed, per VALIDSIG. None when
    #: nothing verified.
    signing_fingerprint: str | None = None
    #: gpg's own output of the SIGNED region -- never the input text.
    signed_payload: bytes | None = None
    value_in_payload: bool = False
    #: The --status-fd lines, verbatim. A disputed verification should be
    #: re-readable rather than re-arguable.
    status_output: str = ""
    verifier: str = "GPG"
    verifier_version: str | None = None
    detail: str = ""

    @property
    def confirms(self) -> bool:
        return self.outcome == VERIFIED

    def signed_payload_present(self) -> bool:
        """Whether gpg emitted any verified plaintext.

        A method rather than exposing the bytes to callers who only want
        to know it exists: the payload is attacker-supplied content and
        should be read deliberately, not incidentally.
        """
        return bool(self.signed_payload)


def gpg_path() -> str | None:
    """The gpg binary, or None. `NOCTORNAL_GPG` overrides discovery."""
    override = os.environ.get("NOCTORNAL_GPG", "").strip()
    if override:
        return override if os.path.isfile(override) else None
    return shutil.which("gpg")


def verifier_version() -> str | None:
    path = gpg_path()
    if not path:
        return None
    try:
        out = subprocess.run(
            [path, "--version"], capture_output=True, text=True,
            timeout=GPG_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    first = (out.stdout or "").splitlines()
    return first[0].strip() if first else None


def _unavailable(detail: str) -> VerificationResult:
    return VerificationResult(
        outcome=NO_VERIFIER, verifier="NONE",
        detail=(f"{detail} No signature was checked. This is a failure to "
                f"LOOK, not a finding about the evidence, and the binding "
                f"stays CLAIMED."))


def verify_clearsigned(signed_message: str, public_key: str, *,
                       claimed_fingerprint: str,
                       confirms_value: str | None = None
                       ) -> VerificationResult:
    """Check a clearsigned message against a supplied public key.

    Runs in an EPHEMERAL keyring so the host's own keys are never
    consulted and nothing is imported anywhere durable -- a verification
    must not depend on what somebody imported last week, and a keyring
    that accumulates attacker-supplied keys is a liability of its own.
    """
    claimed = normalise_fingerprint(claimed_fingerprint)
    if not signed_message or not signed_message.strip():
        return VerificationResult(MALFORMED, detail="no signed message given")
    if not public_key or not public_key.strip():
        return VerificationResult(
            KEY_UNAVAILABLE,
            detail="no public key supplied, so there is nothing to check the "
                   "signature against")
    if len(signed_message.encode()) > MAX_MESSAGE_BYTES:
        return VerificationResult(MALFORMED, detail="signed message too large")
    if len(public_key.encode()) > MAX_KEY_BYTES:
        return VerificationResult(MALFORMED, detail="public key too large")
    if "-----BEGIN PGP SIGNED MESSAGE-----" not in signed_message:
        return VerificationResult(
            MALFORMED,
            detail="not a clearsigned message: no PGP SIGNED MESSAGE header")

    binary = gpg_path()
    if not binary:
        return _unavailable("No gpg binary is available on this host.")

    with tempfile.TemporaryDirectory(prefix="noctornal-pgp-") as work:
        os.makedirs(os.path.join(work, "home"), mode=0o700, exist_ok=True)
        with open(os.path.join(work, "key.asc"), "w",
                  encoding="utf-8", newline="") as fh:
            fh.write(public_key)
        with open(os.path.join(work, "message.asc"), "w",
                  encoding="utf-8", newline="") as fh:
            fh.write(signed_message)
        out_file = os.path.join(work, "verified.txt")

        # RELATIVE paths, with cwd set to the work directory.
        #
        # Not a style choice. The common Windows gpg is the MSYS build
        # shipped with Git, which expects POSIX paths: handed
        # `C:\Users\...\home` it resolves it against its own cwd and
        # produces a nonsense path, then reports "the supplied public key
        # could not be read" -- a MALFORMED outcome for a perfectly good
        # key. Relative paths sidestep drive-letter translation entirely
        # and work identically under a native Windows gpg and a POSIX one.
        base = [binary, "--homedir", "home", "--batch", "--no-tty",
                "--yes", "--quiet",
                # Trust answers a different question (see the module
                # docstring) and consulting it here would make the result
                # depend on the investigator's keyring.
                "--trust-model", "always",
                # No network. A key fetched mid-verification is a key the
                # attacker chose, and an outbound connection from an
                # evidence check is an operational leak.
                "--keyserver-options", "no-auto-key-retrieve",
                "--no-auto-key-locate", "--auto-key-locate", "nodefault",
                # Bound what gpg may PRODUCE. An armored compressed message
                # well inside MAX_MESSAGE_BYTES expands to hundreds of
                # megabytes; the input cap says nothing about the output.
                "--max-output", str(MAX_PAYLOAD_BYTES)]
        try:
            # text=False everywhere: the status stream carries
            # attacker-controlled user-ID bytes, and decoding it to str
            # both enables the line-injection in `_status_lines` and can
            # raise UnicodeDecodeError from inside subprocess (see
            # `_show`). Bytes in, decisions on ASCII tokens only.
            imported = subprocess.run(
                [*base, "--import", "key.asc"], cwd=work,
                capture_output=True, text=False,
                timeout=GPG_TIMEOUT_SECONDS, check=False)
            if imported.returncode != 0:
                return VerificationResult(
                    MALFORMED, status_output=_show(imported.stderr),
                    verifier_version=verifier_version(),
                    detail="the supplied public key could not be read")

            proc = subprocess.run(
                [*base, "--status-fd", "1", "--output", "verified.txt",
                 "--decrypt", "message.asc"], cwd=work,
                capture_output=True, text=False,
                timeout=GPG_TIMEOUT_SECONDS, check=False)
        except subprocess.TimeoutExpired:
            return _unavailable(
                f"gpg did not return within {GPG_TIMEOUT_SECONDS}s.")
        except OSError as exc:
            return _unavailable(f"gpg could not be run ({exc}).")

        status = proc.stdout or b""
        payload = b""
        if os.path.isfile(out_file):
            with open(out_file, "rb") as fh:
                # Capped independently of --max-output: this read must be
                # bounded by OUR limit, not by whatever produced the file.
                payload = fh.read(MAX_PAYLOAD_BYTES + 1)
            if len(payload) > MAX_PAYLOAD_BYTES:
                return VerificationResult(
                    MALFORMED, status_output=_show(status),
                    verifier_version=verifier_version(),
                    detail=(f"the signed payload exceeds "
                            f"{MAX_PAYLOAD_BYTES} bytes, which a "
                            f"contact block never does"))

    return _read_status(status, payload, claimed=claimed,
                        confirms_value=confirms_value,
                        version=verifier_version())


def _show(raw: bytes | None, limit: int = MAX_STATUS_CHARS) -> str:
    """Attacker bytes, rendered for the record and never for a decision.

    `errors="replace"` because an OpenPGP user ID is arbitrary bytes and
    gpg re-emits it unvalidated. Decoding it strictly threw
    `UnicodeDecodeError` from inside `subprocess`, which on Windows killed
    the reader thread and silently produced an empty stream -- reported as
    BAD_SIGNATURE for a signature that verified perfectly -- and on POSIX
    propagated out uncaught, so no row was recorded at all.
    """
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    if len(text) > limit:
        return text[:limit] + f"\n... [truncated at {limit} characters]"
    return text


def _status_lines(status: bytes) -> list[list[str]]:
    """Parse gpg's --status-fd stream. BYTES, split on b"\\n" ONLY.

    This is the whole defence against a forged verdict, so it is worth
    stating what goes wrong otherwise.

    gpg delimits status lines with `\\n` and percent-escapes `%` and every
    byte below 0x20 in the attacker-controlled user-ID field. It does NOT
    escape bytes at or above 0x80. Python's `str.splitlines()` splits on
    far more than `\\n`: it also breaks on U+0085, U+2028 and U+2029, none
    of which gpg escapes.

    So an attacker generated a key whose user ID was:

        Attacker Persona<U+0085>[GNUPG:] VALIDSIG <victim fingerprint> ...

    gpg emitted that verbatim inside GOODSIG -- which it emits BEFORE the
    real VALIDSIG -- `splitlines()` cut it into two lines, and the parser
    read the forged one first. Outcome VERIFIED, `signing_fingerprint` the
    victim's, binding upgraded to CONFIRMED, for a key the attacker did
    not hold. Reproduced end to end.

    The CHECK constraints could not catch it: they compare
    `signing_fingerprint` to `claimed_fingerprint`, and both came from the
    same lied-to parse, so they agreed. A constraint defends against the
    application forgetting to check; it cannot defend against the
    application checking a forged input.

    It was invisible on the Windows dev host because cp1252 does not map
    those bytes to line terminators. The deployment target is Linux under
    UTF-8, where it works.
    """
    out: list[list[str]] = []
    for line in (status or b"").split(b"\n"):
        if not line.startswith(b"[GNUPG:] "):
            continue
        # Fields are ASCII tokens; anything else in them is not something
        # a decision may rest on.
        out.append(line[9:].decode("ascii", errors="replace").split())
    return out


_TOKEN_CHAR = re.compile(r"[0-9A-Za-z]")


def _payload_contains(payload_text: str, value: str) -> tuple[bool, str]:
    """Is `value` genuinely NAMED in the signed text? (present, reason)

    A bare substring test is not enough, and the failure is not
    hypothetical. Telegram durable values are bare digits, so a vendor who
    signed an ordinary sentence containing an order number could confirm a
    stranger's account:

        signed: "Escrow order 3877451900 shipped 2026-07-25."
        value : "77451"      -> substring: True

    That drove a binding to CONFIRMED and recorded it as "cryptographic
    evidence ... of the key's holder publishing that identifier", which is
    false. The same collision happens by accident, which is worse, because
    nothing about it looks like an attack.

    The rule: the match must START at a token boundary, and must also END
    at one unless the value is long enough to be unambiguous on its own.
    The exception is load-bearing rather than a loophole -- an actor
    normally prints the full 76-hex Tox ID while the durable value is its
    64-hex head, so demanding a boundary at both ends would refuse the
    commonest legitimate case.
    """
    needle = (value or "").strip()
    if len(needle) < MIN_CONFIRMABLE_LENGTH:
        return False, (
            f"{needle!r} is too short ({len(needle)} characters) to be "
            f"confirmed by appearing in a text. Short strings occur inside "
            f"longer numbers by coincidence, and a coincidence that reads "
            f"as cryptographic proof is worse than no answer.")

    hay, low = payload_text.lower(), needle.lower()
    start = hay.find(low)
    while start != -1:
        left_ok = start == 0 or not _TOKEN_CHAR.match(hay[start - 1])
        end = start + len(low)
        right_ok = end == len(hay) or not _TOKEN_CHAR.match(hay[end])
        if left_ok and (right_ok or len(needle) >= PREFIX_MATCH_LENGTH):
            return True, ""
        start = hay.find(low, start + 1)
    return False, (
        f"{needle!r} does not appear in the signed text as an identifier. "
        f"It may occur inside a longer run of characters -- an order "
        f"number, another account -- which is not the same as the signer "
        f"naming it.")


def _read_status(status: bytes, payload: bytes, *, claimed: str,
                 confirms_value: str | None,
                 version: str | None) -> VerificationResult:
    """Decide the outcome from the machine-readable lines ONLY.

    Order matters. gpg emits VALIDSIG for an expired or revoked key as
    well as a good one, so checking VALIDSIG first would report a revoked
    key as a clean confirmation.
    """
    lines = _status_lines(status)
    codes = {parts[0] for parts in lines if parts}
    # VALIDSIG <fingerprint> <date> <sig-timestamp> ...
    validsigs = [parts[1].upper() for parts in lines
                 if len(parts) > 1 and parts[0] == "VALIDSIG"]
    signing = validsigs[0] if validsigs else None

    common = {"status_output": _show(status), "verifier_version": version,
              "signing_fingerprint": signing, "signed_payload": payload}

    # Taking the FIRST of several is what made line injection profitable,
    # and it is also wrong on its own terms: a message carrying two
    # signatures has two answers, and picking one silently is a guess
    # about which the analyst meant. Both fixed by refusing.
    if len(validsigs) > 1 or len({parts[0] for parts in lines
                                  if parts and parts[0] == "GOODSIG"}) > 1:
        return VerificationResult(
            MALFORMED, **common,
            detail=(f"the status stream reported {len(validsigs)} valid "
                    f"signatures. This system verifies ONE signature over "
                    f"ONE message; several means either a multiply-signed "
                    f"message or an attempt to smuggle a status line "
                    f"through a crafted user ID, and neither is something "
                    f"to resolve by picking the first."))

    if "NODATA" in codes and not signing:
        return VerificationResult(
            MALFORMED, **common,
            detail="gpg found no OpenPGP data in the message")
    if "REVKEYSIG" in codes:
        return VerificationResult(
            REVOKED_KEY, **common,
            detail="the signature is good but the key is REVOKED. That is a "
                   "fact for a person to interpret -- a signature from a key "
                   "revoked before the message was published is not the same "
                   "as one from a live key -- so it does not confirm a "
                   "binding on its own.")
    if "EXPKEYSIG" in codes:
        return VerificationResult(
            EXPIRED_KEY, **common,
            detail="the signature is good but the key had EXPIRED. It still "
                   "proves the key signed the text; it does not confirm a "
                   "binding without a person deciding the expiry is "
                   "immaterial.")
    if "EXPSIG" in codes:
        # The SIGNATURE expired, which is not the same as the KEY expiring.
        # gpg emits EXPSIG in place of GOODSIG, so without this branch it
        # fell through to "gpg did not report a good signature" -- failing
        # closed, but mislabelling the evidence as forged when it is
        # merely stale. The module gives expired KEYS their own outcome
        # for exactly this reason.
        return VerificationResult(
            EXPIRED_SIGNATURE, **common,
            detail="the signature is good but has EXPIRED. It still shows "
                   "the key signed the text; whether an expired signature "
                   "confirms anything now is a judgement for a person.")
    if "BADSIG" in codes:
        return VerificationResult(
            BAD_SIGNATURE, **common,
            detail="the signature did not verify against this key")
    if "NO_PUBKEY" in codes:
        return VerificationResult(
            KEY_UNAVAILABLE, **common,
            detail="the message was signed by a key that was not supplied")
    if "ERRSIG" in codes and "GOODSIG" not in codes:
        return VerificationResult(
            KEY_UNAVAILABLE, **common,
            detail="gpg could not check the signature (unsupported algorithm "
                   "or missing key)")
    if "GOODSIG" not in codes or not signing:
        return VerificationResult(
            BAD_SIGNATURE, **common,
            detail="gpg did not report a good signature")

    # TRAP 1. A good signature by a key nobody claimed is evidence about a
    # stranger.
    if signing != claimed:
        return VerificationResult(
            KEY_MISMATCH, **common,
            detail=(f"the signature is VALID but it was made by {signing}, "
                    f"not by the claimed key {claimed}. A signature proves "
                    f"control of whatever key signed it; if that is not the "
                    f"key the actor published, it says nothing about them."))

    if confirms_value is None:
        return VerificationResult(
            VALUE_NOT_IN_PAYLOAD, **common, value_in_payload=False,
            detail="the signature is valid and by the claimed key, but no "
                   "identifier was named for it to confirm. A valid signature "
                   "over unspecified text confirms control of the key and "
                   "nothing about any selector.")

    # TRAP 2. Compared against gpg's OUTPUT of the signed region, never
    # against the text we were handed: everything after the signature
    # block in a clearsigned message is unsigned, and a naive substring
    # check over the raw input passes for an identifier pasted there.
    text = payload.decode("utf-8", errors="replace")
    present, why_not = _payload_contains(text, confirms_value)
    if not present:
        return VerificationResult(
            VALUE_NOT_IN_PAYLOAD, **common, value_in_payload=False,
            detail=(f"the signature is valid and by the claimed key, but "
                    f"{why_not} Any message this vendor ever signed can be "
                    f"reposted with somebody else's identifier appended "
                    f"below the signature block, and that is what this "
                    f"refuses. The match is deliberately strict, so a "
                    f"genuine signature can land here when the actor "
                    f"printed the identifier in a different form -- spaced "
                    f"hex, for instance. Check the signed text before "
                    f"reading this as an attack: a false confirmation is "
                    f"far more expensive than a second look."))

    return VerificationResult(
        VERIFIED, **common, value_in_payload=True,
        detail=(f"signed by {signing}, and {confirms_value!r} appears within "
                f"the signed text. This is cryptographic evidence of control "
                f"of the key, and of the key's holder publishing that "
                f"identifier."))


class PgpService:
    """Records verifications, and upgrades a binding when one earns it."""

    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def verify_and_record(self, *, case_id: UUID, signed_message: str,
                          public_key: str, claimed_fingerprint: str,
                          created_by: UUID,
                          confirms_value: str | None = None,
                          channel_binding_id: UUID | None = None,
                          contact_block_id: UUID | None = None,
                          note: str | None = None) -> dict:
        """Verify, record the outcome, and upgrade the binding IF earned.

        Every outcome is recorded, including the ones that failed and the
        one that means nobody looked. A verification queue you can only
        see the successes of is a queue that hides its own gaps.
        """
        import hashlib

        claimed = normalise_fingerprint(claimed_fingerprint)
        binding_value = None
        if channel_binding_id is not None:
            row = self._c.execute(
                """SELECT durable_value, case_id FROM comms.channel_binding
                    WHERE id = %s""", (channel_binding_id,)).fetchone()
            if row is None:
                raise PgpError("no such channel binding")
            if row[1] != case_id:
                raise PgpError(
                    "the binding belongs to a different case: a verification "
                    "recorded against the wrong case is a disclosure as well "
                    "as an error")
            binding_value = row[0]
            # Confirming a binding means confirming ITS identifier. Letting
            # the caller name a different one would let a valid signature
            # over selector A upgrade a binding holding selector B.
            if confirms_value is None:
                confirms_value = binding_value
            elif binding_value is not None and \
                    confirms_value.strip().lower() != binding_value.lower():
                raise PgpError(
                    f"this verification is offered for {confirms_value!r} but "
                    f"the binding holds {binding_value!r}; a signature over "
                    f"one identifier cannot confirm another")

        if contact_block_id is not None:
            # The same check its sibling gets, three lines up. Without it a
            # verification in one case could cite a block in another, and
            # the citation is returned to every `comms.read` holder here.
            row = self._c.execute(
                "SELECT case_id FROM comms.contact_block WHERE id = %s",
                (contact_block_id,)).fetchone()
            if row is None or row[0] != case_id:
                raise PgpError(
                    "no such contact block in this case: a verification "
                    "citing another case's artefact is a disclosure as "
                    "well as an error")

        result = verify_clearsigned(
            signed_message, public_key, claimed_fingerprint=claimed,
            confirms_value=confirms_value)

        # Only digest bytes a signature actually covered. The column is
        # documented as "the exact bytes that were signed", and gpg writes
        # its --output file even when the signature FAILS -- so digesting
        # it unconditionally recorded attacker plaintext under that name.
        digest = (hashlib.sha256(result.signed_payload).digest()
                  if result.signed_payload
                  and result.outcome in _SIGNED_PAYLOAD_OUTCOMES else None)
        with self._c.transaction():
            row = self._c.execute(
                """INSERT INTO comms.pgp_verification
                       (case_id, channel_binding_id, contact_block_id,
                        claimed_fingerprint, signing_fingerprint,
                        confirms_value, signed_payload_sha256,
                        value_in_payload, outcome, verifier, verifier_version,
                        status_output, note, created_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           %s)
                   RETURNING id, verified_at""",
                (case_id, channel_binding_id, contact_block_id, claimed,
                 result.signing_fingerprint, confirms_value, digest,
                 result.value_in_payload, result.outcome, result.verifier,
                 result.verifier_version, result.status_output, note,
                 created_by)).fetchone()
            verification_id, verified_at = row

            upgraded = False
            if result.confirms and channel_binding_id is not None:
                # Only a VERIFIED outcome reaches here, and the schema
                # would refuse the row above if VERIFIED were claimed
                # without a matching fingerprint and an in-payload value.
                self._c.execute(
                    """UPDATE comms.channel_binding
                          SET verification = 'CONFIRMED',
                              verification_note = %s
                        WHERE id = %s""",
                    (f"PGP signature by {result.signing_fingerprint} over "
                     f"the identifier, verified "
                     f"{verified_at.isoformat()} (verification "
                     f"{verification_id})", channel_binding_id))
                upgraded = True

            self._audit(case_id, created_by, "PGP_VERIFICATION",
                        verification_id, {
                            "outcome": result.outcome,
                            "claimed_fingerprint": claimed,
                            "signing_fingerprint": result.signing_fingerprint,
                            "value_in_payload": result.value_in_payload,
                            "binding_upgraded": upgraded,
                            "verifier": result.verifier,
                        })

        return {
            "id": str(verification_id),
            "outcome": result.outcome,
            "confirms": result.confirms,
            "binding_upgraded": upgraded,
            "claimed_fingerprint": claimed,
            "signing_fingerprint": result.signing_fingerprint,
            "value_in_payload": result.value_in_payload,
            "verifier": result.verifier,
            "verifier_version": result.verifier_version,
            "detail": result.detail,
            "verified_at": verified_at.isoformat(),
        }

    def verifications(self, case_id: UUID, *, clearance: str,
                      compartments: frozenset[str] = frozenset()
                      ) -> list[dict]:
        """The verification ledger for a case.

        `comms.pgp_verification` carries no labels of its own -- but it
        carries `confirms_value`, which IS the identifier held by the
        binding it cites, and a binding can be classified above its case.
        So a listing filtered only by case handed an under-cleared reader
        the durable value of a RED binding through a table that looked
        label-free. The row is shown when its binding is visible, or when
        it cites no binding at all (a case-level record).
        """
        rows = self._c.execute(
            """SELECT v.id, v.channel_binding_id, v.contact_block_id,
                      v.claimed_fingerprint, v.signing_fingerprint,
                      v.confirms_value, v.value_in_payload, v.outcome,
                      v.verifier, v.verifier_version, v.note, v.verified_at
                 FROM comms.pgp_verification v
                WHERE v.case_id = %s
                  AND (v.channel_binding_id IS NULL
                       OR EXISTS (SELECT 1 FROM comms.channel_binding cb
                                   WHERE cb.id = v.channel_binding_id
                                     AND cb.classification <= %s::core.tlp
                                     AND cb.compartments <@ %s))
                  AND (v.contact_block_id IS NULL
                       OR EXISTS (SELECT 1 FROM comms.contact_block b
                                   WHERE b.id = v.contact_block_id
                                     AND b.classification <= %s::core.tlp
                                     AND b.compartments <@ %s))
                ORDER BY v.verified_at DESC""",
            (case_id, clearance, list(compartments),
             clearance, list(compartments))).fetchall()
        return [{"id": str(r[0]),
                 "channel_binding_id": str(r[1]) if r[1] else None,
                 "contact_block_id": str(r[2]) if r[2] else None,
                 "claimed_fingerprint": r[3], "signing_fingerprint": r[4],
                 "confirms_value": r[5], "value_in_payload": r[6],
                 "outcome": r[7], "verifier": r[8], "verifier_version": r[9],
                 "note": r[10], "verified_at": r[11].isoformat()}
                for r in rows]

    def unverified_claims(self, case_id: UUID, *, clearance: str,
                          compartments: frozenset[str] = frozenset()
                          ) -> list[dict]:
        """CLAIMED bindings that nobody has tried to confirm.

        The queue that exists because `NO_VERIFIER` is a distinct outcome:
        without it, "not confirmed" and "not checked" look identical, and
        an analyst reads an unchecked claim as a checked-and-failed one.
        """
        rows = self._c.execute(
            """SELECT cb.id, cb.platform_key, cb.observed_value,
                      cb.durable_value, cb.verification,
                      EXISTS (SELECT 1 FROM comms.pgp_verification v
                               WHERE v.channel_binding_id = cb.id) AS attempted
                 FROM comms.channel_binding cb
                WHERE cb.case_id = %s AND cb.verification = 'CLAIMED'
                  -- This returns observed AND durable values, so it is a
                  -- read of the binding's content and not merely of its
                  -- existence: the binding's own labels apply.
                  AND cb.classification <= %s::core.tlp
                  AND cb.compartments <@ %s
                ORDER BY cb.created_at DESC""",
            (case_id, clearance, list(compartments))).fetchall()
        return [{"channel_binding_id": str(r[0]), "platform_key": r[1],
                 "observed_value": r[2], "durable_value": r[3],
                 "verification": r[4], "verification_attempted": r[5],
                 "note": ("a CLAIM nobody has attempted to confirm"
                          if not r[5] else
                          "a CLAIM that has been checked and not confirmed")}
                for r in rows]

    def _audit(self, case_id: UUID, actor_id: UUID, action: str,
               object_id: UUID, detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'pgp_verification', %s, %s, %s)""",
            (actor_id, action, object_id, case_id, Json(detail)))

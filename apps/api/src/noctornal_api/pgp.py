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
MALFORMED = "MALFORMED"
NO_VERIFIER = "NO_VERIFIER"

_FPR = re.compile(r"^[0-9A-F]{40}$|^[0-9A-F]{64}$")
_WS = re.compile(r"\s+")
#: How long gpg gets. A signature check is milliseconds; anything near
#: this is a hang, and a hang in an API worker is an outage.
GPG_TIMEOUT_SECONDS = 20
#: Refuse absurd input before handing it to a subprocess.
MAX_MESSAGE_BYTES = 1_000_000
MAX_KEY_BYTES = 1_000_000


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
                "--no-auto-key-locate", "--auto-key-locate", "nodefault"]
        try:
            imported = subprocess.run(
                [*base, "--import", "key.asc"], cwd=work,
                capture_output=True, text=True,
                timeout=GPG_TIMEOUT_SECONDS, check=False)
            if imported.returncode != 0:
                return VerificationResult(
                    MALFORMED, status_output=_tail(imported.stderr),
                    verifier_version=verifier_version(),
                    detail="the supplied public key could not be read")

            proc = subprocess.run(
                [*base, "--status-fd", "1", "--output", "verified.txt",
                 "--decrypt", "message.asc"], cwd=work,
                capture_output=True, text=True,
                timeout=GPG_TIMEOUT_SECONDS, check=False)
        except subprocess.TimeoutExpired:
            return _unavailable(
                f"gpg did not return within {GPG_TIMEOUT_SECONDS}s.")
        except OSError as exc:
            return _unavailable(f"gpg could not be run ({exc}).")

        status = proc.stdout or ""
        payload = b""
        if os.path.isfile(out_file):
            with open(out_file, "rb") as fh:
                payload = fh.read()

    return _read_status(status, payload, claimed=claimed,
                        confirms_value=confirms_value,
                        version=verifier_version())


def _tail(text: str | None, limit: int = 4000) -> str:
    text = text or ""
    return text[-limit:]


def _status_lines(status: str) -> list[list[str]]:
    return [line[9:].split() for line in status.splitlines()
            if line.startswith("[GNUPG:] ")]


def _read_status(status: str, payload: bytes, *, claimed: str,
                 confirms_value: str | None,
                 version: str | None) -> VerificationResult:
    """Decide the outcome from the machine-readable lines ONLY.

    Order matters. gpg emits VALIDSIG for an expired or revoked key as
    well as a good one, so checking VALIDSIG first would report a revoked
    key as a clean confirmation.
    """
    codes = {parts[0] for parts in _status_lines(status) if parts}
    signing = None
    for parts in _status_lines(status):
        if parts and parts[0] == "VALIDSIG" and len(parts) > 1:
            # VALIDSIG <fingerprint> <date> <sig-timestamp> ...
            signing = parts[1].upper()
            break

    common = {"status_output": _tail(status), "verifier_version": version,
              "signing_fingerprint": signing, "signed_payload": payload}

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
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:                                    # pragma: no cover
        text = ""
    present = confirms_value.strip().lower() in text.lower()
    if not present:
        return VerificationResult(
            VALUE_NOT_IN_PAYLOAD, **common, value_in_payload=False,
            detail=(f"the signature is valid and by the claimed key, but "
                    f"{confirms_value!r} does not appear in the SIGNED text. "
                    f"Any message this vendor ever signed can be reposted "
                    f"with somebody else's identifier appended below the "
                    f"signature block, and that is what this refuses. "
                    f"The comparison is literal, so a genuine signature can "
                    f"land here when the actor printed the identifier in a "
                    f"different form -- spaced hex, a full 76-char Tox ID "
                    f"where the binding holds the 64-char key. Check the "
                    f"signed text before reading this as an attack. Matching "
                    f"loosely is deliberately not done: a false confirmation "
                    f"is far more expensive than a second look."))

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

        result = verify_clearsigned(
            signed_message, public_key, claimed_fingerprint=claimed,
            confirms_value=confirms_value)

        digest = (hashlib.sha256(result.signed_payload).digest()
                  if result.signed_payload else None)
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

    def verifications(self, case_id: UUID) -> list[dict]:
        rows = self._c.execute(
            """SELECT id, channel_binding_id, contact_block_id,
                      claimed_fingerprint, signing_fingerprint, confirms_value,
                      value_in_payload, outcome, verifier, verifier_version,
                      note, verified_at
                 FROM comms.pgp_verification
                WHERE case_id = %s ORDER BY verified_at DESC""",
            (case_id,)).fetchall()
        return [{"id": str(r[0]),
                 "channel_binding_id": str(r[1]) if r[1] else None,
                 "contact_block_id": str(r[2]) if r[2] else None,
                 "claimed_fingerprint": r[3], "signing_fingerprint": r[4],
                 "confirms_value": r[5], "value_in_payload": r[6],
                 "outcome": r[7], "verifier": r[8], "verifier_version": r[9],
                 "note": r[10], "verified_at": r[11].isoformat()}
                for r in rows]

    def unverified_claims(self, case_id: UUID) -> list[dict]:
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
                ORDER BY cb.created_at DESC""", (case_id,)).fetchall()
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

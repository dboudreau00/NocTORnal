"""Vendor keys a case holds, and the one way one is fetched (F10b, F10c,
comms, 2026-09-24; docs/10).

A vendor's public key used to be pasted into a verification and thrown
away, so nothing recorded which key a check used, where it came from, or
who compared its fingerprint with the one the actor published. docs/16 C11
item 3 calls that provenance "a HUMAN step, and an unrecorded one weakens
the whole chain". This module records it.

What holds here, and why:

- **Keys are case-scoped records of what was obtained and from where.**
  An acquisition (the bytes, their digest, how they came in, the source
  reference) is immutable and never deleted; each primary key gpg read
  from it is a row of its own. A key is never born confirmed: a person
  compares its fingerprint with a published one (a contact block line, or
  a publication named by reference) and the comparison is recorded with
  their name.
- **Labels run block <= key <= binding.** An acquisition is filed at the
  floor of what it cites, and only from what the caller can see (a
  hidden citation is the same 404 as an unknown id, so the floor is no
  classification oracle). A key is confirmed only against a block within
  its labels, and a binding is confirmed only with a key and a block
  within the binding's. The triggers hold the same rules.
- **Nothing here writes the graph.** Machines propose, analysts dispose:
  a key found in a directory proposes nothing and still needs a person's
  confirmation.
- **This module makes no network request of its own.** A Web Key
  Directory lookup (F10c) is off by default and sent only through the
  integration route `wkd` (docs/00 decision 68, docs/20 section 9),
  to a directory an administrator listed on that route, after a SECOND
  person approves (docs/00 decision 75), with the record and the SENT
  audit committed before the first packet. Only the hash leaves (no
  `?l=`), no redirect is followed and no User-Agent is sent.

gpg reads every key, in an ephemeral keyring with no agent and one time
budget (pgp.py `_EphemeralGpg`), after the packet walker has refused
secret material and anything that is not public key framing.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.pgp import (
    _VISIBLE_VERIFICATION,
    MAX_KEY_BYTES,
    GPG_TIMEOUT_SECONDS,
    PgpConflict,
    PgpError,
    PgpNotFound,
    PgpShapeError,
    PgpUnavailable,
    _EphemeralGpg,
    _floor_problem,
    _public_key_shape,
    _status_lines,
    gpg_path,
)
from noctornal_api.proposals import strictest

#: More keys than this in one file is not a vendor's key.
MAX_KEYS_PER_ACQUISITION = 8

#: The OpenPGP public-key algorithm ids a person can read (RFC 9580).
ALGORITHMS = {1: "RSA", 2: "RSA", 3: "RSA", 16: "Elgamal", 17: "DSA",
              18: "ECDH", 19: "ECDSA", 22: "EdDSA", 25: "X25519",
              27: "Ed25519", 26: "X448", 28: "Ed448"}

_FPR = re.compile(r"^[0-9A-F]{40}$|^[0-9A-F]{64}$")
_KEY_ID = re.compile(r"^[0-9A-F]{8}$|^[0-9A-F]{16}$")
_HEX_ESCAPE = re.compile(rb"\\x([0-9a-fA-F]{2})")
_MBOX = re.compile(r"<([^<>@\s]+@[^<>@\s]+)>")
_BARE_MBOX = re.compile(r"^[^<>@\s]+@[^<>@\s]+$")

CONFIRMED_NOTICE = ("Nothing is confirmed yet. Compare each fingerprint with "
                    "the one the actor published, then confirm it.")

SOURCES = ("PASTE", "FILE")


def algorithm_name(algorithm: int | None) -> str:
    if algorithm is None:
        return "unknown algorithm"
    return ALGORITHMS.get(algorithm, f"algorithm {algorithm}")


# ---------------------------------------------------------------------------
# Reading keys with gpg
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InspectedKey:
    primary_fingerprint: str
    algorithm: int
    curve: str | None
    bits: int | None
    created: datetime
    expires: datetime | None
    revoked: bool
    capabilities: str
    subkeys: list[dict] = field(default_factory=list)
    user_ids: list[dict] = field(default_factory=list)
    material: str = ""
    material_sha256: bytes = b""


def _colon_records(raw: bytes) -> list[list[bytes]]:
    """gpg's --with-colons listing: split on b"\\n" ONLY and fields on
    b":" (the `_status_lines` rule, pgp.py): a user ID is attacker bytes,
    and a str split would break it on U+0085 as a status line was."""
    return [line.rstrip(b"\r").split(b":")
            for line in (raw or b"").split(b"\n") if line.strip()]


def _ascii(field: bytes) -> str:
    return field.decode("ascii", errors="replace")


def _unescape_uid(field: bytes) -> str:
    """A user ID for DISPLAY: gpg's \\xHH escapes undone, then UTF-8 with
    replacement. Nothing is decided on it."""
    raw = _HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), field)
    return raw.decode("utf-8", errors="replace")


def _mbox(uid: str) -> str | None:
    """The last `<local@domain>` in a user ID, lower-cased, or the bare
    address when that is the whole user ID."""
    found = _MBOX.findall(uid)
    if found:
        return found[-1].lower()
    stripped = uid.strip()
    return stripped.lower() if _BARE_MBOX.match(stripped) else None


def _epoch(field: bytes) -> datetime | None:
    text = _ascii(field).strip()
    if not text.isdigit():
        return None
    return datetime.fromtimestamp(int(text), tz=UTC)


def _int(field: bytes) -> int | None:
    text = _ascii(field).strip()
    return int(text) if text.isdigit() else None


def _key_facts(rec: list[bytes]) -> dict:
    """pub/sub fields, 0-based: 1 validity (r revoked, e expired), 2 bits,
    3 algorithm, 5 created, 6 expires, 11 capabilities, 16 curve."""
    def at(i: int) -> bytes:
        return rec[i] if len(rec) > i else b""
    capabilities = re.sub(r"[^A-Za-z?]", "", _ascii(at(11)))[:32]
    curve = _ascii(at(16)).strip() or None
    return {"algorithm": _int(at(3)) or 0, "bits": _int(at(2)),
            "created": _epoch(at(5)), "expires": _epoch(at(6)),
            "revoked": _ascii(at(1)).strip() == "r",
            "capabilities": capabilities,
            "curve": curve[:64] if curve else None, "fingerprint": None}


def _parse_listing(raw: bytes) -> list[dict]:
    """Each primary with its subkeys and user IDs, from --with-colons.
    Every fpr record attaches to the pub or sub before it."""
    keys: list[dict] = []
    current: dict | None = None
    last: dict | None = None
    for rec in _colon_records(raw):
        kind = _ascii(rec[0])
        if kind == "pub":
            current = _key_facts(rec) | {"subkeys": [], "user_ids": []}
            keys.append(current)
            last = current
        elif kind == "sub" and current is not None:
            sub = _key_facts(rec)
            current["subkeys"].append(sub)
            last = sub
        elif kind == "fpr" and last is not None and len(rec) > 9:
            value = _ascii(rec[9]).upper()
            if _FPR.match(value) and last["fingerprint"] is None:
                last["fingerprint"] = value
        elif kind == "uid" and current is not None and len(rec) > 9:
            uid = _unescape_uid(rec[9])
            current["user_ids"].append({"uid": uid, "mbox": _mbox(uid)})
    return keys


def _import_counts(status: bytes) -> dict[str, int]:
    """IMPORT_RES <count> <no_user_id> <imported> <imported_rsa>
    <unchanged> <n_uids> <n_subk> <n_sigs> <n_revoc> <sec_read>
    <sec_imported> ..."""
    for parts in _status_lines(status):
        if parts and parts[0] == "IMPORT_RES" and len(parts) > 11:
            nums = [int(p) if p.isdigit() else 0 for p in parts]
            return {"count": nums[1], "imported": nums[3], "sec_read": nums[10],
                    "sec_imported": nums[11]}
    return {"count": 0, "imported": 0, "sec_read": 0, "sec_imported": 0}


def _usable_gpg() -> str:
    binary = gpg_path()
    if not binary:
        raise PgpUnavailable(
            "No gpg binary is available on this host, so no key can be read.")
    problem = _floor_problem(binary)
    if problem:
        raise PgpUnavailable(problem[:1].upper() + problem[1:])
    return binary


def inspect_keys(data: bytes) -> list[InspectedKey]:
    """Every primary key in `data`, as gpg reads it, or a refusal.

    The walker refuses secret material and anything that is not public
    key framing before any subprocess; gpg then imports in an ephemeral
    keyring with no agent (so it cannot take secret material either) and
    one budget covers the import, the listing and every export. IMPORT_RES
    reporting any secret key read is refused as well: a third line, from
    gpg's own count (the old list-secret-keys run could never fire with
    no agent)."""
    if not data:
        raise PgpError("there is no key material here")
    if len(data) > MAX_KEY_BYTES:
        raise PgpError(f"the key material is larger than {MAX_KEY_BYTES} "
                       f"bytes, which no vendor key is")
    try:
        _public_key_shape(data)
    except PgpShapeError as exc:
        raise PgpError(str(exc)[:1].upper() + str(exc)[1:]) from None
    binary = _usable_gpg()
    try:
        with _EphemeralGpg(binary) as gpg:
            gpg.put("key.in", data)
            imported = gpg.run("--status-fd", "1", "--import", "key.in")
            counts = _import_counts(imported.stdout or b"")
            if (imported.returncode != 0 or counts["sec_read"]
                    or counts["sec_imported"] or not counts["imported"]):
                raise PgpError("gpg could not read this as a public key")
            listing = gpg.run("--with-colons", "--fixed-list-mode",
                              "--with-subkey-fingerprint", "--list-keys")
            if listing.returncode != 0:
                raise PgpError("gpg could not read this as a public key")
            parsed = _parse_listing(listing.stdout or b"")
            if not parsed:
                raise PgpError("gpg found no public key here")
            if len(parsed) > MAX_KEYS_PER_ACQUISITION:
                raise PgpError(
                    f"this file holds {len(parsed)} keys; a vendor key file "
                    f"holds at most {MAX_KEYS_PER_ACQUISITION}")
            out: list[InspectedKey] = []
            for key in parsed:
                fpr = key["fingerprint"]
                if fpr is None or key["created"] is None:
                    raise PgpError("gpg listed a key without a fingerprint")
                exported = gpg.run("--armor", "--export", fpr)
                material = (exported.stdout or b"").decode("ascii", errors="replace")
                if (exported.returncode != 0 or "-----BEGIN PGP PUBLIC KEY BLOCK-----"
                        not in material or len(material) > MAX_KEY_BYTES):
                    raise PgpError("gpg could not export the key it read")
                out.append(InspectedKey(
                    primary_fingerprint=fpr, algorithm=key["algorithm"],
                    curve=key["curve"], bits=key["bits"],
                    created=key["created"], expires=key["expires"],
                    revoked=key["revoked"], capabilities=key["capabilities"],
                    subkeys=[{"fingerprint": s["fingerprint"],
                              "algorithm": s["algorithm"], "curve": s["curve"],
                              "bits": s["bits"],
                              "created": s["created"].isoformat() if s["created"] else None,
                              "expires": s["expires"].isoformat() if s["expires"] else None,
                              "revoked": s["revoked"],
                              "capabilities": s["capabilities"]}
                             for s in key["subkeys"] if s["fingerprint"]],
                    user_ids=key["user_ids"], material=material,
                    material_sha256=hashlib.sha256(material.encode("ascii")).digest()))
            return out
    except subprocess.TimeoutExpired:
        raise PgpUnavailable(
            f"gpg did not return within {GPG_TIMEOUT_SECONDS}s, so the key was "
            f"not read.") from None
    except OSError:
        raise PgpUnavailable("gpg could not be run, so the key was not read.") from None


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KeyLabels:
    classification: str
    compartments: tuple[str, ...]
    raised_note: str | None = None


#: The same visibility test for an acquisition everywhere in this module:
#: its labels within the caller's.
_ACQ_VISIBLE = ("a.classification <= %(clearance)s::core.tlp "
                "AND a.compartments <@ %(held)s::text[]")

_NOUN = {"comms.channel_binding": ("channel binding", "the channel binding"),
         "comms.contact_block": ("contact block", "the contact block"),
         "core.evidence": ("exhibit", "the exhibit")}


def _fpr_verdict(value: str | None) -> tuple[str | None, str | None]:
    """(fingerprint, None) or (None, KEY_ID_ONLY | NOT_A_FINGERPRINT) for
    a value already through comms.pgp_fingerprint_norm."""
    if value and _FPR.match(value):
        return value, None
    if value and _KEY_ID.match(value):
        return None, "KEY_ID_ONLY"
    return None, "NOT_A_FINGERPRINT"


_CONFIRM_REFUSALS = {
    "NOT_A_FINGERPRINT_LINE": "That contact block line is not a PGP "
                              "fingerprint line.",
    "KEY_ID_ONLY": "A key ID is not a fingerprint: 64-bit IDs collide by "
                   "construction.",
    "NOT_A_FINGERPRINT": "That is not a fingerprint: a fingerprint is 40 hex "
                         "characters (v4) or 64 (v5).",
    "SUBKEY": "That is a subkey of this key; actors publish the primary.",
    "MISMATCH": "The fingerprint the actor published is not this key's. That "
                "is itself worth noting: the key you hold is not the one "
                "they advertise.",
}


class KeyRefused(PgpConflict):
    """A confirmation the record refuses, with its stable reason code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class PgpKeyService:
    """The case key registry and the Web Key Directory lookups."""

    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    # -- labels ---------------------------------------------------------------

    def plan_labels(self, case_id: UUID, *, requested_classification: str | None,
                    requested_compartments: frozenset[str],
                    channel_binding_id: UUID | None,
                    contact_block_id: UUID | None, evidence_id: UUID | None,
                    clearance: str, held: frozenset[str]) -> KeyLabels:
        """The labels an import is filed at: never below the case, the
        request, or anything it cites. Each cited object is loaded under
        the caller's labels FIRST, and a hidden, unknown or other-case
        object is one 404, so the floor is computed from nothing the
        caller cannot see (otherwise the floor would be an oracle).
        Raising is said in a note, as a capture is (extraction.py)."""
        case = self._c.execute(
            'SELECT classification::text, compartments FROM core."case" WHERE id = %s',
            (case_id,)).fetchone()
        if case is None:
            raise PgpNotFound("no such case")
        base = requested_classification or case[0]
        classification = strictest(base, case[0])
        compartments = set(requested_compartments) | set(case[1] or ())
        raised_by: tuple[str, str] | None = None
        for table, object_id in (("comms.channel_binding", channel_binding_id),
                                 ("comms.contact_block", contact_block_id),
                                 ("core.evidence", evidence_id)):
            if object_id is None:
                continue
            row = self._c.execute(
                f"""SELECT classification::text, compartments FROM {table}
                     WHERE id = %s AND case_id = %s
                       AND classification <= %s::core.tlp
                       AND compartments <@ %s::text[]""",   # noqa: S608
                (object_id, case_id, clearance, sorted(held))).fetchone()
            if row is None:
                raise PgpNotFound(f"no such {_NOUN[table][0]} in this case")
            if strictest(classification, row[0]) != classification:
                classification = row[0]
                raised_by = (table, row[0])
            compartments |= set(row[1] or ())
        note = None
        if raised_by is not None and classification != base:
            note = (f"Filed at TLP:{classification} because "
                    f"{_NOUN[raised_by[0]][1]} it cites is TLP:{raised_by[1]}.")
        elif classification != base:
            note = f"Filed at TLP:{classification}, the case's own classification."
        return KeyLabels(classification, tuple(sorted(compartments)), note)

    # -- import ---------------------------------------------------------------

    def import_key(self, *, case_id: UUID, source: str, raw: bytes,
                   filename: str | None, source_ref: str, labels: KeyLabels,
                   created_by: UUID, channel_binding_id: UUID | None = None,
                   contact_block_id: UUID | None = None,
                   evidence_id: UUID | None = None) -> dict:
        """Read the keys (before any transaction: gpg is forked), then
        file one acquisition and a row per key. An identical import (the
        same bytes, source reference AND labels) answers with the row
        already there, re-read through the caller's labels; the insert
        runs in a savepoint so the refusal of the duplicate rolls back
        only itself."""
        if source not in SOURCES:
            raise PgpError("a key comes in as PASTE or FILE")
        ref = (source_ref or "").strip()
        if not 3 <= len(ref) <= 2000:
            raise PgpError("say where the key was obtained, in 3 to 2000 "
                           "characters")
        keys = inspect_keys(raw)
        raw_sha = hashlib.sha256(raw).digest()
        params = {"case": case_id, "source": source, "sha": raw_sha,
                  "ref": ref, "cls": labels.classification,
                  "comps": list(labels.compartments)}
        with self._c.transaction():
            try:
                with self._c.transaction():
                    acquisition_id = self._c.execute(
                        """INSERT INTO comms.pgp_key_acquisition
                               (case_id, source, raw_bytes, raw_sha256, filename,
                                source_ref, channel_binding_id, contact_block_id,
                                evidence_id, classification, compartments,
                                requested_by)
                           VALUES (%(case)s, %(source)s, %(raw)s, %(sha)s,
                                   %(filename)s, %(ref)s, %(binding)s, %(block)s,
                                   %(evidence)s, %(cls)s, %(comps)s, %(by)s)
                           RETURNING id""",
                        params | {"raw": raw, "filename": filename,
                                  "binding": channel_binding_id,
                                  "block": contact_block_id,
                                  "evidence": evidence_id, "by": created_by}
                    ).fetchone()[0]
            except psycopg.errors.UniqueViolation:
                row = self._c.execute(
                    f"""SELECT a.id FROM comms.pgp_key_acquisition a
                         WHERE a.case_id = %(case)s AND a.source = %(source)s
                           AND a.raw_sha256 = %(sha)s AND a.source_ref = %(ref)s
                           AND a.classification = %(cls)s::core.tlp
                           AND a.compartments = %(comps)s::text[]
                           AND {_ACQ_VISIBLE}""",
                    params | {"clearance": labels.classification,
                              "held": list(labels.compartments)}).fetchone()
                if row is None:
                    raise PgpConflict("that key is already recorded in this "
                                      "case") from None
                return self._acquisition_reply(
                    row[0], already_imported=True, labels=labels)
            self._insert_keys(case_id, acquisition_id, keys)
            self._audit(case_id, created_by, "PGP_KEY_IMPORTED", acquisition_id,
                        {"acquisition_id": str(acquisition_id), "source": source,
                         "fingerprints": [k.primary_fingerprint for k in keys],
                         "classification": labels.classification},
                        object_type="pgp_key_acquisition")
        return self._acquisition_reply(acquisition_id, already_imported=False,
                                       labels=labels)

    def _insert_keys(self, case_id: UUID, acquisition_id: UUID,
                     keys: list[InspectedKey]) -> None:
        for key in keys:
            self._c.execute(
                """INSERT INTO comms.pgp_key
                       (case_id, acquisition_id, primary_fingerprint, algorithm,
                        curve, key_bits, key_created_at, key_expires_at, revoked,
                        capabilities, subkeys, user_ids, material,
                        material_sha256)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (case_id, acquisition_id, key.primary_fingerprint, key.algorithm,
                 key.curve, key.bits, key.created, key.expires, key.revoked,
                 key.capabilities, Json(key.subkeys), Json(key.user_ids),
                 key.material, key.material_sha256))

    def _acquisition_reply(self, acquisition_id: UUID, *, already_imported: bool,
                           labels: KeyLabels) -> dict:
        rows = self._c.execute(
            "SELECT id FROM comms.pgp_key WHERE acquisition_id = %s ORDER BY created_at, id",
            (acquisition_id,)).fetchall()
        keys = [self._key_rows(labels.classification, frozenset(labels.compartments),
                               "k.id = %(key)s", {"key": r[0]})[0] for r in rows]
        return {"acquisition_id": str(acquisition_id),
                "already_imported": already_imported,
                "classification": labels.classification,
                "compartments": list(labels.compartments),
                "raised_note": labels.raised_note, "keys": keys,
                "notice": CONFIRMED_NOTICE}

    # -- reads ----------------------------------------------------------------

    _KEY_SELECT = f"""
        SELECT k.id, k.primary_fingerprint, k.algorithm, k.key_bits, k.curve,
               k.key_created_at, k.key_expires_at, k.revoked, k.capabilities,
               k.user_ids, k.subkeys, a.id, a.source, a.filename, a.source_ref,
               a.requested_at, ru.display_name, a.classification::text,
               a.compartments, k.confirmed_fingerprint, k.confirmed_against,
               k.confirmed_contact_block_entry_id, ce.block_id, ce.line_no,
               k.confirmed_source_ref, k.confirmation_statement,
               cu.display_name, k.confirmed_at, k.retired_at, tu.display_name,
               k.retired_reason, a.lookup_id, l.address
          FROM comms.pgp_key k
          JOIN comms.pgp_key_acquisition a ON a.id = k.acquisition_id
          JOIN iam.app_user ru ON ru.id = a.requested_by
          LEFT JOIN iam.app_user cu ON cu.id = k.confirmed_by
          LEFT JOIN iam.app_user tu ON tu.id = k.retired_by
          LEFT JOIN comms.contact_block_entry ce
                 ON ce.id = k.confirmed_contact_block_entry_id
          LEFT JOIN comms.pgp_key_lookup l ON l.id = a.lookup_id
         WHERE {_ACQ_VISIBLE}"""

    def _key_rows(self, clearance: str, held: frozenset[str], where: str,
                  params: dict) -> list[dict]:
        rows = self._c.execute(
            self._KEY_SELECT + f" AND {where} ORDER BY k.created_at DESC, k.id",
            params | {"clearance": clearance, "held": sorted(held)}).fetchall()
        now = datetime.now(UTC)
        out = []
        for r in rows:
            user_ids = list(r[9] or [])
            looked_up = r[32]
            out.append({
                "id": str(r[0]), "fingerprint": r[1],
                "algorithm": algorithm_name(r[2]), "algorithm_id": r[2],
                "bits": r[3], "curve": r[4],
                "created": r[5].isoformat() if r[5] else None,
                "expires": r[6].isoformat() if r[6] else None,
                "expired": bool(r[6] and r[6] <= now), "revoked": r[7],
                "capabilities": r[8], "user_ids": user_ids,
                "subkeys": list(r[10] or []),
                "acquisition": {
                    "id": str(r[11]), "source": r[12], "filename": r[13],
                    "source_ref": r[14],
                    "requested_at": r[15].isoformat() if r[15] else None,
                    "requested_by": r[16], "classification": r[17],
                    "compartments": list(r[18] or []),
                    "lookup_id": str(r[31]) if r[31] else None,
                    "looked_up_address": looked_up,
                    # Computed on read, never stored: whether any user
                    # ID of the key names the address that was looked up.
                    "names_looked_up_address": (
                        None if looked_up is None else any(
                            (u.get("mbox") or "") == looked_up.lower()
                            for u in user_ids)),
                },
                "confirmation": None if r[19] is None else {
                    "against": r[20],
                    "entry_id": str(r[21]) if r[21] else None,
                    "block_id": str(r[22]) if r[22] else None,
                    "line_no": r[23], "source_ref": r[24], "statement": r[25],
                    "confirmed_by": r[26],
                    "confirmed_at": r[27].isoformat() if r[27] else None,
                },
                "retirement": None if r[28] is None else {
                    "retired_at": r[28].isoformat(), "retired_by": r[29],
                    "reason": r[30]},
                "classification": r[17], "compartments": list(r[18] or []),
            })
        return out

    def keys(self, case_id: UUID, *, clearance: str, held: frozenset[str],
             include_retired: bool = False) -> list[dict]:
        where = "k.case_id = %(case)s" + (
            "" if include_retired else " AND k.retired_at IS NULL")
        return self._key_rows(clearance, held, where, {"case": case_id})

    def key(self, case_id: UUID, key_id: UUID, *, clearance: str,
            held: frozenset[str]) -> dict:
        rows = self._key_rows(clearance, held,
                              "k.case_id = %(case)s AND k.id = %(key)s",
                              {"case": case_id, "key": key_id})
        if not rows:
            raise PgpNotFound("no such key in this case")
        out = rows[0]
        extra = self._c.execute(
            """SELECT k.material, a.raw_sha256, k.material_sha256
                 FROM comms.pgp_key k
                 JOIN comms.pgp_key_acquisition a ON a.id = k.acquisition_id
                WHERE k.id = %s""", (key_id,)).fetchone()
        out["material"] = extra[0]
        out["raw_sha256"] = bytes(extra[1]).hex()
        out["material_sha256"] = bytes(extra[2]).hex()
        out["verifications"] = [
            {"id": str(r[0]), "outcome": r[1], "form": r[2],
             "channel_binding_id": str(r[3]) if r[3] else None,
             "attribution": r[4], "verified_at": r[5].isoformat()}
            for r in self._c.execute(
                f"""SELECT v.id, v.outcome, v.signature_form,
                           v.channel_binding_id, v.attribution, v.verified_at
                      FROM comms.pgp_verification v
                     WHERE v.case_id = %(case)s AND v.pgp_key_id = %(key)s
                       AND {_VISIBLE_VERIFICATION}
                     ORDER BY v.verified_at DESC, v.id DESC""",
                {"case": case_id, "key": key_id, "clearance": clearance,
                 "held": sorted(held)}).fetchall()]
        return out

    def _visible_key(self, case_id: UUID, key_id: UUID, *, clearance: str,
                     held: frozenset[str], lock: bool = False) -> dict:
        row = self._c.execute(
            f"""SELECT k.id, k.primary_fingerprint, k.subkeys, k.confirmed_at,
                       k.retired_at, a.classification::text, a.compartments
                  FROM comms.pgp_key k
                  JOIN comms.pgp_key_acquisition a ON a.id = k.acquisition_id
                 WHERE k.id = %(key)s AND k.case_id = %(case)s
                   AND {_ACQ_VISIBLE}
                 {"FOR UPDATE OF k" if lock else ""}""",
            {"key": key_id, "case": case_id, "clearance": clearance,
             "held": sorted(held)}).fetchone()
        if row is None:
            raise PgpNotFound("no such key in this case")
        return {"id": row[0], "fingerprint": row[1],
                "subkeys": {s.get("fingerprint") for s in (row[2] or [])},
                "confirmed_at": row[3], "retired_at": row[4],
                "classification": row[5], "compartments": list(row[6] or [])}

    def published_fingerprints(self, case_id: UUID, *, clearance: str,
                               held: frozenset[str]) -> list[dict]:
        """Every PGP fingerprint line in a visible contact block of the
        case, with whether it can stand behind a confirmation."""
        rows = self._c.execute(
            """SELECT e.id, e.block_id, e.line_no, e.role, b.source_ref,
                      b.publisher_handle, b.classification::text, b.compartments,
                      e.observed_value, comms.pgp_fingerprint_norm(e.durable_value)
                 FROM comms.contact_block_entry e
                 JOIN comms.contact_block b ON b.id = e.block_id
                WHERE b.case_id = %s AND e.selector_type = 'PGP_FPR'
                  AND b.classification <= %s::core.tlp
                  AND b.compartments <@ %s::text[]
                ORDER BY b.created_at DESC, e.line_no""",
            (case_id, clearance, sorted(held))).fetchall()
        out = []
        for r in rows:
            fingerprint, why_not = _fpr_verdict(r[9])
            out.append({"entry_id": str(r[0]), "block_id": str(r[1]),
                        "line_no": r[2], "role": r[3], "source_ref": r[4],
                        "publisher_handle": r[5], "classification": r[6],
                        "compartments": list(r[7] or []),
                        "observed_value": r[8], "fingerprint": fingerprint,
                        "usable": fingerprint is not None, "why_not": why_not})
        return out

    def attribution_blocks(self, case_id: UUID, binding_id: UUID, *,
                           clearance: str, held: frozenset[str]) -> list[dict]:
        """The visible contact blocks that could tie a key to this
        binding's holder: within the binding's labels, listing a usable
        fingerprint as their publisher's own, and either listing the
        binding's identifier as their own or published by the binding's
        identity, with no identity conflict."""
        binding = self._c.execute(
            """SELECT platform_key, durable_value, identity_node_id,
                      classification::text, compartments
                 FROM comms.channel_binding
                WHERE id = %s AND case_id = %s
                  AND classification <= %s::core.tlp
                  AND compartments <@ %s::text[]""",
            (binding_id, case_id, clearance, sorted(held))).fetchone()
        if binding is None:
            raise PgpNotFound("no such channel binding in this case")
        platform, durable, identity, b_cls, b_comp = binding
        rows = self._c.execute(
            """SELECT b.id, b.source_ref, b.publisher_handle, b.created_at,
                      b.classification::text, b.compartments,
                      b.publisher_identity_node_id,
                      ARRAY(SELECT DISTINCT comms.pgp_fingerprint_norm(e.durable_value)
                              FROM comms.contact_block_entry e
                             WHERE e.block_id = b.id AND e.role = 'SELF'
                               AND e.selector_type = 'PGP_FPR'),
                      EXISTS (SELECT 1 FROM comms.contact_block_entry e
                               WHERE e.block_id = b.id AND e.role = 'SELF'
                                 AND e.platform_key = %(platform)s
                                 AND lower(e.durable_value) = lower(%(durable)s))
                 FROM comms.contact_block b
                WHERE b.case_id = %(case)s
                  AND b.classification <= %(clearance)s::core.tlp
                  AND b.compartments <@ %(held)s::text[]
                  AND b.classification <= %(b_cls)s::core.tlp
                  AND b.compartments <@ %(b_comp)s::text[]
                ORDER BY b.created_at DESC""",
            {"case": case_id, "clearance": clearance, "held": sorted(held),
             "b_cls": b_cls, "b_comp": list(b_comp or []),
             "platform": platform, "durable": durable or ""}).fetchall()
        out = []
        for r in rows:
            fingerprints = [f for f in (r[7] or []) if f and _FPR.match(f)]
            if not fingerprints:
                continue
            publisher = r[6]
            if publisher is not None and identity is not None:
                if publisher != identity:
                    continue
                via = "SAME_IDENTITY"
            elif r[8]:
                via = "SAME_BLOCK"
            else:
                continue
            out.append({"block_id": str(r[0]), "source_ref": r[1],
                        "publisher_handle": r[2],
                        "created_at": r[3].isoformat(), "classification": r[4],
                        "compartments": list(r[5] or []),
                        "fingerprints": fingerprints, "via": via})
        return out

    # -- confirmation and retirement -----------------------------------------

    def _refuse(self, case_id: UUID, actor: UUID, key_id: UUID, code: str,
                message: str) -> None:
        """Audited before raising, on the caller's autocommit connection,
        so a refusal is on record whatever the caller does next."""
        self._audit(case_id, actor, "PGP_KEY_CONFIRM_REFUSED", key_id,
                    {"key_id": str(key_id), "reason": code},
                    object_type="pgp_key", outcome="DENIED")
        raise KeyRefused(code, message)

    def confirm(self, *, case_id: UUID, key_id: UUID, confirmed_by: UUID,
                clearance: str, held: frozenset[str],
                contact_block_entry_id: UUID | None = None,
                published_fingerprint: str | None = None,
                source_ref: str | None = None,
                statement: str | None = None) -> dict:
        """Record that a person compared this key's fingerprint with the
        one the actor published, and that they agree. The published value
        is normalised by comms.pgp_fingerprint_norm, the one rule the
        triggers use too."""
        if (contact_block_entry_id is None) == (published_fingerprint is None):
            raise PgpError("confirm against a contact block line, or a "
                           "fingerprint published elsewhere, not both")
        if statement is not None and len(statement) > 2000:
            raise PgpError("a statement is at most 2000 characters")
        key = self._visible_key(case_id, key_id, clearance=clearance, held=held)
        if key["retired_at"] is not None:
            raise PgpConflict("that key is retired, so it is not confirmed")
        if key["confirmed_at"] is not None:
            raise PgpConflict("that key's fingerprint is already confirmed")
        entry_id = None
        against = "PUBLISHED_ELSEWHERE"
        if contact_block_entry_id is not None:
            if source_ref:
                raise PgpError("a contact block line is its own source")
            row = self._c.execute(
                """SELECT e.id, e.selector_type,
                          comms.pgp_fingerprint_norm(e.durable_value),
                          b.classification::text, b.compartments
                     FROM comms.contact_block_entry e
                     JOIN comms.contact_block b ON b.id = e.block_id
                    WHERE e.id = %s AND b.case_id = %s
                      AND b.classification <= %s::core.tlp
                      AND b.compartments <@ %s::text[]""",
                (contact_block_entry_id, case_id, clearance,
                 sorted(held))).fetchone()
            if row is None:
                raise PgpNotFound("no such contact block line in this case")
            if row[1] != "PGP_FPR":
                self._refuse(case_id, confirmed_by, key_id,
                             "NOT_A_FINGERPRINT_LINE",
                             _CONFIRM_REFUSALS["NOT_A_FINGERPRINT_LINE"])
            from noctornal_api.pgp import _labels_within
            if not _labels_within((row[3], list(row[4] or [])),
                                  (key["classification"], key["compartments"])):
                self._refuse(
                    case_id, confirmed_by, key_id, "LABELS",
                    f"That line's contact block is filed at TLP:{row[3]}, above "
                    f"this key. A confirmation shown with the key cannot rest on "
                    f"material its readers may not see. Import the key again at "
                    f"the block's labels and confirm that copy.")
            published = row[2]
            entry_id = row[0]
            against = "CONTACT_BLOCK"
        else:
            ref = (source_ref or "").strip()
            if not 3 <= len(ref) <= 2000:
                raise PgpError("say where the fingerprint was published, in 3 "
                               "to 2000 characters")
            published = self._c.execute(
                "SELECT comms.pgp_fingerprint_norm(%s)",
                (published_fingerprint,)).fetchone()[0]
            source_ref = ref
        fingerprint, why_not = _fpr_verdict(published)
        if why_not is not None:
            self._refuse(case_id, confirmed_by, key_id, why_not,
                         _CONFIRM_REFUSALS[why_not])
        if fingerprint in key["subkeys"]:
            self._refuse(case_id, confirmed_by, key_id, "SUBKEY",
                         _CONFIRM_REFUSALS["SUBKEY"])
        if fingerprint != key["fingerprint"]:
            self._refuse(case_id, confirmed_by, key_id, "MISMATCH",
                         _CONFIRM_REFUSALS["MISMATCH"])
        with self._c.transaction():
            self._visible_key(case_id, key_id, clearance=clearance, held=held,
                              lock=True)
            self._c.execute(
                """UPDATE comms.pgp_key
                      SET confirmed_fingerprint = primary_fingerprint,
                          confirmed_against = %s,
                          confirmed_contact_block_entry_id = %s,
                          confirmed_source_ref = %s,
                          confirmation_statement = %s,
                          confirmed_by = %s, confirmed_at = now()
                    WHERE id = %s AND confirmed_at IS NULL AND retired_at IS NULL""",
                (against, entry_id,
                 source_ref if against == "PUBLISHED_ELSEWHERE" else None,
                 (statement or "").strip() or None, confirmed_by, key_id))
            self._audit(case_id, confirmed_by, "PGP_KEY_CONFIRMED", key_id,
                        {"key_id": str(key_id), "fingerprint": key["fingerprint"],
                         "against": against,
                         "entry_id": str(entry_id) if entry_id else None},
                        object_type="pgp_key")
        return self.key(case_id, key_id, clearance=clearance, held=held)

    def retire(self, *, case_id: UUID, key_id: UUID, reason: str,
               retired_by: UUID, clearance: str, held: frozenset[str]) -> dict:
        """Retire a key: it stands behind no new check. Nothing is demoted
        automatically; the reply names the bindings the caller can see that
        a VERIFIED check with this key confirmed, and says nothing about any
        they cannot (no hidden count)."""
        text = (reason or "").strip()
        if not 3 <= len(text) <= 2000:
            raise PgpError("say why the key is retired, in 3 to 2000 characters")
        with self._c.transaction():
            key = self._visible_key(case_id, key_id, clearance=clearance,
                                    held=held, lock=True)
            if key["retired_at"] is not None:
                raise PgpConflict("that key is already retired")
            self._c.execute(
                """UPDATE comms.pgp_key
                      SET retired_at = now(), retired_by = %s, retired_reason = %s
                    WHERE id = %s""", (retired_by, text, key_id))
            self._audit(case_id, retired_by, "PGP_KEY_RETIRED", key_id,
                        {"key_id": str(key_id), "fingerprint": key["fingerprint"]},
                        object_type="pgp_key")
        bindings = self._c.execute(
            f"""SELECT DISTINCT cb.id, cb.platform_key, cb.observed_value,
                       cb.verification
                  FROM comms.pgp_verification v
                  JOIN comms.channel_binding cb ON cb.id = v.channel_binding_id
                 WHERE v.case_id = %(case)s AND v.pgp_key_id = %(key)s
                   AND v.outcome = 'VERIFIED'
                   AND {_VISIBLE_VERIFICATION}""",
            {"case": case_id, "key": key_id, "clearance": clearance,
             "held": sorted(held)}).fetchall()
        out = self.key(case_id, key_id, clearance=clearance, held=held)
        out["bindings_confirmed_with_it"] = [
            {"channel_binding_id": str(r[0]), "platform_key": r[1],
             "observed_value": r[2], "verification": r[3]} for r in bindings]
        return out

    # -- audit ------------------------------------------------------------

    def _audit(self, case_id: UUID, actor_id: UUID, action: str,
               object_id: UUID | None, detail: dict, *, object_type: str,
               outcome: str = "SUCCESS") -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, outcome, detail)
               VALUES (%s, 'USER', %s, %s, %s, %s, %s, %s)""",
            (actor_id, action, object_type, object_id, case_id, outcome,
             Json(detail)))


# ---------------------------------------------------------------------------
# Web Key Directory lookups (F10c)
# ---------------------------------------------------------------------------

#: CLEAR, GREEN or AMBER: the highest classification a lookup may carry.
#: Unset means lookups are off. Anything else, AMBER_STRICT and RED
#: included (which never leave, egress.py), is a policy problem.
WKD_CEILING_ENV = "NOCTORNAL_WKD_CEILING"
WKD_CEILINGS = ("CLEAR", "GREEN", "AMBER")
#: The integration route every lookup takes (egress.INTEGRATIONS).
WKD_ROUTE = "wkd"
LOOKUP_SIGNOFF_HOURS = 24
WKD_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"
ADVANCED = "ADVANCED"
DIRECT = "DIRECT"
_ADVANCED_PREFIX = "openpgpkey."
#: Names that are never a public directory's: special-use and internal
#: suffixes, and the reserved example names.
_REFUSED_TLDS = frozenset({"onion", "i2p", "local", "localhost", "internal",
                           "arpa", "invalid", "test", "example", "lan",
                           "home", "corp"})
_LDH = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_CONTROL = re.compile(r"[\x00-\x20\x7f-\x9f]")

OFF_PROBLEM = ("Web Key Directory lookups are switched off on this deployment: "
               f"{WKD_CEILING_ENV} is not set.")
BAD_CEILING = (f"{WKD_CEILING_ENV} must be CLEAR, GREEN or AMBER, so lookups "
               f"are refused.")
NO_ROUTE = ("There is no Web Key Directory route. An administrator creates the "
            "integration route named wkd, listing each directory it may reach.")
WILDCARD = ("The Web Key Directory route lists a wildcard entry, so it could "
            "reach any domain. List each directory by name.")
NO_DIRECTORY = "The Web Key Directory route lists no directory."
NO_GPG = "No usable gpg, so a key found could not be read. Nothing is looked up."
#: Recorded when gpg became unusable between the approval and the answer:
#: the request left, and the answer's digest is all that is kept.
GPG_LOST = ("No usable gpg, so the key the directory sent could not be read. "
            "The answer's digest is recorded.")


def _utc_text(moment: datetime) -> str:
    """An instant as the console writes one: "2026-09-25 14:05 UTC"."""
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


@dataclass(frozen=True)
class WkdPolicy:
    enabled: bool
    ceiling: str | None
    route: object | None
    directories: tuple[tuple[str, tuple[str, ...]], ...]
    problem: str | None


def parse_address(text: str) -> tuple[str, str]:
    """(local part, domain) for an address a lookup may name, or PgpError.

    The domain goes to ASCII through IDNA, lower-cased, without a trailing
    dot, two or more letter-digit-hyphen labels; an address literal and
    the special-use suffixes are refused (they are never a directory)."""
    value = (text or "").strip()
    if value.count("@") != 1:
        raise PgpError("an address has exactly one @")
    local, domain = value.split("@")
    if not local or len(local.encode("utf-8")) > 64 or _CONTROL.search(local):
        raise PgpError("the part before the @ is 1 to 64 bytes with no spaces "
                       "or control characters")
    domain = domain.rstrip(".")
    if not domain or domain.startswith("[") or re.match(r"^[0-9.]+$", domain):
        raise PgpError("a lookup names a domain, never an address")
    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise PgpError("that domain is not a name this lookup can use") from None
    labels = ascii_domain.split(".")
    if (len(labels) < 2 or len(ascii_domain) > 253
            or not all(_LDH.match(label) for label in labels)):
        raise PgpError("that domain is not a name this lookup can use")
    if labels[-1] in _REFUSED_TLDS or labels[-1].isdigit():
        raise PgpError("that domain is never a public key directory")
    return local, ascii_domain


def _zbase32(data: bytes) -> str:
    bits = int.from_bytes(data, "big")
    total = len(data) * 8
    out = []
    for shift in range(total - 5, -1, -5):
        out.append(WKD_ALPHABET[(bits >> shift) & 31])
    remainder = total % 5
    if remainder:
        out.append(WKD_ALPHABET[(bits << (5 - remainder)) & 31])
    return "".join(out)


def wkd_hash(local: str) -> str:
    """z-base-32 of SHA-1 over the local part, A to Z lower-cased only
    (the WKD draft: other characters are left as they are)."""
    lowered = "".join(ch.lower() if "A" <= ch <= "Z" else ch for ch in local)
    return _zbase32(hashlib.sha1(lowered.encode("utf-8")).digest())  # noqa: S324


def wkd_urls(domain: str, digest: str) -> dict[str, str]:
    """Both candidate URLs. Neither carries ?l=: only the hash leaves."""
    return {ADVANCED: (f"https://{_ADVANCED_PREFIX}{domain}/.well-known/"
                       f"openpgpkey/{domain}/hu/{digest}"),
            DIRECT: f"https://{domain}/.well-known/openpgpkey/hu/{digest}"}


def _wkd_route(conn, declared=()):
    """The ONE place this module reads the route (docs/20 section 9,
    the WKD row). Called with nothing declared it answers the
    administrator's allowlist or refuses: no route means lookups are off."""
    from noctornal_api import egress
    return egress.route_for("integration", WKD_ROUTE, conn=conn,
                            declared=tuple(declared))


def _directories(route) -> tuple[tuple[tuple[str, tuple[str, ...]], ...], bool]:
    """(directories, wildcard) from the route's allowlist: an entry
    openpgpkey.<d>:443 offers the advanced method for <d>, an entry
    <d>:443 the direct one. A route that would reach any public name, or
    names a suffix, is a wildcard: lookups stay off
    rather than reach a domain nobody listed."""
    policy = route.policy
    if policy.any_public or any(rule.suffix is not None for rule in route.rules):
        return (), True
    found: dict[str, set[str]] = {}
    for rule in route.rules:
        if rule.host is None or 443 not in rule.ports:
            continue
        host = rule.host
        method = DIRECT
        if host.startswith(_ADVANCED_PREFIX):
            host, method = host[len(_ADVANCED_PREFIX):], ADVANCED
        try:
            _local, domain = parse_address(f"x@{host}")
        except PgpError:
            continue
        found.setdefault(domain, set()).add(method)
    ordered = tuple((d, tuple(m for m in (ADVANCED, DIRECT) if m in found[d]))
                    for d in sorted(found))
    return ordered, False


def directory_policy(conn) -> WkdPolicy:
    """Whether lookups are on, and where they may go. Fails closed: an
    unset or unknown ceiling, no usable gpg (a key found could not be read
    after the address was disclosed), no route, a
    wildcard route, or a route with no directory each turn lookups off
    and say why."""
    raw = os.environ.get(WKD_CEILING_ENV, "").strip()
    if not raw:
        return WkdPolicy(False, None, None, (), OFF_PROBLEM)
    ceiling = raw.upper()
    if ceiling not in WKD_CEILINGS:
        return WkdPolicy(False, None, None, (), BAD_CEILING)
    binary = gpg_path()
    if not binary or _floor_problem(binary):
        return WkdPolicy(False, ceiling, None, (), NO_GPG)
    from noctornal_api.egress import RouteUnavailable
    try:
        route = _wkd_route(conn)
    except RouteUnavailable as exc:
        problem = NO_ROUTE
        if getattr(exc, "code", "") not in ("route_unknown",):
            problem = f"{NO_ROUTE} The route answered: {exc}"
        return WkdPolicy(False, ceiling, None, (), problem)
    directories, wildcard = _directories(route)
    if wildcard:
        return WkdPolicy(False, ceiling, route, (), WILDCARD)
    if not directories:
        return WkdPolicy(False, ceiling, route, (), NO_DIRECTORY)
    return WkdPolicy(True, ceiling, route, directories, None)


def _methods_for(policy: WkdPolicy, domain: str) -> tuple[str, ...]:
    for name, methods in policy.directories:
        if name == domain:
            return methods
    return ()


def _default_fetcher(url: str, *, route):
    """The one client call (docs/20 section 9, the WKD row): no
    redirect followed, no User-Agent, 404 accepted, the key cap, 20
    seconds."""
    from noctornal_api import pinned_http
    return pinned_http.fetch_response(
        url, route=route, method="GET", user_agent=None, max_redirects=0,
        accept_status=frozenset({404}), timeout=10, deadline=20.0,
        max_bytes=MAX_KEY_BYTES)


_STATE_WORDS = {"REQUESTED": "waiting for a second person"}


class PgpLookupService(PgpKeyService):
    """Request, approve and send, decline, and read key lookups (docs/00
    decision 75)."""

    def _lookup_refused(self, case_id: UUID, actor: UUID, code: str,
                        exc: PgpError) -> PgpError:
        # No address in the detail: a refusal is recorded without the
        # material it refused to send.
        self._audit(case_id, actor, "PGP_KEY_LOOKUP_REFUSED", None,
                    {"code": code}, object_type="pgp_key_lookup",
                    outcome="DENIED")
        return exc

    def directory_status(self, case_id: UUID) -> dict:
        """What the console needs before anybody types: whether lookups
        are on, where they may go, and whether THIS case's own labels
        keep its addresses in (case_problem)."""
        from noctornal_api.egress import Destination, can_egress
        policy = directory_policy(self._c)
        case = self._c.execute(
            'SELECT classification::text, compartments FROM core."case" WHERE id = %s',
            (case_id,)).fetchone()
        case_problem = None
        if policy.enabled and case is not None:
            decision = can_egress(case[0], Destination.KEY_DIRECTORY,
                                  compartments=frozenset(case[1] or ()),
                                  destination_ceiling=policy.ceiling)
            if decision.denied:
                case_problem = ("This case's addresses are never looked up: "
                                + decision.explain() + ".")
        return {"enabled": policy.enabled, "ceiling": policy.ceiling,
                "directories": [{"domain": d, "methods": list(m)}
                                for d, m in policy.directories],
                "problem": policy.problem, "case_problem": case_problem}

    def request_lookup(self, *, case_id: UUID, address: str, reason: str,
                       classification: str | None,
                       channel_binding_id: UUID | None,
                       contact_block_id: UUID | None, requested_by: UUID,
                       clearance: str, held: frozenset[str],
                       writable: Callable[[str, frozenset[str]], None]
                       ) -> dict:
        """Ask for a lookup. Nothing is sent: a second person approves.
        Every refusal comes before any row and is audited without the
        address."""
        from noctornal_api.egress import Destination, can_egress
        policy = directory_policy(self._c)
        if not policy.enabled:
            raise self._lookup_refused(case_id, requested_by, "POLICY",
                                       PgpConflict(policy.problem))
        text = (reason or "").strip()
        if not 10 <= len(text) <= 2000:
            raise self._lookup_refused(
                case_id, requested_by, "REASON",
                PgpError("say why the key is needed, in 10 to 2000 characters"))
        try:
            local, domain = parse_address(address)
        except PgpError as exc:
            raise self._lookup_refused(case_id, requested_by, "ADDRESS",
                                       exc) from None
        methods = _methods_for(policy, domain)
        if not methods:
            raise self._lookup_refused(
                case_id, requested_by, "NOT_ON_ROUTE",
                PgpConflict(f"{domain} is not on the Web Key Directory route. "
                            f"An administrator adds a directory to the route "
                            f"under Administration."))
        try:
            labels = self.plan_labels(
                case_id, requested_classification=classification,
                requested_compartments=frozenset(),
                channel_binding_id=channel_binding_id,
                contact_block_id=contact_block_id, evidence_id=None,
                clearance=clearance, held=held)
        except PgpNotFound as exc:
            raise self._lookup_refused(case_id, requested_by, "NOT_FOUND",
                                       exc) from None
        writable(labels.classification, frozenset(labels.compartments))
        decision = can_egress(labels.classification, Destination.KEY_DIRECTORY,
                              compartments=frozenset(labels.compartments),
                              destination_ceiling=policy.ceiling)
        if decision.denied:
            raise self._lookup_refused(
                case_id, requested_by, "LABELS",
                PgpConflict(decision.explain()[:1].upper()
                            + decision.explain()[1:]
                            + ". This address is not looked up."))
        digest = wkd_hash(local)
        with self._c.transaction():
            row = self._c.execute(
                """INSERT INTO comms.pgp_key_lookup
                       (case_id, address, local_part, domain, wkd_hash, reason,
                        channel_binding_id, contact_block_id, classification,
                        ceiling, route_name, requested_by, expires_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           now() + make_interval(hours => %s))
                   RETURNING id""",
                (case_id, f"{local}@{domain}", local, domain, digest, text,
                 channel_binding_id, contact_block_id, labels.classification,
                 policy.ceiling, WKD_ROUTE, requested_by,
                 LOOKUP_SIGNOFF_HOURS)).fetchone()
            self._audit(case_id, requested_by, "PGP_KEY_LOOKUP_REQUESTED", row[0],
                        {"lookup_id": str(row[0]), "domain": domain,
                         "wkd_hash": digest, "methods": list(methods)},
                        object_type="pgp_key_lookup")
        lookup = self.lookup(case_id, row[0], viewer=requested_by,
                             clearance=clearance, held=held)
        return {"lookup": lookup,
                "notice": ("Nothing has been sent. A second person who may "
                           "approve key lookups on this case (a Lead "
                           "investigator or a Reviewer) approves it, and it is "
                           f"sent then. It lapses at {lookup['expires_at_text']}.")}

    def _lookup_for_decision(self, case_id: UUID, lookup_id: UUID, *,
                             clearance: str) -> tuple:
        row = self._c.execute(
            """SELECT id, state, expires_at <= now(), requested_by, domain,
                      wkd_hash, classification::text, address
                 FROM comms.pgp_key_lookup
                WHERE id = %s AND case_id = %s
                  AND classification <= %s::core.tlp
                FOR UPDATE""",
            (lookup_id, case_id, clearance)).fetchone()
        if row is None:
            raise PgpNotFound("no such key lookup in this case")
        return row

    def decline(self, *, case_id: UUID, lookup_id: UUID, decided_by: UUID,
                reason: str, clearance: str, held: frozenset[str]) -> dict:
        """Decline a waiting request. Any holder of the approve permission
        may, the person who asked included (a Lead investigator withdrawing
        their own request). Loaded under the caller's labels like approval
        (a decline past the labels would be a write, and its 409 an
        existence oracle)."""
        text = (reason or "").strip()
        if not 3 <= len(text) <= 2000:
            raise PgpError("say why, in 3 to 2000 characters")
        with self._c.transaction():
            row = self._lookup_for_decision(case_id, lookup_id,
                                            clearance=clearance)
            if row[1] != "REQUESTED":
                raise PgpConflict(f"that key lookup is no longer waiting: it is "
                                  f"{row[1]}")
            self._c.execute(
                """UPDATE comms.pgp_key_lookup
                      SET state = 'DECLINED', decided_by = %s, decided_at = now(),
                          decision_note = %s
                    WHERE id = %s""", (decided_by, text, lookup_id))
            self._audit(case_id, decided_by, "PGP_KEY_LOOKUP_DECLINED", lookup_id,
                        {"lookup_id": str(lookup_id)},
                        object_type="pgp_key_lookup")
        return self.lookup(case_id, lookup_id, viewer=decided_by,
                           clearance=clearance, held=held)

    def approve_and_send(self, *, case_id: UUID, lookup_id: UUID,
                         approver: UUID, clearance: str, held: frozenset[str],
                         fetcher: Callable | None = None) -> dict:
        """Approve and send: two transactions around one outbound request.

        Tx 1 commits SENDING, the decision, BOTH candidate URLs and the SENT
        audit before anything leaves, so a process that dies mid-request
        leaves the right destinations named. The request goes through the
        wkd route only. Tx 2 files the key first (its guard admits a WKD
        acquisition only while the lookup is SENDING), then the outcome."""
        from noctornal_api.egress import Destination, RouteUnavailable, can_egress
        from noctornal_api.egress_policy import Rule
        fetch = fetcher or _default_fetcher
        expired = False
        with self._c.transaction():
            row = self._lookup_for_decision(case_id, lookup_id, clearance=clearance)
            _id, state, lapsed, requester, domain, digest, cls, _addr = row
            if state != "REQUESTED":
                raise PgpConflict(f"that key lookup is no longer waiting: it is "
                                  f"{state}")
            if lapsed:
                self._c.execute(
                    """UPDATE comms.pgp_key_lookup
                          SET state = 'EXPIRED', decided_at = now()
                        WHERE id = %s""", (lookup_id,))
                self._audit(case_id, approver, "PGP_KEY_LOOKUP_EXPIRED", lookup_id,
                            {"lookup_id": str(lookup_id)},
                            object_type="pgp_key_lookup")
                expired = True
            else:
                if approver == requester:
                    raise PgpConflict("a second person must approve; the person "
                                      "who asked cannot")
                active = self._c.execute(
                    "SELECT is_active FROM iam.app_user WHERE id = %s",
                    (requester,)).fetchone()
                if not active or not active[0]:
                    raise PgpConflict("the person who asked is no longer active, "
                                      "so the request is not sent; ask again")
                policy = directory_policy(self._c)
                if not policy.enabled:
                    raise PgpConflict(policy.problem)
                methods = _methods_for(policy, domain)
                if not methods:
                    raise PgpConflict(
                        f"{domain} is no longer on the Web Key Directory route, "
                        f"so the request is not sent.")
                case = self._c.execute(
                    'SELECT classification::text, compartments FROM core."case" '
                    'WHERE id = %s', (case_id,)).fetchone()
                decision = can_egress(cls, Destination.KEY_DIRECTORY,
                                      compartments=frozenset(case[1] or ()),
                                      destination_ceiling=policy.ceiling)
                if decision.denied or strictest(case[0], cls) != cls:
                    raise PgpConflict(
                        "The case's labels changed since the lookup was asked "
                        "for, so it is not sent.")
                urls = wkd_urls(domain, digest)
                planned = [(m, urls[m]) for m in (ADVANCED, DIRECT) if m in methods]
                try:
                    route = _wkd_route(self._c, declared=(
                        Rule.for_host(_ADVANCED_PREFIX + domain, {443}),
                        Rule.for_host(domain, {443}))).tagged(f"wkd:{lookup_id}")
                except RouteUnavailable as exc:
                    raise PgpConflict(f"{NO_ROUTE} The route answered: {exc}") from None
                self._c.execute(
                    """UPDATE comms.pgp_key_lookup
                          SET state = 'SENDING', decided_by = %s, decided_at = now(),
                              planned_urls = %s, sent_at = now()
                        WHERE id = %s""",
                    (approver, [u for _m, u in planned], lookup_id))
                self._audit(case_id, approver, "PGP_KEY_LOOKUP_APPROVED", lookup_id,
                            {"lookup_id": str(lookup_id)},
                            object_type="pgp_key_lookup")
                self._audit(case_id, approver, "PGP_KEY_LOOKUP_SENT", lookup_id,
                            {"lookup_id": str(lookup_id), "domain": domain,
                             "urls": [u for _m, u in planned],
                             "route": route.route_id},
                            object_type="pgp_key_lookup")
        if expired:
            raise PgpConflict("the request lapsed; ask again")

        outcome = self._send(planned, route, fetch)
        body = outcome.pop("body", None)
        keys: list[InspectedKey] = []
        if outcome["state"] == "FOUND":
            try:
                keys = inspect_keys(body)
            except PgpUnavailable:
                outcome.update(state="FAILED", detail=GPG_LOST)
            except PgpError as exc:
                outcome.update(state="FAILED",
                               detail=f"The directory answered with something that "
                                      f"is not a usable public key: {exc}")
        with self._c.transaction():
            if outcome["state"] == "FOUND":
                acquisition_id = self._c.execute(
                    """INSERT INTO comms.pgp_key_acquisition
                           (case_id, source, raw_bytes, raw_sha256, source_ref,
                            channel_binding_id, contact_block_id, classification,
                            compartments, requested_by, lookup_id)
                       SELECT case_id, 'WKD', %s, %s, %s, channel_binding_id,
                              contact_block_id, classification, '{}',
                              requested_by, id
                         FROM comms.pgp_key_lookup WHERE id = %s
                       RETURNING id""",
                    (body, hashlib.sha256(body).digest(), outcome["url_used"],
                     lookup_id)).fetchone()[0]
                self._insert_keys(case_id, acquisition_id, keys)
            self._c.execute(
                """UPDATE comms.pgp_key_lookup
                      SET state = %s, method_used = %s, url_used = %s,
                          http_status = %s, response_sha256 = %s,
                          response_bytes = %s, detail = %s, finished_at = now()
                    WHERE id = %s""",
                (outcome["state"], outcome.get("method_used"),
                 outcome.get("url_used"), outcome.get("http_status"),
                 outcome.get("response_sha256"), outcome.get("response_bytes"),
                 outcome.get("detail", "")[:2000], lookup_id))
            self._audit(case_id, approver, "PGP_KEY_LOOKUP_ANSWERED", lookup_id,
                        {"lookup_id": str(lookup_id), "outcome": outcome["state"],
                         "domain": domain, "method": outcome.get("method_used"),
                         "url": outcome.get("url_used"),
                         "status": outcome.get("http_status")},
                        object_type="pgp_key_lookup")
        return self.lookup(case_id, lookup_id, viewer=approver,
                           clearance=clearance, held=held)

    @staticmethod
    def _send(planned: list[tuple[str, str]], route, fetch) -> dict:
        """The request, and the fallback the WKD draft allows: to the
        direct URL only when the advanced host's name does not exist. A
        404 on the advanced method is final; a temporary failure is a
        failure. No exception text is kept: every detail is authored."""
        from noctornal_api import egress_policy
        from noctornal_api.pinned_http import (
            CollectionError,
            HttpStatusError,
            ResponseTooLarge,
            UnresolvableHost,
        )
        for index, (method, url) in enumerate(planned):
            has_next = index + 1 < len(planned)
            try:
                fetched = fetch(url, route=route)
            except UnresolvableHost as exc:
                if exc.permanent and method == ADVANCED and has_next:
                    continue
                return {"state": "FAILED", "method_used": method, "url_used": url,
                        "detail": "The directory's name could not be resolved."}
            except HttpStatusError as exc:
                if 300 <= exc.status < 400:
                    detail = ("The directory answered with a redirect; a key "
                              "lookup follows none.")
                else:
                    detail = f"The directory answered HTTP {exc.status}."
                return {"state": "FAILED", "method_used": method, "url_used": url,
                        "http_status": exc.status, "detail": detail}
            except ResponseTooLarge:
                return {"state": "FAILED", "method_used": method, "url_used": url,
                        "detail": "The directory's answer was larger than any "
                                  "key is."}
            except CollectionError as exc:
                code = getattr(exc, "code", "")
                why = (egress_policy.explain(code) if code in egress_policy.CODES
                       else "the request did not complete.")
                return {"state": "FAILED", "method_used": method, "url_used": url,
                        "detail": "The lookup failed: " + why}
            except Exception:  # noqa: BLE001 - recorded, never reflected
                return {"state": "FAILED", "method_used": method, "url_used": url,
                        "detail": "The lookup failed before an answer came back."}
            status = getattr(fetched, "status", None)
            body = bytes(getattr(fetched, "body", b"") or b"")
            if status == 404:
                return {"state": "NOT_FOUND", "method_used": method,
                        "url_used": url, "http_status": 404,
                        "detail": "The directory has no key for this address."}
            if status == 200 and body:
                return {"state": "FOUND", "method_used": method, "url_used": url,
                        "http_status": 200,
                        "response_sha256": hashlib.sha256(body).digest(),
                        "response_bytes": len(body), "body": body,
                        "detail": "The directory answered with a key."}
            return {"state": "FAILED", "method_used": method, "url_used": url,
                    "http_status": status,
                    "response_sha256": hashlib.sha256(body).digest() if body else None,
                    "response_bytes": len(body) if body else None,
                    "detail": f"The directory answered HTTP {status} with "
                              f"nothing a key lookup reads."}
        return {"state": "FAILED", "detail": "No directory URL could be tried."}

    # -- reads ----------------------------------------------------------------

    _LOOKUP_SELECT = """
        SELECT l.id, l.address, l.domain, l.reason, l.classification::text,
               l.ceiling::text, l.state,
               CASE WHEN l.state = 'REQUESTED' AND l.expires_at <= now()
                    THEN 'EXPIRED' ELSE l.state END,
               l.requested_by, ru.display_name, l.requested_at, l.expires_at,
               du.display_name, l.decided_at, l.decision_note, l.planned_urls,
               l.sent_at, l.method_used, l.url_used, l.http_status,
               l.response_bytes, l.detail, l.finished_at,
               l.channel_binding_id, l.contact_block_id,
               encode(l.response_sha256, 'hex'),
               ARRAY(SELECT k.id::text FROM comms.pgp_key k
                       JOIN comms.pgp_key_acquisition a ON a.id = k.acquisition_id
                      WHERE a.lookup_id = l.id ORDER BY k.created_at)
          FROM comms.pgp_key_lookup l
          JOIN iam.app_user ru ON ru.id = l.requested_by
          LEFT JOIN iam.app_user du ON du.id = l.decided_by
         WHERE l.case_id = %(case)s
           AND l.classification <= %(clearance)s::core.tlp"""

    def _can_approve(self, case_id: UUID, viewer: UUID) -> bool:
        row = self._c.execute(
            """SELECT EXISTS (
                 SELECT 1 FROM iam.case_assignment ca
                   JOIN iam.role_permission rp ON rp.role_key = ca.role_key
                   JOIN iam.app_user u ON u.id = ca.user_id
                  WHERE ca.user_id = %s AND ca.case_id = %s AND u.is_active
                    AND (ca.expires_at IS NULL OR ca.expires_at > now())
                    AND rp.permission_key = 'comms.key.lookup.approve')""",
            (viewer, case_id)).fetchone()
        return bool(row and row[0])

    def _lookup_rows(self, case_id: UUID, *, viewer: UUID, clearance: str,
                     extra: str = "", params: dict | None = None) -> list[dict]:
        approver = self._can_approve(case_id, viewer)
        rows = self._c.execute(
            self._LOOKUP_SELECT + extra + " ORDER BY l.requested_at DESC, l.id",
            {"case": case_id, "clearance": clearance} | (params or {})).fetchall()
        out = []
        for r in rows:
            waiting = r[7] == "REQUESTED"
            out.append({
                "id": str(r[0]), "address": r[1], "domain": r[2], "reason": r[3],
                "classification": r[4], "ceiling": r[5], "state": r[6],
                "effective_state": r[7],
                "requested_by": r[9], "requested_by_me": r[8] == viewer,
                "requested_at": r[10].isoformat(),
                "expires_at": r[11].isoformat(),
                "expires_at_text": _utc_text(r[11]),
                "decided_by": r[12],
                "decided_at": r[13].isoformat() if r[13] else None,
                "decision_note": r[14], "planned_urls": list(r[15] or []),
                "sent_at": r[16].isoformat() if r[16] else None,
                "method_used": r[17], "url_used": r[18], "http_status": r[19],
                "response_bytes": r[20], "detail": r[21],
                "finished_at": r[22].isoformat() if r[22] else None,
                "channel_binding_id": str(r[23]) if r[23] else None,
                "contact_block_id": str(r[24]) if r[24] else None,
                "response_sha256": r[25], "key_ids": list(r[26] or []),
                "can_approve": bool(waiting and approver and r[8] != viewer),
                "can_decline": bool(waiting and approver),
            })
        return out

    def lookups(self, case_id: UUID, *, viewer: UUID, clearance: str,
                held: frozenset[str]) -> list[dict]:
        return self._lookup_rows(case_id, viewer=viewer, clearance=clearance)

    def lookup(self, case_id: UUID, lookup_id: UUID, *, viewer: UUID,
               clearance: str, held: frozenset[str]) -> dict:
        rows = self._lookup_rows(case_id, viewer=viewer, clearance=clearance,
                                 extra=" AND l.id = %(lookup)s",
                                 params={"lookup": lookup_id})
        if not rows:
            raise PgpNotFound("no such key lookup in this case")
        out = rows[0]
        out["keys"] = (self._key_rows(clearance, held, "a.lookup_id = %(lookup)s",
                                      {"lookup": lookup_id})
                       if out["key_ids"] else [])
        return out

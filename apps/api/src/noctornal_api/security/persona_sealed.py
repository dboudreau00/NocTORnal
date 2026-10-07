"""The persona ring's sealed column, and the move onto it (ROADMAP-REMAINING
"A collector process", 2026-10-02).

`security/sealed.py` inventories and re-wraps the columns the TOTP ring
seals. `collect.collection_account.secret_ciphertext` left that list on
2026-10-02: a persona credential seals under NOCTORNAL_PERSONA_KEK
(persona_envelope.py), which in production only the collector holds, so the
API's readiness register could not open one if it tried and must not try.

A persona's forum session (`session_ciphertext`, 0161, the authenticated
forum path) seals under the same ring and is listed beside the credential
(2026-10-03). It is a credential of the same standing and is NOT a second
inventory: it is disposable (a persona whose session cannot be opened signs
in again), so the readers below that count and open credentials leave it
out, and `reseal_sessions` moves it with the credentials when the ring turns.

Four readers here, one per process that has a question:

- `key_groups` counts rows by key id and opens nothing. The API's readiness
  row `collector_split` reads it: how many persona credentials are still
  sealed under the TOTP ring, from before the split.
- `ring_verdict` opens a sample per persona key id with the persona ring,
  in the collector at start, which records the counts in its heartbeat
  for the register (2026-10-03).
- `inventory` opens rows with the persona ring (and the TOTP ring for the
  rows sealed before the split), for the collector's start and for
  `scripts/rewrap_secrets.py --persona`, which hold both.
- `move_and_rewrap` is that script's `--apply`: every credential sealed
  before the split is opened under the TOTP ring and sealed under the
  persona ring, and every persona credential under a retired persona key is
  re-sealed under the active one. A compare-and-set on the ciphertext, row
  by row, as `sealed.rewrap_table`, so a credential re-enrolled meanwhile
  is never overwritten.

An EMPTY ciphertext is a destroyed credential (PersonaVault.destroy_secret)
and is never counted or sealed, for `sealed.inventory`'s reason.
"""
from __future__ import annotations

from dataclasses import dataclass

import psycopg

from noctornal_api.security import envelope, persona_envelope
from noctornal_api.security.sealed import SAMPLE_ROWS, RewrapReport, SealedGroup

#: The persona ring's one sealed column (table, ciphertext, key id).
PERSONA_SEALED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("collect.collection_account", "secret_ciphertext", "secret_key_id"),
    # A forum persona's session cookies, one sealed jar per board origin
    # (forum_session.py): NULL once the persona stops.
    ("collect.collection_account", "session_ciphertext", "session_key_id"),
)

_TABLE, _CIPHER, _KID = PERSONA_SEALED_COLUMNS[0]
_S_TABLE, _S_CIPHER, _S_KID = PERSONA_SEALED_COLUMNS[1]


@dataclass(frozen=True)
class KeyGroup:
    key_id: str
    rows: int

    @property
    def before_split(self) -> bool:
        return not persona_envelope.is_persona_key_id(self.key_id)


def key_groups(conn: psycopg.Connection) -> list[KeyGroup]:
    """Persona credentials by recorded key id, opening nothing. A NULL id
    reads as the TOTP ring's default, which is what sealed it."""
    rows = conn.execute(
        f"SELECT COALESCE({_KID}, %s), count(*) FROM {_TABLE} "
        f"WHERE octet_length({_CIPHER}) > 0 GROUP BY 1 ORDER BY 1",
        (envelope.DEFAULT_KEY_ID,)).fetchall()
    return [KeyGroup(str(k), int(n)) for k, n in rows]


def sealed_before_split(conn: psycopg.Connection) -> int:
    """How many persona credentials are still under the TOTP ring."""
    return sum(g.rows for g in key_groups(conn) if g.before_split)


def inventory(conn: psycopg.Connection, *,
              sample: int = SAMPLE_ROWS) -> list[SealedGroup]:
    """Each key id group with how many of its first `sample` rows open: a
    persona id under the persona ring, a TOTP id under the TOTP ring (which
    is what the move will have to open). Called only where both are held."""
    out: list[SealedGroup] = []
    for group in key_groups(conn):
        blobs = conn.execute(
            f"SELECT {_CIPHER} FROM {_TABLE} "
            f"WHERE COALESCE({_KID}, %s) = %s AND octet_length({_CIPHER}) > 0 "
            f"ORDER BY id LIMIT %s",
            (envelope.DEFAULT_KEY_ID, group.key_id, sample)).fetchall()
        opener = envelope.can_open if group.before_split else persona_envelope.can_open
        unopenable, problem = 0, None
        for (blob,) in blobs:
            verdict = opener(bytes(blob), key_id=group.key_id)
            if verdict is not None:
                unopenable += 1
                problem = problem or verdict
        label = (f"{_TABLE} (sealed before the split)" if group.before_split
                 else _TABLE)
        out.append(SealedGroup(label, group.key_id, group.rows, len(blobs),
                               unopenable, problem))
    return out


@dataclass(frozen=True)
class RingVerdict:
    """What the collector's ring made of the persona credentials at start:
    key ids, counts and one sentence. Never a plaintext, never a key."""
    key_ids: tuple[str, ...]
    sampled: int
    unopenable: int
    problem: str | None


def ring_verdict(conn: psycopg.Connection, *,
                 sample: int = SAMPLE_ROWS) -> RingVerdict:
    """The readiness probe the persona column lost when it left the TOTP
    inventory (2026-10-03), run where the key is: the
    collector, at start. Up to `sample` blobs per persona key id, opened
    with this process's persona ring, as `sealed.inventory` opens the TOTP
    ring's. A key changed under its id (a wrong or restored collector.env)
    is then a red register row by name, not a run of failed acts. Rows
    sealed before the split are left out: the register counts them itself
    and the move needs the TOTP ring. Raises PersonaKeyError when this
    process has no usable persona ring."""
    ids = persona_envelope.key_ids()
    sampled = unopenable = 0
    problem = None
    for group in key_groups(conn):
        if group.before_split:
            continue
        blobs = conn.execute(
            f"SELECT {_CIPHER} FROM {_TABLE} "
            f"WHERE {_KID} = %s AND octet_length({_CIPHER}) > 0 "
            f"ORDER BY id LIMIT %s", (group.key_id, sample)).fetchall()
        for (blob,) in blobs:
            sampled += 1
            verdict = persona_envelope.can_open(bytes(blob), key_id=group.key_id)
            if verdict is not None:
                unopenable += 1
                problem = problem or verdict
    return RingVerdict(ids, sampled, unopenable, problem)


def move_and_rewrap(conn: psycopg.Connection, *, batch: int = 200) -> RewrapReport:
    """Every persona credential under the ACTIVE persona key.

    A row under a TOTP ring id is opened with that ring and sealed with the
    persona ring (`recovered`, the move); a row under a retired persona id
    is re-sealed (`rewrapped`); a row already home is left byte for byte.
    Rows nothing opens are counted and left as found. Keyset-paged on id."""
    active = persona_envelope.active_key_id()
    report = RewrapReport(_TABLE)
    last = None
    while True:
        rows = conn.execute(
            f"SELECT id, {_CIPHER}, {_KID} FROM {_TABLE} "
            f"WHERE octet_length({_CIPHER}) > 0 "
            f"AND COALESCE({_KID}, %s) <> %s "
            f"AND (%s::uuid IS NULL OR id > %s) ORDER BY id LIMIT %s",
            (envelope.DEFAULT_KEY_ID, active, last, last, batch)).fetchall()
        if not rows:
            return report
        for row_id, blob, key_id in rows:
            last = row_id
            blob = bytes(blob)
            before_split = not persona_envelope.is_persona_key_id(key_id)
            try:
                plaintext = (envelope.decrypt(blob, key_id=key_id) if before_split
                             else persona_envelope.decrypt(blob, key_id=key_id))
            except (envelope.UNOPENABLE + persona_envelope.UNOPENABLE):
                report.unopenable += 1
                continue
            new_blob, new_id = persona_envelope.encrypt(plaintext)
            del plaintext
            cur = conn.execute(
                f"UPDATE {_TABLE} SET {_CIPHER} = %s, {_KID} = %s "
                f"WHERE id = %s AND {_CIPHER} = %s",
                (new_blob, new_id, row_id, blob))
            if cur.rowcount != 1:
                report.skipped += 1
            elif before_split:
                report.recovered += 1
            else:
                report.rewrapped += 1


def reseal_sessions(conn: psycopg.Connection, *,
                    batch: int = 200) -> tuple[RewrapReport, int]:
    """Every sealed forum session under the ACTIVE persona key: (report,
    cleared). A session under a retired persona key is re-sealed (`rewrapped`);
    one recorded under a TOTP ring id is CLEARED, never moved, because no
    release sealed a session that way and the persona simply signs in
    again; one nothing here opens is counted and left as found. A
    compare-and-set on the ciphertext, row by row, as `move_and_rewrap`."""
    active = persona_envelope.active_key_id()
    report = RewrapReport(f"{_S_TABLE} (forum sessions)")
    cleared = 0
    last = None
    while True:
        rows = conn.execute(
            f"SELECT id, {_S_CIPHER}, {_S_KID} FROM {_S_TABLE} "
            f"WHERE octet_length({_S_CIPHER}) > 0 "
            f"AND COALESCE({_S_KID}, %s) <> %s "
            f"AND (%s::uuid IS NULL OR id > %s) ORDER BY id LIMIT %s",
            (envelope.DEFAULT_KEY_ID, active, last, last, batch)).fetchall()
        if not rows:
            return report, cleared
        for row_id, blob, key_id in rows:
            last = row_id
            blob = bytes(blob)
            if not persona_envelope.is_persona_key_id(key_id):
                cur = conn.execute(
                    f"UPDATE {_S_TABLE} SET {_S_CIPHER} = NULL, {_S_KID} = NULL, "
                    f"session_sealed_at = NULL "
                    f"WHERE id = %s AND {_S_CIPHER} = %s", (row_id, blob))
                cleared += cur.rowcount
                continue
            try:
                plaintext = persona_envelope.decrypt(blob, key_id=key_id)
            except persona_envelope.UNOPENABLE:
                report.unopenable += 1
                continue
            new_blob, new_id = persona_envelope.encrypt(plaintext)
            del plaintext
            cur = conn.execute(
                f"UPDATE {_S_TABLE} SET {_S_CIPHER} = %s, {_S_KID} = %s "
                f"WHERE id = %s AND {_S_CIPHER} = %s",
                (new_blob, new_id, row_id, blob))
            if cur.rowcount == 1:
                report.rewrapped += 1
            else:
                report.skipped += 1

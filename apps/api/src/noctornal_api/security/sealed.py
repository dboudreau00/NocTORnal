"""The inventory of envelope-sealed columns, and the re-wrap over them.

One list, read by two callers that must agree: the readiness check
`kek_ring_opens_stored_secrets` (does the ring open the rows the database
actually holds?) and `scripts/rewrap_secrets.py` (move every row under
the active key). A column added to one and not the other is a secret the
register vouches for and a rotation leaves behind, so the list lives here
and both import it.

## One row's verdict is not a group's

The first cut of `inventory` opened ONE row per (table, key id) and
called that the group's answer, on the reasoning that every row under an
id was sealed by the key the id names. That is true from 2026-09-11 on
and false for everything before it: until then every blob was recorded as
`env:v1` whatever key sealed it, so a deployment that ever changed its
KEK -- rotated on purpose, restored a secrets file from the wrong backup,
regenerated `.env.local` after a wiped checkout -- holds rows under two
keys and one id. The development database this was written against held
93 enrolled accounts under `env:v1`, of which 65 opened under no key
anyone still had. A one-row sample of that group answers "opens" or "does
not" depending on which row the planner returns first, which is a
readiness verdict decided by luck. So the check opens up to `SAMPLE_ROWS`
rows per group, deterministically, and counts.
"""
from __future__ import annotations

from dataclasses import dataclass

import psycopg

from noctornal_api.security import envelope

#: (table, ciphertext column, key-id column). Every one of these tables
#: has a uuid primary key called `id`, which the re-wrap pages on.
SEALED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("iam.app_user", "totp_secret_ciphertext", "totp_key_id"),
    ("collect.collection_account", "secret_ciphertext", "secret_key_id"),
    ("ingest.victim_credential", "value_ciphertext", "value_key_id"),
    ("lab.sample", "data_key_ciphertext", "data_key_id"),
    ("collect.egress_profile", "endpoint_ciphertext", "key_id"),
)

#: How many rows of one (table, key id) group the readiness check opens:
#: the lowest ids, so two calls agree. A group larger than this (stealer-
#: log victim credentials run to millions) is checked on its first
#: SAMPLE_ROWS and the evidence says so; the rewrap tool visits every row.
SAMPLE_ROWS = 1000


@dataclass(frozen=True)
class SealedGroup:
    table: str
    key_id: str
    rows: int
    checked: int
    unopenable: int
    #: The first problem met, or None when every checked row opened.
    problem: str | None

    @property
    def opens(self) -> bool:
        return self.unopenable == 0

    def describe(self) -> str:
        head = f"{self.table} {self.rows} under {self.key_id}"
        if self.opens:
            return head + (" (all open)" if self.checked == self.rows
                           else f" (first {self.checked} open)")
        return (head + f" ({self.unopenable} of {self.checked} checked do not "
                f"open: {self.problem})")


def inventory(conn: psycopg.Connection, *,
              sample: int = SAMPLE_ROWS) -> list[SealedGroup]:
    """Every (table, key id) pair holding sealed rows, with how many of
    its first `sample` rows the ring opens. A NULL key id is read as
    `envelope.DEFAULT_KEY_ID`, which is what `decrypt` does with it."""
    out: list[SealedGroup] = []
    for table, cipher, kid in SEALED_COLUMNS:
        groups = conn.execute(
            f"SELECT COALESCE({kid}, %s), count(*) FROM {table} "
            f"WHERE {cipher} IS NOT NULL GROUP BY 1 ORDER BY 1",
            (envelope.DEFAULT_KEY_ID,)).fetchall()
        for key_id, rows in groups:
            blobs = conn.execute(
                f"SELECT {cipher} FROM {table} "
                f"WHERE COALESCE({kid}, %s) = %s AND {cipher} IS NOT NULL "
                f"ORDER BY id LIMIT %s",
                (envelope.DEFAULT_KEY_ID, key_id, sample)).fetchall()
            unopenable, problem = 0, None
            for (blob,) in blobs:
                verdict = envelope.can_open(bytes(blob), key_id=key_id)
                if verdict is not None:
                    unopenable += 1
                    problem = problem or verdict
            out.append(SealedGroup(table, key_id, rows, len(blobs),
                                   unopenable, problem))
    return out


@dataclass
class RewrapReport:
    table: str
    #: Opened under the ring and re-sealed under the active key.
    rewrapped: int = 0
    #: Opened under nothing in the ring, then under the legacy key; re-sealed.
    recovered: int = 0
    #: Changed between the read and the write; left alone. Whatever wrote
    #: it sealed under the active key, so it needs nothing from this pass.
    skipped: int = 0
    #: Opened under nothing at all; left exactly as found.
    unopenable: int = 0


def rewrap_table(conn: psycopg.Connection, table: str, cipher: str, kid: str,
                 *, legacy: bytes | None = None,
                 batch: int = 200) -> RewrapReport:
    """Re-seal every row of one table under the active key.

    Without `legacy`, only rows NOT recorded under the active id are
    visited: the rest are the active key's own. With it, every row is
    visited, because the rows a pre-ring key sealed are recorded under
    the active id too -- that is the whole problem -- and a row under the
    active id that opens is left untouched rather than re-nonced.

    The compare-and-set is on the ciphertext, not the key id, because two
    rows under one id are told apart only by their bytes. Keyset-paged on
    `id`, so a row this pass cannot move cannot make it loop.
    """
    active = envelope.active_key_id()
    report = RewrapReport(table)
    last = None
    while True:
        rows = conn.execute(
            f"SELECT id, {cipher}, {kid} FROM {table} "
            f"WHERE {cipher} IS NOT NULL "
            f"AND (%s OR COALESCE({kid}, %s) <> %s) "
            f"AND (%s::uuid IS NULL OR id > %s) ORDER BY id LIMIT %s",
            (legacy is not None, envelope.DEFAULT_KEY_ID, active,
             last, last, batch)).fetchall()
        if not rows:
            return report
        for row_id, blob, key_id in rows:
            last = row_id
            blob = bytes(blob)
            try:
                plaintext = envelope.decrypt(blob, key_id=key_id)
                if (key_id or envelope.DEFAULT_KEY_ID) == active:
                    continue                      # already home
                how = "rewrapped"
            except envelope.UNOPENABLE:
                if legacy is None:
                    report.unopenable += 1
                    continue
                try:
                    plaintext = envelope.open_with(blob, legacy)
                except envelope.UNOPENABLE:
                    report.unopenable += 1
                    continue
                how = "recovered"
            new_blob, new_id = envelope.encrypt(plaintext)
            cur = conn.execute(
                f"UPDATE {table} SET {cipher} = %s, {kid} = %s "
                f"WHERE id = %s AND {cipher} = %s",
                (new_blob, new_id, row_id, blob))
            if cur.rowcount == 1:
                setattr(report, how, getattr(report, how) + 1)
            else:
                report.skipped += 1


def rewrap_all(conn: psycopg.Connection, *,
               legacy: bytes | None = None) -> list[RewrapReport]:
    """`rewrap_table` over every sealed column. Rows nothing opens are
    counted and left; the caller decides what that means."""
    return [rewrap_table(conn, table, cipher, kid, legacy=legacy)
            for table, cipher, kid in SEALED_COLUMNS]

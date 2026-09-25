"""Renaming and retiring a registered compartment key (docs/17, closed
2026-09-23 as sec-compartment-retirement).

0057 made `iam.compartment` the closed vocabulary and 0059 bound every
compartment column to it by trigger, in both directions: a row cannot
carry an unregistered key, and the registry refuses to DROP or RENAME a
key while any row carries it, naming the columns that do. That binding
is right, and it left an administrator with no way to correct a key
short of a hand-written UPDATE on each bound column, in the right
order, inside one transaction they had to remember to open. A key typed
as `OP-KESTRAL` and filed under for a week was permanent, and a key
registered by mistake could not be taken out of the list.

## Rename moves the lock, it does not change who holds it

`rename` registers the new key with the old one's label (or a new
label), rewrites the old key to the new one in EVERY bound column, and
then drops the old key, all in one transaction. Every account read into
the old key is read into the new one, and every row filed under the old
key is filed under the new one, so no access decision changes: the lock
has a new name and the same holders. That is why it may run on a CLOSED
or ARCHIVED case's rows: the name of a lock is governance, not content.

Renaming ONTO a key that is already registered is refused. It would be a
merge: every account read into either compartment would open the other's
cases, which is a widening of access with a rename's name on it.

The order is forced by the binding. The new key must be registered
before any row carries it (the column triggers refuse it otherwise), and
the old key can only be dropped once nothing carries it (the registry
trigger refuses it otherwise). If any bound column is missed, that final
drop is refused by the database, and the whole rename rolls back.

## Retire drops a key nothing carries

`retire` removes a registered key that no row carries, and refuses one
that is still carried, saying where: how many rows of each kind carry
it, and, by name, the accounts, cases and ingest keys the administrator
asking could already see. A case's compartments cannot be edited in the
product (`UpdateCaseBody` says why), so a key that files a case stays
registered for as long as the case does; the refusal says so rather than
suggesting a remedy that does not exist. Accounts can be read out of it
from their card under Accounts.

## The refusal names only what the caller can already see

`user.manage` administers the registry and the accounts. It is not a
case role, and a SYS_ADMIN holds no case content by default (docs/05).
The first version of the refusal named up to five case CODES per key to
any `user.manage` holder, whatever their clearance, read-ins or
assignments, so a GREEN administrator retiring `STEALER-2026` was told
`OP-HALCYON-25`, a RED compartmented case. Nowhere else does the product
name a case to somebody who cannot open it: `CaseService.list_for_user`
exists so "the list [does not become] a disclosure channel", and
governance names a case only to somebody assigned to it (verifier,
sec-compartment-retirement, 2026-09-23). The names did not help the
administrator act either, since the same refusal says a filed case keeps
its key.

So a case is named only when it is in the caller's own case list
(`list_for_user`, the same predicate, so the two cannot drift), accounts
only for a caller holding `user.manage` (who lists every account under
Accounts anyway) and ingest keys only for one holding `ingest.manage`
(who lists every key under Ingest). Everything else is a count, and the
refusal says how many it did not name and why, so a count that exceeds
the names is not read as a mistake.

## Why the tables are locked

Both operations lock every bound table against writes (SHARE ROW
EXCLUSIVE for a rename, which writes them; SHARE for a retire, which only
reads them) for the length of the transaction. Without it, a write that
began before the rename committed (an ingest worker filing records under
the key its API key forces, say) could insert the OLD key after the
rename had moved every row it could see, and commit after it: a row
carrying a key the registry no longer holds, which is the silent
no-access 0059 exists to end. The column trigger cannot catch it,
because it ran while the old key was still registered, and the registry
trigger cannot either, because the row was not yet visible to it. With
the lock the concurrent write waits, and afterwards its own trigger
refuses the old key by name.

The cost is that writes to compartmented tables, and to accounts, wait
while a rename runs. The lock is asked for with a short timeout, and a
rename that cannot get it is refused as busy rather than queued behind a
long transaction with every other writer queued behind it.

Each action is audited in the same transaction as the change
(`COMPARTMENT_RENAMED` with the rows moved per column,
`COMPARTMENT_RETIRED`), so the record and the change cannot disagree.
Audit rows written before a rename keep the old key: they are what
happened, and the rename's own row is the map from one to the other.

Entities and ties both carry a trigger that stamps `updated_at` on every
update (`node_tsv` on `core.node`, `edge_validate` on `core.edge`), so a
rename moves the `updated_at` of each entity and tie it relabels. Nothing
in the product reads either column back; they are written, not
consulted, so no view treats the rename as a change of content.
"""
from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

import psycopg
from psycopg import sql
from psycopg.types.json import Json

from noctornal_api.cases import CaseService
from noctornal_api.iam_admin import COMPARTMENT_KEY, AdminError, IamAdminService
from noctornal_api.wording import agree, count_of

#: Every bound column: (schema, table, column, kind). 0059's eighteen and
#: every later migration's `ADDED_BOUND_COLUMNS` (docs/05, "Binding a
#: compartment column"; docs/00 decision 71, 2026-09-24).
#: test_compartment_contract_pg.py holds this tuple, the migrations and the
#: live bindings (`iam.compartment_bindings()`) to one set, so a column
#: bound by a later migration and missing here fails a test, fails the
#: readiness row `compartment_bindings_intact`, and would also fail the
#: rename itself at the final drop rather than leaving rows behind.
#:
#: APPEND-ONLY: a migration that binds a column adds one line per column
#: below the last, with a comment naming its roadmap item, in the same
#: change as the migration that installs its trigger. Order is not part
#: of the contract; the tests compare sets.
BOUND_COLUMNS: tuple[tuple[str, str, str, str], ...] = (
    ("iam", "app_user", "compartments", "array"),
    ("core", "case", "compartments", "array"),
    ("core", "node", "compartments", "array"),
    ("core", "edge", "compartments", "array"),
    ("core", "evidence", "compartments", "array"),
    ("analytics", "metric_run", "visibility_compartments", "array"),
    ("notify", "notification", "compartments", "array"),
    ("lab", "sample", "compartments", "array"),
    ("ingest", "record", "compartments", "array"),
    ("ingest", "dead_letter", "compartments", "array"),
    ("comms", "channel_binding", "compartments", "array"),
    ("comms", "conversation", "compartments", "array"),
    ("comms", "message", "compartments", "array"),
    ("comms", "contact_block", "compartments", "array"),
    ("deception", "capture", "compartments", "array"),
    ("deception", "email_message", "compartments", "array"),
    ("deception", "call_record", "compartments", "array"),
    ("ingest", "api_key", "forced_compartment", "scalar"),
    # Captured documents carry their case's compartments (L1, 0070).
    ("collect", "document", "compartments", "array"),
    # YARA rule sets are labelled (F12, 0080).
    ("lab", "yara_ruleset", "compartments", "array"),
    # Vendor key acquisitions carry their labels (F10b, 0088).
    ("comms", "pgp_key_acquisition", "compartments", "array"),
    # A document's similarity vectors carry its keys (F6.1, 2026-09-24).
    ("collect", "document_embedding", "read_compartments", "array"),
)

#: What an administrator calls the rows of each table, (one, many), for
#: the retire refusal and the rename's result. Keyed by table.
#: APPEND-ONLY with BOUND_COLUMNS: one entry per bound table.
NOUNS: dict[tuple[str, str], tuple[str, str]] = {
    ("iam", "app_user"): ("account read in", "accounts read in"),
    ("core", "case"): ("case", "cases"),
    ("core", "node"): ("entity", "entities"),
    ("core", "edge"): ("tie", "ties"),
    ("core", "evidence"): ("exhibit", "exhibits"),
    ("analytics", "metric_run"): ("analytics run", "analytics runs"),
    ("notify", "notification"): ("notification", "notifications"),
    ("lab", "sample"): ("sample", "samples"),
    ("ingest", "record"): ("ingested record", "ingested records"),
    ("ingest", "dead_letter"): ("dead letter", "dead letters"),
    ("comms", "channel_binding"): ("channel binding", "channel bindings"),
    ("comms", "conversation"): ("conversation", "conversations"),
    ("comms", "message"): ("message", "messages"),
    ("comms", "contact_block"): ("contact block", "contact blocks"),
    ("deception", "capture"): ("capture", "captures"),
    ("deception", "email_message"): ("email", "emails"),
    ("deception", "call_record"): ("call record", "call records"),
    ("ingest", "api_key"): ("ingest key", "ingest keys"),
    # L1, 0070.
    ("collect", "document"): ("document", "documents"),
    # F12, 0080.
    ("lab", "yara_ruleset"): ("YARA rule set", "YARA rule sets"),
    # F10b, 0088.
    ("comms", "pgp_key_acquisition"): ("imported vendor key", "imported vendor keys"),
    # F6.1.
    ("collect", "document_embedding"): ("similarity index row",
                                        "similarity index rows"),
}

#: The column that names a row to a person, where there is one, so the
#: refusal can say WHICH cases, accounts and ingest keys and not only how
#: many; and how the refusal says why the rest are not named. Which rows a
#: caller may be told by name is `CompartmentLifecycle._nameable`'s
#: question (module docstring, "The refusal names only what the caller
#: can already see").
_NAMED_BY: dict[tuple[str, str], tuple[str, str]] = {
    ("iam", "app_user"): ("email", "list"),
    ("core", "case"): ("code", "open"),
    ("ingest", "api_key"): ("name", "list"),
}

#: The global verb whose holder already lists every row of a kind by name
#: elsewhere in the console. Cases have none: a case is named only when it
#: is in the caller's own case list.
_LISTED_WITH: dict[tuple[str, str], str] = {
    ("iam", "app_user"): "user.manage",
    ("ingest", "api_key"): "ingest.manage",
}

#: How many names the refusal prints per kind before it says "and N more".
_NAMES_SHOWN = 5

#: The one bound column an administrator can change from the console: an
#: account's read-ins. Everything else is filed content.
ACCOUNTS_COLUMN = "iam.app_user.compartments"

#: How long a rename or retire waits for the bound tables before it gives
#: up and says so. Every writer of a compartmented table queues behind a
#: lock request that is waiting, so this is kept short.
LOCK_TIMEOUT = "5s"


class CompartmentError(AdminError):
    """A refusal about a compartment. An `AdminError`, so the router maps
    it as it maps every registry refusal."""


class NoSuchCompartment(CompartmentError):
    pass


class CompartmentBusy(CompartmentError):
    pass


@dataclass(frozen=True)
class Carrier:
    """One bound column that carries a key: what its rows are called, how
    many carry it, and (for cases, accounts and ingest keys) which of them
    the caller may be told by name.

    `nameable` is how many of the `rows` the caller could already see by
    name elsewhere, `names` the first few of those, and `seen_by` the verb
    ("open", "list") that says why the others are only counted. A kind
    with no name column has no `seen_by`, and is only counted."""
    column: str
    one: str
    many: str
    rows: int
    names: tuple[str, ...] = ()
    nameable: int = 0
    seen_by: str = ""

    def phrase(self) -> str:
        text = count_of(self.rows, self.one, self.many)
        hidden = self.rows - self.nameable if self.seen_by else 0
        if not self.names:
            # Nothing the caller may be told by name: the count, and why.
            if not hidden:
                return text
            return f"{text}, " + agree(
                hidden, f"which you cannot {self.seen_by}",
                f"none of which you can {self.seen_by}")
        said = ", ".join(self.names)
        more = self.rows - len(self.names)
        if more > 0 and hidden == more:
            said += f", and {hidden} you cannot {self.seen_by}"
        elif more > 0 and hidden:
            said += (f", and {more} more, including {hidden} you cannot "
                     f"{self.seen_by}")
        elif more > 0:
            said += f", and {more} more"
        return f"{text} ({said})"


def column_label(schema: str, table: str, column: str) -> str:
    return f"{schema}.{table}.{column}"


def _table(schema: str, table: str) -> sql.Composed:
    return sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(table))


def _carries(column: str, kind: str) -> sql.Composed:
    """`WHERE` predicate: this row carries the key given as the parameter.

    The array form is containment behind a cardinality test
    (2026-09-24): the same rows as `%s = ANY(col)` for a non-NULL key, and
    the shape a partial GIN index whose predicate is `cardinality(col) >
    0` can answer, which `collect.document` has (0070). A rename holds
    every bound table locked while it runs, so scanning the table of
    forum bodies for a key would hold every writer that long."""
    col = sql.Identifier(column)
    if kind == "array":
        return sql.SQL("cardinality({c}) > 0 AND {c} @> ARRAY[%s]::text[]"
                       ).format(c=col)
    return sql.SQL("{} = %s").format(col)


class CompartmentLifecycle:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    # -- reading ----------------------------------------------------------

    def where_carried(self, key: str, *,
                      viewer_id: UUID | None = None) -> list[Carrier]:
        """Every bound column that carries `key`, with its count and, where
        a row has a name a person would use, the first few names that
        `viewer_id` could already see. Without a viewer nothing is named:
        a caller that forgets to say who is asking gets counts, never a
        name it should not have (module docstring)."""
        out: list[Carrier] = []
        for schema, table, column, kind in BOUND_COLUMNS:
            where = _carries(column, kind)
            n = self._c.execute(
                sql.SQL("SELECT count(*) FROM {} WHERE {}").format(
                    _table(schema, table), where), (key,)).fetchone()[0]
            if not n:
                continue
            one, many = NOUNS[(schema, table)]
            label = column_label(schema, table, column)
            naming = _NAMED_BY.get((schema, table))
            if naming is None:
                out.append(Carrier(label, one, many, n))
                continue
            name_col, seen_by = naming
            nameable, names = self._nameable(
                schema, table, name_col, where, key, n, viewer_id)
            out.append(Carrier(label, one, many, n, names, nameable, seen_by))
        return out

    def _nameable(self, schema: str, table: str, name_col: str,
                  where: sql.Composed, key: str, rows: int,
                  viewer_id: UUID | None) -> tuple[int, tuple[str, ...]]:
        """How many of the `rows` carrying `key` in this table `viewer_id`
        may be told by name, and the first few of those names."""
        if viewer_id is None:
            return 0, ()
        if (schema, table) == ("core", "case"):
            # The caller's own case list, asked of the same method the case
            # list is, so what this names and what the console lists cannot
            # drift apart. A listing, not an access: no break-glass use.
            codes = sorted(c.code for c in
                           CaseService(self._c).list_for_user(viewer_id)
                           if key in c.compartments)
            return len(codes), tuple(codes[:_NAMES_SHOWN])
        verb = _LISTED_WITH[(schema, table)]
        if not IamAdminService(self._c).holds_global_permission(viewer_id,
                                                                verb):
            return 0, ()
        names = tuple(r[0] for r in self._c.execute(
            sql.SQL("SELECT {n} FROM {t} WHERE {w} ORDER BY {n} "
                    "LIMIT %s").format(
                n=sql.Identifier(name_col), t=_table(schema, table),
                w=where), (key, _NAMES_SHOWN)).fetchall())
        return rows, names

    # -- writing ----------------------------------------------------------

    def rename(self, key: str, new_key: str, *, label: str | None,
               actor_id: UUID) -> dict:
        """Rename `key` to `new_key` in the registry and in every bound
        column, in one transaction, and audit it. See the module
        docstring for the order and the lock."""
        key = (key or "").strip()
        new_key = (new_key or "").strip()
        label = (label or "").strip() or None
        if not COMPARTMENT_KEY.match(new_key):
            raise CompartmentError(
                f"{new_key!r} is not a valid compartment key: 2 to 32 "
                f"characters of A to Z, 0 to 9, underscore and hyphen, upper "
                f"case with no spaces, because the lock compares it exactly")
        if new_key == key:
            raise CompartmentError(
                f"{key} is already called {key}; nothing to rename")
        try:
            with self._c.transaction():
                old = self._lock_registry(key, mode="SHARE ROW EXCLUSIVE")
                if self._c.execute(
                        "SELECT 1 FROM iam.compartment WHERE key = %s",
                        (new_key,)).fetchone():
                    raise CompartmentError(
                        f"{new_key} is already registered. Renaming {key} "
                        f"onto it would merge two compartments, so everybody "
                        f"read into either would open the other's cases. "
                        f"Choose a key that is not in use.")
                self._c.execute(
                    """INSERT INTO iam.compartment (key, label, created_by,
                                                    created_at)
                       VALUES (%s, %s, %s, %s)""",
                    (new_key, label or old["label"], old["created_by"],
                     old["created_at"]))
                moved: dict[str, int] = {}
                for schema, table, column, kind in BOUND_COLUMNS:
                    moved_n = self._move(schema, table, column, kind,
                                         key, new_key)
                    if moved_n:
                        moved[column_label(schema, table, column)] = moved_n
                # The registry trigger refuses this while ANY bound column
                # still carries the old key, which is the proof that every
                # column above was covered.
                self._c.execute("DELETE FROM iam.compartment WHERE key = %s",
                                (key,))
                self._audit(actor_id, "COMPARTMENT_RENAMED", {
                    "from": key, "to": new_key,
                    "label": label or old["label"],
                    "previous_label": old["label"],
                    "rows": moved, "total": sum(moved.values())})
        except (psycopg.errors.LockNotAvailable,
                psycopg.errors.DeadlockDetected):
            raise self._busy("renamed") from None
        except psycopg.errors.UniqueViolation:
            # Registered by somebody else between the check and the insert.
            raise CompartmentError(
                f"{new_key} was registered while this rename ran, so {key} "
                f"was not renamed onto it. Choose a key that is not in use."
            ) from None
        except psycopg.errors.RaiseException as exc:
            # A binding trigger refusing: a bound column this module does
            # not know, most likely. Its first line names the column, and
            # nothing was changed.
            raise CompartmentError(str(exc).splitlines()[0]) from exc
        total = sum(moved.values())
        return {"key": new_key, "label": label or old["label"],
                "previous_key": key, "rows": moved, "total": total,
                "summary": self._moved_summary(key, new_key, moved)}

    def retire(self, key: str, *, actor_id: UUID) -> dict:
        """Drop `key` from the registry, or refuse, counting everything
        that still carries it and naming what `actor_id` can already see."""
        key = (key or "").strip()
        try:
            with self._c.transaction():
                old = self._lock_registry(key, mode="SHARE")
                carried = self.where_carried(key, viewer_id=actor_id)
                if carried:
                    raise CompartmentInUse(key, carried)
                self._c.execute("DELETE FROM iam.compartment WHERE key = %s",
                                (key,))
                self._audit(actor_id, "COMPARTMENT_RETIRED",
                            {"key": key, "label": old["label"]})
        except (psycopg.errors.LockNotAvailable,
                psycopg.errors.DeadlockDetected):
            raise self._busy("retired") from None
        except psycopg.errors.RaiseException as exc:
            raise CompartmentError(str(exc).splitlines()[0]) from exc
        return {"key": key, "label": old["label"], "retired": True}

    # -- internals --------------------------------------------------------

    def _lock_registry(self, key: str, *, mode: str) -> dict:
        """Lock the registry row, then every bound table in `mode`, with a
        short timeout (module docstring, "Why the tables are locked").
        `mode` is one of two literals, never caller input."""
        assert mode in ("SHARE", "SHARE ROW EXCLUSIVE")
        self._c.execute("SELECT set_config('lock_timeout', %s, true)",
                        (LOCK_TIMEOUT,))
        row = self._c.execute(
            """SELECT key, label, created_by, created_at
                 FROM iam.compartment WHERE key = %s FOR UPDATE""",
            (key,)).fetchone()
        if row is None:
            raise NoSuchCompartment(f"no compartment {key} is registered")
        tables = sql.SQL(", ").join(
            _table(s, t) for s, t, _c, _k in BOUND_COLUMNS)
        self._c.execute(sql.SQL("LOCK TABLE {} IN " + mode + " MODE").format(
            tables))
        self._c.execute("SET LOCAL lock_timeout TO DEFAULT")
        return {"key": row[0], "label": row[1], "created_by": row[2],
                "created_at": row[3]}

    def _move(self, schema: str, table: str, column: str, kind: str,
              key: str, new_key: str) -> int:
        col = sql.Identifier(column)
        if kind == "array":
            stmt = sql.SQL(
                "UPDATE {t} SET {c} = array_replace({c}, %s, %s) "
                "WHERE {w}").format(t=_table(schema, table), c=col,
                                    w=_carries(column, kind))
            params = (key, new_key, key)
        else:
            stmt = sql.SQL("UPDATE {t} SET {c} = %s WHERE {c} = %s").format(
                t=_table(schema, table), c=col)
            params = (new_key, key)
        return self._c.execute(stmt, params).rowcount or 0

    def _audit(self, actor_id: UUID, action: str, detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    detail)
               VALUES (%s, 'USER', %s, 'compartment', NULL, %s)""",
            (actor_id, action, Json(detail)))

    @staticmethod
    def _busy(what: str) -> CompartmentBusy:
        return CompartmentBusy(
            f"the compartment was not {what}: other work was writing to the "
            f"tables it is filed in and did not finish within "
            f"{LOCK_TIMEOUT.rstrip('s')} seconds. Nothing was changed; try "
            f"again in a quieter moment")

    @staticmethod
    def _moved_summary(key: str, new_key: str, moved: dict[str, int]) -> str:
        if not moved:
            return (f"Renamed {key} to {new_key}. Nothing was filed under it "
                    f"yet, so only the registry changed.")
        parts = []
        for schema, table, column, _kind in BOUND_COLUMNS:
            n = moved.get(column_label(schema, table, column))
            if n:
                one, many = NOUNS[(schema, table)]
                parts.append(count_of(n, one, many))
        return (f"Renamed {key} to {new_key} everywhere it was used: "
                f"{', '.join(parts)}. Everyone who could open what it locks "
                f"still can, and nobody else.")


class CompartmentInUse(CompartmentError):
    """The retire refusal. The message names every kind of row that still
    carries the key; `carriers` is the same, structured, for the console."""

    def __init__(self, key: str, carriers: list[Carrier]):
        self.key = key
        self.carriers = carriers
        where = "; ".join(c.phrase() for c in carriers)
        accounts = [c for c in carriers if c.column == ACCOUNTS_COLUMN]
        filed = [c for c in carriers if c.column != ACCOUNTS_COLUMN]
        said = [f"{key} is still in use, so it cannot be retired. It is "
                f"carried by {where}."]
        if accounts:
            n = accounts[0].rows
            said.append(
                f"Read {agree(n, 'that account', 'those accounts')} out of it "
                f"on {agree(n, 'its card', 'their cards')} under Accounts"
                + ("." if filed else ", then retire it."))
        if filed:
            # A case's compartments cannot be edited (UpdateCaseBody), and
            # everything inside a case copies the case's, so there is no
            # product action to offer here, and none is suggested.
            said.append(
                "Anything filed under it keeps it for as long as it exists: "
                "a case's compartments are fixed when it is opened, and "
                "what is filed in a case carries the case's. To change what "
                "the key is called, rename it instead.")
        super().__init__(" ".join(said))

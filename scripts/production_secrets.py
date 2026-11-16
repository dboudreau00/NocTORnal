"""Bring the production secrets files in infra/production to the layout
this release reads: the schema owner's credential out of secrets.env, a
Redis password and REDIS_URL for the limiter's own Redis user, the pepper the
audit log's hashes are keyed with, TLS that checks the server on every DSN
naming the bundled database, and the env files of Redis and MinIO, which read
no secrets.env. Nothing it prints carries a value.

    python3 scripts/production_secrets.py [--dir infra/production] [--new-database]

release/install.sh --production-secrets and release/install.ps1
-ProductionSecrets run this; running it by hand does the same.

1. Creates secrets.env, postgres-init.env and migrate.env from their templates when one is missing
   (mode 600).
2. Moves POSTGRES_PASSWORD from secrets.env to postgres-init.env, which only the database reads,
   and NOCTORNAL_MIGRATION_DATABASE_URL to migrate.env, which only the migration job reads: the
   owner is not bound by row-level security and can switch off the append-only triggers. Moves
   NOCTORNAL_APP_DB_PASSWORD to postgres-init.env too, since only initdb reads it and the database
   no longer reads secrets.env. A destination that already holds a different value is a refusal,
   because which one the database was initialised with is the operator's question, not a script's
   guess.
3. Writes REDIS_PASSWORD when it is missing, a placeholder or not URL-safe (the production Redis
   rebuilds its ACL from it at every start), and makes REDIS_URL sign in as noctornal_limiter with
   it over TLS (rediss://, naming the deployment's CA), since the production Redis disables its
   default user and speaks TLS alone. Every REDIS_URL the redis service's start check would refuse
   is one this rewrites, so the two never send an operator in a circle; a REDIS_URL naming another
   host is the operator's own Redis, left alone and said.
4. With --new-database, and only when no owner password was ever chosen, generates one into
   postgres-init.env and migrate.env. The installers pass it when the database volume does not
   exist yet: initdb fixes the owner's password for good.
5. Writes NOCTORNAL_AUDIT_PEPPER when it is missing, a placeholder, shorter than the API accepts or
   the same value as the ingest pepper or the TOTP key, with the template's comment above a line it
   adds to an older secrets.env. A value the API accepts is never replaced: rotating it is the
   operator's choice, and costs the correlation of new audit rows with older ones.
6. Makes every DSN naming the bundled `postgres` service (DATABASE_URL and
   NOCTORNAL_WORKER_DATABASE_URL in secrets.env, NOCTORNAL_MIGRATION_DATABASE_URL in migrate.env,
   NOCTORNAL_EGRESS_DATABASE_URL in egress-proxy.env when that file exists) ask for
   sslmode=verify-full against the deployment's CA, since that database admits the network over
   TLS alone and production refuses any other sslmode. A DSN naming another host is the operator's
   own database, left alone and said.
7. Writes redis.env and minio.env from secrets.env, mode 600: redis.env with REDIS_PASSWORD and
   REDIS_URL, minio.env with MinIO's root pair and every other MINIO_ setting but the four the
   application's store clients read, and the SAMPLE_ and PRESERVE_ account keys and bucket names
   minio-init makes. Postgres, Redis and MinIO read no secrets.env (docs/17, 2026-11-15), so a
   value changed in secrets.env reaches them when this runs again. A line it does not carry is left
   as the operator wrote it, and one secrets.env no longer sets is taken out.

Every file it changes is first copied to NAME.backup-UTCSTAMP (mode 600), the way back
(release/secrets-upgrade/README.md). It writes nothing when it refuses. Exit 0 when the files are
ready, 1 when it refused or something is left for the operator, each said in one line.

Each file is replaced whole (written beside it, then renamed), and secrets.env is written last, so
a write that fails part way leaves secrets.env as it was and a re-run finishes the job, finding the
same value in both places. A file it cannot read or write (root-owned, mode 600) or that is not
UTF-8 text is refused in one sentence naming the file and the fix, never a traceback. Comments an
older template put above a line it moves or rewrites go with the line or are replaced by the
current template's; they are recognised by a phrase only that template carried (STALE_COMMENTS),
and anything else stays as the operator wrote it.
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

PROD_DIR = Path(__file__).resolve().parent.parent / "infra" / "production"

#: Held equal to ratelimit_redis.LIMITER_ACL_USER by a test. This script
#: imports nothing from the application, so it runs on a host python with
#: no virtual environment (3.8 or later).
LIMITER_USER = "noctornal_limiter"
#: The owner role, compose's POSTGRES_USER.
OWNER_ROLE = "noctornal"
#: Values somebody has already published; each is in config's marker list
#: (a test holds that), so a value refused at boot is never kept here.
PUBLISHED = ("replace-me", "dev_only_change_me", "not-a-real-one")
#: What a password must be made of to sit in a URL unencoded, and to be
#: compared as text by the redis service's start check in compose.yml.
URL_SAFE = re.compile(r"^[A-Za-z0-9_.~-]+$")

SECRETS = "secrets.env"
POSTGRES_INIT = "postgres-init.env"
MIGRATE = "migrate.env"
#: Each line that leaves secrets.env: the file it moves to, and when and why, for the note left behind.
MOVES = (("POSTGRES_PASSWORD", POSTGRES_INIT, "docs/17 F52, 2026-10-02"),
         ("NOCTORNAL_MIGRATION_DATABASE_URL", MIGRATE, "docs/17 F52, 2026-10-02"),
         ("NOCTORNAL_APP_DB_PASSWORD", POSTGRES_INIT, "docs/17, 2026-11-15"))

#: The env files of the services that run another project's image, written from secrets.env with the
#: names each reads and no other (docs/17, 2026-11-15): compose gives none of them secrets.env.
REDIS = "redis.env"
STORE = "minio.env"
DERIVED = {
    REDIS: ("REDIS_PASSWORD", "REDIS_URL"),
    STORE: ("MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD", "SAMPLE_ACCESS_KEY", "SAMPLE_SECRET_KEY",
            "PRESERVE_ACCESS_KEY", "PRESERVE_SECRET_KEY", "EVIDENCE_BUCKET", "INGEST_BUCKET",
            "SAMPLE_BUCKET", "COLLECT_RAW_BUCKET", "PRESERVE_BUCKET"),
}
#: minio.env also takes every other MINIO_ setting, the server's own, but these four, which the
#: application's store clients read and the server must not (MINIO_ACCESS_KEY and MINIO_SECRET_KEY
#: are MinIO's legacy names for its root pair).
MINIO_CLIENT = ("MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY", "MINIO_SECURE")
#: The comment each derived file opens with.
DERIVED_HEADER = {
    REDIS: ("# Written from secrets.env by `sudo bash release/install.sh --production-secrets`, and NOT in",
            "# git. Read by the redis service alone (infra/production/compose.yml): the limiter's",
            "# password, and the URL the application signs in with, so that the service can refuse one",
            "# that would not sign in. Change them in secrets.env and run the installer step again."),
    STORE: ("# Written from secrets.env by `sudo bash release/install.sh --production-secrets`, and NOT in",
            "# git. Read by minio and minio-init alone (infra/production/compose.yml): MinIO's root pair",
            "# and any other MINIO_ setting of the server's, and the account keys and bucket names",
            "# minio-init makes. Change them in secrets.env and run the installer step again."),
}
#: The services each derived file is read by, for what the script says.
DERIVED_READERS = {REDIS: "the redis service", STORE: "minio and minio-init"}
#: The compose service the bundled Redis answers as.
BUNDLED_REDIS_HOST = "redis"
#: The audit pepper and what the API asks of it (security/audit_hash.py, held equal by a test): the
#: shortest it accepts, and the secrets it must not be a copy of.
AUDIT_PEPPER = "NOCTORNAL_AUDIT_PEPPER"
AUDIT_PEPPER_MIN = 16
AUDIT_PEPPER_DISTINCT_FROM = ("NOCTORNAL_INGEST_PEPPER", "NOCTORNAL_TOTP_KEK")

#: The egress proxy's env file: read when it exists, never created here (its keys come from
#: scripts/egress_setup.py).
EGRESS = "egress-proxy.env"
#: The compose service the bundled database answers as, and the name on its certificate.
BUNDLED_POSTGRES_HOST = "postgres"
#: Every DSN a deployment holds, by file.
DSNS = ((SECRETS, "DATABASE_URL"), (SECRETS, "NOCTORNAL_WORKER_DATABASE_URL"),
        (MIGRATE, "NOCTORNAL_MIGRATION_DATABASE_URL"), (EGRESS, "NOCTORNAL_EGRESS_DATABASE_URL"))
#: The query that makes a DSN check the database's certificate and name. Held equal to
#: config.DATABASE_SSLMODE and config.DATABASE_CA_FILE by a test.
DATABASE_SSLMODE = "verify-full"
DATABASE_CA_FILE = "/certs/ca.crt"
#: The bundled Redis's URL names the same CA, as redis-py reads it.
REDIS_CA_QUERY = ("ssl_ca_certs", DATABASE_CA_FILE)
#: Query arguments that would switch redis-py's check of the server off, as it reads them.
REDIS_FALSE = ("0", "F", "FALSE", "N", "NO")
#: The comment an older secrets.env.example put above each line this script moves or rewrites, by
#: a phrase only that comment carried.
STALE_COMMENTS = {
    "POSTGRES_PASSWORD": "The OWNER role's password, given to the Postgres image",
    "NOCTORNAL_MIGRATION_DATABASE_URL": "What Alembic connects as. Read ONLY by",
    "NOCTORNAL_APP_DB_PASSWORD": "The APP role's password. Read by the initdb script",
    "REDIS_PASSWORD": "What `redis-server --requirepass` is started with",
    "REDIS_URL": "Note the empty username before the colon",
}
#: What to do about a file this cannot read or write: the files are root's,
#: mode 600, once the README's lock-down step has run.
AS_OWNER = ("run this as the user who owns the secrets files, with sudo on "
            "Linux (sudo bash release/install.sh --production-secrets) or as that "
            "user on Windows")


class Refused(Exception):
    """One sentence; nothing is written."""


def _cannot(verb: str, path: Path, exc: OSError) -> str:
    """One sentence for a file the OS would not let this read or write."""
    reason = exc.strerror or type(exc).__name__
    return f"cannot {verb} {path.name} in {path.parent} ({reason}): {AS_OWNER}."


def _published(value: str | None) -> bool:
    return value is None or not value.strip() or any(
        marker in value.lower() for marker in PUBLISHED)


def _generate() -> str:
    return secrets.token_urlsafe(32)


class EnvFile:
    """One env file, kept line by line so comments and order survive."""

    _LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")

    def __init__(self, path: Path, lines: list, newline: str, existed: bool,
                 original: bytes | None):
        self.path, self.lines, self.newline = path, lines, newline
        self.existed, self.original, self.changed = existed, original, False

    @classmethod
    def load(cls, path: Path) -> EnvFile:
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            # A comment saved as Windows-1252, say: one sentence, not a traceback. Where the byte
            # is, never what it is.
            raise Refused(f"{path.name} in {path.parent} is not UTF-8 text "
                          f"({exc.reason}, at byte {exc.start}); save it as UTF-8 "
                          f"and run this again.") from None
        newline = "\r\n" if "\r\n" in text else "\n"
        return cls(path, text.splitlines(), newline, True, raw)

    @classmethod
    def from_template(cls, path: Path) -> EnvFile:
        template = path.with_name(path.name + ".example")
        if not template.is_file():
            raise Refused(f"{path.name} is missing and so is {template.name}, "
                          f"its template; check out the whole release again.")
        made = cls.load(template)
        made.path, made.existed, made.original, made.changed = path, False, None, True
        return made

    def _where(self, key: str) -> list:
        return [i for i, line in enumerate(self.lines)
                if (m := self._LINE.match(line)) and m.group(1) == key]

    def get(self, key: str) -> str | None:
        found = self._where(key)
        if len(found) > 1:
            raise Refused(f"{key} is set {len(found)} times in {self.path.name}; "
                          f"keep the one this deployment uses and run this again.")
        if not found:
            return None
        value = self._LINE.match(self.lines[found[0]]).group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        return value

    def line(self, key: str) -> str:
        return self.lines[self._where(key)[0]].strip()

    def put(self, key: str, line: str) -> None:
        found = self._where(key)
        if found:
            if self.lines[found[0]] == line:
                return
            self.lines[found[0]] = line
        else:
            self.lines.append(line)
        self.changed = True

    def drop(self, key: str, note: str) -> None:
        for index in self._where(key):
            self.lines[index] = note
            self.changed = True

    def keys(self) -> list:
        """Every name the file sets, in its order."""
        return [m.group(1) for line in self.lines if (m := self._LINE.match(line))]

    def remove(self, key: str) -> None:
        found = set(self._where(key))
        if found:
            self.lines = [line for i, line in enumerate(self.lines) if i not in found]
            self.changed = True

    def comment_above(self, key: str) -> list:
        """The comment lines directly above `key`'s line, up to a blank
        line, a line that is not a comment or a rule of dashes."""
        found = self._where(key)
        if not found:
            return []
        start = found[0]
        while start > 0:
            above = self.lines[start - 1].strip()
            if not above.startswith("#") or set(above[1:].strip()) <= {"-"}:
                break
            start -= 1
        return self.lines[start:found[0]]

    def replace_stale_comment(self, key: str, replacement: list) -> bool:
        """Swap the comment above `key` for `replacement` when it is the one an older template
        wrote there (STALE_COMMENTS); leave any other comment as the operator wrote it."""
        block = self.comment_above(key)
        phrase = STALE_COMMENTS.get(key)
        if not phrase or not any(phrase in line for line in block):
            return False
        end = self._where(key)[0]
        self.lines[end - len(block):end] = list(replacement)
        self.changed = True
        return True

    def text(self) -> str:
        return self.newline.join(self.lines) + self.newline


def _write_private(path: Path, data: bytes) -> None:
    """Write `data` to `path` readable by its owner alone, by replacing it
    with a file created 0600 beside it, so no reader ever sees a half
    written file and no moment exists when it is readable by others."""
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # Before the replace, not after it: the last step is then the one that cannot half-succeed,
        # so the file at `path` is the old one or the finished new one whichever call fails.
        os.chmod(str(temp), 0o600)
        os.replace(str(temp), str(path))
    except BaseException:
        if temp.exists():
            temp.unlink()
        raise


def _backup(path: Path, original: bytes, stamp: str) -> Path:
    target = path.with_name(f"{path.name}.backup-{stamp}")
    count = 1
    while target.exists():
        count += 1
        target = path.with_name(f"{path.name}.backup-{stamp}-{count}")
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(original)
    os.chmod(str(target), 0o600)
    return target


def _password_in(url: str | None) -> str | None:
    if not url:
        return None
    try:
        password = urlsplit(url).password
    except ValueError:
        return None
    return unquote(password) if password is not None else None


def _with_credentials(url: str | None, user: str, password: str, default: str,
                      scheme: str | None = None) -> str:
    """`url` with its user and password replaced, host, port, path and
    query kept; `default` when `url` has no host to keep. `scheme`, when
    given, replaces the scheme too."""
    try:
        parts = urlsplit(url or "")
        host, port = parts.hostname, parts.port
    except ValueError:
        host = None
    if not host:
        parts, host, port = urlsplit(default), urlsplit(default).hostname, urlsplit(default).port
    netloc = f"{quote(user, safe='')}:{quote(password, safe='')}@{host}"
    if port:
        netloc += f":{port}"
    return urlunsplit((scheme or parts.scheme, netloc, parts.path, parts.query,
                       parts.fragment))


def _names_another_redis(url: str | None) -> bool:
    """True when REDIS_URL names a host other than the bundled `redis`
    service: the operator's own Redis, which the redis service's start
    check lets through and this script leaves alone. Everything else, an
    empty or published value, no host, or not a URL, is the bundled
    service's to write, as that check refuses all of it."""
    if not url or _published(url):
        return False
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    return bool(host) and host != BUNDLED_REDIS_HOST


def _with_database_tls(url: str | None) -> str | None:
    """`url` asking for sslmode=verify-full against the deployment's CA when it names the bundled
    database, its other query parameters kept and an sslrootcert it already names left as it is;
    None when it names another host, no host, or already asks for exactly that."""
    try:
        parts = urlsplit(url or "")
        host = parts.hostname
    except ValueError:
        return None
    if host != BUNDLED_POSTGRES_HOST:
        return None
    query = parse_qsl(parts.query, keep_blank_values=True)
    names = [name for name, _ in query]
    if "sslmode" in names:
        query = [(n, DATABASE_SSLMODE if n == "sslmode" else v) for n, v in query]
    else:
        query.append(("sslmode", DATABASE_SSLMODE))
    if "sslrootcert" not in names:
        query.append(("sslrootcert", DATABASE_CA_FILE))
    want = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, safe="/"),
                       parts.fragment))
    return None if want == url else want


def _another_database_unverified(url: str | None) -> bool:
    """True when `url` names a database host other than the bundled one and does not ask for
    sslmode=verify-full: production refuses it, and it is the operator's to change."""
    try:
        parts = urlsplit(url or "")
        host = parts.hostname
    except ValueError:
        return False
    if not host or host == BUNDLED_POSTGRES_HOST:
        return False
    return dict(parse_qsl(parts.query)).get("sslmode") != DATABASE_SSLMODE


def _with_redis_tls(url: str) -> str:
    """`url` (the bundled Redis's, already given the limiter's credentials) naming the CA, with any
    argument that would switch off the check of the server dropped."""
    parts = urlsplit(url)
    query = [(n, v) for n, v in parse_qsl(parts.query, keep_blank_values=True)
             if not (n == "ssl_cert_reqs" and v.lower() != "required")
             and not (n == "ssl_check_hostname" and v.upper() in REDIS_FALSE)]
    if REDIS_CA_QUERY[0] not in [n for n, _ in query]:
        query.append(REDIS_CA_QUERY)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, safe="/"),
                       parts.fragment))


def _template_comment(directory: Path, key: str) -> list:
    """The comment secrets.env.example writes above `key`, or none when
    the template cannot be read."""
    try:
        return EnvFile.load(directory / (SECRETS + ".example")).comment_above(key)
    except (OSError, Refused):
        return []


def _derived_names(name: str, key: str) -> bool:
    """Whether the derived file `name` carries the variable `key`."""
    return key in DERIVED[name] or (name == STORE and key.startswith("MINIO_")
                                    and key not in MINIO_CLIENT)


def _derive(files: dict, path: Path, said: list) -> None:
    """Bring the derived file at `path` (redis.env or minio.env) to what secrets.env says: each line
    it carries copied whole, one secrets.env no longer sets taken out, and any other line left as
    the operator wrote it (compose blanks every application secret on those services anyway)."""
    name, sec = path.name, files[SECRETS]
    wanted = [key for key in sec.keys() if _derived_names(name, key)]
    for key in wanted:
        sec.get(key)  # a name set twice is a refusal, as everywhere here
    target = files.get(name)
    if target is None:
        target = EnvFile(path, list(DERIVED_HEADER[name]), sec.newline, False, None)
        target.changed = True
        files[name] = target
        said.append(f"created {name} from secrets.env (mode 600): only "
                    f"{DERIVED_READERS[name]} read it")
    for key in [k for k in target.keys() if _derived_names(name, k) and k not in wanted]:
        target.remove(key)
        said.append(f"removed {key} from {name}: secrets.env no longer sets it")
    for key in wanted:
        had = target.line(key) if target.get(key) is not None else None
        target.put(key, sec.line(key))
        if target.existed and had != sec.line(key):
            said.append(f"copied {key} from secrets.env into {name}")


def plan(directory: Path, *, new_database: bool = False):
    """(files, said, left): the files as they should be written, the lines
    saying what changed, and what is left for the operator. Writes
    nothing. Refused propagates."""
    said: list[str] = []
    left: list[str] = []
    files = {}
    for name in (SECRETS, POSTGRES_INIT, MIGRATE):
        path = directory / name
        try:
            if path.is_file():
                files[name] = EnvFile.load(path)
            else:
                files[name] = EnvFile.from_template(path)
                said.append(f"created {name} from {name}.example (mode 600)")
        except OSError as exc:
            # A root-owned mode 600 file read by anybody else: one sentence and the fix, not a
            # traceback.
            raise Refused(_cannot("read", Path(exc.filename or path), exc)) from None
    for name in (EGRESS, REDIS, STORE):
        path = directory / name
        try:
            if path.is_file():
                files[name] = EnvFile.load(path)
        except OSError as exc:
            raise Refused(_cannot("read", path, exc)) from None
    sec = files[SECRETS]

    # 2. The owner's credential, and the request role's password only initdb reads, leave secrets.env.
    for key, home, why in MOVES:
        theirs = sec.get(key)
        if theirs is None:
            continue
        dest = files[home]
        ours = dest.get(key)
        reader = "the database" if home == POSTGRES_INIT else "the migration job"
        note = f"# {key} moved to {home} ({why}): only {reader} reads it."
        # A DSN step 5 already gave its TLS query (a run that stopped before secrets.env was
        # written) is the same DSN, not a second one.
        if ours is not None and not _published(ours) and ours != theirs \
                and (_with_database_tls(ours) or ours) != (_with_database_tls(theirs) or theirs):
            if _published(theirs):
                # secrets.env kept the template's placeholder while the
                # real value was written where it belongs: drop the copy.
                sec.replace_stale_comment(key, [])
                sec.drop(key, note)
                said.append(f"removed the placeholder {key} from secrets.env "
                            f"({home} already holds it)")
                continue
            raise Refused(
                f"{key} is in both secrets.env and {home}, with different values. "
                f"Keep the one the database was initialised with in {home}, delete "
                f"the line from secrets.env, and run this again.")
        dest.put(key, sec.line(key))
        # The old template's comment above the line goes with it, or it would describe a line that
        # is not there.
        sec.replace_stale_comment(key, [])
        sec.drop(key, note)
        said.append(f"moved {key} from secrets.env to {home}")

    # 4. A new database's owner password, only when none was ever chosen.
    init, mig = files[POSTGRES_INIT], files[MIGRATE]
    owner = init.get("POSTGRES_PASSWORD")
    dsn = mig.get("NOCTORNAL_MIGRATION_DATABASE_URL")
    if _published(owner) and _published(_password_in(dsn)):
        if new_database:
            password = _generate()
            init.put("POSTGRES_PASSWORD", f"POSTGRES_PASSWORD={password}")
            mig.put("NOCTORNAL_MIGRATION_DATABASE_URL",
                    "NOCTORNAL_MIGRATION_DATABASE_URL=" + _with_credentials(
                        dsn, urlsplit(dsn or "").username or OWNER_ROLE, password,
                        f"postgresql+psycopg://{OWNER_ROLE}:x@postgres:5432/noctornal"))
            said.append("generated the schema owner's password into postgres-init.env "
                        "and migrate.env, for a database volume that does not exist yet")
        else:
            left.append(
                "choose the schema owner's password and write it as POSTGRES_PASSWORD "
                "in postgres-init.env and inside NOCTORNAL_MIGRATION_DATABASE_URL in "
                "migrate.env, before the first up: the database fixes it at "
                "initialisation for good. On a host with Docker and no database "
                "volume yet, the installer generates it.")
    elif dsn is None:
        left.append("migrate.env has no NOCTORNAL_MIGRATION_DATABASE_URL; copy the "
                    "line from migrate.env.example and put the owner's password in it.")
    elif _password_in(dsn) != owner:
        left.append("the password inside NOCTORNAL_MIGRATION_DATABASE_URL (migrate.env) "
                    "is not POSTGRES_PASSWORD (postgres-init.env). The migration job "
                    "signs in with the first and a new database is initialised with "
                    "the second, so make them the same.")

    # 6. Every DSN naming the bundled database asks for TLS that checks it (after 2 and 4, so a DSN
    # moved or written above is covered).
    for name, key in DSNS:
        envfile = files.get(name)
        if envfile is None:
            continue
        url = envfile.get(key)
        want = _with_database_tls(url)
        if want is not None:
            envfile.put(key, f"{key}={want}")
            said.append(f"{key} in {name} now asks for TLS that checks the database's "
                        f"certificate (sslmode={DATABASE_SSLMODE})")
        elif _another_database_unverified(url):
            said.append(f"note: {key} in {name} names a database on another host, so it was "
                        f"left alone; production refuses it without sslmode={DATABASE_SSLMODE} "
                        f"(infra/production/README.md, step 3)")

    # 3. The limiter's Redis user.
    password = sec.get("REDIS_PASSWORD")
    if _published(password) or not URL_SAFE.match(password or ""):
        why = ("not URL-safe" if password and not _published(password)
               else "missing or a placeholder")
        password = _generate()
        sec.put("REDIS_PASSWORD", f"REDIS_PASSWORD={password}")
        said.append(f"generated REDIS_PASSWORD (it was {why})")
    url = sec.get("REDIS_URL")
    if not _names_another_redis(url):
        # The bundled service, in the one scheme it speaks: the start check refuses a `redis://`
        # URL naming it, so the scheme is rewritten too, and the CA is named.
        try:
            keep = None if _published(url) or not urlsplit(url or "").hostname else url
        except ValueError:
            keep = None
        want = _with_redis_tls(_with_credentials(
            keep, LIMITER_USER, password, f"rediss://x@{BUNDLED_REDIS_HOST}:6379/0",
            scheme="rediss"))
        if want != url:
            sec.put("REDIS_URL", f"REDIS_URL={want}")
            said.append(f"REDIS_URL now signs in as {LIMITER_USER} with REDIS_PASSWORD, "
                        f"over TLS")
    else:
        said.append("note: REDIS_URL names a Redis on another host, so it was left alone, "
                    "and the bundled redis service starts with no client; that Redis "
                    "needs the limiter's own ACL user (infra/production/README.md, The "
                    "limiter's Redis, which also says how to leave the bundled one out)")
    # The old template's comments above the two Redis lines describe `--requirepass` and a URL with
    # no user name; the current template's replace them.
    for key in ("REDIS_PASSWORD", "REDIS_URL"):
        sec.replace_stale_comment(key, _template_comment(directory, key))

    # 5. The audit pepper, whenever the API would refuse the one there, so the two never send an
    # operator in a circle.
    pepper = sec.get(AUDIT_PEPPER)
    if _published(pepper):
        why = "missing or a placeholder"
    elif len(pepper) < AUDIT_PEPPER_MIN:
        why = f"shorter than {AUDIT_PEPPER_MIN} characters"
    else:
        why = next((f"the same value as {other}" for other in AUDIT_PEPPER_DISTINCT_FROM
                    if pepper == sec.get(other)), None)
    if why:
        if pepper is None:
            # An older secrets.env, with no such line: it goes at the end, under the template's
            # comment.
            sec.lines.extend(([""] if sec.lines and sec.lines[-1].strip() else [])
                             + _template_comment(directory, AUDIT_PEPPER))
        sec.put(AUDIT_PEPPER, f"{AUDIT_PEPPER}={_generate()}")
        said.append(f"generated {AUDIT_PEPPER} (it was {why})")

    # 7. The env files of Redis and MinIO, from secrets.env as it is now written (after 3, so a Redis
    # password generated above is the one copied).
    for name in (REDIS, STORE):
        _derive(files, directory / name, said)

    for name in (SECRETS, POSTGRES_INIT, MIGRATE):
        envfile = files[name]
        held = sorted({m.group(1) for line in envfile.lines
                       if (m := EnvFile._LINE.match(line))
                       and "replace-me" in m.group(2).lower()})
        if held:
            said.append(f"note: {name} still carries a placeholder in "
                        f"{', '.join(held)}")
    return files, said, left


def apply(directory: Path, *, new_database: bool = False, out=print,
          stamp: str | None = None) -> int:
    try:
        files, said, left = plan(directory, new_database=new_database)
    except Refused as exc:
        out(f"refused: {exc} Nothing was written.")
        return 1
    stamp = stamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    changed = [f for f in files.values() if f.changed]
    # The files the owner's lines move into first, secrets.env, which they leave, last: a stop at
    # any point leaves secrets.env as it was, and a re-run finds the same value in both places,
    # which is agreement. The other order could leave the DSN only in a backup. sorted() is stable.
    ordered = sorted(changed, key=lambda f: f.path.name == SECRETS)
    written: list[str] = []
    envfile = None
    try:
        for envfile in changed:
            if envfile.existed:
                copy = _backup(envfile.path, envfile.original, stamp)
                out(f"backed up {envfile.path.name} to {copy.name} (mode 600)")
        for envfile in ordered:
            _write_private(envfile.path, envfile.text().encode("utf-8"))
            written.append(envfile.path.name)
    except OSError as exc:
        # Named by the file being written, never the temporary beside it. Backups are taken before
        # any file is changed, so a stop before the first write changed nothing.
        done = ("No secrets file was changed, so run this again once that is fixed."
                if not written else
                f"Already changed, each with its backup beside it: {', '.join(written)}. "
                f"{SECRETS} is written last, so it still holds every line it had; once "
                f"that is fixed, run this again and it finishes what is left.")
        out(f"stopped: {_cannot('write', envfile.path, exc)} {done}")
        return 1
    for line in said:
        out(line)
    if not changed:
        out("nothing to change: the files are already in this release's layout")
    for line in left:
        out(f"still to do: {line}")
    return 1 if left else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--dir", type=Path, default=PROD_DIR,
                        help="the directory holding secrets.env (default infra/production)")
    parser.add_argument("--new-database", action="store_true",
                        help="the database volume does not exist yet, so an owner "
                             "password may be generated")
    args = parser.parse_args(argv)
    try:
        is_dir = args.dir.is_dir()
    except OSError as exc:
        print(f"refused: {_cannot('read', args.dir, exc)} Nothing was written.")
        return 1
    if not is_dir:
        print(f"refused: {args.dir} is not a directory. Nothing was written.")
        return 1
    return apply(args.dir, new_database=args.new_database)


if __name__ == "__main__":
    sys.exit(main())

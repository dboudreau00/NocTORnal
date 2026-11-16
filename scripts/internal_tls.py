"""The production stack's own certificate authority: one CA, and a certificate for each server that
terminates TLS inside the compose network (MinIO, Postgres and Redis). Nothing it prints carries a
key.

    sudo python3 scripts/internal_tls.py init        a new deployment
    sudo python3 scripts/internal_tls.py migrate     a deployment with the old tls/public.crt and private.key
    sudo python3 scripts/internal_tls.py renew [minio] [postgres] [redis]
    sudo python3 scripts/internal_tls.py check
    sudo python3 scripts/internal_tls.py add-ca FILE

Every subcommand takes `--dir` (default infra/production/tls). The layout under it, and what
infra/production/compose.yml mounts from it:

    public/ca.crt                          what every client trusts; mounted read-only at /certs
                                           into every service that connects to one of the three,
                                           and into redis for its healthcheck
    minio/public.crt, minio/private.key    MinIO's names for its pair; mounted into minio alone
    postgres/server.crt, server.key        mounted into postgres alone
    redis/server.crt, server.key           mounted into redis alone
    ca/ca.key, ca/ca.crt                   the CA; mounted nowhere, and needed only to renew
    legacy-minio/                          after `migrate`: the old self-signed pair, mounted
                                           nowhere, for the way back

So a private key is mounted exactly where a server terminates TLS, and no client can read one
whatever the modes say. The modes are stated anyway: public/ and ca.crt readable by all, every
other directory 0700 and every key 0600, each root's when this runs as root (it says so when it
does not). MinIO holds no capability, so it reads only a key root owns.

The CA lasts ten years and each leaf 1095 days. A leaf names exactly its own compose service in its
subjectAltName (DNS:minio, DNS:postgres, DNS:redis), the name every client verifies, and the CA
carries name constraints that permit those three names and exclude every IP address, so a stolen
ca.key cannot mint a certificate for anything else the containers trust: the clients' bundle is the
system roots plus this CA, and it reaches the internet through the egress proxy. OpenSSL, Python's
ssl (strict mode included), libpq and Go's crypto/x509 enforce the constraints.

`migrate` takes an existing deployment's self-signed MinIO pair out of tls/ and re-issues MinIO's
certificate from the new CA. The old certificate is not kept in the trust bundle: `openssl req
-x509`, which made it, marks it CA:TRUE with no name constraint, so trusting it beside the CA would
let MinIO's key vouch for any name. The pair is kept, mounted nowhere, in legacy-minio/.

`add-ca` appends another CA to public/ca.crt, for a store or a database of the agency's own that
the services must trust; it refuses a file holding a private key or anything but certificates.
That file is also what every database and Redis client names as its only trust anchor (sslrootcert,
ssl_ca_certs), and a second CA in it is not bound by this CA's constraints, so `add-ca` refuses a
certificate that could vouch for minio, postgres or redis: a CA must carry name constraints that
leave the three out (permitted only other names, or the three excluded), and a certificate that is
not a CA must not name one of them. `check` fails a bundle that already holds such a certificate.

Standard library and the `openssl` binary (1.1.1 or later) only, so it runs on the host's python3,
3.8 or later, with no virtual environment, as the installer step does. openssl is run with a list
of arguments, never through a shell. Exit 0 when the command did what it was asked, 1 when it
refused, failed or (for `check`) found anything wrong or a certificate within 30 days of its end.
"""
from __future__ import annotations

import argparse
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

TLS_DIR = Path(__file__).resolve().parent.parent / "infra" / "production" / "tls"

#: Each server's certificate and key names. MinIO's are the names it looks for in its certificate
#: directory; Postgres and Redis are given theirs by compose.yml.
SERVERS = {
    "minio": ("public.crt", "private.key"),
    "postgres": ("server.crt", "server.key"),
    "redis": ("server.crt", "server.key"),
}
PUBLIC = "public"
BUNDLE = "ca.crt"
CA = "ca"
CA_KEY = "ca.key"
CA_CERT = "ca.crt"
LEGACY = "legacy-minio"
#: The layout before this script: MinIO's self-signed pair at the top of tls/, mounted whole into
#: every application container.
OLD_CERT, OLD_KEY = "public.crt", "private.key"

CA_DAYS = 3650
LEAF_DAYS = 1095
#: `check` fails a certificate this close to its end, since a leaf past notAfter stops every
#: client that verifies it.
WARN_DAYS = 30
#: How far before its issue a certificate is dated valid from. A certificate valid only from the
#: second it was signed reads as not yet valid on a host whose clock then steps back (a virtual
#: machine's time sync does, by a second or more), so its first verification can fail; public CAs
#: and Caddy's own backdate theirs the same way.
BACKDATE_SECONDS = 3600

PUBLIC_DIR_MODE = 0o755
PUBLIC_FILE_MODE = 0o644
PRIVATE_DIR_MODE = 0o700
KEY_MODE = 0o600
CERT_MODE = 0o644

#: The signing configuration `openssl ca` reads, relative to the staging directory it runs in.
#: `openssl ca` rather than `x509 -req` because only it takes a start date on every OpenSSL
#: release from 1.1.1 (see BACKDATE_SECONDS); its database is a throwaway in the staging directory,
#: since nothing here keeps a record of what it issued beyond the files themselves.
_CA_CONFIG = """\
[ca]
default_ca = issuer
[issuer]
database = index.txt
new_certs_dir = issued
serial = serial
default_md = sha256
policy = policy_any
unique_subject = no
email_in_dn = no
copy_extensions = none
[policy_any]
commonName = supplied
[req]
distinguished_name = dn
prompt = no
[dn]
CN = NocTORnal internal CA
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
nameConstraints = critical, {permitted}, excluded;IP:0.0.0.0/0.0.0.0, excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0
"""

_LEAF_CONFIG = """\
[req]
distinguished_name = dn
prompt = no
[dn]
CN = {name}
[v3_leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:{name}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""

#: Where to run it from, in the sentences that need it.
COMMAND = "sudo python3 scripts/internal_tls.py"
RESTART = "sudo docker compose -p noctornal-prod -f infra/production/compose.yml restart"


class Refused(Exception):
    """One sentence; nothing was written, or what was written is said."""


def _posix() -> bool:
    return os.name == "posix"


def _root() -> bool:
    return _posix() and os.geteuid() == 0


def _openssl_binary() -> str:
    found = shutil.which("openssl")
    if not found:
        raise Refused("openssl is not installed on this host, and every certificate here is "
                      "made and checked with it: install it (the openssl package) and run "
                      "this again.")
    return found


def _openssl(*args: str, input_text: str | None = None, cwd: Path | None = None) -> str:
    """Run openssl with `args` and return its stdout; Refused with the line that names the error
    on a non-zero exit. Never through a shell, and never with a key on the command line."""
    done = subprocess.run([_openssl_binary(), *args], input=input_text, capture_output=True,
                          text=True, cwd=str(cwd) if cwd else None)
    if done.returncode != 0:
        lines = [line.strip() for line in (done.stderr + done.stdout).splitlines()
                 if line.strip()]
        detail = next((line for line in lines if "error" in line.lower()),
                      lines[0] if lines else f"exit status {done.returncode}")
        raise Refused(f"openssl {args[0]} failed ({detail[:200]}).")
    return done.stdout


def _serial() -> str:
    """A random positive serial of 16 bytes, in the hex `openssl ca` reads from its serial file:
    unpredictable, and inside RFC 5280's 20."""
    return format(secrets.randbits(127) | (1 << 120), "x").zfill(32)


def _validity(days: int) -> tuple[str, str]:
    """`-startdate` and `-enddate` for a certificate issued now: dated BACKDATE_SECONDS early, and
    valid for `days` from now. UTCTime, which RFC 5280 asks for through 2049."""
    now = time.time()
    return (time.strftime("%y%m%d%H%M%SZ", time.gmtime(now - BACKDATE_SECONDS)),
            time.strftime("%y%m%d%H%M%SZ", time.gmtime(now + days * 86400)))


def _signer(staging: Path) -> Path:
    """The staging directory made ready for `openssl ca`: its configuration, an empty database and
    a directory for the copies it keeps. Returns the configuration."""
    config = staging / "issuer.cnf"
    if not config.exists():
        permitted = ", ".join(f"permitted;DNS:{name}" for name in SERVERS)
        config.write_text(_CA_CONFIG.format(permitted=permitted), encoding="ascii")
        (staging / "index.txt").write_text("", encoding="ascii")
        (staging / "issued").mkdir()
    return config


def _sign(staging: Path, request: Path, out: Path, days: int, extra: list) -> None:
    config = _signer(staging)
    (staging / "serial").write_text(_serial() + "\n", encoding="ascii")
    start, end = _validity(days)
    _openssl("ca", "-batch", "-notext", "-config", config.name, "-in", str(request),
             "-out", str(out), "-startdate", start, "-enddate", end, *extra, cwd=staging)


def _chmod(path: Path, mode: int) -> None:
    os.chmod(str(path), mode)
    if _root():
        os.chown(str(path), 0, 0)


def _ensure_dir(path: Path, mode: int, made: list) -> None:
    if path.is_symlink():
        raise Refused(f"{path} is a symbolic link; this writes keys only into a real directory.")
    if not path.is_dir():
        path.mkdir(parents=True)
        made.append(path)
    _chmod(path, mode)


def _place(source: Path, target: Path, mode: int, placed: list) -> None:
    """Move `source` (written private, in the staging directory) to `target` and state its mode.
    A rename, so no reader ever sees half a file."""
    os.chmod(str(source), mode)
    if _root():
        os.chown(str(source), 0, 0)
    os.replace(str(source), str(target))
    placed.append(target)


class _Staging:
    """A private directory beside the files being written, on the same filesystem, so every
    file is renamed into place whole. Removed however the work ends."""

    def __init__(self, base: Path):
        self.path = base / f".staging-{os.getpid()}"

    def __enter__(self) -> Path:
        self.path.mkdir(mode=PRIVATE_DIR_MODE)
        os.chmod(str(self.path), PRIVATE_DIR_MODE)
        return self.path

    def __exit__(self, *_exc) -> None:
        shutil.rmtree(str(self.path), ignore_errors=True)


def _new_key(path: Path) -> None:
    _openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-out", str(path))


def _issue_ca(staging: Path) -> tuple[Path, Path]:
    key, cert, request = staging / CA_KEY, staging / CA_CERT, staging / "ca.csr"
    config = _signer(staging)
    _new_key(key)
    _openssl("req", "-new", "-key", str(key), "-config", str(config), "-out", str(request))
    _sign(staging, request, cert, CA_DAYS,
          ["-selfsign", "-keyfile", str(key), "-extensions", "v3_ca"])
    return key, cert


def _issue_leaf(staging: Path, name: str, ca_key: Path, ca_cert: Path) -> tuple[Path, Path]:
    key, cert = staging / f"{name}.key", staging / f"{name}.crt"
    config, request = staging / f"{name}.cnf", staging / f"{name}.csr"
    config.write_text(_LEAF_CONFIG.format(name=name), encoding="ascii")
    _new_key(key)
    _openssl("req", "-new", "-key", str(key), "-config", str(config), "-out", str(request))
    _sign(staging, request, cert, LEAF_DAYS,
          ["-cert", str(ca_cert), "-keyfile", str(ca_key),
           "-extfile", str(config), "-extensions", "v3_leaf"])
    # What every client will do, before anything is placed: a leaf the CA does not vouch for is
    # refused here rather than by every service at its first handshake.
    _verify(cert, ca_cert)
    return key, cert


def _verify(cert: Path, bundle: Path) -> None:
    _openssl("verify", "-CAfile", str(bundle), str(cert))


def _end_date(cert: Path) -> str:
    out = _openssl("x509", "-noout", "-enddate", "-in", str(cert)).strip()
    return out.partition("=")[2] or out


def _ends_within(cert: Path, days: int) -> bool:
    done = subprocess.run([_openssl_binary(), "x509", "-noout", "-checkend",
                           str(days * 86400), "-in", str(cert)], capture_output=True, text=True)
    return done.returncode != 0


def _san(cert: Path) -> list[str]:
    out = _openssl("x509", "-noout", "-ext", "subjectAltName", "-in", str(cert))
    names = []
    for line in out.splitlines()[1:]:
        names.extend(part.strip() for part in line.split(",") if part.strip())
    return names


def _public_key(path: Path, *, of_cert: bool) -> str:
    if of_cert:
        return _openssl("x509", "-noout", "-pubkey", "-in", str(path))
    return _openssl("pkey", "-pubout", "-in", str(path))


def _layout(base: Path) -> dict:
    """Every file this script owns, by role."""
    files = {"bundle": base / PUBLIC / BUNDLE, "ca_key": base / CA / CA_KEY,
             "ca_cert": base / CA / CA_CERT}
    for name, (cert, key) in SERVERS.items():
        files[f"{name}_cert"] = base / name / cert
        files[f"{name}_key"] = base / name / key
    return files


def _issue_all(base: Path, said: list, placed: list) -> None:
    """The CA, the three leaves and the bundle, each renamed into place once all are made, and
    appended to `placed` as it lands so a caller can take them back. Refuses when any of them is
    already there."""
    files = _layout(base)
    present = [p.relative_to(base).as_posix() for p in files.values() if p.exists()]
    if present:
        raise Refused(f"{', '.join(present)} already exist under {base}, so this would replace "
                      f"certificates the running services trust: `renew` re-issues a leaf, "
                      f"`check` says what is there. Nothing was written.")
    made: list = []
    _ensure_dir(base, PUBLIC_DIR_MODE, made)
    _ensure_dir(base / PUBLIC, PUBLIC_DIR_MODE, made)
    _ensure_dir(base / CA, PRIVATE_DIR_MODE, made)
    for name in SERVERS:
        _ensure_dir(base / name, PRIVATE_DIR_MODE, made)
    with _Staging(base) as staging:
        ca_key, ca_cert = _issue_ca(staging)
        leaves = {name: _issue_leaf(staging, name, ca_key, ca_cert) for name in SERVERS}
        bundle = staging / "bundle.crt"
        shutil.copyfile(str(ca_cert), str(bundle))
        for name, (key, cert) in leaves.items():
            cert_name, key_name = SERVERS[name]
            _place(key, base / name / key_name, KEY_MODE, placed)
            _place(cert, base / name / cert_name, CERT_MODE, placed)
        _place(ca_cert, files["ca_cert"], CERT_MODE, placed)
        _place(ca_key, files["ca_key"], KEY_MODE, placed)
        # The bundle last: until it exists no client trusts anything this run made.
        _place(bundle, files["bundle"], PUBLIC_FILE_MODE, placed)
    said.append(f"issued the CA (tls/{CA}/{CA_KEY} and {CA_CERT}, valid {CA_DAYS} days, for "
                f"the names {', '.join(SERVERS)} alone)")
    for name, (cert_name, key_name) in SERVERS.items():
        said.append(f"issued {name}'s certificate (tls/{name}/{cert_name} and {key_name}, "
                    f"subjectAltName DNS:{name}, valid {LEAF_DAYS} days)")
    said.append(f"wrote tls/{PUBLIC}/{BUNDLE}, the CA every client trusts")


def _undo(placed: list) -> None:
    for path in reversed(placed):
        try:
            path.unlink()
        except OSError:
            pass


def _ownership_note(base: Path) -> list:
    if _root() or not _posix():
        return []
    return [f"note: this ran as uid {os.geteuid()} rather than root, so every file under {base} "
            f"is that user's. MinIO holds no capability and reads only a key root owns: run it "
            f"with sudo, or `sudo chown -R root:root {base}`, before the stack starts."]


def init(base: Path) -> list:
    if (base / OLD_KEY).exists() or (base / OLD_CERT).exists():
        raise Refused(f"{base} holds {OLD_CERT} and {OLD_KEY}, the layout before this release: "
                      f"run `{COMMAND} migrate`, which moves them aside and issues the rest. "
                      f"Nothing was written.")
    said: list = []
    placed: list = []
    try:
        _issue_all(base, said, placed)
    except BaseException:
        _undo(placed)
        raise
    return said + _ownership_note(base) + [
        f"move tls/{CA}/{CA_KEY} off this host once the stack runs: it is needed only to renew "
        f"(infra/production/README.md, step 3)"]


def migrate(base: Path) -> list:
    old_cert, old_key = base / OLD_CERT, base / OLD_KEY
    if not (old_cert.is_file() and old_key.is_file()):
        raise Refused(f"{base} does not hold {OLD_CERT} and {OLD_KEY}, so there is nothing to "
                      f"migrate: a new deployment runs `{COMMAND} init`. Nothing was written.")
    legacy = base / LEGACY
    if (legacy / OLD_KEY).exists() or (legacy / OLD_CERT).exists():
        raise Refused(f"{legacy} already holds a pair, so a migration ran here before: run "
                      f"`{COMMAND} check`. Nothing was written.")
    said: list = []
    placed: list = []
    made: list = []
    try:
        # The old pair is copied aside first and removed last, so a failure part way leaves the
        # old layout as it was and a re-run starts from it.
        _ensure_dir(legacy, PRIVATE_DIR_MODE, made)
        for source, mode in ((old_cert, CERT_MODE), (old_key, KEY_MODE)):
            target = legacy / source.name
            shutil.copy2(str(source), str(target))
            placed.append(target)
            _chmod(target, mode)
        said.append(f"copied {OLD_CERT} and {OLD_KEY} to tls/{LEGACY}/ (mounted nowhere, "
                    f"kept for the way back)")
        _issue_all(base, said, placed)
    except BaseException:
        _undo(placed)
        for directory in reversed(made):
            try:
                directory.rmdir()
            except OSError:
                pass
        raise
    left = []
    for source in (old_key, old_cert):
        try:
            source.unlink()
        except OSError as exc:
            left.append(f"still to do: remove tls/{source.name} by hand ({exc.strerror}); "
                        f"compose.yml no longer mounts it")
    said.append(f"removed tls/{OLD_KEY} and tls/{OLD_CERT}: MinIO now serves the certificate "
                f"this CA issued, and no client mounts a key")
    return said + _ownership_note(base) + left + [
        f"move tls/{CA}/{CA_KEY} off this host once the stack runs: it is needed only to renew "
        f"(infra/production/README.md, step 3)"]


def renew(base: Path, names: list) -> list:
    names = list(names) or list(SERVERS)
    unknown = [n for n in names if n not in SERVERS]
    if unknown:
        raise Refused(f"{', '.join(unknown)} is not one of {', '.join(SERVERS)}. Nothing was "
                      f"written.")
    files = _layout(base)
    if not files["ca_cert"].is_file():
        raise Refused(f"tls/{CA}/{CA_CERT} is missing, so there is no CA to renew from: a "
                      f"deployment without one runs `{COMMAND} init` (or `migrate`). Nothing "
                      f"was written.")
    if not files["ca_key"].is_file():
        raise Refused(f"tls/{CA}/{CA_KEY} is not on this host, as step 3 advises once the "
                      f"leaves are issued: copy it back to {files['ca_key']} (root's, mode "
                      f"600), run this again, and move it off afterwards. Nothing was written.")
    said: list = []
    with _Staging(base) as staging:
        issued = {n: _issue_leaf(staging, n, files["ca_key"], files["ca_cert"]) for n in names}
        ca_end = _end_date(files["ca_cert"])
        placed: list = []
        for name, (key, cert) in issued.items():
            cert_name, key_name = SERVERS[name]
            _ensure_dir(base / name, PRIVATE_DIR_MODE, [])
            _place(key, base / name / key_name, KEY_MODE, placed)
            _place(cert, base / name / cert_name, CERT_MODE, placed)
            said.append(f"renewed {name}'s certificate: valid until "
                        f"{_end_date(base / name / cert_name)}; `{RESTART} {name}` loads it")
    if _ends_within(files["ca_cert"], LEAF_DAYS):
        said.append(f"note: the CA itself ends {ca_end}, before these certificates do, and "
                    f"every client stops trusting them then")
    return said + _ownership_note(base)


def _pem_blocks(text: str) -> list:
    """Every PEM block in `text`, as (label, block)."""
    blocks, current, label = [], [], None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("-----BEGIN ") and stripped.endswith("-----"):
            label, current = stripped[len("-----BEGIN "):-len("-----")], [stripped]
        elif label is not None:
            current.append(stripped)
            if stripped == f"-----END {label}-----":
                blocks.append((label, "\n".join(current) + "\n"))
                label, current = None, []
    return blocks


def _fingerprint(block: str) -> str:
    out = _openssl("x509", "-noout", "-fingerprint", "-sha256", input_text=block)
    return out.strip().partition("=")[2].upper()


def _extension(block: str, name: str) -> list:
    """The lines openssl prints for the extension `name` of the certificate in `block`, stripped and
    without the heading; [] when the certificate does not carry it."""
    lines = _openssl("x509", "-noout", "-ext", name, input_text=block).splitlines()
    heading = next((i for i, line in enumerate(lines) if line.startswith("X509v3 ")), None)
    return [] if heading is None else [line.strip() for line in lines[heading + 1:] if line.strip()]


def _dns_within(name: str, base: str) -> bool:
    """Whether the DNS name constraint `base` covers `name`, as OpenSSL matches one: an empty base
    covers every name; otherwise the name is the base, or ends with it after a dot, and a base that
    starts with a dot covers only the names below it. Case does not count."""
    name, base = name.lower(), base.lower()
    if not base:
        return True
    if len(name) < len(base) or not name.endswith(base):
        return False
    return len(name) == len(base) or base.startswith(".") or name[-len(base) - 1] == "."


def _servers_vouched_for(block: str) -> list:
    """Which of the internal servers' names (SERVERS) the certificate in `block` could vouch for from
    the clients' bundle, where libpq, redis-py and the store's client take every certificate as a
    trust anchor. A certificate that is not a CA vouches only for itself: for the DNS names in its
    subjectAltName, or its common name when it has none. One that is a CA, or does not say (a
    version 1 root, which OpenSSL takes as one), vouches for every name its name constraints leave
    in: a permitted DNS subtree must cover the name when there is any, and no excluded one may."""
    if "CA:FALSE" in " ".join(_extension(block, "basicConstraints")):
        names = [part.strip()[4:] for line in _extension(block, "subjectAltName")
                 for part in line.split(",") if part.strip().startswith("DNS:")]
        if not names:
            subject = _openssl("x509", "-noout", "-subject", "-nameopt", "RFC2253",
                               input_text=block).strip().partition("=")[2]
            names = [field[3:] for field in subject.split(",") if field.startswith("CN=")]
        own = {name.lower() for name in names}
        return [server for server in SERVERS if server in own]
    permitted: list = []
    excluded: list = []
    section = None
    for line in _extension(block, "nameConstraints"):
        if line in ("Permitted:", "Excluded:"):
            section = permitted if line == "Permitted:" else excluded
        elif section is not None and line.startswith("DNS:"):
            section.append(line[4:])
    return [server for server in SERVERS
            if (not permitted or any(_dns_within(server, b) for b in permitted))
            and not any(_dns_within(server, b) for b in excluded)]


#: What add-ca and check say about a certificate that could vouch for an internal server.
CONSTRAIN = ("the database, Redis and object store clients trust every certificate in "
             f"tls/{PUBLIC}/{BUNDLE} for those names, so whoever holds its key could answer as "
             "one of them. Add a CA whose name constraints leave them out instead: one its owner "
             "issues permitted only your own names (permitted;DNS:.agency.example), or excluding "
             "postgres, redis and minio (excluded;DNS:postgres, excluded;DNS:redis, "
             "excluded;DNS:minio). A CA nobody will constrain is not for this file "
             "(infra/production/README.md, step 3)")


def add_ca(base: Path, source: Path) -> list:
    bundle = base / PUBLIC / BUNDLE
    if not bundle.is_file():
        raise Refused(f"tls/{PUBLIC}/{BUNDLE} does not exist yet: run `{COMMAND} init` first. "
                      f"Nothing was written.")
    try:
        text = source.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise Refused(f"cannot read {source} as PEM text ({type(exc).__name__}). Nothing was "
                      f"written.") from None
    if "PRIVATE KEY" in text:
        raise Refused(f"{source} holds a private key, and nothing in tls/{PUBLIC}/ may: give it "
                      f"the CA's certificate alone. Nothing was written.")
    blocks = _pem_blocks(text)
    others = sorted({label for label, _ in blocks if label != "CERTIFICATE"})
    certificates = [block for label, block in blocks if label == "CERTIFICATE"]
    if others or not certificates:
        raise Refused(f"{source} is not a file of PEM certificates"
                      + (f" (it holds {', '.join(others)})" if others else "")
                      + ". Nothing was written.")
    have = {_fingerprint(block) for label, block in _pem_blocks(
        bundle.read_text(encoding="ascii")) if label == "CERTIFICATE"}
    new = []
    for block in certificates:
        fingerprint = _fingerprint(block)
        if fingerprint not in have:
            new.append(block)
            have.add(fingerprint)
    if not new:
        return [f"nothing to change: tls/{PUBLIC}/{BUNDLE} already trusts every certificate in "
                f"{source.name}"]
    for block in new:
        vouched = _servers_vouched_for(block)
        if vouched:
            position = certificates.index(block) + 1
            raise Refused(f"certificate {position} of {len(certificates)} in {source.name} could "
                          f"vouch for {', '.join(vouched)}, and {CONSTRAIN}. Nothing was "
                          f"written.")
    with _Staging(base) as staging:
        written = staging / BUNDLE
        current = bundle.read_text(encoding="ascii")
        written.write_text(current.rstrip("\n") + "\n" + "".join(new), encoding="ascii")
        _place(written, bundle, PUBLIC_FILE_MODE, [])
    return [f"added {len(new)} certificate{'s' if len(new) != 1 else ''} from {source.name} "
            f"to tls/{PUBLIC}/{BUNDLE}; every service reads it when it starts, so restart them "
            f"(infra/production/README.md, step 3)"]


def check(base: Path) -> tuple:
    """(lines, ok). Reads the layout and changes nothing."""
    lines: list = []
    failed = False

    def fail(text: str) -> None:
        nonlocal failed
        failed = True
        lines.append(f"FAILED: {text}")

    def mode_of(path: Path) -> int:
        return path.stat().st_mode & 0o777

    files = _layout(base)
    if not base.is_dir():
        return [f"FAILED: {base} does not exist: run `{COMMAND} init`"], False
    if _posix() and mode_of(base) & 0o022:
        fail(f"{base} is mode {mode_of(base):o}: whoever may write it may replace what every "
             f"client trusts (755)")
    if (base / OLD_KEY).exists():
        fail(f"tls/{OLD_KEY} is still there, the old layout's MinIO key: run `{COMMAND} "
             f"migrate`")
    elif (base / OLD_CERT).exists():
        lines.append(f"note: tls/{OLD_CERT}, the old layout's certificate, is still there and "
                     f"nothing reads it; remove it")
    public = base / PUBLIC
    bundle = files["bundle"]
    if not bundle.is_file():
        fail(f"tls/{PUBLIC}/{BUNDLE} is missing, so no client can verify any server")
    else:
        for entry in sorted(public.iterdir()):
            if entry.suffix == ".key" or (entry.is_file() and "PRIVATE KEY" in entry.read_text(
                    encoding="ascii", errors="replace")):
                fail(f"tls/{PUBLIC}/{entry.name} holds a private key, and that directory is "
                     f"mounted into every client")
        if _posix():
            if mode_of(public) & 0o022 or mode_of(public) & 0o005 != 0o005:
                fail(f"tls/{PUBLIC} is mode {mode_of(public):o}: every client must read it and "
                     f"only its owner write it (755)")
            if mode_of(bundle) & 0o022 or not mode_of(bundle) & 0o004:
                fail(f"tls/{PUBLIC}/{BUNDLE} is mode {mode_of(bundle):o}: every client must "
                     f"read it and only its owner write it (644)")
            if _root() and (public.stat().st_uid != 0 or bundle.stat().st_uid != 0):
                fail(f"tls/{PUBLIC} or its {BUNDLE} is not root's, and its owner may replace "
                     f"what every client trusts: `chown -R root:root {base}`")
    ca_dir = base / CA
    if _posix() and ca_dir.is_dir() and mode_of(ca_dir) & 0o077:
        fail(f"tls/{CA} is mode {mode_of(ca_dir):o}; it holds the CA's key (700)")
    if _posix() and files["ca_key"].is_file() and mode_of(files["ca_key"]) & 0o077:
        fail(f"tls/{CA}/{CA_KEY} is mode {mode_of(files['ca_key']):o}; a key is 600")
    ca_cert = files["ca_cert"]
    if ca_cert.is_file():
        when = _end_date(ca_cert)
        if _ends_within(ca_cert, WARN_DAYS):
            fail(f"the CA ends {when}, within {WARN_DAYS} days")
        else:
            lines.append(f"ok: the CA is valid until {when}")
    else:
        fail(f"tls/{CA}/{CA_CERT} is missing")
    if files["ca_key"].is_file():
        lines.append(f"note: tls/{CA}/{CA_KEY} is on this host; it is needed only to renew, "
                     f"so keep it elsewhere between renewals")
    if bundle.is_file():
        # Another certificate in the clients' bundle that could vouch for an internal server: an
        # add-ca from before add-ca asked (the deployment's CA is the first, as init writes it).
        held = [block for label, block in _pem_blocks(bundle.read_text(encoding="ascii"))
                if label == "CERTIFICATE"]
        own = _fingerprint(ca_cert.read_text(encoding="ascii")) if ca_cert.is_file() else None
        for position, block in enumerate(held, 1):
            if (own is None and position == 1) or _fingerprint(block) == own:
                continue
            vouched = _servers_vouched_for(block)
            if vouched:
                fail(f"certificate {position} of {len(held)} in tls/{PUBLIC}/{BUNDLE} could vouch "
                     f"for {', '.join(vouched)}, and {CONSTRAIN}; take it out of the file")
    for name, (cert_name, key_name) in SERVERS.items():
        directory, cert, key = base / name, base / name / cert_name, base / name / key_name
        if not (cert.is_file() and key.is_file()):
            fail(f"tls/{name}/{cert_name} or {key_name} is missing, so {name} cannot start TLS")
            continue
        if _posix():
            if mode_of(directory) & 0o077:
                fail(f"tls/{name} is mode {mode_of(directory):o}; it holds a key (700)")
            if mode_of(key) & 0o077:
                fail(f"tls/{name}/{key_name} is mode {mode_of(key):o}; a key is 600")
            if _root() and (key.stat().st_uid != 0 or directory.stat().st_uid != 0):
                fail(f"tls/{name}/{key_name} is not root's, and a server that holds no "
                     f"capability reads only a key root owns: `chown -R root:root {base}`")
        san = _san(cert)
        if san != [f"DNS:{name}"]:
            fail(f"tls/{name}/{cert_name} names {', '.join(san) or 'nothing'} rather than "
                 f"DNS:{name} alone")
        try:
            _verify(cert, bundle)
        except Refused:
            fail(f"tls/{name}/{cert_name} does not verify against tls/{PUBLIC}/{BUNDLE}")
            continue
        if _public_key(cert, of_cert=True) != _public_key(key, of_cert=False):
            fail(f"tls/{name}/{key_name} is not the key of tls/{name}/{cert_name}")
            continue
        when = _end_date(cert)
        if _ends_within(cert, WARN_DAYS):
            fail(f"{name}'s certificate ends {when}, within {WARN_DAYS} days: "
                 f"`{COMMAND} renew {name}`, then `{RESTART} {name}`")
        else:
            lines.append(f"ok: {name}'s certificate verifies, names DNS:{name} and is valid "
                         f"until {when}")
    if (base / LEGACY).is_dir():
        lines.append(f"note: tls/{LEGACY} holds the old self-signed pair for the way back; "
                     f"remove it once this release runs")
    return lines, not failed


def main(argv=None, *, out=print) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--dir", type=Path, default=TLS_DIR,
                        help="the TLS directory (default infra/production/tls)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="a new deployment: the CA and every certificate")
    sub.add_parser("migrate", help="a deployment with the old tls/public.crt and private.key")
    renew_parser = sub.add_parser("renew", help="re-issue certificates from the CA")
    renew_parser.add_argument("servers", nargs="*", metavar="SERVER")
    sub.add_parser("check", help="read the layout, change nothing")
    add = sub.add_parser("add-ca", help="trust another CA as well")
    add.add_argument("file", type=Path)
    args = parser.parse_args(argv)
    # Absolute: openssl ca runs in the staging directory, where a relative --dir names nothing.
    base = args.dir.resolve()
    # Every file this process creates is private from its first byte; each is then given its own
    # mode explicitly, so the operator's umask decides nothing.
    previous = os.umask(0o077)
    try:
        if args.command == "check":
            lines, ok = check(base)
            for line in lines:
                out(line)
            out("check passed" if ok else "check FAILED")
            return 0 if ok else 1
        if args.command == "init":
            said = init(base)
        elif args.command == "migrate":
            said = migrate(base)
        elif args.command == "renew":
            said = renew(base, args.servers)
        else:
            said = add_ca(base, args.file)
    except Refused as exc:
        out(f"refused: {exc}")
        return 1
    except OSError as exc:
        out(f"refused: cannot write under {base} ({exc.strerror or type(exc).__name__}): run "
            f"it as root, `{COMMAND} {args.command}`. Every file is written whole or not at "
            f"all, and what init or migrate had placed was taken back.")
        return 1
    finally:
        os.umask(previous)
    for line in said:
        out(line)
    return 1 if any(line.startswith("still to do:") for line in said) else 0


if __name__ == "__main__":
    sys.exit(main())

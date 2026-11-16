"""scripts/internal_tls.py: the production stack's own CA, and a certificate for each server that
terminates TLS inside the compose network.

Held here, against temporary directories and the host's openssl:

* `init` issues a CA and three leaves that openssl and Python's TLS client verify by the service
  name, each leaf naming its own service alone, and the CA's name constraints refuse a leaf for any
  other name or for an address;
* the private keys are 0600 in 0700 directories and the public directory, the one every client
  mounts, holds the bundle and no key;
* `init` replaces nothing, `migrate` takes the old self-signed pair out of the public mount and
  leaves the old layout whole when it fails part way, `renew` refuses without the CA's key,
  `add-ca` refuses a key or anything but certificates, and a certificate that could vouch for minio,
  postgres or redis (a CA whose name constraints leave one of them in, or a certificate that names one),
  since the clients take every certificate in the bundle as a trust anchor for those names; `check`
  fails a bundle already holding one, and a leaf inside its last thirty days;
* nothing printed carries a key, and the script stays runnable on a host python 3.8 with the
  standard library alone.
"""
from __future__ import annotations

import ast
import importlib.util
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "internal_tls.py"
OPENSSL = shutil.which("openssl")

pytestmark = pytest.mark.skipif(OPENSSL is None, reason="no openssl on this machine")
posix_only = pytest.mark.skipif(os.name != "posix", reason="file modes need POSIX")


def _module():
    spec = importlib.util.spec_from_file_location("internal_tls", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(*argv: str) -> tuple[int, list[str]]:
    said: list[str] = []
    status = _module().main(list(argv), out=said.append)
    for line in said:
        assert "PRIVATE KEY" not in line and "-----BEGIN" not in line, line
    return status, said


def _openssl(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([OPENSSL, *args], input=input_text, capture_output=True, text=True)


def _verifies(cert: Path, bundle: Path) -> bool:
    return _openssl("verify", "-CAfile", str(bundle), str(cert)).returncode == 0


@pytest.fixture(scope="module")
def issued(tmp_path_factory) -> Path:
    """One `init`, copied into each test that changes it."""
    base = tmp_path_factory.mktemp("issued") / "tls"
    status, said = _run("--dir", str(base), "init")
    assert status == 0, said
    return base


@pytest.fixture
def tls(issued, tmp_path) -> Path:
    copy = tmp_path / "tls"
    shutil.copytree(issued, copy)
    return copy


def _leaf(base: Path, name: str, san: str, days: int = 30) -> tuple[Path, Path]:
    """A leaf for `san`, signed by the CA under `base`, as anybody holding ca.key could make."""
    out = base.parent / f"extra-{name}"
    out.mkdir()
    key, csr, cert, config = (out / f"{name}.{ext}" for ext in ("key", "csr", "crt", "cnf"))
    config.write_text("[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = leaf\n"
                      "[v3_leaf]\nbasicConstraints = critical, CA:FALSE\n"
                      "keyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\n"
                      f"subjectAltName = {san}\nsubjectKeyIdentifier = hash\n"
                      "authorityKeyIdentifier = keyid\n", encoding="ascii")
    for args in (("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                  "-out", str(key)),
                 ("req", "-new", "-key", str(key), "-config", str(config), "-out", str(csr)),
                 ("x509", "-req", "-in", str(csr), "-CA", str(base / "ca" / "ca.crt"),
                  "-CAkey", str(base / "ca" / "ca.key"), "-set_serial", "0x7e57",
                  "-days", str(days), "-sha256", "-extfile", str(config),
                  "-extensions", "v3_leaf", "-out", str(cert))):
        done = _openssl(*args)
        assert done.returncode == 0, done.stderr
    return cert, key


def _old_layout(tmp_path: Path) -> Path:
    """The layout the README's step 3 made before this release: a self-signed MinIO pair at the top
    of tls/, by the command it printed."""
    base = tmp_path / "tls"
    base.mkdir()
    done = _openssl("req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "3650", "-nodes",
                    "-keyout", str(base / "private.key"), "-out", str(base / "public.crt"),
                    "-subj", "/CN=minio", "-addext", "subjectAltName=DNS:minio")
    if done.returncode != 0 and "/CN=minio" in done.stderr:
        pytest.skip("this openssl rewrites a leading slash")
    assert done.returncode == 0, done.stderr
    return base


# ---------------------------------------------------------------------------
# What init issues
# ---------------------------------------------------------------------------

def test_init_issues_a_chain_openssl_verifies(issued):
    bundle = issued / "public" / "ca.crt"
    for name, (cert, key) in _module().SERVERS.items():
        assert (issued / name / key).is_file(), name
        assert _verifies(issued / name / cert, bundle), name
    # The CA itself, and nothing else, is what every client trusts.
    assert bundle.read_text() == (issued / "ca" / "ca.crt").read_text()
    text = _openssl("x509", "-noout", "-text", "-in", str(bundle)).stdout
    assert "CA:TRUE, pathlen:0" in text and "Certificate Sign" in text


def test_every_leaf_names_only_its_own_service_in_its_san(issued):
    module = _module()
    for name, (cert, _key) in module.SERVERS.items():
        assert module._san(issued / name / cert) == [f"DNS:{name}"], name
        text = _openssl("x509", "-noout", "-text", "-in", str(issued / name / cert)).stdout
        assert "CA:FALSE" in text and "TLS Web Server Authentication" in text, name
        end = module._end_date(issued / name / cert)
        assert not module._ends_within(issued / name / cert, module.LEAF_DAYS - 2), end
        assert module._ends_within(issued / name / cert, module.LEAF_DAYS + 2), end


@pytest.mark.parametrize("san", ["DNS:example.org", "DNS:api", "DNS:minio.example.org",
                                 "DNS:redis, IP:10.20.30.40", "IP:172.31.243.10"])
def test_the_ca_cannot_vouch_for_another_name(tls, san):
    """The bundle reaches every client's trust store beside the system roots, and those clients
    reach the internet through the egress proxy, so a stolen ca.key must not mint a certificate
    they would accept for anything else: the name constraints permit minio, postgres and redis
    (and names below them) and exclude every address."""
    cert, _key = _leaf(tls, "other", san)
    assert not _verifies(cert, tls / "public" / "ca.crt"), san


def _handshake(cert: Path, key: Path, bundle: Path, name: str) -> str:
    """A TLS 1.3 handshake on loopback, the client built as redis-py, minio-py's urllib3 and the
    other clients build theirs (`ssl.create_default_context`, which in Python 3.13 adds
    VERIFY_X509_STRICT), checking the certificate against `name`. The version, or the error."""
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.load_cert_chain(str(cert), str(key))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve():
        conn, _ = listener.accept()
        try:
            server.wrap_socket(conn, server_side=True).recv(1)
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = ssl.create_default_context(cafile=str(bundle))
    raw = socket.create_connection(listener.getsockname(), timeout=10)
    try:
        wrapped = client.wrap_socket(raw, server_hostname=name)
        version = wrapped.version()
        wrapped.sendall(b"x")
        wrapped.close()
        return version
    except ssl.SSLError as exc:
        return f"refused: {exc.reason}"
    finally:
        raw.close()
        thread.join(5)
        listener.close()


def test_the_python_client_verifies_each_leaf_by_its_service_name_and_no_other(issued):
    bundle = issued / "public" / "ca.crt"
    for name, (cert, key) in _module().SERVERS.items():
        assert _handshake(issued / name / cert, issued / name / key, bundle, name) == "TLSv1.3"
    refused = _handshake(issued / "redis" / "server.crt", issued / "redis" / "server.key",
                         bundle, "postgres")
    assert refused.startswith("refused:"), refused


# ---------------------------------------------------------------------------
# Where the keys are, and their modes
# ---------------------------------------------------------------------------

def test_the_public_directory_holds_the_bundle_and_no_private_key(issued):
    public = issued / "public"
    assert sorted(p.name for p in public.iterdir()) == ["ca.crt"]
    assert "PRIVATE KEY" not in (public / "ca.crt").read_text()
    for name, (_cert, key) in _module().SERVERS.items():
        assert "PRIVATE KEY" in (issued / name / key).read_text(), name
    assert not list(issued.glob("*.key")) and not list(issued.glob(".staging-*"))


@posix_only
def test_private_keys_are_0600_and_directories_0700(issued):
    def mode(path):
        return path.stat().st_mode & 0o777
    assert mode(issued) == 0o755 and mode(issued / "public") == 0o755
    assert mode(issued / "public" / "ca.crt") == 0o644
    assert mode(issued / "ca") == 0o700 and mode(issued / "ca" / "ca.key") == 0o600
    for name, (cert, key) in _module().SERVERS.items():
        assert mode(issued / name) == 0o700, name
        assert mode(issued / name / key) == 0o600, name
        assert mode(issued / name / cert) == 0o644, name


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0,
                    reason="needs POSIX permissions and a user that is not root")
def test_a_run_that_is_not_root_says_minio_cannot_read_its_key(tmp_path):
    status, said = _run("--dir", str(tmp_path / "tls"), "init")
    assert status == 0
    assert any(line.startswith("note: this ran as uid") and "reads only a key root owns" in line
               for line in said), said


# ---------------------------------------------------------------------------
# init, migrate, renew and add-ca refuse what would break a running stack
# ---------------------------------------------------------------------------

def test_a_relative_dir_issues_as_an_absolute_one_does(tmp_path, monkeypatch):
    """openssl ca runs in the staging directory, so a relative --dir named a request it could not find
    and init stopped at the CA (found running the stack in WSL for TRANSPORT-01)."""
    monkeypatch.chdir(tmp_path)
    status, said = _run("--dir", "relative/tls", "init")
    assert status == 0, said
    assert _run("--dir", "relative/tls", "check")[0] == 0


def test_init_refuses_to_overwrite_a_ca(tls):
    before = {p: p.read_bytes() for p in tls.rglob("*") if p.is_file()}
    status, said = _run("--dir", str(tls), "init")
    assert status == 1 and said[0].startswith("refused:") and "ca/ca.key" in said[0]
    assert {p: p.read_bytes() for p in tls.rglob("*") if p.is_file()} == before


def test_init_on_the_old_layout_names_migrate_and_writes_nothing(tmp_path):
    base = _old_layout(tmp_path)
    status, said = _run("--dir", str(base), "init")
    assert status == 1 and "internal_tls.py migrate" in said[0]
    assert sorted(p.name for p in base.iterdir()) == ["private.key", "public.crt"]


def test_migrate_moves_the_key_out_of_the_public_mount_and_reissues_minio(tmp_path):
    """The old layout mounted tls/ whole, MinIO's private.key with it, into every application
    container. After the migration tls/ holds no key at its top, the public directory the clients
    mount holds the bundle alone, MinIO's new certificate verifies against it, and the old
    certificate does not: `openssl req -x509` made it CA:TRUE with no name constraint, so trusting
    it would let MinIO's old key vouch for any name. The old pair is kept, mounted nowhere."""
    base = _old_layout(tmp_path)
    old_cert = (base / "public.crt").read_bytes()
    old_key = (base / "private.key").read_bytes()
    status, said = _run("--dir", str(base), "migrate")
    assert status == 0, said
    assert not (base / "private.key").exists() and not (base / "public.crt").exists()
    assert sorted(p.name for p in (base / "public").iterdir()) == ["ca.crt"]
    assert (base / "legacy-minio" / "public.crt").read_bytes() == old_cert
    assert (base / "legacy-minio" / "private.key").read_bytes() == old_key
    bundle = base / "public" / "ca.crt"
    assert _verifies(base / "minio" / "public.crt", bundle)
    assert (base / "minio" / "public.crt").read_bytes() != old_cert
    assert not _verifies(base / "legacy-minio" / "public.crt", bundle)
    assert "CA:TRUE" in _openssl("x509", "-noout", "-text", "-in",
                                 str(base / "legacy-minio" / "public.crt")).stdout
    status, lines = _run("--dir", str(base), "check")
    assert status == 0, lines


def test_migrate_failure_part_way_leaves_the_old_layout(tmp_path, monkeypatch):
    base = _old_layout(tmp_path)
    before = {p.name: p.read_bytes() for p in base.iterdir()}
    module = _module()
    real = module._issue_leaf

    def fails_at_redis(staging, name, *args, **kwargs):
        if name == "redis":
            raise module.Refused("openssl x509 failed (a stand-in failure).")
        return real(staging, name, *args, **kwargs)

    monkeypatch.setattr(module, "_issue_leaf", fails_at_redis)
    said: list[str] = []
    assert module.main(["--dir", str(base), "migrate"], out=said.append) == 1
    assert said[0].startswith("refused: openssl x509 failed"), said
    assert {p.name: p.read_bytes() for p in base.iterdir() if p.is_file()} == before
    assert not [p for p in base.rglob("*") if p.is_file() and p.parent != base]
    monkeypatch.undo()
    status, said = _run("--dir", str(base), "migrate")
    assert status == 0, said


def test_renew_refuses_when_the_ca_key_is_absent(tls):
    (tls / "ca" / "ca.key").unlink()
    before = (tls / "redis" / "server.crt").read_bytes()
    status, said = _run("--dir", str(tls), "renew", "redis")
    assert status == 1
    assert "ca/ca.key is not on this host" in said[0] and "copy it back to" in said[0]
    assert (tls / "redis" / "server.crt").read_bytes() == before


def test_renew_issues_a_new_key_and_certificate_the_bundle_still_trusts(tls):
    old_cert = (tls / "postgres" / "server.crt").read_bytes()
    old_key = (tls / "postgres" / "server.key").read_bytes()
    untouched = (tls / "redis" / "server.crt").read_bytes()
    status, said = _run("--dir", str(tls), "renew", "postgres")
    assert status == 0, said
    assert said[0].startswith("renewed postgres's certificate: valid until ")
    assert "restart postgres" in said[0]
    assert (tls / "postgres" / "server.crt").read_bytes() != old_cert
    assert (tls / "postgres" / "server.key").read_bytes() != old_key
    assert (tls / "redis" / "server.crt").read_bytes() == untouched
    assert _run("--dir", str(tls), "check")[0] == 0


def test_renew_refuses_a_name_that_is_not_a_server(tls):
    status, said = _run("--dir", str(tls), "renew", "caddy")
    assert status == 1 and "caddy is not one of minio, postgres, redis" in said[0]


@pytest.mark.parametrize("text", [
    "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
    "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
    "not a certificate at all\n",
])
def test_add_ca_refuses_a_key_or_a_non_certificate(tls, tmp_path, text):
    source = tmp_path / "offered.pem"
    source.write_text(text, encoding="ascii")
    before = (tls / "public" / "ca.crt").read_bytes()
    status, said = _run("--dir", str(tls), "add-ca", str(source))
    assert status == 1 and said[0].startswith("refused:"), said
    assert (tls / "public" / "ca.crt").read_bytes() == before


def test_add_ca_refuses_a_certificate_beside_a_key(tls, issued, tmp_path):
    source = tmp_path / "pair.pem"
    source.write_text((issued / "redis" / "server.crt").read_text()
                      + (issued / "redis" / "server.key").read_text(), encoding="ascii")
    status, said = _run("--dir", str(tls), "add-ca", str(source))
    assert status == 1 and "holds a private key" in said[0]


def test_add_ca_appends_another_ca_once(tls, tmp_path):
    other = tmp_path / "agency"
    other.mkdir()
    _agency_ca(other, "basicConstraints = critical, CA:TRUE\n"
                      "nameConstraints = critical, permitted;DNS:.agency.example\n")
    status, said = _run("--dir", str(tls), "add-ca", str(other / "ca.pem"))
    assert status == 0 and said[0].startswith("added 1 certificate from ca.pem"), said
    bundle = (tls / "public" / "ca.crt").read_text()
    assert bundle.count("BEGIN CERTIFICATE") == 2 and "PRIVATE KEY" not in bundle
    status, said = _run("--dir", str(tls), "add-ca", str(other / "ca.pem"))
    assert status == 0 and said[0].startswith("nothing to change")
    assert (tls / "public" / "ca.crt").read_text() == bundle
    assert _run("--dir", str(tls), "check")[0] == 0


def _config(directory: Path, extensions: str = "") -> Path:
    path = directory / "req.cnf"
    path.write_text("[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = Agency CA\n"
                    + (f"[ext]\n{extensions}" if extensions else ""), encoding="ascii")
    return path


def _agency_ca(directory: Path, extensions: str) -> Path:
    """A self-signed certificate with `extensions`, as an agency's CA (or a server's own) is made:
    ca.pem and its key k.pem in `directory`."""
    done = _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-days", "30", "-keyout", str(directory / "k.pem"),
                    "-out", str(directory / "ca.pem"),
                    "-config", str(_config(directory, extensions)), "-extensions", "ext")
    assert done.returncode == 0, done.stderr
    return directory / "ca.pem"


def _issued_by(directory: Path, san: str) -> Path:
    """A server certificate for `san` signed by the CA in `directory`, as whoever holds its key
    could make one."""
    key, csr, cert, config = (directory / f"leaf.{ext}" for ext in ("key", "csr", "crt", "cnf"))
    config.write_text("[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = leaf\n"
                      "[v3_leaf]\nbasicConstraints = critical, CA:FALSE\n"
                      "keyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\n"
                      f"subjectAltName = {san}\nsubjectKeyIdentifier = hash\n"
                      "authorityKeyIdentifier = keyid\n", encoding="ascii")
    for args in (("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                  "-out", str(key)),
                 ("req", "-new", "-key", str(key), "-config", str(config), "-out", str(csr)),
                 ("x509", "-req", "-in", str(csr), "-CA", str(directory / "ca.pem"),
                  "-CAkey", str(directory / "k.pem"), "-set_serial", "0x7e58", "-days", "30",
                  "-sha256", "-extfile", str(config), "-extensions", "v3_leaf",
                  "-out", str(cert))):
        done = _openssl(*args)
        assert done.returncode == 0, done.stderr
    return cert


#: A CA as an agency makes one, with no name constraints.
UNCONSTRAINED = ("basicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign\n"
                 "subjectKeyIdentifier = hash\n")


def test_a_second_ca_in_the_bundle_is_not_bound_by_the_deployment_cas_constraints(tls, tmp_path):
    """the independent review TRANSPORT-03's premise, run: the deployment CA's name constraints bind its own signatures
    alone, so a CA appended to the bundle as add-ca appended one signs a certificate for DNS:postgres
    that verifies against the very file every DSN names as sslrootcert, and Python's client (redis-py's
    and the store client's) completes a handshake with it as `postgres`."""
    agency = tmp_path / "agency"
    agency.mkdir()
    _agency_ca(agency, UNCONSTRAINED)
    bundle = tmp_path / "bundle.crt"
    bundle.write_text((tls / "public" / "ca.crt").read_text() + (agency / "ca.pem").read_text(),
                      encoding="ascii")
    forged = _issued_by(agency, "DNS:postgres")
    assert _verifies(forged, bundle)
    assert _handshake(forged, agency / "leaf.key", bundle, "postgres") == "TLSv1.3"


@pytest.mark.parametrize("extensions, vouched", [
    (UNCONSTRAINED, "minio, postgres, redis"),
    # Constraints of another type leave DNS names unconstrained.
    (UNCONSTRAINED + "nameConstraints = critical, permitted;IP:10.0.0.0/255.0.0.0\n",
     "minio, postgres, redis"),
    (UNCONSTRAINED + "nameConstraints = critical, excluded;DNS:postgres\n", "minio, redis"),
    (UNCONSTRAINED + "nameConstraints = critical, permitted;DNS:redis\n", "redis"),
    # A base with no leading dot covers the name itself.
    (UNCONSTRAINED + "nameConstraints = critical, permitted;DNS:minio, permitted;DNS:.agency.example\n",
     "minio"),
    ("basicConstraints = critical, CA:FALSE\nsubjectAltName = DNS:relay.agency.example, DNS:Postgres\n",
     "postgres"),
])
def test_add_ca_refuses_a_certificate_that_could_vouch_for_an_internal_server(
        tls, tmp_path, extensions, vouched):
    agency = tmp_path / "agency"
    agency.mkdir()
    source = _agency_ca(agency, extensions)
    before = (tls / "public" / "ca.crt").read_bytes()
    status, said = _run("--dir", str(tls), "add-ca", str(source))
    assert status == 1, said
    assert said[0].startswith(f"refused: certificate 1 of 1 in ca.pem could vouch for {vouched}, "
                              f"and the database, Redis and object store clients trust"), said
    assert "excluded;DNS:postgres" in said[0] and said[0].endswith("Nothing was written.")
    assert (tls / "public" / "ca.crt").read_bytes() == before


@pytest.mark.parametrize("extensions", [
    UNCONSTRAINED + "nameConstraints = critical, permitted;DNS:.agency.example\n",
    UNCONSTRAINED + "nameConstraints = critical, permitted;DNS:agency.example, permitted;IP:10.0.0.0/255.0.0.0\n",
    UNCONSTRAINED + ("nameConstraints = critical, excluded;DNS:postgres, excluded;DNS:redis, "
                     "excluded;DNS:minio\n"),
    # Its own names alone, none of them an internal server's.
    "basicConstraints = critical, CA:FALSE\nsubjectAltName = DNS:relay.agency.example\n",
])
def test_add_ca_takes_a_certificate_that_leaves_the_internal_servers_out(tls, tmp_path, extensions):
    agency = tmp_path / "agency"
    agency.mkdir()
    source = _agency_ca(agency, extensions)
    status, said = _run("--dir", str(tls), "add-ca", str(source))
    assert status == 0 and said[0].startswith("added 1 certificate from ca.pem"), said
    assert _run("--dir", str(tls), "check")[0] == 0


def test_what_add_ca_takes_cannot_answer_as_an_internal_server(tls, tmp_path):
    """The other half of the reading: what passes is what OpenSSL and the Python client refuse."""
    agency = tmp_path / "agency"
    agency.mkdir()
    _agency_ca(agency, UNCONSTRAINED + ("nameConstraints = critical, excluded;DNS:postgres, "
                                        "excluded;DNS:redis, excluded;DNS:minio\n"))
    assert _run("--dir", str(tls), "add-ca", str(agency / "ca.pem"))[0] == 0
    bundle = tls / "public" / "ca.crt"
    forged = _issued_by(agency, "DNS:postgres")
    assert not _verifies(forged, bundle)
    assert _handshake(forged, agency / "leaf.key", bundle, "postgres").startswith("refused:")


def test_check_fails_a_bundle_that_already_holds_such_a_certificate(tls, tmp_path):
    """A bundle an earlier add-ca grew, before it asked."""
    agency = tmp_path / "agency"
    agency.mkdir()
    _agency_ca(agency, UNCONSTRAINED)
    bundle = tls / "public" / "ca.crt"
    bundle.write_text(bundle.read_text() + (agency / "ca.pem").read_text(), encoding="ascii")
    status, lines = _run("--dir", str(tls), "check")
    assert status == 1
    failed = [line for line in lines if line.startswith("FAILED: certificate 2 of 2 in tls/public")]
    assert len(failed) == 1 and "could vouch for minio, postgres, redis" in failed[0], lines
    assert lines[-1] == "check FAILED"


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def test_check_passes_a_fresh_layout_and_names_every_certificates_end(issued):
    status, lines = _run("--dir", str(issued), "check")
    assert status == 0 and lines[-1] == "check passed", lines
    for name in ("minio", "postgres", "redis"):
        assert any(line.startswith(f"ok: {name}'s certificate verifies, names DNS:{name}")
                   for line in lines), name
    assert any(line.startswith("ok: the CA is valid until") for line in lines)


def test_check_fails_inside_thirty_days_of_expiry(tls):
    cert, key = _leaf(tls, "redis", "DNS:redis", days=10)
    shutil.copyfile(cert, tls / "redis" / "server.crt")
    shutil.copyfile(key, tls / "redis" / "server.key")
    status, lines = _run("--dir", str(tls), "check")
    assert status == 1 and lines[-1] == "check FAILED"
    assert any(line.startswith("FAILED: redis's certificate ends") and "within 30 days" in line
               and "renew redis" in line for line in lines), lines


def test_check_fails_a_key_in_the_public_directory(tls):
    shutil.copyfile(tls / "minio" / "private.key", tls / "public" / "stray.pem")
    status, lines = _run("--dir", str(tls), "check")
    assert status == 1
    assert any("public/stray.pem holds a private key" in line for line in lines), lines


def test_check_fails_a_leaf_for_the_wrong_name_or_a_key_that_is_not_its_own(tls):
    cert, _key = _leaf(tls, "wrong", "DNS:postgres")
    shutil.copyfile(cert, tls / "redis" / "server.crt")
    status, lines = _run("--dir", str(tls), "check")
    assert status == 1
    assert any("redis/server.crt names DNS:postgres rather than DNS:redis alone" in line
               for line in lines), lines
    assert any("redis/server.key is not the key of" in line for line in lines), lines


def test_check_fails_the_old_layouts_key_left_at_the_top(tls, issued):
    shutil.copyfile(issued / "minio" / "private.key", tls / "private.key")
    status, lines = _run("--dir", str(tls), "check")
    assert status == 1 and any("tls/private.key is still there" in line for line in lines)


@posix_only
def test_check_fails_a_key_any_other_user_can_read(tls):
    os.chmod(tls / "postgres" / "server.key", 0o644)
    os.chmod(tls / "public", 0o777)
    status, lines = _run("--dir", str(tls), "check")
    assert status == 1
    assert any("postgres/server.key is mode 644" in line for line in lines), lines
    assert any("tls/public is mode 777" in line for line in lines), lines


# ---------------------------------------------------------------------------
# A host python, no virtual environment
# ---------------------------------------------------------------------------

def test_the_script_is_python_3_8_and_the_standard_library_alone():
    """README step 3 runs it with the host's python3, 3.8 or later, as the installer step runs
    scripts/production_secrets.py: no third-party import and no syntax newer than 3.8."""
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source, feature_version=(3, 8))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= set(sys.stdlib_module_names), imported - set(sys.stdlib_module_names)
    assert "shell=True" not in source
    assert source.isascii()

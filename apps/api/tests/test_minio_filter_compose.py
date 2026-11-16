"""The unsigned-trailer refusal in front of the bundled MinIO.

The pinned community build lets a caller who knows only an access key write
an object through STREAMING-UNSIGNED-PAYLOAD-TRAILER (GHSA-hv4r-mvr4-25vw,
GHSA-9c4q-hq6p-c237). Caddy shares MinIO's network namespace and is the
only listener on 9000 and 9001; MinIO itself binds loopback. Pure: no
Docker.
"""
from __future__ import annotations

from pathlib import Path

from test_egress_topology import Reader

ROOT = Path(__file__).resolve().parents[3]
PRODUCTION = ROOT / "infra" / "production"
PROD_COMPOSE = PRODUCTION / "compose.yml"
DEV_COMPOSE = ROOT / "infra" / "docker-compose.yml"
PROD_CADDY = PRODUCTION / "minio-filter.Caddyfile"
DEV_CADDY = ROOT / "infra" / "minio-filter-dev.Caddyfile"
CADDY_IMAGE = (
    "caddy:2-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648"
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _services(path: Path) -> dict:
    return Reader(_text(path)).document()["services"]


def test_minio_binds_only_loopback_in_production():
    script = _services(PROD_COMPOSE)["minio"]["entrypoint"][-1]
    assert "--address 127.0.0.1:19000" in script
    assert "--console-address 127.0.0.1:19001" in script
    assert '--console-address ":9001"' not in script


def test_minio_binds_only_loopback_in_development():
    command = _services(DEV_COMPOSE)["minio"]["command"]
    assert "--address 127.0.0.1:19000" in command
    assert "--console-address 127.0.0.1:19001" in command


def test_the_filter_shares_minios_network_namespace():
    for path, caddyfile in ((PROD_COMPOSE, "./minio-filter.Caddyfile"),
                            (DEV_COMPOSE, "./minio-filter-dev.Caddyfile")):
        services = _services(path)
        filt = services["minio-filter"]
        assert filt["network_mode"] == "service:minio", path
        assert filt["depends_on"] == ["minio"], path
        assert filt["image"] == CADDY_IMAGE, path
        assert filt.get("cap_drop") == ["ALL"], path
        assert "no-new-privileges:true" in filt.get("security_opt", []), path
        assert filt.get("read_only") is True, path
        assert caddyfile + ":/etc/caddy/Caddyfile:ro" in filt["volumes"], path
        # Publishing stays on the minio service, whose ports now reach the filter.
        assert "ports" not in filt, path
        assert "networks" not in filt, path
        assert services["minio-init"]["depends_on"] == ["minio", "minio-filter"], path


def test_the_filter_reuses_the_public_terminators_image():
    prod = _services(PROD_COMPOSE)
    assert prod["minio-filter"]["image"] == prod["caddy"]["image"] == CADDY_IMAGE


def test_production_caddyfile_refuses_the_unsigned_trailer_over_tls():
    text = _text(PROD_CADDY)
    assert "auto_https off" in text
    assert "protocols h1 h2" in text
    assert "STREAMING-UNSIGNED-PAYLOAD-TRAILER" in text
    assert "header X-Amz-Content-Sha256 STREAMING-UNSIGNED-PAYLOAD-TRAILER" in text
    assert "respond 403" in text
    assert "tls /certs/public.crt /certs/private.key" in text
    assert "protocols tls1.3" in text
    assert "reverse_proxy 127.0.0.1:19000" in text
    assert "reverse_proxy 127.0.0.1:19001" in text
    # The console is proxied but the trailer match lives in the API site only.
    api, _, console = text.partition(":9001")
    assert "@unsigned_trailer" in api
    assert "@unsigned_trailer" not in console


def test_development_caddyfile_refuses_the_unsigned_trailer_over_http():
    text = _text(DEV_CADDY)
    assert "auto_https off" in text
    assert "STREAMING-UNSIGNED-PAYLOAD-TRAILER" in text
    assert "respond 403" in text
    assert "reverse_proxy 127.0.0.1:19000" in text
    assert "tls " not in text
    api, _, console = text.partition(":9001")
    assert "@unsigned_trailer" in api
    assert "@unsigned_trailer" not in console


def test_production_filter_mounts_minios_certificate_as_certs():
    filt = _services(PROD_COMPOSE)["minio-filter"]
    assert "./tls/minio:/certs:ro" in filt["volumes"]
    assert "./minio-filter.Caddyfile:/etc/caddy/Caddyfile:ro" in filt["volumes"]

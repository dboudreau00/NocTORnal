# The image every NocTORnal process runs from. ONE image, ten services: the API, the sample origin,
# the Alembic migration job, the cron loop, the collector, the analysis worker, the Lab's triage, cron
# and embedding loops and the egress proxy (`python -m noctornal_api.egress_proxy`) are the same code
# started differently (infra/production/compose.yml). One image is the architecture (CONVENTIONS,
# decision 30: no task-queue worker); two would be two dependency sets that can drift.
FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285

# Pinned by digest, since a tag is whatever its registry says at pull time; the tag stays for the
# reader. The base does not pick up Debian security updates by itself: move the digest when you
# take a release and build with --pull (infra/production/README.md, Hardening). 3.13 because CI
# pins it. `slim`, not `alpine`: every compiled dependency ships manylinux wheels, and psycopg's
# `[binary]` is glibc-only, so on musl the driver would have to be built against libpq.

# No build toolchain, on purpose: a `pip install` below that starts compiling means a dependency
# stopped shipping a wheel for this platform, to fix upstream or by adding the toolchain
# deliberately. In the extras, Telethon's pyaes is a pure-Python sdist that pip builds with no
# compiler, and yara-x, which the image carries by default, needs glibc 2.28, which this Debian 13
# base (glibc 2.41) has.

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# gnupg for PGP verification. The distribution's build reports a version below the floor the
# verifier enforces, so a deployment attests it with NOCTORNAL_GPG_PATCHED_AS once it has checked
# the changelog carries the fixes; until then every check records NO_VERIFIER and pgp_verifier
# says why. No recommends: no agent, no pinentry.
#
# Pinned to one Debian version, so the gpg a deployment attests is the one its image carries and
# not whatever Debian shipped on the day of the build. gnupg holds gpg, gpg-agent, dirmngr and
# gpgsm to its own source upload, and the two checks after the install say both are that upload.
# Debian removes a superseded version from its archive, so when a security update to gnupg2 lands
# this build fails until the pin moves: that is the signal, and CI's image job shows it first.
# Not snapshot.debian.org, which would also freeze libgcrypt and every other library at that day,
# unpatched. To move it: take the version `apt-cache madison gnupg` prints inside the base image
# (move the base digest at the same time), write it here, and build with --pull.
# ca-certificates is upgraded in the same layer. The slim base is pinned by digest
# (2026-10-03) and therefore still ships the bundle that contained the compromised
# emSign ECC Root CA - G3; Debian DSA-6572-1 removed it in 20250419+deb13u1
# (2026-10-20). Production builds SSL_CERT_FILE from this file, and the pinned
# HTTP client uses the platform store, so a stale bundle would trust a cert a
# compromised intermediate minted. Same pin style as gnupg: a superseded version
# leaving the archive fails the build until the pin moves.
ARG GNUPG_VERSION=2.4.7-21+deb13u1
ARG CACERTS_VERSION=20250419+deb13u1
RUN apt-get update \
    && apt-get install -y --no-install-recommends "gnupg=${GNUPG_VERSION}" \
        "ca-certificates=${CACERTS_VERSION}" \
    && test "$(dpkg-query -W -f='${Version}' gnupg)" = "${GNUPG_VERSION}" \
    && test "$(dpkg-query -W -f='${source:Version}' gpg)" = "${GNUPG_VERSION}" \
    && test "$(dpkg-query -W -f='${Version}' ca-certificates)" = "${CACERTS_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

# PYTHONUNBUFFERED: stdout is the cron loop's only channel to its operator, and block-buffered
# it shows nothing in `docker logs` for hours, which reads as a hung job.
# PYTHONDONTWRITEBYTECODE: /app is root-owned and the process is not root, so every
# __pycache__ write would fail anyway.

# /app is the repository root, which three things depend on: `alembic.ini`'s
# `script_location = db/migrations` is relative to the working directory;
# `readiness._MIGRATIONS_DIR` is `Path(__file__).parents[4]/db/migrations`, so the install below
# is editable; and `scripts/_env.py` looks for `.env.local` beside `scripts/`, of which the image
# has none (.dockerignore), the environment coming from compose.
WORKDIR /app

# The whole tree in one COPY, filtered by .dockerignore. No dependency-layer caching: every scheme
# for it puts a second declaration of the dependency set in the image that can fall behind
# apps/api/pyproject.toml, and a slow rebuild is cheaper than an image running an old library.
COPY . /app

# Editable, which is a correctness requirement: under a normal install `readiness._MIGRATIONS_DIR`
# would resolve under /usr/local/lib and report a migrated deployment as broken, and setuptools
# would drop noctornal_api/http/static/ (pyproject.toml declares no package data), so /ui would
# 404. Both workspace packages, in dependency order: noctornal-api imports noctornal_ontology at
# startup. `-c constraints.txt` pins the versions the release's suite passed on, as the
# installers and CI do; it adds no dependency of its own.
#
# NOCTORNAL_EXTRAS is "telegram", "yara" or both, and "yara" by default: the analysis worker runs
# this image, and without yara-x it scans no sample with a rule, so the image a plain build makes
# is the one that scans. An empty value is the one way to an image without it; telegram stays
# opt-in. Any other value is refused before pip runs: a typo would build an image without the
# extra and say nothing, and the value is interpolated into a pip argument, which only a closed
# list may be.
#
# Hashed installs first, then the two editable trees with --no-deps: an
# editable install cannot itself be hash-checked, and --require-hashes cannot
# be combined with one. constraints.txt cannot carry the hashes: pip does not
# apply them there. It still pins the versions, and every pip install keeps
# `-c constraints.txt`.
#
# With yara, yara-x is installed first from requirements-yara.txt, by the sha256 of its wheel, and
# the editable install after it finds the pin already satisfied, so the wheel in the image is the
# hashed one. The rest of the closure is requirements-lock.txt; the telegram extra adds
# requirements-telegram.txt.
#
# The final `find`: COPY keeps the build context's modes, and a checkout made under umask 077
# holds 0600 files and 0700 directories, which uid 10001 could not read under root-owned /app.
# It chmods only what is not already world-readable, so a normal context adds no layer weight.
ARG NOCTORNAL_EXTRAS="yara"
RUN case "$NOCTORNAL_EXTRAS" in \
      ""|telegram|yara|telegram,yara|yara,telegram) ;; \
      *) echo "NOCTORNAL_EXTRAS may name telegram and yara only" >&2; exit 1 ;; \
    esac \
    && case ",$NOCTORNAL_EXTRAS," in \
      *,yara,*) pip install --no-cache-dir --require-hashes --only-binary=:all: --no-deps \
                -c constraints.txt -r requirements-yara.txt ;; \
    esac \
    && pip install --no-cache-dir --require-hashes -c constraints.txt -r requirements-lock.txt \
    && case ",$NOCTORNAL_EXTRAS," in \
      *,telegram,*) pip install --no-cache-dir --require-hashes -c constraints.txt \
                -r requirements-telegram.txt ;; \
    esac \
    && pip install --no-cache-dir --no-deps -c constraints.txt -e packages/ontology \
       -e "apps/api${NOCTORNAL_EXTRAS:+[$NOCTORNAL_EXTRAS]}" \
    && find /app \( -type f ! -perm -o=r -o -type d ! -perm -o=rx \) -exec chmod go+rX {} +

# An unprivileged account, with no login shell and no home directory. /app stays root-owned: the
# application never writes its own source tree, so a runtime user that cannot modify its code
# costs nothing and denies an RCE its most useful next step. The uid and gid are pinned because
# the kernel checks the number and a base-image update may renumber its accounts; `--system`
# would allocate below 999 and warn at 10001.
RUN groupadd --gid 10001 noctornal \
    && useradd --uid 10001 --gid 10001 --no-create-home \
       --shell /usr/sbin/nologin noctornal
USER 10001:10001

EXPOSE 8000

# `python -c` because slim ships neither curl nor wget. /healthz is the one path the auth
# middleware lets through unauthenticated, and carries no version. `urlopen` raises on any 4xx or
# 5xx and when nothing listens, so the exit status is the check. Every container built from this
# image inherits the HEALTHCHECK, so the migration job and the cron loop, which serve no HTTP,
# disable it in compose.yml; otherwise they would sit `unhealthy` and block `service_healthy`.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", \
         "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"]

# 0.0.0.0 because the only route to this port is the compose network: nothing publishes 8000 to
# the host (infra/production/compose.yml). The production command adds workers and the
# proxy-header settings; this default is for `docker run` on the image alone, single-process.
CMD ["uvicorn", "noctornal_api.http.app:app", "--host", "0.0.0.0", "--port", "8000", "--ws-max-size", "8192"]

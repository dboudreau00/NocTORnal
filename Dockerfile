# The image every NocTORnal process runs from. ONE image, four commands:
# the API, the sample origin, the Alembic migration job and the cron loop
# are the same code started differently (infra/production/compose.yml).
#
# That is not a packaging convenience, it is the architecture. CONVENTIONS
# says "one process" and decision 30 says there is no worker: the sample
# origin is the same FastAPI application with a different
# NOCTORNAL_PUBLIC_ORIGIN, and the cron loop is `python scripts/...`. Two
# images would be two dependency sets that can drift, and the first
# symptom of that drift would be a notification drain that imports a
# module the API has moved.
FROM python:3.13-slim

# 3.13 because CI pins PYTHON_VERSION 3.13 and the suite is proven there.
#
# `slim` and NOT `alpine`. Every compiled dependency here (psycopg[binary],
# cryptography, argon2-cffi, blake3, python-igraph, leidenalg) ships
# manylinux wheels; on musl the picture is mixed and it only has to fail
# once. psycopg is the one that settles it -- its `[binary]` distribution
# is glibc-only by policy, so on alpine that extra resolves to nothing and
# the database driver has to be built against libpq. Assume the others
# would each need checking on every upgrade rather than that they are
# fine, because the failure is a build that starts invoking a compiler
# nobody installed.

# No build toolchain is installed on purpose. If a `pip install` step below
# ever starts compiling, that is the signal that a dependency stopped
# shipping a wheel for this platform -- fix that upstream or add the
# toolchain deliberately, rather than discovering it as a five-minute build.

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# PYTHONUNBUFFERED: the cron loop's only channel back to its operator is
# stdout (scripts/notify_drain.py prints its counters and exits non-zero on
# a failed delivery). Block-buffered stdout on a pipe means `docker logs`
# shows nothing for hours and then a burst, which reads as a hung job.
#
# PYTHONDONTWRITEBYTECODE: /app is root-owned and the process is not root,
# so every import would attempt a __pycache__ write, fail, and silently
# fall back. Not writing is the same outcome without the syscalls.

# /app IS the repository root, and three things depend on that literally:
#
#   * `alembic.ini` sets `script_location = db/migrations`, relative to the
#     working directory. The migration job runs `alembic upgrade head` from
#     here or it finds no scripts.
#   * `readiness._MIGRATIONS_DIR` resolves `Path(__file__).parents[4]/db/
#     migrations` -- four levels up from
#     apps/api/src/noctornal_api/readiness.py. That arithmetic only lands
#     on a repository root, which is why the install below is EDITABLE.
#   * `scripts/_env.py` looks for `.env.local` at the parent of `scripts/`.
#     There is deliberately none in the image (see .dockerignore); the
#     production environment comes from compose.
WORKDIR /app

# The whole tree in one COPY, filtered by .dockerignore.
#
# No dependency-layer caching, deliberately. Every scheme for it (a
# skeleton pyproject, a generated requirements.txt) puts a SECOND
# declaration of the dependency set in the image that can silently fall
# behind apps/api/pyproject.toml -- and the failure mode is an image that
# builds fast and runs an old library. A slow rebuild is the cheaper
# mistake.
COPY . /app

# EDITABLE, and this is a correctness requirement rather than a
# development habit. Two things break under a normal install:
#
#   * `readiness._MIGRATIONS_DIR` (above) would resolve to
#     /usr/local/lib/db/migrations, so the migrations_at_head check would
#     report "migration scripts not found" on a correctly migrated
#     deployment -- a working system reported as broken, which is exactly
#     the defect readiness.py exists to prevent.
#   * apps/api/pyproject.toml declares no `package-data` and no
#     `include-package-data`, so setuptools would drop
#     noctornal_api/http/static/ from the wheel. The console at /ui would
#     404 with nothing in any log to say why.
#
# Fixing either of those in pyproject.toml is another workstream's file, so
# the image is built to match the code as it stands.
#
# Both workspace packages, in dependency order: noctornal-api imports
# noctornal_ontology at startup (the selector normalisers).
RUN pip install --no-cache-dir -e packages/ontology -e apps/api

# An unprivileged account: no login shell, and no home directory of its own
# to write to.
#
# /app stays ROOT-OWNED and is never chowned: nothing in this application
# writes to its own source tree at runtime (evidence goes to MinIO, state
# goes to Postgres, .pyc writes are off above), so a runtime user that
# cannot modify the code it is executing costs nothing and removes the
# most useful thing an RCE could do next.
#
# The uid and gid are pinned rather than left to useradd. A named user is
# for a human reading `ps`; the NUMBER is what the kernel checks against
# file ownership, and pinning it is what makes an ownership decision here
# still mean the same thing after a base-image update renumbers its
# accounts. `--system` is deliberately not used: it allocates below
# SYS_UID_MAX (999) and warns when given a uid above it.
RUN groupadd --gid 10001 noctornal \
    && useradd --uid 10001 --gid 10001 --no-create-home \
       --shell /usr/sbin/nologin noctornal
USER 10001:10001

EXPOSE 8000

# `python -c` rather than curl or wget, because slim ships neither and the
# interpreter is already here. /healthz is the one path the auth middleware
# lets through unauthenticated (http/app.py), returns `{"status": "ok"}`,
# and deliberately carries no version for an unauthenticated caller.
#
# No explicit status comparison: `urlopen` raises HTTPError on any 4xx or
# 5xx and URLError when nothing is listening, and an uncaught exception
# exits non-zero. Testing the status as well would be a second statement of
# the same rule, and a longer one than the line has room for.
#
# TRAP for anyone reading compose.yml next to this: a HEALTHCHECK is
# inherited by EVERY container built from this image, including the ones
# that serve no HTTP at all. The migration job and the cron loop would sit
# permanently `unhealthy` -- and a `depends_on: service_healthy` elsewhere
# would then wait for a container that is never going to answer. Those two
# services disable it explicitly; that is why.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", \
         "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"]

# 0.0.0.0 because the only route to this port is the compose network --
# nothing publishes 8000 to the host (infra/production/compose.yml). The
# production command adds workers and the proxy-header settings; this
# default exists so `docker run` on the image alone does something
# sensible and single-process.
CMD ["uvicorn", "noctornal_api.http.app:app", "--host", "0.0.0.0", "--port", "8000"]

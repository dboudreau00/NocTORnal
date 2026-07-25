#!/usr/bin/env bash
# Starts the whole NocTORnal development stack: Docker services, database
# migrations, then the API. The POSIX counterpart of scripts/launch.ps1 for
# macOS and Linux; the Windows script is the one that gets exercised daily.
#
# One command, in order: Docker engine -> compose stack -> TOTP key ->
# environment -> migrations -> first-user check -> API. Safe to re-run; every
# step is idempotent and reports what it found rather than assuming.
#
# Usage:  ./scripts/launch.sh [--skip-docker] [--port 8000]

set -euo pipefail

SKIP_DOCKER=0
PORT=8000

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-docker) SKIP_DOCKER=1; shift ;;
    --port)        PORT="${2:?--port needs a number}"; shift 2 ;;
    --port=*)      PORT="${1#*=}"; shift ;;
    -h|--help)     sed -n '2,12p' "$0"; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/infra/docker-compose.yml"
PYTHON="$REPO_ROOT/.venv/bin/python"
ALEMBIC="$REPO_ROOT/.venv/bin/alembic"
ENV_LOCAL="$REPO_ROOT/.env.local"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

STEP=0
step()   { STEP=$((STEP + 1)); printf '\n[%d] %s\n' "$STEP" "$1"; }
detail() { printf '    %s\n' "$1"; }
good()   { printf '    %s\n' "$1"; }
note()   { printf '    %s\n' "$1"; }

fail() {
  printf '\n  FAILED: %s\n' "$1" >&2
  shift
  if [ $# -gt 0 ]; then
    printf '\n  What to do:\n' >&2
    for line in "$@"; do printf '    %s\n' "$line" >&2; done
  fi
  printf '\n' >&2
  exit 1
}

indent() { sed 's/^/    | /'; }

printf '\n  NocTORnal - launching the development stack\n'
printf '  repo: %s\n' "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Step 0: preflight. Fail here rather than three minutes into Docker.
# ---------------------------------------------------------------------------

step 'Checking the Python environment'

if [ ! -x "$PYTHON" ]; then
  fail "no virtual environment at $REPO_ROOT/.venv" \
    'Create it and install the packages, from the repo root:' \
    '  python3 -m venv .venv' \
    '  .venv/bin/python -m pip install -r db/requirements.txt' \
    '  .venv/bin/python -m pip install -e packages/ontology -e apps/api'
fi

# uvicorn and the two editable packages are what the last step actually needs.
if ! probe="$("$PYTHON" -c 'import uvicorn, alembic, noctornal_api, noctornal_ontology, igraph, leidenalg' 2>&1)"; then
  printf '%s\n' "$probe" | indent
  fail 'the virtual environment is missing packages the API needs' \
    'Install them, from the repo root:' \
    '  .venv/bin/python -m pip install -r db/requirements.txt' \
    '  .venv/bin/python -m pip install -e packages/ontology -e apps/api' \
    '' \
    'Then run this script again.'
fi
good 'virtual environment ready'

# ---------------------------------------------------------------------------
# Step a: the Docker engine
# ---------------------------------------------------------------------------

step 'Checking Docker'

if [ "$SKIP_DOCKER" -eq 1 ]; then
  detail 'skipped (--skip-docker); assuming the compose stack is already up'
else
  command -v docker >/dev/null 2>&1 || fail 'the docker command was not found' \
    'Install Docker Desktop or the Docker engine, then run this script again:' \
    '  https://www.docker.com/products/docker-desktop/'

  if docker info >/dev/null 2>&1; then
    good 'Docker engine responding'
  else
    detail 'Docker engine not responding; trying to start it'
    case "$(uname -s)" in
      Darwin) open -a Docker >/dev/null 2>&1 || note 'could not launch Docker Desktop automatically' ;;
      *)      note 'start the engine yourself if needed: sudo systemctl start docker' ;;
    esac

    # Poll rather than sleep-once: a cold start is slow and highly variable, so
    # a fixed wait either fails early or wastes time.
    started=$(date +%s)
    ready=0
    while [ $(( $(date +%s) - started )) -lt 180 ]; do
      sleep 5
      if docker info >/dev/null 2>&1; then ready=1; break; fi
      detail "still waiting for the Docker engine ($(( $(date +%s) - started ))s of 180s)"
    done

    [ "$ready" -eq 1 ] || fail 'the Docker engine did not come up within three minutes' \
      'Start Docker by hand and wait until it reports the engine is running.' \
      '' \
      'On macOS: open Docker Desktop and wait for the whale icon to settle.' \
      'On Linux: sudo systemctl start docker, and check you are in the docker' \
      '  group (groups | grep docker) or the socket will refuse you.' \
      '' \
      'Once the engine is running, re-run this script.'
    good 'Docker engine responding'
  fi
fi

# ---------------------------------------------------------------------------
# Step b: the compose stack
# ---------------------------------------------------------------------------

step 'Starting the service containers (Postgres, Redis, MinIO, OpenFGA, NATS, Mailpit)'

if [ "$SKIP_DOCKER" -eq 1 ]; then
  detail 'skipped (--skip-docker)'
else
  [ -f "$COMPOSE_FILE" ] || fail "no compose file at $COMPOSE_FILE"

  # -f rather than a directory change: compose derives the project directory
  # from the compose file, so the relative volume paths (../db/init) still
  # resolve, and the caller's working directory is left alone.
  if ! docker compose -f "$COMPOSE_FILE" up -d 2>&1 | indent; then
    fail 'docker compose up failed' \
      'Read the output above. Common causes:' \
      '  - a port is already taken (5432, 6379, 9000, 9001, 8080, 4222, 8025)' \
      '    stop whatever else is using it, or stop a stale stack:' \
      "      docker compose -f '$COMPOSE_FILE' down" \
      '  - an image could not be pulled: check the network and try again'
  fi

  # Postgres is the only container the next steps depend on, and the only one
  # with a healthcheck. Alembic against a still-initialising cluster fails in
  # confusing ways, so wait for healthy rather than for running.
  detail 'waiting for Postgres to report healthy'
  started=$(date +%s)
  healthy=0
  last_seen='unknown'

  while [ $(( $(date +%s) - started )) -lt 180 ]; do
    cid="$(docker compose -f "$COMPOSE_FILE" ps -q postgres 2>/dev/null | head -n 1 || true)"
    if [ -n "$cid" ]; then
      last_seen="$(docker inspect --format '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo unknown)"
      if [ "$last_seen" = 'healthy' ]; then healthy=1; break; fi
    fi
    sleep 3
    detail "Postgres status: $last_seen ($(( $(date +%s) - started ))s of 180s)"
  done

  [ "$healthy" -eq 1 ] || fail "Postgres did not become healthy (last status: $last_seen)" \
    'Look at the container log:' \
    "  docker compose -f '$COMPOSE_FILE' logs postgres" \
    '' \
    'If a previous run died part-way through first-time initialisation, the' \
    'data volume keeps a half-built cluster and the init scripts will not' \
    're-run. That state is only recoverable by destroying the volume (this' \
    'deletes all local case data):' \
    "  docker compose -f '$COMPOSE_FILE' down -v" \
    '  then run this script again.'
  good 'Postgres healthy'
fi

# ---------------------------------------------------------------------------
# Step c: the TOTP key-encryption key
# ---------------------------------------------------------------------------

step 'Checking the TOTP key-encryption key'

kek_from_environment=0
if [ -n "${NOCTORNAL_TOTP_KEK:-}" ]; then
  kek_from_environment=1
  good 'NOCTORNAL_TOTP_KEK already set in this environment'
fi

# Load the local key store first, then generate only if the key is still
# missing. An explicitly exported value always wins over the file, which is the
# usual .env precedence and stops this script overriding a deliberate choice
# made by whoever launched it. Parsed line by line rather than sourced: the
# file is data, and a hand-edited line should never execute.
if [ -f "$ENV_LOCAL" ]; then
  detail "reading $ENV_LOCAL"
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) continue ;; esac

    name="${line%%=*}"
    value="${line#*=}"
    name="$(printf '%s' "$name" | tr -d '[:space:]')"
    [ -n "$name" ] || continue
    value="${value#\"}"; value="${value%\"}"
    value="${value#\'}"; value="${value%\'}"

    if [ -n "${!name:-}" ]; then
      detail "$name already set in the environment - file value ignored"
      continue
    fi
    export "$name=$value"
    detail "$name loaded from .env.local"
  done < "$ENV_LOCAL"
fi

if [ -z "${NOCTORNAL_TOTP_KEK:-}" ]; then
  generated="$("$PYTHON" -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())')"

  if [ -f "$ENV_LOCAL" ]; then
    # The file exists but carries no key: append rather than replace, so
    # anything else the operator put in there survives.
    printf 'NOCTORNAL_TOTP_KEK=%s\n' "$generated" >> "$ENV_LOCAL"
  else
    cat > "$ENV_LOCAL" <<EOF
# NocTORnal local key store. Created by scripts/launch.sh.
#
# NOCTORNAL_TOTP_KEK seals every TOTP secret at rest. LOSING THIS FILE MEANS
# EVERY USER MUST RE-ENROL THEIR AUTHENTICATOR. Back it up somewhere you
# trust; it is deliberately not committed (.gitignore covers .env.*) and
# there is no default anywhere in the code.
#
# Anything else you add here as KEY=VALUE is loaded into the environment
# on launch.
NOCTORNAL_TOTP_KEK=$generated
EOF
    chmod 600 "$ENV_LOCAL" 2>/dev/null || true
  fi

  export NOCTORNAL_TOTP_KEK="$generated"

  printf '\n'
  printf '    ------------------------------------------------------------\n'
  printf '    A NEW TOTP KEY WAS GENERATED AND SAVED TO:\n'
  printf '      %s\n' "$ENV_LOCAL"
  printf '\n'
  printf '    That file is now your key store. It seals every TOTP secret in\n'
  printf '    the database. If you lose it, every user has to re-enrol their\n'
  printf '    authenticator app - there is no recovery and no default key.\n'
  printf '    Keep a backup. It is git-ignored, so it will never be committed.\n'
  printf '    ------------------------------------------------------------\n'
  printf '\n'
elif [ "$kek_from_environment" -eq 0 ]; then
  good 'TOTP key ready'
fi

# ---------------------------------------------------------------------------
# Step d: the rest of the environment
# ---------------------------------------------------------------------------

step 'Setting the service connection details'

# Dev-only credentials, mirroring infra/docker-compose.yml. They are the only
# literal secrets allowed in this repo, they only ever address containers on
# localhost, and a real deployment supplies all of these from the environment
# or Vault instead.
set_default() {
  local name="$1" value="$2"
  if [ -z "${!name:-}" ]; then
    export "$name=$value"
    detail "$name set to the local development default"
  else
    detail "$name kept from the environment"
  fi
}

set_default DATABASE_URL     'postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal'
set_default MINIO_ENDPOINT   'localhost:9000'
set_default MINIO_ACCESS_KEY 'noctornal'
set_default MINIO_SECRET_KEY 'dev_only_change_me'
set_default EVIDENCE_BUCKET  'noctornal-evidence'

# ---------------------------------------------------------------------------
# Step e: migrations
# ---------------------------------------------------------------------------

step 'Applying database migrations (alembic upgrade head)'

# Alembic resolves script_location and prepend_sys_path from alembic.ini
# relative to the working directory, so it must run from the repo root. The
# subshell keeps the change local.
if [ -x "$ALEMBIC" ]; then
  alembic_ok=0
  ( cd "$REPO_ROOT" && "$ALEMBIC" upgrade head ) && alembic_ok=1 || alembic_ok=0
else
  alembic_ok=0
  ( cd "$REPO_ROOT" && "$PYTHON" -m alembic upgrade head ) && alembic_ok=1 || alembic_ok=0
fi

[ "$alembic_ok" -eq 1 ] || fail 'alembic upgrade head failed' \
  'Read the traceback above. Common causes:' \
  '  - Postgres accepting connections but the schema half-built from an' \
  '    interrupted first run. Destroy the volume and start clean (this' \
  '    deletes all local case data):' \
  "      docker compose -f '$COMPOSE_FILE' down -v" \
  '  - a migration genuinely failing: fix the migration, do not edit the' \
  '    database by hand. One owner of the schema, no drift.'
good 'schema up to date'

# ---------------------------------------------------------------------------
# Step f: is there anyone who can log in?
# ---------------------------------------------------------------------------

step 'Checking for a user account'

count_code="import noctornal_api.db as d; print(d.connect().execute('select count(*) from iam.app_user').fetchone()[0])"

if ! count_out="$("$PYTHON" -c "$count_code" 2>&1)"; then
  # Not fatal: a failed count must not stop the API from starting.
  note 'could not count users (the API may still work) - output was:'
  printf '%s\n' "$count_out" | indent
else
  users="$(printf '%s' "$count_out" | tr -d '[:space:]')"
  if [ "${users:-0}" != '0' ]; then
    good "$users user account(s) exist"
  else
    printf '\n'
    printf '    ============================================================\n'
    printf '    NO USER ACCOUNTS YET - you cannot log in until you make one.\n'
    printf '\n'
    printf '    In a SECOND terminal, from the repo root, run:\n'
    printf '\n'
    # One line on purpose: it is meant to be copied, and a wrapped command
    # invites a mangled continuation.
    printf '      .venv/bin/python scripts/bootstrap.py create-user --email you@example.com --name "Your Name"\n'
    printf '\n'
    if [ ! -f "$REPO_ROOT/scripts/bootstrap.py" ]; then
      printf '    Note: scripts/bootstrap.py does not exist in this checkout yet,\n'
      printf '    so that command will fail until it is written.\n'
      printf '\n'
    fi
    printf '    ============================================================\n'
    printf '\n'
  fi
fi

# ---------------------------------------------------------------------------
# Step g: the API
# ---------------------------------------------------------------------------

step 'Starting the API'

printf '\n'
printf '  Everything is up. Open this in your browser:\n'
printf '      http://127.0.0.1:%s/ui/\n' "$PORT"
printf '\n'
printf '  Also available:\n'
printf '      http://localhost:9001   MinIO console (evidence store)\n'
printf '      http://localhost:8025   Mailpit (captured e-mail)\n'
printf '      http://localhost:3001   OpenFGA playground\n'

# The OpenAPI page is off unless NOCTORNAL_ENABLE_DOCS says otherwise: it
# describes the shape of a case system, so it stays opt-in. Advertise the URL
# only when it will actually answer.
case "$(printf '%s' "${NOCTORNAL_ENABLE_DOCS:-}" | tr '[:upper:]' '[:lower:]')" in
  1|true) printf '      http://127.0.0.1:%s/api/v1/docs   API reference\n' "$PORT" ;;
esac
printf '\n'
printf '  The API log follows below. Press Ctrl+C to stop it.\n'
printf '  The containers keep running afterwards; stop them with:\n'
printf "      docker compose -f '%s' down\n" "$COMPOSE_FILE"
printf '\n'

# exec so signals reach uvicorn directly and Ctrl+C is not swallowed by bash.
exec "$PYTHON" -m uvicorn noctornal_api.http.app:app --host 127.0.0.1 --port "$PORT"

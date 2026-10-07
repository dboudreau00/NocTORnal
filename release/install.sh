#!/usr/bin/env bash
#
# One-command install for NocTORnal on macOS and Linux, as a short wizard
# of eight numbered steps.
#
# Step 1 looks at your computer and changes nothing. The rest builds the
# virtual environment, generates the secrets that have no safe default,
# starts the containers, migrates the database, creates the first account
# (and waits while you save its password), offers a fictional demo case
# and runs the API.
#
# Every step is idempotent and reports what it found rather than assuming.
# Re-running this is safe. Start here: release/START-HERE.md.
#
# READ THE README.md AT THE PROJECT ROOT FIRST, section "Five blocking
# items". Five legal decisions, L1 to L5, gate any use of this software
# against real material.
#
# Usage, from the project root:
#   ./release/install.sh                  start everything
#   ./release/install.sh --port 8001      a different API port
#   ./release/install.sh --skip-launch    install and configure, start nothing
#   ./release/install.sh --demo           load the fictional demo case, without asking
#   ./release/install.sh --no-demo        do not load it, without asking
#   ./release/install.sh --open           open the console in your browser when it is up
#   ./release/install.sh --with-telegram  also install the Telegram collection library (optional)
#   ./release/install.sh --with-yara      also install the YARA scanning library (optional)
#
# With no terminal attached (a pipe, cron, CI) it never asks a question
# beyond the two the account needs, read from standard input: an email,
# then a display name. The demo case is then loaded only with --demo.
#
# The production deployment (infra/production, read its README.md first):
#   sudo ./release/install.sh --production-secrets
#       brings infra/production's secrets files to this release's layout,
#       moving the schema owner's credential out of secrets.env and writing
#       the Redis password and REDIS_URL, with a backup of every file it
#       changes. Installs and starts nothing. With sudo because the files
#       are root's, mode 600. Add --dir DIR for another directory. What it
#       does and the way back: release/secrets-upgrade/README.md.
#
set -euo pipefail

# --help prints the comment block above and stops at its end. It was a
# fixed line range, `sed -n '2,20p'`, which ran one line past the block and
# printed `set -euo pipefail` as the last line of the usage text (Alpha 6
# pre-release check, 2026-09-23). Reading to the first non-comment line
# cannot drift when the header is edited.
usage() {
  awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
}

PORT=8000
SKIP_LAUNCH=0
# The optional extras (2026-09-24): installed only when asked for by
# name, and then a failure is loud. "telegram" is Telethon, "yara" is
# yara-x; neither is needed to run the API, and each one's absence is a
# gap the readiness register shows.
WITH_TELEGRAM=0
WITH_YARA=0
PRODUCTION_STEP=0
PROD_DIR=""
# The demo case: "" asks when a person is at the keyboard and skips when
# not, "yes" loads it, "no" skips it. The browser: 1 opens it without asking.
DEMO_MODE=""
OPEN_BROWSER=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --skip-launch) SKIP_LAUNCH=1; shift ;;
    --demo)
      if [[ "$DEMO_MODE" == "no" ]]; then echo "choose --demo or --no-demo, not both" >&2; exit 2; fi
      DEMO_MODE=yes; shift ;;
    --no-demo)
      if [[ "$DEMO_MODE" == "yes" ]]; then echo "choose --demo or --no-demo, not both" >&2; exit 2; fi
      DEMO_MODE=no; shift ;;
    --open) OPEN_BROWSER=1; shift ;;
    --with-telegram) WITH_TELEGRAM=1; shift ;;
    --with-yara) WITH_YARA=1; shift ;;
    --production-secrets) PRODUCTION_STEP=1; shift ;;
    --dir) PROD_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -t 1 ]]; then
  C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_RED=$'\033[31m';  C_DIM=$'\033[2m';    C_OFF=$'\033[0m'
else
  C_CYAN=; C_GREEN=; C_YELLOW=; C_RED=; C_DIM=; C_OFF=
fi

# The wizard's numbered steps. step() counts for itself, so a step added or
# removed cannot leave "Step 3 of 8" wrong in the middle of the run; a test
# holds STEP_TOTAL to the number of step calls. heading() is for output that
# is not one of the eight (the production secrets job, the closing line of
# --skip-launch).
STEP_TOTAL=8
STEP_NO=0
step() {
  STEP_NO=$((STEP_NO + 1))
  printf '\n  %sStep %d of %d: %s%s\n' "$C_CYAN" "$STEP_NO" "$STEP_TOTAL" "$1" "$C_OFF"
}
heading() { printf '\n  %s%s%s\n' "$C_CYAN" "$1" "$C_OFF"; }
good()   { printf '    %s%s%s\n' "$C_GREEN" "$1" "$C_OFF"; }
note()   { printf '    %s%s%s\n' "$C_YELLOW" "$1" "$C_OFF"; }
detail() { printf '    %s\n' "$1"; }

# The first line of the second argument is the one sentence that says what to
# do; any lines after it are the commands.
stop_with() {
  printf '\n  %sCannot continue: %s%s\n\n' "$C_RED" "$1" "$C_OFF"
  printf '  %sWhat to do:%s\n' "$C_YELLOW" "$C_OFF"
  printf '%s\n' "$2" | sed 's/^/    /'
  printf '\n'
  exit 1
}

# Whether a person is at the keyboard. Standard input is the test, because it
# is what the questions read: a clean-VM harness, cron, CI and `curl | bash`
# all feed or close it, and a question asked there eats the lines meant for
# the account prompt.
INTERACTIVE=0
if [[ -t 0 ]]; then INTERACTIVE=1; fi

# The decisions below are functions of their arguments and nothing else, so a
# test can run them (apps/api/tests/test_install_wizard.py).
#
# decide_demo MODE INTERACTIVE FRESH: what to do about the fictional demo
# case. MODE is yes, no or empty; INTERACTIVE and FRESH are 1 or 0, FRESH
# meaning this run made the account. Prints load, ask or skip. A question is
# asked only of a person who has just made their first account.
decide_demo() {
  local mode="$1" interactive="$2" fresh="$3"
  if [[ "$mode" == "no" ]]; then echo skip; return 0; fi
  if [[ "$mode" == "yes" ]]; then echo load; return 0; fi
  if [[ "$fresh" == "1" && "$interactive" == "1" ]]; then echo ask; else echo skip; fi
}

# decide_open FORCE INTERACTIVE DESKTOP: whether to open the browser. Prints
# open, ask or skip. --open forces it, and nothing opens without a desktop.
decide_open() {
  local force="$1" interactive="$2" desktop="$3"
  if [[ "$desktop" != "1" ]]; then echo skip; return 0; fi
  if [[ "$force" == "1" ]]; then echo open; return 0; fi
  if [[ "$interactive" == "1" ]]; then echo ask; else echo skip; fi
}

# Whether this machine has a desktop to open a page on: macOS always, Linux
# when a display is set and xdg-open exists. Prints 1 or 0.
has_desktop() {
  case "$(uname -s 2>/dev/null || echo unknown)" in
    Darwin) if command -v open >/dev/null 2>&1; then echo 1; else echo 0; fi ;;
    *) if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] && command -v xdg-open >/dev/null 2>&1; then echo 1; else echo 0; fi ;;
  esac
}

# The question's answer: empty and anything starting with y or Y is yes,
# so Enter takes the default. Prints yes or no.
answer_is_yes() {
  case "$1" in
    ''|[Yy]*) echo yes ;;
    *) echo no ;;
  esac
}

# What this machine calls itself, read as data (never sourced).
describe_os() {
  local name=""
  case "$(uname -s 2>/dev/null || echo unknown)" in
    Darwin) name="macOS $(sw_vers -productVersion 2>/dev/null || true)" ;;
    *)
      if [[ -r /etc/os-release ]]; then
        name="$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n 1 | tr -d '"')"
      fi
      if [[ -z "$name" ]]; then name="$(uname -sr 2>/dev/null || echo unknown)"; fi ;;
  esac
  printf '%s, %s' "$name" "$(uname -m 2>/dev/null || echo unknown)"
}

RELEASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# --production-secrets (docs/17 F52 and the limiter's Redis ACL, 2026-10-02)
#
# A different job from everything below: it touches the production
# deployment's secrets files and nothing else, so it runs before the
# Windows refusal (which is about a virtual environment this does not
# build) and exits. The work is scripts/production_secrets.py, the one
# implementation install.ps1 calls too, run on the host's own python3: a
# production host need not have this repository's virtual environment, and
# the helper imports the standard library alone. It prints names, never a
# value, and backs up every file before it changes it.
#
# Whether the database volume exists decides one thing: an owner password
# may be generated only for a volume initdb has not run on, because initdb
# fixes it for good. Docker is asked, and only "no such volume" from an
# engine that answers counts; anything else passes nothing, and the helper
# asks the operator to choose the password instead of guessing.
# ---------------------------------------------------------------------------
if [[ $PRODUCTION_STEP -eq 1 ]]; then
  ROOT_DIR="$(dirname "$RELEASE_DIR")"
  TARGET_DIR="${PROD_DIR:-$ROOT_DIR/infra/production}"
  heading 'Bringing the production secrets files to this release'
  detail "in $TARGET_DIR"
  HOST_PY=""
  for name in python3 python; do
    command -v "$name" >/dev/null 2>&1 || continue
    if "$name" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
      HOST_PY="$(command -v "$name")"
      break
    fi
  done
  [[ -n "$HOST_PY" ]] || stop_with 'Python 3.8 or newer was not found on this host.' \
    "Install Python 3 on this host, then run this again.
The production secrets step runs on the host's own python3, with the
standard library only. Debian/Ubuntu:  sudo apt update && sudo apt install python3"
  NEW_DATABASE=0
  if [[ -z "$PROD_DIR" ]] && command -v docker >/dev/null 2>&1 \
       && docker info >/dev/null 2>&1 \
       && ! docker volume inspect noctornal-prod_prod-pgdata >/dev/null 2>&1; then
    NEW_DATABASE=1
    detail 'Docker has no database volume for this deployment yet'
  fi
  set +e
  if [[ $NEW_DATABASE -eq 1 ]]; then
    "$HOST_PY" "$ROOT_DIR/scripts/production_secrets.py" --dir "$TARGET_DIR" --new-database \
      | sed 's/^/    /'
  else
    "$HOST_PY" "$ROOT_DIR/scripts/production_secrets.py" --dir "$TARGET_DIR" \
      | sed 's/^/    /'
  fi
  status=${PIPESTATUS[0]}
  set -e
  if [[ $status -eq 0 ]]; then
    good "the production secrets files are in this release's layout"
    detail 'next: docker compose -p noctornal-prod -f infra/production/compose.yml up -d --build'
  else
    note 'not finished: the lines above say what is left, or why it stopped and what it changed'
  fi
  exit "$status"
fi

# ---------------------------------------------------------------------------
# Refuse to run on Windows.
#
# Git Bash, MSYS2 and Cygwin all provide a working bash on Windows, so this
# script RUNS there — and then does damage, because a Windows virtualenv
# puts its interpreter in Scripts/ rather than bin/. The "is there already a
# venv?" check below therefore says no, and the script recreates an
# environment over a working one.
#
# Found by doing exactly that during development. It only failed safe
# because the API happened to be running and held python.exe open; with the
# API stopped it would have replaced a working environment with a broken
# one, and the error message names a venvlauncher copy rather than anything
# a user could act on.
# ---------------------------------------------------------------------------
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    stop_with "this is the macOS/Linux installer and you are on Windows." \
      "Use the PowerShell installer instead, from the project root:

    powershell -ExecutionPolicy Bypass -File .\\release\\install.ps1

Running this script under Git Bash or MSYS would create a Unix-layout
virtual environment on top of a Windows one and break both."
    ;;
esac

printf '\n  NocTORnal - Beta Install\n'
printf '  %s─────────────────────────%s\n' "$C_DIM" "$C_OFF"
# Five, L1 to L5, as the root README's table has them, and a heading that
# exists there. The banner said four and pointed at a "LEGAL STATUS"
# section only release/README.md has. It names the README at the project
# root in full because release/README.md is the one beside this script
# and has no such heading (Alpha 6 pre-release check, 2026-09-23).
printf '  %sBeta software. Not audited. Five legal decisions (L1 to L5)%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sgate any use against real material: see "Five blocking items"%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sin the README.md at the project root. Installing is fine;%s\n' "$C_YELLOW" "$C_OFF"
printf '  %spointing it at a real case is not, until those are settled.%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sLegal review is required before any active case load, and%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sholding this material is itself dangerous: see docs/16.%s\n' "$C_YELLOW" "$C_OFF"
printf '\n  This takes %d short steps. Step 1 only looks at your computer and\n' "$STEP_TOTAL"
printf '  changes nothing. If a step fails it says what to do, and running this\n'
printf '  again is safe.\n'

# ---------------------------------------------------------------------------
# Locate the application. The release directory may sit inside the source
# tree or beside it; resolve rather than assume, so a moved folder gives a
# clear message instead of a confusing failure four steps later.
# ---------------------------------------------------------------------------

# THE PROJECT ROOT IS THE PARENT OF THIS DIRECTORY. Nothing else.
#
# This used to probe four candidates, the last a HARDCODED sibling folder
# name (release finding R1) that resolved on exactly one machine and
# produced "the application source could not be found" everywhere else.
# The package is self-contained now: release/ lives inside the project
# tree, so its parent IS the project. One rule, no search, no dependence
# on what any adjacent directory is called or whether it exists.
REPO_ROOT=""
candidate="$(dirname "$RELEASE_DIR")"
if [[ -f "$candidate/alembic.ini" ]]; then
  REPO_ROOT="$(cd "$candidate" && pwd)"
fi
[[ -n "$REPO_ROOT" ]] || stop_with \
  "this does not look like a complete NocTORnal package." \
  "Clone or download the whole repository, then run this installer again from
the project root:

    ./release/install.sh

install.sh expects to live in the release/ directory of the project, so
that its parent contains alembic.ini. That parent has no alembic.ini. The
usual cause is copying release/ out on its own. It is documentation and
installers only, with no application source in it."

# ---------------------------------------------------------------------------
# Step 1: look at the computer. Nothing is changed here. What it finds is
# printed as it goes, so the summary is on screen before step 2 touches
# anything: the system, Python, Docker and Compose, and the API's port.
# ---------------------------------------------------------------------------

step 'Checking your computer'
detail 'This step only looks. Nothing on your computer has been changed.'
good "folder:  $REPO_ROOT"
good "system:  $(describe_os)"

# ---------------------------------------------------------------------------
# 1a. Python
# ---------------------------------------------------------------------------

PYTHON=""
for name in python3.13 python3.12 python3 python; do
  command -v "$name" >/dev/null 2>&1 || continue
  ver="$("$name" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)" || continue
  major="${ver%%.*}"; minor="${ver##*.}"
  if (( major > 3 || (major == 3 && minor >= 12) )); then
    PYTHON="$(command -v "$name")"
    full="$("$PYTHON" -c 'import platform; print(platform.python_version())' 2>/dev/null || echo "$ver")"
    good "Python:  $full at $PYTHON"
    break
  fi
  detail "found Python $ver at $(command -v "$name"), which is too old"
done
# `apt update` first, in this message and the venv one below: on a fresh
# cloud image the package lists are empty and `apt install python3.12-venv`
# answers "has no installation candidate" (Alpha 6 pre-release check,
# 2026-09-23, on the clean VM).
[[ -n "$PYTHON" ]] || stop_with "Python 3.12 or newer was not found." \
  "Install Python 3.12 or newer, then run this installer again.
Debian/Ubuntu:  sudo apt update && sudo apt install python3.12 python3.12-venv
Fedora:         sudo dnf install python3.12
macOS:          brew install python@3.12"

# `venv` is a separate package on Debian-family systems and its absence
# only shows up at the create step, with a message that does not name the
# package. Check it here instead.
#
# ASK FOR ensurepip, NOT venv. `import venv` succeeds on a stock Ubuntu
# 24.04 that cannot build an environment at all, because `venv/` ships in
# python3-minimal while python3.12-venv carries `ensurepip` and the pip
# wheel it installs. So this guard passed, said nothing, and the install
# died two steps later inside `python -m venv` with a message in Python's
# voice rather than this script's. Measured on a clean VM, 2026-09-17:
# `import venv` exit 0, `import ensurepip` exit 1, `python3.12 -m venv`
# non-zero. `venv` is still checked, because a stripped build could lack
# either.
missing_venv=""
"$PYTHON" -c 'import venv'      >/dev/null 2>&1 || missing_venv="venv"
"$PYTHON" -c 'import ensurepip' >/dev/null 2>&1 || missing_venv="${missing_venv:+$missing_venv and }ensurepip"
if [[ -n "$missing_venv" ]]; then
  # python3.12 -> python3.12-venv. Naming the versioned package matters:
  # `apt install python3-venv` on a host whose default python3 is not the
  # interpreter found above installs the wrong one and changes nothing.
  py_pkg="$(basename "$PYTHON")-venv"
  stop_with "Python is installed but cannot build a virtual environment ($missing_venv missing)." \
    "Install the Python venv package, then run this installer again.
Debian/Ubuntu:  sudo apt update && sudo apt install $py_pkg
                (or: sudo apt update && sudo apt install python3-venv)
Fedora:         sudo dnf install python3-devel

This is a separate package on Debian-family systems: the interpreter is
present and importing 'venv' succeeds, but 'ensurepip' is what actually
creates the environment, and it ships separately."
fi

# ---------------------------------------------------------------------------
# 1b. Docker
# ---------------------------------------------------------------------------

command -v docker >/dev/null 2>&1 || stop_with "Docker was not found." \
  "Install Docker, then run this installer again.
Linux:  https://docs.docker.com/engine/install/
macOS:  https://www.docker.com/products/docker-desktop/  (or: brew install --cask docker)"

if ! docker info >/dev/null 2>&1 </dev/null; then
  stop_with "Docker is installed but the engine is not reachable." \
    "Start Docker and wait until it is running, then run this installer again.
Linux:  sudo systemctl start docker
        and add yourself to the docker group so sudo is not needed:
          sudo usermod -aG docker \$USER   (then log out and back in)
macOS:  start Docker Desktop and wait for it to report running."
fi

docker compose version >/dev/null 2>&1 </dev/null || stop_with \
  "Docker Compose v2 was not found." \
  "Update Docker to a current release, then run this installer again.
This needs the 'docker compose' subcommand, not the older standalone
'docker-compose' binary."
DOCKER_VERSION="$(docker version --format '{{.Server.Version}}' 2>/dev/null </dev/null || true)"
COMPOSE_VERSION="$(docker compose version --short 2>/dev/null </dev/null || true)"
good "Docker:  ${DOCKER_VERSION:-version unknown}, engine running, Compose ${COMPOSE_VERSION:-v2} present"

# ---------------------------------------------------------------------------
# 1c. The port. A re-run while the API is already up says so here, before
# anything is built, in this script's voice. It used to run every step and
# then end in uvicorn's "[Errno 98] ... address already in use" and exit 3,
# while INSTALL.md quoted a message only launch.ps1 printed (Alpha 6
# pre-release check, 2026-09-23). bash's /dev/tcp connects without any extra
# tool; a refused connection means the port is free. --skip-launch starts no
# API, so a busy port is only reported then.
# ---------------------------------------------------------------------------

PORT_BUSY=0
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
  PORT_BUSY=1
fi
if [[ $PORT_BUSY -eq 1 && $SKIP_LAUNCH -eq 0 ]]; then
  stop_with "port $PORT is already in use." \
    "Open http://127.0.0.1:$PORT/ui/ if an earlier copy is still running there, or choose another port.

    ./release/install.sh --port $((PORT + 1))

To stop an earlier copy, press Ctrl-C in the window it runs in."
fi
if [[ $PORT_BUSY -eq 1 ]]; then
  note "Port:    $PORT is in use (fine, since --skip-launch starts nothing)"
else
  good "Port:    $PORT is free"
fi

# The other ports are the containers'. When none of this project's containers
# is running and one of those is taken, `docker compose up` fails on it, so
# the install says so now rather than after the images are pulled. Not fatal:
# the compose file is the authority, and a port held by an earlier copy of
# this stack is fine.
if [[ -z "$(docker compose -f "$REPO_ROOT/infra/docker-compose.yml" ps -q 2>/dev/null </dev/null || true)" ]]; then
  taken=""
  for p in 5432 6379 9000 9001 1025 8025; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then taken="${taken:+$taken, }$p"; fi
  done
  if [[ -n "$taken" ]]; then
    note "Ports:   in use by another program: $taken"
    note 'The containers need them. If step 4 fails, stop that program first.'
  fi
fi

printf '\n'
detail 'All good. Next it will:'
detail '  build a private Python environment in the .venv folder'
detail '  write .env.local with fresh random keys (the file is yours to keep)'
detail '  start four containers: Postgres, Redis, MinIO and Mailpit'
detail '  set up the database and make your account'

# ---------------------------------------------------------------------------
# 3. Virtual environment and dependencies
# ---------------------------------------------------------------------------

VENV="$REPO_ROOT/.venv"
VENV_PY="$VENV/bin/python"

step 'Building the Python environment'
if [[ -x "$VENV_PY" && -x "$VENV/bin/pip" ]]; then
  good '.venv already exists'
elif [[ -x "$VENV_PY" ]]; then
  # An interpreter but no pip: `python -m venv` got far enough to link the
  # binaries and then failed at ensurepip. This is not someone's
  # environment, it is the wreckage of an interrupted run of THIS script,
  # and it is safe to remove.
  #
  # It used to be indistinguishable from a good one, because the test
  # above was `-x "$VENV_PY"` alone and a half-built venv has bin/python.
  # The second run therefore reported '.venv already exists', went on to
  # install dependencies, and died with 'No module named pip' -- a message
  # FURTHER from the cause than the first run's, and one that never
  # mentioned the real fix again however many times it was re-run.
  note 'a previous run left a half-built .venv (no pip); rebuilding it'
  rm -rf "$VENV"
  detail 'creating .venv (this takes a moment)'
  "$PYTHON" -m venv "$VENV" || { rm -rf "$VENV"; stop_with \
    "the virtual environment could not be created." \
    "Fix what the output above names, then run this installer again.
Nothing was left behind, so that is all that is needed."; }
  good 'created'
elif [[ -e "$VENV" ]]; then
  # Something is there and it is not a Unix venv. Refuse rather than
  # write over it: `python -m venv` on an existing directory MERGES, so a
  # half-overwritten environment is the likely outcome and it fails later,
  # somewhere unrelated.
  stop_with "$VENV exists but has no bin/python." \
    "Delete that folder, then run this installer again.
It usually means the folder was created on Windows (interpreter in
Scripts/ rather than bin/), or a previous install was interrupted.

    rm -rf '$VENV'"
else
  detail 'creating .venv (this takes a moment)'
  # Remove the partial directory on failure. Leaving it is what turned a
  # clear "install python3.12-venv" into a permanent "No module named
  # pip" on every later run.
  "$PYTHON" -m venv "$VENV" || { rm -rf "$VENV"; stop_with \
    "the virtual environment could not be created." \
    "Fix what the output above names, then run this installer again.
Nothing was left behind, so that is all that is needed."; }
  good 'created'
fi

detail 'installing dependencies (a few minutes the first time)'
# Every install below is held to constraints.txt, the exact versions the
# release's suite passed on (sec-pin-dependencies, 2026-09-23). Without it
# each `>=` in the pyproject files resolved to whatever was newest that day,
# and the clean VM of the Alpha 6 check ran a newer stack than the one
# tested. Checked for here, so a missing file is named as that and not as
# "dependency installation failed" with pip's error scrolled past.
CONSTRAINTS="$REPO_ROOT/constraints.txt"
[[ -f "$CONSTRAINTS" ]] || stop_with "constraints.txt is missing from $REPO_ROOT." \
  "Unpack the release again, or check out the whole repository, then run this
installer again. The file pins every Python dependency to the version this
release was tested on, and it ships with the release."
"$VENV_PY" -m pip install --upgrade pip --quiet
# BOTH packages, editable. The ontology package is the single source of the
# selector normalisers and the API imports it; installing only the API
# produces an ImportError at the first comms request rather than here.
"$VENV_PY" -m pip install --quiet -c "$CONSTRAINTS" \
  -e "$REPO_ROOT/packages/ontology" \
  -e "$REPO_ROOT/apps/api" \
  || stop_with "dependency installation failed." \
     "Check your internet connection, then run this installer again.
The output above says why. The commonest causes are no network
access, or a proxy that needs pip configured for it."
"$VENV_PY" -m pip install --quiet -c "$CONSTRAINTS" -e "$REPO_ROOT/apps/api[dev]" 2>/dev/null || true
good 'dependencies installed'

# The extras asked for by name: a third install, and a LOUD one. The dev
# extra above is best effort because nobody asked for it; these were
# asked for, so a failure stops here rather than leaving an install that
# silently lacks what its operator requested.
EXTRAS=""
if [[ $WITH_TELEGRAM -eq 1 ]]; then EXTRAS="telegram"; fi
if [[ $WITH_YARA -eq 1 ]]; then EXTRAS="${EXTRAS:+$EXTRAS,}yara"; fi
if [[ -n "$EXTRAS" ]]; then
  detail "installing the optional extras: $EXTRAS"
  "$VENV_PY" -m pip install --quiet -c "$CONSTRAINTS" -e "$REPO_ROOT/apps/api[$EXTRAS]" \
    || stop_with "the optional extras ($EXTRAS) did not install." \
       "Run this installer again without the switch to install everything else.
The output above says why. The commonest causes are no network
access, or a macOS older than 14 for yara (yara-x publishes no wheel for
it). The readiness register then shows what the missing extra leaves out."
  good "optional extras installed: $EXTRAS"
fi

# ---------------------------------------------------------------------------
# 4. Secrets
# ---------------------------------------------------------------------------
# Nothing in this system has a default secret. A missing value produces a
# deliberate refusal, never an insecure fallback -- so these are generated
# once, here, and left alone on every subsequent run.

step 'Creating your secret keys'
ENV_LOCAL="$REPO_ROOT/.env.local"
if [[ -f "$ENV_LOCAL" ]]; then
  good '.env.local already exists - left untouched'
  # A collector process (2026-10-02): a file written before the persona
  # key existed gains it, appended, with the inline mode this install runs
  # in. Nothing already in the file is changed.
  if ! grep -q '^NOCTORNAL_PERSONA_KEK=' "$ENV_LOCAL"; then
    PKEK="$("$VENV_PY" -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())')"
    [[ -n "$PKEK" ]] || stop_with 'Could not generate the persona key.' \
'Run this installer again. Nothing was written, so that is safe.
The Python in the virtual environment produced nothing.'
    {
      printf '%s\n' '# NOCTORNAL_PERSONA_KEK seals every collection persona credential. Lost, every persona is enrolled again.'
      printf 'NOCTORNAL_PERSONA_KEK=%s\n' "$PKEK"
      grep -q '^NOCTORNAL_COLLECTOR_INLINE=' "$ENV_LOCAL" || printf 'NOCTORNAL_COLLECTOR_INLINE=1\n'
    } >> "$ENV_LOCAL"
    good 'added the persona key to .env.local'
  fi
else
  # CHECKED before anything is written. `set -euo pipefail` already stops
  # the script if the interpreter EXITS non-zero, which covers most of it
  # -- but not an interpreter that exits 0 and prints nothing, and not one
  # that prints a warning to stdout ahead of the value. Either way the
  # file would be written with an empty or malformed key while the
  # installer announced fresh random keys.
  #
  # And the failure LATCHES: every later run takes the `-f "$ENV_LOCAL"`
  # branch and reports "left untouched", so a half-failed first install is
  # permanent and is reported as a success twice. Refusing before the write
  # leaves no file, so re-running is the fix. install.ps1 carries the same
  # checks, where they matter more -- `& cmd` there does not stop the
  # script at all.
  KEK="$("$VENV_PY" -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())')"
  PEPPER="$("$VENV_PY" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  # Length, not just presence: envelope.py requires exactly 32 bytes and
  # refuses anything else at RUN time, which the recipient meets much
  # later, in a different program, with no connection back to here.
  KEK_BYTES="$(printf '%s' "$KEK" | "$VENV_PY" -c \
    'import base64,sys; print(len(base64.b64decode(sys.stdin.read().strip())))' \
    2>/dev/null || printf '0')"
  if [[ -z "$KEK" || "$KEK_BYTES" != "32" ]]; then
    stop_with "The generated TOTP key is ${KEK_BYTES:-0} bytes, not 32." \
"Run this installer again. Nothing was written, so that is safe.
The Python in the virtual environment did not produce a usable key.
Run \"$VENV_PY -c 'import base64, os'\" to see the real error."
  fi
  # The persona key (A collector process, 2026-10-02), checked as the TOTP
  # key is: the persona ring refuses anything but 32 bytes at run time.
  PKEK="$("$VENV_PY" -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())')"
  PKEK_BYTES="$(printf '%s' "$PKEK" | "$VENV_PY" -c \
    'import base64,sys; print(len(base64.b64decode(sys.stdin.read().strip())))' \
    2>/dev/null || printf '0')"
  if [[ -z "$PKEK" || "$PKEK_BYTES" != "32" ]]; then
    stop_with "The generated persona key is ${PKEK_BYTES:-0} bytes, not 32." \
"Run this installer again. Nothing was written, so that is safe.
The Python in the virtual environment did not produce a usable key."
  fi
  if [[ -z "$PEPPER" ]]; then
    stop_with 'Could not generate the ingest pepper.' \
"Run this installer again. Nothing was written, so that is safe.
The Python in the virtual environment produced nothing."
  fi
  # R9: the SERVICE CONFIG is persisted too, not just the secrets. These
  # used to be exported into this script's own shell and lost when it
  # exited, so every documented "second terminal" command failed for a
  # fresh recipient. bootstrap.py reads this file now.
  #
  # R11: the SMTP values make the advertised Mailpit demo actually work --
  # the default port in transports.py is 587 and Mailpit listens on 1025.
  #
  # 127.0.0.1, not localhost, in every address below. The dev stack
  # publishes its ports on 127.0.0.1 only, so nothing answers on ::1, and a
  # client that resolves localhost to ::1 first (the Windows default order)
  # waits about two seconds for each refused attempt before trying IPv4
  # (Alpha 6 pre-release check, 2026-09-23). The header names everything
  # the two secrets protect, from security/sealed.py's SEALED_COLUMNS and
  # ingest.py's HMAC; it named only authenticators and ingest keys.
  # Private from the first byte (infra-9, 2026-10-03): the file is created
  # under umask 077, so the key store is never world-readable between this
  # write and the chmod below, which stays as the belt.
  PREVIOUS_UMASK="$(umask)"
  umask 077
  cat > "$ENV_LOCAL" <<EOF
# Generated by install.sh. Machine-local; never commit this file.
# BACK IT UP: nothing can recover these three secrets.
# NOCTORNAL_TOTP_KEK seals every secret the database stores encrypted,
# except the egress exits, which are sealed to the egress proxy's own key,
# and collection persona credentials, which NOCTORNAL_PERSONA_KEK seals:
# enrolled authenticators, stored victim
# credentials, each sample's data key, and the credentials of the outbound
# integrations an administrator configures (Jira and lookup provider
# credentials). Lost, or replaced other than by
# the key rotation security/envelope.py describes, none of them opens
# again: every user re-enrols an authenticator, and no stored sample,
# preserved ones included, can be decrypted. NOCTORNAL_INGEST_PEPPER keys
# the HMAC of every issued ingest key and every victim-credential
# fingerprint: lost or changed, every ingest key must be reissued, and
# stored fingerprints no longer match new ones for the same value.
NOCTORNAL_TOTP_KEK=$KEK
NOCTORNAL_INGEST_PEPPER=$PEPPER
# NOCTORNAL_PERSONA_KEK seals every collection persona credential. Lost,
# every persona is enrolled again. This install has no collector process,
# so persona acts run inside the API (NOCTORNAL_COLLECTOR_INLINE); a
# production deployment keeps the key in the collector service alone.
NOCTORNAL_PERSONA_KEK=$PKEK
NOCTORNAL_COLLECTOR_INLINE=1

# Local development stack (infra/docker-compose.yml). Change these to
# point at a real deployment; they are read by the API, by
# scripts/launch.sh and by scripts/bootstrap.py.
DATABASE_URL=postgresql+psycopg://noctornal:dev_only_change_me@127.0.0.1:5432/noctornal
REDIS_URL=redis://127.0.0.1:6379/0
MINIO_ENDPOINT=127.0.0.1:9000
MINIO_ACCESS_KEY=noctornal
MINIO_SECRET_KEY=dev_only_change_me
EVIDENCE_BUCKET=noctornal-evidence
SAMPLE_BUCKET=noctornal-samples
# Raw partner submissions, deliberately in a bucket WITHOUT object lock:
# an exhibit is locked so not even root can delete it before its deadline,
# and a partner's raw submission has to stay deletable to answer a
# deletion order.
INGEST_BUCKET=noctornal-raw
# Raw markup of collected forum pages, per item, deliberately WITHOUT
# object lock: it is deleted with its document.
COLLECT_RAW_BUCKET=noctornal-collect-raw

# Rejected malware samples are PRESERVED, not destroyed (docs/11): their
# encrypted bytes move into this object-locked bucket under a legal hold,
# and a retrieval needs a Security Officer's authorisation. Set the
# disposition to destroy only if counsel has decided rejected samples must
# not be kept; any other value refuses rejections until it is corrected.
PRESERVE_BUCKET=noctornal-preserved
NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=preserve

# The largest exhibit and the largest sample this deployment accepts,
# declared rather than defaulted. Production REFUSES TO BOOT while
# NOCTORNAL_MAX_EVIDENCE_BYTES is unset, because a cap nobody chose is a
# cap nobody can be held to; the development stack only warns. These are
# written here so that promoting this file to a real deployment, which is
# the obvious thing to do with it, does not meet a boot refusal with no
# hint that the line was ever available. Accepts 256MB, 1G, or bytes.
NOCTORNAL_MAX_EVIDENCE_BYTES=256MB
NOCTORNAL_MAX_SAMPLE_BYTES=64MB

# Mailpit, on the dev stack only. SMTP_ALLOW_PLAINTEXT is required
# explicitly: sending case material over an unencrypted connection is a
# decision, not a default.
SMTP_HOST=127.0.0.1
SMTP_PORT=1025
SMTP_ALLOW_PLAINTEXT=1
EOF
  umask "$PREVIOUS_UMASK"
  chmod 600 "$ENV_LOCAL"
  good 'wrote .env.local with fresh random keys (mode 600)'
  note 'Back this file up. Without it every user must re-enrol their'
  note 'authenticator, and no stored credential or sample can be decrypted'
  note 'again. Its header lists what each secret protects.'
fi

# Read .env.local as DATA, never run it (infra-9, 2026-10-03). This line was
# `set -a; . "$ENV_LOCAL"; set +a`, which EXECUTES the file: a .env.local
# that was handed over, restored from a backup or edited by hand ran as this
# user, and a value with a `$`, an `&`, a `;` or a space was mangled or run.
# launch.sh, scripts/_env.py and launch.ps1 already parse the same file line
# by line for that reason. The file's value wins over the environment here,
# as sourcing made it win: this installer migrates and seeds whatever the
# file names, and an exported DATABASE_URL pointing somewhere else must not
# receive them. The tests extract this function and run it
# (apps/api/tests/test_g48_install_env_data.py).
#
# A name that changes how programs start is left out (g48 verification,
# 2026-10-03). Reading the file as data stops it running as shell syntax, but
# the loop still exported any identifier in it, and the file's value wins over
# the environment here: `PYTHONPATH=./evil` (with a sitecustomize.py),
# `PATH=./evilbin`, `LD_PRELOAD=./evil.so` or `BASH_ENV=./evil.sh` ran code as
# the installing user in the next python or shell the installer starts. So did
# the tools it starts (Beta 1 verification, 2026-10-07): `DOCKER_CONFIG` held a
# fake `cli-plugins/docker-compose` that `docker compose` ran as root, hence
# `DOCKER_`, `COMPOSE_`, `GIT_`, `PIP_`, `NODE_` and `PSModulePath` as well. Not an
# allow-list on purpose: a new setting would silently stop loading. The same
# list is in scripts/_env.py, scripts/launch.sh, scripts/launch.ps1 and
# scripts/open-ui.ps1, and a test holds them to each other.
load_env_local_as_data() {
  local file="$1" line name value upper first=1
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ $first -eq 1 ]]; then
      first=0
      line="${line#$'\xef\xbb\xbf'}"
    fi
    line="${line#"${line%%[![:space:]]*}"}"
    if [[ -z "$line" || "$line" == '#'* || "$line" != *=* ]]; then
      continue
    fi
    name="${line%%=*}"
    value="${line#*=}"
    name="${name#export[[:space:]]}"
    name="${name//[[:space:]]/}"
    if [[ ! "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      continue
    fi
    upper="$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')"
    case "$upper" in
      PATH|PATHEXT|HOME|COMSPEC|IFS|ENV|CDPATH|GLOBIGNORE|SHELLOPTS|BASHOPTS|PROMPT_COMMAND|PS1|PS2|PS3|PS4|PSMODULEPATH|BASH_*|LD_*|DYLD_*|PYTHON*|DOCKER_*|COMPOSE_*|GIT_*|PIP_*|NODE_*)
        printf '%s\n' ".env.local: ignored $name, a name that changes how programs start (set it in your shell if you mean it)" >&2
        continue ;;
    esac
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    value="${value#\"}"; value="${value%\"}"
    value="${value#\'}"; value="${value%\'}"
    export "$name=$value"
  done < "$file"
}
load_env_local_as_data "$ENV_LOCAL"

# The same 127.0.0.1 addresses as the file above, for a .env.local that
# lacks a line. An existing .env.local is never rewritten, so one written
# before Alpha 6 keeps localhost until its owner edits it (Alpha 6
# pre-release check, 2026-09-23).
export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://noctornal:dev_only_change_me@127.0.0.1:5432/noctornal}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
export MINIO_ENDPOINT="${MINIO_ENDPOINT:-127.0.0.1:9000}"
export MINIO_ACCESS_KEY="${MINIO_ACCESS_KEY:-noctornal}"
export MINIO_SECRET_KEY="${MINIO_SECRET_KEY:-dev_only_change_me}"
export EVIDENCE_BUCKET="${EVIDENCE_BUCKET:-noctornal-evidence}"

if [[ $SKIP_LAUNCH -eq 1 ]]; then
  heading 'Done (nothing was started, because --skip-launch was given)'
  detail "To start it:  $0 --port $PORT"
  printf '\n'
  exit 0
fi

# ---------------------------------------------------------------------------
# 5. Containers
# ---------------------------------------------------------------------------

step 'Starting the services'
detail 'Four containers: Postgres, Redis, MinIO, Mailpit.'
detail 'The first time, Docker downloads about 1 GB, which can take several minutes.'
docker compose -f "$REPO_ROOT/infra/docker-compose.yml" up -d \
  || stop_with 'docker compose up failed.' \
"Read the output above, fix what it names, then run this installer again.
The usual causes are a port that is already taken (5432, 6379, 9000, 9001,
1025, 8025), or an image that could not be pulled. To stop a stale stack
that holds the ports:

    docker compose -f infra/docker-compose.yml down"

detail 'waiting for Postgres to report healthy'
# R17 (2026-07-26): the loop had no failure branch. Sixty exhausted probes
# simply fell through to the migrations, which then died with a raw psycopg
# traceback that reads as a broken install. `docker compose up -d` used to
# block on the postgres healthcheck via openfga-migrate's service_healthy
# condition, which MASKED this — and R13 removes OpenFGA, so the branch has
# to go in with that change rather than after it.
# `< /dev/null` IS LOAD-BEARING. `docker compose exec` forwards the
# parent's stdin to the container even with -T, which disables the TTY and
# not the attach, so sixty iterations of this loop drained whatever the
# installer was given. The account prompt below then read EOF, and under
# `set -e` the script ended there: no account, no API, exit 1, and the
# last thing printed was "Email: " with nothing after it. Every
# non-interactive install hit it (piped input, cron, CI, cloud-init,
# Ansible, ssh without a TTY); nobody typing at a terminal ever did,
# because a pty does not reach EOF, which is why this stood for so long.
# Measured on a clean VM, 2026-09-17: one `exec -T` left `read` with
# nothing, while `compose up -d` left it intact.
# `-h 127.0.0.1` IS LOAD-BEARING TOO (2026-09-30). On a fresh volume the
# image runs a TEMPORARY server for its init scripts, reachable only over
# the Unix socket, then stops it and starts the real one. A probe without
# -h answers on that socket, so the installer migrated in the gap and died
# with "the database system is starting up". Over TCP only the real
# server answers, as the compose healthcheck does.
PG_READY=0
for _ in $(seq 1 60); do
  if docker compose -f "$REPO_ROOT/infra/docker-compose.yml" \
       exec -T postgres pg_isready -h 127.0.0.1 -U noctornal -d noctornal \
       >/dev/null 2>&1 </dev/null; then
    good 'Postgres is ready'
    PG_READY=1
    break
  fi
  sleep 2
done
if [[ "$PG_READY" -ne 1 ]]; then
  stop_with 'Postgres did not become ready within two minutes.' \
"Look at the Postgres log, fix what it names, then run this installer again.
The container is up but not accepting connections:

    docker compose -f infra/docker-compose.yml logs postgres

The usual causes are a half-initialised data volume from an interrupted
first run, or port 5432 already taken by a local Postgres. For the first:

    docker compose -f infra/docker-compose.yml down -v

which DELETES the dev database and starts clean."
fi

# ---------------------------------------------------------------------------
# 6. Migrations
# ---------------------------------------------------------------------------
# From the REPOSITORY ROOT. alembic.ini lives there, and running from db/
# fails with "No 'script_location' key found in configuration", which reads
# as a broken install and is not one.

step 'Setting up the database'
( cd "$REPO_ROOT" && "$VENV/bin/alembic" upgrade head )
good "at $( cd "$REPO_ROOT" && "$VENV/bin/alembic" current 2>/dev/null | tail -1 )"

# ---------------------------------------------------------------------------
# Step 6: the first account. The password and the QR code are printed once by
# bootstrap.py, so when a person is at the keyboard the installer WAITS here
# until they say they have saved them: nothing printed later can push them off
# the screen. (install.ps1 used to hand off to launch.ps1, whose server log did
# exactly that: release finding R8.)
# ---------------------------------------------------------------------------

step 'Creating your account'
USERS="$( cd "$REPO_ROOT" && "$VENV_PY" - <<'PY'
import os
import psycopg
url = os.environ["DATABASE_URL"].replace("postgresql+psycopg", "postgresql")
with psycopg.connect(url) as c:
    print(c.execute("SELECT count(*) FROM iam.app_user").fetchone()[0])
PY
)"
# Declared out here: the closing output below reads them on every path, and
# under `set -u` an unset variable ends the script.
ADMIN_EMAIL=""; ADMIN_NAME=""
ACCOUNT_CREATED=0
if [[ "$USERS" == "0" ]]; then
  # R4 (2026-07-26): this called `bootstrap.py init`, which does not
  # exist -- argparse exits 2 and `set -e` then killed the install at the
  # account step, on every clean machine. The real command is
  # `create-user`, which is flag-driven and GENERATES the password rather
  # than asking for one, so the prompt below matches what happens.
  note 'No account exists yet. Creating one.'
  detail 'Enter your email address (you sign in with it) and a display name.'
  detail 'A strong password is made for you and shown once, with a QR code'
  detail 'for an authenticator app (any TOTP app on your phone will do).'
  printf '\n'
  # `|| true` is not decoration either. `read` returns non-zero at EOF,
  # and `set -e` acts on that BEFORE the emptiness test below, so the
  # branch written to handle "they gave nothing" was unreachable: the
  # script simply stopped, mid-sentence, with no message at all. Anything
  # that is not a terminal reaches EOF here.
  #
  # A person at the keyboard gets three tries at an address that is not one.
  # Standard input that is not a terminal is read once, as it always was:
  # the harness feeds an email, then a name, and nothing else.
  for _attempt in 1 2 3; do
    printf '    Email: '
    read -r ADMIN_EMAIL || true
    printf '    Display name: '
    read -r ADMIN_NAME || true
    if [[ $INTERACTIVE -eq 1 && -n "$ADMIN_EMAIL" && "$ADMIN_EMAIL" != *@* ]]; then
      note 'That does not look like an email address. Try again.'
      ADMIN_EMAIL=""
      continue
    fi
    break
  done
  printf '\n'
  if [[ -z "$ADMIN_EMAIL" || -z "$ADMIN_NAME" ]]; then
    note 'Skipped: both an email and a display name are needed.'
    detail 'Create one later with:'
    detail "  .venv/bin/python scripts/bootstrap.py create-user \\"
    detail "      --email you@example.org --name 'Your Name'"
    ADMIN_EMAIL=""
  else
    detail 'Your password and the QR code are printed next. They are shown once.'
    ( cd "$REPO_ROOT" && "$VENV_PY" scripts/bootstrap.py create-user \
        --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" ) \
      || stop_with 'the account could not be made.' \
"Fix what the lines above name, then run this installer again.
Everything before this step is kept, so it picks up where it stopped."
    ACCOUNT_CREATED=1
    if [[ $INTERACTIVE -eq 1 ]]; then
      printf '\n'
      note 'Save the password and scan the QR code now. They are not shown again.'
      printf '    Press Enter when you have saved them: '
      read -r _saved || true
      printf '\n'
    fi
  fi
elif [[ "$USERS" == "1" ]]; then
  good '1 account already exists'
else
  good "$USERS accounts already exist"
fi

# ---------------------------------------------------------------------------
# Step 7: the fictional demo case. Asked only of a person at the keyboard who
# has just made their first account, and defaulting to yes. Without a terminal
# nothing is asked, because a question there would eat the lines the account
# prompt reads: the demo loads only with --demo. It is the synthetic
# TLP:CLEAR network `bootstrap.py demo-network` makes, and the installer says
# it is fictional.
# ---------------------------------------------------------------------------

step 'Loading the demo case (optional)'
DEMO_CODE_NAME="OP-LATTICEWORK-26"
DEMO_DECISION="$(decide_demo "$DEMO_MODE" "$INTERACTIVE" "$ACCOUNT_CREATED")"
DEMO_LOADED=0
DEMO_OWNER="$ADMIN_EMAIL"
if [[ "$DEMO_DECISION" == "ask" ]]; then
  detail 'A fictional case with made-up people and ties, so there is something'
  detail 'to look at straight away. It is marked TLP:CLEAR and holds nothing real.'
  printf '    Load the synthetic demo case so there is something to explore? [Y/n] '
  read -r DEMO_ANSWER || true
  if [[ "$(answer_is_yes "${DEMO_ANSWER:-}")" == "yes" ]]; then DEMO_DECISION=load; else DEMO_DECISION=skip; fi
  printf '\n'
fi
if [[ "$DEMO_DECISION" == "load" ]]; then
  if [[ -z "$DEMO_OWNER" ]]; then
    # --demo on a re-run: the earliest active Lead investigator owns it.
    DEMO_OWNER="$( cd "$REPO_ROOT" && "$VENV_PY" - 2>/dev/null <<'PY'
import os
import psycopg
url = os.environ["DATABASE_URL"].replace("postgresql+psycopg", "postgresql")
with psycopg.connect(url) as c:
    row = c.execute(
        "SELECT u.email FROM iam.app_user u"
        " JOIN iam.user_role ur ON ur.user_id = u.id"
        " WHERE ur.role_key = 'CASE_OWNER' AND u.is_active"
        " ORDER BY u.created_at LIMIT 1"
    ).fetchone()
    print(row[0] if row else "")
PY
)" || DEMO_OWNER=""
  fi
  if [[ -z "$DEMO_OWNER" ]]; then
    note 'The demo case needs an account to own it, and none was found.'
  elif ( cd "$REPO_ROOT" && "$VENV_PY" scripts/bootstrap.py demo-network \
           --owner-email "$DEMO_OWNER" --code "$DEMO_CODE_NAME" --classification CLEAR ); then
    DEMO_LOADED=1
    good "demo case loaded: Operation Latticework, code $DEMO_CODE_NAME"
    detail 'It is fictional: made-up names and ties, marked TLP:CLEAR. Find it in the case list.'
  else
    note 'The demo case was not loaded. The lines above say why.'
    detail 'If it is already there from an earlier run, that is fine.'
  fi
elif [[ "$DEMO_MODE" == "no" ]]; then
  detail 'Skipped, because --no-demo was given.'
else
  detail 'Skipped. The closing card says how to load it later.'
fi

# ---------------------------------------------------------------------------
# Step 8: start the API, and say what to do next.
#
# The port was checked in step 1, so a re-run while the API is already up said
# what was wrong before anything was built. The Security Officer count is
# read, not assumed, so a re-run on a stack that has one says nothing about
# it; a count that cannot be read prints the advice anyway, because it costs
# less than a blocked collection nobody can explain (Alpha 6 pre-release
# check, 2026-09-23).
# ---------------------------------------------------------------------------

step 'Starting the API'
OFFICERS="$( cd "$REPO_ROOT" && "$VENV_PY" - 2>/dev/null <<'PY'
import os
import psycopg
url = os.environ["DATABASE_URL"].replace("postgresql+psycopg", "postgresql")
with psycopg.connect(url) as c:
    print(c.execute(
        "SELECT count(DISTINCT u.id) FROM iam.app_user u"
        " JOIN iam.user_role ur ON ur.user_id = u.id"
        " WHERE ur.role_key = 'SECURITY_OFFICER' AND u.is_active"
    ).fetchone()[0])
PY
)" || OFFICERS=""
OWNER_EMAIL="${DEMO_OWNER:-you@example.org}"

warn() { printf '  %s%s%s\n' "$C_YELLOW" "$1" "$C_OFF"; }

# Open the console once the API answers, from the background so uvicorn can
# stay in the foreground and keep Ctrl-C. It gives up after a minute.
open_when_up() {
  local url="$1" i
  for i in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
      if [[ "$(uname -s 2>/dev/null)" == "Darwin" ]]; then open "$url" || true; else xdg-open "$url" || true; fi
      return 0
    fi
    sleep 1
  done
}

DESKTOP="$(has_desktop)"
OPEN_DECISION="$(decide_open "$OPEN_BROWSER" "$INTERACTIVE" "$DESKTOP")"
if [[ "$OPEN_BROWSER" == "1" && "$DESKTOP" != "1" ]]; then
  note 'No desktop was found, so no browser will be opened. Open the address below yourself.'
fi
if [[ "$OPEN_DECISION" == "ask" ]]; then
  printf '    Open the console in your browser when it is ready? [Y/n] '
  read -r OPEN_ANSWER || true
  if [[ "$(answer_is_yes "${OPEN_ANSWER:-}")" == "yes" ]]; then OPEN_DECISION=open; else OPEN_DECISION=skip; fi
fi

printf '\n  %s------------------------------------------------------------%s\n' "$C_GREEN" "$C_OFF"
printf '  %sYou are ready.%s\n' "$C_GREEN" "$C_OFF"
printf '  %s------------------------------------------------------------%s\n' "$C_GREEN" "$C_OFF"
detail "console:  http://127.0.0.1:$PORT/ui/"
if [[ -n "$ADMIN_EMAIL" ]]; then
  detail "sign in:  $ADMIN_EMAIL, with the password from step 6"
else
  detail 'sign in:  your email and password'
fi
detail '          then the six-digit code from your authenticator app'
detail "start:    next time, run: cd '$REPO_ROOT' && bash release/start.sh"
detail 'stop:     press Ctrl-C here. The containers keep running; to stop them too, from that folder:'
detail '          docker compose -f infra/docker-compose.yml down'
detail 'help:     release/START-HERE.md, and release/MANUAL.md for what each pane does'
printf '\n'
warn 'This is a beta: use it on synthetic or published, non-personal data only.'
warn 'Real case material needs legal review first (docs/16, "Read this before you hold anything").'
if [[ "$DEMO_LOADED" -eq 0 ]]; then
  printf '\n'
  printf '  To load the fictional demo case later, from %s:\n' "$REPO_ROOT"
  printf '      .venv/bin/python scripts/bootstrap.py demo-network --owner-email %s --code %s --classification CLEAR\n' "$OWNER_EMAIL" "$DEMO_CODE_NAME"
fi
printf '\n'
printf '  The bigger showcase case the README screenshots come from is in\n'
printf '  README.md, section "First run".\n'
if [[ "$OFFICERS" == "0" || -z "$OFFICERS" ]]; then
  printf '\n'
  warn 'Nobody holds the Security Officer role yet, so collection runs and break-glass'
  warn 'are refused. That does not matter for the demo. To fix it, give the role to a'
  warn 'second person, not to your own account (release/INSTALL.md, "After installing"):'
  # security.officer@, not officer@: officer@example.org is the account
  # seed_readme_showcase.py creates, so after the README recipe this
  # command exited 1 with "already exists", and run first it would have
  # made the seeder adopt the real officer (Alpha 6 pre-release check,
  # 2026-09-23).
  printf '      .venv/bin/python scripts/bootstrap.py create-user --email security.officer@example.org --name "Officer Name" --roles SECURITY_OFFICER\n'
fi
printf '\n'
printf '  %sUploading samples is refused until a prohibited-content policy is%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sdeclared (README, L1). That refusal is deliberate.%s\n' "$C_YELLOW" "$C_OFF"
printf '\n'
printf '  The API log follows below. Leave this window open while you use it.\n'
printf '\n'

cd "$REPO_ROOT"
if [[ "$OPEN_DECISION" == "open" ]]; then
  open_when_up "http://127.0.0.1:$PORT/ui/" >/dev/null 2>&1 &
fi
exec "$VENV/bin/uvicorn" noctornal_api.http.app:app \
     --host 127.0.0.1 --port "$PORT"

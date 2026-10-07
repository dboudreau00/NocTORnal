# Clean-machine installs: the record

Each run installs NocTORnal on a machine that has never seen it, following
the documentation as a new user would. The newest run is first and is kept
in full. Earlier runs are condensed to what was run, the result and the
defects they found. The finding ids (R, F and G) are the ones the code and
the tests cite: `test_script_invariants.py` names R25 to R28, and
`constraints.txt` and `test_dependency_pins.py` name F17 and G9.

| Date | Artefact | Result | Install command to a working console | Disk added |
|---|---|---|---|---|
| 2026-10-07 | Beta 1 release candidate, packaged from git | PASS | 6 min 11 s | not recorded |
| 2026-10-07 | Beta 1 zip as `scripts/package_release.ps1 -Zip` makes it | PASS WITH NOTES | 7 min 41 s | 1.49 GB |
| 2026-09-24 | Alpha 6 working tree with the 2026-09-23 fixes | PASS WITH FINDINGS | 72 s | 1.37 GB |
| 2026-09-23 | Alpha 6 release candidate, `git archive` of `main` at `a859e9e` | PASS WITH FINDINGS | 85 s | 1.4 GB |
| 2026-09-17 | `git archive HEAD` of `main` at `4c43ea8` | FAIL on first run, all five findings fixed the same day | stopped before it | 1.9 GB |

## Beta 1 release candidate, 2026-10-07

**Result: PASS.** The release candidate, packaged from git exactly as the
release is, on a machine rebuilt again from its base image, with START-HERE's
prerequisites and nothing else: `bash release/install.sh --demo` ran all eight
steps with no traceback, the console answered after 6 minutes 11 seconds (most
of it pulling 1.1 GB of images) and the first sign-in, password and
authenticator code, was accepted at 6 minutes 52 seconds. The walkthrough ran
its six steps, the demo case's analysis named its broker, a new case took an
exhibit and a tie citing it, and a stop, a start, a reboot and a start again
kept everything. After a reboot nothing runs until `bash release/start.sh`.
One thing a new user may meet: a tab chosen while a case is still opening is
switched back to Graph when the case finishes loading; choosing it again
works.

## Beta 1 run, 2026-10-07

**Result: PASS WITH NOTES.** A new user who follows START-HERE on a pristine
Ubuntu 24.04 machine gets a working console: one command installs it, they
sign in with a password and an authenticator code, the walkthrough shows, and
real work succeeds. Nothing found blocks a beta used on non-sensitive data.
Nine installer and document defects were found and fixed, each with a
regression test, and the fixes were proved on the machine.

**Machine and package.** An Ubuntu 24.04 virtual machine rebuilt from its base
image, with no Docker, no `unzip`, no Python and no venv package. The release
zip as `scripts/package_release.ps1 -Zip` makes it: 1,108 entries.

**What was run.**

- The installer without its prerequisites stopped at step 1 on the venv
  package and left nothing on disk; without the docker group it stopped on
  "engine is not reachable". Both messages said what to do. The prerequisites
  as START-HERE names them took 252 seconds.
- `bash release/install.sh --demo`, answers from a file and no terminal:
  `/ui/` answered after 461 seconds, about 5.5 minutes of it pulling 1.1 GB of
  images. The database was at its head revision, the account and the demo case
  existed, there was no traceback, everything listened on 127.0.0.1 only,
  `.env.local` was mode 600, and the install added 1.49 GB (`.venv` is 273 MB
  of it).
- The console, in Chromium 153 inside the machine: sign-in took 0.5 seconds,
  the six-step tour opened by itself and Help, Getting started opened it
  again. On the demo case the graph, the entities, Analysis (which names
  `oriel` after Run analysis) and Search worked. A new case, an exhibit upload
  (its SHA-256 shown), two entities and a MEMBER_OF link citing the exhibit (3
  of 3 elements evidenced) and the readiness page (11 of 45 checks need
  attention, 4 blocking) all worked. 24 screenshots were taken.
- Stop and start (Ctrl+C, `docker compose down`, `bash release/start.sh`):
  21 seconds with the data intact. Re-running the installer while the API was
  up stopped in step 1; stopped, it re-ran fully in 31 seconds with
  `.env.local` unchanged byte for byte. After a reboot the containers do not
  come back on their own (they have no restart policy); `start.sh` brought
  everything up in 19 seconds. An uninstall and reinstall at a pseudo-terminal
  (email, display name, Enter, Enter) was up in 58 seconds, the demo question
  included.

What a user must do by hand on Linux: install the venv package
(`sudo apt update && sudo apt install python3.12-venv`), install Docker Engine
with its Compose plugin, add themselves to the docker group
(`sudo usermod -aG docker $USER`) and log out and in, and on a server image
install `unzip`. Every user must save the password and enrol the TOTP secret
(the QR is drawn for a dark terminal; on a light one, type the secret in),
keep the installer's terminal open while using the console, run
`bash release/start.sh` after every reboot, choose Run analysis in the
Analysis pane, make a second account for the Security Officer role, and reach
the console of a remote machine through an SSH tunnel. Preparing a bare Ubuntu
first took about 4 minutes more.

**Defects found, each fixed:**

- medium, the packager: under Windows PowerShell 5.1 all 1,108 zip entries were
  stored with backslashes, so `unzip` warned and exited 1 and Python's zipfile
  extracted loose files and no folders (PowerShell 7 writes correct zips). The
  packager names every entry itself and refuses a backslash.
- low, `bootstrap.py` create-user and both installers: the "Next" block said to
  sign in before the API was up, and to load a showcase case right before step
  7 offers the demo (`--no-next`).
- low, step 7: a re-run with `--demo` said "case code already in use", and the
  closing card offered the same failing command.
- low, `install.sh`: it printed `./release/install.sh --port 8001` and
  `$0 --port`, which fail with "Permission denied" on a file with no execute
  bit. Every printed command runs the script through bash.
- low, step 1 preview: it said "write .env.local with fresh random keys" on a
  re-run, where the user's keys were already copied in.
- low, README "Verifying the install": it ran `set -a; . ./.env.local`,
  executing the file, where INSTALL.md reads it as data.
- low, START-HERE: the Docker link sent Linux users to Docker Desktop, its
  check passes before the docker group step that stops the install, and
  `unzip` is absent on server images.
- low, START-HERE: "Open Analysis. It singles out oriel" while the pane is
  empty until Run analysis, which then lists `mer_florin` first.
- low, INSTALL.md: no word on reaching the console of a machine installed over
  SSH.
- consistency: the README and INSTALL prerequisites disk figures (now this
  run's measurements, with a test holding the two tables equal), the counters
  (now generated by `scripts/refresh_counters.py`), and `release/README.md`,
  still titled Alpha.
- info: `core.autocrlf=true` on the packaging host makes `.py` and `.md` files
  CRLF inside a zip built on Windows (`.sh` stays LF), which works; and
  `pgvector:pg16` and `redis:7-alpine` in `infra/docker-compose.yml` are
  floating tags (docs/17).

**How it was checked.** The authenticator codes were computed from the printed
secret. The browser was headless Chromium. The reinstall proved the fixes from
an overlay on the packaged tree. Listening addresses were checked with `ss`
inside the machine.

## Alpha 6 final re-run, 2026-09-24

**Artefact:** the Alpha 6 working tree with the 2026-09-23 fixes applied,
before it was committed: 444 files, 5,920,545 bytes, packed on the Windows
development machine, so 374 of its 426 text files had CRLF line endings. A
file-by-file comparison with git's own LF build of the same tree
(`core.autocrlf=false`, which is what GitHub serves) found 70 files identical,
374 differing only in line endings and none differing in anything else.
**Host:** the same VM, rebuilt again from the untouched cloud image.

**Result: PASS WITH FINDINGS.** F19 is fixed: every bundled service listens on
127.0.0.1 only and is refused on the guest's external address and on the
Docker bridge address, from the guest and from a container on Docker's default
bridge (and on `[::1]`, from the guest), while sshd's port 22 connected as the
control. The install
worked first time in 72 seconds, with `.env.local` mode 600, migrations at
`0065` and no RATE-LIMIT line, warning or traceback in 941 log lines. The
readiness register reported, the README's First run completed (`demo-network`,
the five seeders and `bootstrap.py session` each exited 0; the showcase case
has 20 nodes and 22 edges and each of four selector searches found its
identifier) and the installer's closing advice worked as printed. After
seeding, the register read with a 35-minute-old session link answered 403
"re-authentication required"; after a fresh password and TOTP sign-in it was
not ready with three blocking checks and `security_officer_present` passing.
Re-running the installer while the API was up stopped with "port 8000 is
already in use"; the restart after `docker compose down` took 10 seconds. The
suite with no services configured, on the installed CRLF tree and on git's LF
build, gave 2107 passed, 1535 skipped and 1 failed of 3643 collected (the
counter check, G1): line endings changed nothing.

Measured: 1.37 GB added by the install and the showcase seed, 1.097 GB of
images, 294 MiB of containers, a 189 MB `.venv`, 65 migration files from empty.

| Id | Finding | Where it stands |
|---|---|---|
| G1 medium | The documents quoted 2518 tests where the tree had 2568, so the counter check failed on both trees. | Fixed: `scripts/refresh_counters.py` generates every quoted counter and `test_doc_invariants` fails on any that is not exact |
| G2 low | `refresh_counters.py` crashed on Python 3.12 (`Path.read_text` takes `newline` only from 3.13). | Fixed: it reads bytes |
| G3 low | The example Security Officer address, `officer@example.org`, was the showcase seeder's own, so the printed command exited 1. | Fixed: `security.officer@example.org` |
| G4 low | `bootstrap.py create-user` still printed `python scripts/bootstrap.py demo-case`, which exits 127 on a stock Ubuntu. | Fixed: it prints the console address and the README's First run command with the project's interpreter |
| G5 low | `ARCHITECTURE.md`, `docs/16` C8 and a compose comment still called the development Redis `allkeys-lru`. | Fixed, and in the register's advice |
| G6 low | `release/README.md`, `release/MANUAL.md` and `ARCHITECTURE.md` still counted four legal items. | Fixed: five |
| G7 low | `release/MANUAL.md` said a rejection destroys the sample. | Fixed: preserved by default, destroyed only under `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=destroy` and never under a legal hold |
| G8 info | Mailpit logs that its API is reachable from any host that can route to its interface. | Documented in INSTALL.md: it describes the stack's own network |
| G9 info | Nothing is pinned: starlette 1.7.0, uvicorn 0.53.0, alembic 1.20.0, psycopg 3.3.6, SQLAlchemy 2.0.54, `axllent/mailpit:latest` (v1.31.2). | Left, as F17 |
| G10 info | INSTALL.md said only that a suite run with `DATABASE_URL` writes permanent rows; `test_compartment_binding_pg.py` also downgrades the database to `0058` and back. | Fixed: the recipe makes a scratch database and says why |
| G11 info | The changelog had no collected total for the release. | Fixed: the Alpha 6 section records the collected total of the release run |
| G12 info | This document's header called the artefact byte-for-byte GitHub's download; it was CRLF. | Corrected |
| G13 info | INSTALL.md did not say the register needs a sign-in from the last 15 minutes. | Fixed |

## Alpha 6 re-run, 2026-09-23

**Artefact:** `git archive` of `main` at `a859e9e`, the Alpha 6 release
candidate: 5,880,969 bytes, and `git get-tar-commit-id` inside the guest read
back `a859e9e`. It was made on the same Windows clone, so 400 of its 418 text
files had CRLF line endings, where GitHub's download of that commit has LF.
**Host:** the same VM, rebuilt from the untouched Ubuntu 24.04 cloud image:
Ubuntu 24.04.5 LTS, kernel 6.8, 4 vCPU, 8 GB RAM, 40 GB disk, Python 3.12.3, and
at first boot no Docker, no `python3.12-venv`, no pip, no `python` command and
package lists never fetched.

**Result: PASS WITH FINDINGS.** Nothing stopped an install except the
installer's own stops, and each named the next action: the venv package
("ensurepip missing", with `apt update` not yet named, F7), Docker, and the
docker group. The full install answered on `/ui/` after 85 seconds, 1.1 GB of
image pulls included; `.env.local` was mode 600 and declared the raw and
preservation buckets, the rejected-sample disposition and both size caps;
migrations reached `0065`; the account was created from answers in a file with
no terminal (clearance RED, CASE_OWNER and SYS_ADMIN). From inside the guest
`/healthz` answered ok, `/api/v1/auth/me` 401 without a session and `/docs`
and `/openapi.json` 404. The buckets, read with the MinIO client library and
`mc stat`: `noctornal-evidence` versioned with a GOVERNANCE 365-day default and
a per-object COMPLIANCE retention on every object, `noctornal-raw` and
`noctornal-samples` without a lock, and `noctornal-preserved` versioned and
locked with no default retention, where a probe object under a legal hold could
not be deleted by version. A printed password and a TOTP code computed from the
printed secret gave 204 and both `__Host-` cookies. The readiness register was
not ready: four blocking checks before seeding, and the showcase seeder's
officer account took them to three. The README's First run completed. One
finding was high, every bundled service listening on every interface (F19).
Re-running the installer while the API was up repeated every step and ended in
uvicorn's "address already in use" with exit 3 (F9); `docker compose down` kept
the volumes and the next run served `/ui/` after 16 seconds. The suite with no
services configured gave 1995 passed, 1533 skipped and 0 failed of 3528
collected, in 58 seconds.

Measured: 1.4 GB added by the install and the showcase seed (after about 0.75
GB for Docker Engine and the venv package), 1.10 GB of images, 301 MiB of
containers after the seed (minio 229, postgres 61, mailpit 7, redis 3.5), a 189
MB `.venv`, 65 migration files from empty.

The exposure was tested from a second network namespace on the guest.

| Id | Finding | Where it stands |
|---|---|---|
| F19 high | Postgres (as a superuser), the MinIO root, Redis and Mailpit were published on 0.0.0.0 and `[::]` and answered from another network namespace with the credentials written in the repository; with ufw denying incoming traffic they still answered, because Docker forwards a published port before ufw sees it. | Fixed: the compose file publishes every port on 127.0.0.1 only and `test_compose_exposure.py` refuses any other binding; SECURITY.md, INSTALL.md and the README say so |
| F1 medium | The README's L1 row said a rejected sample's bytes are destroyed; since `0063` they are preserved by default. | Fixed: `test_install_copy.py` holds the row to the code's default |
| F2 medium | INSTALL.md expected "1252 passed, 12 skipped" and "roughly 700 skips". | Fixed: no totals; it says what skips without which setting; held by `test_install_copy.py` |
| F3 medium | INSTALL.md carried two BACKSPACE bytes where `scripts\bootstrap.py` belonged, in both Windows recovery commands, in every release from Alpha 1 to Alpha 5.2. | Fixed: `check_source_hygiene.py` refuses every control byte except tab, line feed and carriage return in every tracked text file |
| F4 medium | The first command printed after the account was made, `python scripts/bootstrap.py demo-case`, fails on stock Ubuntu, names the wrong seeder and offered an API login to someone about to use the console. | Fixed: the closing output gives the console address and the README's First run recipe with each platform's interpreter (G4) |
| F5 low | README First run asked for `create-user` although the installer had made the account. | Fixed |
| F6 low | The banners and INSTALL.md said four legal decisions and pointed at a README section that does not exist. | Fixed: five, L1 to L5, and the heading that exists (G6) |
| F7 low | The venv advice fails on a fresh image until `apt update` has run. | Fixed in both Debian messages |
| F8 low | Every API start printed "RATE-LIMIT REDIS EVICTS KEYS" over a setting the bundled stack chose. | Fixed: the bundled Redis runs `noeviction` (G5) |
| F9 low | INSTALL.md quoted a port-in-use message only `launch.ps1` printed. | Fixed: `install.sh` checks the port and stops with it |
| F10 low | The two prerequisites tables disagreed with each other and with the measured install, and neither named `python3.12-venv`. | Fixed: one table, the same in both |
| F11 low | The README and INSTALL.md said the installer opens the console; it prints the address. | Fixed |
| F12 low | `launch.sh` named 8080 and 4222, the ports of removed services, and not Mailpit's 1025. | Fixed, held to the compose file's ports |
| F13 low | `alembic current` in a second terminal ended in a traceback. | Fixed: a one-line refusal naming `.env.local` |
| F14 low | `install.sh --help` printed `set -euo pipefail`. | Fixed in `install.sh` and `launch.sh` |
| F15 low | The minio-init log opened with an ERROR on every clean start. | Fixed: the wait is quiet and bounded |
| F16 low | Printed copy outside the server still carried em dashes and spaced double hyphens; the CLI prints role keys where the console shows names. | Dashes fixed, held by `test_install_copy.py`; role keys left |
| F17 info | Python dependencies and the Mailpit image are unpinned, so a clean install ran newer versions than development. | Left |
| F18 info | `mc retention info --default` reports the preservation bucket as having no object lock. | Documented: the register's `preservation_bucket_object_lock` check is the witness |
| F20 info | Redis logs a memory-overcommit warning on every start. | Documented as harmless for an evaluation install |
| | The installer's account holds no SECURITY_OFFICER role, so `security_officer_present` blocks a fresh install. | Documented, with the command that makes a second person the officer |

## First clean-machine run, 2026-09-17

**Artefact:** `git archive HEAD` of `main` at `4c43ea8`, made on the Windows
development clone, where `core.autocrlf=true` made 345 of the archive's 363
text files CRLF. **Host:** a VM built for this and nothing else: Ubuntu
24.04.5 LTS from the official cloud image, 4 vCPU, 8 GB RAM, 40 GB disk,
VMware Workstation, Python 3.12.3 as shipped, no Docker and no build tools.

**Result: FAIL on first run.** All five findings were fixed and re-verified on
the same VM the same day, and a single non-interactive run then installed and
served. Three defects stopped a new user and the suite could not see any of
them, because `test_script_invariants.py` holds both installers textually and
nothing executed one. Two of the three stopped every Debian or Ubuntu user.
What worked: the application is located as the installer's parent directory (a
copy placed in `/tmp` is refused with the right message); the missing-Docker
message stops at the right step with exit 1 and leaves nothing on disk; Docker
installed but not reachable is told apart from not installed and names
`usermod -aG docker`; `.env.local` is left alone on a re-run; and the end
state was migrations at `0061`, the console serving at `/ui/`,
`/api/v1/auth/me` 200 for a minted session and four blocking readiness
failures, all four the legal declarations. Measured: 1.9 GB of disk added
(2.0 GB to 3.9 GB), 304 MB of container memory idle across all four, a 189 MB
`.venv`.

| Id | Finding | Fix |
|---|---|---|
| R25 blocking, every Debian-family host | Ubuntu 24.04 ships `python3.12` without `python3.12-venv`. The guard asked for `import venv`, which succeeds on a machine that cannot build one, so the failure came two steps later in Python's voice, not the installer's. | The guard asks for `ensurepip` and names the versioned package of the interpreter it selected |
| R26 blocking | A failed `venv` leaves a half-built `.venv` (`bin/python`, no pip) that the idempotency check accepted, so every later run said "No module named pip" and installing the named package did not recover it. | The check requires `bin/pip`, a half-built environment is recognised and rebuilt, and a failed `venv` removes its partial directory; `install.ps1` has the same treatment |
| R27 blocking for non-interactive installs | `docker compose exec -T` forwards the parent's stdin, so by the account prompt stdin was at EOF and `read` ended the script under `set -e`, silently; the fallback written for that case was unreachable. | The readiness probe reads `</dev/null` and both prompts are `read -r ... \|\| true` |
| R28 minor here, blocking in production | The generated `.env.local` omitted the upload caps and `INGEST_BUCKET`, so promoting it to a deployment met a boot refusal with no hint. | Both installers write `NOCTORNAL_MAX_EVIDENCE_BYTES=256MB`, `NOCTORNAL_MAX_SAMPLE_BYTES=64MB` and `INGEST_BUCKET=noctornal-raw` |
| R29 cosmetic | The shell scripts shipped as `100644`, so `./release/install.sh` answered "Permission denied". | `100755` in the tree; the documented `chmod +x` stayed, because a zip may not carry the bit |

`test_script_invariants.py` holds R25 to R28 with
`test_the_venv_guard_asks_for_ensurepip_not_just_venv`,
`test_a_half_built_venv_is_not_mistaken_for_a_good_one`,
`test_the_readiness_probe_does_not_eat_the_installers_stdin`,
`test_the_account_prompt_survives_end_of_input` and
`test_the_generated_env_declares_the_upload_caps`. They read the source.

# Clean-VM install, Linux, step by step

**Date:** 2026-09-17
**Artefact tested:** `git archive HEAD` of `main` at `4c43ea8`, made on
the Windows development clone. That clone sets `core.autocrlf=true`, so
345 of the archive's 363 text files have CRLF line endings, where
GitHub's "Download ZIP" of the same commit has LF. The files and their
content are the commit's; the bytes are not what GitHub serves. Section
10 compares the two on a later tree.
**Host:** a VM built for this and nothing else. Ubuntu 24.04.5 LTS from
the official cloud image, 4 vCPU, 8 GB RAM, 40 GB disk, VMware
Workstation. Python 3.12.3 as shipped. No Docker, no build tools, no
Python packaging beyond the base image.

**Result: FAIL on first run. All five findings fixed and re-verified on
the same VM the same day; a single non-interactive run now installs and
serves.**

Three defects stop a new user, and the suite cannot see any of them.
`test_script_invariants.py` does hold both installers, but textually: it
reads them and asserts on their source. Nothing executes one. Two of the
three defects stop *every* Debian or Ubuntu user, which is the most
likely host for this software.

> The Windows counterpart of this exercise was `TestFlight.md`,
> 2026-07-26, deleted in the documentation pass on 2026-09-16 as a stale
> record of a superseded commit. This is the Linux half, run for the
> first time.

---

## 0) Why this document exists

`release/INSTALL.md` promises that the installer "checks what it needs
and tells you exactly what to do if one is missing, rather than failing
halfway". That promise had never been tested against a machine that was
not already a development box. This is that test.

Every command below was run, in this order, and the output quoted is the
output received.

---

## 1) What worked, and is worth keeping

- **Locating the application.** The "the project is my parent directory"
  rule resolved correctly, and a copy placed in `/tmp` was refused with
  the right message. One rule, no search.
- **The missing-Docker message.** Stops at the right step, exit code 1,
  names the platform-specific next action, leaves nothing on disk.
- **Docker installed but not reachable.** Distinguished from "not
  installed", which is the distinction that matters, and it names
  `usermod -aG docker` rather than telling you to use `sudo`.
- **Idempotency, where it is reached.** `.env.local` is left untouched on
  a re-run, containers already up are recognised as running.
- **The end state.** Migrations to `0061` head, console at `/ui/` serving
  132 KB with the right title, `app.js` 445 KB, `/api/v1/auth/me` 200 for
  a minted session. Four blocking readiness failures, all four the legal
  declarations, which is deliberate and correct.

---

## 2) R25: `python3 -m venv` does not work on a stock Debian or Ubuntu

**Blocking. Every Debian-family host.**

Ubuntu 24.04 ships `python3.12` and does **not** ship `python3.12-venv`:

```
  matching installed packages: 0
  python3.12-venv:
    Installed: (none)
    Candidate: 3.12.3-1ubuntu0.17
```

A guard for exactly this existed and did not fire, which is the
interesting part:

```bash
if ! "$PYTHON" -c 'import venv' >/dev/null 2>&1; then
  stop_with "Python is installed but the venv module is missing."
```

`import venv` **succeeds** on a machine that cannot build one. `venv/`
ships in `python3-minimal`; `python3.12-venv` carries `ensurepip` and the
pip wheel it installs. Measured on the VM with the package removed:

```
  import venv        -> SUCCEEDS  (so the guard passes)
  import ensurepip   -> FAILS     (this is the real test)
  python3.12 -m venv -> NONZERO
```

So the step reports success:

```
  Checking Python
    Python 3.12 at /usr/bin/python3.12
```

and then fails two steps later in Python's voice, not its own:

```
  Building the Python environment
    creating .venv (this takes a moment)
The virtual environment was not created successfully because ensurepip is not
available.  On Debian/Ubuntu systems, you need to install the python3-venv
package using the following command.

    apt install python3.12-venv
```

Every other prerequisite failure gets a formatted `Cannot continue: ...`
/ `What to do:` block. This one does not, which is precisely the
"failing halfway" the document promises does not happen.

**Fixed 2026-09-17.** The guard now asks for `ensurepip` as well as
`venv`, and names the versioned package derived from the interpreter it
selected, because `apt install python3-venv` on a host whose default
`python3` is not that interpreter installs the wrong one and changes
nothing. Re-verified on the same VM: it stops at the Python step, in the
installer's own voice, with exit 1 and nothing written to disk.

---

## 3) R26: the failed environment is left behind, and the next run reports something else entirely

**Blocking, and worse than R25, because it hides it.**

The failed `venv` does not clean up after itself. What it leaves looks
real:

```
  .venv EXISTS
  interpreter present? yes
  pip present?         no
```

The idempotency check was `[[ -x "$VENV_PY" ]]`, which that wreckage
satisfies: it asks for `bin/python`, and a failed `venv` links the
binaries before it dies at `ensurepip`. So the second run takes the
"already built" path:

```
  Building the Python environment
    .venv already exists
    installing dependencies
/home/tester/noctornal/.venv/bin/python: No module named pip
```

**The second message is further from the cause than the first.** Run one
names the package to install. Run two, and every run after it, says
`No module named pip`, which sends the reader to pip, to `ensurepip`, to
their Python install: everywhere except the half-built directory that is
actually the problem.

Verified: installing exactly what run one named, and re-running, **does
not recover**. Same error, exit 1. Only `rm -rf .venv` does, and nothing
in the output, in `INSTALL.md` or in `README.md` tells anyone that.

This is the mirror of the hazard `install.sh`'s own header comment
describes at length for Windows, where the check says *no* over a working
environment. Here it says *yes* over a broken one.

**Fixed 2026-09-17.** The check now requires `bin/pip` as well as
`bin/python`, a half-built environment is recognised, named and rebuilt
rather than used, and a failed `venv` removes its partial directory so
the next run starts clean either way. Re-verified by manufacturing the
exact wreckage (`python3.12 -m venv` with `ensurepip` missing), then
installing the package and re-running: `a previous run left a half-built
.venv (no pip); rebuilding it`, then exit 0 with both packages importing.
`install.ps1` had the same shape and got the same treatment.

---

## 4) R27: the readiness loop eats stdin, and the account prompt dies silently

**Blocking for every non-interactive install. Invisible to anyone at a
keyboard.**

The Postgres readiness loop runs, up to sixty times:

```bash
docker compose -f "$REPO_ROOT/infra/docker-compose.yml" \
  exec -T postgres pg_isready -U noctornal
```

`docker compose exec` forwards the parent's stdin to the container even
with `-T`, which disables the TTY but not the attach. Measured, against
a two-line file:

```
  after one 'compose exec -T': read got []
  after 'compose up -d':       read got [FIRSTLINE]
```

So by the time the installer reaches

```bash
printf '    Email: '
read -r ADMIN_EMAIL
```

stdin is at EOF. `read` returns 1. The script runs under `set -euo
pipefail`, so **it exits there**, and the fallback written for exactly
this case

```bash
if [[ -z "$ADMIN_EMAIL" || -z "$ADMIN_NAME" ]]; then
  note 'Skipped: both an email and a display name are needed.'
```

is unreachable: `set -e` fires before the test. Confirmed in isolation,
where the fallback never prints and the exit code is 1.

What the user sees is the installer stopping mid-sentence:

```
  Checking for a user account
    No account exists yet. Creating one.
    Email: 
```

No account, no API, exit 1, no error message of any kind.

**Who this hits.** Anyone piping input, redirecting from `/dev/null`, or
running from cron, CI, cloud-init, Ansible, a provisioning script, or any
SSH session without a TTY. A person typing at a terminal is unaffected,
because a pty never reaches EOF, which is why the development machine
has never seen it.

**Fixed 2026-09-17.** Two lines, as expected. The probe now runs
`... pg_isready -U noctornal >/dev/null 2>&1 </dev/null`, and both prompts
are `read -r ADMIN_EMAIL || true`, which is what makes the fallback branch
reachable at all rather than dead code. Re-verified with a file on stdin
and nothing attached to a terminal: the account was created with its
password, TOTP secret and QR code, and the API came up with `/ui/`
answering 200. That run was not possible before.

---

## 5) R28: the generated `.env.local` omits the size caps

**Minor here, blocking in production.**

`install.sh` writes the two secrets and the service URLs, and no upload
caps. On a fresh install the register therefore says:

```
    warn  evidence_size_cap_declared
```

That is only a warning on the development stack. In production
`verify_environment` **refuses to boot** without
`NOCTORNAL_MAX_EVIDENCE_BYTES`, so an operator who promotes the file the
installer generated, which is the obvious thing to do, meets a boot
refusal with no hint that the installer could have written the line.
`INGEST_BUCKET` is missing for the same reason.

**Fixed 2026-09-17.** Both installers now write
`NOCTORNAL_MAX_EVIDENCE_BYTES=256MB`, `NOCTORNAL_MAX_SAMPLE_BYTES=64MB`
and `INGEST_BUCKET=noctornal-raw`, each with a comment saying what it caps
and why the raw bucket has no object lock. Re-verified: a brand-new
install now reports `ok evidence_size_cap_declared`.

---

## 6) R29: the shell scripts ship without the execute bit

**Cosmetic, already worked around, worth closing anyway.**

```
100644 release/install.sh
100644 scripts/launch.sh
```

As extracted: `-rw-r--r--`, and `./release/install.sh` answers
`Permission denied`. `README.md` and `INSTALL.md` both give the
`chmod +x release/install.sh && ./release/install.sh` form, so a reader
following either is fine. `INSTALL.md` line 129 then shows a bare
`./release/install.sh`, which is not.

**Fixed 2026-09-17.** Both are `100755` in the tree now, and the
extracted file is `-rwxr-xr-x`. The documented `chmod +x` stays, because a
ZIP download still may not carry the bit through whatever unpacks it; it
is idempotent and costs nothing. What changes is that a `git clone`, and
`INSTALL.md`'s bare `./release/install.sh` on line 129, now work.

---

## 7) Measurements

| | Documented | Measured |
|---|---|---|
| Disk | ~2 GB | 1.9 GB added (2.0 GB base to 3.9 GB) |
| Container memory | budget ~3 GB | 304 MB idle across all four |
| `.venv` | not stated | 189 MB |
| Migrations | head `0061` | head `0061`, from empty |

The memory budget is conservative by roughly ten times at idle. Postgres
is configured with `shared_buffers=512MB`, so the figure is defensible as
a ceiling, but a reader deciding whether their 4 GB box will cope is
being told to expect ten times what it uses.

---

## 8) After the fixes

The path on a stock Debian or Ubuntu is now what the document always
claimed it was: run it, and it tells you the one thing it needs.

```bash
./release/install.sh
#   -> Cannot continue: Python is installed but cannot build a virtual
#      environment (ensurepip missing).
#      Debian/Ubuntu:  sudo apt install python3.12-venv
sudo apt install -y python3.12-venv
./release/install.sh
```

Re-verified end to end on the same VM, in a single run with a file on
stdin and no terminal anywhere: containers up, migrations to `0061`,
account created with password, TOTP secret and QR code, API serving,
`/ui/` answering 200, `evidence_size_cap_declared` green, and the only
blocking readiness failures the four legal declarations.

### What now holds these

`test_script_invariants.py` gained five checks, in the same static style
as the file's existing installer tests, because nothing here can be caught
by running the suite:

| | |
|---|---|
| `test_the_venv_guard_asks_for_ensurepip_not_just_venv` | R25 |
| `test_a_half_built_venv_is_not_mistaken_for_a_good_one` | R26 |
| `test_the_readiness_probe_does_not_eat_the_installers_stdin` | R27 |
| `test_the_account_prompt_survives_end_of_input` | R27 |
| `test_the_generated_env_declares_the_upload_caps` | R28, both installers |

They are weaker than a run, and they are the checks that would have fired.
The run itself is still the only thing that finds the next one of these,
and it now has a record.

---

## 9) Alpha 6 re-run, 2026-09-23

**Artefact tested:** `git archive` of `main` at `a859e9e`, the Alpha 6
release candidate: 5,880,969 bytes, and `git get-tar-commit-id` inside the
guest reads back `a859e9e`. It was made on the same Windows clone, so 400
of its 418 text files have CRLF line endings, where GitHub's download of
that commit has LF.
**Host:** the same VM, rebuilt from the untouched Ubuntu 24.04 cloud image
under a new cloud-init instance id. Ubuntu 24.04.5 LTS, kernel 6.8, 4 vCPU,
8 GB RAM, 40 GB disk, Python 3.12.3. At first boot it had no Docker, no
`python3.12-venv`, no pip and no `python` command, and, unlike the image of
2026-09-17, its package lists had never been fetched.

**Result: PASS WITH FINDINGS.** Nothing stopped an install: every stop on
the way was the installer's own, and each named the next action. One
finding was high, every bundled service listening on every interface, and
it is fixed in this release together with most of the rest. The fixes
are held by the tests named in the table below, and were then run on the
same VM, rebuilt again: section 10.

### What was run

1. `chmod +x release/install.sh && ./release/install.sh`, with stdin from a
   file and no terminal, run again after each stop:
   - "Cannot continue: Python is installed but cannot build a virtual
     environment (ensurepip missing)", naming
     `sudo apt install python3.12-venv`. Exit 1, nothing left on disk: R25
     holds. That command then failed with "has no installation candidate"
     until `sudo apt-get update` had run (F7).
   - "Cannot continue: Docker was not found", with the docs.docker.com
     link. Docker Engine 29.8.1 and Compose v5.5.1 were installed as that
     page says.
   - "Docker is installed but the engine is not reachable", naming
     `sudo usermod -aG docker $USER`. In a new session after it,
     `docker ps` worked.
   - The full install. `/ui/` answered 200 after 85 s, 1.1 GB of image
     pulls included. `.env.local` was written with mode 600 and declares
     the raw and preservation buckets, the rejected-sample disposition and
     both size caps: R28 holds. Migrations reached `0065`. The account was
     created from answers in a file, with no terminal: R27 holds. It has
     clearance RED and the global roles CASE_OWNER and SYS_ADMIN.
   - As extracted, `install.sh` and `launch.sh` are `-rwxr-xr-x`: R29
     holds.
2. **The stack, from inside the guest.** Postgres and Mailpit healthy,
   Redis and MinIO up, minio-init exited 0 after creating four buckets and
   setting `GOVERNANCE 365DAYS` on the evidence bucket. `/healthz` answers
   ok, `/api/v1/auth/me` 401 without a session, and `/docs` and
   `/openapi.json` 404, off by default as documented.
3. **The buckets**, read with the MinIO client library and with `mc stat`
   on each. `noctornal-evidence` is versioned and locked with a GOVERNANCE
   365-day default, and every object in it carries a per-object COMPLIANCE
   retention. `noctornal-raw` and `noctornal-samples` have no lock.
   `noctornal-preserved` is versioned and locked with no default
   retention, as the compose file intends. A probe object put under a
   legal hold there could not be deleted by version. Three readiness calls
   reused the register's canary objects rather than adding more: the
   version ids were identical before and after.
4. **A real sign-in.** The printed password and a TOTP code computed from
   the printed secret gave 204 and both `__Host-` cookies, and
   `/api/v1/auth/me` then answered 200.
5. **The readiness register**: 200, not ready. Blocking before any
   seeding: `prohibited_content_policy`, `sample_origin_configured`,
   `retention_rules_confirmed` and `security_officer_present`. Both
   object-lock checks passed by proving write-once, the preservation one
   also proving the legal hold, and `migrations_at_head` read `0065` on
   both sides. Warnings: `redis_limiter_store`, `app_db_role_not_owner`,
   `smtp_configured`.
6. **README First run**, in a fresh session with no exports and the
   installer's address as `--owner-email`. `create-user` for that address
   refused ("already exists. Nothing was changed."); `demo-network`, the
   five seeders (deception, lab, feeds, ACH and the README showcase) and
   `bootstrap.py session` each exited 0. The showcase
   case has 20 nodes and 22 edges, the selector search added in `0065`
   found each seeded identifier, and the session link signed in. The
   showcase seeder's officer account took the blocking list down to three.
7. **Off and on.** Re-running the installer while the API was up repeated
   every step and then ended in uvicorn's "address already in use" with
   exit 3 (F9); the running API was unaffected. `docker compose down` kept
   the volumes, and the next run served `/ui/` after 16 s with the case and
   the three accounts intact.
8. **The suite with no services configured**: 1995 passed, 1533 skipped,
   0 failed, of 3528 collected, in 58 s. It was not run with
   `DATABASE_URL`, because that writes permanent rows into append-only
   tables and objects into the locked buckets under inspection.
9. **Network exposure**, from a separate network namespace on the guest
   to its LAN address (F19).

Answers came from a file, launches were detached and Ctrl-C was sent as a
signal; ufw was enabled for the exposure test and then disabled again.

### Measurements

| | Measured |
|---|---|
| Disk added by the install and the showcase seed | 1.4 GB (2,388 MB to 3,758 MB), after about 0.75 GB for Docker Engine and the venv package |
| Images | 1.10 GB |
| Containers after the seed | 301 MiB: minio 229, postgres 61, mailpit 7, redis 3.5 |
| `.venv` | 189 MB |
| Migrations | 65 files, head `0065`, from empty |
| Install time | 85 s |
| Restart time | 16 s |
| Stops on stock Ubuntu | four, each actionable: the venv package, `apt update` (not named), Docker, the docker group |

### Findings, and what was done about each

| | Finding | Done in this release |
|---|---|---|
| **F19** high | Postgres (as a superuser), the MinIO root, Redis and Mailpit were published on 0.0.0.0 and `[::]`, and answered from another network namespace with the credentials written in the repository. With ufw enabled and denying incoming traffic they still answered, because Docker forwards a published port before ufw sees it. | **Fixed.** `infra/docker-compose.yml` publishes every port on 127.0.0.1 only, and `SECURITY.md`, which said "publishes ports to localhost", now says 127.0.0.1 (IPv4 loopback) only; `test_compose_exposure.py` refuses any other binding. `INSTALL.md` and the README say so, and why. Re-run in section 10. |
| **F1** medium | The README's L1 row said a rejected sample's bytes are destroyed. Since `0063` they are preserved by default. | **Fixed** in the README. The row says what a rejection does and names the `destroy` opt-in; `test_install_copy.py` holds it to the code's default. `release/MANUAL.md`, which still said "Rejecting destroys the bytes and the key", now says the same as the README (G7 in section 10). |
| **F2** medium | `INSTALL.md` expected "1252 passed, 12 skipped" and "roughly 700 skips". | **Fixed.** It quotes no totals now: it says what skips without which setting, that the database, Redis and object-store tests fail or error rather than skip when their setting is loaded and the containers are down, and CI's zero-skip rule. Held by `test_install_copy.py`. |
| **F3** medium | `INSTALL.md` carried two BACKSPACE bytes where `scripts\bootstrap.py` belonged, in both Windows recovery commands, in every tagged release from Alpha 1 to Alpha 5.2, and a broken line join beside one of them. | **Fixed.** Both commands and the join are restored. `check_source_hygiene.py` now refuses every control byte except tab, line feed and carriage return, in every text file the repository tracks; `test_source_hygiene.py` proves it on built bytes and compares the files it reads with what git calls text. |
| **F4** medium | The first command printed after the account was made, `python scripts/bootstrap.py demo-case`, fails on stock Ubuntu (no `python`), names the wrong seeder, and the block offered an API login to someone about to use the console. | **Fixed.** `install.sh`'s closing output, and `launch.ps1`'s for the Windows installer, now give the console address to sign in at and the README's First run recipe with each platform's interpreter. `bootstrap.py create-user`'s own block, which still printed the old suggestion, now does the same, and its import hint names the project's `.venv` (G4 in section 10). |
| **F5** low | README First run asked for `create-user` although the installer had made the account. | **Fixed.** The step is marked as only for a missing account, and the recipe says to use the installer's address. |
| **F6** low | The installers' banner and `INSTALL.md` said four legal decisions and pointed at a README section that does not exist; the README says five. | **Fixed** in the README, `INSTALL.md` and both installers: five, L1 to L5, and the heading that exists, in the README at the project root, which the banners now name in full. `release/README.md`, `release/MANUAL.md` and `ARCHITECTURE.md`, which still said four, now say five as well (G6 in section 10). |
| **F7** low | The venv advice fails on a fresh image until `apt update` has run. | **Fixed** in both of `install.sh`'s Debian messages. |
| **F8** low | Every API start printed "RATE-LIMIT REDIS EVICTS KEYS" over a setting the bundled stack chose. | **Fixed.** The bundled Redis runs `noeviction`, and the documents that still said `allkeys-lru` now say so too (G5 in section 10). |
| **F9** low | `INSTALL.md` quoted a port-in-use message only `launch.ps1` printed. | **Fixed.** `install.sh` checks the port before starting the API and stops with "port 8000 is already in use", the message `INSTALL.md` quotes. |
| **F10** low | The two prerequisites tables disagreed with each other and with the measured install, and neither named `python3.12-venv`. | **Fixed.** One table, the same in both documents, from the measurements above. |
| **F11** low | The README and `INSTALL.md` said the installer opens the console; it prints the address. | **Fixed.** |
| **F12** low | `launch.sh` named 8080 and 4222, the ports of services removed in R13, and not Mailpit's 1025. | **Fixed** in both launchers, and held to the compose file's ports. |
| **F13** low | `alembic current` in a second terminal ended in a traceback. | **Fixed.** A one-line refusal that names `.env.local`; the file is still not loaded, because migrations refuse to guess a target. |
| **F14** low | `install.sh --help` printed `set -euo pipefail`. | **Fixed** in `install.sh` and `launch.sh`: help prints the header comment and stops at its end. |
| **F15** low | The minio-init log opened with an ERROR on every clean start, from the first pass of its wait. | **Fixed.** The wait is quiet and bounded. |
| **F16** low | Printed copy outside the server still carried em dashes and spaced double hyphens; the CLI prints role keys where the console shows names. | **Dashes fixed** in the installers, the launchers and what `scripts/*.py` print, `--help` text included; `test_install_copy.py` holds them to the server copy rule. Role keys in the CLI: **left**, recorded here. |
| **F17** info | Python dependencies and the Mailpit image are unpinned, so a clean install ran newer versions than development. | **Left**, recorded here. |
| **F18** info | `mc retention info --default` reports the preservation bucket as having no object lock. | **Documented.** `INSTALL.md` says so and names the register's `preservation_bucket_object_lock` check as the way to verify it. |
| **F20** info | Redis logs a memory-overcommit warning on every start. | **Documented** in `INSTALL.md`'s troubleshooting as harmless for an evaluation install. |
| | The installer's account holds no SECURITY_OFFICER role, so `security_officer_present` blocks a fresh install. | **Documented.** `INSTALL.md`, the README and the closing output of `install.sh` (and of `launch.ps1`) say so and give the command that makes a second person the officer. The installer still grants the same two roles. |

### Not done

- No browser and no authenticator app: the console was exercised over
  HTTP, and TOTP codes were computed from the printed secret.
- No suite run with `DATABASE_URL`, for the reason above.
- No sample was rejected into `noctornal-preserved` end to end: ingest
  answers 451 until L1 is declared. The register's canaries and the probe
  object cover the bucket instead.
- The R26 path (a half-built `.venv`) was not reached.
- `install.ps1`, macOS, `launch.sh` and QUICKSTART were not run.
- The exposure was tested from a second network namespace on the guest,
  not from a second machine.

---

## 10) Alpha 6 final re-run, 2026-09-24 (UTC)

**Artefact tested:** the Alpha 6 working tree with the fixes in section
9's table applied, before it was committed and before the corrections at
the end of this section: 444 files, 5,920,545 bytes, packed on the
Windows development machine, so 374 of its 426 text files have CRLF line
endings. It was compared file by file with git's own LF build of the same
tree, made with `core.autocrlf=false`, which is what GitHub serves: 70
files are byte-identical, 374 differ only in line endings, and none
differs in anything else. Two files, `db/init/10-app-role.sh` and
`scripts/yara_db.py`, carried an execute bit in the artefact that git
does not record; the first is written to work either way, and
initialisation succeeded.
**Host:** the same VM, rebuilt again from the untouched cloud image under
a new cloud-init instance id, starting from the state section 9
describes.

**Result: PASS WITH FINDINGS.** F19 is fixed: every bundled service
listens on 127.0.0.1 only and is refused on the guest's external address.
The install worked first time, in 72 s. The readiness register reports,
the README's First run completes, and the installer's closing advice
works as printed. What the run still found is in the table at the end,
with where each finding now stands.

### What was run

1. `chmod +x release/install.sh && ./release/install.sh`, with stdin from
   a file and no terminal, run again after each stop. Every run opened
   with the banner naming five legal decisions, L1 to L5, and the README
   at the project root.
   - "Cannot continue: Python is installed but cannot build a virtual
     environment (ensurepip missing)", naming
     `sudo apt update && sudo apt install python3.12-venv`, which worked as
     printed (F7). Exit 1, nothing left on disk.
   - "Cannot continue: Docker was not found", with the docs.docker.com
     link. Docker Engine 29.8.1 and Compose v5.5.1 were installed as that
     page says.
   - "Docker is installed but the engine is not reachable", naming
     `sudo usermod -aG docker $USER`. In a new session after it,
     `docker ps` worked.
   - The full install. `/ui/` answered 200 after 72 s. `.env.local` was
     written with mode 600, migrations reached `0065` and the account was
     created. The 941 lines of its log hold no RATE-LIMIT line, no
     warning and no traceback.
2. **The stack, from inside the guest.** Postgres and Mailpit healthy,
   Redis and MinIO up, and minio-init exited 0 with no ERROR line in its
   log (F15). Redis reports `maxmemory-policy noeviction` (F8), and
   Mailpit's SMTP greeting arrived in 4 ms. `/healthz` answers ok,
   `/api/v1/auth/me` 401 without a session and `/docs` 404. The buckets
   are as in section 9. The printed password and a TOTP code computed from
   the printed secret signed in (204). The register before seeding: four
   blocking checks, `security_officer_present` among them as `INSTALL.md`
   says, and `redis_limiter_store` passing. `alembic current` in a fresh
   shell printed its one-line refusal and exited 1 (F13).
3. **Network exposure (F19).** `ss -ltnp` shows 5432, 6379, 9000, 9001,
   1025 and 8025 held by Docker and the API's 8000 by uvicorn, every one
   on 127.0.0.1 only; sshd is the only listener on every interface. From
   the guest itself, all seven were refused on its external address, on
   the Docker bridge address and on `[::1]`, while sshd's 22 connected as
   the control, and 127.0.0.1 reached each of them. From a container on
   Docker's default bridge, a separate network namespace, all seven were
   closed on the external and bridge addresses, and `redis-cli` there
   could not connect. Docker's NAT rules for the published ports all
   match `127.0.0.1/32` only, and ufw was inactive, as found: the binding
   alone does the work.
4. **README First run**, in a fresh session with no exports. The command
   the installer's closing output quotes is character for character the
   README's first. `demo-network`, the five seeders and
   `bootstrap.py session` each exited 0, the showcase case has 20 nodes
   and 22 edges, and each of the four selector searches found its
   identifier. The Security Officer command the installer printed exited 1
   with "already exists" (G3); the same command with another address
   exited 0.
5. **The register after seeding.** Read with the README's session link 35
   minutes after it was made, it answered 403 "re-authentication
   required" while `/api/v1/auth/me` answered 200 (G13). After a fresh
   password and TOTP sign-in: 200, not ready, three blocking
   (`prohibited_content_policy`, `sample_origin_configured`,
   `retention_rules_confirmed`), `security_officer_present` passing with
   two active officers, and `migrations_at_head` at `0065`.
6. **Off and on.** `--help` works for both scripts, and `launch.sh` names
   all six ports (F12, F14). Re-running the installer while the API was up
   repeated every step and stopped with "Cannot continue: port 8000 is
   already in use." (F9); `--port 8001` served. After Ctrl-C and
   `docker compose down`, the next run served `/ui/` in 10 s with the data
   kept and no ERROR from minio-init.
7. **The suite with no services configured** (`DATABASE_URL`,
   `MINIO_ENDPOINT`, `REDIS_URL` and `SMTP_HOST` unset), twice: on the
   installed CRLF tree, and on git's LF build with a virtual environment
   of its own, so that the code and the tests each came from the tree
   under test. Both gave 2107 passed, 1535 skipped and 1 failed, of 3643
   collected: line endings changed nothing. The failure is the counter
   check (G1), and the one warning is Starlette's deprecation notice (G9).
   It was not run with `DATABASE_URL`, for the reason in section 9.

Answers came from a file, launches were detached, Ctrl-C was sent as a
signal, and the LF run had a second virtual environment.

### Measurements

| | Measured |
|---|---|
| Disk added by the install and the showcase seed | 1.37 GB |
| Images | 1.097 GB |
| Containers | 294 MiB |
| `.venv` | 189 MB |
| Migrations | 65 files, head `0065`, from empty |
| Install time | 72 s |
| Restart time | 10 s |
| Stops on stock Ubuntu | three, each actionable: the venv package (with `apt update` now named), Docker, the docker group |

### What the run found, and where each stands

G1 to G13 continue section 9's F numbers. None of the fixes below was
run on this VM again: they came after it, and the tests named hold them.

| | Finding | Now |
|---|---|---|
| **G1** medium | The documents quoted 2518 tests where the tree had 2568, so the counter check failed on both trees and CI would have failed on the commit. | **Fixed at the release commit**, which regenerates every quoted counter from the tree with `scripts/refresh_counters.py`; `test_doc_invariants` fails on any that is not exact. |
| **G2** low | `scripts/refresh_counters.py` crashed on Python 3.12, the documented minimum: `Path.read_text` takes `newline` only from 3.13. | **Fixed.** It reads bytes and decodes them. |
| **G3** low | The example Security Officer address, `officer@example.org`, was the showcase seeder's own officer, so after the showcase the printed command exited 1. | **Fixed.** Both installers and `INSTALL.md` print `security.officer@example.org`. |
| **G4** low | `bootstrap.py create-user` still printed `python scripts/bootstrap.py demo-case`, which exits 127 on a stock Ubuntu, above the installer's correct block. | **Fixed.** It prints the console address and the README's First run command with the project's interpreter, and its import hint names `.venv`. |
| **G5** low | `ARCHITECTURE.md`, `docs/16` C8 and a comment in `infra/production/compose.yml` still called the development Redis `allkeys-lru`. | **Fixed** in all three, and in the readiness register's advice for an evicting Redis. |
| **G6** low | `release/README.md`, `release/MANUAL.md` and `ARCHITECTURE.md` still counted four legal items. | **Fixed.** Five, L1 to L5, in all three; `release/README.md`'s table has the L5 row. |
| **G7** low | `release/MANUAL.md` said a rejection destroys the sample. | **Fixed.** It says a rejection preserves by default, destroys only under `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=destroy` and never under a legal hold, and that retrieval takes two people. |
| **G8** info | Mailpit logs that its API "is reachable from any host that can route to this interface". | **Documented** in `INSTALL.md`'s troubleshooting: it describes the stack's own network, and the host publishes Mailpit on 127.0.0.1 only. |
| **G9** info | Nothing is pinned: starlette 1.7.0, uvicorn 0.53.0, alembic 1.20.0, psycopg 3.3.6, SQLAlchemy 2.0.54, `axllent/mailpit:latest` (v1.31.2). | **Left**, as F17. |
| **G10** info | `INSTALL.md` said only that a suite run with `DATABASE_URL` writes permanent rows. `test_compartment_binding_pg.py` also downgrades the database it is given to `0058` and upgrades it back. | **Fixed.** `INSTALL.md`'s recipe makes a scratch database, the way CI does, points the suite there, and says why. |
| **G11** info | `release/CHANGELOG.md` had no collected total for this release. | **Fixed at the release commit**: the Alpha 6 section records the collected total of the release run. |
| **G12** info | This document's header called the tested artefact byte-for-byte GitHub's download. It was CRLF. | **Corrected**, in the header and in section 9, with the counts. |
| **G13** info | `INSTALL.md` did not say that the register needs a sign-in from the last 15 minutes. | **Fixed.** It says so, and how to get a fresh one. |

### Not done

- No browser and no authenticator app.
- No suite run with `DATABASE_URL`.
- Nothing from a second machine.
- `install.ps1`, macOS, `launch.sh` as an installer and QUICKSTART were
  not run.
- The refusals before a Security Officer exists were not exercised.

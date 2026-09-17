# Clean-VM install, Linux, step by step

**Date:** 2026-09-17
**Artefact tested:** `git archive HEAD` of `main` at `4c43ea8`, which is
byte-for-byte what GitHub's "Download ZIP" gives for that commit.
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

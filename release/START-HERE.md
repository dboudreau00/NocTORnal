# Start here

NocTORnal is a case system for investigators who work on cybercrime. This
page gets it running on your own computer in about fifteen minutes. It is a
**beta**: use it on **synthetic or published, non-personal data only**. Real
case material needs legal review first (see "What the beta is" below).

## What you need

| | Needed | How to check | Where to get it |
|---|---|---|---|
| **Docker** | Docker Desktop (Windows, macOS) or Docker Engine (Linux), with Compose | `docker compose version` prints a version | <https://www.docker.com/products/docker-desktop/> |
| **Python** | 3.12 or newer | `python --version` (macOS and Linux: `python3 --version`) | <https://www.python.org/downloads/> (Windows: tick "Add python.exe to PATH") |

Also about 8 GB of memory, 2 GB of free disk and an internet connection for
the first install. On Debian and Ubuntu add the venv package:
`sudo apt update && sudo apt install python3.12-venv`. Start Docker before
you install, and wait until it says it is running.

## Install in three steps

**1. Download and unzip.** Unzip the release, then open a terminal inside the
folder that holds `release` and `alembic.ini`. Windows: open the folder in
File Explorer, click the address bar, type `powershell` and press Enter.
macOS: right-click the folder and choose New Terminal at Folder.

**2. Run the one command.**

| Windows (PowerShell) | macOS and Linux |
|---|---|
| `powershell -ExecutionPolicy Bypass -File .\release\install.ps1` | `bash release/install.sh` |

It has eight numbered steps. Step 1 only looks at your computer and changes
nothing. The first run downloads about 1 GB and takes 5 to 15 minutes. It asks
for your email and a display name, then shows your password and a QR code
**once**. Save the password, scan the code (see below), then press Enter. It
then offers a fictional demo case: press Enter to say yes.

**3. Sign in.** Open <http://127.0.0.1:8000/ui/> in your browser. The
installer leaves its window open while NocTORnal runs. Add `--open` (Windows:
`-Open`) to the command and it opens the page for you.

## Your first sign-in

Signing in takes two things: **your password** and **a six-digit code from an
authenticator app** (any TOTP app, for example Aegis, 1Password, Google
Authenticator or Microsoft Authenticator). Scan the QR code the installer
showed with that app, then type the password and the code the app shows. The
code changes every 30 seconds. No QR code on screen? The installer also
printed a text secret; type it into the app by hand.

## Load the demo case

Say yes when the installer offers it, or load it later from the project
folder:

```
.venv/bin/python scripts/bootstrap.py demo-network --owner-email you@example.org --code OP-LATTICEWORK-26 --classification CLEAR
```

(Windows: `.venv\Scripts\python scripts\bootstrap.py ...`; use the email you
signed up with.) It makes "Operation Latticework": made-up people in three
crews, marked TLP:CLEAR. **All of it is fictional.**

## The first five things to try

1. Open Operation Latticework from the case list and look at the **Graph**:
   three crews joined by a few brokers.
2. Open **Analysis**. It singles out `oriel`, the one broker that ties a crew
   to the rest of the network.
3. Click a person in **Entities** and read their claims. Every claim shows a
   source and a grade. Nothing in the system is stated as a fact.
4. Use **Search** to find a handle such as `oriel`.
5. Add an entity and a relationship of your own, and notice that it asks for a
   source and a grade. [MANUAL.md](MANUAL.md) explains each pane.

## What the beta is

It is for trying the software on **synthetic data or published reporting with
no personal data**. It has not been audited, and some features refuse to work
on purpose until a legal decision is recorded (uploading malware samples, for
one). Holding real case material is dangerous and needs legal review first:
read "Read this before you hold anything" in
[docs/16](../docs/16-legal-and-external.md). It listens on your own computer
only (127.0.0.1); other machines cannot reach it.

## Start, stop, update, uninstall

- **Start again:** `bash release/start.sh` (Windows:
  `powershell -ExecutionPolicy Bypass -File .\release\start.ps1`, or
  double-click `start.cmd` in the project folder).
- **Stop:** press Ctrl+C in its window. The containers keep running; to stop
  them as well: `docker compose -f infra/docker-compose.yml down`.
- **Update:** unzip the new release in a new folder, copy `.env.local` from the
  old folder into it, then run the install command again. Keep that file: it
  holds the keys, and without it stored data cannot be opened.
- **Uninstall:** stop it, run `docker compose -f infra/docker-compose.yml down -v`
  (this deletes every case in it), then delete the folder.

## Something went wrong

| You see | Do this |
|---|---|
| "Python 3.12 or newer was not found" | Install Python 3.12 or newer, open a **new** terminal, run the command again. |
| "Docker is installed but the engine is not running" (Linux: "not reachable") | Start Docker Desktop and wait for "Engine running". Linux: `sudo systemctl start docker`, and `sudo usermod -aG docker $USER`, then log out and in. |
| "port 8000 is already in use" | NocTORnal may already be running: open <http://127.0.0.1:8000/ui/>. Otherwise add `--port 8001` (Windows: `-Port 8001`) to the command. |
| "docker compose up failed", or "Ports: in use by another program" | Something else holds 5432, 6379, 9000, 9001, 1025 or 8025, often a local Postgres. Stop it, then run the command again. |
| The six-digit code is refused | Check your computer's clock is right, then try the next code. Still refused: `.venv/bin/python scripts/bootstrap.py totp-diagnose --email you@example.org --code 123456` says whether the clock or the secret is wrong. |

More detail and the rest of the troubleshooting: [INSTALL.md](INSTALL.md).

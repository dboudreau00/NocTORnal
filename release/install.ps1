#Requires -Version 5
<#
.SYNOPSIS
    One-command install for NocTORnal on Windows.

.DESCRIPTION
    Checks prerequisites, builds the virtual environment, generates the
    secrets that have no safe default, then hands off to scripts/launch.ps1
    which starts the containers, migrates and runs the API.

    Every step is idempotent and reports what it found rather than
    assuming. Re-running this is safe.

    READ README.md FIRST. Four legal decisions gate any use of this
    software against real material.

.PARAMETER Port
    Port for the API. Default 8000.

.PARAMETER SkipLaunch
    Install and configure, but do not start anything. Useful when you want
    to review .env.local before the first run.

.EXAMPLE
    .\install.ps1
#>
[CmdletBinding()]
param(
    [int]    $Port = 8000,
    [switch] $SkipLaunch
)

$ErrorActionPreference = 'Stop'

# THE PROJECT ROOT IS THE PARENT OF THIS DIRECTORY. Nothing else.
#
# This used to probe four candidates, the last of which was the HARDCODED
# sibling folder name "NocTORnal - Social Network Analysis software"
# (release finding R1). That resolved on exactly one machine -- the one it
# was written on -- and produced "the application source could not be
# found" everywhere else, with a suggestion ("put it next to the
# application source directory") that silently failed for any other folder
# name.
#
# The package is now self-contained: `release/` sits inside the project
# tree, so its parent IS the project. One rule, no search, no dependence
# on what any adjacent directory happens to be called or whether it
# exists at all.
$ReleaseDir = $PSScriptRoot
$RepoRoot   = $null
$candidate  = Split-Path -Parent $ReleaseDir
if ($candidate -and (Test-Path (Join-Path $candidate 'alembic.ini'))) {
    $RepoRoot = (Resolve-Path $candidate).Path
}

function Invoke-Capture {
    # R5 (2026-07-26). Runs a native command and returns its exit code plus
    # combined output, WITHOUT tripping over PowerShell 5.1.
    #
    # With $ErrorActionPreference = 'Stop', redirecting a native command's
    # stderr (`*> $null` or `2>$null`) throws RemoteException the moment
    # that command writes anything to stderr. `docker info` writes to
    # stderr exactly when the engine is down -- so this script used to
    # crash with a raw .NET exception in the precise case its friendly
    # "start Docker Desktop" message exists for.
    #
    # PS 5.1 is the default shell on Windows and `#Requires -Version 5`
    # blesses it. launch.ps1 documents this hazard and carries this fix;
    # install.ps1, the script a NEW user meets first, did not.
    param([Parameter(Mandatory)][string] $Exe, [string[]] $Arguments = @())
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $text = & $Exe @Arguments 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_ }
        } | Out-String
        [pscustomobject]@{ Code = $LASTEXITCODE; Text = $text }
    }
    finally { $ErrorActionPreference = $saved }
}

function Write-Step { param([string] $Text)
    Write-Host ''
    Write-Host "  $Text" -ForegroundColor Cyan
}
function Write-Good { param([string] $Text) Write-Host "    $Text" -ForegroundColor Green }
function Write-Note { param([string] $Text) Write-Host "    $Text" -ForegroundColor Yellow }
function Write-Detail { param([string] $Text) Write-Host "    $Text" }

function Stop-With {
    param([string] $Problem, [string] $Fix)
    Write-Host ''
    Write-Host "  Cannot continue: $Problem" -ForegroundColor Red
    Write-Host ''
    Write-Host "  What to do:" -ForegroundColor Yellow
    foreach ($line in $Fix -split "`n") { Write-Host "    $line" }
    Write-Host ''
    exit 1
}

# ASCII only in this banner. The file is UTF-8 and the Windows PowerShell 5
# console reads it as the system ANSI code page, so a box-drawing character
# arrives as mojibake -- and an installer whose first line looks corrupted
# is one the user distrusts before it has done anything.
Write-Host ''
Write-Host '  NocTORnal - Alpha Release' -ForegroundColor White
Write-Host '  -------------------------' -ForegroundColor DarkGray
Write-Host '  Alpha software. Not audited. Four legal decisions gate any' -ForegroundColor Yellow
Write-Host '  use against real material - see README.md, section "LEGAL' -ForegroundColor Yellow
Write-Host '  STATUS". Installing is fine; pointing it at a real case is' -ForegroundColor Yellow
Write-Host '  not, until those are settled.' -ForegroundColor Yellow

if (-not $RepoRoot) {
    Stop-With 'this does not look like a complete NocTORnal package.' @'
install.ps1 expects to live in the `release/` directory of the project,
so that its parent contains alembic.ini. That parent has no alembic.ini.

The usual cause is copying release/ out on its own. It is documentation
and installers only -- there is no application source in it. Download or
clone the whole repository and run:

    powershell -ExecutionPolicy Bypass -File .\release\install.ps1

from the project root.
'@
}
Write-Step 'Locating the application'
Write-Good "found at $RepoRoot"

# ---------------------------------------------------------------------------
# 1. Python
# ---------------------------------------------------------------------------

Write-Step 'Checking Python'
$python = $null
foreach ($name in @('python', 'python3', 'py')) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    # R5: via Invoke-Capture. On a fresh Windows box the Microsoft Store
    # `python` alias fires first and writes to stderr, which under
    # EAP=Stop killed this loop before python3/py were ever tried.
    $probe = Invoke-Capture $cmd.Source @('-c', "import sys; print('%d.%d' % sys.version_info[:2])")
    # Trim: Invoke-Capture pipes through Out-String, which appends a
    # trailing newline, and the banner below interpolates $raw mid-string
    # -- so without this the version and the path break across two lines
    # in the very first thing a new user sees.
    $raw = ($probe.Text).Trim()
    if ($probe.Code -ne 0 -or -not $raw -or -not ($raw.Trim() -match '^\d+\.\d+$')) { continue }
    $parts = $raw.Trim().Split('.')
    if ([int]$parts[0] -gt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 12)) {
        $python = $cmd.Source
        Write-Good "Python $raw at $python"
        break
    }
    Write-Detail "found Python $raw at $($cmd.Source) - too old"
}
if (-not $python) {
    Stop-With 'Python 3.12 or newer was not found.' @'
Install it from https://www.python.org/downloads/ (tick "Add python.exe
to PATH" in the installer), or:

    winget install Python.Python.3.12

Then open a NEW terminal and run this script again.
'@
}

# ---------------------------------------------------------------------------
# 2. Docker
# ---------------------------------------------------------------------------

Write-Step 'Checking Docker'
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Stop-With 'Docker was not found.' @'
Install Docker Desktop from https://www.docker.com/products/docker-desktop/
or:

    winget install Docker.DockerDesktop

Start it, wait for the whale icon to stop animating, then run this again.
'@
}
# R5: this line was `& docker info *> $null`, which THREW instead of
# setting an exit code when the engine was down.
if ((Invoke-Capture 'docker' @('info')).Code -ne 0) {
    Stop-With 'Docker is installed but the engine is not running.' @'
Start Docker Desktop and wait for it to report "Engine running", then run
this script again. On a cold start that takes a minute or two.
'@
}
Write-Good 'Docker engine is running'

# R16 (2026-07-26): install.sh checks `docker compose version` and this
# did not, so a CLI-only Docker or a podman alias passed both checks here
# and failed later at `compose up` with no remedy text. Docker Desktop
# bundles Compose, so the population hitting this is small -- but the
# failure it produces is opaque, and the check is one line.
if ((Invoke-Capture 'docker' @('compose', 'version')).Code -ne 0) {
    Stop-With 'Docker Compose v2 is not available.' @'
This needs the Compose plugin (the "docker compose" subcommand, not the
older standalone "docker-compose" binary). Docker Desktop ships it; a
CLI-only or podman-aliased Docker may not.

    docker compose version

should print a version. If it does not, install Docker Desktop.
'@
}

# ---------------------------------------------------------------------------
# 3. Virtual environment and dependencies
# ---------------------------------------------------------------------------

$Venv       = Join-Path $RepoRoot '.venv'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'

Write-Step 'Building the Python environment'
if (Test-Path $VenvPython) {
    Write-Good '.venv already exists'
} else {
    Write-Detail 'creating .venv (this takes a moment)'
    & $python -m venv $Venv
    if ($LASTEXITCODE -ne 0) { Stop-With 'could not create the virtual environment.' 'Check that the venv module is available: python -m venv --help' }
    Write-Good 'created'
}

Write-Detail 'installing dependencies'
& $VenvPython -m pip install --upgrade pip --quiet
# Editable, and BOTH packages: the ontology package is the single source of
# the selector normalisers, and the API imports it. Installing only the API
# produces an ImportError at the first comms request rather than at install.
& $VenvPython -m pip install --quiet -e (Join-Path $RepoRoot 'packages\ontology') -e (Join-Path $RepoRoot 'apps\api')
if ($LASTEXITCODE -ne 0) {
    Stop-With 'dependency installation failed.' @'
The output above says why. The commonest causes are no network access, or
a corporate proxy that needs pip configured for it.
'@
}
# The dev extras (pytest, ruff) are best-effort: an analyst installing this
# to USE it does not need them, and a failure here must not fail the
# install. Built as ONE string - `-e $path"[dev]"` is two arguments to
# PowerShell, and pip would silently install the package without the
# extras rather than error, which is the worst of both.
$devTarget = (Join-Path $RepoRoot 'apps\api') + '[dev]'
$null = Invoke-Capture $VenvPython @('-m', 'pip', 'install', '--quiet', '-e', $devTarget)
if ($LASTEXITCODE -eq 0) { Write-Good 'dependencies installed (with dev extras)' }
else { Write-Good 'dependencies installed'; Write-Detail 'dev extras skipped' }

# ---------------------------------------------------------------------------
# 4. Secrets
# ---------------------------------------------------------------------------
# Nothing in this system has a default secret. A missing value produces a
# deliberate refusal, never an insecure fallback -- so these are generated
# here, once, and left alone on every subsequent run.

Write-Step 'Generating secrets'
$EnvLocal = Join-Path $RepoRoot '.env.local'
if (Test-Path $EnvLocal) {
    Write-Good '.env.local already exists - left untouched'
} else {
    $kek    = & $VenvPython -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
    $pepper = & $VenvPython -c "import secrets; print(secrets.token_urlsafe(32))"
    # R9 (2026-07-26): the SERVICE CONFIG is persisted too, not just the
    # secrets. It used to be exported into the installer's own shell and
    # lost the moment that shell exited, so every documented "run this in
    # a second terminal" command -- create-user, demo-case, the TOTP
    # bypass -- failed for a fresh recipient with a DATABASE_URL error.
    # bootstrap.py now reads this file (see _load_env_local), so writing
    # it here is what makes those commands work at all.
    #
    # R11: the three SMTP values are here so the advertised Mailpit demo
    # actually captures mail. The default SMTP_PORT in transports.py is
    # 587 and Mailpit listens on 1025, and plaintext needs asking for.
    @(
        '# Generated by install.ps1. Machine-local; never commit this file.',
        '# Rotating either secret invalidates what it protects: the TOTP KEK',
        '# makes every enrolled authenticator unreadable, and the pepper',
        '# invalidates every issued ingest key.',
        "NOCTORNAL_TOTP_KEK=$kek",
        "NOCTORNAL_INGEST_PEPPER=$pepper",
        '',
        '# Local development stack (infra/docker-compose.yml). Change these',
        '# to point at a real deployment; they are read by the API, by',
        '# scripts/launch.ps1 and by scripts/bootstrap.py.',
        'DATABASE_URL=postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal',
        'REDIS_URL=redis://localhost:6379/0',
        'MINIO_ENDPOINT=localhost:9000',
        'MINIO_ACCESS_KEY=noctornal',
        'MINIO_SECRET_KEY=dev_only_change_me',
        'EVIDENCE_BUCKET=noctornal-evidence',
        'SAMPLE_BUCKET=noctornal-samples',
        '',
        '# Mailpit, on the dev stack only. SMTP_ALLOW_PLAINTEXT is required',
        '# explicitly: sending case material over an unencrypted connection',
        '# is a decision, not a default.',
        'SMTP_HOST=localhost',
        'SMTP_PORT=1025',
        'SMTP_ALLOW_PLAINTEXT=1'
    # ASCII, NOT `-Encoding UTF8`.
    #
    # PowerShell 5.1's UTF8 encoder writes a BYTE ORDER MARK, and
    # install.sh sources this file with `set -a; . "$ENV_LOCAL"`. Bash
    # does not strip a BOM, so line 1 becomes the token $'ï»¿#'
    # and the shell reports "command not found" for it and for the next
    # word on that line. bootstrap.py's own loader survived it only
    # because line 1 happens to be a comment -- had a KEY been first, that
    # key would have been silently mis-named.
    #
    # Every byte written here is ASCII (base64 secrets, a URL, a port), so
    # this loses nothing and cannot introduce a BOM.
    ) | Set-Content -LiteralPath $EnvLocal -Encoding ascii
    Write-Good 'wrote .env.local with fresh random keys'
    Write-Note 'Back this file up. Losing the TOTP key locks every account out.'
}

# ---------------------------------------------------------------------------
# 5. Hand off
# ---------------------------------------------------------------------------

if ($SkipLaunch) {
    Write-Step 'Done (not started, -SkipLaunch was given)'
    Write-Detail 'To start it:'
    Write-Detail "    powershell -ExecutionPolicy Bypass -File `"$RepoRoot\scripts\launch.ps1`""
    Write-Host ''
    exit 0
}

Write-Step 'Starting the stack'
Write-Detail 'containers, migrations, first account, then the API'
Write-Host ''

& powershell -ExecutionPolicy Bypass -File (Join-Path $RepoRoot 'scripts\launch.ps1') -Port $Port
exit $LASTEXITCODE

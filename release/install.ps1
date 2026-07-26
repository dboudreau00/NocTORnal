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

# The repository is the PARENT of this release directory when the release
# ships alongside the source, and the release directory itself when it
# ships standalone. Resolve rather than assume, so a moved folder produces
# a clear message instead of a confusing failure four steps later.
$ReleaseDir = $PSScriptRoot
$RepoRoot   = $null
foreach ($candidate in @(
        $ReleaseDir,
        (Join-Path $ReleaseDir 'app'),
        (Split-Path -Parent $ReleaseDir),
        (Join-Path (Split-Path -Parent $ReleaseDir) 'NocTORnal - Social Network Analysis software'))) {
    if ($candidate -and (Test-Path (Join-Path $candidate 'alembic.ini'))) {
        $RepoRoot = (Resolve-Path $candidate).Path
        break
    }
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
    Stop-With 'the application source could not be found.' @'
This installer looks for alembic.ini in, and beside, its own directory.

If you have the release folder on its own, put it next to the
application source directory, or move it inside it.
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
    $raw = & $cmd.Source -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) { continue }
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
& docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Stop-With 'Docker is installed but the engine is not running.' @'
Start Docker Desktop and wait for it to report "Engine running", then run
this script again. On a cold start that takes a minute or two.
'@
}
Write-Good 'Docker engine is running'

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
& $VenvPython -m pip install --quiet -e $devTarget 2>$null
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
    @(
        '# Generated by install.ps1. Machine-local; never commit this file.',
        '# Rotating either value invalidates what it protects: the TOTP KEK',
        '# makes every enrolled authenticator unreadable, and the pepper',
        '# invalidates every issued ingest key.',
        "NOCTORNAL_TOTP_KEK=$kek",
        "NOCTORNAL_INGEST_PEPPER=$pepper"
    ) | Set-Content -LiteralPath $EnvLocal -Encoding UTF8
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

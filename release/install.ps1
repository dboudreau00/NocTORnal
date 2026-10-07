#Requires -Version 5
<#
.SYNOPSIS
    One-command install for NocTORnal on Windows, as a short wizard of
    eight numbered steps.

.DESCRIPTION
    Step 1 looks at your computer and changes nothing. The rest builds the
    virtual environment, generates the secrets that have no safe default,
    starts the containers, migrates the database, creates the first account
    (and waits while you save its password), offers a fictional demo case
    and runs the API.

    Every step is idempotent and reports what it found rather than
    assuming. Re-running this is safe. Start here: release\START-HERE.md.
    To start it again later: release\start.ps1.

    With no terminal attached (input piped in, a scheduled task) it never
    asks a question beyond the two the account needs, read from standard
    input: an email, then a display name. The demo case is then loaded only
    with -Demo.

    READ THE README.md AT THE PROJECT ROOT FIRST, section "Five blocking
    items". Five legal decisions, L1 to L5, gate any use of this software
    against real material.

.PARAMETER Port
    Port for the API. Default 8000.

.PARAMETER SkipLaunch
    Install and configure, but do not start anything. Useful when you want
    to review .env.local before the first run.

.PARAMETER Demo
    Load the fictional demo case without asking.

.PARAMETER NoDemo
    Do not load the demo case, and do not ask.

.PARAMETER Open
    Open the console in your browser once the API is up, without asking.

.PARAMETER WithTelegram
    Also install the Telegram collection library (optional).

.PARAMETER WithYara
    Also install the YARA scanning library (optional).

.PARAMETER ProductionSecrets
    For the production deployment (infra/production, read its README.md
    first): bring its secrets files to this release's layout, moving the
    schema owner's credential out of secrets.env and writing the Redis
    password and REDIS_URL, with a backup of every file it changes.
    Installs and starts nothing. Run it as the user who owns those files.
    What it does and the way back: release/secrets-upgrade/README.md.

.PARAMETER ProductionDir
    With -ProductionSecrets: the directory holding secrets.env, when it is
    not infra\production.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\release\install.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\release\install.ps1 -ProductionSecrets
#>
[CmdletBinding()]
param(
    [int]    $Port = 8000,
    [switch] $SkipLaunch,
    # The wizard: the fictional demo case, and the browser.
    [switch] $Demo,
    [switch] $NoDemo,
    [switch] $Open,
    # 2026-09-24: the optional extras, installed only when asked for
    # by name, and then a failure stops the install.
    [switch] $WithTelegram,
    [switch] $WithYara,
    # docs/17 F52 and the limiter's Redis ACL (2026-10-02).
    [switch] $ProductionSecrets,
    [string] $ProductionDir = ''
)

$ErrorActionPreference = 'Stop'

if ($Demo -and $NoDemo) {
    Write-Host 'choose -Demo or -NoDemo, not both' -ForegroundColor Red
    exit 2
}

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

# The wizard's numbered steps. Write-Step counts for itself, so a step added
# or removed cannot leave "Step 3 of 8" wrong in the middle of the run; a test
# holds $script:StepTotal to the number of Write-Step calls. Write-Heading is
# for output that is not one of the eight (the production secrets job, the
# closing line of -SkipLaunch).
$script:StepTotal = 8
$script:StepNo = 0
function Write-Step { param([string] $Text)
    $script:StepNo++
    Write-Host ''
    Write-Host "  Step $($script:StepNo) of $($script:StepTotal): $Text" -ForegroundColor Cyan
}
function Write-Heading { param([string] $Text)
    Write-Host ''
    Write-Host "  $Text" -ForegroundColor Cyan
}
function Write-Good { param([string] $Text) Write-Host "    $Text" -ForegroundColor Green }
function Write-Note { param([string] $Text) Write-Host "    $Text" -ForegroundColor Yellow }
function Write-Detail { param([string] $Text) Write-Host "    $Text" }

# The first line of the fix is the one sentence that says what to do; any lines
# after it are the commands.
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

# Whether a person is at the keyboard. Standard input is the test, because it
# is what the questions read: a clean-VM harness, a scheduled task and piped
# input all feed or close it, and a question asked there eats the lines meant
# for the account prompt.
function Test-Interactive {
    try { return (-not [Console]::IsInputRedirected) } catch { return $false }
}
$script:Interactive = Test-Interactive

# The decisions below are functions of their arguments and nothing else, so a
# test can run them (apps/api/tests/test_install_wizard.py). They mirror
# decide_demo and decide_open in install.sh.
#
# Get-DemoDecision: what to do about the fictional demo case. Mode is yes, no
# or empty; Fresh means this run made the account. Returns load, ask or skip.
# A question is asked only of a person who has just made their first account.
function Get-DemoDecision {
    param([string] $Mode, [bool] $Interactive, [bool] $Fresh)
    if ($Mode -eq 'no') { return 'skip' }
    if ($Mode -eq 'yes') { return 'load' }
    if ($Fresh -and $Interactive) { return 'ask' }
    return 'skip'
}

# Get-OpenDecision: whether to open the browser. Returns open, ask or skip.
# -Open forces it, and nothing opens without a desktop.
function Get-OpenDecision {
    param([bool] $Force, [bool] $Interactive, [bool] $Desktop)
    if (-not $Desktop) { return 'skip' }
    if ($Force) { return 'open' }
    if ($Interactive) { return 'ask' }
    return 'skip'
}

# The answer to a [Y/n] question: empty and anything starting with y or Y is
# yes, so Enter takes the default.
function Test-AnswerYes {
    param([string] $Answer)
    $text = $Answer.Trim()
    return ($text -eq '' -or $text -match '^[Yy]')
}

# One line from the person, or from standard input when it is piped. Null at
# the end of input becomes an empty answer.
function Read-Line {
    param([string] $Prompt, [string] $Suffix = ': ')
    Write-Host -NoNewline "    ${Prompt}${Suffix}"
    if ($script:Interactive) { $line = Read-Host } else { $line = [Console]::In.ReadLine() }
    if ($null -eq $line) { return '' }
    # A byte order mark in front of the first line, which Windows PowerShell 5.1
    # puts on text it pipes to a program, is not part of the answer.
    return $line.TrimStart([char] 0xFEFF).Trim()
}

function Test-PortInUse {
    param([int] $Number)
    $props = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    foreach ($listener in $props.GetActiveTcpListeners()) {
        if ($listener.Port -eq $Number) { return $true }
    }
    return $false
}

# Runs a program with its output going straight to the screen, as it is
# written (a first-time image pull takes minutes and should not look frozen),
# and returns its exit code. Invoke-Capture is for the short ones.
function Invoke-Live {
    param([Parameter(Mandatory)][string] $Exe, [string[]] $Arguments = @())
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @Arguments | Out-Host
        return $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $saved }
}

# .env.local is read as DATA, never run: one line, one NAME=value, and a name
# that changes how programs start is left out and named (g48 verification,
# 2026-10-03). The same list is in scripts/_env.py, release/install.sh,
# scripts/launch.sh, scripts/launch.ps1 and scripts/open-ui.ps1, and a test
# holds them to each other. The file's value wins over the environment, as it
# does in install.sh: this installer migrates and seeds whatever the file
# names, and an exported DATABASE_URL pointing somewhere else must not receive
# them. -contains and -like are case-insensitive, as Windows names are.
function Import-EnvLocal {
    param([string] $Path)
    $refusedExact    = @('PATH', 'PATHEXT', 'HOME', 'COMSPEC', 'IFS', 'ENV', 'CDPATH', 'GLOBIGNORE', 'SHELLOPTS', 'BASHOPTS', 'PROMPT_COMMAND', 'PS1', 'PS2', 'PS3', 'PS4', 'PSMODULEPATH')
    $refusedPrefixes = @('BASH_', 'LD_', 'DYLD_', 'PYTHON', 'DOCKER_', 'COMPOSE_', 'GIT_', 'PIP_', 'NODE_')
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        $split = $trimmed.IndexOf('=')
        if ($split -lt 1) { continue }
        $name  = ($trimmed.Substring(0, $split).Trim() -replace '^export\s+', '').Trim()
        $value = $trimmed.Substring($split + 1).Trim().Trim('"').Trim("'")
        if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { continue }
        $refused = ($refusedExact -contains $name)
        foreach ($prefix in $refusedPrefixes) { if ($name -like "$prefix*") { $refused = $true } }
        if ($refused) {
            Write-Detail ".env.local: ignored $name, a name that changes how programs start (set it in your shell if you mean it)"
            continue
        }
        [System.Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
}

# ASCII only in this banner. The file is UTF-8 and the Windows PowerShell 5
# console reads it as the system ANSI code page, so a box-drawing character
# arrives as mojibake -- and an installer whose first line looks corrupted
# is one the user distrusts before it has done anything.
Write-Host ''
Write-Host '  NocTORnal - Beta Install' -ForegroundColor White
Write-Host '  -------------------------' -ForegroundColor DarkGray
# Five, L1 to L5, as the root README's table has them, and a heading that
# exists there. The banner said four and pointed at a "LEGAL STATUS"
# section only release/README.md has. It names the README at the project
# root in full because release/README.md is the one beside this script
# and has no such heading (Alpha 6 pre-release check, 2026-09-23).
Write-Host '  Beta software. Not audited. Five legal decisions (L1 to L5)' -ForegroundColor Yellow
Write-Host '  gate any use against real material: see "Five blocking items"' -ForegroundColor Yellow
Write-Host '  in the README.md at the project root. Installing is fine;' -ForegroundColor Yellow
Write-Host '  pointing it at a real case is not, until those are settled.' -ForegroundColor Yellow
Write-Host '  Legal review is required before any active case load, and' -ForegroundColor Yellow
Write-Host '  holding this material is itself dangerous: see docs/16.' -ForegroundColor Yellow
Write-Host ''
Write-Host "  This takes $($script:StepTotal) short steps. Step 1 only looks at your computer and"
Write-Host '  changes nothing. If a step fails it says what to do, and running this'
Write-Host '  again is safe.'

if (-not $RepoRoot) {
    Stop-With 'this does not look like a complete NocTORnal package.' @'
Download or clone the whole repository, then run this installer again from
the project root:

    powershell -ExecutionPolicy Bypass -File .\release\install.ps1

install.ps1 expects to live in the `release/` directory of the project, so
that its parent contains alembic.ini. That parent has no alembic.ini. The
usual cause is copying release/ out on its own. It is documentation and
installers only, with no application source in it.
'@
}

# ---------------------------------------------------------------------------
# -ProductionSecrets (docs/17 F52 and the limiter's Redis ACL, 2026-10-02)
#
# A different job from everything below: it touches the production
# deployment's secrets files and nothing else, then exits. The work is
# scripts/production_secrets.py, the one implementation install.sh calls
# too, on any Python 3.8 or later with the standard library alone. It
# prints names, never a value, and backs up every file before it changes
# it.
#
# Mode 600 means nothing on Windows, where chmod only toggles read-only, so
# each secrets file and backup is then given an ACL naming this user alone,
# with inheritance cut: the same "readable by its owner and nobody else".
#
# An owner password may be generated only for a database volume initdb has
# not run on, because initdb fixes it for good: Docker is asked, and only
# "no such volume" from an engine that answers counts.
# ---------------------------------------------------------------------------
if ($ProductionSecrets) {
    $target = if ($ProductionDir) { $ProductionDir } else { Join-Path $RepoRoot 'infra\production' }
    Write-Heading 'Bringing the production secrets files to this release'
    Write-Detail "in $target"
    $hostPython = $null
    foreach ($name in @('python', 'python3', 'py')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        $probe = Invoke-Capture $cmd.Source @('-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)')
        if ($probe.Code -eq 0) { $hostPython = $cmd.Source; break }
    }
    if (-not $hostPython) {
        Stop-With 'Python 3.8 or newer was not found.' @'
Install Python 3.8 or later, then open a NEW terminal and run this again. The
production secrets step runs on any Python 3.8 or later, with the standard
library only:

    winget install Python.Python.3.12
'@
    }
    $helperArgs = @((Join-Path $RepoRoot 'scripts\production_secrets.py'), '--dir', $target)
    if (-not $ProductionDir -and (Get-Command docker -ErrorAction SilentlyContinue) -and
            (Invoke-Capture 'docker' @('info')).Code -eq 0 -and
            (Invoke-Capture 'docker' @('volume', 'inspect', 'noctornal-prod_prod-pgdata')).Code -ne 0) {
        $helperArgs += '--new-database'
        Write-Detail 'Docker has no database volume for this deployment yet'
    }
    & $hostPython @helperArgs | ForEach-Object { Write-Detail $_ }
    $status = $LASTEXITCODE
    if ($env:OS -eq 'Windows_NT' -and (Test-Path -LiteralPath $target)) {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Get-ChildItem -LiteralPath $target -File | Where-Object {
            $_.Name -in @('secrets.env', 'postgres-init.env', 'migrate.env') -or $_.Name -like '*.env.backup-*'
        } | ForEach-Object {
            $acl = Invoke-Capture 'icacls' @($_.FullName, '/inheritance:r', '/grant:r', "${me}:(F)")
            if ($acl.Code -ne 0) { Write-Note "could not restrict $($_.Name) to $me; do it by hand" }
        }
    }
    if ($status -eq 0) {
        Write-Good "the production secrets files are in this release's layout"
        Write-Detail 'next: docker compose -p noctornal-prod -f infra/production/compose.yml up -d --build'
    } else {
        Write-Note 'not finished: the lines above say what is left, or why it stopped and what it changed'
    }
    exit $status
}

# ---------------------------------------------------------------------------
# Step 1: look at the computer. Nothing is changed here. What it finds is
# printed as it goes, so the summary is on screen before step 2 touches
# anything: the system, Python, Docker and Compose, and the API's port.
# ---------------------------------------------------------------------------

Write-Step 'Checking your computer'
Write-Detail 'This step only looks. Nothing on your computer has been changed.'
Write-Good "folder:  $RepoRoot"
$osName = 'Windows'
try { $osName = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption.Trim() }
catch { $osName = [System.Environment]::OSVersion.VersionString }
Write-Good "system:  $osName, PowerShell $($PSVersionTable.PSVersion)"

# ---------------------------------------------------------------------------
# 1a. Python
# ---------------------------------------------------------------------------

$python = $null
foreach ($name in @('python', 'python3', 'py')) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    # R5: via Invoke-Capture. On a fresh Windows box the Microsoft Store
    # `python` alias fires first and writes to stderr, which under
    # EAP=Stop killed this loop before python3/py were ever tried.
    $probe = Invoke-Capture $cmd.Source @('-c', "import sys; print('%d.%d.%d' % sys.version_info[:3])")
    # Trim: Invoke-Capture pipes through Out-String, which appends a
    # trailing newline, and the line below interpolates $raw mid-string, so
    # without this the version and the path break across two lines in the
    # very first thing a new user sees.
    $raw = ($probe.Text).Trim()
    if ($probe.Code -ne 0 -or -not $raw -or -not ($raw -match '^\d+\.\d+\.\d+$')) { continue }
    $parts = $raw.Split('.')
    if ([int]$parts[0] -gt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 12)) {
        $python = $cmd.Source
        Write-Good "Python:  $raw at $python"
        break
    }
    Write-Detail "found Python $raw at $($cmd.Source), which is too old"
}
if (-not $python) {
    Stop-With 'Python 3.12 or newer was not found.' @'
Install Python 3.12 or newer, then open a NEW terminal and run this installer
again. Get it from https://www.python.org/downloads/ (tick "Add python.exe
to PATH" in the installer), or:

    winget install Python.Python.3.12
'@
}

# ---------------------------------------------------------------------------
# 1b. Docker
# ---------------------------------------------------------------------------

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Stop-With 'Docker was not found.' @'
Install Docker Desktop, start it, wait for the whale icon to stop animating,
then run this installer again. Get it from
https://www.docker.com/products/docker-desktop/ or:

    winget install Docker.DockerDesktop
'@
}
# R5: this line was `& docker info *> $null`, which THREW instead of
# setting an exit code when the engine was down.
if ((Invoke-Capture 'docker' @('info')).Code -ne 0) {
    Stop-With 'Docker is installed but the engine is not running.' @'
Start Docker Desktop and wait for it to report "Engine running", then run
this installer again. On a cold start that takes a minute or two.
'@
}

# R16 (2026-07-26): install.sh checks `docker compose version` and this
# did not, so a CLI-only Docker or a podman alias passed both checks here
# and failed later at `compose up` with no remedy text. Docker Desktop
# bundles Compose, so the population hitting this is small, but the
# failure it produces is opaque, and the check is one line.
if ((Invoke-Capture 'docker' @('compose', 'version')).Code -ne 0) {
    Stop-With 'Docker Compose v2 is not available.' @'
Install Docker Desktop, which includes Compose, then run this installer again.
This needs the Compose plugin (the "docker compose" subcommand, not the
older standalone "docker-compose" binary). A CLI-only or podman-aliased
Docker may not have it:

    docker compose version

should print a version.
'@
}
$dockerVersion  = (Invoke-Capture 'docker' @('version', '--format', '{{.Server.Version}}')).Text.Trim()
$composeVersion = (Invoke-Capture 'docker' @('compose', 'version', '--short')).Text.Trim()
if (-not $dockerVersion)  { $dockerVersion = 'version unknown' }
if (-not $composeVersion) { $composeVersion = 'v2' }
Write-Good "Docker:  $dockerVersion, engine running, Compose $composeVersion present"

# ---------------------------------------------------------------------------
# 1c. The port. A re-run while the API is already up says so here, before
# anything is built, in this script's voice. -SkipLaunch starts no API, so a
# busy port is only reported then.
# ---------------------------------------------------------------------------

$ComposeFile = Join-Path $RepoRoot 'infra\docker-compose.yml'
$portBusy = Test-PortInUse -Number $Port
if ($portBusy -and -not $SkipLaunch) {
    Stop-With "port $Port is already in use." @"
Open http://127.0.0.1:$Port/ui/ if an earlier copy is still running there, or choose another port.

    powershell -ExecutionPolicy Bypass -File .\release\install.ps1 -Port $($Port + 1)

To stop an earlier copy, press Ctrl+C in the window it runs in.
"@
}
if ($portBusy) { Write-Note "Port:    $Port is in use (fine, since -SkipLaunch starts nothing)" }
else { Write-Good "Port:    $Port is free" }

# The other ports are the containers'. When none of this project's containers
# is running and one of those is taken, `docker compose up` fails on it, so
# the install says so now rather than after the images are pulled. Not fatal:
# the compose file is the authority, and a port held by an earlier copy of
# this stack is fine.
$running = (Invoke-Capture 'docker' @('compose', '-f', $ComposeFile, 'ps', '-q')).Text.Trim()
if (-not $running) {
    $taken = @(5432, 6379, 9000, 9001, 1025, 8025 | Where-Object { Test-PortInUse -Number $_ })
    if ($taken.Count -gt 0) {
        Write-Note "Ports:   in use by another program: $($taken -join ', ')"
        Write-Note 'The containers need them. If step 4 fails, stop that program first.'
    }
}

Write-Host ''
Write-Detail 'All good. Next it will:'
Write-Detail '  build a private Python environment in the .venv folder'
Write-Detail '  write .env.local with fresh random keys (the file is yours to keep)'
Write-Detail '  start four containers: Postgres, Redis, MinIO and Mailpit'
Write-Detail '  set up the database and make your account'

# ---------------------------------------------------------------------------
# 3. Virtual environment and dependencies
# ---------------------------------------------------------------------------

$Venv       = Join-Path $RepoRoot '.venv'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'

Write-Step 'Building the Python environment'
$VenvPip = Join-Path $Venv 'Scripts\pip.exe'
if ((Test-Path $VenvPython) -and (Test-Path $VenvPip)) {
    Write-Good '.venv already exists'
} else {
    # An interpreter and no pip is the wreckage of an interrupted run, not
    # an environment. Testing only for python.exe meant the next run said
    # '.venv already exists' and then died with 'No module named pip',
    # which names neither the cause nor the fix, on every attempt after.
    # Found on Linux (release finding R26); the same shape is here.
    if (Test-Path $VenvPython) {
        Write-Note 'a previous run left a half-built .venv (no pip); rebuilding it'
        Remove-Item -Recurse -Force $Venv
    }
    Write-Detail 'creating .venv (this takes a moment)'
    & $python -m venv $Venv
    if ($LASTEXITCODE -ne 0) {
        # Leave nothing behind, so the next run starts clean instead of
        # taking the "already exists" path over a broken directory.
        if (Test-Path $Venv) { Remove-Item -Recurse -Force $Venv }
        Stop-With 'could not create the virtual environment.' "Fix what the output above names, then run this installer again.`nCheck that the venv module is available: python -m venv --help"
    }
    Write-Good 'created'
}

Write-Detail 'installing dependencies (a few minutes the first time)'
# Every install below is held to constraints.txt, the exact versions the
# release's suite passed on (sec-pin-dependencies, 2026-09-23). Without it
# each `>=` in the pyproject files resolved to whatever was newest that day,
# and the clean VM of the Alpha 6 check ran a newer stack than the one
# tested. Checked for here, so a missing file is named as that and not as
# "dependency installation failed" with pip's error scrolled past.
$Constraints = Join-Path $RepoRoot 'constraints.txt'
if (-not (Test-Path -LiteralPath $Constraints)) {
    Stop-With "constraints.txt is missing from $RepoRoot." @'
Unpack the release again, or check out the whole repository, then run this
installer again. The file pins every Python dependency to the version this
release was tested on, and it ships with the release.
'@
}
& $VenvPython -m pip install --upgrade pip --quiet
# Editable, and BOTH packages: the ontology package is the single source of
# the selector normalisers, and the API imports it. Installing only the API
# produces an ImportError at the first comms request rather than at install.
& $VenvPython -m pip install --quiet -c $Constraints -e (Join-Path $RepoRoot 'packages\ontology') -e (Join-Path $RepoRoot 'apps\api')
if ($LASTEXITCODE -ne 0) {
    Stop-With 'dependency installation failed.' @'
Check your internet connection, then run this installer again. The output
above says why. The commonest causes are no network access, or a corporate
proxy that needs pip configured for it.
'@
}
# The dev extras (pytest, ruff) are best-effort: an analyst installing this
# to USE it does not need them, and a failure here must not fail the
# install. Built as ONE string - `-e $path"[dev]"` is two arguments to
# PowerShell, and pip would silently install the package without the
# extras rather than error, which is the worst of both.
$devTarget = (Join-Path $RepoRoot 'apps\api') + '[dev]'
$null = Invoke-Capture $VenvPython @('-m', 'pip', 'install', '--quiet', '-c', $Constraints, '-e', $devTarget)
if ($LASTEXITCODE -eq 0) { Write-Good 'dependencies installed (with dev extras)' }
else { Write-Good 'dependencies installed'; Write-Detail 'dev extras skipped' }

# The extras asked for by name: a third install, and a LOUD one. The dev
# extras above are best effort because nobody asked for them; these were
# asked for, so a failure stops here. The target is ONE string, for the
# reason the dev target above gives.
$extras = @()
if ($WithTelegram) { $extras += 'telegram' }
if ($WithYara) { $extras += 'yara' }
if ($extras.Count -gt 0) {
    $extrasText = $extras -join ','
    Write-Detail "installing the optional extras: $extrasText"
    $extrasTarget = (Join-Path $RepoRoot 'apps\api') + "[$extrasText]"
    & $VenvPython -m pip install --quiet -c $Constraints -e $extrasTarget
    if ($LASTEXITCODE -ne 0) {
        Stop-With "the optional extras ($extrasText) did not install." @'
Run this installer again without the switch to install everything else.
The output above says why. The commonest causes are no network access, or
a macOS older than 14 for yara (yara-x publishes no wheel for it). The
readiness register then shows what the missing extra leaves out.
'@
    }
    Write-Good "optional extras installed: $extrasText"
}

# ---------------------------------------------------------------------------
# 4. Secrets
# ---------------------------------------------------------------------------
# Nothing in this system has a default secret. A missing value produces a
# deliberate refusal, never an insecure fallback -- so these are generated
# here, once, and left alone on every subsequent run.

# The key store is private to this user from the first byte (infra-9,
# 2026-10-03). On Windows a new file inherits its folder's ACL, which is
# every account that can read the project directory, and nothing restricted
# it afterwards. The file is created empty, restricted, and only then
# written, so the keys never exist in a file others can read. Not fatal when
# icacls refuses (a FAT volume, say): the installer says so and goes on,
# because a stopped install would leave no key store at all.
function Protect-EnvLocal {
    param([string] $Path)
    if ($env:OS -ne 'Windows_NT') { return }
    try {
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & icacls.exe $Path /inheritance:r /grant:r "*${sid}:(F)" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls exited $LASTEXITCODE" }
    }
    catch {
        Write-Note "Could not restrict $Path to this user ($($_.Exception.Message)). Do it by hand: icacls `"$Path`" /inheritance:r /grant:r `"%USERNAME%:F`""
    }
}

Write-Step 'Creating your secret keys'
$EnvLocal = Join-Path $RepoRoot '.env.local'
if (Test-Path $EnvLocal) {
    Write-Good '.env.local already exists - left untouched'
    # A collector process (2026-10-02): a file written before the persona
    # key existed gains it, appended, with the inline mode this install
    # runs in. Nothing already in the file is changed.
    $envText = Get-Content -LiteralPath $EnvLocal -Raw
    if ($envText -notmatch '(?m)^NOCTORNAL_PERSONA_KEK=') {
        $pkek = & $VenvPython -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pkek)) {
            Stop-With 'Could not generate the persona key.' `
                'Run this installer again. Nothing was written, so that is safe. The Python in the virtual environment produced nothing.'
        }
        $added = @('# NOCTORNAL_PERSONA_KEK seals every collection persona credential. Lost, every persona is enrolled again.',
                   "NOCTORNAL_PERSONA_KEK=$pkek")
        if ($envText -notmatch '(?m)^NOCTORNAL_COLLECTOR_INLINE=') { $added += 'NOCTORNAL_COLLECTOR_INLINE=1' }
        Add-Content -LiteralPath $EnvLocal -Value $added
        Write-Good 'added the persona key to .env.local'
    }
} else {
    # The output of these is CHECKED before anything is written.
    #
    # It used to be taken on trust. If the subprocess failed -- a broken
    # venv, a missing DLL, an interpreter that dies on import -- PowerShell
    # left the variable empty, the file was written with
    # `NOCTORNAL_TOTP_KEK=` and the installer announced "wrote .env.local
    # with fresh random keys". That claim was false.
    #
    # And the failure LATCHES. Every later run takes the
    # `Test-Path $EnvLocal` branch and reports ".env.local already exists -
    # left untouched", so a recipient whose first run half-failed is
    # permanently installed with an empty key and is told twice that it
    # worked. Refusing before the write leaves no file, so re-running is
    # the fix.
    $kek    = & $VenvPython -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($kek)) {
        Stop-With 'Could not generate the TOTP key-encryption key.' `
            "Run this installer again after you have seen the real error. The Python in the virtual environment exited $LASTEXITCODE and produced nothing. Run `"$VenvPython -c 'import base64'`" to see it."
    }
    # Length, not just presence. `envelope.py` requires exactly 32 bytes
    # and refuses anything else at RUN time -- which is a refusal the
    # recipient meets much later, in a different program, with no
    # connection back to here.
    $kekBytes = 0
    try { $kekBytes = [Convert]::FromBase64String($kek).Length } catch { $kekBytes = 0 }
    if ($kekBytes -ne 32) {
        Stop-With "The generated TOTP key is $kekBytes bytes, not 32." `
            'Report this with the line above, then run this installer again. Nothing was written. It is a defect in the installer or a damaged Python.'
    }
    # The persona key (A collector process, 2026-10-02), checked as the
    # TOTP key is: the persona ring refuses anything but 32 bytes.
    $pkek = & $VenvPython -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
    $pkekBytes = 0
    try { $pkekBytes = [Convert]::FromBase64String($pkek).Length } catch { $pkekBytes = 0 }
    if ($LASTEXITCODE -ne 0 -or $pkekBytes -ne 32) {
        Stop-With "The generated persona key is $pkekBytes bytes, not 32." `
            'Report this with the line above, then run this installer again. Nothing was written. It is a defect in the installer or a damaged Python.'
    }
    $pepper = & $VenvPython -c "import secrets; print(secrets.token_urlsafe(32))"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pepper)) {
        Stop-With 'Could not generate the ingest pepper.' `
            'Run this installer again. Nothing was written, so that is safe. The Python in the virtual environment produced nothing.'
    }
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
    #
    # 127.0.0.1, not localhost, in every address below. The dev stack
    # publishes its ports on 127.0.0.1 only, so nothing answers on ::1,
    # and Windows by default resolves localhost to ::1 first: each new
    # connection then waited about two seconds for the refused attempt
    # before trying IPv4 (Alpha 6 pre-release check, 2026-09-23). The
    # header names everything the two secrets protect, from
    # security/sealed.py's SEALED_COLUMNS and ingest.py's HMAC; it named
    # only authenticators and ingest keys.
    # Create it empty and restrict it BEFORE the keys are written.
    New-Item -ItemType File -Path $EnvLocal -Force | Out-Null
    Protect-EnvLocal -Path $EnvLocal
    @(
        '# Generated by install.ps1. Machine-local; never commit this file.',
        '# BACK IT UP: nothing can recover these three secrets.',
        '# NOCTORNAL_TOTP_KEK seals every secret the database stores encrypted,',
        '# except the egress exits, which are sealed to the egress proxy''s own key,',
        '# and collection persona credentials, which NOCTORNAL_PERSONA_KEK seals:',
        '# enrolled authenticators, stored victim',
        '# credentials, each sample''s data key, and the credentials of the outbound',
        '# integrations an administrator configures (Jira and lookup provider',
        '# credentials). Lost, or replaced other than by',
        '# the key rotation security/envelope.py describes, none of them opens',
        '# again: every user re-enrols an authenticator, and no stored sample,',
        '# preserved ones included, can be decrypted. NOCTORNAL_INGEST_PEPPER keys',
        '# the HMAC of every issued ingest key and every victim-credential',
        '# fingerprint: lost or changed, every ingest key must be reissued, and',
        '# stored fingerprints no longer match new ones for the same value.',
        "NOCTORNAL_TOTP_KEK=$kek",
        "NOCTORNAL_INGEST_PEPPER=$pepper",
        '# NOCTORNAL_PERSONA_KEK seals every collection persona credential. Lost,',
        '# every persona is enrolled again. This install has no collector process,',
        '# so persona acts run inside the API (NOCTORNAL_COLLECTOR_INLINE); a',
        '# production deployment keeps the key in the collector service alone.',
        "NOCTORNAL_PERSONA_KEK=$pkek",
        'NOCTORNAL_COLLECTOR_INLINE=1',
        '',
        '# Local development stack (infra/docker-compose.yml). Change these',
        '# to point at a real deployment; they are read by the API, by',
        '# scripts/launch.ps1 and by scripts/bootstrap.py.',
        'DATABASE_URL=postgresql+psycopg://noctornal:dev_only_change_me@127.0.0.1:5432/noctornal',
        'REDIS_URL=redis://127.0.0.1:6379/0',
        'MINIO_ENDPOINT=127.0.0.1:9000',
        'MINIO_ACCESS_KEY=noctornal',
        'MINIO_SECRET_KEY=dev_only_change_me',
        'EVIDENCE_BUCKET=noctornal-evidence',
        'SAMPLE_BUCKET=noctornal-samples',
        '# Raw partner submissions, deliberately in a bucket WITHOUT object',
        '# lock: an exhibit is locked so not even root can delete it before',
        '# its deadline, and a partner submission has to stay deletable to',
        '# answer a deletion order.',
        'INGEST_BUCKET=noctornal-raw',
        '# Raw markup of collected forum pages, per item, deliberately WITHOUT',
        '# object lock: it is deleted with its document.',
        'COLLECT_RAW_BUCKET=noctornal-collect-raw',
        '',
        '# Rejected malware samples are PRESERVED, not destroyed (docs/11):',
        '# their encrypted bytes move into this object-locked bucket under a',
        '# legal hold, and a retrieval needs a Security Officer''s',
        '# authorisation. Set the disposition to destroy only if counsel has',
        '# decided rejected samples must not be kept; any other value refuses',
        '# rejections until it is corrected.',
        'PRESERVE_BUCKET=noctornal-preserved',
        'NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=preserve',
        '',
        '# The largest exhibit and the largest sample this deployment',
        '# accepts, declared rather than defaulted. Production REFUSES TO',
        '# BOOT while NOCTORNAL_MAX_EVIDENCE_BYTES is unset, because a cap',
        '# nobody chose is a cap nobody can be held to; the development',
        '# stack only warns. Written here so that promoting this file to a',
        '# real deployment does not meet a boot refusal with no hint that',
        '# the line was available. Accepts 256MB, 1G, or bytes.',
        'NOCTORNAL_MAX_EVIDENCE_BYTES=256MB',
        'NOCTORNAL_MAX_SAMPLE_BYTES=64MB',
        '',
        '# Mailpit, on the dev stack only. SMTP_ALLOW_PLAINTEXT is required',
        '# explicitly: sending case material over an unencrypted connection',
        '# is a decision, not a default.',
        'SMTP_HOST=127.0.0.1',
        'SMTP_PORT=1025',
        'SMTP_ALLOW_PLAINTEXT=1'
    # ASCII, NOT `-Encoding UTF8`.
    #
    # PowerShell 5.1's UTF8 encoder writes a BYTE ORDER MARK. install.sh
    # used to source this file (`set -a; . "$ENV_LOCAL"`), where bash does
    # not strip a BOM, so line 1 became the token $'ï»¿#' and the shell
    # reported "command not found" for it and for the next word on that
    # line; it reads the file as data now and drops a BOM itself
    # (infra-9, 2026-10-03). bootstrap.py's own loader survived it only
    # because line 1 happens to be a comment -- had a KEY been first, that
    # key would have been silently mis-named.
    #
    # Every byte written here is ASCII (base64 secrets, a URL, a port), so
    # this loses nothing and cannot introduce a BOM.
    ) | Set-Content -LiteralPath $EnvLocal -Encoding ascii
    Write-Good 'wrote .env.local with fresh random keys'
    Write-Note 'Back this file up. Without it every user must re-enrol their'
    Write-Note 'authenticator, and no stored credential or sample can be decrypted'
    Write-Note 'again. Its header lists what each secret protects.'
}

# ---------------------------------------------------------------------------
# -SkipLaunch ends here: the keys are written and nothing is started.
# ---------------------------------------------------------------------------

if ($SkipLaunch) {
    Write-Heading 'Done (nothing was started, because -SkipLaunch was given)'
    Write-Detail 'To start it:'
    Write-Detail "    powershell -ExecutionPolicy Bypass -File `"$RepoRoot\release\start.ps1`""
    Write-Host ''
    exit 0
}

# .env.local is read as data, and the development defaults fill what it says
# nothing about: an .env.local made by an earlier launcher carries the keys and
# little else. The same addresses as the file above, 127.0.0.1 and not
# localhost, for the reason given there.
Import-EnvLocal -Path $EnvLocal
$defaults = [ordered]@{
    DATABASE_URL     = 'postgresql+psycopg://noctornal:dev_only_change_me@127.0.0.1:5432/noctornal'
    REDIS_URL        = 'redis://127.0.0.1:6379/0'
    MINIO_ENDPOINT   = '127.0.0.1:9000'
    MINIO_ACCESS_KEY = 'noctornal'
    MINIO_SECRET_KEY = 'dev_only_change_me'
    EVIDENCE_BUCKET  = 'noctornal-evidence'
}
foreach ($key in $defaults.Keys) {
    if ([string]::IsNullOrWhiteSpace([System.Environment]::GetEnvironmentVariable($key, 'Process'))) {
        [System.Environment]::SetEnvironmentVariable($key, $defaults[$key], 'Process')
    }
}

# ---------------------------------------------------------------------------
# Step 4: the containers
# ---------------------------------------------------------------------------

Write-Step 'Starting the services'
Write-Detail 'Four containers: Postgres, Redis, MinIO, Mailpit.'
Write-Detail 'The first time, Docker downloads about 1 GB, which can take several minutes.'
# -f rather than a directory change: compose derives the project directory
# from the compose file, so the relative volume paths still resolve.
if ((Invoke-Live 'docker' @('compose', '-f', $ComposeFile, 'up', '-d')) -ne 0) {
    Stop-With 'docker compose up failed.' @"
Read the output above, fix what it names, then run this installer again.
The usual causes are a port that is already taken (5432, 6379, 9000, 9001,
1025, 8025), or an image that could not be pulled. To stop a stale stack
that holds the ports:

    docker compose -f "$ComposeFile" down
"@
}

# Postgres is the only container the next steps depend on, and it is the only
# one with a healthcheck. Alembic against a still-initialising cluster fails in
# confusing ways, so wait for healthy rather than for running.
Write-Detail 'waiting for Postgres to report healthy'
$started  = Get-Date
$deadline = $started.AddMinutes(3)
$healthy  = $false
$lastSeen = 'unknown'
$tick     = 0
while ((Get-Date) -lt $deadline) {
    $ids = Invoke-Capture 'docker' @('compose', '-f', $ComposeFile, 'ps', '-q', 'postgres')
    $containerId = ($ids.Text -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    if ($containerId) {
        $inspect = Invoke-Capture 'docker' @('inspect', '--format', '{{.State.Health.Status}}', $containerId.Trim())
        $lastSeen = $inspect.Text.Trim()
        if ($lastSeen -eq 'healthy') { $healthy = $true; break }
    }
    Start-Sleep -Seconds 3
    $tick++
    if (($tick % 5) -eq 0) {
        $waited = [int]((Get-Date) - $started).TotalSeconds
        Write-Detail "still waiting: Postgres is $lastSeen ($waited s of 180 s)"
    }
}
if (-not $healthy) {
    Stop-With "Postgres did not become healthy (last status: $lastSeen)." @"
Look at the Postgres log, fix what it names, then run this installer again.

    docker compose -f "$ComposeFile" logs postgres

If an earlier run died part-way through first-time setup, the data volume keeps
a half-built cluster. That is only recoverable by destroying the volume, which
DELETES the local database:

    docker compose -f "$ComposeFile" down -v
"@
}
Write-Good 'Postgres is ready'

# ---------------------------------------------------------------------------
# Step 5: the database
# ---------------------------------------------------------------------------

Write-Step 'Setting up the database'
# Alembic resolves script_location from alembic.ini relative to the working
# directory, so it runs from the repository root. -Wait is what makes
# ExitCode readable, and a null is a failure here, never a pass.
$AlembicExe  = Join-Path $Venv 'Scripts\alembic.exe'
$alembicArgs = @('upgrade', 'head')
if (Test-Path -LiteralPath $AlembicExe) { $alembicTarget = $AlembicExe }
else { $alembicTarget = $VenvPython; $alembicArgs = @('-m', 'alembic') + $alembicArgs }
$run = Start-Process -FilePath $alembicTarget -ArgumentList $alembicArgs `
    -WorkingDirectory $RepoRoot -NoNewWindow -Wait -PassThru
if ($null -eq $run.ExitCode -or $run.ExitCode -ne 0) {
    Stop-With 'the database could not be set up.' @"
Read the output above, fix what it names, then run this installer again.
If an earlier run stopped half way, destroying the volume starts clean (this
deletes all local case data):

    docker compose -f "$ComposeFile" down -v
"@
}
Write-Good 'database is up to date'

# ---------------------------------------------------------------------------
# Step 6: the first account. The password and the QR code are printed once by
# bootstrap.py, so when a person is at the keyboard the installer WAITS here
# until they say they have saved them, and the API starts only after that.
# It used to hand off to launch.ps1, whose server log scrolled them off the
# screen within seconds (release finding R8).
# ---------------------------------------------------------------------------

Write-Step 'Creating your account'
$bootstrap = Join-Path $RepoRoot 'scripts\bootstrap.py'
# No double quotes inside the Python: Windows PowerShell 5.1 does not escape
# them when it passes an argument to a native program.
$countCode = 'import noctornal_api.db as d; print(d.connect().execute(''select count(*) from iam.app_user'').fetchone()[0])'
$count = Invoke-Capture $VenvPython @('-c', $countCode)
$users = -1
$parsed = 0
if ($count.Code -eq 0 -and [int]::TryParse($count.Text.Trim(), [ref] $parsed)) { $users = $parsed }
if ($users -lt 0) {
    Write-Host $count.Text
    Stop-With 'the user accounts could not be read.' 'Fix what the output above names, then run this installer again.'
}
$adminEmail = ''
$adminName = ''
$accountCreated = $false
if ($users -eq 0) {
    Write-Note 'No account exists yet. Creating one.'
    Write-Detail 'Enter your email address (you sign in with it) and a display name.'
    Write-Detail 'A strong password is made for you and shown once, with a QR code'
    Write-Detail 'for an authenticator app (any TOTP app on your phone will do).'
    Write-Host ''
    # A person at the keyboard gets three tries at an address that is not one.
    # Standard input that is not a terminal is read once: a harness feeds an
    # email, then a name, and nothing else.
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $adminEmail = Read-Line 'Email'
        $adminName = Read-Line 'Display name'
        if ($script:Interactive -and $adminEmail -and $adminEmail -notmatch '@') {
            Write-Note 'That does not look like an email address. Try again.'
            $adminEmail = ''
            continue
        }
        break
    }
    Write-Host ''
    if (-not $adminEmail -or -not $adminName) {
        Write-Note 'Skipped: both an email and a display name are needed.'
        Write-Detail 'Create one later with:'
        Write-Detail '  .venv\Scripts\python scripts\bootstrap.py create-user --email you@example.org --name "Your Name"'
        $adminEmail = ''
    }
    else {
        $adminName = $adminName -replace '"', ''
        Write-Detail 'Your password and the QR code are printed next. They are shown once.'
        & $VenvPython $bootstrap create-user --email $adminEmail --name $adminName
        if ($LASTEXITCODE -ne 0) {
            Stop-With 'the account could not be made.' "Fix what the lines above name, then run this installer again.`nEverything before this step is kept, so it picks up where it stopped."
        }
        $accountCreated = $true
        if ($script:Interactive) {
            Write-Host ''
            Write-Note 'Save the password and scan the QR code now. They are not shown again.'
            $null = Read-Line 'Press Enter when you have saved them'
            Write-Host ''
        }
    }
}
elseif ($users -eq 1) { Write-Good '1 account already exists' }
else { Write-Good "$users accounts already exist" }

# ---------------------------------------------------------------------------
# Step 7: the fictional demo case. Asked only of a person at the keyboard who
# has just made their first account, and defaulting to yes. Without a terminal
# nothing is asked, because a question there would eat the lines the account
# prompt reads: the demo loads only with -Demo. It is the synthetic
# TLP:CLEAR network `bootstrap.py demo-network` makes, and the installer says
# it is fictional.
# ---------------------------------------------------------------------------

Write-Step 'Loading the demo case (optional)'
$demoCode = 'OP-LATTICEWORK-26'
$demoMode = ''
if ($Demo) { $demoMode = 'yes' } elseif ($NoDemo) { $demoMode = 'no' }
$demoDecision = Get-DemoDecision -Mode $demoMode -Interactive $script:Interactive -Fresh $accountCreated
$demoLoaded = $false
$demoOwner = $adminEmail
if ($demoDecision -eq 'ask') {
    Write-Detail 'A fictional case with made-up people and ties, so there is something'
    Write-Detail 'to look at straight away. It is marked TLP:CLEAR and holds nothing real.'
    $answer = Read-Line 'Load the synthetic demo case so there is something to explore? [Y/n]' -Suffix ' '
    if (Test-AnswerYes $answer) { $demoDecision = 'load' } else { $demoDecision = 'skip' }
    Write-Host ''
}
if ($demoDecision -eq 'load') {
    if (-not $demoOwner) {
        # -Demo on a re-run: the earliest active Lead investigator owns it.
        $ownerCode = 'import noctornal_api.db as d; r = d.connect().execute(''select u.email from iam.app_user u join iam.user_role ur on ur.user_id = u.id where ur.role_key = %s and u.is_active order by u.created_at limit 1'', (''CASE_OWNER'',)).fetchone(); print(r[0] if r else '''')'
        $ownerRun = Invoke-Capture $VenvPython @('-c', $ownerCode)
        if ($ownerRun.Code -eq 0) { $demoOwner = $ownerRun.Text.Trim() }
    }
    if (-not $demoOwner) {
        Write-Note 'The demo case needs an account to own it, and none was found.'
    }
    else {
        & $VenvPython $bootstrap demo-network --owner-email $demoOwner --code $demoCode --classification CLEAR
        if ($LASTEXITCODE -eq 0) {
            $demoLoaded = $true
            Write-Good "demo case loaded: Operation Latticework, code $demoCode"
            Write-Detail 'It is fictional: made-up names and ties, marked TLP:CLEAR. Find it in the case list.'
        }
        else {
            Write-Note 'The demo case was not loaded. The lines above say why.'
            Write-Detail 'If it is already there from an earlier run, that is fine.'
        }
    }
}
elseif ($demoMode -eq 'no') { Write-Detail 'Skipped, because -NoDemo was given.' }
else { Write-Detail 'Skipped. The closing card says how to load it later.' }

# ---------------------------------------------------------------------------
# Step 8: start the API, and say what to do next.
#
# The port was checked in step 1, so a re-run while the API is already up said
# what was wrong before anything was built. The Security Officer count is read,
# not assumed, so a re-run on a stack that has one says nothing about it; a
# count that cannot be read prints the advice anyway, because it costs less
# than a blocked collection nobody can explain (Alpha 6 pre-release check,
# 2026-09-23). -1 means the count could not be read.
# ---------------------------------------------------------------------------

Write-Step 'Starting the API'
$officerCode = 'import noctornal_api.db as d; print(d.connect().execute(''select count(distinct u.id) from iam.app_user u join iam.user_role ur on ur.user_id = u.id where ur.role_key = %s and u.is_active'', (''SECURITY_OFFICER'',)).fetchone()[0])'
$officers = -1
$officerCount = Invoke-Capture $VenvPython @('-c', $officerCode)
if ($officerCount.Code -eq 0) {
    $parsedOfficers = 0
    if ([int]::TryParse($officerCount.Text.Trim(), [ref] $parsedOfficers)) { $officers = $parsedOfficers }
}
$ownerEmail = $demoOwner
if (-not $ownerEmail) { $ownerEmail = 'you@example.org' }
$consoleUrl = "http://127.0.0.1:$Port/ui/"

$openDecision = Get-OpenDecision -Force ([bool] $Open) -Interactive $script:Interactive -Desktop ([bool] [Environment]::UserInteractive)
if ($Open -and $openDecision -eq 'skip') {
    Write-Note 'No desktop was found, so no browser will be opened. Open the address below yourself.'
}
if ($openDecision -eq 'ask') {
    $answer = Read-Line 'Open the console in your browser when it is ready? [Y/n]' -Suffix ' '
    if (Test-AnswerYes $answer) { $openDecision = 'open' } else { $openDecision = 'skip' }
}

Write-Host ''
Write-Host '  ------------------------------------------------------------' -ForegroundColor Green
Write-Host '  You are ready.' -ForegroundColor Green
Write-Host '  ------------------------------------------------------------' -ForegroundColor Green
Write-Detail "console:  $consoleUrl"
if ($adminEmail) { Write-Detail "sign in:  $adminEmail, with the password from step 6" }
else { Write-Detail 'sign in:  your email and password' }
Write-Detail '          then the six-digit code from your authenticator app'
Write-Detail "start:    next time, from $RepoRoot run:"
Write-Detail '          powershell -ExecutionPolicy Bypass -File .\release\start.ps1'
Write-Detail 'stop:     press Ctrl+C here. The containers keep running; to stop them too, from that folder:'
Write-Detail '          docker compose -f infra/docker-compose.yml down'
Write-Detail 'help:     release\START-HERE.md, and release\MANUAL.md for what each pane does'
Write-Host ''
Write-Host '  This is a beta: use it on synthetic or published, non-personal data only.' -ForegroundColor Yellow
Write-Host '  Real case material needs legal review first (docs/16, "Read this before you hold anything").' -ForegroundColor Yellow
if (-not $demoLoaded) {
    Write-Host ''
    Write-Host "  To load the fictional demo case later, from ${RepoRoot}:"
    Write-Host "      .venv\Scripts\python scripts\bootstrap.py demo-network --owner-email $ownerEmail --code $demoCode --classification CLEAR"
}
Write-Host ''
Write-Host '  The bigger showcase case the README screenshots come from is in'
Write-Host '  README.md, section "First run".'
if ($officers -le 0) {
    Write-Host ''
    Write-Host '  Nobody holds the Security Officer role yet, so collection runs and break-glass' -ForegroundColor Yellow
    Write-Host '  are refused. That does not matter for the demo. To fix it, give the role to a' -ForegroundColor Yellow
    Write-Host '  second person, not to your own account (release\INSTALL.md, "After installing"):' -ForegroundColor Yellow
    # security.officer@, not officer@: officer@example.org is the account
    # seed_readme_showcase.py creates, so after the README recipe this
    # command exited 1 with "already exists", and run first it would have
    # made the seeder adopt the real officer (Alpha 6 pre-release check,
    # 2026-09-23).
    Write-Host '      .venv\Scripts\python scripts\bootstrap.py create-user --email security.officer@example.org --name "Officer Name" --roles SECURITY_OFFICER'
}
Write-Host ''
Write-Host '  Uploading samples is refused until a prohibited-content policy is' -ForegroundColor Yellow
Write-Host '  declared (README, L1). That refusal is deliberate.' -ForegroundColor Yellow
Write-Host ''
Write-Host '  The API log follows below. Leave this window open while you use it.'
Write-Host ''

# Open the console once the API answers, from a background job so uvicorn can
# stay in the foreground and keep Ctrl+C. The job gives up after a minute.
$openJob = $null
if ($openDecision -eq 'open') {
    $openJob = Start-Job -ScriptBlock {
        param($jobPort, $jobUrl)
        for ($i = 0; $i -lt 60; $i++) {
            try {
                $client = New-Object System.Net.Sockets.TcpClient
                $client.Connect('127.0.0.1', $jobPort)
                $client.Close()
                Start-Process $jobUrl
                return
            }
            catch { Start-Sleep -Seconds 1 }
        }
    } -ArgumentList $Port, $consoleUrl
}

# Uvicorn logs to stderr. Run it bare, not piped and not redirected, so the log
# reaches the console as plain text and Ctrl+C reaches the process.
Set-Location -LiteralPath $RepoRoot
$ErrorActionPreference = 'Continue'
try {
    & $VenvPython -m uvicorn 'noctornal_api.http.app:app' --host 127.0.0.1 --port $Port
    $apiExit = $LASTEXITCODE
}
finally {
    if ($openJob) {
        Stop-Job -Job $openJob -ErrorAction SilentlyContinue
        Remove-Job -Job $openJob -Force -ErrorAction SilentlyContinue
    }
}
exit $apiExit

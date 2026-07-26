#Requires -Version 5
<#
.SYNOPSIS
    Starts the whole NocTORnal development stack: Docker services, database
    migrations, then the API.

.DESCRIPTION
    One command, in order: Docker engine -> compose stack -> TOTP key ->
    environment -> migrations -> first-user check -> API. Safe to re-run;
    every step is idempotent and reports what it found rather than assuming.

.PARAMETER SkipDocker
    Assume the compose stack is already up. Skips the engine and container
    health checks.

.PARAMETER Port
    Port for the API. Default 8000.

.EXAMPLE
    .\scripts\launch.ps1
#>
[CmdletBinding()]
param(
    [switch] $SkipDocker,
    [int]    $Port = 8000
)

# Cmdlet failures abort. Native executables do not honour this, so every
# external call below checks its exit code explicitly.
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

$RepoRoot    = Split-Path -Parent $PSScriptRoot
$ComposeFile = Join-Path $RepoRoot 'infra\docker-compose.yml'
$VenvScripts = Join-Path $RepoRoot '.venv\Scripts'
$Python      = Join-Path $VenvScripts 'python.exe'
$AlembicExe  = Join-Path $VenvScripts 'alembic.exe'
$EnvLocal    = Join-Path $RepoRoot '.env.local'

# ---------------------------------------------------------------------------
# Output and process helpers
# ---------------------------------------------------------------------------

$script:StepNumber = 0

function Write-Step {
    param([string] $Text)
    $script:StepNumber++
    Write-Host ''
    Write-Host ("[{0}] {1}" -f $script:StepNumber, $Text) -ForegroundColor Cyan
}

function Write-Detail { param([string] $Text) Write-Host "    $Text" }
function Write-Good   { param([string] $Text) Write-Host "    $Text" -ForegroundColor Green }
function Write-Note   { param([string] $Text) Write-Host "    $Text" -ForegroundColor Yellow }

function Stop-With {
    param([string] $Problem, [string[]] $Remedy = @())
    Write-Host ''
    Write-Host "  FAILED: $Problem" -ForegroundColor Red
    if ($Remedy.Count -gt 0) {
        Write-Host ''
        Write-Host '  What to do:' -ForegroundColor Yellow
        foreach ($line in $Remedy) { Write-Host "    $line" }
    }
    Write-Host ''
    exit 1
}

function Invoke-Capture {
    # Runs a native command and returns its exit code plus combined output.
    # Redirecting native stderr into a variable raises NativeCommandError when
    # $ErrorActionPreference is 'Stop' on PowerShell 5.1, so the preference is
    # relaxed for the duration of the call only.
    param([Parameter(Mandatory)][string] $Exe, [string[]] $Arguments = @())
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # Redirected stderr arrives as ErrorRecord objects on 5.1, which
        # Out-String would render with a stack-trace banner around every line.
        # Flatten them to their message so the output reads as the tool wrote it.
        $text = & $Exe @Arguments 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_ }
        } | Out-String
        [pscustomobject]@{ Code = $LASTEXITCODE; Text = $text }
    }
    finally { $ErrorActionPreference = $saved }
}

function Write-Indented {
    param([string] $Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    foreach ($line in ($Text.TrimEnd() -split "`r?`n")) { Write-Host "    | $line" }
}

function Test-PortInUse {
    param([int] $Number)
    $props = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    foreach ($listener in $props.GetActiveTcpListeners()) {
        if ($listener.Port -eq $Number) { return $true }
    }
    return $false
}

Write-Host ''
Write-Host '  NocTORnal - launching the development stack' -ForegroundColor White
Write-Host "  repo: $RepoRoot"

# ---------------------------------------------------------------------------
# Step 0: preflight. Fail here rather than three minutes into Docker.
# ---------------------------------------------------------------------------

Write-Step 'Checking the Python environment'

if (-not (Test-Path -LiteralPath $Python)) {
    Stop-With "no virtual environment at $($RepoRoot)\.venv" @(
        'Create it and install the packages, from the repo root:',
        '  python -m venv .venv',
        '  .venv\Scripts\python -m pip install -r db\requirements.txt',
        '  .venv\Scripts\python -m pip install -e packages\ontology -e apps\api'
    )
}

# uvicorn and the two editable packages are what the last step actually needs.
$probe = Invoke-Capture $Python @('-c', 'import uvicorn, alembic, noctornal_api, noctornal_ontology, igraph, leidenalg')
if ($probe.Code -ne 0) {
    Write-Indented $probe.Text
    Stop-With 'the virtual environment is missing packages the API needs' @(
        'Install them, from the repo root:',
        '  .venv\Scripts\python -m pip install -r db\requirements.txt',
        '  .venv\Scripts\python -m pip install -e packages\ontology -e apps\api',
        '',
        'Then run this script again.'
    )
}
Write-Good 'virtual environment ready'

# ---------------------------------------------------------------------------
# Step a: the Docker engine
# ---------------------------------------------------------------------------

Write-Step 'Checking Docker'

if ($SkipDocker) {
    Write-Detail 'skipped (-SkipDocker); assuming the compose stack is already up'
}
else {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Stop-With 'the docker command was not found' @(
            'Install Docker Desktop, then run this script again:',
            '  https://www.docker.com/products/docker-desktop/'
        )
    }

    if ((Invoke-Capture 'docker' @('info')).Code -eq 0) {
        Write-Good 'Docker engine responding'
    }
    else {
        Write-Detail 'Docker engine not responding; trying to start Docker Desktop'

        $desktop = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
        if (Test-Path -LiteralPath $desktop) {
            Start-Process -FilePath $desktop | Out-Null
            Write-Detail 'Docker Desktop launched; it takes a minute or two to become usable'
        }
        else {
            Write-Note "Docker Desktop not found at $desktop - waiting in case the engine is starting anyway"
        }

        # Poll rather than sleep-once: first start after a reboot is slow and
        # highly variable, and a fixed wait either fails early or wastes time.
        $started  = Get-Date
        $deadline = $started.AddMinutes(3)
        $ready    = $false
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 5
            if ((Invoke-Capture 'docker' @('info')).Code -eq 0) { $ready = $true; break }
            $waited = [int]((Get-Date) - $started).TotalSeconds
            Write-Detail "still waiting for the Docker engine (${waited}s of 180s)"
        }

        if (-not $ready) {
            Stop-With 'the Docker engine did not come up within three minutes' @(
                'Open Docker Desktop by hand and wait until the whale icon in the',
                'system tray stops animating and the dashboard says "Engine running".',
                '',
                'If it never starts, the usual causes are:',
                '  - WSL 2 is not installed or needs updating: run  wsl --update',
                '  - virtualisation is disabled in the BIOS/UEFI',
                '  - a pending Windows restart',
                '',
                'Once the dashboard shows the engine running, re-run this script.'
            )
        }
        Write-Good 'Docker engine responding'
    }
}

# ---------------------------------------------------------------------------
# Step b: the compose stack
# ---------------------------------------------------------------------------

Write-Step 'Starting the service containers (Postgres, Redis, MinIO, OpenFGA, NATS, Mailpit)'

if ($SkipDocker) {
    Write-Detail 'skipped (-SkipDocker)'
}
else {
    if (-not (Test-Path -LiteralPath $ComposeFile)) {
        Stop-With "no compose file at $ComposeFile"
    }

    # -f rather than a directory change: compose derives the project directory
    # from the compose file, so the relative volume paths (../db/init) still
    # resolve, and the caller's working directory is left alone.
    $up = Invoke-Capture 'docker' @('compose', '-f', $ComposeFile, 'up', '-d')
    Write-Indented $up.Text
    if ($up.Code -ne 0) {
        Stop-With 'docker compose up failed' @(
            'Read the output above. Common causes:',
            '  - a port is already taken (5432, 6379, 9000, 9001, 8080, 4222, 8025)',
            '    stop whatever else is using it, or stop a stale stack:',
            "      docker compose -f `"$ComposeFile`" down",
            '  - an image could not be pulled: check the network and try again'
        )
    }

    # Postgres is the only container the next steps depend on, and it is the
    # only one with a healthcheck. Alembic against a still-initialising cluster
    # fails in confusing ways, so wait for healthy rather than for running.
    Write-Detail 'waiting for Postgres to report healthy'
    $started  = Get-Date
    $deadline = $started.AddMinutes(3)
    $healthy  = $false
    $lastSeen = 'unknown'

    while ((Get-Date) -lt $deadline) {
        $ids = Invoke-Capture 'docker' @('compose', '-f', $ComposeFile, 'ps', '-q', 'postgres')
        $containerId = ($ids.Text -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)

        if ($containerId) {
            $inspect = Invoke-Capture 'docker' @('inspect', '--format', '{{.State.Health.Status}}', $containerId.Trim())
            $lastSeen = $inspect.Text.Trim()
            if ($lastSeen -eq 'healthy') { $healthy = $true; break }
        }

        Start-Sleep -Seconds 3
        $waited = [int]((Get-Date) - $started).TotalSeconds
        Write-Detail "Postgres status: $lastSeen (${waited}s of 180s)"
    }

    if (-not $healthy) {
        Stop-With "Postgres did not become healthy (last status: $lastSeen)" @(
            'Look at the container log:',
            "  docker compose -f `"$ComposeFile`" logs postgres",
            '',
            'If a previous run died part-way through first-time initialisation,',
            'the data volume keeps a half-built cluster and the init scripts will',
            'not re-run. That state is only recoverable by destroying the volume',
            '(this deletes all local case data):',
            "  docker compose -f `"$ComposeFile`" down -v",
            '  then run this script again.'
        )
    }
    Write-Good 'Postgres healthy'
}

# ---------------------------------------------------------------------------
# Step c: the TOTP key-encryption key
# ---------------------------------------------------------------------------

Write-Step 'Checking the TOTP key-encryption key'

$kekFromEnvironment = -not [string]::IsNullOrWhiteSpace($env:NOCTORNAL_TOTP_KEK)
if ($kekFromEnvironment) {
    Write-Good 'NOCTORNAL_TOTP_KEK already set in this environment'
}

# Load the local key store first, then generate only if the key is still
# missing. An explicitly exported value always wins over the file, which is
# the usual .env precedence and stops this script overriding a deliberate
# choice made by whoever launched it.
if (Test-Path -LiteralPath $EnvLocal) {
    Write-Detail "reading $EnvLocal"
    foreach ($line in (Get-Content -LiteralPath $EnvLocal)) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }

        $split = $trimmed.IndexOf('=')
        if ($split -lt 1) { continue }

        $name  = $trimmed.Substring(0, $split).Trim()
        $value = $trimmed.Substring($split + 1).Trim().Trim('"').Trim("'")
        if (-not $name) { continue }

        $current = [System.Environment]::GetEnvironmentVariable($name, 'Process')
        if (-not [string]::IsNullOrWhiteSpace($current)) {
            Write-Detail "$name already set in the environment - file value ignored"
            continue
        }
        [System.Environment]::SetEnvironmentVariable($name, $value, 'Process')
        Write-Detail "$name loaded from .env.local"
    }
}

if ([string]::IsNullOrWhiteSpace($env:NOCTORNAL_TOTP_KEK)) {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $generated = [Convert]::ToBase64String($bytes)

    if (Test-Path -LiteralPath $EnvLocal) {
        # The file exists but carries no key: append rather than replace, so
        # anything else the operator put in there survives.
        Add-Content -LiteralPath $EnvLocal -Value "NOCTORNAL_TOTP_KEK=$generated"
    }
    else {
        $header = @(
            '# NocTORnal local key store. Created by scripts/launch.ps1.',
            '#',
            '# NOCTORNAL_TOTP_KEK seals every TOTP secret at rest. LOSING THIS FILE',
            '# MEANS EVERY USER MUST RE-ENROL THEIR AUTHENTICATOR. Back it up',
            '# somewhere you trust; it is deliberately not committed (.gitignore',
            '# covers .env.*) and there is no default anywhere in the code.',
            '#',
            '# Anything else you add here as KEY=VALUE is loaded into the',
            '# environment on launch.',
            "NOCTORNAL_TOTP_KEK=$generated",
            ''
        ) -join "`n"
        [System.IO.File]::WriteAllText($EnvLocal, $header, (New-Object System.Text.UTF8Encoding($false)))
    }

    $env:NOCTORNAL_TOTP_KEK = $generated

    Write-Host ''
    Write-Host '    ------------------------------------------------------------' -ForegroundColor Yellow
    Write-Host '    A NEW TOTP KEY WAS GENERATED AND SAVED TO:' -ForegroundColor Yellow
    Write-Host "      $EnvLocal" -ForegroundColor Yellow
    Write-Host '' -ForegroundColor Yellow
    Write-Host '    That file is now your key store. It seals every TOTP secret in' -ForegroundColor Yellow
    Write-Host '    the database. If you lose it, every user has to re-enrol their' -ForegroundColor Yellow
    Write-Host '    authenticator app - there is no recovery and no default key.' -ForegroundColor Yellow
    Write-Host '    Keep a backup. It is git-ignored, so it will never be committed.' -ForegroundColor Yellow
    Write-Host '    ------------------------------------------------------------' -ForegroundColor Yellow
    Write-Host ''
}
elseif (-not $kekFromEnvironment) {
    Write-Good 'TOTP key ready'
}

# ---------------------------------------------------------------------------
# Step d: the rest of the environment
# ---------------------------------------------------------------------------

Write-Step 'Setting the service connection details'

# Dev-only credentials, mirroring infra/docker-compose.yml. They are the only
# literal secrets allowed in this repo, they only ever address containers on
# localhost, and a real deployment supplies all of these from the environment
# or Vault instead.
$defaults = [ordered]@{
    DATABASE_URL     = 'postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal'
    # Rate limiting. Unset, the limiter falls back to per-process metering
    # and warns; set, the meter is shared and a second uvicorn worker does
    # not double every limit.
    REDIS_URL        = 'redis://localhost:6379/0'
    MINIO_ENDPOINT   = 'localhost:9000'
    MINIO_ACCESS_KEY = 'noctornal'
    MINIO_SECRET_KEY = 'dev_only_change_me'
    EVIDENCE_BUCKET  = 'noctornal-evidence'
    # Raw ingest payloads, in their OWN bucket and deliberately without
    # object lock. An exhibit is locked so not even root can delete it
    # before its deadline; a partner's raw submission must stay deletable,
    # because it runs on a short category clock and may have to go in
    # response to a deletion order (decision 50). Compose creates it with
    # `mc mb --ignore-existing local/noctornal-raw` -- note the absent
    # `--with-lock`, which is the difference that matters.
    INGEST_BUCKET    = 'noctornal-raw'
}

foreach ($name in $defaults.Keys) {
    $current = [System.Environment]::GetEnvironmentVariable($name, 'Process')
    if ([string]::IsNullOrWhiteSpace($current)) {
        [System.Environment]::SetEnvironmentVariable($name, $defaults[$name], 'Process')
        Write-Detail "$name set to the local development default"
    }
    else {
        Write-Detail "$name kept from the environment"
    }
}

# ---------------------------------------------------------------------------
# Step e: migrations
# ---------------------------------------------------------------------------

Write-Step 'Applying database migrations (alembic upgrade head)'

# Alembic resolves script_location and prepend_sys_path from alembic.ini
# relative to the working directory, so it must run from the repo root.
# Start-Process with -WorkingDirectory does that without moving the caller.
$alembicArgs = @('upgrade', 'head')
if (Test-Path -LiteralPath $AlembicExe) {
    $alembicTarget = $AlembicExe
}
else {
    $alembicTarget = $Python
    $alembicArgs   = @('-m', 'alembic') + $alembicArgs
}

# -Wait is what makes ExitCode readable: without it the returned object has
# dropped the process handle and ExitCode comes back null. A null is treated as
# a failure here rather than a pass - a migration that cannot be confirmed to
# have succeeded must not let the API start against a half-built schema.
$run = Start-Process -FilePath $alembicTarget -ArgumentList $alembicArgs `
    -WorkingDirectory $RepoRoot -NoNewWindow -Wait -PassThru
$migrationExit = $run.ExitCode
if ($null -eq $migrationExit) { $migrationExit = 'unknown' }

if ($migrationExit -ne 0) {
    Stop-With "alembic upgrade head failed (exit $migrationExit)" @(
        'Read the traceback above. Common causes:',
        '  - Postgres accepting connections but the schema half-built from an',
        '    interrupted first run. Destroy the volume and start clean (this',
        '    deletes all local case data):',
        "      docker compose -f `"$ComposeFile`" down -v",
        '  - a migration genuinely failing: fix the migration, do not edit the',
        '    database by hand. One owner of the schema, no drift.'
    )
}
Write-Good 'schema up to date'

# ---------------------------------------------------------------------------
# Step f: is there anyone who can log in?
# ---------------------------------------------------------------------------

Write-Step 'Checking for a user account'

$countCode = 'import noctornal_api.db as d; print(d.connect().execute(''select count(*) from iam.app_user'').fetchone()[0])'
$count = Invoke-Capture $Python @('-c', $countCode)

if ($count.Code -ne 0) {
    # Not fatal: a failed count must not stop the API from starting.
    Write-Note 'could not count users (the API may still work) - output was:'
    Write-Indented $count.Text
}
else {
    $users = 0
    if ([int]::TryParse($count.Text.Trim(), [ref] $users) -and $users -gt 0) {
        Write-Good "$users user account(s) exist"
    }
    else {
        $bootstrap = Join-Path $RepoRoot 'scripts\bootstrap.py'
        Write-Host ''
        Write-Host '    ============================================================' -ForegroundColor Yellow
        Write-Host '    NO USER ACCOUNTS YET - you cannot log in until you make one.' -ForegroundColor Yellow
        Write-Host '' -ForegroundColor Yellow
        Write-Host '    In a SECOND terminal, from the repo root, run:' -ForegroundColor Yellow
        Write-Host ''
        # One line on purpose: it is meant to be copied, and a wrapped command
        # needs a different continuation character in PowerShell than in cmd.
        Write-Host '      .venv\Scripts\python scripts\bootstrap.py create-user --email you@example.com --name "Your Name"' -ForegroundColor White
        Write-Host ''
        if (-not (Test-Path -LiteralPath $bootstrap)) {
            Write-Host '    Note: scripts\bootstrap.py does not exist in this checkout yet,' -ForegroundColor Yellow
            Write-Host '    so that command will fail until it is written.' -ForegroundColor Yellow
            Write-Host ''
        }
        Write-Host '    ============================================================' -ForegroundColor Yellow
        Write-Host ''
    }
}

# ---------------------------------------------------------------------------
# Step g: the API
# ---------------------------------------------------------------------------

Write-Step 'Starting the API'

if (Test-PortInUse -Number $Port) {
    Stop-With "port $Port is already in use" @(
        'Either something else is on that port, or an earlier copy of the API is',
        'still running. Stop it, or pick another port:',
        "  .\scripts\launch.ps1 -Port $($Port + 1)"
    )
}

Write-Host ''
Write-Host '  Everything is up. Open this in your browser:' -ForegroundColor Green
Write-Host "      http://127.0.0.1:$Port/ui/" -ForegroundColor White
Write-Host ''
Write-Host '  Also available:'
Write-Host '      http://localhost:9001   MinIO console (evidence store)'
Write-Host '      http://localhost:8025   Mailpit (captured e-mail)'
Write-Host '      http://localhost:3001   OpenFGA playground'

# The OpenAPI page is off unless NOCTORNAL_ENABLE_DOCS says otherwise: it
# describes the shape of a case system, so it stays opt-in. Advertise the URL
# only when it will actually answer.
$docsFlag = ''
if ($env:NOCTORNAL_ENABLE_DOCS) { $docsFlag = $env:NOCTORNAL_ENABLE_DOCS.ToLower() }
if ($docsFlag -eq '1' -or $docsFlag -eq 'true') {
    Write-Host "      http://127.0.0.1:$Port/api/v1/docs   API reference"
}
Write-Host ''
Write-Host '  The API log follows below. Press Ctrl+C to stop it.'
Write-Host '  The containers keep running afterwards; stop them with:'
Write-Host "      docker compose -f `"$ComposeFile`" down"
Write-Host ''

# Uvicorn logs to stderr. Run it bare - not piped, not redirected - so the log
# reaches the console as plain text and Ctrl+C reaches the process.
$ErrorActionPreference = 'Continue'
& $Python -m uvicorn 'noctornal_api.http.app:app' --host 127.0.0.1 --port $Port
exit $LASTEXITCODE

<#
.SYNOPSIS
  Mint a session and open the analyst UI in your browser. One command.

.DESCRIPTION
  `bootstrap.py session` already prints a URL that lands you signed in, but
  it needs DATABASE_URL and NOCTORNAL_TOTP_KEK in the environment first, and
  then you have to copy the URL out of the terminal. This does all three
  steps: loads .env.local the same way launch.ps1 does, applies the same
  development defaults, and hands the URL to your browser.

  It does NOT start anything. If the stack or the API is down, run
  scripts/launch.ps1 instead -- that starts Docker, applies migrations and
  serves the API, and this is the "I already have it running" shortcut.

  The token travels in the URL fragment, so it is never sent to the server
  and never appears in an access log; the page erases it from the address
  bar on load. It is still recorded in the audit trail as an MFA-bypassed
  login, because a session that appeared from nowhere would be worse than
  no session at all.

.PARAMETER Email
  The account to sign in as. Defaults to the only user if there is exactly
  one, so the common case needs no arguments at all.

.PARAMETER Port
  Port the API is serving on. Default 8000.

.PARAMETER PrintOnly
  Print the URL instead of launching a browser.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File "scripts\open-ui.ps1"

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File "scripts\open-ui.ps1" -Email you@example.com
#>
[CmdletBinding()]
param(
    [string] $Email,
    [int]    $Port = 8000,
    [switch] $PrintOnly
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$EnvLocal = Join-Path $RepoRoot '.env.local'
$Python   = Join-Path $RepoRoot '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $Python)) {
    Write-Error "No virtualenv at .venv. Run scripts\launch.ps1 first -- it creates one."
    exit 1
}

# .env.local holds NOCTORNAL_TOTP_KEK. An already-set environment variable
# wins, matching launch.ps1: the file is a convenience, not an override.
if (Test-Path -LiteralPath $EnvLocal) {
    foreach ($line in Get-Content -LiteralPath $EnvLocal) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        $split = $trimmed.IndexOf('=')
        if ($split -lt 1) { continue }
        $name  = $trimmed.Substring(0, $split).Trim()
        $value = $trimmed.Substring($split + 1).Trim().Trim('"').Trim("'")
        if (-not $name) { continue }
        if ([string]::IsNullOrWhiteSpace(
                [System.Environment]::GetEnvironmentVariable($name, 'Process'))) {
            [System.Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
}

# The same dev-only default launch.ps1 uses. It only ever addresses a
# container on localhost; a real deployment supplies this from the
# environment or Vault.
if ([string]::IsNullOrWhiteSpace($env:DATABASE_URL)) {
    $env:DATABASE_URL =
        'postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal'
}

if ([string]::IsNullOrWhiteSpace($env:NOCTORNAL_TOTP_KEK)) {
    Write-Error @'
NOCTORNAL_TOTP_KEK is not set and .env.local does not supply it.
That file is created by scripts\launch.ps1 on first run. Run the launcher
once, or set the variable yourself if you have the key somewhere durable.
'@
    exit 1
}

# Is anything actually listening? A browser opening onto a connection error
# is a worse message than this one.
try {
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/healthz" -TimeoutSec 3 `
        -UseBasicParsing | Out-Null
}
catch {
    Write-Error @"
Nothing is serving on port $Port.
Start it with:  powershell -ExecutionPolicy Bypass -File "scripts\launch.ps1"
(-SkipDocker if the containers are already up.)
"@
    exit 1
}

# With one account, asking which is just friction.
if (-not $Email) {
    $listing = & $Python (Join-Path $PSScriptRoot 'bootstrap.py') list-users 2>&1
    $emails  = @([regex]::Matches(($listing -join "`n"),
                 '[\w.+-]+@[\w.-]+\.\w+') | ForEach-Object { $_.Value } |
                 Select-Object -Unique)
    if ($emails.Count -eq 1) {
        $Email = $emails[0]
        Write-Host "Signing in as $Email (the only account)." -ForegroundColor DarkGray
    }
    elseif ($emails.Count -eq 0) {
        Write-Error @'
No accounts exist yet. Create one:
  .venv\Scripts\python scripts\bootstrap.py create-user --email you@example.com --name "Your Name"
'@
        exit 1
    }
    else {
        Write-Error ("Several accounts exist; pick one with -Email.`n  " +
                     ($emails -join "`n  "))
        exit 1
    }
}

$argv = @('session', '--email', $Email, '--port', $Port)
if (-not $PrintOnly) { $argv += '--open' }
& $Python (Join-Path $PSScriptRoot 'bootstrap.py') @argv
exit $LASTEXITCODE

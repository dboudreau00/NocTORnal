#Requires -Version 5
<#
.SYNOPSIS
    Package NocTORnal for handover, via `git archive`.

.DESCRIPTION
    Produces a STANDALONE tree (and optionally a .zip) that a recipient can
    install from. Replaces scripts/assemble_release.ps1, which copied only
    the six files in release/ and produced something that could not install
    anything (release finding R1).

    ## Why `git archive` and never a zip of the working tree (R2)

    A zip of the working directory ships four things that must never leave
    this machine, and `git archive` cannot ship any of them because it
    exports the COMMIT, not the directory:

      .env.local   the real TOTP KEK. Double damage: the secret leaks, AND
                   both installers see the file exists and skip secret
                   generation -- so the recipient runs on the dev key and
                   never gets an ingest pepper.
      .venv        a copied Windows venv passes install.ps1's existence
                   check but its pyvenv.cfg points at THIS machine's
                   Python; pip then fails and the script's diagnosis
                   ("no network access, or a corporate proxy") is wrong.
      .git         the full history, including anything ever committed and
                   later removed.
      screenshots/ renders of real case panes. .gitignore's own comment
      shots/       classifies them as the same disclosure as the case file.

    Everything above is gitignored or untracked, so `git archive` omits all
    of it by construction rather than by a list somebody has to maintain.

.PARAMETER Destination
    Where to write the tree. Defaults to a sibling of the repository named
    "NocTORnal - Alpha Release".

.PARAMETER Ref
    What to package. Defaults to HEAD. Use a tag for a real release.

.PARAMETER Zip
    Also produce <Destination>.zip.

.PARAMETER Force
    Overwrite an existing destination.

.EXAMPLE
    .\scripts\package_release.ps1
    .\scripts\package_release.ps1 -Ref v0.1.0-alpha -Zip
#>
[CmdletBinding()]
param(
    [string] $Destination,
    [string] $Ref = 'HEAD',
    [switch] $Zip,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

function Say  { param($t) Write-Host "  $t" -ForegroundColor Cyan }
function Good { param($t) Write-Host "    $t" -ForegroundColor Green }
function Warn { param($t) Write-Host "    $t" -ForegroundColor Yellow }
function Die  { param($t) Write-Host "`n  $t`n" -ForegroundColor Red; exit 1 }

$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Destination) {
    $Destination = Join-Path (Split-Path -Parent $RepoRoot) 'NocTORnal - Alpha Release'
}

Push-Location $RepoRoot
try {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Die 'git is required: this script packages a commit, not a directory.'
    }

    # An uncommitted change is not in the commit, so it will not be in the
    # package -- and the operator will not find that out until the
    # recipient does. Say so before doing the work.
    $dirty = git status --porcelain
    if ($dirty) {
        Warn 'The working tree has uncommitted changes. They will NOT be'
        Warn 'packaged -- git archive exports the commit, not the directory:'
        $dirty -split "`n" | Select-Object -First 12 | ForEach-Object {
            if ($_) { Write-Host "      $_" -ForegroundColor DarkYellow }
        }
        if (-not $Force) {
            Die 'Commit them, or re-run with -Force to package HEAD as it stands.'
        }
    }

    if ((Test-Path $Destination) -and -not $Force) {
        Die "Destination already exists: $Destination`n  Use -Force to overwrite."
    }
    if (Test-Path $Destination) { Remove-Item -Recurse -Force $Destination }
    New-Item -ItemType Directory -Force $Destination | Out-Null

    Say "Packaging $Ref"
    # `git archive --format=zip` + Expand-Archive, NOT tar.
    #
    # `tar` is not reliably the one you think on Windows. With Git for
    # Windows on PATH ahead of System32 -- which is the normal result of
    # installing it -- `tar` is the MSYS build, and it interprets a
    # `C:/...` destination as a REMOTE HOST, failing with "Cannot connect
    # to C: resolve failed". Found by running this script rather than by
    # reading it.
    #
    # zip has no such ambiguity: git writes it, and Expand-Archive ships
    # with PowerShell 5.1, so neither depends on PATH order.
    $tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) "noctornal-$(Get-Random).zip"
    git archive --format=zip --output="$tmpZip" $Ref
    if ($LASTEXITCODE -ne 0) { Die "git archive failed for ref '$Ref'." }
    try {
        Expand-Archive -LiteralPath $tmpZip -DestinationPath $Destination -Force
    }
    catch { Die "extraction failed: $_" }
    finally { Remove-Item -Force -ErrorAction SilentlyContinue $tmpZip }
    Good "wrote $Destination"

    # ---- verify, rather than trust ------------------------------------
    # The point of this script is that four specific things are absent.
    # Checking is cheap; discovering otherwise from the recipient is not.
    Say 'Verifying the package'
    $mustNotExist = @('.env.local', '.venv', '.git', 'screenshots', 'shots')
    $leaked = @()
    foreach ($name in $mustNotExist) {
        if (Test-Path (Join-Path $Destination $name)) { $leaked += $name }
    }
    if ($leaked.Count) {
        Die ("PACKAGE IS UNSAFE -- it contains: " + ($leaked -join ', ') +
             "`n  Do not hand this over. git archive should have excluded them.")
    }
    Good 'no .env.local, no .venv, no .git, no screenshots'

    foreach ($needed in @('alembic.ini', 'release/install.ps1',
                          'release/install.sh', 'apps/api/pyproject.toml',
                          'infra/docker-compose.yml', 'LICENSE')) {
        if (-not (Test-Path (Join-Path $Destination $needed))) {
            Die "PACKAGE IS INCOMPLETE -- missing $needed"
        }
    }
    Good 'installers, alembic.ini, compose file and LICENSE all present'

    # install.sh must keep LF endings or `#!/usr/bin/env bash\r` is not a
    # shebang. .gitattributes enforces it; this proves it survived.
    $sh = Get-Content -Raw -Path (Join-Path $Destination 'release/install.sh')
    if ($sh -match "`r`n") {
        Die 'install.sh has CRLF line endings and will not run on Linux.'
    }
    Good 'install.sh is LF'

    # BOTH INSTALLERS MUST PARSE. Added after this script happily packaged
    # an install.ps1 that did not: an edit put a literal newline inside a
    # comment, so the continuation line stopped being a comment and
    # PowerShell tried to run `at`. The failure appeared only when somebody
    # ran the packaged artefact. A syntax check is free; a recipient
    # discovering it is not.
    $psErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $Destination 'release\install.ps1'),
        [ref]$null, [ref]$psErrors) | Out-Null
    if ($psErrors -and $psErrors.Count) {
        Die ("install.ps1 does not parse -- " + $psErrors[0].Message +
             " (line " + $psErrors[0].Extent.StartLineNumber + ")")
    }
    Good 'install.ps1 parses'

    if (Get-Command bash -ErrorAction SilentlyContinue) {
        $null = & bash -n (Join-Path $Destination 'release/install.sh') 2>&1
        if ($LASTEXITCODE -ne 0) { Die 'install.sh does not parse (bash -n).' }
        Good 'install.sh parses'
    }

    if ($Zip) {
        $zipPath = "$Destination.zip"
        if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
        Compress-Archive -Path "$Destination\*" -DestinationPath $zipPath
        Good "wrote $zipPath"
        Warn 'A recipient unzipping this on Linux/macOS must run:'
        Warn '    chmod +x release/install.sh'
        Warn 'and on Windows must launch it as:'
        Warn '    powershell -ExecutionPolicy Bypass -File .\release\install.ps1'
        Warn '(zip carries no execute bit, and downloaded files carry MotW).'
    }

    Write-Host ''
    Say 'Done. Tell the recipient to start at release/INSTALL.md.'
    Write-Host ''
}
finally { Pop-Location }

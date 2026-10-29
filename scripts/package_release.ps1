#Requires -Version 5
<#
.SYNOPSIS
    Package NocTORnal for handover, via `git archive`.

.DESCRIPTION
    Produces a STANDALONE tree (and optionally a .zip) that a recipient can
    install from. Replaced scripts/assemble_release.ps1, which copied only
    the six files in release/ and produced something that could not install
    anything (release finding R1). That script has since been DELETED, not
    merely deprecated: it defaulted to this same destination path, so the
    superseded one could silently overwrite a good package with six files
    that install nothing, and its name is the one that sounds correct to
    run. This is now the only packaging script.

    ## Why `git archive` and never a zip of the working tree (R2)

    A zip of the working directory ships four things that must never leave
    this machine, and `git archive` cannot ship any of them because it
    exports the COMMIT, not the directory:

      .env.local   the real TOTP KEK. Double damage: the secret leaks, AND
                   both installers see the file exists and skip secret
                   generation, so the recipient runs on the dev key and
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
        Warn 'packaged, because git archive exports the commit, not the directory:'
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
    # `git archive --format=zip` + Expand-Archive, not tar: with Git for Windows ahead of System32
    # on PATH, `tar` is the MSYS build, which reads a `C:/...` destination as a remote host. git
    # writes the zip and Expand-Archive ships with PowerShell 5.1, so neither depends on PATH order.
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
        Die ("PACKAGE IS UNSAFE. It contains: " + ($leaked -join ', ') +
             "`n  Do not hand this over. git archive should have excluded them.")
    }
    Good 'no .env.local, no .venv, no .git, no screenshots'

    # Both installers refuse to run without constraints.txt.
    foreach ($needed in @('alembic.ini', 'release/install.ps1',
                          'release/install.sh', 'release/START-HERE.md',
                          'release/start.sh', 'release/start.ps1',
                          'apps/api/pyproject.toml',
                          'constraints.txt',
                          'infra/docker-compose.yml', 'LICENSE')) {
        if (-not (Test-Path (Join-Path $Destination $needed))) {
            Die "PACKAGE IS INCOMPLETE: missing $needed"
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

    # Both installers must parse: a syntax error otherwise surfaces only when a recipient runs the
    # packaged artefact.
    $psErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $Destination 'release\install.ps1'),
        [ref]$null, [ref]$psErrors) | Out-Null
    if ($psErrors -and $psErrors.Count) {
        Die ("install.ps1 does not parse: " + $psErrors[0].Message +
             " (line " + $psErrors[0].Extent.StartLineNumber + ")")
    }
    Good 'install.ps1 parses'

    # `bash` on Windows may be System32\bash.exe, a WSL shim that fails when no distribution is
    # installed and writes to stderr, which under $ErrorActionPreference = 'Stop' raises
    # NativeCommandError. So Git's bash is looked for first, and the check is skipped loudly when
    # no bash runs: only a bash that ran and said no is a reason to refuse to package.
    $bash = $null
    foreach ($candidate in @(
        (Join-Path $env:ProgramFiles 'Git\bin\bash.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Git\bin\bash.exe'),
        (Get-Command bash -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Source -First 1)
    )) {
        if (-not $candidate) { continue }
        # The WSL shim lives in System32 and is never the right choice here:
        # even with a distro installed it would parse the file inside a
        # different filesystem view, which is not what is being verified.
        if ($candidate -like "$env:SystemRoot\System32\*") { continue }
        if (Test-Path -LiteralPath $candidate) { $bash = $candidate; break }
    }

    if (-not $bash) {
        Warn 'skipped the install.sh syntax check: no usable bash found'
        Warn '(the WSL shim in System32 does not count). Install Git for'
        Warn 'Windows, or run this check on the target platform.'
    }
    else {
        $saved = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $shPath = (Join-Path $Destination 'release/install.sh') -replace '\\', '/'
            $out = & $bash -n $shPath 2>&1 | ForEach-Object {
                if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_ }
            } | Out-String
            $code = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $saved }
        if ($code -ne 0) {
            Die ("install.sh does not parse (bash -n):`n    " + $out.Trim())
        }
        Good "install.sh parses (via $bash)"
    }

    if ($Zip) {
        $zipPath = "$Destination.zip"
        if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
        # Archive the directory, not its contents: every entry sits under one wrapper folder, so
        # unzipping does not scatter the release into the recipient's Downloads. One entry per file,
        # named here with forward slashes, not ZipFile.CreateFromDirectory or Compress-Archive:
        # under Windows PowerShell 5.1 CreateFromDirectory stores backslashes, which unzip on Linux
        # rejects and Python's zipfile turns into loose files.
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $wrapper = Split-Path -Leaf $Destination
        $base = (Resolve-Path -LiteralPath $Destination).ProviderPath.TrimEnd('\') + '\'
        $writer = [System.IO.Compression.ZipFile]::Open(
            $zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($file in Get-ChildItem -LiteralPath $Destination -Recurse -File -Force) {
                $name = $wrapper + '/' + ($file.FullName.Substring($base.Length) -replace '\\', '/')
                [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $writer, $file.FullName, $name,
                    [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
            }
        }
        finally { $writer.Dispose() }

        # Confirm the wrapper is there rather than assuming it. Split on either separator, so a
        # backslash name is counted below rather than reported as hundreds of roots.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            $roots = @($archive.Entries |
                ForEach-Object { ($_.FullName -split '[\\/]')[0] } |
                Sort-Object -Unique)
            $entryCount = $archive.Entries.Count
            $backslashed = @($archive.Entries |
                Where-Object { $_.FullName.Contains([char]92) }).Count
        }
        finally { $archive.Dispose() }
        if ($roots.Count -ne 1) {
            Die ("the zip has $($roots.Count) top-level entries and should " +
                 "have exactly one wrapper directory: " + ($roots -join ', '))
        }

        # ZipArchiveEntry.FullName is the name as stored, under 5.1 and 7 alike, so this checks the
        # stored separators.
        if ($backslashed) {
            Die ("the zip has $backslashed entry names with a backslash; " +
                 "unzip on Linux and macOS would not rebuild the folders.")
        }
        Good "wrote $zipPath ($entryCount entries, wrapped in '$($roots[0])', forward slashes)"
        Warn 'A recipient unzipping this on Linux/macOS must run:'
        Warn '    chmod +x release/install.sh'
        Warn 'and on Windows must launch it as:'
        Warn '    powershell -ExecutionPolicy Bypass -File .\release\install.ps1'
        Warn '(zip carries no execute bit, and downloaded files carry MotW).'
    }

    Write-Host ''
    Say 'Done. Tell the recipient to start at release/START-HERE.md.'
    Write-Host ''
}
finally { Pop-Location }

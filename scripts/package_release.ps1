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
    that install nothing -- and its name is the one that sounds correct to
    run. This is now the only packaging script.

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

    # `bash` on Windows is not the bash you meant.
    #
    # This ran `& bash -n ...` against whatever `Get-Command bash` returned,
    # and on a machine with the Windows Subsystem for Linux feature enabled
    # but NO distribution installed, that is C:\Windows\System32\bash.exe --
    # a shim which fails with
    #
    #   WSL (...) ERROR: CreateProcessCommon:818: execvpe(/bin/bash) failed
    #
    # Two things then went wrong at once. The shim writes that to stderr,
    # and under $ErrorActionPreference = 'Stop' a native command writing to
    # stderr raises NativeCommandError -- so the script died with a raw .NET
    # exception BEFORE reaching its own error handling, and produced no zip
    # at all. install.ps1 and launch.ps1 both carry Invoke-Capture for
    # exactly this hazard; this script did not.
    #
    # Second, even reaching the check, a shim that cannot start any shell is
    # not evidence that install.sh is malformed. An absent interpreter must
    # SKIP the check, loudly. Only a bash that actually ran and said no is a
    # reason to refuse to package.
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
        # ARCHIVE THE DIRECTORY, NOT ITS CONTENTS.
        #
        # `-Path "$Destination\*"` produces a zip whose entries sit at the
        # ROOT, so unzipping it scatters twenty-two top-level files and
        # folders loose into whatever directory the recipient happened to
        # be in -- typically Downloads, mixed in with everything else.
        # Getting that back out is manual and irritating, and it is the
        # first thing they experience.
        #
        # Passing the directory itself wraps everything in one folder,
        # which is what every release archive a developer has ever
        # downloaded does.
        # ZipFile.CreateFromDirectory, not Compress-Archive.
        #
        # `includeBaseDirectory: $true` is the wrapper, done by the API
        # rather than by argument-shape trickery, and this is the
        # documented .NET entry point rather than a cmdlet whose path
        # handling has changed between PowerShell versions.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            $Destination, $zipPath,
            [System.IO.Compression.CompressionLevel]::Optimal,
            $true)

        # Confirm the wrapper is actually there rather than assuming it.
        # This script has already shipped one artefact it had "verified"
        # without executing -- see the install.ps1 parse check above.
        #
        # Split on EITHER separator. The zip format stores forward slashes
        # and the archive on disk does use them, but .NET's
        # ZipArchiveEntry.FullName reports the platform separator here, so
        # a check that split on '/' alone saw one 300-segment "root" and
        # failed a perfectly good archive. Accepting both is correct
        # whichever way the runtime reports it.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            $roots = @($archive.Entries |
                ForEach-Object { ($_.FullName -split '[\\/]')[0] } |
                Sort-Object -Unique)
            $entryCount = $archive.Entries.Count
        }
        finally { $archive.Dispose() }
        if ($roots.Count -ne 1) {
            Die ("the zip has $($roots.Count) top-level entries and should " +
                 "have exactly one wrapper directory: " + ($roots -join ', '))
        }

        # NOT checked here: whether the stored separators are forward
        # slashes. They must be -- a zip carrying backslashes makes Unix
        # `unzip` create files literally named "dir\sub\file" instead of
        # directories -- but this runtime cannot answer the question.
        # .NET's ZipArchiveEntry.FullName reports the PLATFORM separator on
        # read, so a check here reports backslashes for an archive whose
        # stored bytes are correct. An earlier version of this script did
        # exactly that and refused to package a perfectly good zip.
        #
        # ZipFile.CreateFromDirectory writes spec-compliant forward slashes,
        # which is one of the reasons it is used above instead of
        # Compress-Archive. Confirm from outside PowerShell if it matters:
        #     python -c "import zipfile,sys; print(zipfile.ZipFile(sys.argv[1]).namelist()[:3])" <zip>
        Good "wrote $zipPath ($entryCount entries, wrapped in '$($roots[0])')"
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

#Requires -Version 5
<#
.SYNOPSIS
    Assemble the distributable release folder from release/.

.DESCRIPTION
    `release/` in this repository is the SOURCE OF TRUTH for the packaged
    release: it is versioned, it shows up in diffs, and it cannot drift
    away from the code it documents without somebody seeing the change.

    This script copies it out to a standalone folder for handing to
    somebody. The copy is disposable; regenerate it rather than editing
    it, or you will have two sources of truth and the wrong one will be
    the one you hand over.

    ## SUPERSEDED 2026-07-26 by scripts/package_release.ps1 (R1)

    THIS SCRIPT DOES NOT PRODUCE AN INSTALLABLE ARTEFACT and never did.

    It copies only the six files in `release/`. The installers then locate
    the application by probing for `alembic.ini` in and beside their own
    directory, with a final fallback to the HARDCODED sibling name
    "NocTORnal - Social Network Analysis software" — which resolves on the
    machine this was written on and almost nowhere else. A recipient handed
    the assembled folder alone gets "the application source could not be
    found", and the error's first suggestion ("put it next to the
    application source directory") silently fails for any other folder name.

    Use `scripts/package_release.ps1` instead: it exports the whole tree
    with `git archive`, which cannot include `.env.local`, `.venv`, `.git`
    or the screenshot directories, and it verifies that before finishing.

    This script is kept only for producing a DOCS-ONLY bundle for somebody
    who already has the source, and it now says so on the way out.

.PARAMETER Destination
    Where to write it. Defaults to a sibling of the repository named
    "NocTORnal - Alpha Release".

.PARAMETER Force
    Overwrite an existing destination.

.EXAMPLE
    .\scripts\assemble_release.ps1
#>
[CmdletBinding()]
param(
    [string] $Destination,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$SourceDir  = Join-Path $RepoRoot 'release'
if (-not $Destination) {
    $Destination = Join-Path (Split-Path -Parent $RepoRoot) 'NocTORnal - Alpha Release'
}

if (-not (Test-Path $SourceDir)) {
    Write-Host "release/ not found at $SourceDir" -ForegroundColor Red
    exit 1
}

if ((Test-Path $Destination) -and -not $Force) {
    # Not silently overwritten. The destination is where somebody may have
    # put notes, a signed manifest or a licence they cleared -- and this
    # script has no way to tell those from a stale copy.
    Write-Host ''
    Write-Host "  $Destination already exists." -ForegroundColor Yellow
    Write-Host '  Re-run with -Force to overwrite it.' -ForegroundColor Yellow
    Write-Host ''
    exit 1
}

New-Item -ItemType Directory -Force -Path $Destination | Out-Null
Copy-Item (Join-Path $SourceDir '*') -Destination $Destination -Recurse -Force

# The shell installer needs its executable bit, which a Windows filesystem
# does not carry. Say so rather than shipping a file that fails with
# "permission denied" on the target.
Write-Host ''
Write-Host '  Assembled:' -ForegroundColor Green
Write-Host "    $Destination"
Get-ChildItem $Destination | ForEach-Object {
    Write-Host ("      {0,-16} {1,7:N0} bytes" -f $_.Name, $_.Length)
}
Write-Host ''
Write-Host '  On macOS/Linux the shell installer needs its executable bit:' -ForegroundColor Yellow
Write-Host '      chmod +x install.sh'
Write-Host ''
# R1: say plainly what this folder is NOT, at the moment somebody is about
# to hand it over. The failure it prevents -- a recipient who cannot
# install anything -- is silent until they try.
Write-Host '  THIS FOLDER IS DOCUMENTATION AND INSTALLERS ONLY.' -ForegroundColor Red
Write-Host '  It contains no application source, so it CANNOT install' -ForegroundColor Red
Write-Host '  NocTORnal on a machine that does not already have the repo.' -ForegroundColor Red
Write-Host ''
Write-Host '  For a handover artefact somebody can actually install from:' -ForegroundColor Yellow
Write-Host '      .\scripts\package_release.ps1 -Zip'
Write-Host ''

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

    The installers resolve the application by looking for alembic.ini in,
    and beside, their own directory — so they work identically whether
    they are run from `release/` inside the repo or from the assembled
    folder next to it.

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

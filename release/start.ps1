#Requires -Version 5
<#
.SYNOPSIS
    Start NocTORnal again after the first install, on Windows.

.DESCRIPTION
    Runs scripts\launch.ps1 and nothing else: Docker, the four containers,
    the database migrations, then the API. Safe to run any time. Stop the
    API with Ctrl+C. Help: release\START-HERE.md.

.PARAMETER Port
    Port for the API. Default 8000.

.PARAMETER SkipDocker
    The containers are already up.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\release\start.ps1
#>
[CmdletBinding()]
param(
    [int]    $Port = 8000,
    [switch] $SkipDocker
)

$ErrorActionPreference = 'Stop'

# Through a new PowerShell with the bypass, as install.ps1 hands off: the
# default execution policy blocks a script from a downloaded zip.
$launch = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\launch.ps1'
$launchArgs = @('-ExecutionPolicy', 'Bypass', '-File', $launch, '-Port', $Port)
if ($SkipDocker) { $launchArgs += '-SkipDocker' }
& powershell @launchArgs
exit $LASTEXITCODE

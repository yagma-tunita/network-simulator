# Code-sign the Windows CLI with signtool.
# Requires the Windows SDK signtool and a code-signing certificate (.pfx).
#   powershell -ExecutionPolicy Bypass -File packaging\sign.ps1 -Pfx cert.pfx -Password secret
param(
    [Parameter(Mandatory = $true)][string]$Pfx,
    [Parameter(Mandatory = $true)][string]$Password
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$stamp = 'http://timestamp.digicert.com'
$exe = Join-Path $root 'netsim.exe'
if (-not (Test-Path $exe)) { throw "missing $exe (build first)" }
& signtool sign /fd SHA256 /f $Pfx /p $Password /tr $stamp /td SHA256 $exe
if ($LASTEXITCODE -ne 0) { throw 'signing failed' }
& signtool verify /pa $exe
Write-Host 'signed and verified'

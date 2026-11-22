# Build the Windows CLI (bundled Lua) and produce a portable ZIP.
# Requires MinGW-w64 (g++, gcc, windres) on PATH.
#   powershell -ExecutionPolicy Bypass -File packaging\build-win.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    & mingw32-make -f Makefile.win -B
    if ($LASTEXITCODE -ne 0) { throw "build failed" }

    $ver = (Get-Content VERSION -Raw).Trim()
    New-Item -ItemType Directory -Force -Path dist | Out-Null
    $zip = Join-Path $root "dist\yanas-net-$ver-cli-win64.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }

    $items = @(
        'netsim.exe', 'docs',
        'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'VERSION', 'CHANGELOG.md'
    )
    Compress-Archive -Path $items -DestinationPath $zip -Force
    Write-Host "wrote $zip"
}
finally {
    Pop-Location
}

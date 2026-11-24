# Build the Windows CLI (bundled Lua) and produce a portable ZIP.
# The ZIP also contains a source archive (GPLv3 compliance).
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

    $stage = Join-Path $root 'dist\src-stage'
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $stage | Out-Null

    $srcDirs = @('core','device','link','engine','topo','netstack','app','script','win','tests','docs','examples','third_party','packaging','tools','.github')
    foreach ($d in $srcDirs) {
        $p = Join-Path $root $d
        if (Test-Path $p) { Copy-Item -Recurse -Force $p (Join-Path $stage $d) }
    }
    $srcFiles = @('CMakeLists.txt','Makefile','Makefile.win','README.md','LICENSE','COPYRIGHT',
                  'THIRD_PARTY_NOTICES.md','SOURCE-CODE.md','CONTRIBUTING.md','SECURITY.md',
                  'VERSION','CHANGELOG.md','DEVELOPMENT_LOG.md','.clang-tidy','.gitignore','.gitattributes')
    foreach ($f in $srcFiles) {
        $p = Join-Path $root $f
        if (Test-Path $p) { Copy-Item -Force $p (Join-Path $stage $f) }
    }
    Get-ChildItem -Path $stage -Recurse -File -Include *.o,*.a,*.exe,*.d,*.gcda,*.gcno,*.gcov -ErrorAction SilentlyContinue | Remove-Item -Force

    $srcZip = Join-Path $root "dist\yanas-net-$ver-src.zip"
    Remove-Item -Force $srcZip -ErrorAction SilentlyContinue
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $srcZip -Force
    Remove-Item -Recurse -Force $stage

    $zip = Join-Path $root "dist\yanas-net-$ver-cli-win64.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }

    $items = @(
        'netsim.exe', 'examples', 'docs',
        'README.md', 'LICENSE', 'COPYRIGHT', 'THIRD_PARTY_NOTICES.md',
        'SOURCE-CODE.md', 'CONTRIBUTING.md', 'SECURITY.md', 'VERSION', 'CHANGELOG.md'
    )
    Compress-Archive -Path $items -DestinationPath $zip -Force
    Compress-Archive -Path $srcZip -DestinationPath $zip -Update

    Write-Host "wrote $zip"
    Write-Host "wrote $srcZip"
}
finally {
    Pop-Location
}

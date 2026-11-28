$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path '.\netsim.exe')) {
    throw 'netsim.exe not found; run: mingw32-make -f Makefile.win'
}

$ErrorActionPreference = 'Continue'
$status = 0

foreach ($file in Get-ChildItem 'tests\*.txt') {
    $wantPath = [System.IO.Path]::ChangeExtension($file.FullName, '.want')
    if (-not (Test-Path $wantPath)) { continue }
        $want = (Get-Content -Raw $wantPath).TrimEnd()
        $out = (& .\netsim.exe -q $file.FullName 2>&1 | Out-String)
        $want = $want -replace "`r`n", "`n"
        $out = $out -replace "`r`n", "`n"
    if ($out.Contains($want) -and -not $out.Contains('fatal:')) {
        Write-Host "PASS  $($file.Name)"
    } else {
        Write-Host "FAIL  $($file.Name)  (want: $want)"
        Write-Host $out
        $status = 1
    }
}

$features = (& .\netsim.exe --features 2>&1 | Out-String)
if ($features -match 'lua') {
    foreach ($file in Get-ChildItem 'tests\*.lua' -ErrorAction SilentlyContinue) {
        $wantPath = [System.IO.Path]::ChangeExtension($file.FullName, '.want')
        if (-not (Test-Path $wantPath)) { continue }
        $want = (Get-Content -Raw $wantPath).TrimEnd()
    $out = (& .\netsim.exe -q $file.FullName 2>&1 | Out-String)
    $want = $want -replace "`r`n", "`n"
    $out = $out -replace "`r`n", "`n"
        if ($out.Contains($want) -and -not $out.Contains('fatal:')) {
            Write-Host "PASS  $($file.Name)"
        } else {
            Write-Host "FAIL  $($file.Name)  (want: $want)"
            Write-Host $out
            $status = 1
        }
    }
}

foreach ($file in Get-ChildItem 'examples\*' -Include *.txt, *.lua, *.yn) {
    & .\netsim.exe -q $file.FullName 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "PASS  example $($file.Name)"
    } else {
        Write-Host "FAIL  example $($file.Name)"
        $status = 1
    }
}

Remove-Item (Join-Path $root 'tests\netsim_test.pcap') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_tcp_test.pcap') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_saved.yn') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_ipv6_saved.yn') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_acl_saved.yn') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_acl6_saved.yn') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_nat_saved.yn') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_span_saved.yn') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_bgp_saved.yn') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_bgp_filter_saved.yn') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_bgp_asf_saved.yn') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_bgp_prepend_saved.yn') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_bgp_comm_saved.yn') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'tests\netsim_bgp_max_saved.yn') -Force -ErrorAction SilentlyContinue
exit $status

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$cap = 'tests\netsim_tcp_test.pcap'
Remove-Item (Join-Path $root $cap) -Force -ErrorAction SilentlyContinue
& .\netsim.exe -q tests\tcp_pcap.txt | Out-Null
& .\build\ynpcap.exe -q $cap
$status = $LASTEXITCODE
if ($status -ne 0) {
    exit $status
}
Remove-Item (Join-Path $root $cap) -Force -ErrorAction SilentlyContinue
Write-Host 'pcap conformance: ok'

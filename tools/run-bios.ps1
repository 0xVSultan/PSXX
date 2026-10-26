# Usage: .\tools\run-bios.ps1 -Exe build\psx\psxx.exe [-Bios "SCPH1001"] [-All]
# Runs DuckStation with a per-run settings copy, so your real settings.ini is untouched.
param([string]$Exe = "$PSScriptRoot\..\build\psx\psxx.exe", [string]$Bios, [switch]$All)
$dir  = "$PSScriptRoot\..\psxbios"
$base = "$env:LOCALAPPDATA\DuckStation\settings.ini"
$ds   = (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Recurse -Filter duckstation-qt*.exe | Select -First 1).FullName
$list = Get-ChildItem $dir -File | ? { $All -or $_.Name -like "*$Bios*" }
if (-not $list) { throw "no matching BIOS" }
foreach ($b in $list) {
  $ini = Join-Path $env:TEMP "ds-$($b.BaseName -replace '\W','_').ini"
  $t = (Get-Content $base) | ? { $_ -notmatch '^(PathNTSC[UJ]|PathPAL|SearchDirectory)\s*=' }
  $t = $t -replace '^\[BIOS\]', "[BIOS]`nPathNTSCU = $($b.Name)`nPathNTSCJ = $($b.Name)`nPathPAL = $($b.Name)`nSearchDirectory = $((Resolve-Path $dir).Path)"
  Set-Content $ini $t
  Write-Host "BIOS: $($b.Name)"
  Start-Process $ds -ArgumentList '-settings', "`"$ini`"", '-exe', "`"$((Resolve-Path $Exe).Path)`"" -Wait
}


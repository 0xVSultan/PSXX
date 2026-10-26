# Usage: .\tools\run-card.ps1 [-Bios SCPH7001] [-Card build\card\psxx.mcd]
# Boots the BIOS shell in a portable DuckStation copy (toolchain\duckstation) with the card in slot 1.
param([string]$Bios = "SCPH7001", [string]$Card = "$PSScriptRoot\..\build\card\psxx.mcd")
$root = (Resolve-Path "$PSScriptRoot\..").Path
$b    = Get-ChildItem "$root\psxbios" -File | ? Name -like "*$Bios*" | Select -First 1
if (-not $b) { throw "BIOS not found: $Bios" }
$run  = "$root\build\card\run.mcd"; Copy-Item $Card $run -Force   # emulator writes to a copy
$dsdir = "$root\toolchain\duckstation"
$t = Get-Content "$env:LOCALAPPDATA\DuckStation\settings.ini" | ? { $_ -notmatch '^(PathNTSC[UJ]|PathPAL|SearchDirectory|Card1Type|Card1Path|FastBoot)\s*=' }
$t = $t -replace '^\[BIOS\]', "[BIOS]`nPathNTSCU = $($b.Name)`nPathNTSCJ = $($b.Name)`nPathPAL = $($b.Name)`nSearchDirectory = $root\psxbios"
$t = $t -replace '^\[MemoryCards\]', "[MemoryCards]`nCard1Type = File`nCard1Path = $run"
Set-Content "$dsdir\settings.ini" $t
Write-Host "BIOS $($b.Name), card $run"
Start-Process "$dsdir\duckstation-qt-x64-ReleaseLTCG.exe" -ArgumentList '-bios'

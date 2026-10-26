# Usage: .\tools\probe-log.ps1 [-All]
# Shows the output of the card probe (M0) as DuckStation writes it to toolchain\duckstation\duckstation.log: the [card], [stat] and [dump] lines (with -All the whole TTY).
# Start it in a terminal of your own; stop it with Ctrl+C.
param([switch]$All)
$log = (Resolve-Path "$PSScriptRoot\..").Path + "\toolchain\duckstation\duckstation.log"
if (-not (Test-Path $log)) { throw "no log yet: $log (start tools\run-probe-duckstation.ps1 first)" }
$pattern = if ($All) { 'TTY:' } else { 'TTY: \[(card|stat|dump|ldr|ovl)\]' }
Write-Host "reading $log (Ctrl+C to stop)"
Get-Content -Path $log -Wait -Tail 200 | Where-Object { $_ -match $pattern } | ForEach-Object { $_ -replace '^.*TTY: ', '' }

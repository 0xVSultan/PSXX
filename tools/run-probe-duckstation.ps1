# Usage: .\tools\run-probe-duckstation.ps1 [-Card1 build\card\psxx-1002-cardprobe.mcd] [-Card2 build\card\blank-slot2.mcd] [-Bios SCPH1002] [-OneCard] [-NoLaunch] [-Ini path]
# Starts the portable DuckStation (toolchain\duckstation) with the SCPH-1002 BIOS and a card in BOTH slots, to try the card probe.
# F5 is bound to "Swap Memory Card Slots" of DuckStation, a quick way to take a card out and put it in while the program runs:
#   two cards (default): F5 exchanges the cards of the two ports at once (the content of both slots changes, no card is absent);
#   -OneCard (only the card of slot 1, slot 2 empty): F5 moves the card to the other port and the next F5 back: the slot it left is empty until the second press, so the
#   time between two presses is the time the card is out. The probe is booted from the card in slot 1; the emulator does not need a card in slot 2 for that
#   (a real SCPH-1002 does).
# Slowly: Settings > Memory Cards > Card 2 > type "No Memory Card" ejects it, "Shared" with a path inserts it again (a path change while it runs is a card swap).
# Keyboard (Pad1 of the portable settings): K cross, L circle, J square, I triangle, Q L1, E R1, 1 L2, 3 R2, Backspace select, Enter start, F5 swap the cards.
# Order, as for every emulator run: all emulators are stopped first (and none may be left), the card of slot 2 is saved if it is not the blank one, only then DuckStation starts.
# The cards are copies (build\card\run.mcd, run2.mcd), the originals are not touched. The TTY output of the program is logged to toolchain\duckstation\duckstation.log
# and shown in a second window (only the [card], [stat] and [dump] lines).
param(
    [string]$Card1 = "build\card\psxx-1002-cardprobe.mcd",
    [string]$Card2 = "build\card\blank-slot2.mcd",
    [string]$Bios = "SCPH1002",
    [string]$Ini = "",
    [switch]$OneCard,
    [switch]$NoLaunch,
    [string]$Exe = ""
)
# -Exe: run a PS-X EXE instead of booting the shell (the portable DuckStation takes -exe), the cards are as above. From the project root:
#   .\tools\run-probe-duckstation.ps1 -Exe build\psx\psxx_signer_keys.exe -Card1 build\card\blank-slot2.mcd -Card2 build\card\keys.mcd
$root = (Resolve-Path "$PSScriptRoot\..").Path
$dsdir = "$root\toolchain\duckstation"
if (-not $Ini) { $Ini = "$dsdir\settings.ini" }
$b = Get-ChildItem "$root\psxbios" -File | Where-Object Name -like "*$Bios*" | Select-Object -First 1
if (-not $b) { throw "BIOS not found: $Bios" }
foreach ($f in @($Card1, $Card2)) { if (-not (Test-Path "$root\$f")) { throw "card image not found: $f" } }

# set key = value in a section of an ini file (lines array), adding the key or the section if needed
function Set-Ini([System.Collections.Generic.List[string]]$lines, [string]$section, [string]$key, [string]$value) {
    $start = $lines.FindIndex({ param($l) $l -eq "[$section]" })
    if ($start -lt 0) { $lines.Add(""); $lines.Add("[$section]"); $lines.Add("$key = $value"); return }
    $end = $lines.Count
    for ($i = $start + 1; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\[') { $end = $i; break } }
    for ($i = $start + 1; $i -lt $end; $i++) {
        if ($lines[$i] -match "^$([regex]::Escape($key))\s*=") { $lines[$i] = "$key = $value"; return }
    }
    $lines.Insert($end, "$key = $value")
}

if (-not $NoLaunch) {
    Get-Process | Where-Object { $_.Name -match 'pcsx|duckstation|no\$psx|nops' } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $left = @(Get-Process | Where-Object { $_.Name -match 'pcsx|duckstation|no\$psx|nops' }).Count
    if ($left -ne 0) { throw "$left emulator process(es) are still running" }
}

$run1 = "$root\build\card\run.mcd"
$run2 = "$root\build\card\run2.mcd"
$logs = "$root\build\card\logs"
if ((Test-Path $run2) -and (Get-FileHash $run2).Hash -ne (Get-FileHash "$root\$Card2").Hash) {
    New-Item -ItemType Directory -Force $logs | Out-Null
    $save = "$logs\slot2-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".mcd"
    Copy-Item $run2 $save
    Write-Host "the old slot 2 card was saved as $save"
}
if (-not $NoLaunch) {
    Copy-Item "$root\$Card1" $run1 -Force
    Copy-Item "$root\$Card2" $run2 -Force
}

$lines = [System.Collections.Generic.List[string]]::new()
$lines.AddRange([string[]](Get-Content $Ini))
foreach ($k in 'PathNTSCU', 'PathNTSCJ', 'PathPAL') { Set-Ini $lines 'BIOS' $k $b.Name }
Set-Ini $lines 'BIOS' 'SearchDirectory' "$root\psxbios"
Set-Ini $lines 'BIOS' 'TTYLogging' 'true'
Set-Ini $lines 'BIOS' 'FastForwardBoot' 'false'
Set-Ini $lines 'BIOS' 'PatchFastBoot' 'false'
Set-Ini $lines 'MemoryCards' 'Card1Type' 'Shared'                   # 'Shared': the card of Card1Path (DuckStation has no 'File' type: it took its default, a per-game card, and left slot 2 empty)
Set-Ini $lines 'MemoryCards' 'Card1Path' $run1
Set-Ini $lines 'MemoryCards' 'Card2Type' $(if ($OneCard) { 'None' } else { 'Shared' })
Set-Ini $lines 'MemoryCards' 'Card2Path' $run2
Set-Ini $lines 'Logging' 'LogToFile' 'true'
Set-Ini $lines 'Hotkeys' 'SwapMemoryCards' 'Keyboard/F5'
Set-Content -Path $Ini -Value $lines -Encoding UTF8
if ($OneCard) { Write-Host "BIOS $($b.Name), ONE card: slot 1 $run1 (from $Card1), slot 2 empty (F5 moves the card between the ports)" }
else { Write-Host "BIOS $($b.Name), slot 1 card $run1 (from $Card1), slot 2 card $run2 (from $Card2)" }
if ($NoLaunch) { Write-Host "settings written to $Ini, DuckStation not started"; return }

$log = "$dsdir\duckstation.log"
Set-Content -Path $log -Value "" -Encoding ASCII
if ($Exe) {
    $exeFull = if (Test-Path "$root\$Exe") { "$root\$Exe" } else { $Exe }
    if (-not (Test-Path $exeFull)) { throw "EXE not found: $Exe" }
    Start-Process "$dsdir\duckstation-qt-x64-ReleaseLTCG.exe" -ArgumentList '-exe', ('"' + (Resolve-Path $exeFull).Path + '"')
} else {
    Start-Process "$dsdir\duckstation-qt-x64-ReleaseLTCG.exe" -ArgumentList '-bios'
}
Start-Sleep -Seconds 2
Start-Process powershell -ArgumentList '-NoExit', '-Command', "Get-Content -Path '$log' -Wait -Tail 0 | Select-String -Pattern 'card\]|stat\]|dump\]|ldr\]|ovl\]|prof\]|psxx' | ForEach-Object { `$_.Line }"
Write-Host "DuckStation started; the probe output is also in $log"
for ($i = 0; $i -lt 20; $i++) {                       # which cards DuckStation really plugged in (the log says so at the start)
    Start-Sleep -Milliseconds 500
    $pad = Select-String -Path $log -Pattern 'Pad: Memory card slot [01]:' -ErrorAction SilentlyContinue
    if (@($pad).Count -ge 2) { $pad | ForEach-Object { Write-Host ("  " + ($_.Line -replace '^.*Pad: ', '')) }; break }
}

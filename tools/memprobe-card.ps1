# Usage: .\tools\memprobe-card.ps1 [-Bios SCPH1002] [-All]
# Builds the memory probe (hal/psx/memprobe.c) and its boot card for slot 1 of a real console (FreePSXBoot): build\card\psxx-<bios>-memprobe.mcd. -Bios is a part of the name of a file
# in psxbios\ (default SCPH1002 = BIOS 2.0 E, which is also build\card\psxx-1002-memprobe.mcd); -All makes the cards of every BIOS in psxbios\ that FreePSXBoot supports.
# Put a formatted card in slot 2 (the probe writes its report there as PSXXMP01..), start the console, press X, wait about a minute, read the card with
#   py -3.13 tools\memprobe_read.py <dump of the card in slot 2>
# For an emulator: .\tools\run-probe-duckstation.ps1 -Bios SCPH1000 -Card1 build\card\psxx-1000-memprobe.mcd (the TTY shows the [mem] lines). Each BIOS has its own report (the first
# line of a report names the BIOS and its ROM CRC-32): read the card of slot 2 of each run with memprobe_read.py --out <name>.txt and compare the files.
param([string]$Bios = "SCPH1002", [switch]$All)
$root = (Resolve-Path "$PSScriptRoot\..").Path
. "$root\env.ps1"
# the BIOS files of psxbios\ by ROM CRC-32: the name FreePSXBoot's builder takes, the model for the card file name
$known = @{
    "3b601fc8" = @("1.0-19940922-I", "1000");  "3539def6" = @("1.1-19950122-I", "3000");  "37157331" = @("2.2-19951204-A", "1001");  "9bb87c4b" = @("2.0-19950510-E", "1002")
    "bc190209" = @("2.1-19950717-I", "3500");  "24fc7e17" = @("2.2-19951204-I", "5000");  "ff3eeb8c" = @("3.0-19960909-I", "5500");  "d786f0b9" = @("3.0-19970106-E", "5552")
    "8d8cb7e4" = @("3.0-19961118-A", "7003");  "ec541cd0" = @("4.0-19970818-I", "7000");  "502224b6" = @("4.1-19971216-A", "7001");  "318178bf" = @("4.1-19971216-E", "7502")
    "171bdcec" = @("4.5-20000525-A", "101")
}
function Crc32([byte[]]$b) { $t = New-Object 'uint32[]' 256; for ($i = 0; $i -lt 256; $i++) { $c = [uint32]$i; for ($k = 0; $k -lt 8; $k++) { if ($c -band 1) { $c = [uint32](0xEDB88320 -bxor ($c -shr 1)) } else { $c = $c -shr 1 } }; $t[$i] = $c }
    $r = [uint32]::MaxValue; foreach ($x in $b) { $r = $t[($r -bxor $x) -band 0xFF] -bxor ($r -shr 8) }; return ('{0:x8}' -f ($r -bxor [uint32]::MaxValue)) }
Push-Location "$root\build\psx"
try { ninja psxx_memprobe; if ($LASTEXITCODE) { throw "ninja failed" } } finally { Pop-Location }
py -3.13 "$root\tools\packexe.py" "$root\build\psx\psxx_memprobe.exe" "$root\build\psx\psxx_memprobe_packed.exe"
if ($LASTEXITCODE) { throw "packexe failed" }
$files = Get-ChildItem "$root\psxbios" -File | Where-Object { $All -or $_.Name -like "*$Bios*" }
if (-not $files) { throw "no BIOS file matches $Bios in psxbios\" }
$done = @{}
foreach ($f in $files) {
    $crc = Crc32 ([IO.File]::ReadAllBytes($f.FullName))
    if (-not $known.ContainsKey($crc)) { Write-Host "skipped $($f.Name): ROM CRC-32 $crc is not one that FreePSXBoot lists"; continue }
    if ($done.ContainsKey($crc)) { continue }
    $done[$crc] = 1
    $v, $m = $known[$crc]
    $out = "$root\build\card\psxx-$m-memprobe.mcd"
    & "$root\toolchain\FreePSXBoot\builder\builder.exe" -bios $v -slot 1 -in "$root\build\psx\psxx_memprobe_packed.exe" -out $out | Out-Null
    if ($LASTEXITCODE) { throw "builder failed for $v" }
    Write-Host ("card: build\card\psxx-{0}-memprobe.mcd  (BIOS {1}, ROM CRC-32 {2}, {3})" -f $m, $v, $crc, $f.Name)
}

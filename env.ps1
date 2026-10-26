# Dot-source: . .\env.ps1
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$sdk  = "$root\toolchain\sdk\PSn00bSDK-0.24-win32"
$env:PSN00BSDK_LIBS = "$sdk\lib\libpsn00b"
$env:PATH = "$sdk\bin;$root\toolchain\gcc\bin;C:\msys64\ucrt64\bin;C:\msys64\usr\bin;$env:PATH"
Write-Host "psx-x env ready (host gcc + mipsel-none-elf + PSn00bSDK)"

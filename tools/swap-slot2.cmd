@echo off
rem Swaps the card of slot 2 in no$psx: the new image is copied next to the card file with a fresh time stamp and then renamed over it
rem in one step, so no$psx reloads it (the program sees CONTENT CHANGED). The card file is never missing: no$psx does not take a missing file for a card that was taken
rem out (15.1), and a read of the card while the file was missing stopped it with "NO$PSX - FATAL _01_2_A_.mcd" (the card watch looks at the card every 5 s).
rem   tools\swap-slot2.cmd                 the same card again (reloaded)
rem   tools\swap-slot2.cmd toggle          the other one of build\card\blank-slot2.mcd and build\card\signer-demo-xmr.mcd
rem   tools\swap-slot2.cmd file.mcd        that card image
rem   tools\swap-slot2.cmd ok|damaged|wrong|empty   the B cards of build\release\demo (big-ok, big-damaged ...: those of build\release\demo-big)
rem Run it from anywhere with the full path, or from the project root as tools\swap-slot2.cmd
rem A card that is none of the two known ones is copied to build\card\logs\slot2-<time>.mcd before it is replaced (it may hold logs).
rem If the emulator keeps the file open, the rename fails and nothing is changed.
setlocal enabledelayedexpansion
for %%i in ("%~dp0..") do set "ROOT=%%~fi"
set "DIR=%ROOT%\emulator\npsx\MEMCARD"
set "CARD=%DIR%\_01_2_A_.mcd"
set "NEXT=%DIR%\_01_2_A_.new"
set "A=%ROOT%\build\card\blank-slot2.mcd"
set "B=%ROOT%\build\card\signer-demo-xmr.mcd"
set "NEW="
set "KNOWN="

if not exist "%CARD%" echo The slot 2 card file is missing: %CARD% & exit /b 1

fc /b "%CARD%" "%A%" >nul 2>nul && set "KNOWN=blank"
fc /b "%CARD%" "%B%" >nul 2>nul && set "KNOWN=demo"

if "%~1"=="" goto :args_done
if /i "%~1"=="toggle" (
  if "!KNOWN!"=="blank" (set "NEW=%B%") else (set "NEW=%A%")
) else (
  set "NEW=%~f1"
  set "K=%~1"
  set "SET=demo"
  if /i "!K:~0,4!"=="big-" (set "SET=demo-big" & set "K=!K:~4!")
  if exist "%ROOT%\build\release\!SET!\B-!K!.mcd" set "NEW=%ROOT%\build\release\!SET!\B-!K!.mcd"
)
:args_done

if defined NEW if not exist "!NEW!" echo Card image not found: !NEW! & exit /b 1

if defined NEW if not defined KNOWN (
  for /f %%i in ('powershell -nologo -noprofile -command "Get-Date -Format yyyyMMdd-HHmmss"') do set "TS=%%i"
  if not exist "%ROOT%\build\card\logs" mkdir "%ROOT%\build\card\logs"
  copy /y "%CARD%" "%ROOT%\build\card\logs\slot2-!TS!.mcd" >nul
  echo The old card was saved as build\card\logs\slot2-!TS!.mcd
)
if not defined NEW set "NEW=%CARD%"

copy /y "!NEW!" "%NEXT%" >nul
if errorlevel 1 echo Copying the card failed. Nothing was changed. & exit /b 1
powershell -nologo -noprofile -command "(Get-Item -LiteralPath '%NEXT%').LastWriteTime = Get-Date"
move /y "%NEXT%" "%CARD%" >nul
if errorlevel 1 (
  del "%NEXT%"
  echo Replacing the card failed ^(the emulator has the file open?^). Nothing was changed.
  exit /b 1
)
echo Card in: !NEW!
endlocal

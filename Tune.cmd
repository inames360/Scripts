@echo off
setlocal EnableExtensions
REM ============================================================================
REM  Tune.cmd - one-click launcher for Win11Home_fine_tune_v6.ps1
REM  Double-click this file. It self-elevates (UAC), bypasses the Restricted
REM  execution policy for this one process only, and shows a menu.
REM  Keep it in the SAME folder as the .ps1 and the .psd1 manifest.
REM ============================================================================

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%Win11Home_fine_tune_v6.ps1"
REM Prefer Windows PowerShell 5.1 (always present on Home); the script runs on 7.x too.
set "PWSH=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

REM --- self-elevate if not already admin ---
net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo Requesting administrator privileges...
    "%PWSH%" -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

if not exist "%PS1%" (
    echo [ERROR] Cannot find:
    echo        %PS1%
    echo Keep Tune.cmd in the same folder as the script and manifest.
    echo.
    pause
    exit /b 1
)

:menu
cls
echo ==============================================================
echo   Win11 Home Tuning Launcher  ^(v6^)
echo   %PS1%
echo ==============================================================
echo.
echo   [1]  Preview changes            ^(-WhatIf, nothing is changed^)
echo   [2]  Apply tuning
echo   [3]  Apply, skip Network items  ^(-Exclude Network^)
echo   [4]  Audit / drift check        ^(-Mode Audit^)
echo.
echo   [5]  Preview Defender fixes      ^(-Include Defender -WhatIf^)
echo   [6]  Apply Defender fixes        ^(-Include Defender^)
echo.
echo   [7]  Roll back LAST apply        ^(-Mode Rollback^)
echo   [8]  Roll back EVERYTHING        ^(-Mode Rollback -All^)
echo.
echo   [9]  Register logon drift audit  ^(-Mode RegisterAuditTask^)
echo   [0]  Exit
echo.
set "choice="
set /p "choice=Select: "

if "%choice%"=="1" ( call :run -WhatIf & goto after )
if "%choice%"=="2" ( call :run & goto after )
if "%choice%"=="3" ( call :run -Exclude Network & goto after )
if "%choice%"=="4" ( call :run -Mode Audit & goto after )
if "%choice%"=="5" ( call :run -Include Defender -WhatIf & goto after )
if "%choice%"=="6" ( call :run -Include Defender & goto after )
if "%choice%"=="7" ( call :run -Mode Rollback & goto after )
if "%choice%"=="8" ( call :run -Mode Rollback -All & goto after )
if "%choice%"=="9" ( call :run -Mode RegisterAuditTask & goto after )
if "%choice%"=="0" ( exit /b 0 )
goto menu

:run
echo.
echo ---- powershell -ExecutionPolicy Bypass -File "Win11Home_fine_tune_v6.ps1" %* ----
echo.
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
echo.
echo ---- exit code: %errorlevel% ----
exit /b

:after
echo.
pause
goto menu

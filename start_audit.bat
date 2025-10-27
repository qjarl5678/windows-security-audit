@echo off
chcp 65001 >nul
cd /d "%~dp0"

:: Elevate to Administrator if not already
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ===================================
echo   KISA Security Assessment Tool
echo ===================================
echo.

if not exist "Security-Audit-Main.ps1" (
    echo Error: Cannot find Security-Audit-Main.ps1
    echo Current path: %CD%
    pause
    exit /b 1
)

echo Running PowerShell script...
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -NoExit -Command "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($true); [Console]::InputEncoding=[System.Text.UTF8Encoding]::new($true); \$OutputEncoding=[System.Text.UTF8Encoding]::new($true); & '%~dp0Security-Audit-Main.ps1'"

echo.
echo Execution completed.
pause
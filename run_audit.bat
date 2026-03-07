@echo off
:: ═══════════════════════════════════════════════════════════════
::  CredAudit — run_audit.bat
::  Launcher for Windows Command Prompt
::  Usage: Double-click  OR  run_audit.bat
::         run_audit.bat --wordlist C:\wordlists\rockyou.txt
:: ═══════════════════════════════════════════════════════════════

title CredAudit - Windows Credential Audit Tool
color 0A

echo.
echo  ================================================
echo   CredAudit Launcher - Windows
echo  ================================================
echo.

:: ── Check Python ─────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python not found.
    echo  Please install Python 3.8+ from https://python.org
    echo  Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version 2^>^&1') do echo  [+] %%i

:: ── Activate virtual environment if exists ───────────────────
if exist venv\Scripts\activate.bat (
    echo  [+] Virtual environment found - activating...
    call venv\Scripts\activate.bat
) else (
    echo  [!] No venv found. Running with system Python.
)

:: ── Install dependencies if needed ───────────────────────────
echo  [*] Checking dependencies...
python -c "import impacket" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Installing dependencies...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo  [ERROR] Failed to install dependencies.
        pause
        exit /b 1
    )
    echo  [+] Dependencies installed.
) else (
    echo  [+] Dependencies OK
)

:: ── Check Hashcat ─────────────────────────────────────────────
hashcat --version >nul 2>&1
if %errorlevel% equ 0 (
    echo  [+] Hashcat found
) else (
    echo  [!] Hashcat not found - will use Python engine
    echo      Download from: https://hashcat.net/hashcat/
)

:: ── Create required directories ───────────────────────────────
if not exist input  mkdir input
if not exist reports mkdir reports
if not exist logs   mkdir logs

echo.
echo  [*] Starting CredAudit...
echo.

:: ── Run ───────────────────────────────────────────────────────
python main.py --auto %*

if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Audit failed. Check logs\audit.log for details.
    pause
    exit /b 1
)

echo.
echo  [+] Done! Check the reports\ folder for your audit report.
pause

# ═══════════════════════════════════════════════════════════════
#  CredAudit — run_audit.ps1
#  Launcher for Windows PowerShell
#  Usage: .\run_audit.ps1
#         .\run_audit.ps1 --wordlist C:\wordlists\rockyou.txt
#
#  If execution policy blocks this, run first:
#  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# ═══════════════════════════════════════════════════════════════

$Host.UI.RawUI.WindowTitle = "CredAudit - Windows Credential Audit Tool"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

function Write-Ok   { param($msg) Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Write-Warn { param($msg) Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Err  { param($msg) Write-Host "  [x] $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "  ================================================" -ForegroundColor Red
Write-Host "   CredAudit Launcher - PowerShell" -ForegroundColor White
Write-Host "  ================================================" -ForegroundColor Red
Write-Host ""

# ── Check Python ──────────────────────────────────────────────
$python = $null
foreach ($cmd in @("python3","python")) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        $python = $cmd
        break
    }
}

if (-not $python) {
    Write-Err "Python not found."
    Write-Warn "Install Python 3.8+ from https://python.org"
    Write-Warn "Check 'Add Python to PATH' during installation."
    Read-Host "Press Enter to exit"
    exit 1
}

$pyVer = & $python --version 2>&1
Write-Ok "Python : $pyVer"

# ── Activate virtual environment ──────────────────────────────
if (Test-Path "venv\Scripts\Activate.ps1") {
    Write-Ok "Virtual environment found - activating..."
    & "venv\Scripts\Activate.ps1"
} else {
    Write-Warn "No venv found. Running with system Python."
}

# ── Check / install dependencies ─────────────────────────────
Write-Info "Checking dependencies..."
$checkImpacket = & $python -c "import impacket" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warn "Installing dependencies..."
    & $python -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to install dependencies."
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Ok "Dependencies installed."
} else {
    Write-Ok "Dependencies OK"
}

# ── Check Hashcat ─────────────────────────────────────────────
if (Get-Command "hashcat" -ErrorAction SilentlyContinue) {
    Write-Ok "Hashcat found"
} else {
    Write-Warn "Hashcat not found - will use Python engine (slower)"
    Write-Warn "Download from: https://hashcat.net/hashcat/"
}

# ── Create directories ────────────────────────────────────────
foreach ($dir in @("input","reports","logs")) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}

Write-Host ""
Write-Info "Starting CredAudit..."
Write-Host ""

# ── Run ───────────────────────────────────────────────────────
& $python main.py --auto @args

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Err "Audit failed. Check logs\audit.log for details."
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Ok "Done! Check the reports\ folder for your audit report."
Read-Host "Press Enter to exit"

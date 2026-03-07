#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  CredAudit — run_audit.sh
#  Launcher for Linux / Kali / macOS
#  Usage: ./run_audit.sh
#         ./run_audit.sh --wordlist /usr/share/wordlists/rockyou.txt
# ═══════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colors ────────────────────────────────────────────────────
RED='\033[38;5;196m'
GREEN='\033[38;5;82m'
YELLOW='\033[38;5;220m'
BLUE='\033[38;5;39m'
BOLD='\033[1m'
RESET='\033[0m'

echo ""
echo -e "${RED}${BOLD}  CredAudit Launcher${RESET}"
echo -e "${BLUE}  ─────────────────────────────────────────${RESET}"

# ── Check Python ──────────────────────────────────────────────
if command -v python3 &>/dev/null; then
    PYTHON="python3"
elif command -v python &>/dev/null; then
    PYTHON="python"
else
    echo -e "${RED}[✗] Python not found. Install Python 3.8+${RESET}"
    exit 1
fi

PY_VERSION=$($PYTHON --version 2>&1)
echo -e "${GREEN}[+]${RESET} Python : $PY_VERSION"

# ── Check / activate virtual environment ─────────────────────
if [ -d "venv" ]; then
    echo -e "${GREEN}[+]${RESET} Virtual environment found — activating..."
    source venv/bin/activate
else
    echo -e "${YELLOW}[!]${RESET} No venv found. Running with system Python."
    echo -e "${YELLOW}[!]${RESET} Tip: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
fi

# ── Check dependencies ────────────────────────────────────────
echo -e "${BLUE}[*]${RESET} Checking dependencies..."
if ! $PYTHON -c "import impacket" 2>/dev/null && ! $PYTHON -c "from Registry import Registry" 2>/dev/null; then
    echo -e "${YELLOW}[!]${RESET} Dependencies not installed. Installing now..."
    pip install -r requirements.txt
    echo -e "${GREEN}[+]${RESET} Dependencies installed."
else
    echo -e "${GREEN}[+]${RESET} Dependencies OK"
fi

# ── Check Hashcat ─────────────────────────────────────────────
if command -v hashcat &>/dev/null; then
    echo -e "${GREEN}[+]${RESET} Hashcat : $(hashcat --version 2>/dev/null || echo 'found')"
else
    echo -e "${YELLOW}[!]${RESET} Hashcat not found — will use Python engine (slower)"
    echo -e "${YELLOW}    Install: sudo apt install hashcat${RESET}"
fi

# ── Create required directories ───────────────────────────────
mkdir -p input reports logs

echo ""
echo -e "${BLUE}[*]${RESET} Starting CredAudit..."
echo ""

# ── Run ───────────────────────────────────────────────────────
# Pass any extra arguments (e.g. --wordlist) straight through
$PYTHON main.py --auto "$@"

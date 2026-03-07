#!/usr/bin/env python3
"""
CredAudit - Automated Windows Credential Audit Tool v2.0.0
For authorized use only in controlled environments.
"""

import argparse
import sys
import os
import time
import platform
import logging
from datetime import datetime

from modules.hash_extractor import HashExtractor
from modules.hash_parser import HashParser
from modules.password_cracker import PasswordCracker
from modules.report_generator import ReportGenerator
from modules.logger import setup_logger


# ── ANSI Colors ───────────────────────────────────────────────────────────────

class C:
    RED     = "\033[38;5;196m"
    ORANGE  = "\033[38;5;208m"
    GREEN   = "\033[38;5;82m"
    YELLOW  = "\033[38;5;220m"
    BLUE    = "\033[38;5;39m"
    CYAN    = "\033[38;5;51m"
    MAGENTA = "\033[38;5;213m"
    GRAY    = "\033[38;5;240m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

    @classmethod
    def disable(cls):
        for attr in ["RED","ORANGE","GREEN","YELLOW","BLUE","CYAN","MAGENTA","GRAY","BOLD","RESET"]:
            setattr(cls, attr, "")


BANNER = """
  ██████╗██████╗ ███████╗██████╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗
 ██╔════╝██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
 ██║     ██████╔╝█████╗  ██║  ██║    ███████║██║   ██║██║  ██║██║   ██║
 ██║     ██╔══██╗██╔══╝  ██║  ██║    ██╔══██║██║   ██║██║  ██║██║   ██║
 ╚██████╗██║  ██║███████╗██████╔╝    ██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
"""


# ── Print helpers ─────────────────────────────────────────────────────────────

# Big block letters for CRED AUDIT animation
BIG_LETTERS = {
    "C": [
        " ██████╗ ",
        "██╔════╝ ",
        "██║      ",
        "██║      ",
        "╚██████╗ ",
        " ╚═════╝ ",
    ],
    "R": [
        "██████╗  ",
        "██╔══██╗ ",
        "██████╔╝ ",
        "██╔══██╗ ",
        "██║  ██║ ",
        "╚═╝  ╚═╝ ",
    ],
    "E": [
        "███████╗ ",
        "██╔════╝ ",
        "█████╗   ",
        "██╔══╝   ",
        "███████╗ ",
        "╚══════╝ ",
    ],
    "D": [
        "██████╗  ",
        "██╔══██╗ ",
        "██║  ██║ ",
        "██║  ██║ ",
        "██████╔╝ ",
        "╚═════╝  ",
    ],
    " ": [
        "   ",
        "   ",
        "   ",
        "   ",
        "   ",
        "   ",
    ],
    "A": [
        " █████╗  ",
        "██╔══██╗ ",
        "███████║ ",
        "██╔══██║ ",
        "██║  ██║ ",
        "╚═╝  ╚═╝ ",
    ],
    "U": [
        "██╗   ██╗",
        "██║   ██║",
        "██║   ██║",
        "██║   ██║",
        "╚██████╔╝",
        " ╚═════╝ ",
    ],
    "I": [
        "██╗ ",
        "██║ ",
        "██║ ",
        "██║ ",
        "██║ ",
        "╚═╝ ",
    ],
    "T": [
        "████████╗",
        "╚══██╔══╝",
        "   ██║   ",
        "   ██║   ",
        "   ██║   ",
        "   ╚═╝   ",
    ],
}

def animate_title():
    """Animate CRED AUDIT letter by letter in big block letters."""
    text   = "CRED AUDIT"
    rows   = 6  # each letter is 6 rows tall
    delay  = 0.12  # seconds per letter

    for i in range(1, len(text) + 1):
        os.system("clear" if platform.system() != "Windows" else "cls")
        current = text[:i]

        print("\n\n\n")
        for row in range(rows):
            line = "  "
            for char in current:
                letter = BIG_LETTERS.get(char, BIG_LETTERS[" "])
                line += letter[row]
            sys.stdout.write(C.RED + line + C.RESET + "\n")

        sys.stdout.flush()
        time.sleep(delay)

    # Hold the full title for a moment
    time.sleep(0.5)

    # Then clear and show full banner
    os.system("clear" if platform.system() != "Windows" else "cls")


def p_banner():
    animate_title()
    print(C.RED + BANNER + C.RESET)
    print(C.RED + "  ╔═══════════════════════════════════════════════════════════╗" + C.RESET)
    print(C.RED + "  ║          C R E D A U D I T   —   v 2 . 0 . 0            ║" + C.RESET)
    print(C.RED + "  ║      Automated Windows Credential Audit & Analysis       ║" + C.RESET)
    print(C.RED + "  ╚═══════════════════════════════════════════════════════════╝" + C.RESET)
    print()
    print(C.GRAY + "  Defensive Security  |  NTLM Hash Analysis  |  Cross-Platform" + C.RESET)
    print()

def p_step(n, total, msg):
    print(f"\n{C.BLUE}{C.BOLD}[{n}/{total}]{C.RESET} {C.BOLD}{msg}{C.RESET}")
    print(C.GRAY + "─" * 64 + C.RESET)

def p_ok(msg):   print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def p_info(msg): print(f"  {C.BLUE}[*]{C.RESET} {msg}")
def p_warn(msg): print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def p_err(msg):  print(f"  {C.RED}[✗]{C.RESET} {msg}")

def p_box(title, lines, color=""):
    if not color:
        color = C.CYAN
    w = 66
    print(f"\n{color}┌{'─' * (w - 2)}┐{C.RESET}")
    print(f"{color}│{C.RESET}  {C.BOLD}{title:<{w - 4}}{C.RESET}{color}│{C.RESET}")
    print(f"{color}├{'─' * (w - 2)}┤{C.RESET}")
    for line in lines:
        print(f"{color}│{C.RESET}  {line:<{w - 4}}{color}│{C.RESET}")
    print(f"{color}└{'─' * (w - 2)}┘{C.RESET}")

def detect_os():
    s = platform.system()
    if s == "Linux":
        try:
            with open("/etc/os-release") as f:
                if "kali" in f.read().lower():
                    return "kali"
        except Exception:
            pass
        return "linux"
    elif s == "Windows":
        return "windows"
    elif s == "Darwin":
        return "macos"
    return "unknown"


# ── Guided auto mode ──────────────────────────────────────────────────────────

def guided_setup(default_wordlist, preset_wordlist=None):
    """
    Interactive guided setup.
    Shows the user exactly what commands to run, detects files,
    prompts for wordlist and report format.
    Returns resolved config dict.
    """
    os_type  = detect_os()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    input_dir = os.path.join(base_dir, "input")
    os.makedirs(input_dir, exist_ok=True)

    print(f"\n{C.BOLD}{C.MAGENTA}  ══════════════  GUIDED SETUP  ══════════════{C.RESET}\n")
    p_info(f"Detected platform : {C.BOLD}{os_type.upper()}{C.RESET}")

    # ── STEP 1: Show export commands ──────────────────────────────────────────
    p_box(
        "STEP 1  —  Export SAM + SYSTEM on your Windows machine",
        [
            "⚠  COMPLETE ALL 3 STEPS BELOW BEFORE PRESSING ENTER:",
            "",
            "  1. Open Command Prompt as Administrator on Windows and run:",
            "",
            "     reg save HKLM\\SAM C:\\Users\\Public\\SAM",
            "     reg save HKLM\\SYSTEM C:\\Users\\Public\\SYSTEM",
            "",
            "  2. Transfer both files into the  input/  folder:",
            "",
            "     Via Python server (on Windows):",
            "     cd C:\\Users\\Public && python -m http.server 8888",
            "",
            "     Then on Kali download them:",
            "     wget http://<windows-ip>:8888/SAM -O input/SAM",
            "     wget http://<windows-ip>:8888/SYSTEM -O input/SYSTEM",
            "",
            "     Via SCP from Kali:",
            "     scp user@<IP>:C:/Users/Public/SAM ./input/SAM",
            "     scp user@<IP>:C:/Users/Public/SYSTEM ./input/SYSTEM",
            "",
            "  3. Verify both files are in input/ folder:",
            "     ls input/   ←  you should see SAM and SYSTEM",
            "",
            "  ONLY THEN press Enter to continue ↓",
        ],
        C.CYAN
    )

    input(f"\n  {C.YELLOW}✅ Done? SAM + SYSTEM are in input/ folder → Press Enter to continue...{C.RESET}")

    # ── STEP 2: Auto-detect files ─────────────────────────────────────────────
    print(f"\n{C.BLUE}[*]{C.RESET} Scanning {C.BOLD}input/{C.RESET} for hive files...")

    sam_path    = None
    system_path = None

    for fname in os.listdir(input_dir):
        lower = fname.lower()
        full  = os.path.join(input_dir, fname)
        if lower in ("sam", "sam.hive", "sam.save") and sam_path is None:
            sam_path = full
        elif lower in ("system", "system.hive", "system.save") and system_path is None:
            system_path = full

    if sam_path:
        p_ok(f"SAM    detected → {C.CYAN}{sam_path}{C.RESET}")
    else:
        p_err("SAM file not found in input/ folder.")
        p_warn("Place your SAM file in the input/ folder and run again.")
        sys.exit(1)

    if system_path:
        p_ok(f"SYSTEM detected → {C.CYAN}{system_path}{C.RESET}")
    else:
        p_err("SYSTEM file not found in input/ folder.")
        p_warn("Place your SYSTEM file in the input/ folder and run again.")
        sys.exit(1)

    # ── STEP 3: Wordlist ──────────────────────────────────────────────────────
    if preset_wordlist:
        # --wordlist was passed via CLI alongside --auto
        if not os.path.isfile(preset_wordlist):
            p_err(f"Wordlist not found: {preset_wordlist}")
            sys.exit(1)
        wordlist_path = preset_wordlist
        p_ok(f"Wordlist (from CLI) → {C.CYAN}{wordlist_path}{C.RESET}")
    else:
        p_box(
            "STEP 2  —  Wordlist Selection",
            [
                "Provide a wordlist for the dictionary attack.",
                "",
                "  Recommended  : rockyou.txt  (14 million passwords)",
                "  Kali default : /usr/share/wordlists/rockyou.txt",
                "  Custom path  : /path/to/your/wordlist.txt",
                "",
                "  Press Enter  : use built-in example wordlist (demo only)",
            ],
            C.MAGENTA
        )

        wl_input = input(f"\n  {C.BOLD}Enter wordlist path (or press Enter for default): {C.RESET}").strip()

        if wl_input == "":
            wordlist_path = default_wordlist
            p_info(f"Using default wordlist → {wordlist_path}")
            p_warn("For real audits, provide rockyou.txt for better coverage.")
        else:
            wordlist_path = wl_input
            if not os.path.isfile(wordlist_path):
                p_err(f"Wordlist not found: {wordlist_path}")
                sys.exit(1)
            p_ok(f"Wordlist → {C.CYAN}{wordlist_path}{C.RESET}")

    # ── STEP 4: Report format ─────────────────────────────────────────────────
    p_box(
        "STEP 3  —  Report Format",
        [
            "  [1]  All formats — TXT + JSON + HTML  (recommended)",
            "  [2]  HTML only  — visual report, open in browser",
            "  [3]  JSON only  — machine readable",
            "  [4]  TXT only   — plain text",
            "",
            "  Press Enter for default [1]",
        ],
        C.CYAN
    )

    fmt_input  = input(f"\n  {C.BOLD}Enter choice [1-4]: {C.RESET}").strip()
    fmt_map    = {"1": "all", "2": "html", "3": "json", "4": "txt", "": "all"}
    fmt        = fmt_map.get(fmt_input, "all")
    p_ok(f"Report format → {C.BOLD}{fmt.upper()}{C.RESET}")

    # ── Confirm ───────────────────────────────────────────────────────────────
    print(f"\n{C.GRAY}{'═' * 64}{C.RESET}")
    print(f"{C.BOLD}  AUDIT CONFIGURATION{C.RESET}")
    print(f"{C.GRAY}{'─' * 64}{C.RESET}")
    p_info(f"SAM file      : {sam_path}")
    p_info(f"SYSTEM file   : {system_path}")
    p_info(f"Wordlist      : {wordlist_path}")
    p_info(f"Report format : {fmt.upper()}")
    p_info(f"Output dir    : reports/")
    p_info(f"Platform      : {os_type.upper()}")
    print(f"{C.GRAY}{'═' * 64}{C.RESET}")

    confirm = input(f"\n  {C.YELLOW}{C.BOLD}Start audit? [Y/n]: {C.RESET}").strip().lower()
    if confirm in ("n", "no"):
        print(f"\n  {C.GRAY}Audit cancelled.{C.RESET}\n")
        sys.exit(0)

    return {
        "sam":      sam_path,
        "system":   system_path,
        "wordlist": wordlist_path,
        "format":   fmt,
    }


# ── Argument parser ───────────────────────────────────────────────────────────

def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="credaudit",
        description="Automated Windows Credential Audit Tool v2.0.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Guided auto mode (recommended — just drop files in input/)
  python3 main.py --auto

  # Auto mode with your own wordlist
  python3 main.py --auto --wordlist /usr/share/wordlists/rockyou.txt

  # Manual mode — full control
  python3 main.py --sam input/SAM --system input/SYSTEM --wordlist rockyou.txt --format all

  # Manual mode — HTML only
  python3 main.py --sam input/SAM --system input/SYSTEM --wordlist rockyou.txt --format html

  # Force Python engine (no Hashcat needed)
  python3 main.py --auto --cracker python

Disclaimer:
  For authorized security auditing and cybersecurity education only.
  Unauthorized use is illegal and unethical.
        """
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--auto", action="store_true",
                      help="Guided auto mode — detects SAM+SYSTEM from input/ folder")
    mode.add_argument("--sam", metavar="FILE",
                      help="Manual mode — path to SAM hive file")

    parser.add_argument("--system",       metavar="FILE",   help="Path to SYSTEM hive (required in manual mode)")
    parser.add_argument("--wordlist",     metavar="FILE",   help="Path to wordlist file")
    parser.add_argument("--format",       choices=["txt","json","html","all"], default="all")
    parser.add_argument("--output",       default="reports", metavar="DIR")
    parser.add_argument("--cracker",      choices=["hashcat","python","auto"], default="auto")
    parser.add_argument("--hashcat-path", default="hashcat", metavar="PATH")
    parser.add_argument("--skip-disabled", action="store_true")
    parser.add_argument("--no-color",      action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--log-file",      default="logs/audit.log")

    return parser.parse_args()


# ── Main pipeline ─────────────────────────────────────────────────────────────

def main():
    args = parse_arguments()

    # Color setup
    if args.no_color:
        C.disable()
    elif platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7
            )
        except Exception:
            C.disable()

    p_banner()

    # Logger
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_dir   = os.path.dirname(args.log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    logger = setup_logger(log_level, args.log_file)
    logger.info(f"CredAudit v2.0.0 | OS: {platform.system()} | Mode: {'auto' if args.auto else 'manual'}")

    base_dir         = os.path.dirname(os.path.abspath(__file__))
    default_wordlist = os.path.join(base_dir, "wordlists", "example_wordlist.txt")

    # ── Resolve config ────────────────────────────────────────────────────────
    if args.auto:
        config        = guided_setup(default_wordlist, preset_wordlist=args.wordlist)
        sam_path      = config["sam"]
        system_path   = config["system"]
        wordlist_path = config["wordlist"]
        report_format = config["format"]
    else:
        if not args.system:
            p_err("--system is required in manual mode")
            sys.exit(1)
        for label, path in [("SAM", args.sam), ("SYSTEM", args.system)]:
            if not os.path.isfile(path):
                p_err(f"{label} file not found: {path}")
                sys.exit(1)
        sam_path      = args.sam
        system_path   = args.system
        wordlist_path = args.wordlist or default_wordlist
        report_format = args.format
        if not os.path.isfile(wordlist_path):
            p_err(f"Wordlist not found: {wordlist_path}")
            sys.exit(1)

    os.makedirs(args.output, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    total_steps = 4

    # ── STEP 1: Extract ───────────────────────────────────────────────────────
    p_step(1, total_steps, "Extracting NTLM hashes from SAM + SYSTEM hives")
    try:
        extractor  = HashExtractor(sam_path, system_path, logger)
        raw_hashes = extractor.extract()
        p_ok(f"Boot key extracted successfully")
        p_ok(f"{len(raw_hashes)} raw hash entries obtained")
        logger.info(f"Extraction: {len(raw_hashes)} entries")
    except Exception as e:
        p_err(f"Extraction failed: {e}")
        logger.exception("Extraction error")
        sys.exit(1)

    # ── STEP 2: Parse ─────────────────────────────────────────────────────────
    p_step(2, total_steps, "Parsing account records")
    try:
        parser   = HashParser(logger)
        accounts = parser.parse(raw_hashes, skip_disabled=args.skip_disabled)
        p_ok(f"Parsed {len(accounts)} user accounts")
        print()
        print(f"  {C.GRAY}{'USERNAME':<22} {'RID':<8} {'NTLM HASH':<34} {'TYPE'}{C.RESET}")
        print(f"  {C.GRAY}{'─'*22} {'─'*8} {'─'*34} {'─'*20}{C.RESET}")
        for acc in accounts:
            dis = f" {C.YELLOW}[DISABLED]{C.RESET}" if acc.get("disabled") else ""
            print(f"  {C.BOLD}{acc['username']:<22}{C.RESET} "
                  f"{acc['rid']:<8} "
                  f"{C.CYAN}{acc['ntlm_hash']}{C.RESET}  "
                  f"{C.GRAY}{acc.get('account_type','')}{C.RESET}{dis}")
        logger.info(f"Parsed {len(accounts)} accounts")
    except Exception as e:
        p_err(f"Parsing failed: {e}")
        logger.exception("Parsing error")
        sys.exit(1)

    # ── STEP 3: Crack ─────────────────────────────────────────────────────────
    p_step(3, total_steps, "Running dictionary attack against NTLM hashes")
    try:
        cracker = PasswordCracker(
            wordlist_path=wordlist_path,
            engine=args.cracker,
            hashcat_path=args.hashcat_path,
            logger=logger
        )
        results     = cracker.crack(accounts)
        cracked     = [r for r in results if r["status"] == "cracked"]
        not_cracked = [r for r in results if r["status"] == "not_cracked"]

        p_ok(f"Engine used  : {C.BOLD}{cracker.engine_used}{C.RESET}")
        p_ok(f"Cracked      : {C.RED}{C.BOLD}{len(cracked)}{C.RESET} / {len(results)}")
        p_ok(f"Not cracked  : {C.GREEN}{len(not_cracked)}{C.RESET}")

        if cracked:
            print(f"\n  {C.RED}{C.BOLD}  ⚠  WEAK PASSWORDS DETECTED:{C.RESET}")
            print(f"  {C.GRAY}  {'─' * 50}{C.RESET}")
            for r in cracked:
                pwd = r["cleartext"] if r["cleartext"] else "(empty password)"
                print(f"  {C.RED}  ✗{C.RESET}  {C.BOLD}{r['username']:<22}{C.RESET} "
                      f"→  {C.YELLOW}{C.BOLD}{pwd}{C.RESET}")

        logger.info(f"Cracking: {len(cracked)} cracked, {len(not_cracked)} not cracked")
    except Exception as e:
        p_err(f"Cracking failed: {e}")
        logger.exception("Cracking error")
        sys.exit(1)

    # ── STEP 4: Report ────────────────────────────────────────────────────────
    p_step(4, total_steps, "Generating security audit reports")
    try:
        generator    = ReportGenerator(output_dir=args.output, logger=logger)
        formats      = ["txt","json","html"] if report_format == "all" else [report_format]
        report_paths = generator.generate(results, formats=formats, timestamp=timestamp)
        for fmt, path in report_paths.items():
            p_ok(f"{fmt.upper():<5} → {C.CYAN}{path}{C.RESET}")
        logger.info(f"Reports: {report_paths}")
    except Exception as e:
        p_err(f"Report generation failed: {e}")
        logger.exception("Report error")
        sys.exit(1)

    # ── Summary ───────────────────────────────────────────────────────────────
    weak_pct = round(len(cracked) / len(results) * 100) if results else 0
    print(f"\n{C.GRAY}{'═' * 64}{C.RESET}")
    print(f"{C.BOLD}  ✅  AUDIT COMPLETE{C.RESET}")
    print(f"{C.GRAY}{'═' * 64}{C.RESET}")
    p_info(f"Accounts audited  : {C.BOLD}{len(results)}{C.RESET}")
    p_warn(f"Weak passwords    : {C.RED}{C.BOLD}{len(cracked)} ({weak_pct}%){C.RESET}")
    p_ok(f"Strong/uncracked  : {C.GREEN}{len(not_cracked)}{C.RESET}")
    p_info(f"Reports saved to  : {C.CYAN}{args.output}/{C.RESET}")
    p_info(f"Log               : {C.GRAY}{args.log_file}{C.RESET}")
    print(f"{C.GRAY}{'═' * 64}{C.RESET}\n")

    if weak_pct >= 50:
        print(f"  {C.RED}{C.BOLD}  ⚠  CRITICAL: Over half of accounts have weak passwords!{C.RESET}")
        print(f"  {C.YELLOW}     Open the HTML report and apply recommendations immediately.{C.RESET}\n")

    logger.info("Session complete")
    sys.exit(0)


if __name__ == "__main__":
    main()

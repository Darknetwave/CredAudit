"""
hash_parser.py
===============
Parses raw hash extraction output into structured account records.

Handles:
  - Standard secretsdump-style lines: username:rid:lm:ntlm:::
  - Disabled / locked account detection
  - Empty hash detection (LM disabled, Guest account, etc.)
  - Deduplication
  - Account metadata enrichment (account type, risk flags)
"""

import logging
import re
from typing import List, Dict, Any

# Well-known empty / blank hashes
EMPTY_LM_HASH   = "aad3b435b51404eeaad3b435b51404ee"
EMPTY_NTLM_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"  # hash of empty string ""

# Well-known built-in RIDs
KNOWN_RIDS = {
    500: "Built-in Administrator",
    501: "Built-in Guest",
    502: "Kerberos KRBTGT",
    503: "Default Account",
}

# Service account naming patterns
SERVICE_ACCOUNT_PATTERNS = re.compile(
    r"^(svc_|service_|sa_|sql|backup|deploy|scan|agent|daemon)", re.IGNORECASE
)


class HashParser:
    """
    Converts raw extracted hash entries into clean, structured account dicts.

    Each output dict has the shape:
    {
        "username":     str,
        "rid":          int,
        "lm_hash":      str,      # 32-char hex or EMPTY_LM_HASH
        "ntlm_hash":    str,      # 32-char hex
        "lm_enabled":   bool,     # True if a real LM hash is present
        "empty_password": bool,   # True if NTLM = empty-string hash
        "disabled":     bool,     # True if account appears disabled
        "account_type": str,      # "Administrator" | "Service Account" | "Standard User" | "Built-in"
        "risk_flags":   List[str],# e.g. ["LM hash present", "Empty password", "Default RID 500"]
        "raw_line":     str,
    }
    """

    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger(__name__)

    def parse(
        self,
        raw_entries: List[Dict[str, Any]],
        skip_disabled: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Parse a list of raw hash dicts returned by HashExtractor.

        Args:
            raw_entries:    List from HashExtractor.extract()
            skip_disabled:  If True, exclude accounts flagged as disabled

        Returns:
            List of enriched account dicts.
        """
        results   = []
        seen_rids = set()

        for entry in raw_entries:
            try:
                account = self._parse_entry(entry)
            except Exception as e:
                self.logger.warning(f"Skipping malformed entry: {entry} — {e}")
                continue

            # Deduplication by RID
            if account["rid"] in seen_rids:
                self.logger.debug(f"Duplicate RID {account['rid']} skipped")
                continue
            seen_rids.add(account["rid"])

            if skip_disabled and account["disabled"]:
                self.logger.debug(f"Skipping disabled account: {account['username']}")
                continue

            results.append(account)
            self.logger.debug(
                f"Parsed: {account['username']} (RID {account['rid']}) "
                f"NTLM:{account['ntlm_hash']} type:{account['account_type']}"
            )

        self.logger.info(f"HashParser: {len(results)} accounts parsed from {len(raw_entries)} raw entries")
        return results

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _parse_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and enrich a single raw entry dict."""

        username  = str(entry.get("username", "unknown")).strip()
        rid       = int(entry.get("rid", 0))
        lm_hash   = str(entry.get("lm_hash", EMPTY_LM_HASH)).strip().lower()
        ntlm_hash = str(entry.get("ntlm_hash", EMPTY_NTLM_HASH)).strip().lower()
        raw_line  = str(entry.get("raw_line", ""))

        # Validate hash formats
        if not self._is_valid_hash(lm_hash):
            self.logger.warning(f"Invalid LM hash for {username}, using empty placeholder")
            lm_hash = EMPTY_LM_HASH

        if not self._is_valid_hash(ntlm_hash):
            self.logger.warning(f"Invalid NTLM hash for {username}, using empty placeholder")
            ntlm_hash = EMPTY_NTLM_HASH

        # Derived flags
        lm_enabled     = lm_hash != EMPTY_LM_HASH
        empty_password = ntlm_hash == EMPTY_NTLM_HASH
        disabled       = self._is_disabled(username, ntlm_hash, raw_line)
        account_type   = self._classify_account(username, rid)
        risk_flags     = self._build_risk_flags(username, rid, lm_enabled, empty_password, ntlm_hash)

        return {
            "username":      username,
            "rid":           rid,
            "lm_hash":       lm_hash,
            "ntlm_hash":     ntlm_hash,
            "lm_enabled":    lm_enabled,
            "empty_password": empty_password,
            "disabled":      disabled,
            "account_type":  account_type,
            "risk_flags":    risk_flags,
            "raw_line":      raw_line,
            # These will be filled in by PasswordCracker
            "status":        "pending",
            "cleartext":     None,
        }

    def _is_valid_hash(self, h: str) -> bool:
        """Check that hash is a 32-char hex string."""
        return bool(re.fullmatch(r"[0-9a-f]{32}", h))

    def _is_disabled(self, username: str, ntlm_hash: str, raw_line: str) -> bool:
        """
        Heuristically detect disabled accounts.
        Impacket marks disabled accounts with (Disabled) in some outputs.
        Also, account named Guest is almost always disabled.
        """
        if "(Disabled)" in raw_line or "(disabled)" in raw_line:
            return True
        if username.lower() == "guest" and ntlm_hash == EMPTY_NTLM_HASH:
            return True
        return False

    def _classify_account(self, username: str, rid: int) -> str:
        """Classify account type for reporting."""
        if rid == 500:
            return "Built-in Administrator"
        if rid == 501:
            return "Built-in Guest"
        if rid in KNOWN_RIDS:
            return "Built-in"
        if SERVICE_ACCOUNT_PATTERNS.match(username):
            return "Service Account"
        if username.lower() in ("administrator", "admin"):
            return "Administrator"
        return "Standard User"

    def _build_risk_flags(
        self,
        username: str,
        rid: int,
        lm_enabled: bool,
        empty_password: bool,
        ntlm_hash: str,
    ) -> List[str]:
        """Build a list of risk observations for this account."""
        flags = []

        if rid == 500:
            flags.append("Default Administrator RID 500 — high-value target")
        if lm_enabled:
            flags.append("LM hash present — LAN Manager auth vulnerable to trivial cracking")
        if empty_password:
            flags.append("Empty password — account has no password set")
        if username.lower() in ("administrator", "admin") and rid != 500:
            flags.append("Non-default admin account name — review necessity")
        if SERVICE_ACCOUNT_PATTERNS.match(username):
            flags.append("Service account — rotate regularly, consider gMSA")

        return flags

    # ── Utility: parse raw secretsdump line ───────────────────────────────────

    @staticmethod
    def parse_secretsdump_line(line: str) -> Dict[str, Any]:
        """
        Parse a raw secretsdump-style line:
            username:rid:lm_hash:ntlm_hash:::

        Useful if you have a pre-existing secretsdump output file.
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return {}

        parts = line.split(":")
        if len(parts) < 4:
            return {}

        return {
            "username":  parts[0],
            "rid":       int(parts[1]) if parts[1].isdigit() else 0,
            "lm_hash":   parts[2].lower(),
            "ntlm_hash": parts[3].lower(),
            "raw_line":  line,
        }

"""
password_cracker.py
====================
Performs dictionary attacks against NTLM hashes.

Primary engine  : Hashcat (mode 1000 — NTLM)
Fallback engine : Python hashlib (MD4/NTLM)

The engine selection logic:
  - "auto"    → try Hashcat; if not found or fails, use Python
  - "hashcat" → use Hashcat only; raise if unavailable
  - "python"  → use Python only (no Hashcat required)

Hashcat integration:
  Spawns hashcat as a subprocess:
    hashcat -m 1000 -a 0 <hash_file> <wordlist> --potfile-path <potfile> --quiet
  Then reads the potfile to retrieve cracked passwords.

Python fallback:
  Computes MD4(password.encode('utf-16-le')) for each wordlist entry and
  compares against stored NTLM hashes.
"""

import os
import re
import hashlib
import logging
import shutil
import subprocess
import tempfile
from typing import List, Dict, Any


class PasswordCracker:
    """
    Runs dictionary attacks against a list of parsed account records.
    Supports Hashcat (primary) and Python hashlib (fallback).
    """

    def __init__(
        self,
        wordlist_path: str,
        engine: str = "auto",
        hashcat_path: str = "hashcat",
        logger: logging.Logger = None,
    ):
        self.wordlist_path  = wordlist_path
        self.requested_engine = engine
        self.hashcat_path   = hashcat_path
        self.logger         = logger or logging.getLogger(__name__)
        self.engine_used    = None   # set after crack() resolves the engine

    # ── Public API ─────────────────────────────────────────────────────────────

    def crack(self, accounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Run dictionary attack against all accounts.

        Updates each account dict in-place with:
          "status":    "cracked" | "not_cracked" | "empty_password" | "skipped"
          "cleartext": str | None

        Returns the updated accounts list.
        """
        # Handle empty-password accounts immediately (no cracking needed)
        for acc in accounts:
            if acc.get("empty_password"):
                acc["status"]    = "cracked"
                acc["cleartext"] = ""
                self.logger.debug(f"{acc['username']}: empty password (no hash to crack)")

        # Filter accounts that actually need cracking
        to_crack = [a for a in accounts if a.get("status") == "pending"]

        if not to_crack:
            self.logger.info("No accounts require cracking (all empty or pre-resolved)")
            self.engine_used = "none"
            return accounts

        # Resolve engine
        engine = self._resolve_engine()
        self.engine_used = engine
        self.logger.info(f"Using cracking engine: {engine}")

        if engine == "hashcat":
            cracked_map = self._crack_with_hashcat(to_crack)
        else:
            cracked_map = self._crack_with_python(to_crack)

        # Apply results back to account records
        for acc in to_crack:
            ntlm = acc["ntlm_hash"]
            if ntlm in cracked_map:
                acc["status"]    = "cracked"
                acc["cleartext"] = cracked_map[ntlm]
                self.logger.debug(f"{acc['username']}: CRACKED → {cracked_map[ntlm]!r}")
            else:
                acc["status"]    = "not_cracked"
                acc["cleartext"] = None
                self.logger.debug(f"{acc['username']}: not cracked")

        cracked_count = sum(1 for a in accounts if a["status"] == "cracked")
        self.logger.info(
            f"Cracking complete: {cracked_count}/{len(accounts)} accounts cracked"
        )
        return accounts

    # ── Engine resolution ──────────────────────────────────────────────────────

    def _resolve_engine(self) -> str:
        """Determine which engine to actually use based on user preference + availability."""
        if self.requested_engine == "python":
            return "python"

        if self.requested_engine == "hashcat":
            if self._hashcat_available():
                return "hashcat"
            raise RuntimeError(
                f"Hashcat not found at '{self.hashcat_path}'. "
                "Install hashcat or use --cracker python."
            )

        # "auto": prefer hashcat, fall back to python
        if self._hashcat_available():
            self.logger.info("Hashcat detected — using Hashcat engine")
            return "hashcat"

        self.logger.warning(
            "Hashcat not found in PATH — falling back to Python hashlib engine. "
            "Install hashcat for significantly faster cracking."
        )
        return "python"

    def _hashcat_available(self) -> bool:
        """Check if hashcat binary is reachable."""
        # Explicit path provided?
        if self.hashcat_path != "hashcat" and os.path.isfile(self.hashcat_path):
            return True
        # In PATH?
        return shutil.which(self.hashcat_path) is not None

    # ── Hashcat backend ────────────────────────────────────────────────────────

    def _crack_with_hashcat(self, accounts: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Run hashcat in mode 1000 (NTLM) with dictionary attack (mode -a 0).
        Returns dict: {ntlm_hash_lower: cleartext_password}
        """
        cracked = {}

        with tempfile.TemporaryDirectory(prefix="credaudit_") as tmpdir:
            hash_file = os.path.join(tmpdir, "hashes.txt")
            out_file  = os.path.join(tmpdir, "cracked.txt")
            pot_file  = os.path.join(tmpdir, "cracked.pot")

            unique_hashes = list({a["ntlm_hash"] for a in accounts})
            with open(hash_file, "w") as f:
                f.write("\n".join(unique_hashes) + "\n")

            self.logger.debug(f"Wrote {len(unique_hashes)} hashes to {hash_file}")

            # Step 1: Run cracking
            cmd = [
                self.hashcat_path,
                "-m", "1000",
                "-a", "0",
                hash_file,
                self.wordlist_path,
                "--potfile-path", pot_file,
            ]

            self.logger.info(f"Hashcat crack command: {' '.join(cmd)}")

            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=3600,
                )
                self.logger.debug(f"Hashcat exit code: {proc.returncode}")

            except subprocess.TimeoutExpired:
                self.logger.error("Hashcat timed out after 1 hour")
                raise
            except FileNotFoundError:
                self.logger.error(f"Hashcat binary not found: {self.hashcat_path}")
                raise

            # Step 2: Use --show to retrieve cracked results reliably
            show_cmd = [
                self.hashcat_path,
                "-m", "1000",
                hash_file,
                "--potfile-path", pot_file,
                "--show",
            ]

            self.logger.info(f"Hashcat show command: {' '.join(show_cmd)}")

            show_proc = subprocess.run(
                show_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            output = show_proc.stdout.decode(errors="replace").strip()
            self.logger.debug(f"Hashcat show output: {repr(output)}")

            # Parse: hash:plaintext
            for line in output.splitlines():
                line = line.strip()
                if not line or ":" not in line:
                    continue
                idx   = line.rindex(":")
                h     = line[:idx].lower()
                plain = line[idx + 1:]
                cracked[h] = plain
                self.logger.debug(f"Cracked: {h} → {plain!r}")

            self.logger.info(f"Hashcat cracked {len(cracked)} hashes")

        return cracked

    def _parse_potfile(self, pot_file: str) -> Dict[str, str]:
        """Parse hashcat potfile → {hash: plaintext}."""
        cracked = {}
        if not os.path.isfile(pot_file):
            self.logger.warning(f"Potfile not found: {pot_file} (no passwords cracked)")
            return cracked

        with open(pot_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                # Last colon separates hash from password (passwords may contain colons)
                idx   = line.rindex(":")
                h     = line[:idx].lower()
                plain = line[idx + 1:]
                cracked[h] = plain

        return cracked

    # ── Python hashlib backend ─────────────────────────────────────────────────

    def _crack_with_python(self, accounts: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Pure Python dictionary attack using MD4 (NTLM) via hashlib.

        NTLM hash = MD4(password.encode('utf-16-le'))

        Returns dict: {ntlm_hash_lower: cleartext_password}
        """
        cracked     = {}
        target_hashes = {a["ntlm_hash"] for a in accounts}

        if not target_hashes:
            return cracked

        self.logger.info(f"Python engine: cracking {len(target_hashes)} unique hashes")

        wordlist_size = self._count_lines(self.wordlist_path)
        self.logger.info(f"Wordlist: {self.wordlist_path} ({wordlist_size:,} words)")

        tried   = 0
        found   = 0

        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="replace") as wf:
                for word in wf:
                    word = word.rstrip("\n\r")

                    ntlm = self._ntlm_hash(word)

                    if ntlm in target_hashes:
                        cracked[ntlm] = word
                        found += 1
                        self.logger.debug(f"Match: {ntlm} → {word!r}")

                        # Stop early if all found
                        if len(cracked) == len(target_hashes):
                            self.logger.info("All hashes cracked — stopping early")
                            break

                    tried += 1
                    if tried % 500_000 == 0:
                        self.logger.debug(f"  Progress: {tried:,} / {wordlist_size:,} words tried, {found} cracked")

        except FileNotFoundError:
            self.logger.error(f"Wordlist not found: {self.wordlist_path}")
            raise

        self.logger.info(f"Python engine: tried {tried:,} words, cracked {found} hashes")
        return cracked

    # ── Utilities ──────────────────────────────────────────────────────────────

    @staticmethod
    def _ntlm_hash(password: str) -> str:
        """Compute NTLM hash (MD4 of UTF-16-LE encoded password)."""
        # Try hashlib MD4 first (works on most systems)
        try:
            h = hashlib.new("md4", password.encode("utf-16-le"))
            return h.hexdigest()
        except ValueError:
            pass

        # Fallback 1: impacket's MD4 (works on Python 3.12+)
        try:
            from impacket.crypto import MD4
            m = MD4()
            m.update(password.encode("utf-16-le"))
            return m.hexdigest()
        except Exception:
            pass

        # Fallback 2: pure Python MD4 — no dependencies needed
        return PasswordCracker._pure_md4(password.encode("utf-16-le"))

    @staticmethod
    def _pure_md4(data: bytes) -> str:
        """
        Pure Python MD4 implementation — RFC 1320 compliant.
        Works on any Python version regardless of OpenSSL configuration.
        """
        import struct

        def F(x, y, z): return (x & y) | ((~x) & z)
        def G(x, y, z): return (x & y) | (x & z) | (y & z)
        def H(x, y, z): return x ^ y ^ z
        def lrot(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
        def add(*args):
            r = 0
            for a in args: r = (r + a) & 0xFFFFFFFF
            return r

        msg = bytearray(data)
        orig_bits = len(data) * 8
        msg.append(0x80)
        while len(msg) % 64 != 56:
            msg.append(0)
        msg += struct.pack("<Q", orig_bits)

        a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

        for i in range(0, len(msg), 64):
            X = list(struct.unpack("<16I", msg[i:i+64]))
            A, B, C, D = a, b, c, d

            # Round 1
            s1 = [3, 7, 11, 19]
            for j in range(16):
                k = j
                s = s1[j % 4]
                a = lrot(add(a, F(b, c, d), X[k]), s)
                a, b, c, d = d, a, b, c

            # Round 2
            s2 = [3, 5, 9, 13]
            for j in range(16):
                k = (j % 4) * 4 + j // 4
                s = s2[j % 4]
                a = lrot(add(a, G(b, c, d), X[k], 0x5A827999), s)
                a, b, c, d = d, a, b, c

            # Round 3
            r3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            s3 = [3, 9, 11, 15]
            for j in range(16):
                k = r3[j]
                s = s3[j % 4]
                a = lrot(add(a, H(b, c, d), X[k], 0x6ED9EBA1), s)
                a, b, c, d = d, a, b, c

            a = add(a, A)
            b = add(b, B)
            c = add(c, C)
            d = add(d, D)

        return struct.pack("<4I", a, b, c, d).hex()

    @staticmethod
    def _count_lines(filepath: str) -> int:
        """Fast line count for progress reporting."""
        try:
            count = 0
            with open(filepath, "rb") as f:
                for _ in f:
                    count += 1
            return count
        except Exception:
            return 0

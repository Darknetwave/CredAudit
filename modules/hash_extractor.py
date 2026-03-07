"""
hash_extractor.py
==================
Extracts NTLM hashes from exported Windows SAM and SYSTEM registry hives.

Technique:
  1. Parse the SYSTEM hive to derive the boot key (SysKey).
  2. Use the boot key to decrypt the SAM hive's hashed boot key (HBoot key).
  3. Decrypt each user's V value to extract LM and NTLM hashes.

This replicates the core logic of tools like Impacket's secretsdump.py
for educational and defensive auditing purposes.

References:
  - https://www.passcape.com/index.php?section=docsys&cmd=details&id=23
  - Impacket project (SecureAuth / fortra) - Apache 2.0 License
"""

import struct
import hashlib
import logging
from typing import List, Dict, Any

try:
    from impacket.examples.secretsdump import LocalOperations, SAMHashes
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False

try:
    from Registry import Registry
    PYTHON_REGISTRY_AVAILABLE = True
except ImportError:
    PYTHON_REGISTRY_AVAILABLE = False


# ── Constants ────────────────────────────────────────────────────────────────

# Boot key scramble indices used by Windows to obfuscate the SysKey
BOOT_KEY_SCRAMBLE = [0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
                     0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7]

# SAM AES key constant
SAM_KEY_CONSTANT = b"NTPASSWORD\x00"
EMPTY_LM_HASH    = b"\xaa\xd3\xb4\x35\xb5\x14\x04\xee\xaa\xd3\xb4\x35\xb5\x14\x04\xee"
EMPTY_NT_HASH    = b"\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0"


class HashExtractor:
    """
    Extracts NTLM (and LM) password hashes from offline SAM + SYSTEM hive files.

    Tries Impacket (preferred, most accurate) first.
    Falls back to a native Python implementation if Impacket is unavailable.
    """

    def __init__(self, sam_path: str, system_path: str, logger: logging.Logger = None):
        self.sam_path    = sam_path
        self.system_path = system_path
        self.logger      = logger or logging.getLogger(__name__)

    def extract(self) -> List[Dict[str, Any]]:
        """
        Main extraction entry point.

        Returns:
            List of dicts:
            {
                "username": str,
                "rid": int,
                "lm_hash": str,   # hex string, empty string if no LM
                "ntlm_hash": str, # hex string
                "raw_line": str,  # original secretsdump-style line
            }
        """
        if IMPACKET_AVAILABLE:
            self.logger.info("Impacket available — using LocalOperations / SAMHashes")
            return self._extract_with_impacket()
        elif PYTHON_REGISTRY_AVAILABLE:
            self.logger.warning("Impacket not found — falling back to python-registry extraction")
            return self._extract_with_python_registry()
        else:
            self.logger.error(
                "Neither impacket nor python-registry is installed. "
                "Run: pip install impacket  OR  pip install python-registry"
            )
            raise ImportError(
                "Required library missing. Install impacket: pip install impacket"
            )

    # ── Impacket backend ─────────────────────────────────────────────────────

    def _extract_with_impacket(self) -> List[Dict[str, Any]]:
        """Use Impacket's LocalOperations + SAMHashes for accurate extraction."""
        results = []

        try:
            from io import StringIO
            import sys

            local_ops = LocalOperations(self.system_path)
            boot_key  = local_ops.getBootKey()
            self.logger.debug(f"Boot key: {boot_key.hex()}")

            # Capture stdout since SAMHashes.dump() prints directly
            old_stdout = sys.stdout
            sys.stdout = captured = StringIO()

            sam_hashes = SAMHashes(self.sam_path, boot_key, isRemote=False)
            sam_hashes.dump()
            sam_hashes.finish()

            sys.stdout = old_stdout
            output = captured.getvalue()

            # Parse each line: username:rid:lm:ntlm:::
            for line in output.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 4:
                    results.append({
                        "username":  parts[0],
                        "rid":       int(parts[1]) if parts[1].isdigit() else 0,
                        "lm_hash":   parts[2].lower(),
                        "ntlm_hash": parts[3].lower(),
                        "raw_line":  line,
                    })

            self.logger.info(f"Impacket extraction: {len(results)} hashes found")

        except Exception as e:
            sys.stdout = old_stdout if 'old_stdout' in locals() else sys.stdout
            self.logger.error(f"Impacket extraction failed: {e}")
            raise

        return results

    # ── Python-registry backend ───────────────────────────────────────────────

    def _extract_with_python_registry(self) -> List[Dict[str, Any]]:
        """
        Native Python extraction using python-registry.
        Implements the SysKey → SAM decryption chain manually.
        """
        self.logger.info("Starting native Python registry extraction")
        results = []

        try:
            boot_key = self._get_boot_key()
            self.logger.debug(f"Derived boot key: {boot_key.hex()}")

            hashed_boot_key = self._get_hashed_boot_key(boot_key)
            self.logger.debug(f"Hashed boot key derived")

            results = self._dump_sam_hashes(hashed_boot_key)
            self.logger.info(f"Native extraction: {len(results)} hashes found")

        except Exception as e:
            self.logger.error(f"Native extraction failed: {e}")
            raise

        return results

    def _get_boot_key(self) -> bytes:
        """
        Derives the 16-byte boot key (SysKey) from four SYSTEM hive subkey class names.
        The class names of JD, Skew1, GBG, Data under
        SYSTEM\\CurrentControlSet\\Control\\Lsa encode the scrambled boot key.
        """
        reg = Registry.Registry(self.system_path)

        # Determine CurrentControlSet number
        try:
            select_key = reg.open("Select")
            current    = select_key.value("Current").value()
            ccs        = f"ControlSet{current:03d}"
        except Exception:
            ccs = "ControlSet001"

        lsa_path   = f"{ccs}\\Control\\Lsa"
        subkeys    = ["JD", "Skew1", "GBG", "Data"]
        key_parts  = b""

        for sk in subkeys:
            key  = reg.open(f"{lsa_path}\\{sk}")
            cls  = key.classname()          # class name encodes 4 bytes each
            key_parts += bytes.fromhex(cls)

        # Descramble using BOOT_KEY_SCRAMBLE table
        boot_key = bytes(key_parts[BOOT_KEY_SCRAMBLE[i]] for i in range(16))
        return boot_key

    def _get_hashed_boot_key(self, boot_key: bytes) -> bytes:
        """
        Opens SAM\\Domains\\Account and decrypts the F value to get the
        hashed boot key used to decrypt individual user hashes.
        """
        import hashlib

        reg     = Registry.Registry(self.sam_path)
        account = reg.open("SAM\\Domains\\Account")
        f_value = account.value("F").value()

        # Revision 2 AES (Win >= Vista) or RC4 (XP and older)
        revision = struct.unpack("<H", f_value[0:2])[0]

        if revision == 3:
            # AES-128-CBC
            iv       = f_value[8:24]
            enc_data = f_value[24:56]
            hbk      = self._aes_decrypt(boot_key, iv, enc_data)
        else:
            # RC4 (legacy)
            rc4_key  = self._md5_rc4_key(boot_key, f_value)
            hbk      = self._rc4(rc4_key, f_value[80:112])

        return hbk

    def _dump_sam_hashes(self, hashed_boot_key: bytes) -> List[Dict[str, Any]]:
        """Enumerate all user RIDs under SAM\\Domains\\Account\\Users and decrypt hashes."""
        results = []
        reg     = Registry.Registry(self.sam_path)

        try:
            users_key = reg.open("SAM\\Domains\\Account\\Users")
        except Exception as e:
            raise RuntimeError(f"Cannot open SAM Users key: {e}")

        for subkey in users_key.subkeys():
            if subkey.name() == "Names":
                continue

            try:
                rid  = int(subkey.name(), 16)
                v    = subkey.value("V").value()
                name = self._get_username(subkey, rid)
                lm, ntlm = self._decrypt_user_hashes(v, hashed_boot_key, rid)

                results.append({
                    "username":  name,
                    "rid":       rid,
                    "lm_hash":   lm.hex() if lm else "aad3b435b51404eeaad3b435b51404ee",
                    "ntlm_hash": ntlm.hex() if ntlm else "31d6cfe0d16ae931b73c59d7e0c089c0",
                    "raw_line":  f"{name}:{rid}:{lm.hex() if lm else 'aad3b435b51404eeaad3b435b51404ee'}:{ntlm.hex() if ntlm else '31d6cfe0d16ae931b73c59d7e0c089c0'}:::",
                })
            except Exception as e:
                self.logger.warning(f"Skipping RID {subkey.name()}: {e}")
                continue

        return results

    def _get_username(self, user_key, rid: int) -> str:
        """Extract the username string from the V value offset table."""
        try:
            v      = user_key.value("V").value()
            offset = struct.unpack("<I", v[12:16])[0] + 0xCC
            length = struct.unpack("<I", v[16:20])[0]
            name   = v[offset:offset + length].decode("utf-16-le", errors="replace")
            return name if name else f"RID_{rid}"
        except Exception:
            return f"RID_{rid}"

    def _decrypt_user_hashes(self, v_data: bytes, hbk: bytes, rid: int):
        """
        Decrypt LM and NTLM hashes from the user's V value.
        Returns (lm_bytes, ntlm_bytes) — either may be None for empty/no hash.
        """
        def _extract_hash(v, offset_offset, hbk, rid, is_ntlm):
            try:
                offset = struct.unpack("<I", v[offset_offset:offset_offset + 4])[0] + 0xCC
                length = struct.unpack("<I", v[offset_offset + 4:offset_offset + 8])[0]
                if length not in (20, 24, 32, 40):
                    return None
                enc_hash = v[offset:offset + length]
                revision = struct.unpack("<H", enc_hash[2:4])[0]
                if revision == 1:
                    return self._decrypt_hash_rc4(enc_hash[4:], hbk, rid, is_ntlm)
                elif revision == 2:
                    return self._decrypt_hash_aes(enc_hash[4:], hbk, rid)
                return None
            except Exception:
                return None

        lm   = _extract_hash(v_data, 0x9C, hbk, rid, False)
        ntlm = _extract_hash(v_data, 0xA8, hbk, rid, True)
        return lm, ntlm

    # ── Crypto helpers ────────────────────────────────────────────────────────

    def _aes_decrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        from Crypto.Cipher import AES
        cipher = AES.new(key[:16], AES.MODE_CBC, iv)
        return cipher.decrypt(data)

    def _rc4(self, key: bytes, data: bytes) -> bytes:
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) % 256
            s[i], s[j] = s[j], s[i]
        i = j = 0
        result = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            result.append(byte ^ s[(s[i] + s[j]) % 256])
        return bytes(result)

    def _md5_rc4_key(self, boot_key: bytes, f_value: bytes) -> bytes:
        return hashlib.md5(boot_key + b"\x00" * 4 + f_value[96:112]).digest()

    def _decrypt_hash_rc4(self, enc: bytes, hbk: bytes, rid: int, is_ntlm: bool) -> bytes:
        rid_bytes = struct.pack("<I", rid) * 4
        const     = SAM_KEY_CONSTANT if is_ntlm else b"LMPASSWORD\x00"
        rc4_key   = hashlib.md5(hbk[:16] + rid_bytes[:16] + const).digest()
        return self._rc4(rc4_key, enc[:16])

    def _decrypt_hash_aes(self, enc: bytes, hbk: bytes, rid: int) -> bytes:
        iv  = enc[:16]
        ct  = enc[16:32]
        return self._aes_decrypt(hbk[:16], iv, ct)[:16]

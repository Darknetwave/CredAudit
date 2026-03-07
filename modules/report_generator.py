"""
report_generator.py
====================
Generates security audit reports in TXT, JSON, and HTML formats.

Each report includes:
  - Per-account summary (username, RID, hash, status, recovered password)
  - Risk flags per account
  - Overall statistics (cracked %, account type breakdown)
  - Actionable security recommendations
"""

import json
import logging
import os
from datetime import datetime
from typing import List, Dict, Any


# ── Recommendations logic ────────────────────────────────────────────────────

def build_recommendations(results: List[Dict[str, Any]]) -> List[str]:
    """Generate dynamic recommendations based on audit findings."""
    recs   = []
    cracked = [r for r in results if r["status"] == "cracked" and r["cleartext"] != ""]
    empty   = [r for r in results if r.get("empty_password")]
    lm      = [r for r in results if r.get("lm_enabled")]
    svc     = [r for r in results if r.get("account_type") == "Service Account"]
    admin   = [r for r in results if r.get("rid") == 500]

    if cracked:
        pct = round(len(cracked) / len(results) * 100)
        recs.append(
            f"CRITICAL — {len(cracked)} account(s) ({pct}%) had passwords recovered "
            "from a common wordlist. Enforce a minimum password length of 12+ characters "
            "with complexity requirements immediately."
        )

    if empty:
        names = ", ".join(e["username"] for e in empty)
        recs.append(
            f"CRITICAL — {len(empty)} account(s) have empty/blank passwords: {names}. "
            "Set strong passwords or disable unused accounts."
        )

    if lm:
        recs.append(
            f"HIGH — {len(lm)} account(s) have LAN Manager (LM) hashes stored. "
            "LM hashes are trivially crackable. Disable LM hash storage via Group Policy: "
            "Computer Configuration → Windows Settings → Security Settings → Local Policies → "
            "Security Options → 'Network security: Do not store LAN Manager hash value'."
        )

    if admin:
        recs.append(
            "HIGH — The built-in Administrator account (RID 500) is active. "
            "Rename it, disable it when not in use, and ensure it has a strong unique password."
        )

    if svc:
        recs.append(
            f"MEDIUM — {len(svc)} service account(s) found. "
            "Replace password-based service accounts with Group Managed Service Accounts (gMSA) "
            "which auto-rotate 120-character passwords."
        )

    recs += [
        "Enforce a password policy: minimum 12 characters, uppercase, lowercase, digits, special characters.",
        "Enable account lockout: threshold 5 attempts, lockout duration 30 minutes.",
        "Deploy and enforce Multi-Factor Authentication (MFA) for all interactive logons.",
        "Enable Windows Credential Guard to protect LSASS from memory-scraping attacks.",
        "Audit privileged group memberships (Administrators, Domain Admins) quarterly.",
        "Implement a Privileged Access Workstation (PAW) strategy for admin tasks.",
        "Monitor for Pass-the-Hash indicators: event IDs 4624 (type 3) with unexpected sources.",
        "Rotate all credentials exposed in this audit immediately.",
    ]

    return recs


# ── Severity helpers ──────────────────────────────────────────────────────────

def account_severity(acc: Dict[str, Any]) -> str:
    if acc.get("empty_password") or (acc["status"] == "cracked" and acc.get("rid") == 500):
        return "CRITICAL"
    if acc["status"] == "cracked":
        return "HIGH"
    if acc.get("lm_enabled"):
        return "MEDIUM"
    return "PASS"

SEVERITY_COLOR = {
    "CRITICAL": "#ff2d55",
    "HIGH":     "#ff9f0a",
    "MEDIUM":   "#ffd60a",
    "PASS":     "#30d158",
}


# ── Main class ────────────────────────────────────────────────────────────────

class ReportGenerator:
    """Generates TXT, JSON, and HTML audit reports."""

    def __init__(self, output_dir: str = "reports", logger: logging.Logger = None):
        self.output_dir = output_dir
        self.logger     = logger or logging.getLogger(__name__)
        os.makedirs(output_dir, exist_ok=True)

    def generate(
        self,
        results: List[Dict[str, Any]],
        formats: List[str],
        timestamp: str = None,
    ) -> Dict[str, str]:
        """
        Generate reports in the requested formats.

        Returns:
            Dict mapping format → output file path
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        recs   = build_recommendations(results)
        paths  = {}
        stats  = self._compute_stats(results)

        for fmt in formats:
            fname = f"audit_report_{timestamp}.{fmt}"
            path  = os.path.join(self.output_dir, fname)
            try:
                if fmt == "txt":
                    self._write_txt(path, results, recs, stats, timestamp)
                elif fmt == "json":
                    self._write_json(path, results, recs, stats, timestamp)
                elif fmt == "html":
                    self._write_html(path, results, recs, stats, timestamp)
                paths[fmt] = path
                self.logger.info(f"Report written: {path}")
            except Exception as e:
                self.logger.error(f"Failed to write {fmt} report: {e}")
                raise

        return paths

    # ── Stats ─────────────────────────────────────────────────────────────────

    def _compute_stats(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        cracked     = [r for r in results if r["status"] == "cracked"]
        not_cracked = [r for r in results if r["status"] == "not_cracked"]
        empty       = [r for r in results if r.get("empty_password")]
        lm          = [r for r in results if r.get("lm_enabled")]
        total       = len(results)

        type_counts: Dict[str, int] = {}
        for r in results:
            t = r.get("account_type", "Unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "total":         total,
            "cracked":       len(cracked),
            "not_cracked":   len(not_cracked),
            "empty_password": len(empty),
            "lm_enabled":    len(lm),
            "weak_pct":      round(len(cracked) / total * 100) if total else 0,
            "type_counts":   type_counts,
            "generated_at":  datetime.now().isoformat(),
        }

    # ── TXT Report ────────────────────────────────────────────────────────────

    def _write_txt(self, path, results, recs, stats, ts):
        W = 70
        lines = []
        sep   = "═" * W

        lines += [
            sep,
            "  WINDOWS CREDENTIAL SECURITY AUDIT REPORT",
            f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Timestamp : {ts}",
            sep, "",
            "  EXECUTIVE SUMMARY",
            "  " + "─" * (W - 2),
            f"  Total accounts audited : {stats['total']}",
            f"  Weak passwords found   : {stats['cracked']}  ({stats['weak_pct']}%)",
            f"  Strong / uncracked     : {stats['not_cracked']}",
            f"  Empty passwords        : {stats['empty_password']}",
            f"  LM hashes present      : {stats['lm_enabled']}",
            "",
        ]

        lines += ["  ACCOUNT DETAILS", "  " + "─" * (W - 2)]
        for acc in results:
            sev = account_severity(acc)
            lines.append(f"\n  User        : {acc['username']}")
            lines.append(f"  RID         : {acc['rid']}")
            lines.append(f"  Account Type: {acc.get('account_type', 'Unknown')}")
            lines.append(f"  NTLM Hash   : {acc['ntlm_hash']}")
            lines.append(f"  LM Hash     : {acc['lm_hash']}")
            lines.append(f"  LM Stored   : {'YES — RISK' if acc.get('lm_enabled') else 'No'}")
            if acc["status"] == "cracked":
                pwd_display = acc["cleartext"] if acc["cleartext"] else "(empty)"
                lines.append(f"  Status      : [WEAK] Password cracked — '{pwd_display}'")
            elif acc["status"] == "not_cracked":
                lines.append(f"  Status      : [STRONG] Password not in wordlist")
            else:
                lines.append(f"  Status      : [{acc['status'].upper()}]")

            if acc.get("risk_flags"):
                lines.append(f"  Risk Flags  :")
                for flag in acc["risk_flags"]:
                    lines.append(f"    • {flag}")

        lines += [
            "", sep,
            "  SECURITY RECOMMENDATIONS",
            "  " + "─" * (W - 2),
        ]
        for i, rec in enumerate(recs, 1):
            # Word-wrap at ~66 chars
            words = rec.split()
            current_line = f"  {i:02d}. "
            prefix       = " " * 6
            for w in words:
                if len(current_line) + len(w) + 1 > W:
                    lines.append(current_line)
                    current_line = prefix + w + " "
                else:
                    current_line += w + " "
            lines.append(current_line.rstrip())
            lines.append("")

        lines += [
            sep,
            "  DISCLAIMER",
            "  This report was generated by an authorized security audit tool.",
            "  Handle with strict confidentiality. Do not distribute.",
            sep,
        ]

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    # ── JSON Report ───────────────────────────────────────────────────────────

    def _write_json(self, path, results, recs, stats, ts):
        # Build clean output (exclude internal fields)
        accounts_out = []
        for acc in results:
            accounts_out.append({
                "username":       acc["username"],
                "rid":            acc["rid"],
                "account_type":   acc.get("account_type"),
                "ntlm_hash":      acc["ntlm_hash"],
                "lm_hash":        acc["lm_hash"],
                "lm_enabled":     acc.get("lm_enabled", False),
                "status":         acc["status"],
                "cleartext":      acc["cleartext"],
                "empty_password": acc.get("empty_password", False),
                "disabled":       acc.get("disabled", False),
                "severity":       account_severity(acc),
                "risk_flags":     acc.get("risk_flags", []),
            })

        report = {
            "report_metadata": {
                "tool":        "Automated Windows Credential Audit Tool",
                "version":     "1.0.0",
                "generated_at": datetime.now().isoformat(),
                "timestamp_id": ts,
            },
            "statistics":       stats,
            "accounts":         accounts_out,
            "recommendations":  recs,
            "disclaimer": (
                "This report is generated for authorized security auditing purposes only. "
                "Handle with strict confidentiality."
            ),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    # ── HTML Report ───────────────────────────────────────────────────────────

    def _write_html(self, path, results, recs, stats, ts):
        cracked_pct = stats["weak_pct"]
        strong_pct  = 100 - cracked_pct

        rows = ""
        for acc in results:
            sev   = account_severity(acc)
            color = SEVERITY_COLOR.get(sev, "#8e8e93")
            if acc["status"] == "cracked":
                status_html = f'<span class="badge cracked">⚠ WEAK — {acc["cleartext"] if acc["cleartext"] else "(empty)"}</span>'
            else:
                status_html = '<span class="badge strong">✓ STRONG</span>'
            flags_html = "".join(f'<li>{f}</li>' for f in acc.get("risk_flags", []))
            rows += f"""
            <tr>
              <td><strong>{acc["username"]}</strong></td>
              <td class="mono">{acc["rid"]}</td>
              <td>{acc.get("account_type","")}</td>
              <td class="mono small">{acc["ntlm_hash"]}</td>
              <td>{"<span class='lm-warn'>YES</span>" if acc.get("lm_enabled") else "No"}</td>
              <td>{status_html}</td>
              <td><span class="sev-badge" style="color:{color};border-color:{color}40;background:{color}15">{sev}</span></td>
              <td><ul class="flags">{flags_html}</ul></td>
            </tr>"""

        rec_items = "".join(f"<li>{r}</li>" for r in recs)

        type_bars = ""
        for t, cnt in stats["type_counts"].items():
            pct = round(cnt / stats["total"] * 100) if stats["total"] else 0
            type_bars += f"""
            <div class="type-row">
              <span class="type-label">{t}</span>
              <div class="type-bar-bg"><div class="type-bar" style="width:{pct}%"></div></div>
              <span class="type-count">{cnt}</span>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Windows Credential Audit Report</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Syne:wght@400;600;700;800&display=swap');
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: #080810; color: #e0e0f0;
      font-family: 'Syne', sans-serif; font-size: 14px; line-height: 1.6;
      padding: 40px 24px;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    /* Header */
    .header {{
      background: linear-gradient(135deg, #0d0d1a, #12122a);
      border: 1px solid #1e1e3a; border-radius: 16px;
      padding: 36px 40px; margin-bottom: 32px;
      position: relative; overflow: hidden;
    }}
    .header::before {{
      content: ""; position: absolute; top: -60px; right: -60px;
      width: 220px; height: 220px; border-radius: 50%;
      background: radial-gradient(circle, rgba(255,45,85,0.12), transparent 70%);
      pointer-events: none;
    }}
    .header-tag {{ color: #ff2d55; font-family: 'JetBrains Mono', monospace; font-size: 11px; letter-spacing: 3px; margin-bottom: 10px; text-transform: uppercase; }}
    .header h1 {{ font-size: 28px; font-weight: 800; letter-spacing: 1px; margin-bottom: 8px; }}
    .header-meta {{ color: #636380; font-family: 'JetBrains Mono', monospace; font-size: 11px; }}
    .header-meta span {{ color: #8080a0; margin-right: 24px; }}
    /* Stat cards */
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
    .stat-card {{
      background: #0d0d1a; border: 1px solid #1e1e3a; border-radius: 12px;
      padding: 20px; text-align: center; position: relative; overflow: hidden;
    }}
    .stat-card .val {{ font-size: 36px; font-weight: 800; line-height: 1; margin-bottom: 4px; }}
    .stat-card .lbl {{ font-size: 11px; color: #636380; text-transform: uppercase; letter-spacing: 1px; font-family: 'JetBrains Mono', monospace; }}
    .stat-card.danger  .val {{ color: #ff2d55; }}
    .stat-card.warning .val {{ color: #ff9f0a; }}
    .stat-card.good    .val {{ color: #30d158; }}
    .stat-card.info    .val {{ color: #0a84ff; }}
    /* Donut */
    .chart-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 32px; }}
    .chart-card {{
      background: #0d0d1a; border: 1px solid #1e1e3a; border-radius: 12px; padding: 24px;
    }}
    .chart-title {{ font-weight: 700; font-size: 13px; margin-bottom: 16px; letter-spacing: 1px; text-transform: uppercase; color: #8080a0; }}
    .donut-wrap {{ display: flex; align-items: center; gap: 24px; }}
    .donut-legend {{ flex: 1; }}
    .legend-item {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; font-size: 13px; }}
    .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
    .type-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }}
    .type-label {{ font-size: 11px; font-family: 'JetBrains Mono', monospace; color: #8080a0; width: 170px; flex-shrink: 0; }}
    .type-bar-bg {{ flex: 1; height: 6px; background: #1a1a2e; border-radius: 3px; overflow: hidden; }}
    .type-bar {{ height: 100%; background: linear-gradient(90deg, #0a84ff, #5ac8fa); border-radius: 3px; }}
    .type-count {{ font-size: 12px; font-family: 'JetBrains Mono', monospace; color: #636380; width: 24px; text-align: right; }}
    /* Table */
    .section-title {{ font-size: 13px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; color: #636380; margin-bottom: 16px; }}
    .table-wrap {{ overflow-x: auto; margin-bottom: 32px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    thead tr {{ background: #0d0d1a; }}
    thead th {{
      padding: 12px 14px; text-align: left; font-size: 10px;
      font-family: 'JetBrains Mono', monospace; font-weight: 500;
      letter-spacing: 1px; text-transform: uppercase; color: #636380;
      border-bottom: 1px solid #1e1e3a;
    }}
    tbody tr {{ border-bottom: 1px solid #111120; transition: background 0.15s; }}
    tbody tr:hover {{ background: #0d0d1a; }}
    tbody td {{ padding: 12px 14px; vertical-align: top; font-size: 13px; }}
    .mono  {{ font-family: 'JetBrains Mono', monospace; }}
    .small {{ font-size: 10px; color: #636380; }}
    .badge {{
      display: inline-block; padding: 3px 10px; border-radius: 5px;
      font-size: 11px; font-family: 'JetBrains Mono', monospace; font-weight: 500;
    }}
    .badge.cracked {{ background: rgba(255,45,85,0.15); color: #ff2d55; border: 1px solid rgba(255,45,85,0.3); }}
    .badge.strong  {{ background: rgba(48,209,88,0.12); color: #30d158; border: 1px solid rgba(48,209,88,0.25); }}
    .lm-warn {{ color: #ff9f0a; font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 600; }}
    .sev-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; border: 1px solid; font-size: 10px; font-family: 'JetBrains Mono', monospace; letter-spacing: 1px; }}
    ul.flags {{ list-style: none; padding: 0; font-size: 11px; color: #636380; line-height: 1.8; }}
    ul.flags li::before {{ content: "• "; color: #ff9f0a; }}
    /* Recommendations */
    .rec-card {{
      background: #0d0d1a; border: 1px solid #1e1e3a; border-radius: 12px;
      padding: 28px 32px; margin-bottom: 32px;
    }}
    .rec-card ol {{ padding-left: 20px; }}
    .rec-card li {{ margin-bottom: 12px; font-size: 13px; line-height: 1.7; color: #c0c0d8; }}
    .rec-card li::marker {{ color: #ff2d55; font-weight: 700; }}
    /* Disclaimer */
    .disclaimer {{
      background: rgba(255,214,10,0.06); border: 1px solid rgba(255,214,10,0.2);
      border-radius: 10px; padding: 16px 20px;
      font-size: 12px; color: #ffd60a; font-family: 'JetBrains Mono', monospace; line-height: 1.7;
    }}
  </style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <div class="header-tag">Security Audit Report</div>
    <h1>Windows Credential Audit</h1>
    <div class="header-meta">
      <span>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>
      <span>Report ID: {ts}</span>
      <span>Tool: Automated Windows Credential Audit Tool v1.0.0</span>
    </div>
  </div>

  <!-- Stat cards -->
  <div class="stats-grid">
    <div class="stat-card info"><div class="val">{stats["total"]}</div><div class="lbl">Accounts Audited</div></div>
    <div class="stat-card danger"><div class="val">{stats["cracked"]}</div><div class="lbl">Weak Passwords</div></div>
    <div class="stat-card good"><div class="val">{stats["not_cracked"]}</div><div class="lbl">Strong / Uncracked</div></div>
    <div class="stat-card warning"><div class="val">{stats["empty_password"]}</div><div class="lbl">Empty Passwords</div></div>
    <div class="stat-card warning"><div class="val">{stats["lm_enabled"]}</div><div class="lbl">LM Hashes Present</div></div>
    <div class="stat-card danger"><div class="val">{stats["weak_pct"]}%</div><div class="lbl">Weak Password Rate</div></div>
  </div>

  <!-- Charts -->
  <div class="chart-row">
    <div class="chart-card">
      <div class="chart-title">Password Strength Distribution</div>
      <div class="donut-wrap">
        <svg width="120" height="120" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="46" fill="none" stroke="#1a1a2e" stroke-width="16"/>
          <circle cx="60" cy="60" r="46" fill="none" stroke="#ff2d55" stroke-width="16"
            stroke-dasharray="{cracked_pct * 2.89:.1f} 289"
            stroke-dashoffset="72.25" stroke-linecap="butt"/>
          <circle cx="60" cy="60" r="46" fill="none" stroke="#30d158" stroke-width="16"
            stroke-dasharray="{strong_pct * 2.89:.1f} 289"
            stroke-dashoffset="{72.25 - cracked_pct * 2.89:.1f}" stroke-linecap="butt"/>
          <text x="60" y="55" text-anchor="middle" fill="#e0e0f0" font-size="20" font-family="Syne" font-weight="800">{stats["weak_pct"]}%</text>
          <text x="60" y="72" text-anchor="middle" fill="#636380" font-size="10" font-family="JetBrains Mono">weak</text>
        </svg>
        <div class="donut-legend">
          <div class="legend-item"><div class="legend-dot" style="background:#ff2d55"></div><span>Weak / Cracked: {stats["cracked"]}</span></div>
          <div class="legend-item"><div class="legend-dot" style="background:#30d158"></div><span>Strong: {stats["not_cracked"]}</span></div>
          <div class="legend-item"><div class="legend-dot" style="background:#ff9f0a"></div><span>Empty Password: {stats["empty_password"]}</span></div>
        </div>
      </div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Account Type Breakdown</div>
      {type_bars}
    </div>
  </div>

  <!-- Table -->
  <div class="section-title">Account Audit Details</div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Username</th><th>RID</th><th>Account Type</th>
          <th>NTLM Hash</th><th>LM Hash</th><th>Password Status</th>
          <th>Severity</th><th>Risk Flags</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>

  <!-- Recommendations -->
  <div class="section-title">Security Recommendations</div>
  <div class="rec-card">
    <ol>{rec_items}</ol>
  </div>

  <!-- Disclaimer -->
  <div class="disclaimer">
    ⚠ CONFIDENTIAL — This report was generated for authorized security auditing purposes only.
    All findings represent potential vulnerabilities identified in a controlled assessment.
    Handle this document with strict confidentiality and distribute only to authorized personnel.
    Immediately rotate any exposed credentials identified in this report.
  </div>
</div>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

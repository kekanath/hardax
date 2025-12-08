#!/usr/bin/env python3
"""
CRISCAN - Critical Infrastructure Security Scanner (Python 3)

A comprehensive security audit framework for Android-based critical infrastructure:
  • Medical Devices (FDA 524B, HIPAA)
  • Connected Vehicles (ISO 21434, UNECE R155/R156)
  • Industrial IoT (IEC 62443)
  • Smart Infrastructure

Features:
- Loads checks from JSON:
    * --json <file>         (can be repeated)
    * --json-dir <folder>   (loads all *.json in folder)
  Each file may be either:
    * a list of check objects: [ {category, label, command, safe_pattern, ...}, ... ]
    * or { "checks": [ ... ] }

- Auto-detects ADB devices (friendly guidance if none/multiple)
- Generates TXT, HTML, CSV reports in timestamped folders
- Progress display: --progress-numbers prints live "X/Y" only
- Compliance mapping support (OWASP IoT, NIST, ISO 21434, FDA, IEC 62443)
- SBOM generation capability
- Industry profile support (--profile medical/automotive/industrial)

Usage:
    # Run with all checks in commands folder
    python3 criscan.py --json-dir commands/

    # Run with specific profile
    python3 criscan.py --profile medical --json-dir commands/

    # Run specific check files
    python3 criscan.py --json commands/boot_security.json --json commands/network.json

    # Target specific device
    python3 criscan.py --serial <DEVICE_SERIAL> --json-dir commands/

Reports are saved in `criscan_reports/` with timestamped folders.

Made with ❤️ by IoTSRG Team
"""

import argparse
import csv
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import List, Dict, Any, Tuple, Optional

# ============================================================================
# VERSION & METADATA
# ============================================================================
__version__ = "2.0.0"
TOOL_NAME = "CRISCAN"
TOOL_FULL = "Critical Infrastructure Security Scanner"

# ============================================================================
# INDUSTRY PROFILES
# ============================================================================
PROFILES = {
    "medical": {
        "name": "Medical Device Audit (FDA 524B)",
        "description": "FDA cybersecurity requirements for medical devices",
        "categories": ["BOOT SECURITY", "ENCRYPTION", "NETWORK", "APPS", "TEE/TPM", 
                      "PATCHING", "USER PRIVACY", "MEDICAL DEVICE", "SBOM"]
    },
    "automotive": {
        "name": "Automotive Audit (ISO 21434 / UNECE R155)",
        "description": "Connected vehicle security assessment",
        "categories": ["BOOT SECURITY", "AVB", "DM-VERITY", "BOOTLOADER", "BLUETOOTH",
                      "NETWORK", "OTA SECURITY", "AUTOMOTIVE"]
    },
    "industrial": {
        "name": "Industrial IoT Audit (IEC 62443)",
        "description": "Industrial control system security",
        "categories": ["BOOT SECURITY", "SELINUX", "NETWORK", "KERNEL", "MEMORY",
                      "FILESYSTEM", "PROCESS SNAPSHOT"]
    },
    "full": {
        "name": "Full Security Audit",
        "description": "Comprehensive audit with all checks",
        "categories": []  # Empty means all categories
    }
}

# ============================================================================
# COMPLIANCE FRAMEWORKS (for reference in reports)
# ============================================================================
COMPLIANCE_FRAMEWORKS = {
    "owasp_iot": "OWASP IoT Top 10 (2018)",
    "nist_8259a": "NISTIR 8259A Core Baseline",
    "iso_21434": "ISO/SAE 21434 Automotive Cybersecurity",
    "unece_r155": "UNECE WP.29 R155 (CSMS)",
    "unece_r156": "UNECE WP.29 R156 (SUMS)",
    "fda_524b": "FDA Section 524B Cyber Devices",
    "hipaa": "HIPAA Security Rule",
    "iec_62443": "IEC 62443 Industrial Security",
    "cis_android": "CIS Android Benchmark"
}

# ============================================================================
# SHELL HELPERS
# ============================================================================
def which(prog: str) -> Optional[str]:
    return shutil.which(prog)


def run(cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


# ============================================================================
# ADB DEVICE DISCOVERY
# ============================================================================
def list_adb_devices() -> list:
    """Return a list of dicts: [{"serial": "...", "state": "...", "desc": "..."}]"""
    code, out, _ = run(["adb", "devices", "-l"])
    if code != 0:
        return []
    lines = [l.strip() for l in out.splitlines()[1:] if l.strip()]
    devices = []
    for ln in lines:
        parts = ln.split()
        if not parts:
            continue
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"
        desc = " ".join(parts[2:]) if len(parts) > 2 else ""
        devices.append({"serial": serial, "state": state, "desc": desc})
    return devices


def pick_default_serial(user_serial: Optional[str]) -> Optional[str]:
    """Pick a sane default serial if not provided."""
    if user_serial:
        return user_serial
    devs = list_adb_devices()
    healthy = [d for d in devs if d["state"] == "device"]
    if len(healthy) == 1:
        return healthy[0]["serial"]
    return None


def explain_adb_devices_and_exit(exit_code: int = 2):
    devs = list_adb_devices()
    if not devs:
        msg = (
            "\n╔══════════════════════════════════════════════════════════════════╗\n"
            "║  ⚠️  No ADB devices detected                                      ║\n"
            "╠══════════════════════════════════════════════════════════════════╣\n"
            "║  Troubleshooting:                                                ║\n"
            "║  • Enable Developer options and USB debugging on device         ║\n"
            "║  • Trust this computer on the device prompt                     ║\n"
            "║  • Run: adb kill-server && adb start-server                     ║\n"
            "║  • Check USB cable/port or try: adb connect <ip>:5555           ║\n"
            "╚══════════════════════════════════════════════════════════════════╝\n"
        )
        print(msg, file=sys.stderr)
        sys.exit(exit_code)
    
    print("\n┌─ Detected ADB Devices (use --serial <id>) ─────────────────────┐")
    for d in devs:
        icon = "✓" if d["state"] == "device" else "✗"
        print(f"│  {icon} {d['serial']:<24} {d['state']:<12} {d['desc'][:20]:<20} │")
    print("├────────────────────────────────────────────────────────────────┤")
    print("│  • Only 'device' state is usable                              │")
    print("│  • 'unauthorized' = Accept RSA fingerprint on device          │")
    print("└────────────────────────────────────────────────────────────────┘\n")
    sys.exit(exit_code)


# ============================================================================
# ADB SHELL WRAPPER
# ============================================================================
class ADB:
    def __init__(self, serial: Optional[str] = None):
        self.serial = serial

    def base(self) -> List[str]:
        return ["adb"] + (["-s", self.serial] if self.serial else [])

    def check_connected(self) -> None:
        code, out, err = run(self.base() + ["get-state"])
        if code != 0:
            _, devs, _ = run(["adb", "devices", "-l"])
            raise RuntimeError("No ADB device detected or unauthorized. Output:\n" + devs)

    def shell(self, command: str, timeout: int = 30) -> str:
        code, out, err = run(self.base() + ["shell", command], timeout=timeout)
        out = (out or "").replace("\r", "")
        return out if out.strip() else ""


# ============================================================================
# UTILITIES
# ============================================================================
def html_escape(s: str) -> str:
    return html.escape(s or "", quote=False)


def normalize_for_match(s: str) -> str:
    return re.sub(r"\r?\n+", " ", s or "")


def bucket_from_level(level: str) -> str:
    lvl = (level or "").strip().lower()
    if lvl in ("critical", "high"):
        return "critical"
    if lvl in ("warning", "medium"):
        return "warning"
    return "info"


# ============================================================================
# BANNER
# ============================================================================
def print_banner(serial: Optional[str], profile: Optional[str] = None) -> None:
    banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║   ██████╗██████╗ ██╗███████╗ ██████╗ █████╗ ███╗   ██╗                        ║
║  ██╔════╝██╔══██╗██║██╔════╝██╔════╝██╔══██╗████╗  ██║                        ║
║  ██║     ██████╔╝██║███████╗██║     ███████║██╔██╗ ██║                        ║
║  ██║     ██╔══██╗██║╚════██║██║     ██╔══██║██║╚██╗██║                        ║
║  ╚██████╗██║  ██║██║███████║╚██████╗██║  ██║██║ ╚████║                        ║
║   ╚═════╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                        ║
║                                                                               ║
║  CRISCAN - Critical Infrastructure Security Scanner v{version:<22}║
║  Android Security Audit Framework for IoT | Medical | Automotive             ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """.format(version=__version__)
    print(banner)
    
    if profile and profile in PROFILES:
        p = PROFILES[profile]
        print(f"  Profile: {p['name']}")
        print(f"  {p['description']}")
    
    if serial:
        print(f"  Target Device: {serial}")
    print()


# ============================================================================
# DEVICE INFO COLLECTION
# ============================================================================
def get_prop_fallback(adb: ADB, props: List[str]) -> str:
    for p in props:
        v = adb.shell(f"getprop {p}").strip()
        if v:
            return v
    return "(unknown)"


def collect_device_info(adb: ADB) -> Dict[str, str]:
    info = {
        "model": get_prop_fallback(adb, ["ro.product.model", "ro.product.device", "ro.product.name"]),
        "brand": get_prop_fallback(adb, ["ro.product.brand", "ro.product.manufacturer"]),
        "manufacturer": get_prop_fallback(adb, ["ro.product.manufacturer", "ro.product.brand"]),
        "name": get_prop_fallback(adb, ["ro.product.name", "ro.product.model"]),
        "soc_manufacturer": get_prop_fallback(adb, ["ro.soc.manufacturer", "ro.board.platform"]),
        "soc_model": get_prop_fallback(adb, ["ro.soc.model", "ro.hardware", "ro.board.platform"]),
        "android_version": adb.shell("getprop ro.build.version.release").strip(),
        "sdk_level": adb.shell("getprop ro.build.version.sdk").strip(),
        "build_id": adb.shell("getprop ro.build.display.id").strip(),
        "fingerprint": adb.shell("getprop ro.build.fingerprint").strip(),
        "serialno": get_prop_fallback(adb, ["ro.serialno", "ro.boot.serialno"]),
        "security_patch": adb.shell("getprop ro.build.version.security_patch").strip(),
        "kernel_version": adb.shell("uname -r").strip(),
        "timezone": adb.shell("getprop persist.sys.timezone").strip(),
        "build_type": adb.shell("getprop ro.build.type").strip(),
    }
    return info


# ============================================================================
# CHECK LOADER
# ============================================================================
def _load_checks_from_file(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("checks"), list):
        return data["checks"]
    raise ValueError(f"JSON in '{path}' must be a list of checks or an object with a 'checks' array")


def _load_checks_from_dir(folder: str) -> List[Dict[str, Any]]:
    if not os.path.isdir(folder):
        raise FileNotFoundError(f"JSON directory not found: {folder}")
    checks: List[Dict[str, Any]] = []
    for name in sorted(os.listdir(folder)):
        if not name.lower().endswith(".json"):
            continue
        path = os.path.join(folder, name)
        try:
            checks.extend(_load_checks_from_file(path))
        except Exception as e:
            print(f"[WARN] Skipping '{path}': {e}", file=sys.stderr)
    return checks


def filter_checks_by_profile(checks: List[Dict], profile_name: str) -> List[Dict]:
    """Filter checks based on profile categories."""
    if profile_name not in PROFILES or not PROFILES[profile_name]["categories"]:
        return checks  # Return all if profile not found or 'full' profile
    
    allowed_categories = [c.upper() for c in PROFILES[profile_name]["categories"]]
    filtered = []
    for check in checks:
        cat = check.get("category", "").upper()
        # Match if category starts with any allowed category prefix
        if any(cat.startswith(allowed) or allowed in cat for allowed in allowed_categories):
            filtered.append(check)
    return filtered if filtered else checks


# ============================================================================
# CHECK RUNNER
# ============================================================================
def run_checks(adb: ADB, checks: List[Dict[str, Any]], on_progress=None) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    rows = []
    counts = {"safe": 0, "warning": 0, "critical": 0, "info": 0, "not_supported": 0}
    total = len(checks)
    
    for idx, chk in enumerate(checks, start=1):
        if on_progress:
            try:
                on_progress(idx, total)
            except Exception:
                pass

        category = chk.get("category", "")
        label = chk.get("label", "")
        command = chk.get("command", "")
        safe_pattern = chk.get("safe_pattern", ".*")
        level = chk.get("level", "info")
        desc = chk.get("description", "")
        compliance = chk.get("compliance", {})
        cve_related = chk.get("cve_related", [])

        raw = adb.shell(command).rstrip("\n")
        if not raw.strip():
            raw = "[Not Supported]"

        match_src = normalize_for_match(raw)
        try:
            matched = bool(re.search(safe_pattern, match_src, flags=re.DOTALL))
        except re.error:
            matched = False

        if raw == "[Not Supported]":
            status = "INFO"
            bucket = "info"
            counts["not_supported"] += 1
        elif matched:
            status = "SAFE"
            bucket = "info"
            counts["safe"] += 1
        else:
            bucket = bucket_from_level(level)
            if bucket == "critical":
                status = "CRITICAL"
                counts["critical"] += 1
            elif bucket == "warning":
                status = "WARNING"
                counts["warning"] += 1
            else:
                status = "INFO"
                counts["info"] += 1

        rows.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "category": category,
            "label": label,
            "level": level,
            "bucket": bucket,
            "status": status,
            "matched": str(matched),
            "command": command,
            "result": raw,
            "description": desc,
            "compliance": compliance,
            "cve_related": cve_related,
        })
    return rows, counts


# ============================================================================
# REPORT WRITERS
# ============================================================================
def write_csv(csv_path: str, rows: List[Dict[str, Any]]) -> None:
    fieldnames = ["timestamp", "category", "label", "level", "bucket", "status",
                  "matched", "command", "result", "description"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_json(json_path: str, device: Dict, rows: List[Dict], counts: Dict, profile: str = None) -> None:
    """Write machine-readable JSON report."""
    report = {
        "tool": TOOL_NAME,
        "version": __version__,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "profile": profile,
        "device": device,
        "summary": counts,
        "findings": rows
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def write_html(html_path: str, device: Dict[str, str], rows: List[Dict[str, Any]], 
               counts: Dict[str, int], profile: str = None) -> None:
    
    def esc(x):
        return html.escape(str(x) if x else "", quote=False)

    # Build sections
    sections = []
    for r in rows:
        css_class = {"SAFE": "safe", "WARNING": "warning", "CRITICAL": "critical"}.get(r["status"], "info")
        
        # Compliance badges
        compliance_html = ""
        if r.get("compliance"):
            badges = []
            for framework, refs in r["compliance"].items():
                if framework in COMPLIANCE_FRAMEWORKS:
                    badges.append(f'<span class="badge">{framework.upper()}</span>')
            if badges:
                compliance_html = f'<div class="compliance">{"".join(badges)}</div>'
        
        # CVE references
        cve_html = ""
        if r.get("cve_related"):
            cves = ", ".join(r["cve_related"])
            cve_html = f'<div class="cve">Related CVEs: {esc(cves)}</div>'
        
        sections.append(f"""
<section class="check-result">
  <h3>{esc(r["category"])} — {esc(r["label"])}</h3>
  <p class="description"><strong>Description:</strong> {esc(r.get("description",""))}</p>
  {compliance_html}
  {cve_html}
  <details>
    <summary>Command & Output</summary>
    <p><strong>Command:</strong></p><pre><code>{esc(r["command"])}</code></pre>
    <p><strong>Result:</strong></p><pre><code>{esc(r["result"])}</code></pre>
  </details>
  <div class="status-box {css_class}"><strong>Status:</strong> {esc(r["status"])}</div>
</section>
""")
    sections_html = "\n".join(sections)

    # Profile info
    profile_html = ""
    if profile and profile in PROFILES:
        p = PROFILES[profile]
        profile_html = f"""
        <div class="profile-info">
            <strong>Audit Profile:</strong> {esc(p['name'])}<br>
            <small>{esc(p['description'])}</small>
        </div>
        """

    # Calculate pass rate
    evaluated = counts["safe"] + counts["warning"] + counts["critical"]
    pass_rate = round((counts["safe"] / evaluated) * 100, 1) if evaluated > 0 else 0

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{TOOL_NAME} - Security Audit Report</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="generator" content="{TOOL_NAME} v{__version__}">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {{
      --bg: #f8f9fa;
      --fg: #212529;
      --card: #ffffff;
      --border: #dee2e6;
      --safe: #28a745;
      --safe-bg: #d4edda;
      --warn: #ffc107;
      --warn-bg: #fff3cd;
      --crit: #dc3545;
      --crit-bg: #f8d7da;
      --info: #17a2b8;
      --info-bg: #d1ecf1;
      --primary: #0d6efd;
    }}
    
    * {{ box-sizing: border-box; }}
    
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: var(--bg);
      color: var(--fg);
      margin: 0;
      padding: 20px;
      line-height: 1.6;
    }}
    
    .container {{ max-width: 1200px; margin: 0 auto; }}
    
    header {{
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      color: white;
      padding: 30px;
      border-radius: 12px;
      margin-bottom: 30px;
    }}
    
    header h1 {{
      margin: 0 0 10px 0;
      font-size: 2rem;
    }}
    
    header .subtitle {{
      opacity: 0.9;
      font-size: 1.1rem;
    }}
    
    .toolbar {{
      position: sticky;
      top: 0;
      z-index: 100;
      background: var(--bg);
      padding: 15px 0;
      display: flex;
      gap: 15px;
      flex-wrap: wrap;
      align-items: center;
      border-bottom: 1px solid var(--border);
      margin-bottom: 20px;
    }}
    
    .toolbar input[type="text"] {{
      padding: 10px 15px;
      border: 1px solid var(--border);
      border-radius: 8px;
      font-size: 1rem;
      width: 300px;
      max-width: 100%;
    }}
    
    .toolbar select {{
      padding: 10px 15px;
      border: 1px solid var(--border);
      border-radius: 8px;
      font-size: 1rem;
      background: white;
    }}
    
    .btn {{
      padding: 10px 20px;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-size: 1rem;
      transition: all 0.2s;
    }}
    
    .btn-primary {{
      background: var(--primary);
      color: white;
    }}
    
    .btn-primary:hover {{
      background: #0b5ed7;
    }}
    
    .card {{
      background: var(--card);
      border-radius: 12px;
      padding: 25px;
      margin-bottom: 20px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }}
    
    .card h2 {{
      margin-top: 0;
      padding-bottom: 15px;
      border-bottom: 2px solid var(--border);
    }}
    
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 15px;
      margin: 20px 0;
    }}
    
    .stat-box {{
      text-align: center;
      padding: 20px;
      border-radius: 10px;
      background: var(--bg);
    }}
    
    .stat-box.safe {{ background: var(--safe-bg); border-left: 4px solid var(--safe); }}
    .stat-box.warning {{ background: var(--warn-bg); border-left: 4px solid var(--warn); }}
    .stat-box.critical {{ background: var(--crit-bg); border-left: 4px solid var(--crit); }}
    .stat-box.info {{ background: var(--info-bg); border-left: 4px solid var(--info); }}
    
    .stat-box .number {{
      font-size: 2.5rem;
      font-weight: bold;
      display: block;
    }}
    
    .stat-box .label {{
      font-size: 0.9rem;
      text-transform: uppercase;
      opacity: 0.8;
    }}
    
    .device-info {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 10px;
    }}
    
    .device-info div {{
      padding: 8px 0;
      border-bottom: 1px solid var(--border);
    }}
    
    .device-info strong {{
      color: #6c757d;
      font-size: 0.85rem;
      text-transform: uppercase;
    }}
    
    .check-result {{
      background: var(--card);
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 15px;
      border-left: 4px solid var(--border);
    }}
    
    .check-result h3 {{
      margin: 0 0 10px 0;
      font-size: 1.1rem;
    }}
    
    .check-result .description {{
      color: #6c757d;
      margin-bottom: 10px;
    }}
    
    .check-result details {{
      margin: 15px 0;
    }}
    
    .check-result summary {{
      cursor: pointer;
      color: var(--primary);
      font-weight: 500;
    }}
    
    .check-result pre {{
      background: #f1f3f4;
      padding: 15px;
      border-radius: 8px;
      overflow-x: auto;
      font-size: 0.85rem;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    
    .status-box {{
      display: inline-block;
      padding: 8px 16px;
      border-radius: 6px;
      font-weight: 600;
    }}
    
    .status-box.safe {{ background: var(--safe-bg); color: var(--safe); }}
    .status-box.warning {{ background: var(--warn-bg); color: #856404; }}
    .status-box.critical {{ background: var(--crit-bg); color: var(--crit); }}
    .status-box.info {{ background: var(--info-bg); color: var(--info); }}
    
    .badge {{
      display: inline-block;
      padding: 3px 8px;
      background: #e9ecef;
      border-radius: 4px;
      font-size: 0.75rem;
      margin-right: 5px;
      text-transform: uppercase;
    }}
    
    .compliance {{ margin: 10px 0; }}
    .cve {{ color: var(--crit); font-size: 0.9rem; margin: 10px 0; }}
    
    .profile-info {{
      background: rgba(255,255,255,0.1);
      padding: 15px;
      border-radius: 8px;
      margin-top: 15px;
    }}
    
    .chart-container {{
      max-width: 300px;
      margin: 20px auto;
    }}
    
    footer {{
      text-align: center;
      padding: 30px;
      color: #6c757d;
      border-top: 1px solid var(--border);
      margin-top: 30px;
    }}
    
    footer a {{ color: var(--primary); text-decoration: none; }}
    
    /* Dark mode */
    body.dark {{
      --bg: #1a1a2e;
      --fg: #e9ecef;
      --card: #16213e;
      --border: #3a3a5c;
    }}
    
    body.dark .check-result pre {{
      background: #0f0f1a;
    }}
    
    body.dark .toolbar {{
      background: var(--bg);
    }}
    
    body.dark .toolbar input,
    body.dark .toolbar select {{
      background: var(--card);
      color: var(--fg);
      border-color: var(--border);
    }}
    
    @media print {{
      .toolbar, .btn {{ display: none; }}
      body {{ padding: 0; }}
      .check-result {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🔒 {TOOL_NAME} Security Audit Report</h1>
      <div class="subtitle">{TOOL_FULL}</div>
      <div style="margin-top: 10px; opacity: 0.8;">
        <strong>Generated:</strong> {time.strftime("%Y-%m-%d %H:%M:%S")} | 
        <strong>Version:</strong> {__version__}
      </div>
      {profile_html}
    </header>
    
    <div class="toolbar">
      <input type="text" id="searchInput" placeholder="🔍 Search findings...">
      <select id="filterStatus">
        <option value="">All Status</option>
        <option value="CRITICAL">Critical Only</option>
        <option value="WARNING">Warnings Only</option>
        <option value="SAFE">Safe Only</option>
      </select>
      <button class="btn btn-primary" onclick="toggleTheme()">🌙 Toggle Theme</button>
      <button class="btn btn-primary" onclick="window.print()">🖨️ Print Report</button>
    </div>
    
    <div class="card">
      <h2>📊 Executive Summary</h2>
      <div class="stats-grid">
        <div class="stat-box safe">
          <span class="number">{counts["safe"]}</span>
          <span class="label">Passed</span>
        </div>
        <div class="stat-box warning">
          <span class="number">{counts["warning"]}</span>
          <span class="label">Warnings</span>
        </div>
        <div class="stat-box critical">
          <span class="number">{counts["critical"]}</span>
          <span class="label">Critical</span>
        </div>
        <div class="stat-box info">
          <span class="number">{pass_rate}%</span>
          <span class="label">Pass Rate</span>
        </div>
      </div>
      <div class="chart-container">
        <canvas id="summaryChart"></canvas>
      </div>
    </div>
    
    <div class="card">
      <h2>📱 Device Information</h2>
      <div class="device-info">
        <div><strong>Model</strong><br>{esc(device.get("model"))}</div>
        <div><strong>Brand</strong><br>{esc(device.get("brand"))}</div>
        <div><strong>Manufacturer</strong><br>{esc(device.get("manufacturer"))}</div>
        <div><strong>Android Version</strong><br>{esc(device.get("android_version"))}</div>
        <div><strong>SDK Level</strong><br>{esc(device.get("sdk_level"))}</div>
        <div><strong>Security Patch</strong><br>{esc(device.get("security_patch"))}</div>
        <div><strong>Kernel</strong><br>{esc(device.get("kernel_version"))}</div>
        <div><strong>Build ID</strong><br>{esc(device.get("build_id"))}</div>
        <div><strong>Build Type</strong><br>{esc(device.get("build_type"))}</div>
        <div><strong>Serial</strong><br>{esc(device.get("serialno"))}</div>
        <div><strong>SoC</strong><br>{esc(device.get("soc_model"))}</div>
        <div><strong>Fingerprint</strong><br><small>{esc(device.get("fingerprint"))}</small></div>
      </div>
    </div>
    
    <div class="card">
      <h2>🔍 Security Findings ({len(rows)} checks)</h2>
      <div id="findings">
        {sections_html}
      </div>
    </div>
    
    <footer>
      <p>Made with ❤️ by <strong>IoTSRG Team</strong></p>
      <p><a href="https://github.com/IoTSRG/criscan">{TOOL_NAME}</a> - {TOOL_FULL}</p>
    </footer>
  </div>
  
  <script>
    // Chart
    const ctx = document.getElementById('summaryChart').getContext('2d');
    new Chart(ctx, {{
      type: 'doughnut',
      data: {{
        labels: ['Safe', 'Warnings', 'Critical'],
        datasets: [{{
          data: [{counts["safe"]}, {counts["warning"]}, {counts["critical"]}],
          backgroundColor: ['#28a745', '#ffc107', '#dc3545']
        }}]
      }},
      options: {{
        responsive: true,
        plugins: {{
          legend: {{ position: 'bottom' }}
        }}
      }}
    }});
    
    // Search filter
    document.getElementById('searchInput').addEventListener('input', filterResults);
    document.getElementById('filterStatus').addEventListener('change', filterResults);
    
    function filterResults() {{
      const query = document.getElementById('searchInput').value.toLowerCase();
      const status = document.getElementById('filterStatus').value;
      document.querySelectorAll('.check-result').forEach(el => {{
        const text = el.innerText.toLowerCase();
        const matchesQuery = !query || text.includes(query);
        const matchesStatus = !status || el.querySelector('.status-box').innerText.includes(status);
        el.style.display = (matchesQuery && matchesStatus) ? '' : 'none';
      }});
    }}
    
    // Theme toggle
    function toggleTheme() {{
      document.body.classList.toggle('dark');
      localStorage.setItem('theme', document.body.classList.contains('dark') ? 'dark' : 'light');
    }}
    
    // Load saved theme
    if (localStorage.getItem('theme') === 'dark') {{
      document.body.classList.add('dark');
    }}
  </script>
</body>
</html>"""
    
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(doc)


def write_txt(txt_path: str, device: Dict, rows: List[Dict], counts: Dict, profile: str = None) -> None:
    """Write plain text report."""
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(f"  {TOOL_NAME} - {TOOL_FULL}\n")
        f.write(f"  Security Audit Report\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Version: {__version__}\n")
        if profile:
            f.write(f"Profile: {profile}\n")
        f.write("\n")
        
        f.write("-" * 40 + "\n")
        f.write("DEVICE INFORMATION\n")
        f.write("-" * 40 + "\n")
        for key in ["model", "brand", "manufacturer", "android_version", "sdk_level",
                    "security_patch", "kernel_version", "build_id", "serialno", "fingerprint"]:
            f.write(f"{key.replace('_', ' ').title()}: {device.get(key, '')}\n")
        f.write("\n")
        
        f.write("-" * 40 + "\n")
        f.write("FINDINGS\n")
        f.write("-" * 40 + "\n\n")
        
        for r in rows:
            f.write(f"[{r['status']}] {r['category']} - {r['label']}\n")
            f.write(f"  Command: {r['command']}\n")
            f.write(f"  Description: {r['description']}\n")
            f.write(f"  Result: {r['result'][:200]}{'...' if len(r['result']) > 200 else ''}\n")
            f.write("\n")
        
        f.write("=" * 80 + "\n")
        f.write("SUMMARY\n")
        f.write("=" * 80 + "\n")
        f.write(f"Safe Checks:      {counts['safe']}\n")
        f.write(f"Warnings:         {counts['warning']}\n")
        f.write(f"Critical Issues:  {counts['critical']}\n")
        f.write(f"Not Supported:    {counts['not_supported']}\n")
        f.write("=" * 80 + "\n")
        f.write(f"\nMade with love by IoTSRG Team\n")


# ============================================================================
# CLI ENTRY POINT
# ============================================================================
def main():
    ap = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - {TOOL_FULL}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --json-dir commands/
  %(prog)s --profile medical --json-dir commands/
  %(prog)s --serial DEVICE123 --json commands/boot_security.json
  %(prog)s --json-dir commands/ --ci --critical-threshold 0

Made with ❤️ by IoTSRG Team
        """
    )
    
    # Input options
    ap.add_argument("--json", action="append", default=[], 
                    help="Path to commands JSON (can be repeated)")
    ap.add_argument("--json-dir", 
                    help="Directory containing JSON check files")
    
    # Device options
    ap.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""), 
                    help="ADB device serial (or set ANDROID_SERIAL env var)")
    
    # Profile options
    ap.add_argument("--profile", choices=list(PROFILES.keys()),
                    help="Industry audit profile (medical, automotive, industrial, full)")
    
    # Output options
    ap.add_argument("--out", default="criscan_reports", 
                    help="Output directory (default: criscan_reports)")
    ap.add_argument("--format", nargs="+", choices=["html", "txt", "csv", "json"],
                    default=["html", "txt", "csv", "json"],
                    help="Output formats (default: all)")
    
    # CI/CD options
    ap.add_argument("--ci", action="store_true",
                    help="CI/CD mode - exit with code based on findings")
    ap.add_argument("--critical-threshold", type=int, default=0,
                    help="Max critical issues before CI failure (default: 0)")
    ap.add_argument("--warning-threshold", type=int, default=-1,
                    help="Max warnings before CI failure (default: unlimited)")
    
    # Display options
    ap.add_argument("--progress-numbers", action="store_true",
                    help="Print only progress numbers (X/Y)")
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="Minimal output")
    ap.add_argument("--version", "-v", action="version", 
                    version=f"{TOOL_NAME} {__version__}")
    
    args = ap.parse_args()

    # Check ADB
    if which("adb") is None:
        print("ERROR: 'adb' not found in PATH.", file=sys.stderr)
        print("Install via: apt install android-tools-adb", file=sys.stderr)
        sys.exit(1)

    # Start ADB server
    run(["adb", "start-server"])

    # Resolve device serial
    serial = (args.serial or "").strip() or None
    serial = pick_default_serial(serial)
    if not serial:
        explain_adb_devices_and_exit(exit_code=2)

    adb = ADB(serial)
    try:
        adb.check_connected()
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        explain_adb_devices_and_exit(exit_code=3)

    # Print banner
    if not args.quiet:
        print_banner(serial, args.profile)

    # Load checks
    all_checks: List[Dict[str, Any]] = []
    
    if args.json_dir:
        try:
            all_checks.extend(_load_checks_from_dir(args.json_dir))
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
    
    for p in args.json:
        try:
            all_checks.extend(_load_checks_from_file(p))
        except Exception as e:
            print(f"ERROR: Failed to load JSON '{p}': {e}", file=sys.stderr)
            sys.exit(1)

    if not all_checks:
        print("ERROR: No checks loaded. Provide --json or --json-dir.", file=sys.stderr)
        sys.exit(1)

    # Filter by profile if specified
    if args.profile:
        original_count = len(all_checks)
        all_checks = filter_checks_by_profile(all_checks, args.profile)
        if not args.quiet:
            print(f"[*] Profile '{args.profile}': {len(all_checks)}/{original_count} checks selected\n")

    # Progress callback
    def _progress(idx: int, total: int):
        if args.progress_numbers:
            sys.stdout.write(f"\r{idx}/{total}")
            sys.stdout.flush()
        elif not args.quiet:
            pct = int((idx / total) * 100)
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            sys.stdout.write(f"\r[{bar}] {pct}% ({idx}/{total})")
            sys.stdout.flush()

    # Prepare output directories
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(args.out, f"audit_{timestamp}")
    os.makedirs(report_dir, exist_ok=True)
    
    # Collect device info
    if not args.quiet:
        print("[*] Collecting device information...")
    device_info = collect_device_info(adb)
    
    # Run checks
    if not args.quiet:
        print(f"[*] Running {len(all_checks)} security checks...\n")
    
    rows, counts = run_checks(adb, all_checks, on_progress=_progress)
    
    if args.progress_numbers or not args.quiet:
        print()  # Newline after progress

    # Generate reports
    report_files = {}
    
    if "txt" in args.format:
        txt_file = os.path.join(report_dir, "audit_report.txt")
        write_txt(txt_file, device_info, rows, counts, args.profile)
        report_files["txt"] = txt_file
    
    if "csv" in args.format:
        csv_file = os.path.join(report_dir, "audit_report.csv")
        write_csv(csv_file, rows)
        report_files["csv"] = csv_file
    
    if "json" in args.format:
        json_file = os.path.join(report_dir, "audit_report.json")
        write_json(json_file, device_info, rows, counts, args.profile)
        report_files["json"] = json_file
    
    if "html" in args.format:
        html_file = os.path.join(report_dir, "audit_report.html")
        write_html(html_file, device_info, rows, counts, args.profile)
        report_files["html"] = html_file

    # Print summary
    print("\n" + "=" * 70)
    print(f"  {TOOL_NAME} AUDIT COMPLETED")
    print("=" * 70)
    print(f"  Device:           {device_info.get('model', 'Unknown')} ({serial})")
    print(f"  Android:          {device_info.get('android_version', 'Unknown')}")
    print(f"  Security Patch:   {device_info.get('security_patch', 'Unknown')}")
    print("-" * 70)
    print(f"  ✓ Safe Checks:    {counts['safe']}")
    print(f"  ⚠ Warnings:       {counts['warning']}")
    print(f"  ✗ Critical:       {counts['critical']}")
    print(f"  ○ Not Supported:  {counts['not_supported']}")
    print("-" * 70)
    
    evaluated = counts["safe"] + counts["warning"] + counts["critical"]
    pass_rate = round((counts["safe"] / evaluated) * 100, 1) if evaluated > 0 else 0
    print(f"  Pass Rate:        {pass_rate}%")
    print("-" * 70)
    print("  Reports Generated:")
    for fmt, path in report_files.items():
        print(f"    [{fmt.upper()}] {path}")
    print("=" * 70)
    print(f"  Made with ❤️ by IoTSRG Team")
    print("=" * 70 + "\n")

    # CI/CD exit code
    if args.ci:
        if counts["critical"] > args.critical_threshold:
            print(f"[CI] FAILED: {counts['critical']} critical issues (threshold: {args.critical_threshold})")
            sys.exit(2)
        if args.warning_threshold >= 0 and counts["warning"] > args.warning_threshold:
            print(f"[CI] FAILED: {counts['warning']} warnings (threshold: {args.warning_threshold})")
            sys.exit(1)
        print("[CI] PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()

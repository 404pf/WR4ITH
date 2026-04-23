#!/usr/bin/env python3
"""
WR4ITH - export.py
Lightweight txt export. No heavy deps (no reportlab/weasyprint).
"""

import os
from datetime import datetime


def export_txt(data: dict, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)

    h = data["history"]
    target_safe = h["target"].replace("://", "_").replace("/", "_").replace(".", "_")
    date_safe   = h["scan_date"].replace(" ", "_").replace(":", "-")[:16]
    filename    = f"{output_dir}/wr4ith_{target_safe}_{date_safe}.txt"

    lines = []
    lines.append("=" * 70)
    lines.append("  WR4ITH — Security Recon Report")
    lines.append("=" * 70)
    lines.append(f"  Target    : {h['target']}")
    lines.append(f"  Scan date : {h['scan_date']}")
    lines.append(f"  Risk level: {h.get('risk_level','UNKNOWN')}")
    lines.append(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    if data["vulnerabilities"]:
        lines.append("─" * 70)
        lines.append("  VULNERABILITIES")
        lines.append("─" * 70)
        for v in data["vulnerabilities"]:
            lines.append(f"\n  [{v['severity'].upper()}] {v['vuln_name']}")
            if v["port"]:        lines.append(f"  Port   : {v['port']} | Service: {v['service']}")
            if v["description"]: lines.append(f"  Detail : {v['description']}")
            fixes = [f for f in data["fixes"] if f["vuln_id"] == v["id"]]
            for fix in fixes:    lines.append(f"  Fix    : {fix['fix_text']}")

    if data["exploits"]:
        lines.append("\n" + "─" * 70)
        lines.append("  EXPLOITS")
        lines.append("─" * 70)
        for e in data["exploits"]:
            lines.append(f"\n  {e['exploit_name']}")
            lines.append(f"  Tool   : {e['tool_used']}")
            if e["payload"]: lines.append(f"  Payload: {e['payload']}")
            if e["notes"]:   lines.append(f"  Notes  : {e['notes']}")

    if h.get("full_response"):
        lines.append("\n" + "─" * 70)
        lines.append("  FULL AI ANALYSIS")
        lines.append("─" * 70)
        lines.append(h["full_response"])

    if h.get("raw_scan"):
        lines.append("\n" + "─" * 70)
        lines.append("  RAW SCAN DATA")
        lines.append("─" * 70)
        lines.append(h["raw_scan"][:5000])
        if len(h.get("raw_scan","")) > 5000:
            lines.append("[... truncated ...]")

    lines.append("\n" + "=" * 70)
    lines.append("  End of report — WR4ITH")
    lines.append("=" * 70)

    with open(filename, "w") as f:
        f.write("\n".join(lines))

    return filename


def export_menu(data: dict):
    print("\n  [1] Export as .txt")
    print("  [2] Cancel")
    choice = input("\n  Choice: ").strip()

    if choice == "1":
        path = export_txt(data)
        print(f"\n  [+] Saved to: {path}")
    else:
        print("  Cancelled.")

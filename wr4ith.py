#!/usr/bin/env python3
"""
WR4ITH - wr4ith.py
Main interactive shell. Forked from METATRON by sooryathejas (MIT).
Claude API brain, SQLite backend, web-focused recon.
"""

import os
import sys
from db import (
    init_db, create_session, save_vulnerability, save_fix, save_exploit,
    save_summary, get_all_history, get_session, get_vulnerabilities,
    get_fixes, get_exploits, edit_vulnerability, edit_fix, edit_exploit,
    edit_summary_risk, delete_vulnerability, delete_exploit, delete_fix,
    delete_full_session, print_history, print_session
)
from tools import interactive_tool_run, format_recon_for_llm
from webtools import run_web_recon
from llm import analyse_target, get_api_key
from export import export_menu
from ai_mode import run_ai_mode
from poc_tester import run_poc_tester


# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────

def banner():
    os.system("clear")
    print("""
\033[91m
 ██╗    ██╗██████╗ ██╗  ██╗██╗████████╗██╗  ██╗
 ██║    ██║██╔══██╗██║  ██║██║╚══██╔══╝██║  ██║
 ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
 ██║███╗██║██╔══██╗╚════██║██║   ██║   ╚════██║
 ╚███╔███╔╝██║  ██║     ██║██║   ██║        ██║
  ╚══╝╚══╝ ╚═╝  ╚═╝     ╚═╝╚═╝   ╚═╝        ╚═╝
\033[0m
\033[90m  AI Recon Assistant  |  Claude API  |  Web-focused  |  Lubuntu\033[0m
\033[90m  ─────────────────────────────────────────────────────────────\033[0m
""")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def divider(label=""):
    if label:
        print(f"\n\033[33m{'─'*20} {label} {'─'*20}\033[0m")
    else:
        print(f"\033[90m{'─'*60}\033[0m")


def prompt(text):
    return input(f"\033[36m{text}\033[0m").strip()


def success(text): print(f"\033[92m[+] {text}\033[0m")
def warn(text):    print(f"\033[93m[!] {text}\033[0m")
def error(text):   print(f"\033[91m[✗] {text}\033[0m")
def info(text):    print(f"\033[94m[*] {text}\033[0m")


def confirm(question: str) -> bool:
    return prompt(f"{question} [y/N]: ").lower() == "y"


# ─────────────────────────────────────────────
# API KEY SETUP
# ─────────────────────────────────────────────

def check_api_key():
    key = get_api_key()
    if key:
        return True

    warn("No Anthropic API key found.")
    print("  Options:")
    print("  [1] Set ANTHROPIC_API_KEY environment variable")
    print("  [2] Save key to ~/.wr4ith_key (persists across sessions)")
    print("  [3] Enter for this session only")
    print("  [4] Exit")

    choice = prompt("Choice: ")

    if choice == "2":
        key = prompt("Paste API key: ")
        keyfile = os.path.expanduser("~/.wr4ith_key")
        with open(keyfile, "w") as f:
            f.write(key.strip())
        os.chmod(keyfile, 0o600)
        success(f"Key saved to {keyfile}")
        return True

    elif choice == "3":
        key = prompt("Paste API key: ")
        os.environ["ANTHROPIC_API_KEY"] = key.strip()
        success("Key set for this session.")
        return True

    elif choice == "4":
        sys.exit(0)

    else:
        print("  Set ANTHROPIC_API_KEY and rerun.")
        return False


# ─────────────────────────────────────────────
# NEW SCAN
# ─────────────────────────────────────────────

def new_scan():
    divider("NEW SCAN")
    target = prompt("[?] Target (IP or domain): ")
    if not target:
        warn("No target entered.")
        return

    # passive mode?
    print()
    print("  [1] Active scan  — all recon tools + path probing")
    print("  [2] Passive scan — headers, JS, DNS only (quieter)")
    mode_choice = prompt("Mode: ")
    passive = (mode_choice == "2")

    # check if scanned before
    history = get_all_history()
    past = [r for r in history if r["target"] == target]
    if past:
        warn(f"'{target}' scanned before ({len(past)} time(s)).")
        if not confirm("Continue with a new scan?"):
            return

    sl_no = create_session(target)
    success(f"Session created — #{sl_no}")

    # ── network recon ──────────────────────────
    if not passive:
        divider("NETWORK RECON")
        info("Select network tools to run:")
        network_data = interactive_tool_run(target)
    else:
        network_data = ""
        info("Passive mode — skipping network tools.")

    # ── web recon ─────────────────────────────
    divider("WEB RECON")
    info("Running web-focused checks...")
    web_data = run_web_recon(target, passive=passive)

    raw_scan = ""
    if network_data.strip():
        raw_scan += "[ NETWORK RECON ]\n" + network_data + "\n\n"
    raw_scan += "[ WEB RECON ]\n" + web_data

    if not raw_scan.strip():
        warn("No scan data collected. Aborting.")
        delete_full_session(sl_no)
        return

    # ── Claude analysis ────────────────────────
    divider("AI ANALYSIS")
    result = analyse_target(target, raw_scan)

    # ── save to DB ────────────────────────────
    divider("SAVING")

    for vuln in result["vulnerabilities"]:
        vid = save_vulnerability(sl_no, vuln["vuln_name"], vuln["severity"],
                                 vuln["port"], vuln["service"], vuln["description"])
        if vuln.get("fix"):
            save_fix(sl_no, vid, vuln["fix"], source="ai")
        success(f"Saved: {vuln['vuln_name']} [{vuln['severity']}]")

    for exp in result["exploits"]:
        save_exploit(sl_no, exp["exploit_name"], exp["tool_used"],
                     exp["payload"], exp["result"], exp["notes"])
        success(f"Saved exploit: {exp['exploit_name']}")

    save_summary(sl_no, result["raw_scan"], result["full_response"], result["risk_level"])
    success(f"Done. Session #{sl_no} | Risk: {result['risk_level']}")
    divider()

    data = get_session(sl_no)
    print_session(data)

    if confirm("Export this report?"):
        export_menu(data)

    if confirm("Run exploitability test on this session?"):
        run_poc_tester(preloaded_sl_no=sl_no)
        return

    if confirm("Edit or delete anything?"):
        edit_delete_menu(sl_no)


# ─────────────────────────────────────────────
# VIEW HISTORY
# ─────────────────────────────────────────────

def view_history():
    divider("SCAN HISTORY")
    rows = get_all_history()

    if not rows:
        warn("No scans yet.")
        return

    print_history(rows)

    sl_str = prompt("Enter # to view (or Enter to go back): ")
    if not sl_str:
        return

    try:
        sl_no = int(sl_str)
    except ValueError:
        error("Invalid number.")
        return

    data = get_session(sl_no)
    if not data["history"]:
        error(f"Session #{sl_no} not found.")
        return

    print_session(data)

    if confirm("Export this report?"):
        export_menu(data)

    if confirm("Run exploitability test on this session?"):
        run_poc_tester(preloaded_sl_no=sl_no)
        return

    if confirm("Edit or delete anything?"):
        edit_delete_menu(sl_no)


# ─────────────────────────────────────────────
# EDIT / DELETE MENU
# ─────────────────────────────────────────────

def edit_delete_menu(sl_no: int):
    while True:
        divider(f"EDIT/DELETE — Session #{sl_no}")
        print("  [1] Edit vulnerability")
        print("  [2] Edit fix")
        print("  [3] Edit exploit")
        print("  [4] Edit risk level")
        print("  [5] Delete vulnerability")
        print("  [6] Delete fix")
        print("  [7] Delete exploit")
        print("  [8] Delete FULL session")
        print("  [9] Back")
        divider()

        choice = prompt("Choice: ")

        if choice == "1":
            vulns = get_vulnerabilities(sl_no)
            if not vulns: warn("No vulnerabilities."); continue
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]} | port {v[4]}")
            vid = prompt("Vuln id: ")
            if not vid.isdigit(): error("Invalid."); continue
            print("  Fields: vuln_name / severity / port / service / description")
            field = prompt("Field: ")
            value = prompt(f"New value: ")
            edit_vulnerability(int(vid), field, value)

        elif choice == "2":
            fixes = get_fixes(sl_no)
            if not fixes: warn("No fixes."); continue
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")
            fid = prompt("Fix id: ")
            if not fid.isdigit(): error("Invalid."); continue
            new_text = prompt("New fix text: ")
            edit_fix(int(fid), new_text)

        elif choice == "3":
            exploits = get_exploits(sl_no)
            if not exploits: warn("No exploits."); continue
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | tool: {e[3]}")
            eid = prompt("Exploit id: ")
            if not eid.isdigit(): error("Invalid."); continue
            print("  Fields: exploit_name / tool_used / payload / result / notes")
            field = prompt("Field: ")
            value = prompt(f"New value: ")
            edit_exploit(int(eid), field, value)

        elif choice == "4":
            print("  Options: CRITICAL / HIGH / MEDIUM / LOW")
            risk = prompt("New risk level: ").upper()
            if risk not in ("CRITICAL","HIGH","MEDIUM","LOW"):
                error("Invalid."); continue
            edit_summary_risk(sl_no, risk)

        elif choice == "5":
            vulns = get_vulnerabilities(sl_no)
            if not vulns: warn("No vulnerabilities."); continue
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]}")
            vid = prompt("Vuln id to delete: ")
            if not vid.isdigit(): error("Invalid."); continue
            if confirm(f"Delete vuln #{vid} and its fixes?"):
                delete_vulnerability(int(vid))

        elif choice == "6":
            fixes = get_fixes(sl_no)
            if not fixes: warn("No fixes."); continue
            for f in fixes:
                print(f"  id={f[0]} | {f[3][:80]}")
            fid = prompt("Fix id to delete: ")
            if not fid.isdigit(): error("Invalid."); continue
            if confirm(f"Delete fix #{fid}?"):
                delete_fix(int(fid))

        elif choice == "7":
            exploits = get_exploits(sl_no)
            if not exploits: warn("No exploits."); continue
            for e in exploits:
                print(f"  id={e[0]} | {e[2]}")
            eid = prompt("Exploit id to delete: ")
            if not eid.isdigit(): error("Invalid."); continue
            if confirm(f"Delete exploit #{eid}?"):
                delete_exploit(int(eid))

        elif choice == "8":
            if confirm(f"\n\033[91mPermanently delete ENTIRE session #{sl_no}?\033[0m"):
                delete_full_session(sl_no)
                success(f"Session #{sl_no} wiped.")
                return

        elif choice == "9":
            break

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────

def recon_menu():
    """Module 1 — Recon & PoC Discovery sub-menu."""
    while True:
        banner()
        print("  \033[91m── MODULE 1 — RECON & POC DISCOVERY ──\033[0m")
        print()
        print("  \033[92m[1]\033[0m  New Scan")
        print("  \033[92m[2]\033[0m  View History")
        print("  \033[92m[3]\033[0m  AI Mode")
        print("  \033[92m[4]\033[0m  Back")
        divider()

        choice = prompt("wr4ith> ")

        if choice == "1":
            new_scan()
            input("\n\033[90mPress Enter to continue...\033[0m")
        elif choice == "2":
            view_history()
            input("\n\033[90mPress Enter to continue...\033[0m")
        elif choice == "3":
            run_ai_mode()
            input("\n\033[90mPress Enter to continue...\033[0m")
        elif choice == "4":
            return
        else:
            warn("Invalid choice.")


def main_menu():
    while True:
        banner()
        print("  \033[91m  WR4ITH Security Suite\033[0m")
        print()
        print("  \033[92m[1]\033[0m  Recon & PoC Discovery")
        print("  \033[92m[2]\033[0m  PoC Exploitability Test")
        print("  \033[92m[3]\033[0m  Exit")
        divider()

        choice = prompt("wr4ith> ")

        if choice == "1":
            recon_menu()
        elif choice == "2":
            run_poc_tester()
            input("\n\033[90mPress Enter to continue...\033[0m")
        elif choice == "3":
            print("\n\033[91m[*] Shutting down WR4ITH. Stay legal.\033[0m\n")
            sys.exit(0)
        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    if not check_api_key():
        sys.exit(1)
    main_menu()

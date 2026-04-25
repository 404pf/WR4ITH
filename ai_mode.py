#!/usr/bin/env python3
"""
WR4ITH - ai_mode.py
AI Mode — Claude reads SKILLS.md then supervises a full recon session.
WR4ITH runs the tools. Claude thinks.
"""

import os
import json
import requests
from webtools import run_web_recon
from tools import run_tool_by_command, run_default_recon, format_recon_for_llm
from search import handle_search_dispatch
from db import (
    create_session, save_vulnerability, save_fix,
    save_exploit, save_summary, get_session, print_session
)
from export import export_menu

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL             = "claude-sonnet-4-20250514"
MAX_TOKENS        = 8096
MAX_LOOPS         = 8
SKILLS_PATH       = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SKILLS.md")
DISCLAIMER_PATH   = os.path.join(os.path.expanduser("~"), ".wr4ith_disclaimer")


# ─────────────────────────────────────────────
# DISCLAIMER — one time ever
# ─────────────────────────────────────────────

def check_disclaimer() -> bool:
    """Returns True if user has accepted. Shows prompt if not."""
    if os.path.exists(DISCLAIMER_PATH):
        return True

    os.system("clear")
    print("""
\033[91m╔══════════════════════════════════════════════════════════════╗
║                   ⚠  LEGAL NOTICE  ⚠                        ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  WR4ITH is a security recon tool for AUTHORIZED USE ONLY.   ║
║                                                              ║
║  By proceeding you confirm that:                             ║
║                                                              ║
║  • You own the target system, OR                             ║
║  • You have explicit written permission to test it, OR       ║
║  • The target is in scope for an active bug bounty program   ║
║    that explicitly permits automated scanning.               ║
║                                                              ║
║  Unauthorized scanning is ILLEGAL in most jurisdictions.     ║
║  The author is NOT responsible for misuse of this tool.      ║
║                                                              ║
║  WR4ITH is NOT an exploitation toolkit.                      ║
║  It performs passive recon and produces PoC reports only.    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝\033[0m
""")
    print("  [1] I understand and accept — I have authorization to test my target")
    print("  [2] Exit")
    print()

    choice = input("\033[36m  Choice: \033[0m").strip()

    if choice == "1":
        # save acceptance
        with open(DISCLAIMER_PATH, "w") as f:
            f.write("accepted")
        print("\n\033[92m  [+] Accepted. Loading WR4ITH AI Mode...\033[0m\n")
        return True
    else:
        print("\n\033[91m  [*] Exiting. Stay legal.\033[0m\n")
        return False


# ─────────────────────────────────────────────
# SKILLS FILE LOADER
# ─────────────────────────────────────────────

def load_skills() -> str:
    if not os.path.exists(SKILLS_PATH):
        print(f"  \033[91m[!] SKILLS.md not found at {SKILLS_PATH}\033[0m")
        print("  AI Mode requires SKILLS.md to operate.")
        return ""
    with open(SKILLS_PATH, "r") as f:
        return f.read()


# ─────────────────────────────────────────────
# API KEY
# ─────────────────────────────────────────────

def get_api_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key:
        keyfile = os.path.expanduser("~/.wr4ith_key")
        if os.path.exists(keyfile):
            with open(keyfile) as f:
                key = f.read().strip()
    return key


# ─────────────────────────────────────────────
# CLAUDE API
# ─────────────────────────────────────────────

def ask_claude(messages: list, system: str) -> str:
    key = get_api_key()
    if not key or len(key) < 20:
        return "[!] No valid API key found."

    headers = {
        "x-api-key":         key,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }
    payload = {
        "model":      MODEL,
        "max_tokens": MAX_TOKENS,
        "system":     system,
        "messages":   messages,
    }

    try:
        resp = requests.post(ANTHROPIC_API_URL, headers=headers,
                             json=payload, timeout=180)
        resp.raise_for_status()
        data = resp.json()
        content = data.get("content", [])
        text = "".join(b.get("text","") for b in content if b.get("type") == "text")
        return text.strip() if text else "[!] Empty response from Claude."
    except requests.exceptions.HTTPError as e:
        if resp.status_code == 401: return "[!] Invalid API key."
        if resp.status_code == 429: return "[!] Rate limited. Wait and retry."
        return f"[!] HTTP {resp.status_code}: {e}"
    except requests.exceptions.Timeout:
        return "[!] Claude API timed out."
    except Exception as e:
        return f"[!] Error: {e}"


# ─────────────────────────────────────────────
# TOOL DISPATCH
# ─────────────────────────────────────────────

import re

def extract_tool_calls(response: str) -> list:
    calls = []
    for m in re.findall(r'\[TOOL:\s*(.+?)\]', response):
        calls.append(("TOOL", m.strip()))
    for m in re.findall(r'\[SEARCH:\s*(.+?)\]', response):
        calls.append(("SEARCH", m.strip()))
    for m in re.findall(r'\[WEBRECON:\s*(.+?)\]', response):
        calls.append(("WEBRECON", m.strip()))
    return calls


def dispatch_tool(call_type: str, call_content: str, target: str) -> str:
    print(f"\n  \033[33m[DISPATCH]\033[0m {call_type}: {call_content}")

    if call_type == "TOOL":
        return run_tool_by_command(call_content)

    elif call_type == "SEARCH":
        return handle_search_dispatch(call_content)

    elif call_type == "WEBRECON":
        mode = call_content.strip().lower()
        passive = (mode == "passive")
        return run_web_recon(target, passive=passive)

    return f"[!] Unknown tool type: {call_type}"


def run_all_dispatches(response: str, target: str) -> str:
    calls = extract_tool_calls(response)
    if not calls:
        return ""

    results = ""
    for call_type, call_content in calls:
        output = dispatch_tool(call_type, call_content, target)
        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "─" * 40 + "\n"
        results += output.strip() + "\n"
    return results


# ─────────────────────────────────────────────
# RESPONSE PARSERS
# ─────────────────────────────────────────────

def clean(line: str) -> str:
    return re.sub(r'\*+', '', line).strip()


def parse_vulnerabilities(response: str) -> list:
    vulns = []
    lines = response.splitlines()
    i = 0
    while i < len(lines):
        line = clean(lines[i])
        if line.startswith("VULN:"):
            vuln = {
                "vuln_name": "", "severity": "medium",
                "port": "", "service": "",
                "description": "", "poc": "", "fix": ""
            }
            for part in line.split("|"):
                part = part.strip()
                if part.startswith("VULN:"):       vuln["vuln_name"] = part[5:].strip()
                elif part.startswith("SEVERITY:"): vuln["severity"]  = part[9:].strip().lower()
                elif part.startswith("CONFIDENCE:"): pass  # store in description
                elif part.startswith("PORT:"):     vuln["port"]      = part[5:].strip()
                elif part.startswith("SERVICE:"):  vuln["service"]   = part[8:].strip()
            j = i + 1
            while j < len(lines) and j <= i + 8:
                nl = clean(lines[j])
                if nl.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if nl.startswith("DESC:"): vuln["description"] = nl[5:].strip()
                elif nl.startswith("POC:"): vuln["poc"] = nl[4:].strip()
                elif nl.startswith("FIX:"): vuln["fix"] = nl[4:].strip()
                j += 1
            # combine desc + poc into description for DB
            full_desc = vuln["description"]
            if vuln["poc"]:
                full_desc += f"\nPoC: {vuln['poc']}"
            vuln["description"] = full_desc
            if vuln["vuln_name"]:
                vulns.append(vuln)
        i += 1
    return vulns


def parse_exploits(response: str) -> list:
    exploits = []
    lines = response.splitlines()
    i = 0
    while i < len(lines):
        line = clean(lines[i])
        if line.startswith("EXPLOIT:"):
            exp = {
                "exploit_name": "", "tool_used": "",
                "payload": "", "result": "unknown", "notes": ""
            }
            for part in line.split("|"):
                part = part.strip()
                if part.startswith("EXPLOIT:"):  exp["exploit_name"] = part[8:].strip()
                elif part.startswith("TOOL:"):   exp["tool_used"]    = part[5:].strip()
                elif part.startswith("PAYLOAD:"): exp["payload"]     = part[8:].strip()
            j = i + 1
            while j < len(lines) and j <= i + 4:
                nl = clean(lines[j])
                if nl.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if nl.startswith("RESULT:"): exp["result"] = nl[7:].strip()
                elif nl.startswith("NOTES:"): exp["notes"] = nl[6:].strip()
                j += 1
            if exp["exploit_name"]:
                exploits.append(exp)
        i += 1
    return exploits


def parse_risk(response: str) -> str:
    m = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.I)
    return m.group(1).upper() if m else "UNKNOWN"


def parse_summary(response: str) -> str:
    m = re.search(r'SUMMARY:\s*(.+)', response, re.I)
    return m.group(1).strip() if m else ""


# ─────────────────────────────────────────────
# PRINT HELPERS
# ─────────────────────────────────────────────

def divider(label=""):
    if label:
        print(f"\n\033[33m{'─'*20} {label} {'─'*20}\033[0m")
    else:
        print(f"\033[90m{'─'*60}\033[0m")


def info(t):    print(f"\033[94m[*] {t}\033[0m")
def success(t): print(f"\033[92m[+] {t}\033[0m")
def warn(t):    print(f"\033[93m[!] {t}\033[0m")
def error(t):   print(f"\033[91m[✗] {t}\033[0m")


# ─────────────────────────────────────────────
# MAIN AI MODE SESSION
# ─────────────────────────────────────────────

def run_ai_mode():
    """Entry point called from wr4ith.py"""

    # disclaimer check
    if not check_disclaimer():
        return

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
\033[91m  ── AI MODE ──\033[0m  \033[90mClaude reads SKILLS.md · supervises recon · writes report\033[0m
""")

    # load skills
    info("Loading SKILLS.md...")
    skills = load_skills()
    if not skills:
        return
    success(f"Skills loaded ({len(skills)} chars)")

    # build system prompt — skills file IS the system prompt
    system_prompt = f"""You are WR4ITH AI Mode. You have just read your skills file.

{skills}

---
TOOL SYNTAX (use these exactly when you need WR4ITH to run something):
  [WEBRECON: passive]    — run passive web recon (headers, JS, robots, fingerprint)
  [WEBRECON: active]     — run full web recon including path probing
  [TOOL: nmap -sV target] — run a specific network tool
  [TOOL: dig A target]   — DNS lookup
  [SEARCH: CVE-2021-xxxxx] — search for CVE or vulnerability info

You decide what to run and when. WR4ITH executes. You analyze.
Follow the recon decision tree from Section 3 of your skills file.
Output your final report in the exact format from Section 6."""

    # get target
    print()
    target = input("\033[36m[?] Target (IP or domain): \033[0m").strip()
    if not target:
        warn("No target entered.")
        return

    # create DB session
    sl_no = create_session(target)
    success(f"Session #{sl_no} created")

    # initial message — Claude decides first move
    messages = [
        {
            "role": "user",
            "content": f"""TARGET: {target}

You have read your skills file. Begin your analysis.
Follow your recon decision tree. Start with what you think is most appropriate.
Use [WEBRECON:], [TOOL:], or [SEARCH:] tags to request recon data.
I will run each tool and return the results to you."""
        }
    ]

    final_response = ""
    all_raw_data = ""

    print()
    divider("AI MODE — LIVE SESSION")

    for loop in range(MAX_LOOPS):
        print(f"\n\033[33m[Round {loop + 1}/{MAX_LOOPS}]\033[0m Asking Claude...")

        response = ask_claude(messages, system_prompt)

        if response.startswith("[!]"):
            error(response)
            break

        print(f"\n\033[90m{'─'*60}\033[0m")
        print(response)
        print(f"\033[90m{'─'*60}\033[0m")

        final_response = response

        # check for tool calls
        tool_calls = extract_tool_calls(response)

        if not tool_calls:
            info("No tool calls — analysis complete.")
            break

        # run all dispatched tools
        tool_results = run_all_dispatches(response, target)
        all_raw_data += tool_results

        # feed results back to Claude
        messages.append({"role": "assistant", "content": response})
        messages.append({
            "role": "user",
            "content": f"""[TOOL RESULTS]
{tool_results}

Continue your analysis. Use more tools if needed.
When you have enough data, produce your final report in the Section 6 format."""
        })

    # ── parse and save ────────────────────────
    divider("SAVING RESULTS")

    vulns    = parse_vulnerabilities(final_response)
    exploits = parse_exploits(final_response)
    risk     = parse_risk(final_response)
    summary  = parse_summary(final_response)

    for vuln in vulns:
        vid = save_vulnerability(
            sl_no, vuln["vuln_name"], vuln["severity"],
            vuln["port"], vuln["service"], vuln["description"]
        )
        if vuln.get("fix"):
            save_fix(sl_no, vid, vuln["fix"], source="ai_mode")
        success(f"Saved: {vuln['vuln_name']} [{vuln['severity']}]")

    for exp in exploits:
        save_exploit(sl_no, exp["exploit_name"], exp["tool_used"],
                     exp["payload"], exp["result"], exp["notes"])
        success(f"Saved exploit: {exp['exploit_name']}")

    save_summary(sl_no, all_raw_data, final_response, risk)
    success(f"Session #{sl_no} complete | Risk: {risk}")
    if summary:
        print(f"\n  \033[90m{summary}\033[0m")

    # ── print session ─────────────────────────
    divider()
    data = get_session(sl_no)
    print_session(data)

    if input("\n\033[36mExport report? [y/N]: \033[0m").strip().lower() == "y":
        export_menu(data)

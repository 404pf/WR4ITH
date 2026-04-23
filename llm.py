#!/usr/bin/env python3
"""
WR4ITH - llm.py
Claude API brain. Replaces Ollama/metatron-qwen from METATRON.
Keeps the agentic tool loop — Claude can request more tool runs mid-analysis.
"""

import re
import os
import json
import requests
from tools import run_tool_by_command
from search import handle_search_dispatch

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL             = "claude-sonnet-4-20250514"
MAX_TOKENS        = 4096
MAX_TOOL_LOOPS    = 6


# ─────────────────────────────────────────────
# API KEY
# ─────────────────────────────────────────────

def get_api_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key:
        # fallback: check ~/.wr4ith_key
        keyfile = os.path.expanduser("~/.wr4ith_key")
        if os.path.exists(keyfile):
            with open(keyfile) as f:
                key = f.read().strip()
    return key


# ─────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are WR4ITH, an elite AI security recon assistant.
You are precise, technical, and direct. No fluff. No markdown bold or headers.

You specialize in web security recon: headers, endpoints, JS analysis, exposed paths, misconfigurations.

You have access to real tools. To use them write tags in your response:
  [TOOL: nmap -sV 192.168.1.1]
  [SEARCH: CVE-2021-44228 apache exploit]

Rules:
- Analyze all provided recon data thoroughly
- List vulnerabilities with: name, severity (critical/high/medium/low), port, service
- For each vulnerability give a concrete fix
- Use [SEARCH:] for CVE lookups or exploit research
- Use [TOOL:] only when genuinely needed for more data
- Format vulnerabilities exactly as shown below
- Assign final risk rating based on actual evidence only

Output format for vulnerabilities:
VULN: <name> | SEVERITY: <level> | PORT: <port> | SERVICE: <service>
DESC: <description>
FIX: <fix recommendation>

Output format for exploits:
EXPLOIT: <name> | TOOL: <tool> | PAYLOAD: <payload>
RESULT: <expected result>
NOTES: <notes>

End with:
RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>
SUMMARY: <2-3 sentence overall summary>

Accuracy rules:
- Only assert versions you see in the scan data
- Never infer CVEs from guessed versions
- filtered/no-response = INCONCLUSIVE not vulnerable
- Only CRITICAL if direct evidence of exploitability exists
- Missing security headers = MEDIUM unless chained with other issues
- Plain text only. No markdown. No exceptions."""


# ─────────────────────────────────────────────
# CLAUDE API CALL
# ─────────────────────────────────────────────

def ask_claude(messages: list) -> str:
    key = get_api_key()
    if not key:
        return "[!] No API key found. Set ANTHROPIC_API_KEY env var or save to ~/.wr4ith_key"

    headers = {
        "x-api-key":         key,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }

    payload = {
        "model":      MODEL,
        "max_tokens": MAX_TOKENS,
        "system":     SYSTEM_PROMPT,
        "messages":   messages,
    }

    try:
        print(f"\n  [*] Sending to Claude ({MODEL})...")
        resp = requests.post(ANTHROPIC_API_URL, headers=headers,
                             json=payload, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        content = data.get("content", [])
        text = "".join(b.get("text","") for b in content if b.get("type") == "text")
        return text.strip() if text else "[!] Claude returned empty response."

    except requests.exceptions.HTTPError as e:
        if resp.status_code == 401:
            return "[!] Invalid API key. Check ANTHROPIC_API_KEY."
        if resp.status_code == 429:
            return "[!] Rate limited. Wait a moment and retry."
        return f"[!] HTTP error {resp.status_code}: {e}"
    except requests.exceptions.Timeout:
        return "[!] Claude API timed out."
    except Exception as e:
        return f"[!] Unexpected error: {e}"


# ─────────────────────────────────────────────
# TOOL DISPATCH (kept from METATRON)
# ─────────────────────────────────────────────

def extract_tool_calls(response: str) -> list:
    calls = []
    for m in re.findall(r'\[TOOL:\s*(.+?)\]', response):
        calls.append(("TOOL", m.strip()))
    for m in re.findall(r'\[SEARCH:\s*(.+?)\]', response):
        calls.append(("SEARCH", m.strip()))
    return calls


def run_tool_calls(calls: list) -> str:
    if not calls:
        return ""
    results = ""
    for call_type, call_content in calls:
        print(f"\n  [DISPATCH] {call_type}: {call_content}")
        if call_type == "TOOL":
            output = run_tool_by_command(call_content)
        elif call_type == "SEARCH":
            output = handle_search_dispatch(call_content)
        else:
            output = f"[!] Unknown type: {call_type}"

        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "─" * 40 + "\n"
        results += output.strip() + "\n"
    return results


# ─────────────────────────────────────────────
# RESPONSE PARSERS (kept from METATRON)
# ─────────────────────────────────────────────

def _clean(line: str) -> str:
    return re.sub(r'\*+', '', line).strip()


def parse_vulnerabilities(response: str) -> list:
    vulns = []
    lines = response.splitlines()
    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("VULN:"):
            vuln = {"vuln_name":"","severity":"medium","port":"","service":"","description":"","fix":""}
            for part in line.split("|"):
                part = part.strip()
                if part.startswith("VULN:"):     vuln["vuln_name"] = part[5:].strip()
                elif part.startswith("SEVERITY:"): vuln["severity"] = part[9:].strip().lower()
                elif part.startswith("PORT:"):    vuln["port"] = part[5:].strip()
                elif part.startswith("SERVICE:"): vuln["service"] = part[8:].strip()
            j = i + 1
            while j < len(lines) and j <= i + 5:
                nl = _clean(lines[j])
                if nl.startswith(("VULN:","EXPLOIT:","RISK_LEVEL:","SUMMARY:")): break
                if nl.startswith("DESC:"): vuln["description"] = nl[5:].strip()
                elif nl.startswith("FIX:"): vuln["fix"] = nl[4:].strip()
                j += 1
            if vuln["vuln_name"]:
                vulns.append(vuln)
        i += 1
    return vulns


def parse_exploits(response: str) -> list:
    exploits = []
    lines = response.splitlines()
    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("EXPLOIT:"):
            exp = {"exploit_name":"","tool_used":"","payload":"","result":"unknown","notes":""}
            for part in line.split("|"):
                part = part.strip()
                if part.startswith("EXPLOIT:"): exp["exploit_name"] = part[8:].strip()
                elif part.startswith("TOOL:"):   exp["tool_used"] = part[5:].strip()
                elif part.startswith("PAYLOAD:"): exp["payload"] = part[8:].strip()
            j = i + 1
            while j < len(lines) and j <= i + 4:
                nl = _clean(lines[j])
                if nl.startswith(("VULN:","EXPLOIT:","RISK_LEVEL:","SUMMARY:")): break
                if nl.startswith("RESULT:"): exp["result"] = nl[7:].strip()
                elif nl.startswith("NOTES:"): exp["notes"] = nl[6:].strip()
                j += 1
            if exp["exploit_name"]:
                exploits.append(exp)
        i += 1
    return exploits


def parse_risk_level(response: str) -> str:
    m = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.I)
    return m.group(1).upper() if m else "UNKNOWN"


def parse_summary(response: str) -> str:
    m = re.search(r'SUMMARY:\s*(.+)', response, re.I)
    return m.group(1).strip() if m else ""


# ─────────────────────────────────────────────
# MAIN ANALYSIS — agentic loop
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str) -> dict:
    messages = [
        {
            "role": "user",
            "content": f"""TARGET: {target}

RECON DATA:
{raw_scan}

Analyze this target completely. Use [TOOL:] or [SEARCH:] if you need more data.
List all vulnerabilities, fixes, and suggest exploits where applicable."""
        }
    ]

    final_response = ""

    for loop in range(MAX_TOOL_LOOPS):
        response = ask_claude(messages)

        print(f"\n\033[33m{'─'*60}\033[0m")
        print(f"\033[33m[WR4ITH — Round {loop + 1}]\033[0m")
        print(f"\033[33m{'─'*60}\033[0m")
        print(response)

        final_response = response

        tool_calls = extract_tool_calls(response)
        if not tool_calls:
            print("\n  [*] No tool calls. Analysis complete.")
            break

        tool_results = run_tool_calls(tool_calls)

        messages.append({"role": "assistant", "content": response})
        messages.append({
            "role": "user",
            "content": f"""[TOOL RESULTS]
{tool_results}

Continue your analysis with this new information.
If analysis is complete, give the final RISK_LEVEL and SUMMARY."""
        })

    vulns      = parse_vulnerabilities(final_response)
    exploits   = parse_exploits(final_response)
    risk_level = parse_risk_level(final_response)
    summary    = parse_summary(final_response)

    print(f"\n  [+] Parsed: {len(vulns)} vulns, {len(exploits)} exploits | Risk: {risk_level}")

    return {
        "full_response":   final_response,
        "vulnerabilities": vulns,
        "exploits":        exploits,
        "risk_level":      risk_level,
        "summary":         summary,
        "raw_scan":        raw_scan,
    }

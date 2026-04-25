#!/usr/bin/env python3
"""
WR4ITH - poc_tester.py
Module 2 — PoC Exploitability Test.

Reads recorded scan sessions from the DB.
Claude designs a safe single-request confirmation test per finding.
WR4ITH fires it. Reports CONFIRMED / UNCONFIRMED / INCONCLUSIVE.
Nothing is extracted, modified, uploaded, or persisted on target.
"""

import os
import re
import time
import requests
from db import (
    get_all_history, get_session, get_vulnerabilities,
    save_poc_result, get_poc_results, get_poc_result_for_vuln,
    print_history, print_session
)
from export import export_menu

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL             = "claude-sonnet-4-20250514"
MAX_TOKENS        = 4096

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
}

STATUS_COLORS = {
    "CONFIRMED":    "\033[91m",   # red — it's real
    "UNCONFIRMED":  "\033[92m",   # green — not found
    "INCONCLUSIVE": "\033[93m",   # yellow — can't tell
    "UNTESTED":     "\033[90m",   # grey
    "SKIPPED":      "\033[90m",   # grey
}


# ─────────────────────────────────────────────
# API KEY
# ─────────────────────────────────────────────

def _load_dotenv():
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and val:
                os.environ.setdefault(key, val)


def get_api_key() -> str:
    _load_dotenv()
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key:
        keyfile = os.path.expanduser("~/.wr4ith_key")
        if os.path.exists(keyfile):
            with open(keyfile) as f:
                key = f.read().strip()
    return key


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


def status_colored(status: str) -> str:
    color = STATUS_COLORS.get(status, "\033[0m")
    return f"{color}{status}\033[0m"


# ─────────────────────────────────────────────
# CLAUDE — PoC TEST DESIGNER
# ─────────────────────────────────────────────

POC_SYSTEM_PROMPT = """You are WR4ITH's PoC Test Engine.

Your job is to design SAFE, single-request confirmation tests for recorded vulnerabilities.

Rules you must follow:
- Design ONE HTTP request that confirms or denies exploitability
- The request must be READ-ONLY — no writes, no uploads, no modifications
- The request must be SAFE — it reveals whether the vuln exists, nothing more
- You confirm existence, not exploit it
- If a vuln cannot be safely confirmed with a single passive request, mark it SKIP

Output format — one block per vulnerability, exactly:

VULN_ID: <id>
TESTABLE: YES | NO
SKIP_REASON: <reason if NO>
METHOD: GET | POST | HEAD | OPTIONS
URL: <full url to request>
HEADERS: <key: value pairs, one per line, or NONE>
BODY: <request body or NONE>
CONFIRM_IF: <what to look for in the response that confirms the vuln>
DENY_IF: <what in the response means it's not present>

Safe test examples by vuln type:
- Missing security header: HEAD request, check response headers
- CORS misconfiguration: GET with Origin header, check Access-Control-Allow-Origin
- Exposed file (/.env, /.git): GET request, check status code and content
- Open redirect: HEAD request with redirect param, check Location header (do NOT follow)
- XSS reflection: GET with innocuous marker like ?q=WR4ITH_TEST, check if reflected
- GraphQL introspection: POST with __schema query, check response for type names
- Subdomain takeover indicator: GET request, check for known unclaimed service response
- HSTS missing: GET request, check Strict-Transport-Security header absence
- robots.txt disclosure: GET /robots.txt, check Disallow entries

DO NOT design tests for:
- SQL injection (requires active probing)
- Authentication bypass (requires credentials)
- RCE (never)
- File upload (never)
- Anything requiring multiple requests or session state"""


def ask_claude_for_tests(target: str, vulns: list) -> str:
    key = get_api_key()
    if not key or len(key) < 20:
        return "[!] No valid API key."

    vuln_list = ""
    for v in vulns:
        vuln_list += f"\nVULN_ID: {v[0]}\n"
        vuln_list += f"NAME: {v[2]}\n"
        vuln_list += f"SEVERITY: {v[3]}\n"
        vuln_list += f"PORT: {v[4]}\n"
        vuln_list += f"SERVICE: {v[5]}\n"
        vuln_list += f"DESCRIPTION: {v[6]}\n"
        vuln_list += "─" * 30 + "\n"

    messages = [{
        "role": "user",
        "content": f"""TARGET: {target}

RECORDED VULNERABILITIES:
{vuln_list}

Design safe single-request PoC confirmation tests for each vulnerability above.
Follow the output format exactly."""
    }]

    headers = {
        "x-api-key":         key,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }
    payload = {
        "model":      MODEL,
        "max_tokens": MAX_TOKENS,
        "system":     POC_SYSTEM_PROMPT,
        "messages":   messages,
    }

    try:
        print("\n  [*] Claude is designing confirmation tests...")
        resp = requests.post(ANTHROPIC_API_URL, headers=headers, json=payload, timeout=120)
        resp.raise_for_status()
        data    = resp.json()
        content = data.get("content", [])
        text    = "".join(b.get("text","") for b in content if b.get("type") == "text")
        return text.strip() if text else "[!] Empty response."
    except requests.exceptions.HTTPError:
        code = resp.status_code
        if code == 401: return "[!] Invalid API key."
        if code == 429: return "[!] Rate limited — wait and retry."
        if code == 400: return "[!] HTTP 400 — check API credits."
        return f"[!] HTTP {code} from Claude API."
    except Exception as e:
        return f"[!] Error: {type(e).__name__}: {e}"


# ─────────────────────────────────────────────
# TEST PARSER
# ─────────────────────────────────────────────

def parse_test_plans(claude_output: str) -> list:
    """Parse Claude's test plan output into structured dicts."""
    plans = []
    blocks = re.split(r'(?=VULN_ID:)', claude_output)

    for block in blocks:
        if not block.strip() or "VULN_ID:" not in block:
            continue

        plan = {
            "vuln_id":     None,
            "testable":    False,
            "skip_reason": "",
            "method":      "GET",
            "url":         "",
            "headers":     {},
            "body":        None,
            "confirm_if":  "",
            "deny_if":     "",
        }

        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("─"):
                continue

            if line.startswith("VULN_ID:"):
                try:
                    plan["vuln_id"] = int(line.split(":", 1)[1].strip())
                except:
                    pass
            elif line.startswith("TESTABLE:"):
                plan["testable"] = "YES" in line.upper()
            elif line.startswith("SKIP_REASON:"):
                plan["skip_reason"] = line.split(":", 1)[1].strip()
            elif line.startswith("METHOD:"):
                plan["method"] = line.split(":", 1)[1].strip().upper()
            elif line.startswith("URL:"):
                plan["url"] = line.split(":", 1)[1].strip()
                # fix double scheme
                url = plan["url"]
                if url.count("http") > 1:
                    plan["url"] = "https://" + url.split("http")[-1].lstrip("s://").lstrip("://")
            elif line.startswith("HEADERS:"):
                val = line.split(":", 1)[1].strip()
                if val.upper() != "NONE" and ":" in val:
                    k, v = val.split(":", 1)
                    plan["headers"][k.strip()] = v.strip()
            elif ":" in line and not any(line.startswith(k) for k in ["BODY", "CONFIRM", "DENY", "VULN", "TEST", "SKIP", "METHOD", "URL"]):
                # additional header lines
                if plan.get("_in_headers"):
                    k, v = line.split(":", 1)
                    plan["headers"][k.strip()] = v.strip()
            elif line.startswith("BODY:"):
                val = line.split(":", 1)[1].strip()
                plan["body"] = None if val.upper() == "NONE" else val
            elif line.startswith("CONFIRM_IF:"):
                plan["confirm_if"] = line.split(":", 1)[1].strip()
            elif line.startswith("DENY_IF:"):
                plan["deny_if"] = line.split(":", 1)[1].strip()

        if plan["vuln_id"] is not None:
            plans.append(plan)

    return plans


# ─────────────────────────────────────────────
# TEST EXECUTOR
# ─────────────────────────────────────────────

def execute_test(plan: dict) -> dict:
    """
    Fire the single safe request and determine status.
    Returns dict with status, evidence, request/response summary.
    """
    if not plan["testable"]:
        return {
            "status":        "SKIPPED",
            "evidence":      f"Not testable: {plan['skip_reason']}",
            "test_request":  "N/A",
            "test_response": "N/A",
        }

    if not plan["url"]:
        return {
            "status":        "INCONCLUSIVE",
            "evidence":      "Claude did not provide a URL for this test.",
            "test_request":  "N/A",
            "test_response": "N/A",
        }

    # merge headers
    req_headers = {**HEADERS, **plan.get("headers", {})}

    # build request summary
    test_request = f"{plan['method']} {plan['url']}"
    if plan.get("headers"):
        test_request += "\n" + "\n".join(f"{k}: {v}" for k, v in plan["headers"].items())
    if plan["body"]:
        test_request += f"\n\nBody: {plan['body']}"

    try:
        time.sleep(0.5)  # rate limit — be polite

        if plan["method"] == "GET":
            resp = requests.get(plan["url"], headers=req_headers,
                                timeout=15, verify=False, allow_redirects=False)
        elif plan["method"] == "HEAD":
            resp = requests.head(plan["url"], headers=req_headers,
                                 timeout=15, verify=False, allow_redirects=False)
        elif plan["method"] == "POST":
            resp = requests.post(plan["url"], headers=req_headers,
                                 data=plan["body"], timeout=15, verify=False,
                                 allow_redirects=False)
        elif plan["method"] == "OPTIONS":
            resp = requests.options(plan["url"], headers=req_headers,
                                    timeout=15, verify=False, allow_redirects=False)
        else:
            resp = requests.get(plan["url"], headers=req_headers,
                                timeout=15, verify=False, allow_redirects=False)

        # build response summary
        response_headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body_preview = ""
        try:
            body_preview = resp.text[:500]
        except:
            body_preview = "[binary or unreadable]"

        test_response = (
            f"Status: {resp.status_code}\n"
            f"Headers:\n{response_headers}\n"
            f"Body preview:\n{body_preview}"
        )

        # determine status by checking confirm/deny signals
        response_text = (str(resp.status_code) + " " +
                         response_headers.lower() + " " +
                         body_preview.lower())

        confirm_signal = plan.get("confirm_if", "").lower()
        deny_signal    = plan.get("deny_if", "").lower()

        status   = "INCONCLUSIVE"
        evidence = "Response received but confirmation signals unclear."

        if confirm_signal and any(s.strip() in response_text
                                  for s in confirm_signal.split("OR")):
            status   = "CONFIRMED"
            evidence = f"Confirmation signal found: '{plan['confirm_if']}'"

        elif deny_signal and any(s.strip() in response_text
                                 for s in deny_signal.split("OR")):
            status   = "UNCONFIRMED"
            evidence = f"Denial signal found: '{plan['deny_if']}' — vuln not present."

        elif resp.status_code == 200 and "200" in confirm_signal:
            status   = "CONFIRMED"
            evidence = f"HTTP 200 response — resource accessible."

        elif resp.status_code in (404, 403, 401) and confirm_signal == "":
            status   = "UNCONFIRMED"
            evidence = f"HTTP {resp.status_code} — resource not accessible."

        return {
            "status":        status,
            "evidence":      evidence,
            "test_request":  test_request,
            "test_response": test_response,
        }

    except requests.exceptions.ConnectionError:
        return {
            "status":        "INCONCLUSIVE",
            "evidence":      "Connection failed — target may be down or blocking.",
            "test_request":  test_request,
            "test_response": "Connection error",
        }
    except requests.exceptions.Timeout:
        return {
            "status":        "INCONCLUSIVE",
            "evidence":      "Request timed out — target slow or blocking.",
            "test_request":  test_request,
            "test_response": "Timeout",
        }
    except Exception as e:
        return {
            "status":        "INCONCLUSIVE",
            "evidence":      f"Unexpected error: {type(e).__name__}: {e}",
            "test_request":  test_request,
            "test_response": str(e),
        }


# ─────────────────────────────────────────────
# RESULTS DISPLAY
# ─────────────────────────────────────────────

def print_poc_results(vulns: list, poc_results: list):
    result_map = {r["vuln_id"]: r for r in poc_results}

    print(f"\n  {'ID':<6} {'VULNERABILITY':<35} {'SEVERITY':<10} STATUS")
    print(f"  {'─'*6} {'─'*35} {'─'*10} {'─'*15}")

    for v in vulns:
        vid    = v[0]
        name   = v[2][:33]
        sev    = v[3].upper()
        result = result_map.get(vid)
        status = result["status"] if result else "UNTESTED"
        sc     = STATUS_COLORS.get(status, "\033[0m")
        print(f"  {vid:<6} {name:<35} {sev:<10} {sc}{status}\033[0m")

    print()


def print_full_poc_report(vulns: list, poc_results: list):
    result_map = {r["vuln_id"]: r for r in poc_results}
    divider("POC TEST REPORT")

    for v in vulns:
        vid    = v[0]
        name   = v[2]
        sev    = v[3].upper()
        desc   = v[6]
        result = result_map.get(vid)

        if not result:
            print(f"\n  [{vid}] {name} | {sev} | \033[90mUNTESTED\033[0m")
            continue

        sc = STATUS_COLORS.get(result["status"], "\033[0m")
        print(f"\n  [{vid}] {name} | {sev} | {sc}{result['status']}\033[0m")
        print(f"  Evidence : {result['evidence']}")
        if result["tested_at"]:
            print(f"  Tested   : {result['tested_at']}")
        if result["test_request"] and result["test_request"] != "N/A":
            print(f"\n  Request:")
            for line in result["test_request"].splitlines()[:5]:
                print(f"    {line}")
        print()

    print()


# ─────────────────────────────────────────────
# MAIN MODULE 2 FLOW
# ─────────────────────────────────────────────

def run_poc_tester(preloaded_sl_no: int = None):
    """
    Entry point. preloaded_sl_no — jump straight to a session
    (called from new_scan / ai_mode after recording results).
    """
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
\033[91m  ── POC EXPLOITABILITY TEST ──\033[0m
\033[90m  Safe · Single-request · Read-only · Claude-designed\033[0m
""")

    # ── session selection ─────────────────────
    sl_no = preloaded_sl_no

    if sl_no is None:
        rows = get_all_history()
        if not rows:
            warn("No scan sessions in database. Run a scan first.")
            return

        print_history(rows)
        raw = input("\033[36m  Pick session # to test: \033[0m").strip()
        if not raw.isdigit():
            error("Invalid selection.")
            return
        sl_no = int(raw)

    # ── load session ──────────────────────────
    data  = get_session(sl_no)
    if not data["history"]:
        error(f"Session #{sl_no} not found.")
        return

    target = data["history"]["target"]
    vulns  = get_vulnerabilities(sl_no)

    if not vulns:
        warn(f"Session #{sl_no} has no recorded vulnerabilities to test.")
        return

    divider(f"SESSION #{sl_no} — {target}")
    print(f"\n  Found {len(vulns)} recorded vulnerabilities:\n")
    for v in vulns:
        existing = get_poc_result_for_vuln(v[0])
        status   = existing["status"] if existing else "UNTESTED"
        sc       = STATUS_COLORS.get(status, "\033[0m")
        print(f"  [{v[0]}] {v[2]:<40} [{v[3].upper()}]  {sc}{status}\033[0m")

    print()
    print("  [1] Test ALL vulnerabilities")
    print("  [2] Test specific vulnerability by ID")
    print("  [3] View existing results")
    print("  [4] Export full PoC report")
    print("  [5] Back")
    divider()

    choice = input("\033[36m  Choice: \033[0m").strip()

    if choice == "1":
        _run_tests(sl_no, target, vulns)

    elif choice == "2":
        vid_raw = input("\033[36m  Vulnerability ID: \033[0m").strip()
        if not vid_raw.isdigit():
            error("Invalid ID.")
            return
        vid       = int(vid_raw)
        target_v  = [v for v in vulns if v[0] == vid]
        if not target_v:
            error(f"Vulnerability #{vid} not found in session #{sl_no}.")
            return
        _run_tests(sl_no, target, target_v)

    elif choice == "3":
        poc_results = get_poc_results(sl_no)
        if not poc_results:
            warn("No PoC tests run yet for this session.")
            return
        print_full_poc_report(vulns, poc_results)

    elif choice == "4":
        poc_results = get_poc_results(sl_no)
        _export_poc_report(sl_no, target, vulns, poc_results)

    elif choice == "5":
        return

    else:
        warn("Invalid choice.")


def _run_tests(sl_no: int, target: str, vulns: list):
    divider("DESIGNING TESTS")

    # Claude designs the test plans
    claude_output = ask_claude_for_tests(target, vulns)

    if claude_output.startswith("[!]"):
        error(claude_output)
        return

    print(f"\n\033[90m{'─'*60}\033[0m")
    print(claude_output)
    print(f"\033[90m{'─'*60}\033[0m\n")

    plans = parse_test_plans(claude_output)

    if not plans:
        warn("Could not parse test plans from Claude output.")
        return

    success(f"Parsed {len(plans)} test plans.")

    divider("EXECUTING TESTS")

    results_summary = []

    for plan in plans:
        vuln_match = [v for v in vulns if v[0] == plan["vuln_id"]]
        vuln_name  = vuln_match[0][2] if vuln_match else f"Vuln #{plan['vuln_id']}"

        if not plan["testable"]:
            warn(f"SKIP  [{plan['vuln_id']}] {vuln_name} — {plan['skip_reason']}")
            save_poc_result(
                sl_no, plan["vuln_id"],
                "SKIPPED", "N/A", "N/A",
                f"Skipped: {plan['skip_reason']}"
            )
            results_summary.append({"name": vuln_name, "status": "SKIPPED"})
            continue

        info(f"Testing [{plan['vuln_id']}] {vuln_name}...")
        info(f"  {plan['method']} {plan['url']}")

        result = execute_test(plan)

        sc = STATUS_COLORS.get(result["status"], "\033[0m")
        print(f"  → {sc}{result['status']}\033[0m  {result['evidence']}")

        save_poc_result(
            sl_no,
            plan["vuln_id"],
            result["status"],
            result["test_request"],
            result["test_response"],
            result["evidence"]
        )

        results_summary.append({"name": vuln_name, "status": result["status"]})

    # ── summary ───────────────────────────────
    divider("RESULTS SUMMARY")

    confirmed    = [r for r in results_summary if r["status"] == "CONFIRMED"]
    unconfirmed  = [r for r in results_summary if r["status"] == "UNCONFIRMED"]
    inconclusive = [r for r in results_summary if r["status"] == "INCONCLUSIVE"]
    skipped      = [r for r in results_summary if r["status"] == "SKIPPED"]

    print(f"\n  Total tested : {len(results_summary)}")
    print(f"  \033[91mCONFIRMED    : {len(confirmed)}\033[0m")
    print(f"  \033[92mUNCONFIRMED  : {len(unconfirmed)}\033[0m")
    print(f"  \033[93mINCONCLUSIVE : {len(inconclusive)}\033[0m")
    print(f"  \033[90mSKIPPED      : {len(skipped)}\033[0m")

    if confirmed:
        print(f"\n  \033[91mConfirmed findings:\033[0m")
        for r in confirmed:
            print(f"    • {r['name']}")

    print()
    poc_results = get_poc_results(sl_no)
    print_poc_results(vulns, poc_results)

    if input("\033[36m  Export full PoC report? [y/N]: \033[0m").strip().lower() == "y":
        _export_poc_report(sl_no, target, vulns, poc_results)


def _export_poc_report(sl_no: int, target: str, vulns: list, poc_results: list):
    """Export PoC test results as a .txt report."""
    from datetime import datetime
    import os as _os

    _os.makedirs("reports", exist_ok=True)
    target_safe = target.replace("://","_").replace("/","_").replace(".","_")
    filename    = f"reports/wr4ith_poc_{target_safe}_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.txt"

    result_map = {r["vuln_id"]: r for r in poc_results}

    lines = []
    lines.append("=" * 70)
    lines.append("  WR4ITH — PoC Exploitability Test Report")
    lines.append("=" * 70)
    lines.append(f"  Target    : {target}")
    lines.append(f"  Session   : #{sl_no}")
    lines.append(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    confirmed    = [r for r in poc_results if r["status"] == "CONFIRMED"]
    unconfirmed  = [r for r in poc_results if r["status"] == "UNCONFIRMED"]
    inconclusive = [r for r in poc_results if r["status"] == "INCONCLUSIVE"]
    skipped      = [r for r in poc_results if r["status"] == "SKIPPED"]

    lines.append(f"  CONFIRMED    : {len(confirmed)}")
    lines.append(f"  UNCONFIRMED  : {len(unconfirmed)}")
    lines.append(f"  INCONCLUSIVE : {len(inconclusive)}")
    lines.append(f"  SKIPPED      : {len(skipped)}")
    lines.append("")

    lines.append("─" * 70)
    lines.append("  DETAILED FINDINGS")
    lines.append("─" * 70)

    for v in vulns:
        vid    = v[0]
        name   = v[2]
        sev    = v[3].upper()
        desc   = v[6]
        result = result_map.get(vid)
        status = result["status"] if result else "UNTESTED"

        lines.append(f"\n  [{status}] {name} | {sev}")
        if desc:
            lines.append(f"  Description : {desc[:200]}")
        if result:
            lines.append(f"  Evidence    : {result['evidence']}")
            lines.append(f"  Tested at   : {result.get('tested_at','')}")
            if result["test_request"] and result["test_request"] != "N/A":
                lines.append(f"\n  Test request:")
                for line in result["test_request"].splitlines()[:8]:
                    lines.append(f"    {line}")

    lines.append("\n" + "=" * 70)
    lines.append("  End of report — WR4ITH PoC Tester")
    lines.append("=" * 70)

    with open(filename, "w") as f:
        f.write("\n".join(lines))

    print(f"\n  \033[92m[+] Report saved: {filename}\033[0m")

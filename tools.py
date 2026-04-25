#!/usr/bin/env python3
"""
WR4ITH - tools.py
Recon tool runners. Lubuntu/Ubuntu friendly.
Tools: nmap, whois, curl, dig, nikto, whatweb
All available via: sudo apt install nmap whois curl dnsutils nikto whatweb
"""

import subprocess
import shutil


# ─────────────────────────────────────────────
# TOOL AVAILABILITY
# ─────────────────────────────────────────────

TOOL_INSTALL = {
    "nmap":    "sudo apt install nmap",
    "whois":   "sudo apt install whois",
    "whatweb": "sudo apt install whatweb",
    "curl":    "sudo apt install curl",
    "dig":     "sudo apt install dnsutils",
    "nikto":   "sudo apt install nikto",
}


def is_installed(tool: str) -> bool:
    return shutil.which(tool) is not None


def check_tool(tool: str) -> str | None:
    """Returns error string if missing, None if available."""
    if not is_installed(tool):
        install = TOOL_INSTALL.get(tool, f"sudo apt install {tool}")
        return f"[!] '{tool}' is not installed.\n    Fix: {install}"
    return None


def check_all_tools() -> dict:
    return {t: ("installed" if is_installed(t) else "missing") for t in TOOL_INSTALL}


# ─────────────────────────────────────────────
# BASE RUNNER
# ─────────────────────────────────────────────

def run_tool(command: list, timeout: int = 120) -> str:
    tool_name = command[0].split("/")[-1] if command else "unknown"

    err = check_tool(tool_name)
    if err:
        return err

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        out     = result.stdout.strip()
        err_out = result.stderr.strip()

        if result.returncode != 0 and not out:
            return f"[!] {tool_name} failed (exit {result.returncode}):\n{err_out or 'no output'}"

        if out and err_out:
            return out + "\n[STDERR]\n" + err_out
        return out or err_out or f"[!] {tool_name} returned no output."

    except subprocess.TimeoutExpired:
        return f"[!] {tool_name} timed out after {timeout}s — target may be slow or unresponsive. Result: INCONCLUSIVE"
    except FileNotFoundError:
        return f"[!] '{tool_name}' not found on PATH.\n    Fix: {TOOL_INSTALL.get(tool_name, 'sudo apt install ' + tool_name)}"
    except PermissionError:
        return f"[!] Permission denied running '{tool_name}'.\n    Some scans need sudo. Try: sudo python3 wr4ith.py"
    except Exception as e:
        return f"[!] Unexpected error in '{tool_name}': {type(e).__name__}: {e}"


# ─────────────────────────────────────────────
# INDIVIDUAL TOOLS
# ─────────────────────────────────────────────

def run_nmap(target: str) -> str:
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)


def run_whois(target: str) -> str:
    print(f"  [*] whois {target}")
    clean = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    return run_tool(["whois", clean], timeout=30)


def run_whatweb(target: str) -> str:
    print(f"  [*] whatweb -a 3 {target}")
    return run_tool(["whatweb", "-a", "3", target], timeout=60)


def run_curl_headers(target: str) -> str:
    print(f"  [*] curl headers {target}")
    clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    http  = run_tool(["curl", "-sI", "--max-time", "10", "--location", f"http://{clean}"],  timeout=20)
    https = run_tool(["curl", "-sI", "--max-time", "10", "--location", "-k", f"https://{clean}"], timeout=20)
    return f"[HTTP]\n{http}\n\n[HTTPS]\n{https}"


def run_dig(target: str) -> str:
    print(f"  [*] dig {target}")
    clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    results = {}
    for rtype in ["A", "MX", "NS", "TXT"]:
        r = run_tool(["dig", "+short", rtype, clean], timeout=15)
        results[rtype] = "lookup failed" if "[!]" in r else r
    return f"[A]\n{results['A']}\n\n[MX]\n{results['MX']}\n\n[NS]\n{results['NS']}\n\n[TXT]\n{results['TXT']}"


def run_nikto(target: str) -> str:
    print(f"  [*] nikto -h {target}  (slow — up to 5 min)")
    result = run_tool(["nikto", "-h", target, "-nointeractive"], timeout=300)
    if "INCONCLUSIVE" in result:
        return f"[!] nikto timed out — target may be slow or blocking scans.\n{result}"
    return result


# ─────────────────────────────────────────────
# TOOL MENU
# ─────────────────────────────────────────────

TOOLS_MENU = {
    "1": ("nmap",         run_nmap),
    "2": ("whois",        run_whois),
    "3": ("whatweb",      run_whatweb),
    "4": ("curl headers", run_curl_headers),
    "5": ("dig DNS",      run_dig),
    "6": ("nikto",        run_nikto),
}

ALLOWED_TOOLS = {"nmap", "whois", "whatweb", "curl", "dig", "nikto"}


def run_tool_by_command(command_str: str) -> str:
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."
    tool = parts[0].lower().split("/")[-1]
    if tool not in ALLOWED_TOOLS:
        return f"[!] Tool '{parts[0]}' not permitted. Allowed: {', '.join(sorted(ALLOWED_TOOLS))}"
    return run_tool(parts)


def run_default_recon(target: str) -> dict:
    print(f"\n  [*] Starting network recon on: {target}")
    results = {}
    for name, func in [
        ("nmap",         run_nmap),
        ("whois",        run_whois),
        ("whatweb",      run_whatweb),
        ("curl_headers", run_curl_headers),
        ("dig",          run_dig),
    ]:
        results[name] = func(target)
    print("  [+] Network recon complete.")
    return results


def format_recon_for_llm(results: dict) -> str:
    out = ""
    for tool, data in results.items():
        out += f"\n{'='*50}\n[ {tool.upper()} ]\n{'='*50}\n"
        out += data.strip() + "\n"
    return out


def interactive_tool_run(target: str) -> str:
    print("\n  [ NETWORK TOOLS ]")
    for key, (name, _) in TOOLS_MENU.items():
        bin_name = name.split()[0]
        status = "\033[92m✓\033[0m" if is_installed(bin_name) else "\033[91m✗ not installed\033[0m"
        print(f"    [{key}] {name}  {status}")
    print("    [a] all (except nikto)")
    print("    [n] all + nikto (slow)")
    print("    [s] skip — web recon only")

    choice = input("\n  Choice(s) e.g. 1 2 4 or a: ").strip().lower()

    if choice == "s":
        return ""
    if choice == "a":
        return format_recon_for_llm(run_default_recon(target))
    if choice == "n":
        results = run_default_recon(target)
        results["nikto"] = run_nikto(target)
        return format_recon_for_llm(results)

    combined = {}
    for key in choice.split():
        if key in TOOLS_MENU:
            name, func = TOOLS_MENU[key]
            print(f"\n  [*] Running {name}...")
            combined[name] = func(target)
        else:
            print(f"  [!] Unknown option: {key}")

    return format_recon_for_llm(combined)

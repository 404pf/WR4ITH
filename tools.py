#!/usr/bin/env python3
"""
WR4ITH - tools.py
Recon tool runners. Lubuntu/Ubuntu friendly.
Tools: nmap, whois, curl, dig, nikto, whatweb
All available via: sudo apt install nmap whois curl dnsutils nikto whatweb
"""

import subprocess


# ─────────────────────────────────────────────
# BASE RUNNER
# ─────────────────────────────────────────────

def run_tool(command: list, timeout: int = 120) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        out = result.stdout.strip()
        err = result.stderr.strip()
        if out and err: return out + "\n[STDERR]\n" + err
        return out or err or "[!] Tool returned no output."
    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s: {' '.join(command)}"
    except FileNotFoundError:
        return f"[!] Tool not found: {command[0]}\n    Install: sudo apt install {command[0]}"
    except Exception as e:
        return f"[!] Error running {command[0]}: {e}"


# ─────────────────────────────────────────────
# INDIVIDUAL TOOLS
# ─────────────────────────────────────────────

def run_nmap(target: str) -> str:
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)


def run_whois(target: str) -> str:
    print(f"  [*] whois {target}")
    return run_tool(["whois", target], timeout=30)


def run_whatweb(target: str) -> str:
    print(f"  [*] whatweb -a 3 {target}")
    return run_tool(["whatweb", "-a", "3", target], timeout=60)


def run_curl_headers(target: str) -> str:
    print(f"  [*] curl headers {target}")
    http = run_tool(["curl", "-sI", "--max-time", "10", "--location", f"http://{target}"], timeout=20)
    https = run_tool(["curl", "-sI", "--max-time", "10", "--location", "-k", f"https://{target}"], timeout=20)
    return f"[HTTP]\n{http}\n\n[HTTPS]\n{https}"


def run_dig(target: str) -> str:
    print(f"  [*] dig {target}")
    a   = run_tool(["dig", "+short", "A",   target], timeout=15)
    mx  = run_tool(["dig", "+short", "MX",  target], timeout=15)
    ns  = run_tool(["dig", "+short", "NS",  target], timeout=15)
    txt = run_tool(["dig", "+short", "TXT", target], timeout=15)
    return f"[A]\n{a}\n\n[MX]\n{mx}\n\n[NS]\n{ns}\n\n[TXT]\n{txt}"


def run_nikto(target: str) -> str:
    print(f"  [*] nikto -h {target}  (slow — runs up to 5 min)")
    return run_tool(["nikto", "-h", target, "-nointeractive"], timeout=300)


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
    """Called by Claude agentic loop when it writes [TOOL: ...]"""
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."
    tool = parts[0].lower().split("/")[-1]
    if tool not in ALLOWED_TOOLS:
        return f"[!] Tool '{parts[0]}' not permitted. Allowed: {ALLOWED_TOOLS}"
    return run_tool(parts)


def run_default_recon(target: str) -> dict:
    """Standard pipeline — everything except nikto."""
    print(f"\n  [*] Starting recon on: {target}")
    results = {}
    results["nmap"]         = run_nmap(target)
    results["whois"]        = run_whois(target)
    results["whatweb"]      = run_whatweb(target)
    results["curl_headers"] = run_curl_headers(target)
    results["dig"]          = run_dig(target)
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
        print(f"    [{key}] {name}")
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

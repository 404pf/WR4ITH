#!/usr/bin/env python3
"""
WR4ITH - search.py
DuckDuckGo search + CVE lookup. No API key needed.
Called by Claude agentic loop when it writes [SEARCH: ...]
"""

import re
import requests
from bs4 import BeautifulSoup

try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        DDGS = None


# ─────────────────────────────────────────────
# WEB SEARCH
# ─────────────────────────────────────────────

def web_search(query: str, max_results: int = 5) -> str:
    print(f"  [*] Searching: {query}")

    if not DDGS:
        return "[!] duckduckgo-search not installed. Run: pip install duckduckgo-search"

    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))

        if not results:
            return "[!] No results found."

        out = f"[SEARCH: {query}]\n{'─'*50}\n"
        for i, r in enumerate(results, 1):
            out += f"\n[{i}] {r['title']}\n"
            out += f"    {r['href']}\n"
            out += f"    {r['body']}\n"
        return out

    except Exception as e:
        return f"[!] Search failed: {e}"


# ─────────────────────────────────────────────
# CVE LOOKUP
# ─────────────────────────────────────────────

def search_cve(cve_id: str) -> str:
    print(f"  [*] CVE lookup: {cve_id}")
    ddg = web_search(f"{cve_id} vulnerability exploit details", max_results=3)
    mitre = fetch_page(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}", max_chars=2000)
    return f"{ddg}\n\n[MITRE: {cve_id}]\n{mitre}"


def search_fix(vuln_name: str) -> str:
    return web_search(f"how to fix {vuln_name} security mitigation", max_results=3)


# ─────────────────────────────────────────────
# PAGE FETCH
# ─────────────────────────────────────────────

def fetch_page(url: str, max_chars: int = 3000) -> str:
    try:
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0"}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["script","style","nav","footer","header","aside"]):
            tag.decompose()
        text = "\n".join(l for l in soup.get_text(separator="\n", strip=True).splitlines() if l.strip())
        return text[:max_chars] + (f"\n[truncated]" if len(text) > max_chars else "")
    except Exception as e:
        return f"[!] Fetch failed: {e}"


# ─────────────────────────────────────────────
# DISPATCH
# ─────────────────────────────────────────────

def handle_search_dispatch(query: str) -> str:
    query = query.strip()
    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', query, re.I)
    if cve_match:
        return search_cve(cve_match.group())
    if any(w in query.lower() for w in ["exploit","poc","payload","rce","lfi","sqli"]):
        return web_search(query + " exploit poc github", max_results=5)
    if any(w in query.lower() for w in ["fix","patch","mitigate","harden","secure"]):
        return search_fix(query)
    return web_search(query, max_results=5)

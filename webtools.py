#!/usr/bin/env python3
"""
WR4ITH - webtools.py
Web-focused recon module. New in WR4ITH, not in METATRON.
- Security headers deep check
- robots.txt / sitemap.xml
- JS file harvesting + endpoint extraction
- Tech fingerprinting
- Passive mode support
"""

import re
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
}
TIMEOUT = 15


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def normalize(target: str) -> str:
    """Ensure target has a scheme."""
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def fetch(url: str, timeout: int = TIMEOUT) -> requests.Response | None:
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout,
                            verify=False, allow_redirects=True)
    except Exception:
        try:
            fallback = url.replace("https://", "http://")
            return requests.get(fallback, headers=HEADERS, timeout=timeout,
                                verify=False, allow_redirects=True)
        except Exception:
            return None


# ─────────────────────────────────────────────
# SECURITY HEADERS
# ─────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — enforces HTTPS",
    "Content-Security-Policy":   "CSP — prevents XSS/injection",
    "X-Frame-Options":           "Clickjacking protection",
    "X-Content-Type-Options":    "MIME sniffing protection",
    "Referrer-Policy":           "Controls referrer leakage",
    "Permissions-Policy":        "Feature policy / browser API control",
    "X-XSS-Protection":          "Legacy XSS filter (deprecated but informative)",
    "Cross-Origin-Opener-Policy":"COOP — cross-origin isolation",
    "Cross-Origin-Resource-Policy":"CORP — resource sharing control",
}

INTERESTING_HEADERS = {
    "Server":        "Reveals server software",
    "X-Powered-By":  "Reveals backend tech",
    "Via":           "Reveals proxy/CDN",
    "X-AspNet-Version": "ASP.NET version disclosure",
    "X-Generator":   "CMS/framework disclosure",
}


def check_security_headers(target: str) -> str:
    url = normalize(target)
    print(f"  [*] Checking security headers: {url}")

    resp = fetch(url)
    if not resp:
        return f"[!] Could not reach {url}"

    out = f"[SECURITY HEADERS — {url}]\n"
    out += f"Status: {resp.status_code} | Final URL: {resp.url}\n"
    out += "─" * 50 + "\n"

    # check required security headers
    out += "\n[Required Security Headers]\n"
    for header, desc in SECURITY_HEADERS.items():
        val = resp.headers.get(header)
        if val:
            out += f"  ✓ PRESENT  {header}: {val[:120]}\n"
        else:
            out += f"  ✗ MISSING  {header}  ({desc})\n"

    # check info-disclosure headers
    out += "\n[Info Disclosure Headers]\n"
    for header, desc in INTERESTING_HEADERS.items():
        val = resp.headers.get(header)
        if val:
            out += f"  ! EXPOSED  {header}: {val}  ({desc})\n"

    # cookies analysis
    if resp.cookies:
        out += "\n[Cookies]\n"
        for cookie in resp.cookies:
            flags = []
            if not cookie.secure:    flags.append("MISSING Secure flag")
            if "httponly" not in str(cookie.__dict__).lower(): flags.append("MISSING HttpOnly")
            if "samesite" not in str(cookie.__dict__).lower(): flags.append("MISSING SameSite")
            flag_str = " | ".join(flags) if flags else "OK"
            out += f"  {cookie.name}: {flag_str}\n"

    # CORS check
    cors = resp.headers.get("Access-Control-Allow-Origin")
    if cors:
        out += f"\n[CORS]\n  Access-Control-Allow-Origin: {cors}\n"
        if cors == "*":
            out += "  ! WILDCARD CORS — any origin can read responses\n"

    return out


# ─────────────────────────────────────────────
# ROBOTS.TXT + SITEMAP
# ─────────────────────────────────────────────

def check_robots(target: str) -> str:
    base = normalize(target)
    print(f"  [*] Fetching robots.txt and sitemap")

    out = "[ROBOTS.TXT + SITEMAP]\n"

    # robots.txt
    resp = fetch(urljoin(base, "/robots.txt"))
    if resp and resp.status_code == 200 and "text" in resp.headers.get("Content-Type",""):
        out += f"\n[robots.txt]\n{resp.text[:3000]}\n"
        # extract disallowed paths — often reveals hidden endpoints
        disallowed = re.findall(r'Disallow:\s*(.+)', resp.text)
        if disallowed:
            out += "\n[Disallowed paths (potential endpoints)]\n"
            for d in disallowed:
                out += f"  {d.strip()}\n"
    else:
        out += "\n[robots.txt] Not found or not accessible.\n"

    # sitemap
    for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml"]:
        resp = fetch(urljoin(base, sitemap_path))
        if resp and resp.status_code == 200:
            urls = re.findall(r'<loc>(.*?)</loc>', resp.text)
            out += f"\n[sitemap.xml — {len(urls)} URLs found]\n"
            for u in urls[:30]:
                out += f"  {u}\n"
            if len(urls) > 30:
                out += f"  ... and {len(urls)-30} more\n"
            break

    return out


# ─────────────────────────────────────────────
# JS FILE HARVESTING + ENDPOINT EXTRACTION
# ─────────────────────────────────────────────

# patterns to find endpoints/secrets in JS
JS_PATTERNS = {
    "API endpoints":    re.compile(r'["\']\/(?:api|v\d|graphql|rest|endpoint)[\/\w\-\.]*["\']', re.I),
    "URLs in JS":       re.compile(r'https?:\/\/[^\s\'"<>]{10,100}'),
    "Path strings":     re.compile(r'["\']\/[\w\-\/\.]{4,60}["\']'),
    "AWS keys":         re.compile(r'AKIA[0-9A-Z]{16}'),
    "Bearer tokens":    re.compile(r'[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}'),
    "API key patterns": re.compile(r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']?[\w\-]{10,}', re.I),
    "Private keys":     re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'),
}


def harvest_js(target: str) -> str:
    base = normalize(target)
    print(f"  [*] Harvesting JS files and extracting endpoints")

    resp = fetch(base)
    if not resp:
        return f"[!] Could not reach {base}"

    soup = BeautifulSoup(resp.text, "html.parser")

    # find all script src attributes
    script_urls = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        full = src if src.startswith("http") else urljoin(base, src)
        script_urls.append(full)

    # also find inline scripts
    inline_scripts = [tag.string for tag in soup.find_all("script", src=False) if tag.string]

    out = f"[JS ANALYSIS — {base}]\n"
    out += f"Found {len(script_urls)} external JS files, {len(inline_scripts)} inline scripts\n"
    out += "─" * 50 + "\n"

    all_js_content = "\n".join(inline_scripts)

    # fetch and analyze external JS files
    for js_url in script_urls[:15]:  # cap at 15 to avoid flooding
        out += f"\n[JS] {js_url}\n"
        js_resp = fetch(js_url, timeout=10)
        if not js_resp:
            out += "  [!] Could not fetch\n"
            continue
        all_js_content += "\n" + js_resp.text

        # size info
        size_kb = len(js_resp.content) / 1024
        out += f"  Size: {size_kb:.1f} KB\n"

    # run pattern matching on all JS content
    out += "\n[Extracted from JS]\n"
    found_anything = False
    for pattern_name, pattern in JS_PATTERNS.items():
        matches = list(set(pattern.findall(all_js_content)))[:20]
        if matches:
            found_anything = True
            out += f"\n  [{pattern_name}]\n"
            for m in matches:
                out += f"    {m}\n"

    if not found_anything:
        out += "  Nothing suspicious found in JS files.\n"

    return out


# ─────────────────────────────────────────────
# COMMON PATH PROBE
# ─────────────────────────────────────────────

COMMON_PATHS = [
    "/.env", "/.git/HEAD", "/admin", "/admin/login", "/wp-admin",
    "/api", "/api/v1", "/api/v2", "/graphql", "/swagger",
    "/swagger-ui.html", "/api-docs", "/openapi.json", "/phpinfo.php",
    "/server-status", "/server-info", "/.htaccess", "/config.php",
    "/backup", "/backup.zip", "/db.sql", "/dump.sql",
    "/login", "/dashboard", "/console", "/actuator", "/actuator/health",
    "/actuator/env", "/.well-known/security.txt",
]


def probe_paths(target: str, passive: bool = False) -> str:
    if passive:
        return "[PATH PROBE] Skipped in passive mode.\n"

    base = normalize(target)
    print(f"  [*] Probing {len(COMMON_PATHS)} common paths")

    out = f"[COMMON PATH PROBE — {base}]\n"
    out += "─" * 50 + "\n"

    found = []
    for path in COMMON_PATHS:
        url = urljoin(base, path)
        try:
            r = requests.head(url, headers=HEADERS, timeout=5,
                              verify=False, allow_redirects=False)
            if r.status_code in (200, 301, 302, 401, 403):
                found.append((r.status_code, url))
        except Exception:
            pass

    if found:
        for code, url in found:
            indicator = {200: "✓ OPEN", 401: "🔒 AUTH", 403: "⛔ FORBIDDEN",
                         301: "→ REDIRECT", 302: "→ REDIRECT"}.get(code, str(code))
            out += f"  [{code}] {indicator}  {url}\n"
    else:
        out += "  No interesting paths found.\n"

    return out


# ─────────────────────────────────────────────
# TECH FINGERPRINT
# ─────────────────────────────────────────────

def fingerprint_tech(target: str) -> str:
    base = normalize(target)
    print(f"  [*] Fingerprinting technologies")

    resp = fetch(base)
    if not resp:
        return f"[!] Could not reach {base}"

    out = f"[TECH FINGERPRINT — {base}]\n"
    out += "─" * 50 + "\n"

    # from headers
    for h in ["Server", "X-Powered-By", "X-Generator", "X-Drupal-Cache",
              "X-WordPress-Cache", "X-Shopify-Stage"]:
        val = resp.headers.get(h)
        if val:
            out += f"  {h}: {val}\n"

    # from HTML
    soup = BeautifulSoup(resp.text, "html.parser")

    # meta generator
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen:
        out += f"  Meta Generator: {gen.get('content','')}\n"

    # common framework indicators
    html = resp.text.lower()
    indicators = {
        "WordPress":  ["wp-content", "wp-includes", "wordpress"],
        "Drupal":     ["drupal", "/sites/default/"],
        "Laravel":    ["laravel_session", "laravel"],
        "Django":     ["csrfmiddlewaretoken", "django"],
        "React":      ["__react", "react-dom", "_reactfiber"],
        "Vue.js":     ["__vue__", "vue.js"],
        "Angular":    ["ng-version", "angular"],
        "Next.js":    ["__next", "_next/static"],
        "Flask":      ["werkzeug", "flask"],
        "Express":    ["x-powered-by: express"],
        "jQuery":     ["jquery"],
        "Bootstrap":  ["bootstrap"],
        "Cloudflare": ["__cfduid", "cf-ray", "cloudflare"],
        "nginx":      ["nginx"],
        "Apache":     ["apache"],
    }

    detected = []
    for tech, patterns in indicators.items():
        if any(p in html or p in str(resp.headers).lower() for p in patterns):
            detected.append(tech)

    if detected:
        out += f"\n  Detected: {', '.join(detected)}\n"

    return out


# ─────────────────────────────────────────────
# FULL WEB RECON (called by wr4ith.py)
# ─────────────────────────────────────────────

def run_web_recon(target: str, passive: bool = False) -> str:
    """
    Run all web-focused checks.
    passive=True skips active path probing.
    Returns combined string for LLM.
    """
    import warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    results = []
    results.append(check_security_headers(target))
    results.append(check_robots(target))
    results.append(harvest_js(target))
    results.append(fingerprint_tech(target))
    results.append(probe_paths(target, passive=passive))

    return "\n\n".join(results)

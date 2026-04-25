#!/usr/bin/env python3
"""
WR4ITH - webtools.py
Web-focused recon module.
- Security headers deep check
- robots.txt / sitemap.xml
- JS file harvesting + endpoint extraction
- Tech fingerprinting
- Passive mode support with rate limiting
"""

import re
import time
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup


HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
}
TIMEOUT       = 15
PASSIVE_DELAY = 0.8   # seconds between requests in passive mode
ACTIVE_DELAY  = 0.3   # seconds between requests in active mode


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def normalize(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def fetch(url: str, timeout: int = TIMEOUT) -> requests.Response | None:
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout,
                            verify=False, allow_redirects=True)
    except requests.exceptions.SSLError:
        try:
            fallback = url.replace("https://", "http://")
            return requests.get(fallback, headers=HEADERS, timeout=timeout,
                                verify=False, allow_redirects=True)
        except Exception:
            return None
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


def safe_fetch(url: str, delay: float = 0, timeout: int = TIMEOUT) -> requests.Response | None:
    """Fetch with optional rate limit delay."""
    if delay > 0:
        time.sleep(delay)
    return fetch(url, timeout=timeout)


# ─────────────────────────────────────────────
# SECURITY HEADERS
# ─────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — enforces HTTPS",
    "Content-Security-Policy":   "CSP — prevents XSS/injection",
    "X-Frame-Options":           "Clickjacking protection",
    "X-Content-Type-Options":    "MIME sniffing protection",
    "Referrer-Policy":           "Controls referrer leakage",
    "Permissions-Policy":        "Feature/browser API control",
    "X-XSS-Protection":          "Legacy XSS filter",
    "Cross-Origin-Opener-Policy":"COOP — cross-origin isolation",
    "Cross-Origin-Resource-Policy":"CORP — resource sharing control",
}

INTERESTING_HEADERS = {
    "Server":            "Reveals server software",
    "X-Powered-By":      "Reveals backend tech",
    "Via":               "Reveals proxy/CDN",
    "X-AspNet-Version":  "ASP.NET version disclosure",
    "X-Generator":       "CMS/framework disclosure",
}


def check_security_headers(target: str, delay: float = 0) -> str:
    url = normalize(target)
    print(f"  [*] Checking security headers: {url}")

    resp = safe_fetch(url, delay=delay)
    if not resp:
        return f"[SECURITY HEADERS]\n[!] Could not reach {url} — target may be down or blocking requests.\n"

    out = f"[SECURITY HEADERS — {url}]\n"
    out += f"Status: {resp.status_code} | Final URL: {resp.url}\n"
    out += "─" * 50 + "\n"

    out += "\n[Required Security Headers]\n"
    for header, desc in SECURITY_HEADERS.items():
        val = resp.headers.get(header)
        out += f"  {'✓ PRESENT' if val else '✗ MISSING'}  {header}"
        out += f": {val[:120]}\n" if val else f"  ({desc})\n"

    out += "\n[Info Disclosure Headers]\n"
    found_disclosure = False
    for header, desc in INTERESTING_HEADERS.items():
        val = resp.headers.get(header)
        if val:
            found_disclosure = True
            out += f"  ! EXPOSED  {header}: {val}  ({desc})\n"
    if not found_disclosure:
        out += "  None found.\n"

    if resp.cookies:
        out += "\n[Cookies]\n"
        for cookie in resp.cookies:
            flags = []
            if not cookie.secure:
                flags.append("MISSING Secure")
            cd = str(cookie.__dict__).lower()
            if "httponly" not in cd:
                flags.append("MISSING HttpOnly")
            if "samesite" not in cd:
                flags.append("MISSING SameSite")
            flag_str = " | ".join(flags) if flags else "OK"
            out += f"  {cookie.name}: {flag_str}\n"

    cors = resp.headers.get("Access-Control-Allow-Origin")
    if cors:
        out += f"\n[CORS]\n  Access-Control-Allow-Origin: {cors}\n"
        if cors == "*":
            out += "  ! WILDCARD CORS — any origin can read responses\n"

    return out


# ─────────────────────────────────────────────
# ROBOTS.TXT + SITEMAP
# ─────────────────────────────────────────────

def check_robots(target: str, delay: float = 0) -> str:
    base = normalize(target)
    print(f"  [*] Fetching robots.txt and sitemap")
    out = "[ROBOTS.TXT + SITEMAP]\n"

    time.sleep(delay)
    resp = fetch(urljoin(base, "/robots.txt"))
    if resp and resp.status_code == 200 and "text" in resp.headers.get("Content-Type", ""):
        out += f"\n[robots.txt]\n{resp.text[:3000]}\n"
        disallowed = re.findall(r'Disallow:\s*(.+)', resp.text)
        if disallowed:
            out += "\n[Disallowed paths — potential hidden endpoints]\n"
            for d in disallowed:
                out += f"  {d.strip()}\n"
    else:
        out += "\n[robots.txt] Not found or inaccessible.\n"

    time.sleep(delay)
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
# JS HARVESTING + ENDPOINT EXTRACTION
# ─────────────────────────────────────────────

JS_PATTERNS = {
    "API endpoints":    re.compile(r'["\']\/(?:api|v\d|graphql|rest|endpoint)[\/\w\-\.]*["\']', re.I),
    "URLs in JS":       re.compile(r'https?:\/\/[^\s\'"<>]{10,100}'),
    "Path strings":     re.compile(r'["\']\/[\w\-\/\.]{4,60}["\']'),
    "AWS keys":         re.compile(r'AKIA[0-9A-Z]{16}'),
    "Bearer tokens":    re.compile(r'[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}'),
    "API key patterns": re.compile(r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']?[\w\-]{10,}', re.I),
    "Private keys":     re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'),
}


def harvest_js(target: str, delay: float = 0) -> str:
    base = normalize(target)
    print(f"  [*] Harvesting JS files and extracting endpoints")

    resp = safe_fetch(base, delay=delay)
    if not resp:
        return f"[JS ANALYSIS]\n[!] Could not reach {base}\n"

    soup = BeautifulSoup(resp.text, "html.parser")
    script_urls   = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        full = src if src.startswith("http") else urljoin(base, src)
        script_urls.append(full)

    inline_scripts = [tag.string for tag in soup.find_all("script", src=False) if tag.string]

    out = f"[JS ANALYSIS — {base}]\n"
    out += f"Found {len(script_urls)} external JS files, {len(inline_scripts)} inline scripts\n"
    out += "─" * 50 + "\n"

    all_js = "\n".join(s for s in inline_scripts if s)

    for js_url in script_urls[:15]:
        out += f"\n[JS] {js_url}\n"
        time.sleep(delay)
        js_resp = fetch(js_url, timeout=10)
        if not js_resp:
            out += "  [!] Could not fetch\n"
            continue
        all_js += "\n" + js_resp.text
        out += f"  Size: {len(js_resp.content)/1024:.1f} KB\n"

    out += "\n[Extracted from JS]\n"
    found_anything = False
    for pattern_name, pattern in JS_PATTERNS.items():
        matches = list(set(pattern.findall(all_js)))[:20]
        if matches:
            found_anything = True
            out += f"\n  [{pattern_name}]\n"
            for m in matches:
                out += f"    {m}\n"

    if not found_anything:
        out += "  Nothing suspicious found.\n"

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

STATUS_LABELS = {
    200: "✓ OPEN",
    401: "🔒 AUTH REQUIRED",
    403: "⛔ FORBIDDEN",
    301: "→ REDIRECT",
    302: "→ REDIRECT",
}


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
        time.sleep(ACTIVE_DELAY)
        try:
            r = requests.head(url, headers=HEADERS, timeout=5,
                              verify=False, allow_redirects=False)
            if r.status_code in STATUS_LABELS:
                found.append((r.status_code, url))
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.Timeout:
            pass
        except Exception:
            pass

    if found:
        for code, url in found:
            label = STATUS_LABELS.get(code, str(code))
            out += f"  [{code}] {label}  {url}\n"
    else:
        out += "  No interesting paths found.\n"

    return out


# ─────────────────────────────────────────────
# TECH FINGERPRINT
# ─────────────────────────────────────────────

def fingerprint_tech(target: str, delay: float = 0) -> str:
    base = normalize(target)
    print(f"  [*] Fingerprinting technologies")

    resp = safe_fetch(base, delay=delay)
    if not resp:
        return f"[TECH FINGERPRINT]\n[!] Could not reach {base}\n"

    out = f"[TECH FINGERPRINT — {base}]\n"
    out += "─" * 50 + "\n"

    for h in ["Server", "X-Powered-By", "X-Generator", "X-Drupal-Cache",
              "X-WordPress-Cache", "X-Shopify-Stage"]:
        val = resp.headers.get(h)
        if val:
            out += f"  {h}: {val}\n"

    soup = BeautifulSoup(resp.text, "html.parser")
    gen  = soup.find("meta", attrs={"name": "generator"})
    if gen:
        out += f"  Meta Generator: {gen.get('content','')}\n"

    html = resp.text.lower()
    indicators = {
        "WordPress":  ["wp-content", "wp-includes"],
        "Drupal":     ["drupal", "/sites/default/"],
        "Laravel":    ["laravel_session", "laravel"],
        "Django":     ["csrfmiddlewaretoken", "django"],
        "React":      ["__react", "react-dom"],
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

    detected = [tech for tech, patterns in indicators.items()
                if any(p in html or p in str(resp.headers).lower() for p in patterns)]

    if detected:
        out += f"\n  Detected: {', '.join(detected)}\n"
    else:
        out += "\n  No known frameworks detected.\n"

    return out


# ─────────────────────────────────────────────
# FULL WEB RECON
# ─────────────────────────────────────────────

def run_web_recon(target: str, passive: bool = False) -> str:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    delay = PASSIVE_DELAY if passive else ACTIVE_DELAY

    if passive:
        print("  [*] Passive mode — rate limiting active (0.8s between requests)")

    results = []
    results.append(check_security_headers(target, delay=delay))
    results.append(check_robots(target, delay=delay))
    results.append(harvest_js(target, delay=delay))
    results.append(fingerprint_tech(target, delay=delay))
    results.append(probe_paths(target, passive=passive))

    return "\n\n".join(results)

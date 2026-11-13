"""Username search using the WhatsMyName (WMN) project data.
Why it is more reliable than Sherlock-style checks:
 - Every site needs BOTH a 'exists' signal (status code + page text) and no 'missing' signal.
 - Every site is verified once per 3 days with a known real account (must be found) and a random
   fake name (must NOT be found). Sites that fail either test are excluded from results, so a
   broken or lying site can't produce a wrong 'found'.
 - Blocked / captcha / rate-limited responses are never counted as found.
"""
import asyncio, json, os, random, string, time
import httpx
from . import tools

BASE = os.path.join(os.path.dirname(__file__), "..")
SITES_FILE = os.path.join(BASE, "wmn-data.json")
HEALTH_FILE = os.path.join(BASE, "wmn_health.json")
URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
           "Accept-Language": "en-US,en;q=0.9"}
WAF = ["Just a moment...", "Attention Required! | Cloudflare", "challenge-error-text", "AwsWafIntegration",
       "px-captcha", "Enable JavaScript and cookies to continue", "Checking your browser"]
QUICK_CATS = {"social"}
_health = {}

async def load_sites(force=False):
    if force or not os.path.exists(SITES_FILE) or time.time() - os.path.getmtime(SITES_FILE) > 7 * 86400:
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
                r = await c.get(URL)
            if r.status_code == 200 and '"sites"' in r.text:
                open(SITES_FILE, "w").write(r.text)
        except Exception:
            pass
    if not os.path.exists(SITES_FILE):
        raise ValueError("Site list missing. Connect to the internet and run: python update_sites.py")
    sites = json.load(open(SITES_FILE)).get("sites", [])
    return [s for s in sites if s.get("uri_check") and s.get("name")
            and "nsfw" not in str(s.get("cat", "")).lower() and "xx" not in str(s.get("cat", "")).lower()]

def sub(s, u):
    return s.replace("{account}", u) if isinstance(s, str) else s

async def probe(c, s, u):
    """'found', 'missing', 'unknown' or 'blocked'."""
    body = s.get("post_body")
    try:
        r = await c.request("POST" if body else "GET", sub(s["uri_check"], u), headers=s.get("headers") or None,
                            content=sub(body, u) if body else None)
    except Exception:
        return "blocked"
    text = r.text[:300000]
    if r.status_code in (403, 429, 503) or any(w in text[:20000] for w in WAF): return "blocked"
    ok = r.status_code == s.get("e_code") and (not s.get("e_string") or s["e_string"] in text)
    gone = (s.get("m_code") is not None and r.status_code == s["m_code"]) or bool(s.get("m_string") and s["m_string"] in text)
    if ok and not gone: return "found"
    return "missing" if gone else "unknown"

async def verify(c, s, fake):
    for k in (s.get("known") or [])[:2]:
        if await probe(c, s, k) == "found":
            return (await probe(c, s, fake)) in ("missing", "unknown")
    return False

def _load_health():
    global _health
    if not _health and os.path.exists(HEALTH_FILE):
        try:
            h = json.load(open(HEALTH_FILE))
            _health = h if time.time() - h.get("_ts", 0) < 3 * 86400 else {}
        except Exception:
            _health = {}
    return _health

async def scan(u, quick=False, prog=None):
    u = u.strip().lstrip("@")
    if not tools.USER_RE.match(u):
        raise ValueError("A username is one handle with no spaces, like rayana.tataeva or rayana_t. Full names are not usernames.")
    sites = await load_sites()
    total = len(sites)
    if quick: sites = [s for s in sites if str(s.get("cat", "")).lower() in QUICK_CATS]
    health = _load_health(); health.setdefault("_ts", time.time())
    fake = "zq" + "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    sem = asyncio.Semaphore(60)
    async def _one(c, s):
        async with sem:
            if s["name"] not in health:
                health[s["name"]] = await verify(c, s, fake)
            if not health[s["name"]]: return s, "excluded"
            return s, await probe(c, s, u)
    async def one(c, s):
        r = await _one(c, s)
        if prog is not None: prog["done"] += 1
        return r
    if prog is not None: prog["total"] = len(sites)
    async with httpx.AsyncClient(timeout=httpx.Timeout(12), headers=HEADERS, follow_redirects=True,
                                 limits=httpx.Limits(max_connections=80)) as c:
        rows = await asyncio.gather(*[one(c, s) for s in sites])
    json.dump(health, open(HEALTH_FILE, "w"))
    found = [{"site": s["name"], "category": s.get("cat", "other"), "url": sub(s.get("uri_pretty") or s["uri_check"], u)}
             for s, st in rows if st == "found"]
    return {"username": u, "sites_in_database": total,
            "sites_verified_and_checked": sum(1 for _, st in rows if st != "excluded"),
            "profiles_found": sorted(found, key=lambda r: (r["category"], r["site"].lower())),
            "blocked_or_uncertain": [s["name"] for s, st in rows if st == "blocked"]}

async def quick(u, prog=None): return await scan(u, quick=True, prog=prog)
async def deep(u, prog=None): return await scan(u, prog=prog)

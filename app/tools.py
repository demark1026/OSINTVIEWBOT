import asyncio, ipaddress, re
import dns.asyncresolver, httpx
from .config import HIBP_API_KEY

UA = {"User-Agent": "OSINTHubBot/1.0 (+passive lookups)"}
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
USER_RE = re.compile(r"^[A-Za-z0-9._-]{2,30}$")

def client():
    return httpx.AsyncClient(timeout=10, headers=UA, follow_redirects=False)

def clean_domain(d):
    d = d.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(d): raise ValueError("Enter a valid domain, like example.com")
    return d

async def ip_lookup(ip):
    a = ipaddress.ip_address(ip.strip())
    if not a.is_global: raise ValueError("Only public IP addresses can be looked up.")
    async with client() as c:
        j = (await c.get(f"https://ipwho.is/{a}")).json()
    if not j.get("success"): raise ValueError("No data for this IP.")
    conn = j.get("connection", {})
    return {"ip": str(a), "country": j.get("country"), "region": j.get("region"),
            "city": j.get("city"), "coordinates": f'{j.get("latitude")}, {j.get("longitude")}',
            "isp": conn.get("isp"), "organisation": conn.get("org"), "asn": conn.get("asn"),
            "timezone": (j.get("timezone") or {}).get("id")}

async def domain_lookup(domain):
    d = clean_domain(domain)
    r = dns.asyncresolver.Resolver(); r.lifetime = 5
    async def q(t):
        try: return sorted(str(x).rstrip(".") for x in await r.resolve(d, t))
        except Exception: return []
    a, aaaa, ns = await asyncio.gather(q("A"), q("AAAA"), q("NS"))
    out = {"domain": d, "ipv4": a, "ipv6": aaaa, "nameservers": ns}
    try:
        async with client() as c:
            rd = (await c.get(f"https://rdap.org/domain/{d}", follow_redirects=True)).json()
        ev = {e.get("eventAction"): e.get("eventDate") for e in rd.get("events", [])}
        out["created"], out["expires"] = ev.get("registration"), ev.get("expiration")
        for e in rd.get("entities", []):
            if "registrar" in e.get("roles", []):
                for item in e.get("vcardArray", [None, []])[1]:
                    if item[0] == "fn": out["registrar"] = item[3]
    except Exception:
        out["whois"] = "unavailable"
    return out

# (name, url, mode). "status" sites are reliable; the rest block bots, so we mark them uncertain.
SITES = [("GitHub", "https://api.github.com/users/{u}", "reliable"),
         ("Reddit", "https://www.reddit.com/user/{u}/about.json", "reliable"),
         ("X", "https://x.com/{u}", "uncertain"),
         ("Instagram", "https://www.instagram.com/{u}/", "uncertain"),
         ("TikTok", "https://www.tiktok.com/@{u}", "uncertain")]

async def username_check(u):
    u = u.strip().lstrip("@")
    if not USER_RE.match(u): raise ValueError("Usernames use letters, numbers, dots, dashes and underscores.")
    async def one(c, name, url, mode):
        try:
            s = (await c.get(url.format(u=u))).status_code
        except Exception:
            return {"site": name, "status": "error", "confidence": "none"}
        if s == 404: st = "available"
        elif s == 200: st = "taken"
        else: st = "unknown"
        conf = "likely" if mode == "reliable" and st != "unknown" else "uncertain"
        return {"site": name, "status": st, "confidence": conf}
    async with client() as c:
        return {"username": u, "results": await asyncio.gather(*[one(c, *s) for s in SITES])}

async def subdomains(domain):
    d = clean_domain(domain)
    async with client() as c:
        r = await c.get("https://crt.sh/", params={"q": f"%.{d}", "output": "json"}, timeout=25)
    names = set()
    for row in r.json():
        for n in row["name_value"].split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(d): names.add(n)
    return {"domain": d, "source": "certificate transparency (passive)", "count": len(names), "subdomains": sorted(names)[:500]}


# ---------- v2: bot-focused tools ----------
import socket

_tor = {"ts": 0, "ips": set()}
async def tor_check(ip):
    try:
        if time.time() - _tor["ts"] > 6 * 3600:
            async with client() as c:
                r = await c.get("https://check.torproject.org/torbulkexitlist", timeout=10)
            if r.status_code == 200:
                _tor["ips"] = set(r.text.split()); _tor["ts"] = time.time()
        return (ip in _tor["ips"]) if _tor["ips"] else None
    except Exception:
        return None

async def ip_geo_rdns(ip):
    d = await ip_lookup(ip)
    async def rdns():
        try: return (await asyncio.get_running_loop().run_in_executor(None, socket.gethostbyaddr, d["ip"]))[0]
        except Exception: return None
    async def second():
        try:
            async with client() as c:
                j = (await c.get(f"https://ipapi.co/{d['ip']}/json/")).json()
            return j.get("country_name")
        except Exception: return None
    d["reverse_dns"], other, tor = await asyncio.gather(rdns(), second(), tor_check(d["ip"]))
    if other:
        d["location_confidence"] = "2 sources agree on the country" if other == d["country"] else f"sources disagree (second source says {other})"
    if tor is not None: d["tor_exit_node"] = "yes" if tor else "no"
    return d

async def ip_exposure(ip):
    """Passive: Shodan InternetDB data. Nothing is scanned by us."""
    a = ipaddress.ip_address(ip.strip())
    if not a.is_global: raise ValueError("Only public IP addresses can be looked up.")
    async with client() as c:
        r = await c.get(f"https://internetdb.shodan.io/{a}")
    if r.status_code == 404: return {"ip": str(a), "result": "No exposure data indexed for this IP."}
    j = r.json()
    return {"ip": str(a), "open_ports_flagged": j.get("ports"), "hostnames": j.get("hostnames"),
            "tags": j.get("tags"), "known_cves": j.get("vulns"), "software_cpes": j.get("cpes"),
            "note": "Passive index data. It may be days old, so treat as flags, not proof."}

async def dns_full(domain):
    d = clean_domain(domain)
    r = dns.asyncresolver.Resolver(); r.lifetime = 5
    async def q(name, t):
        try: return sorted(x.to_text().strip('"') for x in await r.resolve(name, t))
        except Exception: return []
    types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]
    res = await asyncio.gather(*[q(d, t) for t in types], q("_dmarc." + d, "TXT"))
    out = {"domain": d}
    for t, v in zip(types, res[:-1]): out[t] = v
    out["DMARC"] = res[-1]
    return out

# (site, url). 200 = found, 404 = not found. Anything else is ignored (never guessed).
DEEP = [
 ("GitHub","https://api.github.com/users/{u}"),("GitLab","https://gitlab.com/api/v4/users?username={u}#json"),
 ("Bitbucket","https://api.bitbucket.org/2.0/users/{u}"),("Reddit","https://www.reddit.com/user/{u}/about.json"),
 ("Keybase","https://keybase.io/{u}"),("Dev.to","https://dev.to/api/users/by_username?url={u}"),
 ("Medium","https://medium.com/@{u}"),("Replit","https://replit.com/@{u}"),
 ("CodePen","https://codepen.io/{u}"),("Docker Hub","https://hub.docker.com/v2/users/{u}/"),
 ("npm","https://www.npmjs.com/~{u}"),("PyPI","https://pypi.org/user/{u}/"),
 ("Gravatar","https://en.gravatar.com/{u}.json"),("Chess.com","https://api.chess.com/pub/player/{u}"),
 ("Lichess","https://lichess.org/api/user/{u}"),("Mastodon.social","https://mastodon.social/@{u}"),
 ("Pinterest","https://www.pinterest.com/{u}/"),("SoundCloud","https://soundcloud.com/{u}"),
 ("Vimeo","https://vimeo.com/{u}"),("Wikipedia","https://en.wikipedia.org/wiki/User:{u}"),
 ("Patreon","https://www.patreon.com/{u}"),("Linktree","https://linktr.ee/{u}"),
 ("Kaggle","https://www.kaggle.com/{u}"),("HackerOne","https://hackerone.com/{u}"),
 ("Last.fm","https://www.last.fm/user/{u}"),("Imgur","https://imgur.com/user/{u}"),
 ("Scratch","https://api.scratch.mit.edu/users/{u}"),("Wattpad","https://www.wattpad.com/user/{u}"),
 ("DeviantArt","https://www.deviantart.com/{u}"),("Behance","https://www.behance.net/{u}"),
 ("Dribbble","https://dribbble.com/{u}"),("About.me","https://about.me/{u}"),
 ("Itch.io","https://{u}.itch.io/"),("Newgrounds","https://{u}.newgrounds.com/"),
 ("Hashnode","https://hashnode.com/@{u}"),("Codeberg","https://codeberg.org/{u}"),
 ("Sourcehut","https://sr.ht/~{u}/"),("Launchpad","https://launchpad.net/~{u}"),
 ("Trello","https://trello.com/{u}"),("Telegram (t.me)","https://t.me/{u}"),
]

async def deep_username(u):
    u = u.strip().lstrip("@")
    if not USER_RE.match(u): raise ValueError("Usernames use letters, numbers, dots, dashes and underscores.")
    sem = asyncio.Semaphore(10)
    async def one(c, site, url):
        async with sem:
            try:
                r = await c.get(url.format(u=u))
            except Exception:
                return site, "error", url
            ok = r.status_code == 200
            if site.startswith("GitLab"): ok = ok and r.text.strip() not in ("[]", "")
            if site.startswith("Telegram"): ok = ok and "tgme_page_title" in r.text and "tgme_page_extra" in r.text
            return site, ("found" if ok else "missing" if r.status_code == 404 or site.startswith(("GitLab","Telegram")) else "error"), url.format(u=u).split("#")[0]
    async with client() as c:
        rows = await asyncio.gather(*[one(c, s, x) for s, x in DEEP])
    found = [{"site": s, "url": x} for s, st, x in rows if st == "found"]
    return {"username": u, "sites_checked": len(DEEP), "profiles_found": found,
            "could_not_check": [s for s, st, _ in rows if st == "error"],
            "note": "A match means a profile page exists with this name, not that it is the same person. Open the link to verify."}

# ---------- v3: more tools ----------
import hashlib
from urllib.parse import urlparse

DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "yopmail.com",
              "trashmail.com", "sharklasers.com", "getnada.com", "maildrop.cc", "throwawaymail.com", "temp-mail.org"}
FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com",
             "aol.com", "gmx.com", "mail.com", "zoho.com", "yandex.com", "live.com"}

async def email_intel(email):
    e = email.strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e): raise ValueError("Enter a valid email address.")
    dom = clean_domain(e.split("@")[1])
    r = dns.asyncresolver.Resolver(); r.lifetime = 5
    async def q(name, t):
        try: return [x.to_text().strip('"') for x in await r.resolve(name, t)]
        except Exception: return []
    mx, txt, dmarc = await asyncio.gather(q(dom, "MX"), q(dom, "TXT"), q("_dmarc." + dom, "TXT"))
    h = hashlib.md5(e.encode()).hexdigest()
    out = {"email": e, "domain": dom,
           "domain_can_receive_mail": bool(mx), "mail_servers": sorted(x.split()[-1].rstrip(".") for x in mx),
           "provider_type": "disposable (temporary)" if dom in DISPOSABLE else "free webmail" if dom in FREE_MAIL else "custom domain",
           "spf": any(t.startswith("v=spf1") for t in txt), "dmarc": bool(dmarc)}
    async with client() as c:
        try:
            g = await c.get(f"https://gravatar.com/avatar/{h}?d=404", follow_redirects=True)
            out["gravatar_profile_exists"] = g.status_code == 200
            if g.status_code == 200:
                p = await c.get(f"https://en.gravatar.com/{h}.json", follow_redirects=True)
                if p.status_code == 200:
                    ent = p.json()["entry"][0]
                    out["gravatar_name"] = ent.get("displayName") or None
                    out["gravatar_url"] = ent.get("profileUrl")
        except Exception:
            out["gravatar_profile_exists"] = "unknown"
    out["note"] = "Passive checks only. I can't confirm a mailbox exists. For breach exposure use /breach."
    return out

async def _public_host(host):
    infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    ips = {i[4][0].split("%")[0] for i in infos}
    if not ips or not all(ipaddress.ip_address(i).is_global for i in ips):
        raise ValueError("That is not a public website address.")

SEC = ["strict-transport-security", "content-security-policy", "x-frame-options",
       "x-content-type-options", "referrer-policy", "permissions-policy"]

async def web_headers(target):
    t = target.strip()
    if not t.startswith(("http://", "https://")): t = "https://" + t
    host = urlparse(t).hostname
    if not host: raise ValueError("Enter a website like example.com")
    try: ipaddress.ip_address(host)
    except ValueError: host = clean_domain(host)
    try: await _public_host(host)
    except OSError: raise ValueError("Could not resolve that website.")
    async with httpx.AsyncClient(timeout=10, follow_redirects=False,
                                 headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"}) as c:
        async with c.stream("GET", t) as r:
            body = b""
            async for ch in r.aiter_bytes():
                body += ch
                if len(body) > 200000: break
            h, status = r.headers, r.status_code
    page = body.decode("utf-8", "ignore")
    title = re.search(r"<title[^>]*>(.*?)</title>", page, re.I | re.S)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', page, re.I)
    return {"url": t, "status": status, "redirects_to": h.get("location"), "server": h.get("server"),
            "powered_by": h.get("x-powered-by"), "technology_hint": gen.group(1) if gen else None,
            "page_title": " ".join(title.group(1).split())[:120] if title else None,
            "security_headers_present": [x for x in SEC if x in h], "security_headers_missing": [x for x in SEC if x not in h]}

async def archive_lookup(target):
    t = target.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    if not t or " " in t: raise ValueError("Enter a domain or URL.")
    async def cdx(limit):
        async with client() as c:
            r = await c.get("https://web.archive.org/cdx/search/cdx", timeout=20,
                            params={"url": t, "output": "json", "limit": limit, "fl": "timestamp,original,statuscode"})
        rows = r.json() if r.text.strip() else []
        if len(rows) < 2: return None
        ts, orig, code = rows[1]
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} (HTTP {code}) https://web.archive.org/web/{ts}/{orig}"
    first, last = await asyncio.gather(cdx(1), cdx(-1))
    if not first: return {"target": t, "result": "No snapshots found in the Wayback Machine."}
    return {"target": t, "first_snapshot": first, "latest_snapshot": last}

async def mac_lookup(mac):
    m = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(m) < 6: raise ValueError("Enter a MAC address like 00:1A:2B:3C:4D:5E")
    async with client() as c:
        r = await c.get(f"https://api.macvendors.com/{':'.join(m[i:i+2] for i in range(0, min(len(m), 12), 2))}")
    return {"mac": mac.strip(), "vendor": r.text.strip() if r.status_code == 200 else "Not found in the vendor database",
            "note": "This is the hardware maker, not the owner. Phones often randomize their MAC."}

async def phone_info(num):
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone
    except ImportError:
        raise ValueError("Phone support is not installed. Run: pip install phonenumbers")
    try:
        n = phonenumbers.parse(num.strip(), None)
    except Exception:
        raise ValueError("Send it in international format, like +14155552671")
    kinds = {0: "fixed line", 1: "mobile", 2: "fixed line or mobile", 3: "toll free", 4: "premium rate", 5: "shared cost",
             6: "VoIP", 7: "personal", 8: "pager", 9: "UAN", 10: "voicemail", 99: "unknown"}
    return {"number": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "valid_number": phonenumbers.is_valid_number(n), "country_or_region": geocoder.description_for_number(n, "en") or None,
            "line_type": kinds.get(phonenumbers.number_type(n), "unknown"),
            "original_carrier": carrier.name_for_number(n, "en") or None,
            "timezones": list(timezone.time_zones_for_number(n)),
            "note": "Offline data. Carrier is the original assignment (numbers can be ported). It can't tell who owns the number."}


# ---------- v4: more accurate / extra tools ----------
import time, ssl, html as _html

async def ssl_info(domain):
    d = clean_domain(domain)
    try: await _public_host(d)
    except OSError: raise ValueError("Could not resolve that domain.")
    def fetch():
        ctx = ssl.create_default_context()
        with socket.create_connection((d, 443), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=d) as ss:
                return ss.getpeercert(), ss.version()
    try:
        cert, ver = await asyncio.get_running_loop().run_in_executor(None, fetch)
    except ssl.SSLCertVerificationError as e:
        return {"domain": d, "certificate_valid": False, "problem": e.verify_message}
    except Exception:
        raise ValueError("Could not connect to port 443 on that domain.")
    iss = dict(x[0] for x in cert.get("issuer", ())); sub = dict(x[0] for x in cert.get("subject", ()))
    end = ssl.cert_time_to_seconds(cert["notAfter"])
    return {"domain": d, "certificate_valid": True, "issued_to": sub.get("commonName"),
            "issuer": iss.get("organizationName") or iss.get("commonName"),
            "valid_from": cert["notBefore"], "valid_until": cert["notAfter"], "days_left": int((end - time.time()) / 86400),
            "alt_names": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:40], "tls_version": ver}

async def tg_lookup(u):
    u = u.strip().lstrip("@")
    if not re.match(r"^[A-Za-z][A-Za-z0-9_]{3,31}$", u): raise ValueError("Telegram usernames are 4-32 letters, numbers or underscores.")
    async with client() as c:
        r = await c.get(f"https://t.me/{u}", follow_redirects=True)
    p = r.text
    name = re.search(r'class="tgme_page_title"[^>]*>\s*<span[^>]*>(.*?)</span>', p, re.S)
    if not name: return {"username": "@" + u, "exists": False, "note": "No public Telegram page with this username."}
    desc = re.search(r'<meta property="og:description" content="([^"]*)"', p)
    extra = re.search(r'class="tgme_page_extra"[^>]*>(.*?)</div>', p, re.S)
    ex = _html.unescape(re.sub(r"<[^>]+>", "", extra.group(1))).strip() if extra else None
    kind = "channel" if ex and "subscriber" in ex else "group" if ex and "member" in ex else "user or bot"
    bio = _html.unescape(desc.group(1)).strip() if desc else None
    return {"username": "@" + u, "exists": True, "type": kind, "name": _html.unescape(re.sub(r"<[^>]+>", "", name.group(1))).strip(),
            "audience": ex if kind != "user or bot" else None, "bio": bio if bio and not bio.startswith("If you have Telegram") else None,
            "link": f"https://t.me/{u}", "note": "Only what the owner made public. Telegram hides everything else."}

async def github_user(u):
    u = u.strip().lstrip("@")
    if not re.match(r"^[A-Za-z0-9-]{1,39}$", u): raise ValueError("Enter a GitHub username.")
    async with client() as c:
        r = await c.get(f"https://api.github.com/users/{u}", headers={**UA, "Accept": "application/vnd.github+json"})
    if r.status_code == 404: raise ValueError("No GitHub user with that name.")
    if r.status_code in (403, 429): raise ValueError("GitHub's rate limit was reached. Try again in a few minutes.")
    j = r.json()
    return {"login": j["login"], "type": j.get("type"), "name": j.get("name"), "company": j.get("company"),
            "location": j.get("location"), "website": j.get("blog") or None, "bio": j.get("bio"),
            "twitter": j.get("twitter_username"), "public_repos": j.get("public_repos"), "followers": j.get("followers"),
            "following": j.get("following"), "account_created": j.get("created_at"), "profile": j.get("html_url")}

async def btc_lookup(addr):
    a = addr.strip()
    if not re.match(r"^(bc1[a-z0-9]{20,70}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$", a): raise ValueError("Enter a valid Bitcoin address.")
    async with client() as c:
        r = await c.get(f"https://blockstream.info/api/address/{a}")
    if r.status_code != 200: raise ValueError("Address not found or invalid.")
    j = r.json(); cs, ms = j["chain_stats"], j["mempool_stats"]
    rec, sp = cs["funded_txo_sum"] / 1e8, cs["spent_txo_sum"] / 1e8
    return {"address": a, "balance_btc": round(rec - sp, 8), "total_received_btc": round(rec, 8),
            "transactions": cs["tx_count"], "pending_transactions": ms["tx_count"],
            "explorer": f"https://blockstream.info/address/{a}"}

async def reverse_ip(ip):
    a = ipaddress.ip_address(ip.strip())
    if not a.is_global: raise ValueError("Only public IP addresses can be looked up.")
    async with client() as c:
        r = await c.get("https://api.hackertarget.com/reverseiplookup/", params={"q": str(a)})
    txt = r.text.strip()
    if "API count exceeded" in txt: raise ValueError("The free daily limit for this source is used up. Try again tomorrow.")
    doms = [x for x in txt.splitlines() if "." in x and " " not in x] if not txt.lower().startswith(("no dns", "error")) else []
    return {"ip": str(a), "domains_on_this_ip": len(doms), "domains": doms[:200],
            "note": "Shared hosting means unrelated sites can share one IP."}


# ---------- v5: breach checks without a paid key, plus new tools ----------
from urllib.parse import urljoin

async def _email_breaches(e):
    found, sources = {}, []
    async with client() as c:
        try:
            r = await c.get(f"https://api.xposedornot.com/v1/check-email/{e}")
            if r.status_code == 429: raise ValueError("The breach source is rate-limited. Try again in a minute.")
            if r.status_code in (200, 404):
                sources.append("XposedOrNot")
                if r.status_code == 200:
                    names = r.json().get("breaches") or []
                    names = names[0] if names and isinstance(names[0], list) else names
                    for n in names: found[n] = {"name": n}
        except ValueError:
            raise
        except Exception:
            pass
        if found:
            try:
                r = await c.get("https://api.xposedornot.com/v1/breach-analytics", params={"email": e})
                if r.status_code == 200:
                    for b in (r.json().get("ExposedBreaches") or {}).get("breaches_details", []):
                        if not b.get("breach"): continue
                        item = {"name": b["breach"], "date": str(b.get("xposed_date") or "")[:10],
                                "data": (b.get("xposed_data") or "").replace(";", ", "), "records": b.get("xposed_records")}
                        found[b["breach"]] = {k: v for k, v in item.items() if v}
            except Exception:
                pass
        if HIBP_API_KEY:
            try:
                r = await c.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{e}", params={"truncateResponse": "false"},
                                headers={**UA, "hibp-api-key": HIBP_API_KEY})
                if r.status_code in (200, 404): sources.append("Have I Been Pwned")
                if r.status_code == 200:
                    for b in r.json():
                        found.setdefault(b["Name"], {"name": b["Name"], "date": b["BreachDate"], "data": ", ".join(b["DataClasses"])})
            except Exception:
                pass
    if not sources: raise ValueError("The breach sources did not respond. Try again later.")
    return {"email": e, "found_in_breaches": bool(found), "breach_count": len(found),
            "breaches": list(found.values())[:60], "sources_checked": sources,
            "note": "Only check addresses you own or have permission to check. No breach found does not mean the address is safe."}

async def _domain_breaches(d):
    async with client() as c:
        r = await c.get("https://haveibeenpwned.com/api/v3/breaches", params={"domain": d})
    if r.status_code != 200: raise ValueError("The breach list did not respond. Try again later.")
    rows = [{"name": b["Title"], "date": b["BreachDate"], "accounts": b["PwnCount"], "data": ", ".join(b["DataClasses"][:6])} for b in r.json()]
    return {"domain": d, "breaches_of_this_service": len(rows), "breaches": rows,
            "note": "These are breaches of the website itself, from Have I Been Pwned's public list."}

async def breach_check(target):
    t = target.strip()
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", t): return await _email_breaches(t.lower())
    d = re.sub(r"^https?://", "", t.lower()).split("/")[0]
    if DOMAIN_RE.match(d): return await _domain_breaches(d)
    raise ValueError("Send an email address (you@example.com) or a website domain (adobe.com). For passwords use /pwned. Usernames can't be checked in free breach sources.")

async def pwned_password(p):
    p = p.strip()
    if re.fullmatch(r"[0-9a-fA-F]{40}", p): sha, kind = p.upper(), "SHA-1 hash"
    else: sha, kind = hashlib.sha1(p.encode()).hexdigest().upper(), "password"
    async with client() as c:
        r = await c.get(f"https://api.pwnedpasswords.com/range/{sha[:5]}", headers={**UA, "Add-Padding": "true"})
    if r.status_code != 200: raise ValueError("The password service did not respond. Try again later.")
    count = 0
    for line in r.text.splitlines():
        suf, _, n = line.partition(":")
        if suf.strip() == sha[5:]: count = int(n)
    return {"checked": kind, "found_in_breaches": count > 0, "times_seen": count,
            "advice": "Do not use this password anywhere." if count else "Not found in known breaches. That does not make it strong.",
            "privacy": "Only the first 5 characters of the hash were sent. The password never left this machine."}

async def cve_lookup(q):
    cid = q.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", cid): raise ValueError("Enter a CVE ID like CVE-2024-3094.")
    async with client() as c:
        r = await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cid}, timeout=25)
    if r.status_code in (403, 429): raise ValueError("The vulnerability database is rate-limited. Try again in a minute.")
    v = r.json().get("vulnerabilities", []) if r.status_code == 200 else []
    if not v: raise ValueError("No such CVE found.")
    c0 = v[0]["cve"]; score = sev = vec = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = c0.get("metrics", {}).get(key)
        if m:
            d = m[0]["cvssData"]; score, vec = d.get("baseScore"), d.get("vectorString")
            sev = d.get("baseSeverity") or m[0].get("baseSeverity"); break
    desc = next((x["value"] for x in c0.get("descriptions", []) if x["lang"] == "en"), None)
    return {"cve": cid, "severity": sev, "cvss_score": score, "vector": vec, "published": c0.get("published", "")[:10],
            "status": c0.get("vulnStatus"), "description": (desc or "")[:700], "references": [x["url"] for x in c0.get("references", [])[:5]]}

async def ip_whois(ip):
    a = ipaddress.ip_address(ip.strip())
    if not a.is_global: raise ValueError("Only public IP addresses can be looked up.")
    async with client() as c:
        r = await c.get(f"https://rdap.org/ip/{a}", follow_redirects=True, timeout=15)
    if r.status_code != 200: raise ValueError("No registration data found for this IP.")
    j = r.json(); abuse, names = set(), []
    def walk(ents):
        for e in ents or []:
            vc = (e.get("vcardArray") or [None, []])[1]
            fn = next((i[3] for i in vc if i[0] == "fn"), None)
            if "abuse" in e.get("roles", []): abuse.update(i[3] for i in vc if i[0] == "email")
            elif fn: names.append(fn)
            walk(e.get("entities"))
    walk(j.get("entities"))
    ev = {x.get("eventAction"): x.get("eventDate") for x in j.get("events", [])}
    return {"ip": str(a), "network_name": j.get("name"), "organisation": names[0] if names else None, "handle": j.get("handle"),
            "country": j.get("country"), "range": f"{j.get('startAddress')} - {j.get('endAddress')}",
            "cidr": [f"{x.get('v4prefix') or x.get('v6prefix')}/{x.get('length')}" for x in j.get("cidr0_cidrs", [])],
            "registered": (ev.get("registration") or "")[:10] or None, "abuse_contact": sorted(abuse)}

async def location_lookup(q):
    m = re.match(r"^\s*(-?\d{1,2}(?:\.\d+)?)\s*[,; ]\s*(-?\d{1,3}(?:\.\d+)?)\s*$", q)
    if not m or abs(float(m.group(1))) > 90 or abs(float(m.group(2))) > 180: raise ValueError("Send coordinates like 48.8584, 2.2945")
    lat, lon = float(m.group(1)), float(m.group(2))
    async with client() as c:
        r = await c.get("https://nominatim.openstreetmap.org/reverse",
                        params={"lat": lat, "lon": lon, "format": "jsonv2", "zoom": 14, "addressdetails": 1})
    j = r.json()
    if "error" in j: raise ValueError("No place found at those coordinates (sea or unmapped area).")
    a = j.get("address", {})
    return {"coordinates": f"{lat}, {lon}", "area": j.get("display_name"), "city": a.get("city") or a.get("town") or a.get("village"),
            "country": a.get("country"), "map": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}",
            "note": "Neighbourhood-level result only, from OpenStreetMap."}

async def unshorten(url):
    u = url.strip()
    if not u.startswith(("http://", "https://")): u = "https://" + u
    chain, status = [u], None
    async with httpx.AsyncClient(timeout=8, follow_redirects=False, headers=UA) as c:
        for _ in range(8):
            host = urlparse(chain[-1]).hostname
            if not host: raise ValueError("That does not look like a link.")
            try: await _public_host(host)
            except OSError: raise ValueError("Could not resolve " + host)
            r = await c.head(chain[-1])
            if r.status_code in (400, 403, 405, 501):
                async with c.stream("GET", chain[-1]) as g: status, loc = g.status_code, g.headers.get("location")
            else: status, loc = r.status_code, r.headers.get("location")
            if status in (301, 302, 303, 307, 308) and loc: chain.append(urljoin(chain[-1], loc))
            else: break
    return {"original": u, "final_url": chain[-1], "redirect_hops": len(chain) - 1, "chain": chain,
            "final_status": status, "note": "I only followed redirects. I never opened the final page."}

async def urlscan_search(target):
    d = re.sub(r"^https?://", "", target.strip().lower()).split("/")[0]
    d = clean_domain(d)
    async with client() as c:
        r = await c.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{d}", "size": 10}, timeout=20)
    if r.status_code == 429: raise ValueError("The scan archive is rate-limited. Try again in a minute.")
    if r.status_code != 200: raise ValueError("The scan archive did not respond.")
    j = r.json()
    rows = [{"date": (x["task"].get("time") or "")[:10], "ip": x["page"].get("ip"), "country": x["page"].get("country"),
             "result": f"https://urlscan.io/result/{x['_id']}/"} for x in j.get("results", [])]
    return {"domain": d, "public_scans_found": j.get("total"), "recent_scans": rows,
            "note": "Past public scans of this domain from urlscan.io, with screenshots on each result page."}

def image_report(data):
    """Returns (report dict, ELA image bytes or None). No face recognition: only technical analysis."""
    import io
    from PIL import Image, ImageChops
    img = Image.open(io.BytesIO(data)); ex = img.getexif()
    out = {"format": img.format, "size": f"{img.width}x{img.height}", "file_size_kb": round(len(data) / 1024, 1),
           "md5": hashlib.md5(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest()}
    for k, n in {271: "camera_make", 272: "camera_model", 305: "software", 306: "modified", 315: "artist", 33432: "copyright"}.items():
        if ex.get(k): out[n] = str(ex.get(k)).strip()
    sub = ex.get_ifd(0x8769)
    for k, n in {36867: "taken", 42036: "lens", 34855: "iso", 33437: "f_number", 33434: "exposure_time", 37386: "focal_length"}.items():
        if sub.get(k) is not None: out[n] = str(sub[k]).strip()
    g = ex.get_ifd(0x8825)
    if g.get(2) and g.get(4):
        def deg(v, ref):
            d = float(v[0]) + float(v[1]) / 60 + float(v[2]) / 3600
            return -d if ref in ("S", "W") else d
        lat, lon = deg(g[2], g.get(1)), deg(g[4], g.get(3))
        out["gps"] = f"{lat:.6f}, {lon:.6f}"; out["map"] = f"https://maps.google.com/?q={lat:.6f},{lon:.6f}"
        if g.get(6) is not None: out["altitude_m"] = round(float(g[6]), 1)
    px = list(img.convert("L").resize((8, 8)).getdata()); avg = sum(px) / 64
    out["perceptual_hash"] = f"{int(''.join('1' if p > avg else '0' for p in px), 2):016x}"
    ela = None
    if img.format == "JPEG":
        rgb = img.convert("RGB"); buf = io.BytesIO(); rgb.save(buf, "JPEG", quality=90); buf.seek(0)
        diff = ImageChops.difference(rgb, Image.open(buf).convert("RGB"))
        mx = max(e[1] for e in diff.getextrema()) or 1
        e = diff.point(lambda p: min(255, int(p * 255.0 / mx))); e.thumbnail((1600, 1600))
        b = io.BytesIO(); e.save(b, "PNG"); ela = b.getvalue()
        out["error_level_analysis"] = "See the attached image. Bright uneven patches can hint at editing, but this is not proof."
    try:
        import pytesseract
        txt = pytesseract.image_to_string(img).strip()
        out["text_in_image"] = txt[:700] if txt else "no readable text found"
    except Exception:
        out["text_in_image"] = "OCR not installed (optional): sudo apt install tesseract-ocr, then pip install pytesseract"
    if not any(k in out for k in ("camera_make", "camera_model", "taken", "gps", "software")):
        out["metadata"] = "No camera or location data. It was probably stripped."
    return out, ela

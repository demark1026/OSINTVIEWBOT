"""Extra OSINT tools: live flights, QR reader, image search, decoder, email security,
lookalike domains, tech stack, sun position, past weather, ASN, ID dates, Discord invites."""
import asyncio, base64, binascii, codecs, difflib, io, ipaddress, json, math, re, time
import urllib.parse as up
from datetime import datetime, timedelta, timezone
import httpx, dns.asyncresolver, dns.resolver
from .tools import client, UA, clean_domain, _public_host
from .config import GOOGLE_VISION_KEY

# ====================== LIVE FLIGHTS ======================
_AIR = """UAL|UA|United Airlines
AAL|AA|American Airlines
DAL|DL|Delta Air Lines
SWA|WN|Southwest Airlines
JBU|B6|JetBlue
ASA|AS|Alaska Airlines
NKS|NK|Spirit Airlines
FFT|F9|Frontier Airlines
HAL|HA|Hawaiian Airlines
ACA|AC|Air Canada
WJA|WS|WestJet
AMX|AM|Aeromexico
CMP|CM|Copa Airlines
AVA|AV|Avianca
LAN|LA|LATAM Airlines
TAM|JJ|LATAM Brasil
GLO|G3|Gol
AZU|AD|Azul
ARG|AR|Aerolineas Argentinas
BAW|BA|British Airways
VIR|VS|Virgin Atlantic
EZY|U2|easyJet
RYR|FR|Ryanair
WZZ|W6|Wizz Air
AFR|AF|Air France
KLM|KL|KLM
DLH|LH|Lufthansa
EWG|EW|Eurowings
SWR|LX|Swiss
AUA|OS|Austrian Airlines
BEL|SN|Brussels Airlines
IBE|IB|Iberia
VLG|VY|Vueling
TAP|TP|TAP Air Portugal
ITY|AZ|ITA Airways
SAS|SK|SAS Scandinavian
FIN|AY|Finnair
NAX|DY|Norwegian
EIN|EI|Aer Lingus
LOT|LO|LOT Polish Airlines
AFL|SU|Aeroflot
THY|TK|Turkish Airlines
PGT|PC|Pegasus
AEE|A3|Aegean Airlines
AUI|PS|Ukraine International
UAE|EK|Emirates
QTR|QR|Qatar Airways
ETD|EY|Etihad
FDB|FZ|flydubai
ABY|G9|Air Arabia
SVA|SV|Saudia
KNE|XY|flynas
GFA|GF|Gulf Air
OMA|WY|Oman Air
KAC|KU|Kuwait Airways
RJA|RJ|Royal Jordanian
MEA|ME|Middle East Airlines
ELY|LY|El Al
IRA|IR|Iran Air
IRM|W5|Mahan Air
MSR|MS|EgyptAir
RAM|AT|Royal Air Maroc
DAH|AH|Air Algerie
TAR|TU|Tunisair
ETH|ET|Ethiopian Airlines
KQA|KQ|Kenya Airways
SAA|SA|South African Airways
RWD|WB|RwandAir
KZR|KC|Air Astana
SIA|SQ|Singapore Airlines
CPA|CX|Cathay Pacific
CAL|CI|China Airlines
EVA|BR|EVA Air
JAL|JL|Japan Airlines
ANA|NH|All Nippon Airways
KAL|KE|Korean Air
AAR|OZ|Asiana Airlines
CCA|CA|Air China
CES|MU|China Eastern
CSN|CZ|China Southern
CHH|HU|Hainan Airlines
THA|TG|Thai Airways
MAS|MH|Malaysia Airlines
AXM|AK|AirAsia
GIA|GA|Garuda Indonesia
PAL|PR|Philippine Airlines
CEB|5J|Cebu Pacific
HVN|VN|Vietnam Airlines
VJC|VJ|VietJet Air
AIC|AI|Air India
IGO|6E|IndiGo
SEJ|SG|SpiceJet
PIA|PK|Pakistan International
BBC|BG|Biman Bangladesh
ALK|UL|SriLankan Airlines
QFA|QF|Qantas
VOZ|VA|Virgin Australia
JST|JQ|Jetstar
ANZ|NZ|Air New Zealand
FDX|FX|FedEx
UPS|5X|UPS Airlines
GTI|5Y|Atlas Air
CLX|CV|Cargolux"""
AIR, AIR_IATA = {}, {}
for _l in _AIR.splitlines():
    _i, _a, _n = _l.split("|"); AIR[_i] = (_n, _a); AIR_IATA.setdefault(_a, _i)

def _norm(s): return re.sub(r"[^a-z0-9 ]", "", s.lower()).strip()

def find_airline(text):
    t = _norm(text)
    if len(t) < 3 or t in {"air", "airline", "airlines", "airways", "flight", "flights"}: return None
    names = {_norm(v[0]): k for k, v in AIR.items()}
    if t in names: return names[t]
    hits = sorted((n for n in names if len(t) >= 4 and (t in n or n in t)), key=len)
    if hits: return names[hits[0]]
    m = difflib.get_close_matches(t, list(names), n=1, cutoff=0.62)
    return names[m[0]] if m else None

_os = {"ts": 0, "states": []}
ADSB_BASES = ["https://api.adsb.lol", "https://api.airplanes.live"]

async def _fetch(url, timeout=20):
    """(status, json) or (None, None) if the site could not be reached."""
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=UA, follow_redirects=True) as c:
            r = await c.get(url)
        try: return r.status_code, r.json()
        except Exception: return r.status_code, None
    except Exception:
        return None, None

async def _adsb(path):
    """Aircraft list from community ADS-B networks. None = none of them answered."""
    answered = False
    for base in ADSB_BASES:
        st, j = await _fetch(base + path, 15)
        if st == 200 and isinstance(j, dict) and isinstance(j.get("ac"), list):
            if j["ac"]: return j["ac"]
            answered = True
    return [] if answered else None

async def _opensky():
    if time.time() - _os["ts"] < 45 and _os["states"]: return _os["states"]
    last = "no answer"
    for _ in range(2):
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(70, connect=15), headers=UA) as c:
                r = await c.get("https://opensky-network.org/api/states/all")
            if r.status_code == 429: raise ValueError("The airline-wide flight source is rate-limited right now. Try again in a minute.")
            if r.status_code == 200:
                try: data = r.json()
                except Exception: data = None
                if isinstance(data, dict):
                    _os["states"] = data.get("states") or []; _os["ts"] = time.time()
                    return _os["states"]
                last = "bad reply"
            else: last = f"HTTP {r.status_code}"
        except ValueError: raise
        except httpx.TimeoutException: last = "timed out"
        except Exception: last = "could not connect"
        await asyncio.sleep(2)
    raise ValueError(f"The airline-wide flight source failed ({last}). Try again in a minute, or search one exact flight like UAL123.")

def _from_adsb(a):
    alt = a.get("alt_baro"); gnd = alt == "ground"
    alt_m = None if gnd or not isinstance(alt, (int, float)) else alt * 0.3048
    ga = a.get("alt_geom"); gs = a.get("gs")
    return [a.get("hex"), (a.get("flight") or "").strip(), None, None, None, a.get("lon"), a.get("lat"), alt_m, gnd,
            gs * 0.514444 if isinstance(gs, (int, float)) else None, a.get("track"), None, None,
            ga * 0.3048 if isinstance(ga, (int, float)) else None, a.get("squawk"), False, 0, 0, a.get("r"), a.get("t")]

async def _hexdb(icao24):
    try:
        async with client() as c: r = await c.get(f"https://hexdb.io/api/v1/aircraft/{icao24}")
        if r.status_code == 200:
            j = r.json()
            d = {"registration": j.get("Registration"), "aircraft_type": " ".join(x for x in [j.get("Manufacturer"), j.get("Type")] if x) or j.get("ICAOTypeCode"),
                 "owner": j.get("RegisteredOwners")}
            return {k: v for k, v in d.items() if v}
    except Exception:
        pass
    return {}

def _row(s):
    cs = (s[1] or "").strip() or "(no callsign)"
    alt = s[13] if s[13] is not None else s[7]
    ft = "on the ground" if s[8] else (f"{int(alt * 3.28084):,} ft" if alt is not None else "altitude unknown")
    spd = f"{int(s[9] * 3.6)} km/h" if s[9] is not None else "speed unknown"
    hd = f" · heading {int(s[10])}°" if s[10] is not None else ""
    pos = f"{s[6]:.3f}, {s[5]:.3f}" if s[6] is not None and s[5] is not None else "position unknown"
    al = AIR.get(cs[:3].upper())
    row = {"flight": cs + (f" ({al[0]})" if al else ""), "status": f"{ft} · {spd}{hd}", "position": pos}
    if len(s) > 19 and (s[18] or s[19]): row["aircraft"] = " ".join(x for x in (s[19], s[18]) if x)
    if s[2]: row["registered_in"] = s[2]
    row["live_map"] = f"https://globe.adsbexchange.com/?icao={s[0]}"
    return row

async def flight(q):
    raw = re.sub(r"\s+", "", q).upper().replace("REG:", "")
    if not raw: raise ValueError("Send an airline name, flight number or callsign.")
    mode = key = label = None
    if re.fullmatch(r"N\d{1,5}[A-Z]{0,2}", raw) or re.fullmatch(r"[A-Z0-9]{1,2}-[A-Z0-9]{2,5}", raw):
        mode, key = "reg", raw
    else:
        m = re.fullmatch(r"([A-Z0-9]{2})(\d{1,4}[A-Z]?)", raw)
        if m and m.group(1) in AIR_IATA:
            icao = AIR_IATA[m.group(1)]; mode, key, label = "call", icao + m.group(2), f"{AIR[icao][0]} ({icao})"
        elif re.fullmatch(r"[A-Z]{3}\d{1,4}[A-Z]{0,2}", raw):
            mode, key = "call", raw
            if raw[:3] in AIR: label = f"{AIR[raw[:3]][0]} ({raw[:3]})"
        elif raw in AIR:
            mode, key, label = "airline", raw, f"{AIR[raw][0]} ({raw})"
        elif re.fullmatch(r"[0-9A-F]{6}", raw):
            mode, key = "hex", raw.lower()
        else:
            nm = re.fullmatch(r"([A-Za-z][A-Za-z .&'-]{2,})\s+(\d{1,4}[A-Za-z]?)", q.strip())
            icao = find_airline(nm.group(1)) if nm else None
            if icao: mode, key, label = "call", icao + nm.group(2).upper(), f"{AIR[icao][0]} ({icao})"
            else:
                icao = find_airline(q)
                if icao: mode, key, label = "airline", icao, f"{AIR[icao][0]} ({icao})"
    if not mode:
        raise ValueError("I couldn't match that. Try an airline name (Emirates), a flight number (UA123), a callsign (UAL123), or a registration (N12345).")
    rows, source = None, "ADS-B network (adsb.lol / airplanes.live)"
    if mode != "airline":
        path = {"reg": f"/v2/reg/{key}", "call": f"/v2/callsign/{key}", "hex": f"/v2/hex/{key}"}[mode]
        ac = await _adsb(path)
        if ac == [] and mode == "call" and re.fullmatch(r"[0-9A-F]{6}", raw): ac = await _adsb(f"/v2/hex/{raw.lower()}")
        if ac is not None: rows = [_from_adsb(a) for a in ac]
    if rows is None:
        if mode == "reg": raise ValueError("The ADS-B network did not answer, and registrations can't be searched elsewhere. Try again in a minute.")
        states = await _opensky(); source = "OpenSky Network"
        rows = [s for s in states if ((s[1] or "").strip().upper().startswith(key) if mode in ("call", "airline") else s[0] == key)]
    out = {"search": q.strip(), "matched": label or "aircraft", "source": source}
    if not rows:
        out["live_aircraft"] = 0
        out["note"] = "Nothing airborne matches right now. The flight may not be in the air, may use a different callsign than its flight number, or may be outside ADS-B coverage."
        return out
    rows.sort(key=lambda s: -(s[13] if s[13] is not None else (s[7] or -1)))
    out["live_aircraft"] = len(rows); out["in_the_air"] = sum(1 for s in rows if not s[8]); out["on_the_ground"] = sum(1 for s in rows if s[8])
    if len(rows) == 1 and not (len(rows[0]) > 19 and rows[0][18]): out.update(await _hexdb(rows[0][0]))
    out["aircraft"] = [_row(s) for s in rows[:12]]
    if len(rows) > 12: out["showing"] = f"top 12 of {len(rows)}"
    out["data_note"] = "Live community ADS-B data. Coverage has gaps, some flights are hidden, and positions can be up to a minute old."
    return out

# ====================== QR / BARCODE ======================
SHORT = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "buff.ly", "rb.gy", "lnkd.in", "s.id"}
BADTLD = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "support", "rest", "icu", "cfd"}

def url_flags(u):
    p = up.urlparse(u); host = (p.hostname or "").lower(); f = []
    if p.scheme != "https": f.append("not encrypted (http)")
    try: ipaddress.ip_address(host); f.append("uses a raw IP address instead of a name")
    except ValueError: pass
    if "xn--" in host: f.append("contains lookalike (international) characters")
    if host in SHORT: f.append("link shortener: the real destination is hidden (use /unshort)")
    if host.rsplit(".", 1)[-1] in BADTLD: f.append("uses a domain ending often abused for scams")
    if "@" in p.netloc: f.append("has an @ sign, which can disguise the real site")
    if host.count(".") >= 4: f.append("unusually many subdomains")
    if len(u) > 150: f.append("very long link")
    if re.search(r"login|verify|password|wallet|seed|recovery|secure|account|bank|signin", (p.path + p.query).lower()): f.append("asks about login, accounts or wallets")
    return f or ["no obvious red flags, but stay careful"]

def _classify(t):
    s = t.strip(); low = s.lower()
    if low.startswith(("http://", "https://")): return "web link", s, url_flags(s)
    if s.startswith("WIFI:"):
        ssid = re.search(r"S:((?:\\.|[^;])*);", s); typ = re.search(r"T:([^;]*);", s)
        return "Wi-Fi network", re.sub(r"P:(?:\\.|[^;])*;", "P:(hidden);", s), [f"network name: {ssid.group(1) if ssid else '?'}", f"security: {typ.group(1) if typ else 'unknown'}", "contains the Wi-Fi password"]
    if low.startswith("otpauth://"): return "2FA setup code", re.sub(r"secret=[^&]+", "secret=(hidden)", s), ["contains a secret key: never share or post this code"]
    if low.startswith(("upi://", "bitcoin:", "ethereum:")): return "payment request", s, ["check the receiver and amount carefully before paying"]
    if low.startswith("mailto:"): return "email address", s, []
    if low.startswith(("tel:", "sms:", "smsto:")): return "phone number or SMS", s, []
    if low.startswith("geo:"): return "location", s, []
    if s.startswith("BEGIN:VCARD"): return "contact card", s, []
    return "text", s, []

def qr_decode(data):
    from PIL import Image
    img = Image.open(io.BytesIO(data)).convert("RGB")
    found, backend = [], False
    try:
        from pyzbar.pyzbar import decode
        backend = True
        for im in (img, img.convert("L"), img.resize((img.width * 2, img.height * 2))):
            found = [(d.type, d.data.decode("utf-8", "replace")) for d in decode(im)]
            if found: break
    except ImportError:
        pass
    if not found:
        try:
            import cv2, numpy as np
            backend = True
            ok, vals, _, _ = cv2.QRCodeDetector().detectAndDecodeMulti(np.array(img)[:, :, ::-1].copy())
            if ok: found = [("QRCODE", v) for v in vals if v]
        except ImportError:
            pass
        except Exception:
            pass
    if not backend: raise ValueError("QR reading is not installed. Run: sudo apt install libzbar0, then: pip install pyzbar")
    if not found: return {"codes_found": 0, "result": "No QR code or barcode found. Try a sharper, closer, well-lit picture."}
    found = list(dict.fromkeys(found)); out = {"codes_found": len(found)}
    for i, (typ, txt) in enumerate(found, 1):
        k, shown, flags = _classify(txt); sfx = "" if len(found) == 1 else f"_{i}"
        out["type" + sfx] = f"{k} ({typ})"; out["content" + sfx] = shown[:500]
        if flags: out["safety_flags" + sfx] = flags
    out["note"] = "I never open the link. Check it with /unshort and /urlscan before visiting."
    return out

# ====================== IMAGE SEARCH ======================
def _shrink(data):
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(data)).convert("RGB"); im.thumbnail((2000, 2000))
        b = io.BytesIO(); im.save(b, "JPEG", quality=88); return b.getvalue()
    except Exception:
        return data

async def _vision(data):
    if not GOOGLE_VISION_KEY: return None
    body = {"requests": [{"image": {"content": base64.b64encode(_shrink(data)).decode()}, "features": [{"type": "WEB_DETECTION", "maxResults": 10}]}]}
    async with httpx.AsyncClient(timeout=45) as c:
        r = await c.post("https://vision.googleapis.com/v1/images:annotate", params={"key": GOOGLE_VISION_KEY}, json=body)
    j = r.json()
    if r.status_code != 200: return {"web_search_error": str((j.get("error") or {}).get("message", "request failed"))[:200]}
    w = (j.get("responses") or [{}])[0].get("webDetection", {})
    ents = [f"{e['description']} ({int(e.get('score', 0) * 100)}%)" for e in w.get("webEntities", []) if e.get("description")][:8]
    pages = [{"page": re.sub(r"<[^>]+>", "", p.get("pageTitle") or "")[:70], "url": p["url"]} for p in w.get("pagesWithMatchingImages", [])[:8]]
    out = {"best_guess": [g["label"] for g in w.get("bestGuessLabels", [])], "related_topics": ents, "pages_with_this_image": pages,
           "exact_copies": [x["url"] for x in w.get("fullMatchingImages", [])[:5]], "similar_images": [x["url"] for x in w.get("visuallySimilarImages", [])[:5]]}
    return {k: v for k, v in out.items() if v}

async def _tracemoe(data):
    async with httpx.AsyncClient(timeout=45) as c:
        r = await c.post("https://api.trace.moe/search", params={"anilistInfo": "1"}, files={"image": ("image.jpg", _shrink(data), "image/jpeg")})
    if r.status_code != 200: return None
    res = (r.json().get("result") or [None])[0]
    if not res or res.get("similarity", 0) < 0.87: return None
    al = res.get("anilist") if isinstance(res.get("anilist"), dict) else {}
    if al.get("isAdult"): return None
    tt = al.get("title") or {}; title = tt.get("english") or tt.get("romaji") or tt.get("native") or res.get("filename")
    t = int(res.get("from", 0)); ep = res.get("episode")
    return {"anime_match": f"{title}" + (f", episode {ep}" if ep else "") + f", around {t // 60}:{t % 60:02d} ({int(res['similarity'] * 100)}% match)"}

async def image_search(data):
    vis, anime = await asyncio.gather(_vision(data), _tracemoe(data), return_exceptions=True)
    out = {}
    if isinstance(vis, dict): out.update(vis)
    elif vis is None: out["web_search"] = "Web-wide matching is off. Add a GOOGLE_VISION_KEY to the .env file to turn it on."
    if isinstance(anime, dict): out.update(anime)
    if len(out) <= 1: out["result"] = "No automatic matches found. Try the search engines below and upload the image there."
    out["note"] = "This matches the whole image against the web. It does not identify people by their faces."
    return out

# ====================== DECODER ======================
def _printable(b):
    try: s = b.decode("utf-8")
    except UnicodeDecodeError: return None
    return s if s and sum(c.isprintable() or c in "\n\t" for c in s) / len(s) > 0.9 else None

async def decode_text(s):
    s = s.strip(); res = {}
    jwt = re.fullmatch(r"([A-Za-z0-9_-]{4,})\.([A-Za-z0-9_-]{4,})\.([A-Za-z0-9_-]*)", s)
    if jwt:
        def j(p): return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        try:
            h, p = j(jwt.group(1)), j(jwt.group(2)); res = {"type": "JWT token", "header": h, "payload": p}
            for k in ("exp", "iat", "nbf"):
                if isinstance(p.get(k), int): res[k + "_time"] = datetime.fromtimestamp(p[k], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            res["warning"] = "The signature is not verified here. Never share live tokens."
            return res
        except Exception:
            res = {}
    hx = re.sub(r"^0x|\s", "", s)
    if re.fullmatch(r"[0-9a-fA-F]+", hx):
        names = {32: "MD5 or NTLM", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}
        if len(hx) in names: res["possible_hash_type"] = names[len(hx)] + " (hashes can't be reversed, only guessed)"
        elif len(hx) % 2 == 0:
            t = _printable(bytes.fromhex(hx))
            if t: res["hex_decoded"] = t[:1500]
    if re.fullmatch(r"[01\s]{8,}", s):
        bits = re.sub(r"\s", "", s)
        if len(bits) % 8 == 0:
            t = _printable(int(bits, 2).to_bytes(len(bits) // 8, "big"))
            if t: res["binary_decoded"] = t[:1500]
    if "%" in s and up.unquote(s) != s: res["url_decoded"] = up.unquote(s)
    if re.fullmatch(r"[A-Za-z0-9+/_=-]{8,}", s):
        t0 = s.replace("-", "+").replace("_", "/"); t0 += "=" * (-len(t0) % 4)
        try:
            t = _printable(base64.b64decode(t0))
            if t: res["base64_decoded"] = t[:1500]
        except (binascii.Error, ValueError):
            pass
    if re.fullmatch(r"[A-Za-z ,.!?']{6,}", s): res["rot13"] = codecs.decode(s, "rot13")
    if not res: raise ValueError("I couldn't decode that. I handle base64, hex, binary, URL encoding, ROT13, JWT tokens and hash types.")
    return res

# ====================== EMAIL SECURITY ======================
async def email_security(domain):
    d = clean_domain(domain)
    r = dns.asyncresolver.Resolver(); r.lifetime = 4
    async def txt(name):
        try: return [x.to_text().strip('"').replace('" "', "") for x in await r.resolve(name, "TXT")]
        except Exception: return []
    async def mx():
        try: return sorted(str(x.exchange).rstrip(".") for x in await r.resolve(d, "MX"))
        except Exception: return []
    sels = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "smtp", "zoho", "mandrill", "mxvip"]
    base, dm, mxs, *dk = await asyncio.gather(txt(d), txt("_dmarc." + d), mx(), *[txt(f"{s}._domainkey.{d}") for s in sels])
    spf = next((t for t in base if t.lower().startswith("v=spf1")), None)
    dmarc = next((t for t in dm if t.lower().startswith("v=dmarc1")), None)
    dkim = [s for s, v in zip(sels, dk) if v]
    score, notes = 0, []
    if not spf: notes.append("No SPF record: the domain is easy to spoof.")
    elif spf.rstrip().endswith("-all"): score += 2
    elif spf.rstrip().endswith("~all"): score += 1; notes.append("SPF is soft-fail (~all). Hard-fail (-all) is stricter.")
    else: notes.append("SPF does not reject unauthorised senders.")
    pol = re.search(r"\bp=(\w+)", dmarc or "")
    if not dmarc: notes.append("No DMARC policy: spoofed mail is not blocked.")
    elif pol and pol.group(1) == "reject": score += 3
    elif pol and pol.group(1) == "quarantine": score += 2
    else: score += 1; notes.append("DMARC is monitoring only (p=none).")
    if dkim: score += 1
    else: notes.append("No DKIM selector found among common names (custom names exist, so this is not conclusive).")
    if not mxs: notes.append("No mail servers (MX): this domain may not receive email.")
    grade = "A" if score >= 5 else "B" if score == 4 else "C" if score == 3 else "D" if score == 2 else "F"
    return {"domain": d, "grade": grade, "spf": spf or "missing", "dmarc": dmarc or "missing", "dkim_selectors_found": dkim,
            "mail_servers": mxs, "findings": notes or ["Looks well configured."]}

# ====================== LOOKALIKE DOMAINS ======================
ADJ = {"a": "sq", "b": "vn", "c": "xv", "d": "sf", "e": "wr", "f": "dg", "g": "fh", "h": "gj", "i": "uo", "j": "hk", "k": "jl", "l": "k", "m": "n",
       "n": "bm", "o": "ip", "p": "o", "q": "w", "r": "et", "s": "ad", "t": "ry", "u": "yi", "v": "cb", "w": "qe", "x": "zc", "y": "tu", "z": "x"}
HOMO = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5"], "m": ["rn"], "w": ["vv"], "d": ["cl"], "g": ["q"], "b": ["d"]}

def variants(name):
    v = set()
    for i in range(len(name)):
        v.add(name[:i] + name[i + 1:]); v.add(name[:i] + name[i] + name[i:])
        if i < len(name) - 1: v.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])
        for ch in ADJ.get(name[i], ""): v.add(name[:i] + ch + name[i + 1:])
        for h in HOMO.get(name[i], []): v.add(name[:i] + h + name[i + 1:])
        if i > 0: v.add(name[:i] + "-" + name[i:])
    v.add("www" + name); v.discard(name)
    return {x for x in v if x and not x.startswith("-") and not x.endswith("-")}

async def lookalikes(domain):
    d = clean_domain(domain); name, _, tld = d.partition(".")
    cands = {f"{x}.{tld}" for x in variants(name)} | {f"{name}.{t}" for t in ["com", "net", "org", "co", "io", "info", "biz", "xyz", "online", "shop", "app"] if t != tld}
    cands = sorted(cands)[:400]
    r = dns.asyncresolver.Resolver(); r.lifetime = 3; r.timeout = 3
    sem = asyncio.Semaphore(40)
    async def check(dom):
        async with sem:
            for t in ("A", "NS"):
                try:
                    return {"domain": dom, "records": ", ".join(x.to_text() for x in await r.resolve(dom, t))[:60]}
                except dns.resolver.NoAnswer: return {"domain": dom, "records": "registered (no A record)"}
                except dns.resolver.NXDOMAIN: return None
                except Exception: continue
            return None
    res = [x for x in await asyncio.gather(*[check(c) for c in cands]) if x]
    return {"domain": d, "variations_checked": len(cands), "registered_lookalikes": len(res), "domains": res[:60],
            "note": "A registered lookalike is not automatically malicious. Check who owns it with /domain and what it shows with /web."}

# ====================== TECH STACK ======================
SIGS = [("WordPress", "b", r"wp-content|wp-includes"), ("Shopify", "b", r"cdn\.shopify\.com|Shopify\.theme"), ("Wix", "b", r"wixstatic\.com"),
        ("Squarespace", "b", r"squarespace\.com"), ("Joomla", "b", r"/media/jui/|Joomla!"), ("Drupal", "b", r"Drupal\.settings|/sites/default/files"),
        ("Magento", "b", r"Mage\.Cookies|/static/frontend/Magento"), ("React", "b", r"data-reactroot|react-dom"), ("Next.js", "b", r"__NEXT_DATA__|/_next/"),
        ("Vue.js", "b", r"data-v-[0-9a-f]{6,8}|vue(\.min)?\.js"), ("Nuxt", "b", r"__NUXT__|/_nuxt/"), ("Angular", "b", r"ng-version=|ng-app"),
        ("Svelte", "b", r"svelte-[a-z0-9]{5,}"), ("jQuery", "b", r"jquery[.-]?[0-9.]*(min)?\.js"), ("Bootstrap", "b", r"bootstrap(\.min)?\.(css|js)"),
        ("Tailwind CSS", "b", r"tailwind"), ("Google Analytics", "b", r"google-analytics\.com|gtag\("), ("Google Tag Manager", "b", r"googletagmanager\.com/gtm"),
        ("Facebook Pixel", "b", r"fbevents\.js|fbq\("), ("Hotjar", "b", r"static\.hotjar\.com"), ("Matomo", "b", r"matomo\.js|piwik\.js"),
        ("Cloudflare", "h", r"server: cloudflare|cf-ray"), ("nginx", "h", r"server: nginx"), ("Apache", "h", r"server: apache"),
        ("Microsoft IIS", "h", r"server: microsoft-iis"), ("PHP", "h", r"x-powered-by: php"), ("ASP.NET", "h", r"x-powered-by: asp\.net|x-aspnet-version"),
        ("Express", "h", r"x-powered-by: express"), ("Vercel", "h", r"server: vercel|x-vercel-id"), ("Netlify", "h", r"server: netlify|x-nf-request-id"),
        ("AWS CloudFront", "h", r"x-amz-cf-id|via:.*cloudfront"), ("Fastly", "h", r"fastly"), ("Akamai", "h", r"akamai"), ("Varnish", "h", r"x-varnish|via:.*varnish")]

async def _page(target):
    t = target.strip()
    if not t.startswith(("http://", "https://")): t = "https://" + t
    async with httpx.AsyncClient(timeout=10, follow_redirects=False, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"}) as c:
        for _ in range(4):
            host = up.urlparse(t).hostname
            if not host: raise ValueError("Enter a website like example.com")
            try: ipaddress.ip_address(host)
            except ValueError: host = clean_domain(host)
            try: await _public_host(host)
            except OSError: raise ValueError("Could not resolve that website.")
            async with c.stream("GET", t) as r:
                if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                    t = up.urljoin(t, r.headers["location"]); continue
                body = b""
                async for ch in r.aiter_bytes():
                    body += ch
                    if len(body) > 300000: break
                return t, r.status_code, r.headers, body.decode("utf-8", "ignore")
    raise ValueError("Too many redirects.")

async def tech_stack(target):
    url, status, h, body = await _page(target)
    hdr = "\n".join(f"{k}: {v}" for k, v in h.items()).lower()
    found = sorted({n for n, w, rx in SIGS if re.search(rx, body if w == "b" else hdr, re.I)})
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    return {"url": url, "status": status, "technologies_detected": found, "server": h.get("server"), "generator": gen.group(1) if gen else None,
            "note": "Based on public page code and headers. Sites behind a CDN or firewall may hide some technologies."}

# ====================== PLACES, SUN, WEATHER ======================
def sun_pos(lat, lon, dt):
    n = dt.timestamp() / 86400 + 2440587.5 - 2451545.0
    L = (280.46 + 0.9856474 * n) % 360; g = math.radians((357.528 + 0.9856003 * n) % 360)
    lam = math.radians(L + 1.915 * math.sin(g) + 0.020 * math.sin(2 * g)); eps = math.radians(23.439 - 0.0000004 * n)
    ra = math.atan2(math.cos(eps) * math.sin(lam), math.cos(lam)); dec = math.asin(math.sin(eps) * math.sin(lam))
    ha = math.radians((280.46061837 + 360.98564736629 * n + lon) % 360) - ra; la = math.radians(lat)
    el = math.asin(math.sin(la) * math.sin(dec) + math.cos(la) * math.cos(dec) * math.cos(ha))
    az = math.atan2(-math.sin(ha), math.tan(dec) * math.cos(la) - math.sin(la) * math.cos(ha))
    return math.degrees(el), math.degrees(az) % 360

def compass(a): return ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE", "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"][int((a + 11.25) % 360 // 22.5)]

_DATE_PATS = [(r"\d{4}-\d{1,2}-\d{1,2}", ("%Y-%m-%d",)), (r"\d{1,2}[/.\-]\d{1,2}[/.\-]\d{4}", ("%d/%m/%Y",)),
              (r"\d{1,2}(?:st|nd|rd|th)?\s+[A-Za-z]{3,9},?\s+\d{4}", ("%d %B %Y", "%d %b %Y")),
              (r"[A-Za-z]{3,9}\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}", ("%B %d %Y", "%b %d %Y"))]

def parse_date(text):
    """Finds a date in free text. Returns (date, text with the date removed)."""
    today = datetime.now(timezone.utc).date()
    for word, delta in (("yesterday", -1), ("today", 0), ("tomorrow", 1)):
        if re.search(rf"\b{word}\b", text, re.I): return today + timedelta(days=delta), re.sub(rf"(?i)\b{word}\b", "", text)
    for rx, fmts in _DATE_PATS:
        m = re.search(rx, text)
        if not m: continue
        norm = re.sub(r"(?<=\d)(st|nd|rd|th)\b", "", m.group(0))
        if fmts[0] == "%Y-%m-%d": norm = re.sub(r"[/.]", "-", norm)
        elif fmts[0] == "%d/%m/%Y": norm = re.sub(r"[.\-]", "/", norm)
        else: norm = re.sub(r"\s+", " ", norm.replace(",", ""))
        for f in fmts:
            try: return datetime.strptime(norm, f).date(), text[:m.start()] + text[m.end():]
            except ValueError: continue
    raise ValueError("Add a date, like: Paris, 2024-06-21 or Paris, 21 June 2024")

_COORD = re.compile(r"^\s*(-?\d+(?:\.\d+)?)\s*[,; ]\s*(-?\d+(?:\.\d+)?)\s*$")

async def geocode(place):
    """Place name (or 'lat, lon') -> (lat, lon, label, timezone or None)."""
    m = _COORD.match(place)
    if m:
        lat, lon = float(m.group(1)), float(m.group(2))
        if abs(lat) > 90 or abs(lon) > 180: raise ValueError("Those coordinates are out of range.")
        return lat, lon, f"{lat}, {lon}", None
    parts = [p.strip() for p in re.split(r"[,;]", place) if p.strip()]
    if not parts: raise ValueError("Add a place, like: Paris, 2024-06-21")
    hint = " ".join(parts[1:]).lower()
    async with client() as c:
        r = await c.get("https://geocoding-api.open-meteo.com/v1/search", params={"name": parts[0], "count": 10, "language": "en", "format": "json"})
    res = r.json().get("results") or [] if r.status_code == 200 else []
    if not res: raise ValueError("I couldn't find that place. Try the city and country, like: Paris, France, 2024-06-21")
    pick = res[0]
    if hint:
        for x in res:
            hay = " ".join(str(x.get(k, "")) for k in ("country", "country_code", "admin1", "admin2")).lower()
            if any(w in hay for w in hint.split()): pick = x; break
    label = ", ".join(str(v) for v in (pick.get("name"), pick.get("admin1"), pick.get("country")) if v)
    return pick["latitude"], pick["longitude"], label, pick.get("timezone")

async def sun_info(q):
    d, rest = parse_date(q)
    tm = re.search(r"\b(\d{1,2}):(\d{2})\b", rest); rest = re.sub(r"\b\d{1,2}:\d{2}\b", "", rest)
    place = rest.strip(" ,;-")
    if not place: raise ValueError("Add a place, like: Paris, 2024-06-21 14:30")
    lat, lon, label, tz = await geocode(place)
    try:
        import zoneinfo; tzi = zoneinfo.ZoneInfo(tz) if tz else timezone.utc
    except Exception:
        tzi, tz = timezone.utc, None
    start = datetime(d.year, d.month, d.day, tzinfo=tzi).astimezone(timezone.utc)
    el = [sun_pos(lat, lon, start + timedelta(minutes=i))[0] for i in range(1441)]
    f = lambda i: (start + timedelta(minutes=i)).astimezone(tzi).strftime("%H:%M")
    out = {"place": label, "coordinates": f"{lat:.4f}, {lon:.4f}", "date": d.isoformat(), "times_are": f"local time ({tz})" if tz else "UTC"}
    rises = [i for i in range(1, 1441) if el[i - 1] <= -0.833 < el[i]]; sets = [i for i in range(1, 1441) if el[i - 1] > -0.833 >= el[i]]
    if all(e <= -0.833 for e in el): out["daylight"] = "The sun stays below the horizon all day."
    elif all(e > -0.833 for e in el): out["daylight"] = "The sun stays above the horizon all day."
    else:
        out["sunrise"] = f(rises[0]) if rises else "before midnight"; out["sunset"] = f(sets[0]) if sets else "after midnight"
        out["daylight_hours"] = round(sum(1 for e in el if e > -0.833) / 60, 1)
    top = max(range(1441), key=lambda i: el[i]); out["highest_sun"] = f"{el[top]:.1f}° at {f(top)}"
    if tm:
        t = datetime(d.year, d.month, d.day, int(tm.group(1)) % 24, int(tm.group(2)), tzinfo=tzi).astimezone(timezone.utc)
        e, a = sun_pos(lat, lon, t)
        out["at_time"] = tm.group(0); out["sun_elevation"] = f"{e:.1f}°"; out["sun_direction"] = f"{a:.0f}° ({compass(a)})"
        if e > 0.5:
            out["shadows_point_toward"] = f"{(a + 180) % 360:.0f}° ({compass(a + 180)})"
            out["shadow_length"] = f"{1 / math.tan(math.radians(e)):.2f} × the object's height"
        else: out["shadows"] = "The sun is at or below the horizon at that time."
    out["note"] = "Accurate to about 1°. Use it to check whether a photo's shadows fit its claimed place and time."
    return out

WCODE = {0: "clear sky", 1: "mostly clear", 2: "partly cloudy", 3: "overcast", 45: "fog", 48: "freezing fog", 51: "light drizzle", 53: "drizzle", 55: "heavy drizzle",
         61: "light rain", 63: "rain", 65: "heavy rain", 66: "freezing rain", 67: "heavy freezing rain", 71: "light snow", 73: "snow", 75: "heavy snow", 77: "snow grains",
         80: "light showers", 81: "showers", 82: "heavy showers", 85: "snow showers", 86: "heavy snow showers", 95: "thunderstorm", 96: "thunderstorm with hail", 99: "severe thunderstorm with hail"}

async def weather_on(q):
    d, rest = parse_date(q)
    place = rest.strip(" ,;-")
    if not place: raise ValueError("Add a place, like: Paris, 2024-06-21")
    today = datetime.now(timezone.utc).date()
    if d > today + timedelta(days=14): raise ValueError("That date is too far in the future for weather data.")
    lat, lon, label, _tz = await geocode(place)
    url = "https://api.open-meteo.com/v1/forecast" if (today - d).days < 90 else "https://archive-api.open-meteo.com/v1/archive"
    async with client() as c:
        r = await c.get(url, params={"latitude": lat, "longitude": lon, "start_date": d.isoformat(), "end_date": d.isoformat(), "timezone": "auto",
                                     "daily": "weather_code,temperature_2m_max,temperature_2m_min,precipitation_sum,wind_speed_10m_max,sunrise,sunset"})
    j = r.json()
    if r.status_code != 200 or "daily" not in j: raise ValueError("No weather data for that place and date: " + str(j.get("reason", "try another date")))
    x = {k: v[0] for k, v in j["daily"].items()}
    return {"place": label, "date": d.isoformat(), "conditions": WCODE.get(x.get("weather_code"), "unknown"), "temp_max_c": x.get("temperature_2m_max"),
            "temp_min_c": x.get("temperature_2m_min"), "rain_mm": x.get("precipitation_sum"), "max_wind_kmh": x.get("wind_speed_10m_max"),
            "sunrise_local": (x.get("sunrise") or "")[-5:], "sunset_local": (x.get("sunset") or "")[-5:], "timezone": j.get("timezone"),
            "note": "Daily summary from Open-Meteo. Compare it with what a photo or video shows."}

# ====================== ASN ======================
async def asn_lookup(q):
    q = q.strip(); prefix = None
    async with client() as c:
        try:
            ip = str(ipaddress.ip_address(q))
            d = (await c.get("https://stat.ripe.net/data/prefix-overview/data.json", params={"resource": ip})).json().get("data", {})
            if not d.get("asns"): raise ValueError("No routing data for that IP (it may be private or not announced).")
            n, prefix = str(d["asns"][0]["asn"]), d.get("resource")
        except ValueError as e:
            if "routing" in str(e): raise
            m = re.fullmatch(r"(?:AS|ASN)?\s*(\d{1,10})", q.upper())
            if not m: raise ValueError("Send an ASN like AS15169, or an IP address.")
            n = m.group(1)
        ov, pf = await asyncio.gather(c.get("https://stat.ripe.net/data/as-overview/data.json", params={"resource": f"AS{n}"}),
                                      c.get("https://stat.ripe.net/data/announced-prefixes/data.json", params={"resource": f"AS{n}"}))
    pre = [p["prefix"] for p in pf.json().get("data", {}).get("prefixes", [])]
    v4 = sorted(p for p in pre if ":" not in p)
    out = {"asn": f"AS{n}", "holder": ov.json().get("data", {}).get("holder"), "announced": ov.json().get("data", {}).get("announced")}
    if prefix: out["ip_prefix"] = prefix
    out.update({"prefixes_announced": len(pre), "sample_ipv4_prefixes": v4[:25], "more_info": f"https://bgp.he.net/AS{n}"})
    return out

# ====================== ID TO DATE / DISCORD ======================
async def snowflake(s):
    s = s.strip()
    if not re.fullmatch(r"\d{15,20}", s): raise ValueError("Send the numeric ID (about 17-19 digits).")
    n = int(s); now = datetime.now(timezone.utc)
    def at(epoch):
        d = datetime.fromtimestamp(((n >> 22) + epoch) / 1000, timezone.utc)
        return d.strftime("%Y-%m-%d %H:%M:%S UTC") + ("" if d <= now else " (in the future, so not valid)")
    return {"id": s, "if_discord_id": at(1420070400000), "if_x_twitter_id": at(1288834974657),
            "note": "Both platforms use the same maths. Pick the one the ID came from (a Discord user, server or message, or an X post)."}

async def discord_invite(code):
    c0 = re.sub(r"^(https?://)?(www\.)?(discord\.gg|discord(app)?\.com/invite)/", "", code.strip()).strip("/")
    if not re.fullmatch(r"[A-Za-z0-9-]{2,32}", c0): raise ValueError("Send an invite like discord.gg/abcdef")
    async with client() as c:
        r = await c.get(f"https://discord.com/api/v10/invites/{c0}", params={"with_counts": "true", "with_expiration": "true"})
    if r.status_code == 404: raise ValueError("That invite does not exist or has expired.")
    if r.status_code != 200: raise ValueError("Discord did not respond. Try again later.")
    j = r.json(); g = j.get("guild") or {}
    created = datetime.fromtimestamp(((int(g["id"]) >> 22) + 1420070400000) / 1000, timezone.utc).strftime("%Y-%m-%d") if g.get("id") else None
    return {"server_name": g.get("name"), "description": g.get("description"), "server_created": created, "members_approx": j.get("approximate_member_count"),
            "online_approx": j.get("approximate_presence_count"), "invite_channel": (j.get("channel") or {}).get("name"), "expires": j.get("expires_at"),
            "features": g.get("features", [])[:8], "note": "Public invite data only."}

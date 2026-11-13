import asyncio, html, io, ipaddress, json, math, re, time
from aiogram import Router, F
from aiogram.filters import Command, CommandStart
from aiogram.types import (Message, CallbackQuery, InlineKeyboardMarkup as KB, InlineKeyboardButton as Btn,
                           ReplyKeyboardMarkup, KeyboardButton, WebAppInfo, LabeledPrice, BufferedInputFile,
                           LinkPreviewOptions)
from aiogram.utils.chat_action import ChatActionSender
from . import db, tools, wmn
from .config import *

router = Router()
esc = html.escape
NOPREV = LinkPreviewOptions(is_disabled=True)
LAST, PENDING, RUNNERS = {}, {}, {}   # last result per user, waiting-for-input state, command runners

def tool(fn, cost, ex, what, icon, btn, title, label, eta, prog=False):
    return dict(fn=fn, cost=cost, ex=ex, what=what, icon=icon, btn=btn, title=title, label=label, eta=eta, prog=prog)

TOOLS = {
 "username": tool(wmn.quick, 0, "octocat", "username (one handle, no spaces)", "🔎", "Username", "Username check", "Checking social platforms", 45, True),
 "deepuser": tool(wmn.deep, 5, "octocat", "username (one handle, no spaces)", "🕵️", "Deep username", "Deep username scan", "Scanning hundreds of verified sites", 120, True),
 "ip": tool(tools.ip_geo_rdns, 0, "8.8.8.8", "IP address", "🌍", "IP lookup", "IP lookup", "Looking up IP", 6),
 "domain": tool(tools.domain_lookup, 0, "example.com", "domain", "🌐", "Domain", "Domain lookup", "Checking domain", 6),
 "dns": tool(tools.dns_full, 0, "example.com", "domain", "🗂️", "DNS records", "DNS records", "Reading DNS records", 5),
 "email": tool(tools.email_intel, 0, "name@example.com", "email address", "📧", "Email", "Email intelligence", "Checking email", 6),
 "phone": tool(tools.phone_info, 0, "+14155552671", "phone number with country code", "📞", "Phone", "Phone number info", "Reading number", 2),
 "web": tool(tools.web_headers, 0, "example.com", "website", "🕸️", "Website", "Website check", "Fetching website headers", 8),
 "ssl": tool(tools.ssl_info, 0, "example.com", "domain", "🔐", "SSL certificate", "SSL certificate", "Reading certificate", 6),
 "telegram": tool(tools.tg_lookup, 0, "durov", "Telegram username", "✈️", "Telegram", "Telegram lookup", "Checking Telegram", 5),
 "github": tool(tools.github_user, 0, "octocat", "GitHub username", "🐙", "GitHub", "GitHub profile", "Reading GitHub profile", 4),
 "archive": tool(tools.archive_lookup, 0, "example.com", "website", "🗄️", "Web archive", "Wayback history", "Searching the web archive", 12),
 "subdomains": tool(tools.subdomains, 5, "example.com", "domain", "🌿", "Subdomains", "Subdomains", "Searching certificate logs", 15),
 "ports": tool(tools.ip_exposure, 2, "8.8.8.8", "IP address", "🚪", "Exposure", "Exposure flags", "Checking passive exposure data", 5),
 "reverseip": tool(tools.reverse_ip, 0, "8.8.8.8", "IP address", "🔁", "Reverse IP", "Domains on this IP", "Searching shared hosting", 8),
 "mac": tool(tools.mac_lookup, 0, "00:1A:2B:3C:4D:5E", "MAC address", "🔌", "MAC vendor", "MAC vendor", "Looking up vendor", 3),
 "btc": tool(tools.btc_lookup, 0, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "Bitcoin address", "₿", "Bitcoin", "Bitcoin address", "Reading the blockchain", 5),
 "breach": tool(tools.breach_check, 10, "you@example.com", "email address", "💥", "Breach check", "Breach check", "Checking breach databases", 5),
}
MENU = ["username", "deepuser", "ip", "domain", "email", "phone", "web", "ssl", "telegram", "github",
        "archive", "subdomains", "ports", "reverseip", "mac", "btc", "breach", "dns"]
COMMANDS = [("menu", "Open the tool menu"), ("help", "What I can do")] + \
           [(k, TOOLS[k]["title"]) for k in MENU] + [("export", "Export last result"), ("balance", "Credit balance")]

ICON = {"country": "🌍", "region": "📍", "city": "🏙️", "coordinates": "🧭", "isp": "📡", "organisation": "🏢",
        "asn": "🔢", "timezone": "🕒", "reverse_dns": "↩️", "domain": "🌐", "ip": "🌐", "ipv4": "🔹", "ipv6": "🔸",
        "nameservers": "🗂️", "created": "📅", "expires": "⌛", "registrar": "🏷️", "MX": "✉️", "NS": "🗂️", "TXT": "📝",
        "A": "🔹", "AAAA": "🔸", "SOA": "🧾", "CAA": "🔐", "DMARC": "🛡️", "open_ports_flagged": "🚪",
        "known_cves": "⚠️", "hostnames": "🖥️", "tags": "🏷️", "software_cpes": "💾", "subdomains": "🌿",
        "gps": "📍", "map": "🗺️", "taken": "📅", "camera_make": "📷", "camera_model": "📷", "software": "💾",
        "status": "🚦", "server": "🖥️", "page_title": "📰", "first_snapshot": "🕰️", "latest_snapshot": "🆕",
        "vendor": "🏭", "valid_number": "✔️", "line_type": "📱", "original_carrier": "📶", "email": "📧",
        "gravatar_name": "👤", "tor_exit_node": "🧅", "location_confidence": "🎯", "issuer": "🏛️", "issued_to": "🏷️",
        "valid_until": "⌛", "days_left": "⏳", "alt_names": "🌐", "certificate_valid": "✅", "name": "👤", "bio": "📝",
        "balance_btc": "₿", "exists": "✅", "link": "🔗", "profile": "🔗", "explorer": "🔗", "count": "#️⃣",
        "source": "📚", "found": "⚠️", "breaches": "💥", "note": "ℹ️"}

TERMS = ("🔒 <b>Before you start</b>\nThis bot uses public, passive data only. Don't use it to stalk, harass, dox "
         "or target anyone. Lookups are logged and rate-limited. To remove an identifier, send /optout &lt;value&gt;.")
CAPS = ("👋 <b>I'm an OSINT lookup bot.</b>\n\n<b>✅ What I can do</b>\n"
        "🔎 Check a username on hundreds of verified sites\n🌍 IP location, ISP, Tor-exit check, shared hosting\n"
        "🌐 Domains: DNS, registrar, SSL certificate, subdomains, website headers, history\n"
        "📧 Email setup and breach check · 📞 phone number info\n✈️ Telegram and 🐙 GitHub public profiles\n"
        "₿ Bitcoin address balance · 🔌 MAC vendor · 🖼️ photo metadata (send a photo as a File)\n\n"
        "<b>🚫 What I can't do</b>\nFind a person's home address or live location, search by full name, read private "
        "messages, hack accounts, or search leaked-password dumps.\n\n"
        "<b>⚠️ Good to know</b>\nI only use public data. Results can be incomplete, and a username match does not "
        "prove it's the same person.")

def help_text():
    return CAPS + ("\n\n🎁 <b>Everything is free right now.</b>" if FREE_MODE else "")

# ---------- formatting ----------
def fmt(d):
    out = []
    for k, v in d.items():
        ic = ICON.get(k, "▫️"); name = esc(str(k).replace("_", " "))
        if v in (None, [], ""): out.append(f"{ic} <b>{name}:</b> none"); continue
        if isinstance(v, bool): v = "yes" if v else "no"
        if isinstance(v, dict):
            out.append(f"{ic} <b>{name}:</b>"); out += [f"• {esc(str(a))}: {esc(str(b))}" for a, b in v.items()]
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            out.append(f"{ic} <b>{name}:</b>")
            out += ["• " + esc(" | ".join(str(x) for x in r.values())) for r in v]
        elif isinstance(v, list):
            if len(v) > 4:
                more = f"\n…and {len(v)-40} more (use Export)" if len(v) > 40 else ""
                out.append(f"{ic} <b>{name}:</b>\n" + "\n".join(f"<code>{esc(str(x))}</code>" for x in v[:40]) + more)
            else: out.append(f"{ic} <b>{name}:</b> " + ", ".join(f"<code>{esc(str(x))}</code>" for x in v))
        else: out.append(f"{ic} <b>{name}:</b> {esc(str(v))}")
    return "\n".join(out)

def render_user(d):
    found, blocked = d["profiles_found"], d["blocked_or_uncertain"]
    L = [f"🔎 <b>Username scan</b> · <code>{esc(d['username'])}</code>",
         f"✅ Found on <b>{len(found)}</b> sites",
         f"🧪 {d['sites_verified_and_checked']} verified sites checked (database: {d['sites_in_database']})"]
    if blocked: L.append(f"⚠️ {len(blocked)} sites blocked the check, so those are uncertain")
    by = {}
    for r in found: by.setdefault(r["category"], []).append(r)
    for cat, rows in sorted(by.items()):
        L.append(f"\n📂 <b>{esc(str(cat))}</b> ({len(rows)})")
        for r in rows: L.append(f"• <b>{esc(r['site'])}</b>\n{esc(r['url'])}")
    if not found: L.append("\n😕 No public profiles found with this exact name.")
    L.append("\nℹ️ A match means a page with this name exists, not that it's the same person. Open the link to verify.")
    return "\n".join(L)

def render(cmd, arg, d):
    if "profiles_found" in d: return render_user(d)
    t = TOOLS[cmd]
    return f"{t['icon']} <b>{t['title']}</b> · <code>{esc(arg)}</code>\n\n" + fmt(d)

# ---------- keyboards ----------
REPLY_KB = ReplyKeyboardMarkup(keyboard=[[KeyboardButton(text="📋 Menu")]], resize_keyboard=True, is_persistent=True)

def menu_kb():
    btns = [Btn(text=f"{TOOLS[k]['icon']} {TOOLS[k]['btn']}", callback_data=f"t:{k}") for k in MENU]
    btns.append(Btn(text="🖼️ Photo metadata", callback_data="t:photo"))
    rows = [btns[i:i + 2] for i in range(0, len(btns), 2)]
    last = [Btn(text="❓ Help", callback_data="help")]
    if WEBAPP_URL.startswith("https://"): last.insert(0, Btn(text="🚀 Mini App", web_app=WebAppInfo(url=WEBAPP_URL)))
    if not FREE_MODE: last.append(Btn(text="⭐ Credits", callback_data="buy"))
    return KB(inline_keyboard=rows + [last])

def back_kb():
    return KB(inline_keyboard=[[Btn(text="⬅️ Back to menu", callback_data="menu")]])

def after_kb(cmd):
    return KB(inline_keyboard=[[Btn(text=f"🔁 Another {TOOLS[cmd]['btn']}", callback_data=f"t:{cmd}")],
                               [Btn(text="📄 Export", callback_data="export"), Btn(text="📋 Menu", callback_data="menu")]])

# ---------- start / menu ----------
async def welcome(msg: Message):
    await msg.answer("👋 <b>Welcome to OSINT Hub</b>\nTap a tool below. You can also just send me an IP, domain, "
                     "email, phone number or @username." + ("\n🎁 Everything is free right now." if FREE_MODE else ""),
                     parse_mode="HTML", reply_markup=menu_kb())
    await msg.answer("💡 The <b>📋 Menu</b> button below is always here.", parse_mode="HTML", reply_markup=REPLY_KB)

async def need_consent(msg: Message):
    await msg.answer(TERMS, parse_mode="HTML",
                     reply_markup=KB(inline_keyboard=[[Btn(text="✅ I agree and will use it lawfully", callback_data="agree")]]))

@router.message(CommandStart())
async def start(m: Message):
    PENDING.pop(m.from_user.id, None)
    if not db.has_consent(m.from_user.id): return await need_consent(m)
    await welcome(m)

@router.callback_query(F.data == "agree")
async def agree(c: CallbackQuery):
    db.give_consent(c.from_user.id); await c.answer("Accepted ✅"); await welcome(c.message)

@router.message(Command("menu"))
@router.message(F.text == "📋 Menu")
async def menu(m: Message):
    PENDING.pop(m.from_user.id, None)
    if not db.has_consent(m.from_user.id): return await need_consent(m)
    await m.answer("📋 <b>Choose a tool</b>", parse_mode="HTML", reply_markup=menu_kb())

@router.callback_query(F.data == "menu")
async def menu_cb(c: CallbackQuery):
    PENDING.pop(c.from_user.id, None); await c.answer()
    await c.message.answer("📋 <b>Choose a tool</b>", parse_mode="HTML", reply_markup=menu_kb())

@router.message(Command("help"))
async def help_cmd(m: Message):
    await m.answer(help_text(), parse_mode="HTML", reply_markup=menu_kb())

@router.callback_query(F.data == "help")
async def help_cb(c: CallbackQuery):
    await c.answer(); await c.message.answer(help_text(), parse_mode="HTML", reply_markup=back_kb())

async def ask(msg: Message, uid: int, cmd: str):
    PENDING[uid] = cmd; t = TOOLS[cmd]
    cost = "" if FREE_MODE or not t["cost"] else f"\n⭐ Costs {t['cost']} credits."
    await msg.answer(f"{t['icon']} <b>{t['title']}</b>\n✍️ Send the {t['what']} now.\nExample: <code>{esc(t['ex'])}</code>{cost}",
                     parse_mode="HTML", reply_markup=back_kb())

@router.callback_query(F.data.startswith("t:"))
async def pick(c: CallbackQuery):
    await c.answer()
    if not db.has_consent(c.from_user.id): return await need_consent(c.message)
    cmd = c.data[2:]
    if cmd == "photo":
        return await c.message.answer("🖼️ <b>Photo metadata</b>\nSend the photo as a <b>File</b>: tap the paperclip, choose <b>File</b>, "
                                      "pick the image. Telegram removes the data from normal photos.", parse_mode="HTML", reply_markup=back_kb())
    if cmd in TOOLS: await ask(c.message, c.from_user.id, cmd)

# ---------- balance / opt-out / buy / export ----------
@router.message(Command("balance"))
async def bal(m: Message):
    await m.answer("🎁 Everything is free right now." if FREE_MODE else f"⭐ You have {db.balance(m.from_user.id)} credits.")

@router.message(Command("optout"))
async def optout(m: Message):
    t = (m.text or "").partition(" ")[2].strip()
    if not t: return await m.answer("Usage: /optout <username, email, domain or IP>")
    db.add_optout(t); await m.answer("✅ Done. Future lookups of that identifier are blocked.")

@router.callback_query(F.data == "buy")
@router.message(Command("buy"))
async def buy(x):
    msg = x.message if isinstance(x, CallbackQuery) else x
    if FREE_MODE: await msg.answer("🎁 No need to buy anything. Everything is free right now.")
    else:
        rows = [[Btn(text=f"{c} credits for {s} ★", callback_data=f"pack:{k}")] for k, (c, s) in PACKS.items()]
        await msg.answer("⭐ Pay with Telegram Stars:", reply_markup=KB(inline_keyboard=rows))
    if isinstance(x, CallbackQuery): await x.answer()

@router.callback_query(F.data.startswith("pack:"))
async def pack(c: CallbackQuery):
    k = c.data.split(":")[1]; credits, stars = PACKS[k]
    await c.message.answer_invoice(title=f"{credits} credits", description="OSINT Hub lookup credits",
        payload=k, currency="XTR", prices=[LabeledPrice(label="Credits", amount=stars)], provider_token="")
    await c.answer()

async def send_export(msg: Message, uid: int):
    if uid not in LAST: return await msg.answer("Run a lookup first, then Export saves it.")
    name, arg, d = LAST[uid]
    data = json.dumps({"tool": name, "query": arg, "result": d}, indent=2).encode()
    await msg.answer_document(BufferedInputFile(data, f"osint_{name}.json"), caption="📄 Your full result")

@router.message(Command("export"))
async def export(m: Message): await send_export(m, m.from_user.id)

@router.callback_query(F.data == "export")
async def export_cb(c: CallbackQuery):
    await c.answer(); await send_export(c.message, c.from_user.id)

# ---------- running a tool with a moving progress bar ----------
def bar(p, n=14):
    f = max(0, min(n, int(p * n))); return "▰" * f + "▱" * (n - f)

async def spin(msg, t, prog):
    t0 = time.time()
    try:
        while True:
            await asyncio.sleep(1.4)
            el = time.time() - t0
            if prog and prog["total"]:
                p = min(0.99, prog["done"] / prog["total"]); extra = f" · {prog['done']}/{prog['total']} sites"
            else:
                p = min(0.93, 1 - math.exp(-2 * el / t["eta"])); extra = ""
            try: await msg.edit_text(f"{t['icon']} {t['label']}…\n{bar(p)} {int(p*100)}%{extra}\n⏱ {int(el)}s")
            except Exception: pass
    except asyncio.CancelledError:
        pass

def make_runner(cmd):
    t = TOOLS[cmd]; cost = 0 if FREE_MODE else t["cost"]
    async def run(m: Message, arg: str):
        uid = m.from_user.id
        if not db.has_consent(uid): return await need_consent(m)
        if not db.rate_ok(uid, RATE_LIMIT_PER_MIN): return await m.answer("⏳ Slow down: 20 lookups per minute.")
        if db.opted_out(arg): return await m.answer("🚫 This identifier was removed on request.")
        if cost and not db.spend(uid, cost, cmd):
            return await m.answer(f"⭐ This costs {cost} credits. You have {db.balance(uid)}. Use /buy.")
        db.audit(uid, cmd, arg)
        prog = {"done": 0, "total": 0} if t["prog"] else None
        extra = "\n(the first scan after install takes a few minutes)" if t["prog"] else ""
        wait = await m.answer(f"{t['icon']} {t['label']}…\n{bar(0)} 0%{extra}")
        task = asyncio.create_task(spin(wait, t, prog))
        async def stop(): task.cancel(); await asyncio.gather(task, return_exceptions=True)
        try:
            async with ChatActionSender.typing(bot=m.bot, chat_id=m.chat.id):
                d = await (t["fn"](arg, prog) if prog is not None else t["fn"](arg))
        except ValueError as e:
            await stop()
            if cost: db.refund(uid, cost, cmd)
            return await wait.edit_text("❌ " + esc(str(e)), reply_markup=back_kb())
        except Exception:
            await stop()
            if cost: db.refund(uid, cost, cmd)
            return await wait.edit_text("❌ The data source did not respond. Please try again.", reply_markup=after_kb(cmd))
        await stop()
        LAST[uid] = (cmd, arg, d)
        chunks, cur = [], ""
        for line in render(cmd, arg, d).split("\n"):
            if len(cur) + len(line) > 3800: chunks.append(cur); cur = ""
            cur += line + "\n"
        chunks.append(cur)
        kb = after_kb(cmd)
        if len(chunks) == 1:
            return await wait.edit_text(chunks[0], parse_mode="HTML", link_preview_options=NOPREV, reply_markup=kb)
        await wait.edit_text(chunks[0], parse_mode="HTML", link_preview_options=NOPREV)
        for i, ch in enumerate(chunks[1:], 1):
            await m.answer(ch, parse_mode="HTML", link_preview_options=NOPREV, reply_markup=kb if i == len(chunks) - 1 else None)
    RUNNERS[cmd] = run

    @router.message(Command(cmd))
    async def h(m: Message):
        arg = (m.text or "").partition(" ")[2].strip()
        if arg: return await run(m, arg)
        if not db.has_consent(m.from_user.id): return await need_consent(m)
        await ask(m, m.from_user.id, cmd)

for k in TOOLS: make_runner(k)

# ---------- smart chat: detect what the user sent ----------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
def detect(text):
    t = text.strip()
    try: ipaddress.ip_address(t); return "ip"
    except ValueError: pass
    if EMAIL_RE.match(t): return "email"
    if re.fullmatch(r"\+\d[\d\s\-()]{6,18}", t): return "phone"
    if re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", t): return "mac"
    if re.fullmatch(r"(bc1[a-z0-9]{20,70}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})", t): return "btc"
    d = re.sub(r"^https?://", "", t.lower()).split("/")[0]
    if tools.DOMAIN_RE.match(d): return "domain", d
    if t.startswith("@") and tools.USER_RE.match(t[1:]): return "username", t[1:]
    return None

@router.message(F.text & ~F.text.startswith("/"))
async def chat(m: Message):
    uid, text = m.from_user.id, m.text.strip()
    cmd = PENDING.pop(uid, None)
    if cmd: return await RUNNERS[cmd](m, text)
    kind = detect(text)
    if isinstance(kind, str): return await RUNNERS[kind](m, text)
    if isinstance(kind, tuple): return await RUNNERS[kind[0]](m, kind[1])
    low = text.lower()
    if re.search(r"\b(hi|hello|hey|salam|hola|yo)\b", low) and len(low) < 25:
        return await m.answer("👋 Hey! Pick a tool below, or send me an IP, domain, email, phone number or @username.", reply_markup=menu_kb())
    if re.fullmatch(r"[^\W\d_]+( [^\W\d_]+){1,3}", text):
        return await m.answer("🙋 That looks like a person's name. I can't search by name. I look up things like an IP, a domain, "
                              "an email, a phone number or a username (one handle, no spaces).\n\nIf you know their handle, tap 🔎 Username.",
                              reply_markup=menu_kb())
    await m.answer(help_text(), parse_mode="HTML", reply_markup=menu_kb())

# ---------- photo metadata ----------
def _deg(v, ref):
    d = float(v[0]) + float(v[1]) / 60 + float(v[2]) / 3600
    return -d if ref in ("S", "W") else d

@router.message(F.photo)
async def photo_hint(m: Message):
    await m.answer("🖼️ To read a photo's metadata, send it as a <b>File</b> (paperclip, then File), not as a normal photo.", parse_mode="HTML")

@router.message(F.document & F.document.mime_type.startswith("image/"))
async def exif(m: Message):
    if not db.has_consent(m.from_user.id): return await need_consent(m)
    if (m.document.file_size or 0) > 15_000_000: return await m.answer("❌ File too large (15 MB max).")
    wait = await m.answer(f"🖼️ Reading metadata…\n{bar(0.4)} 40%")
    try:
        from PIL import Image
        buf = io.BytesIO(); await m.bot.download(m.document, destination=buf); buf.seek(0)
        img = Image.open(buf); ex = img.getexif()
        out = {"format": img.format, "size": f"{img.width}x{img.height}"}
        for k, n in {271: "camera_make", 272: "camera_model", 305: "software", 306: "modified"}.items():
            if ex.get(k): out[n] = str(ex.get(k)).strip()
        t = ex.get_ifd(0x8769).get(36867)
        if t: out["taken"] = str(t)
        g = ex.get_ifd(0x8825)
        if g.get(2) and g.get(4):
            lat, lon = _deg(g[2], g.get(1)), _deg(g[4], g.get(3))
            out["gps"] = f"{lat:.6f}, {lon:.6f}"; out["map"] = f"https://maps.google.com/?q={lat:.6f},{lon:.6f}"
        if len(out) == 2: out["result"] = "No camera or location metadata found. It was probably stripped."
    except ImportError:
        return await wait.edit_text("❌ Image support is not installed. Run: pip install pillow")
    except Exception:
        return await wait.edit_text("❌ Could not read that image.")
    LAST[m.from_user.id] = ("exif", m.document.file_name or "image", out)
    await wait.edit_text("🖼️ <b>Photo metadata</b>\n\n" + fmt(out), parse_mode="HTML", link_preview_options=NOPREV,
                         reply_markup=KB(inline_keyboard=[[Btn(text="📄 Export", callback_data="export"), Btn(text="📋 Menu", callback_data="menu")]]))

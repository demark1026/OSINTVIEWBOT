import json, logging, os
from contextlib import asynccontextmanager
from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart, Command
from aiogram.types import (Update, InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo,
                           LabeledPrice, PreCheckoutQuery, Message)
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from . import db, tools, bot_cmds, wmn
from aiogram.types import BotCommand
from .auth import current_user
from .config import *

log = logging.getLogger("osint")
bot = Bot(BOT_TOKEN or "0:placeholder")
dp = Dispatcher()

dp.include_router(bot_cmds.router)

@dp.pre_checkout_query()
async def pre_checkout(q: PreCheckoutQuery):
    await q.answer(ok=q.invoice_payload in PACKS)

@dp.message(F.successful_payment)
async def paid(m: Message):
    p = m.successful_payment
    if p.invoice_payload in PACKS:
        # keyed on Telegram's charge id so retries never double-credit
        if db.credit(m.from_user.id, PACKS[p.invoice_payload][0], "stars", p.telegram_payment_charge_id):
            await m.answer(f"Added {PACKS[p.invoice_payload][0]} credits.")

@asynccontextmanager
async def lifespan(_):
    if WEBAPP_URL and BOT_TOKEN and not os.environ.get("POLLING"):
        await bot.set_webhook(f"{WEBAPP_URL}/webhook", secret_token=WEBHOOK_SECRET,
                              allowed_updates=["message", "callback_query", "pre_checkout_query"])
        await bot.set_my_commands([BotCommand(command=c, description=d) for c, d in bot_cmds.COMMANDS])
    yield
    await bot.session.close()

app = FastAPI(lifespan=lifespan)

@app.post("/webhook")
async def webhook(req: Request):
    if req.headers.get("X-Telegram-Bot-Api-Secret-Token") != WEBHOOK_SECRET:
        raise HTTPException(403)
    await dp.feed_update(bot, Update.model_validate(await req.json(), context={"bot": bot}))
    return {"ok": True}

class Q(BaseModel):
    q: str

def gate(user, target=None):
    uid = user["id"]
    if not db.has_consent(uid): raise HTTPException(403, "Accept the acceptable-use terms first.")
    if not db.rate_ok(uid, RATE_LIMIT_PER_MIN): raise HTTPException(429, "Slow down: 20 lookups per minute.")
    if target and db.opted_out(target): raise HTTPException(451, "This identifier was removed on request.")

async def run(user, name, fn, q, cost=0):
    gate(user, q.q.strip())
    uid = user["id"]
    if cost and not db.spend(uid, cost, name): raise HTTPException(402, f"Needs {cost} credits.")
    db.audit(uid, name, q.q.strip())
    try:
        return await fn(q.q)
    except ValueError as e:
        if cost: db.refund(uid, cost, name)
        raise HTTPException(400, str(e))
    except Exception:
        log.exception(name)
        if cost: db.refund(uid, cost, name)
        raise HTTPException(502, "The data source did not respond. You were not charged.")

@app.get("/api/me")
async def me(user=Depends(current_user)):
    return {"name": user.get("first_name"), "credits": db.balance(user["id"]),
            "consent": db.has_consent(user["id"]), "costs": {k: (0 if FREE_MODE else v["cost"]) for k, v in bot_cmds.TOOLS.items()}, "free": FREE_MODE,
            "packs": {k: {"credits": c, "stars": s} for k, (c, s) in PACKS.items()}}

@app.post("/api/consent")
async def consent(user=Depends(current_user)):
    db.give_consent(user["id"]); return {"ok": True}

@app.post("/api/free/ip")
async def f_ip(q: Q, user=Depends(current_user)): return await run(user, "ip", tools.ip_lookup, q)
@app.post("/api/free/domain")
async def f_dom(q: Q, user=Depends(current_user)): return await run(user, "domain", tools.domain_lookup, q)
@app.post("/api/free/username")
async def f_usr(q: Q, user=Depends(current_user)): return await run(user, "username", wmn.quick, q)
@app.post("/api/paid/subdomains")
async def p_sub(q: Q, user=Depends(current_user)):
    return await run(user, "subdomains", tools.subdomains, q, COSTS["subdomains"])
@app.post("/api/paid/breach")
async def p_br(q: Q, user=Depends(current_user)):
    return await run(user, "breach", tools.breach_check, q, COSTS["breach"])

class Pack(BaseModel):
    pack: str

@app.post("/api/invoice")
async def invoice(p: Pack, user=Depends(current_user)):
    if p.pack not in PACKS: raise HTTPException(400, "Unknown pack")
    credits, stars = PACKS[p.pack]
    link = await bot.create_invoice_link(title=f"{credits} credits", description="OSINT Hub lookup credits",
        payload=p.pack, provider_token="", currency="XTR", prices=[LabeledPrice(label="Credits", amount=stars)])
    return {"url": link}

@app.post("/api/tool/{name}")
async def any_tool(name: str, q: Q, user=Depends(current_user)):
    if name not in bot_cmds.TOOLS: raise HTTPException(404, "Unknown tool")
    fn, cost = bot_cmds.TOOLS[name]["fn"], bot_cmds.TOOLS[name]["cost"]
    return await run(user, name, fn, q, 0 if FREE_MODE else cost)

app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "..", "webapp"), html=True))

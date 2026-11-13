# OSINT Hub (Telegram bot + Mini App)

## Run
1. Create a bot with @BotFather, copy the token.
2. `cp .env.example .env`, fill it in (WEBAPP_URL must be public HTTPS; use a tunnel like cloudflared for dev).
3. `pip install -r requirements.txt`
4. `set -a; source .env; set +a; uvicorn app.main:app --host 0.0.0.0 --port 8000`
The webhook registers itself on startup. In BotFather, set the Mini App/menu button URL to WEBAPP_URL.

## What's included
- initData HMAC validation on every API call (`app/auth.py`)
- Credit ledger with idempotent Stars crediting keyed on charge id (`app/db.py`)
- Bot commands: /ip /domain /dns /username (free); /deepuser /subdomains /ports /breach (credits); /export /buy /balance /optout
- Mini App is an optional extra UI over the same tools
- Paid: subdomains via CT logs (passive), breach check via HIBP (needs `HIBP_API_KEY`)
- Terms consent gate, 20/min rate limit, audit log, `/optout`, auto-refund on failure

## Still to build
- Deep username enumeration (integrate Maigret's site list as an arq/Celery job)
- PDF/JSON export (WeasyPrint from the same result dicts)
- Subscription plans (Stars subscriptions), admin dashboard, Postgres + Redis cache
- Terms/privacy text reviewed by a lawyer; refund handling for Stars disputes

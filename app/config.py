import os
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
WEBAPP_URL = os.environ.get("WEBAPP_URL", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "dev-secret")
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")
DB_PATH = os.environ.get("DB_PATH", "osint.db")
RATE_LIMIT_PER_MIN = 20
COSTS = {"subdomains": 5, "breach": 10, "export": 1}
# Telegram Stars packs: id -> (credits, stars)
PACKS = {"s": (50, 50), "m": (150, 130), "l": (500, 400)}

# Everything free for now. Set FREE_MODE=0 in .env to turn credits back on.
FREE_MODE = os.environ.get("FREE_MODE", "1") == "1"
if FREE_MODE:
    COSTS = {k: 0 for k in COSTS}

# Optional: Google Cloud Vision key, turns on web-wide image search (Cloud Console > APIs > Cloud Vision API > Credentials)
GOOGLE_VISION_KEY = os.environ.get("GOOGLE_VISION_KEY", "")

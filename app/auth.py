import hashlib, hmac, json, time
from urllib.parse import parse_qsl
from fastapi import Header, HTTPException
from .config import BOT_TOKEN

def verify_init_data(init_data: str, max_age: int = 86400) -> dict:
    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received = pairs.pop("hash", "")
    check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    calc = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    if not received or not hmac.compare_digest(calc, received):
        raise ValueError("bad signature")
    if time.time() - int(pairs.get("auth_date", 0)) > max_age:
        raise ValueError("expired")
    return json.loads(pairs["user"])

async def current_user(authorization: str = Header(default="")) -> dict:
    """Every API call must send 'Authorization: tma <initData>'."""
    try:
        scheme, _, data = authorization.partition(" ")
        if scheme != "tma":
            raise ValueError
        return verify_init_data(data)
    except Exception:
        raise HTTPException(401, "Open this app from Telegram.")

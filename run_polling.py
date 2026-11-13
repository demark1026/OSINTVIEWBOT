"""Runs the bot (polling) AND the Mini App web server together. No public server needed for the bot itself."""
import asyncio, logging, os
os.environ["POLLING"] = "1"
import uvicorn
from aiogram.types import BotCommand, MenuButtonCommands
from app.main import app, bot, dp
from app.bot_cmds import COMMANDS
from app.config import WEBAPP_URL
from app import wmn

async def warmup():
    try:
        print("Warming up the username checker (first time takes a few minutes)...")
        await wmn.deep("octocat")
        print("Username checker ready.")
    except Exception as e:
        print("Warm-up skipped:", e)

async def main():
    logging.basicConfig(level=logging.INFO)
    me = await bot.get_me()
    print(f"Connected as @{me.username}")
    await bot.delete_webhook(drop_pending_updates=True)
    await bot.set_my_commands([BotCommand(command=c, description=d) for c, d in COMMANDS])
    await bot.set_chat_menu_button(menu_button=MenuButtonCommands())  # shows the command list button
    if WEBAPP_URL.startswith("https://"):
        print("Mini App URL:", WEBAPP_URL, "(opens from the button under /start)")
    else:
        print("WEBAPP_URL is not set to an https:// address, so the Mini App button is hidden.")
    port = int(os.environ.get("PORT", "8000"))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    asyncio.create_task(warmup())
    print(f"Bot is running. Mini App server on http://127.0.0.1:{port}. Press Ctrl+C to stop.")
    await asyncio.gather(server.serve(),
                         dp.start_polling(bot, allowed_updates=["message", "callback_query", "pre_checkout_query"]))

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("Stopped.")

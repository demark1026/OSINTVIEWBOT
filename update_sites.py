import asyncio
from app.wmn import load_sites
print(len(asyncio.run(load_sites(force=True))), "sites loaded")

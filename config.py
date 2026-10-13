import os
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
if not TELEGRAM_BOT_TOKEN:
    raise ValueError("TELEGRAM_BOT_TOKEN is not set in environment variables")

ADMIN_IDS_RAW = os.environ.get("ADMIN_IDS", "")
ADMIN_IDS = set()
if ADMIN_IDS_RAW:
    for part in ADMIN_IDS_RAW.split(","):
        part = part.strip()
        if part:
            try:
                ADMIN_IDS.add(int(part))
            except ValueError:
                pass

DATABASE_PATH = os.environ.get("DATABASE_PATH", "bot_data.db")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
RATE_LIMIT_PER_SECOND = float(os.environ.get("RATE_LIMIT_PER_SECOND", "25"))
RATE_LIMIT_PER_CHAT_PER_SECOND = float(os.environ.get("RATE_LIMIT_PER_CHAT_PER_SECOND", "0.8"))

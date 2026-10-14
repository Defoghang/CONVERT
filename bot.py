import logging
import sys
from logging.handlers import RotatingFileHandler
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters
from config import TELEGRAM_BOT_TOKEN, LOG_LEVEL
from database import init_db
from rate_limiter import SimpleRateLimiter
from handlers import (
    cmd_start, cmd_help,
    cmd_analyze, cmd_sastinfo,
    handle_message, handle_document, error_handler,
)


def setup_logging():
    fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    root = logging.getLogger()
    root.setLevel(LOG_LEVEL)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter(fmt))
    root.addHandler(ch)
    fh = RotatingFileHandler("bot.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter(fmt))
    root.addHandler(fh)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def main():
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Init DB")
    init_db()

    application = (
        ApplicationBuilder()
        .token(TELEGRAM_BOT_TOKEN)
        .rate_limiter(SimpleRateLimiter())
        .build()
    )

    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("help", cmd_help))
    application.add_handler(CommandHandler("sastinfo", cmd_sastinfo))
    application.add_handler(CommandHandler("analyze", cmd_analyze))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_error_handler(error_handler)

    logger.info("Demarrage polling (SAST only)")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()

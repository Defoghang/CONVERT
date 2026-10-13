import logging
import sys
from logging.handlers import RotatingFileHandler
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters
from config import TELEGRAM_BOT_TOKEN, LOG_LEVEL
from database import init_db
from rate_limiter import SimpleRateLimiter
from handlers import (
    cmd_start, cmd_help, cmd_echo, cmd_stats, cmd_status,
    cmd_broadcast, cmd_crack, cmd_crackf, cmd_johninfo, cmd_testwordlist,
    handle_message, error_handler,
)


def setup_logging():
    fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    root = logging.getLogger()
    root.setLevel(LOG_LEVEL)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter(fmt))
    root.addHandler(console)
    file_handler = RotatingFileHandler("bot.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(fmt))
    root.addHandler(file_handler)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def main():
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Initialisation de la base de donnees")
    init_db()

    application = (
        ApplicationBuilder()
        .token(TELEGRAM_BOT_TOKEN)
        .rate_limiter(SimpleRateLimiter())
        .build()
    )

    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("help", cmd_help))
    application.add_handler(CommandHandler("echo", cmd_echo))
    application.add_handler(CommandHandler("stats", cmd_stats))
    application.add_handler(CommandHandler("status", cmd_status))
    application.add_handler(CommandHandler("broadcast", cmd_broadcast))
    application.add_handler(CommandHandler("crack", cmd_crack))
    application.add_handler(CommandHandler("crackf", cmd_crackf))
    application.add_handler(CommandHandler("johninfo", cmd_johninfo))
    application.add_handler(CommandHandler("testwordlist", cmd_testwordlist))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_error_handler(error_handler)

    logger.info("Demarrage du bot en mode polling")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()

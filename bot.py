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
    cmd_broadcast, cmd_crack, cmd_crackf, cmd_crackrules,
    cmd_crackmask, cmd_crackhybrid, cmd_crackinc, cmd_crackincm,
    cmd_cracksingle, cmd_johninfo, cmd_wordlist, cmd_formats,
    cmd_rules, cmd_extractors, cmd_extract,
    cmd_pdfcrack, cmd_pdfinfo,
    handle_message, handle_document, error_handler,
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
    application.add_handler(CommandHandler("johninfo", cmd_johninfo))
    application.add_handler(CommandHandler("wordlist", cmd_wordlist))
    application.add_handler(CommandHandler("formats", cmd_formats))
    application.add_handler(CommandHandler("rules", cmd_rules))
    application.add_handler(CommandHandler("extractors", cmd_extractors))
    application.add_handler(CommandHandler("extract", cmd_extract))
    application.add_handler(CommandHandler("pdfinfo", cmd_pdfinfo))
    application.add_handler(CommandHandler("pdfcrack", cmd_pdfcrack))
    application.add_handler(CommandHandler("crack", cmd_crack))
    application.add_handler(CommandHandler("crackf", cmd_crackf))
    application.add_handler(CommandHandler("crackrules", cmd_crackrules))
    application.add_handler(CommandHandler("crackmask", cmd_crackmask))
    application.add_handler(CommandHandler("crackhybrid", cmd_crackhybrid))
    application.add_handler(CommandHandler("crackinc", cmd_crackinc))
    application.add_handler(CommandHandler("crackincm", cmd_crackincm))
    application.add_handler(CommandHandler("cracksingle", cmd_cracksingle))
    application.add_handler(CommandHandler("broadcast", cmd_broadcast))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_error_handler(error_handler)

    logger.info("Demarrage du bot en mode polling")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()

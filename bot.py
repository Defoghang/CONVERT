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
    cmd_rules, cmd_extractors, cmd_pdfinfo, cmd_pdfcrack, cmd_pdfanalyze,
    cmd_pdfcrackcmd, cmd_tools, cmd_hdetect, cmd_hcrack, cmd_hcrackm,
    cmd_binwalk, cmd_strings, cmd_tool7z, cmd_steginfo, cmd_stegcrack,
    cmd_decode, cmd_harvest,
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

    commands = [
        ("start", cmd_start), ("help", cmd_help), ("echo", cmd_echo),
        ("stats", cmd_stats), ("status", cmd_status), ("tools", cmd_tools),
        ("johninfo", cmd_johninfo), ("wordlist", cmd_wordlist),
        ("formats", cmd_formats), ("rules", cmd_rules),
        ("extractors", cmd_extractors),
        ("crack", cmd_crack), ("crackf", cmd_crackf),
        ("crackrules", cmd_crackrules), ("crackmask", cmd_crackmask),
        ("crackhybrid", cmd_crackhybrid), ("crackinc", cmd_crackinc),
        ("crackincm", cmd_crackincm), ("cracksingle", cmd_cracksingle),
        ("hdetect", cmd_hdetect), ("hcrack", cmd_hcrack), ("hcrackm", cmd_hcrackm),
        ("pdfinfo", cmd_pdfinfo), ("pdfcrack", cmd_pdfcrack),
        ("pdfanalyze", cmd_pdfanalyze), ("pdfcrackcmd", cmd_pdfcrackcmd),
        ("binwalk", cmd_binwalk), ("strings", cmd_strings), ("tool7z", cmd_tool7z),
        ("steginfo", cmd_steginfo), ("stegcrack", cmd_stegcrack),
        ("decode", cmd_decode), ("harvest", cmd_harvest),
        ("broadcast", cmd_broadcast),
    ]
    for name, fn in commands:
        application.add_handler(CommandHandler(name, fn))

    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_error_handler(error_handler)

    logger.info("Demarrage polling")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()

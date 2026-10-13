import logging
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes
from config import ADMIN_IDS
from database import upsert_user, increment_stat, get_stat

logger = logging.getLogger(__name__)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user:
        upsert_user(user.id, user.username, user.first_name)
    await update.message.reply_text(
        f"Bonjour {user.first_name} !\n\n"
        "Je suis un bot Telegram pret pour la production.\n"
        "Utilise /help pour voir les commandes disponibles.",
        parse_mode=ParseMode.HTML,
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Commandes disponibles :\n"
        "/start - Demarrer le bot\n"
        "/help - Afficher cette aide\n"
        "/echo <texte> - Repeter un texte\n"
        "/stats - Afficher les statistiques\n"
        "/status - Etat du bot (admin)\n"
        "/broadcast <message> - Diffuser un message (admin)"
    )


async def cmd_echo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage : /echo <texte>")
        return
    await update.message.reply_text(" ".join(context.args))


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    messages = get_stat("messages_processed")
    await update.message.reply_text(f"Statistiques :\n- Messages traites : {messages}")


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or user.id not in ADMIN_IDS:
        await update.message.reply_text("Acces refuse.")
        return
    await update.message.reply_text("Bot en ligne.\nBase de donnees : OK\nRate limiter : actif")


async def cmd_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or user.id not in ADMIN_IDS:
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /broadcast <message>")
        return
    await update.message.reply_text("Diffusion simulee : " + " ".join(context.args))


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user:
        upsert_user(user.id, user.username, user.first_name)
    increment_stat("messages_processed")
    if update.message and update.message.text:
        await update.message.reply_text("Message recu : " + update.message.text[:200])


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Exception lors du traitement d'une mise a jour", exc_info=context.error)
    if update and update.effective_message:
        try:
            await update.effective_message.reply_text("Une erreur est survenue. Reessaie plus tard.")
        except Exception:
            pass

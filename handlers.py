import logging
import os
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes
from config import ADMIN_IDS
from database import upsert_user, increment_stat, get_stat
from john_service import (
    JohnError,
    validate_hashes,
    crack_hashes,
    cleanup_workdir,
    get_john_version,
    is_john_available,
)

logger = logging.getLogger(__name__)

WORDLIST_PATH = "/usr/share/wordlists/rockyou.txt"


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
        "/broadcast <message> - Diffuser un message (admin)\n"
        "/crack <hash> - Crack un hash avec John the Ripper (admin)\n"
        "/johninfo - Version de John the Ripper (admin)\n"
        "/testwordlist - Verifier la wordlist (admin)"
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
    john_status = "OK" if is_john_available() else "INDISPONIBLE"
    await update.message.reply_text(
        f"Bot en ligne.\n"
        f"Base de donnees : OK\n"
        f"Rate limiter : actif\n"
        f"John the Ripper : {john_status}"
    )


async def cmd_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or user.id not in ADMIN_IDS:
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /broadcast <message>")
        return
    await update.message.reply_text("Diffusion simulee : " + " ".join(context.args))


async def cmd_johninfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or user.id not in ADMIN_IDS:
        await update.message.reply_text("Acces refuse.")
        return
    if not is_john_available():
        await update.message.reply_text("John the Ripper n'est pas installe.")
        return
    version = get_john_version()
    await update.message.reply_text(f"John the Ripper :\n{version}")


async def cmd_testwordlist(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or user.id not in ADMIN_IDS:
        await update.message.reply_text("Acces refuse.")
        return
    if os.path.isfile(WORDLIST_PATH):
        size = os.path.getsize(WORDLIST_PATH)
        await update.message.reply_text(
            f"Wordlist presente.\nChemin : {WORDLIST_PATH}\nTaille : {size} octets"
        )
    else:
        await update.message.reply_text(
            f"Wordlist absente : {WORDLIST_PATH}\n"
            "Elle sera installee par le workflow GitHub Actions."
        )


async def cmd_crack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or user.id not in ADMIN_IDS:
        await update.message.reply_text("Acces refuse.")
        return

    if not context.args:
        await update.message.reply_text(
            "Usage : /crack <hash1> [hash2] ...\n"
            "Exemple : /crack 5f4dcc3b5aa765d61d8327deb882cf99\n"
            "Formats supportes : md5, sha1, sha256, bcrypt, sha512crypt, etc."
        )
        return

    raw = " ".join(context.args)
    try:
        hashes = validate_hashes(raw)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur de validation : {exc}")
        return

    await update.message.reply_text(
        f"Analyse de {len(hashes)} hash(es) en cours...\n"
        "Cela peut prendre du temps selon la complexite."
    )

    result = None
    try:
        result = crack_hashes(hashes, wordlist=WORDLIST_PATH)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur John : {exc}")
        return

    try:
        lines = []
        lines.append(f"Resultat de session {result['session_id']}")
        lines.append(f"Hashes traites : {result['total']}")
        lines.append(f"Hashes cracks : {result['cracked_count']}")
        lines.append("")
        if result["cracked"]:
            for h, pwd in result["cracked"].items():
                lines.append(f"{h} -> {pwd}")
        else:
            lines.append("Aucun mot de passe trouve avec la wordlist actuelle.")
        text = "\n".join(lines)
        if len(text) > 4000:
            text = text[:4000] + "\n...(tronque)"
        await update.message.reply_text(text)
    finally:
        if result:
            cleanup_workdir(result["workdir"])


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

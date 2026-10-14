import logging
import os
import shutil
from telegram import Update
from telegram.ext import ContextTypes
from config import ADMIN_IDS
from database import upsert_user, increment_stat, get_stat
from sast_service import (
    SastError,
    analyze as sast_analyze,
    is_semgrep_available,
    is_bandit_available,
    get_versions as sast_versions,
    cleanup_workdir as sast_cleanup,
)

logger = logging.getLogger(__name__)

SAST_MAX_INPUT_SIZE = 50 * 1024 * 1024


def _is_admin(update):
    user = update.effective_user
    return user is not None and user.id in ADMIN_IDS


def _truncate(text, limit=4000):
    if not text:
        return "(vide)"
    if len(text) <= limit:
        return text
    return text[: limit - 20] + "\n...(tronque)"


def _sanitize_filename(name):
    if not name:
        return "archive.zip"
    name = os.path.basename(name)
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    return safe[:120] or "archive.zip"


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user:
        upsert_user(user.id, user.username, user.first_name)
    await update.message.reply_text(
        f"Bonjour {user.first_name} !\n\n"
        "Bot SAST pret.\n"
        "Envoie une archive .zip de ton code avec la legende /analyze.\n"
        "Utilise /help pour plus de details."
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "Commandes disponibles :\n"
        "/start - Demarrer le bot\n"
        "/help - Afficher cette aide\n"
        "/sastinfo - Etat des outils SAST (admin)\n"
        "/analyze - Analyser une archive ZIP de code (admin)\n"
        "\n"
        "Utilisation de /analyze :\n"
        "1. Compresse ton code source en .zip\n"
        "2. Envoie le .zip avec la legende /analyze\n"
        "3. Le bot renvoie deux fichiers :\n"
        "   - rapport_securite.txt (findings + corrections)\n"
        "   - code_analyse.zip (code source)\n"
        "\n"
        "Langages supportes : .py .js .ts .java .go .rb .php\n"
        ".c .cpp .cs .rs .swift .sh .yml .sql"
    )
    await update.message.reply_text(text)


async def cmd_sastinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    versions = sast_versions()
    text = "Outils SAST :\n"
    text += "Semgrep : " + ("OK" if is_semgrep_available() else "INDISPONIBLE")
    if "semgrep" in versions:
        text += " (" + str(versions["semgrep"]) + ")"
    text += "\n"
    text += "Bandit : " + ("OK" if is_bandit_available() else "INDISPONIBLE")
    if "bandit" in versions:
        text += " (" + str(versions["bandit"]) + ")"
    text += "\n\n"
    text += (
        "Utilisation :\n"
        "Envoie un ZIP de ton projet avec la legende /analyze.\n"
        "Le bot renvoie :\n"
        "- rapport_securite.txt (findings + corrections)\n"
        "- code_analyse.zip (code source complet)"
    )
    await update.message.reply_text(text)


async def cmd_analyze(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not is_semgrep_available() and not is_bandit_available():
        await update.message.reply_text("Aucun outil SAST disponible.")
        return

    doc = None
    if update.message.document:
        doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        doc = update.message.reply_to_message.document

    if not doc:
        await update.message.reply_text(
            "Envoie une archive ZIP avec la legende /analyze,\n"
            "ou reponds a un ZIP deja envoye avec /analyze."
        )
        return

    name = (doc.file_name or "").lower()
    if not name.endswith(".zip"):
        await update.message.reply_text("Format non supporte. Envoie un .zip.")
        return
    if doc.file_size and doc.file_size > SAST_MAX_INPUT_SIZE:
        await update.message.reply_text("Archive trop volumineuse (max 50 Mo).")
        return

    workdir = "/tmp/sast_input_" + doc.file_unique_id
    os.makedirs(workdir, exist_ok=True)
    status = await update.message.reply_text("Telechargement de l'archive...")

    result = None
    try:
        tg_file = await doc.get_file()
        input_zip = os.path.join(workdir, "input.zip")
        await tg_file.download_to_drive(input_zip)

        await status.edit_text(
            "Analyse SAST en cours (Semgrep + Bandit)...\n"
            "Cela peut prendre plusieurs minutes."
        )

        result = sast_analyze(input_zip)

        summary = "Analyse terminee.\n\n"
        summary += "Fichiers analyses : " + str(result["files_scanned"]) + "\n"
        summary += "Total findings : " + str(result["findings_count"]) + "\n"

        sev_count = {}
        for f in result["findings"]:
            s = str(f.get("severity", "INFO")).upper()
            sev_count[s] = sev_count.get(s, 0) + 1
        if sev_count:
            summary += "\nRepartition par severite :\n"
            for s in sev_count:
                summary += "  " + s + " : " + str(sev_count[s]) + "\n"

        await status.edit_text(summary + "\nEnvoi du rapport...")

        with open(result["report_path"], "rb") as fh:
            await update.message.reply_document(
                document=fh,
                filename="rapport_securite.txt",
                caption=(
                    "Rapport SAST - "
                    + str(result["findings_count"])
                    + " findings sur "
                    + str(result["files_scanned"])
                    + " fichiers"
                ),
            )

        await status.edit_text("Envoi du code source...")

        with open(result["archive_path"], "rb") as fh:
            await update.message.reply_document(
                document=fh,
                filename="code_analyse.zip",
                caption="Code source analyse (" + str(result["archive_size"] // 1024) + " Ko)",
            )

        await status.edit_text(
            "Termine.\n"
            + str(result["findings_count"])
            + " vulnerabilites detectees.\n"
            "Rapport et code source envoyes."
        )
    except SastError as exc:
        await status.edit_text("Erreur SAST : " + str(exc))
    except Exception as exc:
        await status.edit_text("Erreur : " + str(exc))
    finally:
        if result:
            sast_cleanup(result["workdir"])
        if os.path.isdir(workdir):
            shutil.rmtree(workdir, ignore_errors=True)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user:
        upsert_user(user.id, user.username, user.first_name)
    increment_stat("messages_processed")
    if update.message and update.message.text:
        await update.message.reply_text(
            "Commande non reconnue. Utilise /help."
        )


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.document:
        return
    caption = (update.message.caption or "").strip()
    parts = caption.split() if caption else []
    command = parts[0].split("@")[0] if parts else ""

    if command == "/analyze":
        await cmd_analyze(update, context)
        return

    if _is_admin(update):
        await update.message.reply_text(
            "Pour analyser ce code, renvoie-le avec la legende /analyze\n"
            "(format attendu : archive .zip)."
        )


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Exception", exc_info=context.error)
    if update and update.effective_message:
        try:
            await update.effective_message.reply_text("Erreur. Reessaie plus tard.")
        except Exception:
            pass

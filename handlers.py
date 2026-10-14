import logging
import os
import shutil
from telegram import Update
from telegram.ext import ContextTypes
from config import ADMIN_IDS
from database import upsert_user, increment_stat
from sast_service import (
    SastError,
    analyze as sast_analyze,
    is_semgrep_available,
    is_bandit_available,
    is_supported_filename,
    get_versions as sast_versions,
    cleanup_workdir as sast_cleanup,
    SUPPORTED_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    SOURCE_EXTENSIONS,
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


def _ext_list(exts, per_line=8, max_items=32):
    items = list(exts)[:max_items]
    lines = []
    for i in range(0, len(items), per_line):
        lines.append("  " + " ".join(items[i:i + per_line]))
    return "\n".join(lines)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user:
        upsert_user(user.id, user.username, user.first_name)
    await update.message.reply_text(
        f"Bonjour {user.first_name} !\n\n"
        "Bot SAST pret.\n"
        "Envoie une archive de ton code (zip, tar, tar.gz, rar, 7z...)\n"
        "ou un fichier source unique, puis reponds avec /analyze.\n"
        "Utilise /help pour les details."
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "Commandes :\n"
        "/start - Demarrer le bot\n"
        "/help - Afficher cette aide\n"
        "/sastinfo - Etat des outils SAST (admin)\n"
        "/analyze - Analyser un fichier de code (admin)\n"
        "\n"
        "Utilisation :\n"
        "1. Envoie une archive (zip, tar, tar.gz, tgz, tar.bz2, tar.xz,\n"
        "   rar, 7z, gz, bz2, xz) OU un fichier source unique\n"
        "2. Reponds avec /analyze (ou envoie le fichier avec la legende /analyze)\n"
        "3. Le bot renvoie :\n"
        "   - rapport_securite.txt (findings + corrections)\n"
        "   - code_analyse.zip (code source complet)\n"
        "\n"
        "Archives supportees :\n"
        + _ext_list(ARCHIVE_EXTENSIONS, per_line=6)
        + "\n"
        "\nExtensions source reconnues :\n"
        + _ext_list(SOURCE_EXTENSIONS, per_line=8)
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
        "Envoie une archive de ton code avec la legende /analyze,\n"
        "ou reponds a un fichier deja envoye avec /analyze.\n\n"
        "Extensions supportees : " + str(len(SUPPORTED_EXTENSIONS))
    )
    await update.message.reply_text(text)


async def _process_analysis(update, doc):
    workdir = "/tmp/sast_input_" + doc.file_unique_id
    os.makedirs(workdir, exist_ok=True)
    status = await update.message.reply_text("Telechargement du fichier...")

    result = None
    try:
        tg_file = await doc.get_file()
        safe_name = os.path.basename(doc.file_name or "input")
        input_path = os.path.join(workdir, safe_name)
        await tg_file.download_to_drive(input_path)

        kind_msg = "archive" if (doc.file_name or "").lower().endswith(ARCHIVE_EXTENSIONS) else "fichier"
        await status.edit_text(
            f"Analyse SAST en cours ({kind_msg})...\n"
            "Semgrep + Bandit. Cela peut prendre plusieurs minutes."
        )

        result = sast_analyze(input_path)

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

        if result["findings_count"] == 0:
            summary += "\nAucune vulnerabilite detectee par les outils."

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
        logger.exception("Erreur analyse")
        await status.edit_text("Erreur : " + str(exc))
    finally:
        if result:
            sast_cleanup(result["workdir"])
        if os.path.isdir(workdir):
            shutil.rmtree(workdir, ignore_errors=True)


async def cmd_analyze(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not is_semgrep_available() and not is_bandit_available():
        await update.message.reply_text("Aucun outil SAST disponible sur cet environnement.")
        return

    doc = None
    if update.message.document:
        doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        doc = update.message.reply_to_message.document

    if not doc:
        await update.message.reply_text(
            "Envoie un fichier de code avec la legende /analyze,\n"
            "ou reponds a un fichier deja envoye avec /analyze.\n\n"
            "Archives : zip, tar, tar.gz, tgz, tar.bz2, tar.xz, rar, 7z, gz, bz2, xz\n"
            "Sources : " + str(len(SOURCE_EXTENSIONS)) + " extensions reconnues (voir /help)"
        )
        return

    if not is_supported_filename(doc.file_name):
        await update.message.reply_text(
            "Extension non supportee : " + str(doc.file_name) + "\n"
            "Envoie une archive ou un fichier source. Voir /help."
        )
        return

    if doc.file_size and doc.file_size > SAST_MAX_INPUT_SIZE:
        await update.message.reply_text("Fichier trop volumineux (max 50 Mo).")
        return

    await _process_analysis(update, doc)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user:
        upsert_user(user.id, user.username, user.first_name)
    increment_stat("messages_processed")
    if update.message and update.message.text:
        await update.message.reply_text("Commande non reconnue. Utilise /help.")


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.document:
        return

    doc = update.message.document
    caption = (update.message.caption or "").strip()
    parts = caption.split() if caption else []
    command = parts[0].split("@")[0] if parts else ""

    if not _is_admin(update):
        return

    if command == "/analyze":
        await cmd_analyze(update, context)
        return

    if is_supported_filename(doc.file_name):
        if doc.file_size and doc.file_size > SAST_MAX_INPUT_SIZE:
            await update.message.reply_text("Fichier trop volumineux (max 50 Mo).")
            return
        await _process_analysis(update, doc)
        return

    await update.message.reply_text(
        "Format non supporte. Envoie une archive (zip, tar, tar.gz, tgz, rar, 7z...)\n"
        "ou un fichier source. Utilise /help pour la liste complete."
    )


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Exception", exc_info=context.error)
    if update and update.effective_message:
        try:
            await update.effective_message.reply_text("Erreur. Reessaie plus tard.")
        except Exception:
            pass

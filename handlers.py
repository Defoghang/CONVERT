import logging
import os
import shutil
import time
import zipfile as _zip
from telegram import Update
from telegram.ext import ContextTypes
from config import ADMIN_IDS
from database import upsert_user, increment_stat
from ai_service import (
    AIError,
    is_ai_available,
    fix_all_files,
    generate_fix_summary,
)
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
PENDING_KEY = "pending_action"
PENDING_TIMEOUT_SECONDS = 600


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


def _set_pending(context, action):
    context.user_data[PENDING_KEY] = {
        "action": action,
        "timestamp": time.time(),
    }


def _get_pending(context):
    pending = context.user_data.get(PENDING_KEY)
    if not pending:
        return None
    if time.time() - pending.get("timestamp", 0) > PENDING_TIMEOUT_SECONDS:
        context.user_data.pop(PENDING_KEY, None)
        return None
    return pending.get("action")


def _clear_pending(context):
    context.user_data.pop(PENDING_KEY, None)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user:
        upsert_user(user.id, user.username, user.first_name)
    await update.message.reply_text(
        f"Bonjour {user.first_name} !\n\n"
        "Bot SAST + IA pret.\n\n"
        "Deux facons d'utiliser :\n"
        "1. Envoie le fichier avec la legende /analyze ou /fixall\n"
        "2. Envoie /analyze ou /fixall seul, puis envoie le fichier\n\n"
        "Utilise /help pour les details."
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "Commandes :\n"
        "/start - Demarrer le bot\n"
        "/help - Afficher cette aide\n"
        "/sastinfo - Etat des outils (admin)\n"
        "/analyze - Analyse statique (admin)\n"
        "/fixall - Analyse + correction IA + validation tests (admin)\n"
        "\n"
        "Deux methodes pour chaque commande :\n"
        "A) Envoie le fichier avec la legende /analyze ou /fixall\n"
        "B) Envoie /analyze ou /fixall seul, puis le fichier juste apres\n"
        "\n"
        "/analyze produit :\n"
        "  - rapport_securite.txt\n"
        "  - code_analyse.zip\n"
        "\n"
        "/fixall produit :\n"
        "  - corrections_ia_*.txt (rapport de correction)\n"
        "  - code_corrige.zip (code corrige et valide)\n"
        "\n"
        "Archives supportees :\n"
        + _ext_list(ARCHIVE_EXTENSIONS, per_line=6)
        + "\n\nExtensions source :\n"
        + _ext_list(SOURCE_EXTENSIONS, per_line=8)
    )
    await update.message.reply_text(text)


async def cmd_sastinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    versions = sast_versions()
    text = "Outils disponibles :\n"
    text += "Semgrep : " + ("OK" if is_semgrep_available() else "INDISPONIBLE")
    if "semgrep" in versions:
        text += " (" + str(versions["semgrep"]) + ")"
    text += "\n"
    text += "Bandit : " + ("OK" if is_bandit_available() else "INDISPONIBLE")
    if "bandit" in versions:
        text += " (" + str(versions["bandit"]) + ")"
    text += "\n"
    text += "IA (Groq) : " + ("OK" if is_ai_available() else "INDISPONIBLE (GROQ_API_KEY manquant)")
    text += "\n\n"
    text += "Commandes : /analyze /fixall"
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

        await status.edit_text(
            "Analyse SAST en cours...\n"
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


async def _process_fixall(update, doc):
    workdir = "/tmp/fixall_" + doc.file_unique_id
    os.makedirs(workdir, exist_ok=True)
    status = await update.message.reply_text("Telechargement de l'archive...")

    result = None
    fix_results = []
    try:
        tg_file = await doc.get_file()
        input_zip = os.path.join(workdir, "input.zip")
        await tg_file.download_to_drive(input_zip)

        await status.edit_text("Etape 1/3 : Analyse SAST (Semgrep + Bandit)...")

        result = sast_analyze(input_zip)

        if result["findings_count"] == 0:
            await status.edit_text(
                "Aucune vulnerabilite detectee.\n"
                "Il n'y a rien a corriger pour ce fichier.\n\n"
                "Fichiers analyses : " + str(result["files_scanned"]) + "\n"
                "Findings : 0"
            )
            return

        await status.edit_text(
            "Etape 2/3 : Correction IA + validation tests...\n"
            + str(result["findings_count"])
            + " vulnerabilites detectees.\n"
            "Le LLM corrige, teste, et itere jusqu'a validation.\n"
            "Cela peut prendre plusieurs minutes."
        )

        fix_results = fix_all_files(result["workdir"], result["findings"])

        await status.edit_text("Etape 3/3 : Generation du rapport final...")

        fix_summary = generate_fix_summary(fix_results)

        ts = time.strftime("%Y%m%d_%H%M%S")
        fix_report_name = "corrections_ia_" + ts + ".txt"
        fix_report_path = os.path.join(result["workdir"], fix_report_name)
        with open(fix_report_path, "w", encoding="utf-8") as fh:
            fh.write(fix_summary)

        fix_zip_path = os.path.join(result["workdir"], "code_corrige.zip")
        skip_names = {
            "_semgrep.json", "_bandit.json", fix_report_name,
            "code_corrige.zip", "code_analyse.zip", "rapport_securite.txt",
        }
        with _zip.ZipFile(fix_zip_path, "w", _zip.ZIP_DEFLATED, compresslevel=6) as zf:
            for root, dirs, files in os.walk(result["workdir"]):
                dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
                for f in files:
                    if f in skip_names or f.endswith(".bak"):
                        continue
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, result["workdir"])
                    try:
                        zf.write(full, rel)
                    except OSError:
                        continue

        fixed_count = sum(1 for r in fix_results if r.get("fixed"))
        total_count = len(fix_results)

        summary_text = (
            "Correction IA terminee.\n\n"
            "Fichiers avec findings : " + str(total_count) + "\n"
            "Fichiers corriges et valides : " + str(fixed_count) + "\n"
            "Echecs : " + str(total_count - fixed_count) + "\n\n"
            "Envoi du rapport de corrections..."
        )
        await status.edit_text(summary_text)

        with open(fix_report_path, "rb") as fh:
            await update.message.reply_document(
                document=fh,
                filename=fix_report_name,
                caption="Rapport IA - " + str(fixed_count) + "/" + str(total_count) + " fichiers corriges",
            )

        await status.edit_text("Envoi du code corrige...")

        with open(fix_zip_path, "rb") as fh:
            await update.message.reply_document(
                document=fh,
                filename="code_corrige.zip",
                caption="Code source corrige et valide par tests",
            )

        await status.edit_text(
            "Termine.\n"
            + str(fixed_count) + " fichiers corriges, "
            + str(total_count - fixed_count) + " echecs.\n"
            "Rapport et code corrige envoyes."
        )

    except SastError as exc:
        await status.edit_text("Erreur SAST : " + str(exc))
    except AIError as exc:
        await status.edit_text("Erreur IA : " + str(exc))
    except Exception as exc:
        logger.exception("Erreur fixall")
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
        await update.message.reply_text("Aucun outil SAST disponible.")
        return

    doc = None
    if update.message.document:
        doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        doc = update.message.reply_to_message.document

    if doc:
        if not is_supported_filename(doc.file_name):
            await update.message.reply_text("Extension non supportee. Voir /help.")
            return
        if doc.file_size and doc.file_size > SAST_MAX_INPUT_SIZE:
            await update.message.reply_text("Fichier trop volumineux (max 50 Mo).")
            return
        _clear_pending(context)
        await _process_analysis(update, doc)
        return

    _set_pending(context, "analyze")
    await update.message.reply_text(
        "Mode analyse active.\n\n"
        "Envoie maintenant le fichier (archive ou source).\n"
        "Il sera analyse automatiquement dans les 10 minutes."
    )


async def cmd_fixall(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not is_ai_available():
        await update.message.reply_text(
            "GROQ_API_KEY non configuree. Ajoute le secret dans GitHub."
        )
        return
    if not is_semgrep_available() and not is_bandit_available():
        await update.message.reply_text("Aucun outil SAST disponible.")
        return

    doc = None
    if update.message.document:
        doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        doc = update.message.reply_to_message.document

    if doc:
        name = (doc.file_name or "").lower()
        if not name.endswith(".zip"):
            await update.message.reply_text("Format attendu : archive .zip")
            return
        if doc.file_size and doc.file_size > SAST_MAX_INPUT_SIZE:
            await update.message.reply_text("Archive trop volumineuse (max 50 Mo).")
            return
        _clear_pending(context)
        await _process_fixall(update, doc)
        return

    _set_pending(context, "fixall")
    await update.message.reply_text(
        "Mode correction IA active.\n\n"
        "Envoie maintenant l'archive ZIP (sans legende, juste le fichier).\n"
        "Le bot va analyser, corriger via IA et valider par tests.\n"
        "Tu as 10 minutes pour envoyer le fichier."
    )


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
        _clear_pending(context)
        await cmd_analyze(update, context)
        return

    if command == "/fixall":
        _clear_pending(context)
        await cmd_fixall(update, context)
        return

    pending = _get_pending(context)
    if pending == "fixall":
        _clear_pending(context)
        if (doc.file_name or "").lower().endswith(".zip"):
            if doc.file_size and doc.file_size > SAST_MAX_INPUT_SIZE:
                await update.message.reply_text("Archive trop volumineuse (max 50 Mo).")
                return
            await _process_fixall(update, doc)
            return
        await update.message.reply_text(
            "Mode correction IA attendait un .zip. "
            "Fichier recu : " + str(doc.file_name) + "\n"
            "Renvoie une archive .zip ou relance /fixall."
        )
        return

    if pending == "analyze":
        _clear_pending(context)
        if is_supported_filename(doc.file_name):
            if doc.file_size and doc.file_size > SAST_MAX_INPUT_SIZE:
                await update.message.reply_text("Fichier trop volumineux (max 50 Mo).")
                return
            await _process_analysis(update, doc)
            return
        await update.message.reply_text(
            "Mode analyse attendait un fichier supporte. "
            "Fichier recu : " + str(doc.file_name) + "\n"
            "Utilise /help pour la liste des extensions."
        )
        return

    if is_supported_filename(doc.file_name):
        if doc.file_size and doc.file_size > SAST_MAX_INPUT_SIZE:
            await update.message.reply_text("Fichier trop volumineux (max 50 Mo).")
            return
        await _process_analysis(update, doc)
        return

    await update.message.reply_text(
        "Format non supporte.\n"
        "Envoie un fichier avec /analyze ou /fixall en legende,\n"
        "ou utilise /analyze ou /fixall seul puis envoie le fichier."
    )


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Exception", exc_info=context.error)
    if update and update.effective_message:
        try:
            await update.effective_message.reply_text("Erreur. Reessaie plus tard.")
        except Exception:
            pass

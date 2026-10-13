import logging
import os
import re
import shutil
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes
from config import ADMIN_IDS
from database import upsert_user, increment_stat, get_stat
from john_service import (
    JohnError,
    validate_hashes,
    crack_hashes,
    crack_incremental,
    crack_mask,
    crack_single,
    crack_hybrid,
    crack_with_rules,
    list_formats,
    list_rules,
    extract_hash_from_file,
    available_extractors,
    cleanup_workdir,
    get_john_version,
    is_john_available,
    find_john_binary,
)
from pdf_service import (
    PdfError,
    extract_pdf_hash,
    decrypt_pdf,
    make_session_dir,
    cleanup_dir,
    validate_pdf,
    find_pdf2john,
    is_qpdf_available,
)

logger = logging.getLogger(__name__)

WORDLIST_PATH = "/usr/share/wordlists/rockyou.txt"
MAX_TELEGRAM_MESSAGE = 4000
PDF_MAX_FILE_SIZE = 20 * 1024 * 1024

MASK_TOKEN_RE = re.compile(r"^[?a-zA-Z0-9,\-\[\]:. ]{1,120}$")
FORMAT_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,50}$")
RULES_RE = re.compile(r"^[a-zA-Z0-9_\-+,/]{1,200}$")


def _is_admin(update):
    user = update.effective_user
    return user is not None and user.id in ADMIN_IDS


def _truncate(text, limit=MAX_TELEGRAM_MESSAGE):
    if len(text) <= limit:
        return text
    return text[: limit - 20] + "\n...(tronque)"


def _format_crack_result(result, title):
    lines = [f"Resultat de session {result['session_id']}"]
    lines.append(f"{title}")
    lines.append(f"Hashes traites : {result['total']}")
    lines.append(f"Hashes cracks : {result['cracked_count']}")
    lines.append("")
    if result["cracked"]:
        for h, pwd in result["cracked"].items():
            lines.append(f"{h} -> {pwd}")
    else:
        lines.append("Aucun mot de passe trouve avec cette methode.")
    return _truncate("\n".join(lines))


def _sanitize_filename(name):
    if not name:
        return "document.pdf"
    name = os.path.basename(name)
    name = re.sub(r"[^a-zA-Z0-9._\-]", "_", name)
    return name[:120] or "document.pdf"


def _is_pdf_document(doc):
    if not doc:
        return False
    if doc.mime_type and doc.mime_type == "application/pdf":
        return True
    if doc.file_name and doc.file_name.lower().endswith(".pdf"):
        return True
    return False


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
    text = (
        "Commandes generales :\n"
        "/start - Demarrer le bot\n"
        "/help - Afficher cette aide\n"
        "/echo <texte> - Repeter un texte\n"
        "/stats - Afficher les statistiques\n\n"
        "PDF - cassage et deverrouillage automatique :\n"
        "Envoie simplement un PDF au bot, il le casse et te renvoie\n"
        "la version deverrouillee.\n"
        "/pdfinfo - Verifie pdf2john et qpdf\n\n"
        "Commandes admin - John the Ripper :\n"
        "/status - Etat du bot et des outils\n"
        "/johninfo - Version de John\n"
        "/formats - Lister les formats supportes\n"
        "/rules - Lister les regles disponibles\n"
        "/wordlist - Verifier rockyou.txt\n\n"
        "Cassage par dictionnaire :\n"
        "/crack <hash> - Dictionnaire + regles Jumbo\n"
        "/crackf <format> <hash> - Avec format explicite\n"
        "/crackrules <rules> <hash> - Avec regles specifiques\n\n"
        "Cassage par masque :\n"
        "/crackmask <mask> <hash> - Attaque par masque\n"
        "/crackhybrid <mask> <hash> - Dictionnaire + masque\n\n"
        "Cassage exhaustif :\n"
        "/crackinc <hash> - Mode incremental\n"
        "/crackincm <mode> <hash> - Mode incremental nomme\n"
        "/cracksingle <hash> - Mode single\n\n"
        "Extraction de hash depuis fichiers :\n"
        "/extractors - Lister les extracteurs disponibles\n"
        "Envoie un fichier avec la legende /extract <type> pour extraire"
    )
    await update.message.reply_text(text)


async def cmd_echo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage : /echo <texte>")
        return
    await update.message.reply_text(" ".join(context.args))


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    messages = get_stat("messages_processed")
    await update.message.reply_text(f"Statistiques :\n- Messages traites : {messages}")


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    binary = find_john_binary()
    john_status = f"OK ({binary})" if binary else "INDISPONIBLE"
    wordlist_status = "OK" if os.path.isfile(WORDLIST_PATH) else "ABSENTE"
    extractors = available_extractors()
    pdf2john = find_pdf2john()
    qpdf_status = "OK" if is_qpdf_available() else "ABSENT"
    await update.message.reply_text(
        f"Bot en ligne.\n"
        f"Base de donnees : OK\n"
        f"Rate limiter : actif\n"
        f"John the Ripper : {john_status}\n"
        f"Wordlist rockyou : {wordlist_status}\n"
        f"pdf2john : {pdf2john or 'ABSENT'}\n"
        f"qpdf : {qpdf_status}\n"
        f"Extracteurs : {len(extractors)}"
    )


async def cmd_johninfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not is_john_available():
        await update.message.reply_text("John the Ripper n'est pas installe.")
        return
    version = get_john_version()
    binary = find_john_binary()
    await update.message.reply_text(f"John the Ripper :\n{version}\n\nBinaire : {binary}")


async def cmd_wordlist(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if os.path.isfile(WORDLIST_PATH):
        size = os.path.getsize(WORDLIST_PATH)
        await update.message.reply_text(
            f"Wordlist presente.\nChemin : {WORDLIST_PATH}\nTaille : {size} octets"
        )
    else:
        await update.message.reply_text(f"Wordlist absente : {WORDLIST_PATH}")


async def cmd_formats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    try:
        formats = list_formats()
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    if not formats:
        await update.message.reply_text("Aucun format detecte.")
        return
    chunks = []
    current = ""
    for fmt in formats:
        if len(current) + len(fmt) + 2 > 3500:
            chunks.append(current)
            current = ""
        current += f"{fmt}\n"
    if current:
        chunks.append(current)
    await update.message.reply_text(f"{len(formats)} formats supportes :\n\n" + chunks[0])
    for chunk in chunks[1:4]:
        await update.message.reply_text(chunk)


async def cmd_rules(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    try:
        rules = list_rules()
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    if not rules:
        await update.message.reply_text("Aucune regle detectee.")
        return
    text = f"{len(rules)} regles disponibles :\n\n" + "\n".join(rules[:100])
    await update.message.reply_text(_truncate(text))


async def cmd_crack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /crack <hash1> [hash2] ...")
        return
    try:
        hashes = validate_hashes(" ".join(context.args))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur de validation : {exc}")
        return
    await update.message.reply_text(f"Cassage de {len(hashes)} hash(es)...")
    result = None
    try:
        result = crack_hashes(hashes, wordlist=WORDLIST_PATH)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur John : {exc}")
        return
    try:
        await update.message.reply_text(_format_crack_result(result, "Dictionnaire + regles Jumbo"))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackf(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage : /crackf <format> <hash1> [hash2] ...")
        return
    john_format = context.args[0].strip()
    if not FORMAT_RE.match(john_format):
        await update.message.reply_text("Format invalide.")
        return
    try:
        hashes = validate_hashes(" ".join(context.args[1:]))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur de validation : {exc}")
        return
    await update.message.reply_text(f"Cassage au format {john_format}...")
    result = None
    try:
        result = crack_hashes(hashes, wordlist=WORDLIST_PATH, john_format=john_format)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur John : {exc}")
        return
    try:
        await update.message.reply_text(_format_crack_result(result, f"Format : {john_format}"))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackrules(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage : /crackrules <rules> <hash1> ...")
        return
    rules = context.args[0].strip()
    if not RULES_RE.match(rules):
        await update.message.reply_text("Nom de regles invalide.")
        return
    try:
        hashes = validate_hashes(" ".join(context.args[1:]))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur de validation : {exc}")
        return
    await update.message.reply_text(f"Cassage avec regles {rules}...")
    result = None
    try:
        result = crack_with_rules(hashes, rules, wordlist=WORDLIST_PATH)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur John : {exc}")
        return
    try:
        await update.message.reply_text(_format_crack_result(result, f"Regles : {rules}"))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackmask(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage : /crackmask <mask> <hash1> ...")
        return
    mask = context.args[0].strip()
    if not MASK_TOKEN_RE.match(mask) or "?" not in mask:
        await update.message.reply_text("Masque invalide.")
        return
    try:
        hashes = validate_hashes(" ".join(context.args[1:]))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur de validation : {exc}")
        return
    await update.message.reply_text(f"Attaque par masque {mask}...")
    result = None
    try:
        result = crack_mask(hashes, mask)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur John : {exc}")
        return
    try:
        await update.message.reply_text(_format_crack_result(result, f"Masque : {mask}"))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackhybrid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage : /crackhybrid <mask> <hash1> ...")
        return
    mask = context.args[0].strip()
    if not MASK_TOKEN_RE.match(mask) or "?" not in mask:
        await update.message.reply_text("Masque invalide.")
        return
    if not os.path.isfile(WORDLIST_PATH):
        await update.message.reply_text(f"Wordlist absente : {WORDLIST_PATH}")
        return
    try:
        hashes = validate_hashes(" ".join(context.args[1:]))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur de validation : {exc}")
        return
    await update.message.reply_text(f"Hybride wordlist + masque {mask}...")
    result = None
    try:
        result = crack_hybrid(hashes, WORDLIST_PATH, mask)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur John : {exc}")
        return
    try:
        await update.message.reply_text(_format_crack_result(result, f"Hybride masque : {mask}"))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackinc(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /crackinc <hash1> ...")
        return
    try:
        hashes = validate_hashes(" ".join(context.args))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur de validation : {exc}")
        return
    await update.message.reply_text(f"Attaque incrementale sur {len(hashes)} hash(es)...")
    result = None
    try:
        result = crack_incremental(hashes, min_length=1, max_length=8)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur John : {exc}")
        return
    try:
        await update.message.reply_text(_format_crack_result(result, "Incremental (1-8)"))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackincm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage : /crackincm <mode> <hash1> ...")
        return
    mode = context.args[0].strip()
    if not FORMAT_RE.match(mode):
        await update.message.reply_text("Mode invalide.")
        return
    try:
        hashes = validate_hashes(" ".join(context.args[1:]))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur de validation : {exc}")
        return
    await update.message.reply_text(f"Mode incremental {mode}...")
    result = None
    try:
        result = crack_incremental(hashes, incremental_mode=mode, min_length=1, max_length=10)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur John : {exc}")
        return
    try:
        await update.message.reply_text(_format_crack_result(result, f"Incremental : {mode}"))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_cracksingle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /cracksingle <hash1> ...")
        return
    try:
        hashes = validate_hashes(" ".join(context.args))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur de validation : {exc}")
        return
    await update.message.reply_text("Mode single en cours...")
    result = None
    try:
        result = crack_single(hashes)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur John : {exc}")
        return
    try:
        await update.message.reply_text(_format_crack_result(result, "Mode single"))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_extractors(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    extractors = available_extractors()
    if not extractors:
        await update.message.reply_text("Aucun extracteur disponible.")
        return
    text = f"Extracteurs disponibles ({len(extractors)}) :\n\n" + "\n".join(extractors)
    await update.message.reply_text(_truncate(text))


async def cmd_pdfinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    pdf2john = find_pdf2john()
    qpdf = is_qpdf_available()
    await update.message.reply_text(
        f"pdf2john : {pdf2john or 'ABSENT'}\n"
        f"qpdf : {'OK' if qpdf else 'ABSENT'}\n"
        f"Wordlist rockyou : {'OK' if os.path.isfile(WORDLIST_PATH) else 'ABSENTE'}"
    )


async def _process_pdf_crack(update, target_doc):
    file_name = _sanitize_filename(target_doc.file_name or "document.pdf")
    if not _is_pdf_document(target_doc):
        await update.message.reply_text("Le fichier envoye n'est pas un PDF.")
        return
    if target_doc.file_size and target_doc.file_size > PDF_MAX_FILE_SIZE:
        await update.message.reply_text("PDF trop volumineux (max 20 Mo).")
        return
    if not find_pdf2john():
        await update.message.reply_text("pdf2john indisponible sur cet environnement.")
        return
    if not is_qpdf_available():
        await update.message.reply_text("qpdf indisponible, deverrouillage impossible.")
        return
    if not os.path.isfile(WORDLIST_PATH):
        await update.message.reply_text(f"Wordlist absente : {WORDLIST_PATH}")
        return

    session_id, workdir = make_session_dir()
    status_msg = await update.message.reply_text(
        f"PDF recu : {file_name}\nTelechargement en cours..."
    )

    try:
        tg_file = await target_doc.get_file()
        pdf_path = os.path.join(workdir, file_name)
        await tg_file.download_to_drive(pdf_path)

        try:
            validate_pdf(pdf_path)
        except PdfError as exc:
            await status_msg.edit_text(f"PDF invalide : {exc}")
            return

        await status_msg.edit_text("Extraction du hash PDF avec pdf2john...")
        try:
            extracted = extract_pdf_hash(pdf_path)
        except PdfError as exc:
            await status_msg.edit_text(f"Erreur d'extraction : {exc}")
            return

        hash_line = extracted["hash_line"]
        await status_msg.edit_text(
            "Hash PDF extrait.\nCassage en cours avec rockyou + regles Jumbo..."
        )

        crack_result = None
        try:
            crack_result = crack_hashes([hash_line], wordlist=WORDLIST_PATH)
        except JohnError as exc:
            await status_msg.edit_text(f"Erreur John : {exc}")
            return

        try:
            if not crack_result["cracked"]:
                await status_msg.edit_text(
                    "Aucun mot de passe trouve avec rockyou.\n"
                    "Le mot de passe est probablement trop complexe pour cette wordlist.\n\n"
                    "Tu peux essayer manuellement :\n"
                    "/crackmask ?d?d?d?d <hash>\n"
                    "/crackinc <hash>"
                )
                return

            password = next(iter(crack_result["cracked"].values()))
            await status_msg.edit_text(
                f"Mot de passe trouve : {password}\nDeverrouillage en cours..."
            )

            unlocked_path = os.path.join(workdir, "unlocked_" + file_name)
            try:
                decrypt_pdf(pdf_path, password, unlocked_path)
            except PdfError as exc:
                await status_msg.edit_text(
                    f"Mot de passe trouve ({password}) mais echec du deverrouillage :\n{exc}"
                )
                return

            await status_msg.edit_text("Envoi du PDF deverrouille...")
            with open(unlocked_path, "rb") as fh:
                await update.message.reply_document(
                    document=fh,
                    filename="unlocked_" + file_name,
                    caption=f"Mot de passe : {password}",
                )
            await status_msg.edit_text(
                f"PDF deverrouille envoye.\nMot de passe : {password}"
            )
        finally:
            if crack_result:
                cleanup_workdir(crack_result["workdir"])
    finally:
        cleanup_dir(workdir)


async def cmd_pdfcrack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return

    target_doc = None
    if update.message.document:
        target_doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        target_doc = update.message.reply_to_message.document

    if not target_doc:
        await update.message.reply_text(
            "Envoie simplement un PDF au bot (sans commande), il sera traite automatiquement.\n"
            "Ou reponds a un PDF avec /pdfcrack."
        )
        return

    await _process_pdf_crack(update, target_doc)


async def cmd_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
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


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.document:
        return

    doc = update.message.document
    caption = (update.message.caption or "").strip()
    parts = caption.split() if caption else []
    command = parts[0].split("@")[0] if parts else ""

    if not _is_admin(update):
        if command == "/extract" or _is_pdf_document(doc):
            await update.message.reply_text("Acces refuse.")
        return

    if command == "/extract" and len(parts) >= 2:
        extractor_name = parts[1].strip()
        if not FORMAT_RE.match(extractor_name):
            await update.message.reply_text("Nom d'extracteur invalide.")
            return
        if doc.file_size and doc.file_size > 50 * 1024 * 1024:
            await update.message.reply_text("Fichier trop volumineux (max 50 Mo).")
            return
        status_msg = await update.message.reply_text(f"Extraction avec {extractor_name}...")
        tmpdir = None
        try:
            tg_file = await doc.get_file()
            tmpdir = os.path.join("/tmp", f"extract_{doc.file_unique_id}")
            os.makedirs(tmpdir, exist_ok=True)
            file_path = os.path.join(tmpdir, _sanitize_filename(doc.file_name) or "input.bin")
            await tg_file.download_to_drive(file_path)
            result = extract_hash_from_file(file_path, extractor_name)
            text = (
                f"Extraction reussie.\n"
                f"Extracteur : {result['extractor']}\n"
                f"Hash extrait :\n{result['hash_line']}"
            )
            await status_msg.edit_text(_truncate(text))
        except JohnError as exc:
            await status_msg.edit_text(f"Erreur : {exc}")
        finally:
            if tmpdir and os.path.isdir(tmpdir):
                shutil.rmtree(tmpdir, ignore_errors=True)
        return

    if _is_pdf_document(doc):
        await _process_pdf_crack(update, doc)
        return

    await update.message.reply_text(
        "Document recu. Pour extraire un hash, renvoie-le avec la legende :\n"
        "/extract <type>  (ex: /extract zip2john)\n\n"
        "Pour les PDF, envoie simplement le fichier, il sera traite automatiquement."
    )


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Exception lors du traitement d'une mise a jour", exc_info=context.error)
    if update and update.effective_message:
        try:
            await update.effective_message.reply_text("Une erreur est survenue. Reessaie plus tard.")
        except Exception:
            pass

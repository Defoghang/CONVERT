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
from hydra_service import (
    HydraError,
    hydra_attack,
    cleanup_workdir as hydra_cleanup,
    is_hydra_available,
    get_hydra_version,
    list_supported_protocols,
)

from extra_tools_service import (
    ExtraToolError,
    available_tools,
    hashcat_crack,
    hashcat_cleanup,
    pdfcrack_crack,
    pdf_analyze,
    binwalk_scan,
    steghide_info,
    stegseek_crack,
    stegseek_cleanup,
    strings_extract,
    ciphey_decode,
    theharvester_search,
    extract_with_7z,
    detect_hash_type,
)

logger = logging.getLogger(__name__)

WORDLIST_PATH = "/usr/share/wordlists/rockyou.txt"
MAX_TELEGRAM_MESSAGE = 4000
PDF_MAX_FILE_SIZE = 20 * 1024 * 1024
GENERIC_FILE_MAX_SIZE = 30 * 1024 * 1024

MASK_TOKEN_RE = re.compile(r"^[?a-zA-Z0-9,\-\[\]:. ]{1,120}$")
FORMAT_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,50}$")
RULES_RE = re.compile(r"^[a-zA-Z0-9_\-+,/]{1,200}$")
DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.\-]{1,253}$")


def _is_admin(update):
    user = update.effective_user
    return user is not None and user.id in ADMIN_IDS


def _truncate(text, limit=MAX_TELEGRAM_MESSAGE):
    if not text:
        return "(vide)"
    if len(text) <= limit:
        return text
    return text[: limit - 20] + "\n...(tronque)"


def _sanitize_filename(name):
    if not name:
        return "document"
    name = os.path.basename(name)
    name = re.sub(r"[^a-zA-Z0-9._\-]", "_", name)
    return name[:120] or "document"


def _is_pdf_document(doc):
    if not doc:
        return False
    if doc.mime_type and doc.mime_type == "application/pdf":
        return True
    if doc.file_name and doc.file_name.lower().endswith(".pdf"):
        return True
    return False


async def _download_doc(doc, tmpdir):
    tg_file = await doc.get_file()
    os.makedirs(tmpdir, exist_ok=True)
    path = os.path.join(tmpdir, _sanitize_filename(doc.file_name) or "input.bin")
    await tg_file.download_to_drive(path)
    return path


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user:
        upsert_user(user.id, user.username, user.first_name)
    await update.message.reply_text(
        f"Bonjour {user.first_name} !\n\n"
        "Bot pret pour la production.\nUtilise /help pour voir les commandes.",
        parse_mode=ParseMode.HTML,
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "Generales :\n"
        "/start /help /echo /stats\n\n"
        "John the Ripper :\n"
        "/status /johninfo /wordlist /formats /rules\n"
        "/crack /crackf /crackrules /crackmask /crackhybrid /crackinc /crackincm /cracksingle\n\n"
        "Hashcat :\n"
        "/hcrack <hash> - Cassage auto (detection type)\n"
        "/hcrackm <mode> <hash> - Mode numerique explicite\n"
        "/hdetect <hash> - Detecter le type de hash\n\n"
        "PDF :\n"
        "Envoie un PDF => deverrouillage automatique\n"
        "/pdfinfo /pdfanalyze\n"
        "/pdfcrackcmd - pdfcrack manuel\n\n"
        "Steganographie :\n"
        "/steginfo - infos sur un fichier (repondre a une image)\n"
        "/stegcrack - casser steghide avec rockyou\n\n"
        "Analyse de fichiers :\n"
        "/binwalk - signature scan (repondre a un fichier)\n"
        "/strings - extraire les chaines (repondre a un fichier)\n"
        "/tool7z - extraire une archive (repondre a un fichier)\n\n"
        "Hydra (force brute en ligne) :\n"
        "/hydra <proto> <cible> <user> <pass> [port]\n"
        "/hydrawordlist <proto> <cible> <user> [port] - rockyou\n"
        "/hydraprotocols - lister les protocoles\n"
        "/hydrainfo - version Hydra\n\n"
        "OSINT et decoding :\n"
        "/harvest <domaine>\n"
        "/decode <texte>\n\n"
        "Admin :\n"
        "/status /tools"
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


async def cmd_tools(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    tools = available_tools()
    lines = ["Disponibilite des outils :", ""]
    for name, ok in tools.items():
        lines.append(f"{'OK ' if ok else 'KO '} {name}")
    await update.message.reply_text(_truncate("\n".join(lines)))


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    binary = find_john_binary()
    john_status = f"OK" if binary else "INDISPONIBLE"
    wordlist_status = "OK" if os.path.isfile(WORDLIST_PATH) else "ABSENTE"
    tools = available_tools()
    ok_count = sum(1 for v in tools.values() if v)
    await update.message.reply_text(
        f"Bot en ligne.\n"
        f"John : {john_status}\n"
        f"Wordlist : {wordlist_status}\n"
        f"pdf2john : {'OK' if find_pdf2john() else 'ABSENT'}\n"
        f"qpdf : {'OK' if is_qpdf_available() else 'ABSENT'}\n"
        f"Outils supplementaires : {ok_count}/{len(tools)}"
    )


async def cmd_johninfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not is_john_available():
        await update.message.reply_text("John indisponible.")
        return
    await update.message.reply_text(f"John :\n{get_john_version()}\n\n{find_john_binary()}")


async def cmd_wordlist(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if os.path.isfile(WORDLIST_PATH):
        size = os.path.getsize(WORDLIST_PATH)
        await update.message.reply_text(f"rockyou.txt : {size} octets")
    else:
        await update.message.reply_text("rockyou.txt absente.")


async def cmd_formats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    try:
        formats = list_formats()
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
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
    await update.message.reply_text(f"{len(formats)} formats :\n\n" + chunks[0])
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
    text = f"{len(rules)} regles :\n\n" + "\n".join(rules[:80])
    await update.message.reply_text(_truncate(text))


async def _run_john_crack(update, crack_fn, title):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : fournis au moins un hash.")
        return
    try:
        hashes = validate_hashes(" ".join(context.args))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    await update.message.reply_text(f"Traitement de {len(hashes)} hash(es)...")
    result = None
    try:
        result = crack_fn(hashes)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur John : {exc}")
        return
    try:
        lines = [f"Session {result['session_id']}", title,
                 f"Traites : {result['total']}", f"Cracks : {result['cracked_count']}", ""]
        if result["cracked"]:
            for h, pwd in result["cracked"].items():
                lines.append(f"{h} -> {pwd}")
        else:
            lines.append("Aucun mot de passe trouve.")
        await update.message.reply_text(_truncate("\n".join(lines)))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crack(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /crack <hash>")
        return
    try:
        hashes = validate_hashes(" ".join(context.args))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    await update.message.reply_text(f"Cassage {len(hashes)} hash(es)...")
    result = None
    try:
        result = crack_hashes(hashes, wordlist=WORDLIST_PATH)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur John : {exc}")
        return
    try:
        lines = [f"Session {result['session_id']}", "Dictionnaire + regles Jumbo",
                 f"Traites : {result['total']}", f"Cracks : {result['cracked_count']}", ""]
        for h, pwd in result["cracked"].items():
            lines.append(f"{h} -> {pwd}")
        if not result["cracked"]:
            lines.append("Aucun resultat.")
        await update.message.reply_text(_truncate("\n".join(lines)))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackf(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage : /crackf <format> <hash>")
        return
    fmt = context.args[0].strip()
    if not FORMAT_RE.match(fmt):
        await update.message.reply_text("Format invalide.")
        return
    try:
        hashes = validate_hashes(" ".join(context.args[1:]))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    await update.message.reply_text(f"Cassage au format {fmt}...")
    result = None
    try:
        result = crack_hashes(hashes, wordlist=WORDLIST_PATH, john_format=fmt)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    try:
        lines = [f"Session {result['session_id']}", f"Format : {fmt}",
                 f"Traites : {result['total']}", f"Cracks : {result['cracked_count']}", ""]
        for h, pwd in result["cracked"].items():
            lines.append(f"{h} -> {pwd}")
        if not result["cracked"]:
            lines.append("Aucun resultat.")
        await update.message.reply_text(_truncate("\n".join(lines)))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackrules(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage : /crackrules <rules> <hash>")
        return
    rules = context.args[0].strip()
    if not RULES_RE.match(rules):
        await update.message.reply_text("Nom de regles invalide.")
        return
    try:
        hashes = validate_hashes(" ".join(context.args[1:]))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    await update.message.reply_text(f"Cassage avec regles {rules}...")
    result = None
    try:
        result = crack_with_rules(hashes, rules, wordlist=WORDLIST_PATH)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    try:
        lines = [f"Session {result['session_id']}", f"Regles : {rules}",
                 f"Traites : {result['total']}", f"Cracks : {result['cracked_count']}", ""]
        for h, pwd in result["cracked"].items():
            lines.append(f"{h} -> {pwd}")
        if not result["cracked"]:
            lines.append("Aucun resultat.")
        await update.message.reply_text(_truncate("\n".join(lines)))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackmask(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage : /crackmask <mask> <hash>")
        return
    mask = context.args[0].strip()
    if not MASK_TOKEN_RE.match(mask) or "?" not in mask:
        await update.message.reply_text("Masque invalide.")
        return
    try:
        hashes = validate_hashes(" ".join(context.args[1:]))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    await update.message.reply_text(f"Masque {mask}...")
    result = None
    try:
        result = crack_mask(hashes, mask)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    try:
        lines = [f"Session {result['session_id']}", f"Masque : {mask}",
                 f"Traites : {result['total']}", f"Cracks : {result['cracked_count']}", ""]
        for h, pwd in result["cracked"].items():
            lines.append(f"{h} -> {pwd}")
        if not result["cracked"]:
            lines.append("Aucun resultat.")
        await update.message.reply_text(_truncate("\n".join(lines)))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackhybrid(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage : /crackhybrid <mask> <hash>")
        return
    mask = context.args[0].strip()
    if not MASK_TOKEN_RE.match(mask) or "?" not in mask:
        await update.message.reply_text("Masque invalide.")
        return
    if not os.path.isfile(WORDLIST_PATH):
        await update.message.reply_text("Wordlist absente.")
        return
    try:
        hashes = validate_hashes(" ".join(context.args[1:]))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    await update.message.reply_text(f"Hybride wordlist + masque {mask}...")
    result = None
    try:
        result = crack_hybrid(hashes, WORDLIST_PATH, mask)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    try:
        lines = [f"Session {result['session_id']}", f"Hybride masque : {mask}",
                 f"Traites : {result['total']}", f"Cracks : {result['cracked_count']}", ""]
        for h, pwd in result["cracked"].items():
            lines.append(f"{h} -> {pwd}")
        if not result["cracked"]:
            lines.append("Aucun resultat.")
        await update.message.reply_text(_truncate("\n".join(lines)))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackinc(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /crackinc <hash>")
        return
    try:
        hashes = validate_hashes(" ".join(context.args))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    await update.message.reply_text("Incremental en cours...")
    result = None
    try:
        result = crack_incremental(hashes, min_length=1, max_length=8)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    try:
        lines = [f"Session {result['session_id']}", "Incremental (1-8)",
                 f"Traites : {result['total']}", f"Cracks : {result['cracked_count']}", ""]
        for h, pwd in result["cracked"].items():
            lines.append(f"{h} -> {pwd}")
        if not result["cracked"]:
            lines.append("Aucun resultat.")
        await update.message.reply_text(_truncate("\n".join(lines)))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackincm(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage : /crackincm <mode> <hash>")
        return
    mode = context.args[0].strip()
    if not FORMAT_RE.match(mode):
        await update.message.reply_text("Mode invalide.")
        return
    try:
        hashes = validate_hashes(" ".join(context.args[1:]))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    await update.message.reply_text(f"Incremental mode {mode}...")
    result = None
    try:
        result = crack_incremental(hashes, incremental_mode=mode, min_length=1, max_length=10)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    try:
        lines = [f"Session {result['session_id']}", f"Incremental : {mode}",
                 f"Traites : {result['total']}", f"Cracks : {result['cracked_count']}", ""]
        for h, pwd in result["cracked"].items():
            lines.append(f"{h} -> {pwd}")
        if not result["cracked"]:
            lines.append("Aucun resultat.")
        await update.message.reply_text(_truncate("\n".join(lines)))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_cracksingle(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /cracksingle <hash>")
        return
    try:
        hashes = validate_hashes(" ".join(context.args))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    await update.message.reply_text("Mode single...")
    result = None
    try:
        result = crack_single(hashes)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur : {exc}")
        return
    try:
        lines = [f"Session {result['session_id']}", "Single",
                 f"Traites : {result['total']}", f"Cracks : {result['cracked_count']}", ""]
        for h, pwd in result["cracked"].items():
            lines.append(f"{h} -> {pwd}")
        if not result["cracked"]:
            lines.append("Aucun resultat.")
        await update.message.reply_text(_truncate("\n".join(lines)))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_extractors(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    exts = available_extractors()
    if not exts:
        await update.message.reply_text("Aucun extracteur *2john disponible.")
        return
    await update.message.reply_text("Extracteurs *2john :\n\n" + "\n".join(exts))


async def cmd_pdfinfo(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    await update.message.reply_text(
        f"pdf2john : {find_pdf2john() or 'ABSENT'}\n"
        f"qpdf : {'OK' if is_qpdf_available() else 'ABSENT'}\n"
        f"pdfcrack : {'OK' if available_tools().get('pdfcrack') else 'ABSENT'}\n"
        f"pdftotext : {'OK' if available_tools().get('pdftotext') else 'ABSENT'}\n"
        f"rockyou : {'OK' if os.path.isfile(WORDLIST_PATH) else 'ABSENTE'}"
    )


async def cmd_pdfanalyze(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    doc = None
    if update.message.document:
        doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        doc = update.message.reply_to_message.document
    if not doc or not _is_pdf_document(doc):
        await update.message.reply_text("Reponds a un PDF avec /pdfanalyze.")
        return
    workdir = "/tmp/analyze_" + doc.file_unique_id
    status = await update.message.reply_text("Analyse du PDF...")
    try:
        path = await _download_doc(doc, workdir)
        results = pdf_analyze(path)
        text = "Analyse PDF :\n\n"
        for tool, output in results.items():
            text += f"--- {tool} ---\n{_truncate(output, 1200)}\n\n"
        await status.edit_text(_truncate(text))
    except Exception as exc:
        await status.edit_text(f"Erreur : {exc}")
    finally:
        if os.path.isdir(workdir):
            shutil.rmtree(workdir, ignore_errors=True)


async def cmd_pdfcrackcmd(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    doc = None
    if update.message.document:
        doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        doc = update.message.reply_to_message.document
    if not doc or not _is_pdf_document(doc):
        await update.message.reply_text("Reponds a un PDF avec /pdfcrackcmd.")
        return
    if not available_tools().get("pdfcrack"):
        await update.message.reply_text("pdfcrack indisponible.")
        return
    workdir = "/tmp/pdfcrack_" + doc.file_unique_id
    status = await update.message.reply_text("Telechargement...")
    try:
        path = await _download_doc(doc, workdir)
        await status.edit_text("pdfcrack en cours (rockyou)...")
        result = pdfcrack_crack(path)
        if result["cracked"]:
            await status.edit_text(f"Mot de passe trouve : {result['cracked']}")
        else:
            await status.edit_text("Aucun mot de passe trouve par pdfcrack.")
    except ExtraToolError as exc:
        await status.edit_text(f"Erreur : {exc}")
    finally:
        if os.path.isdir(workdir):
            shutil.rmtree(workdir, ignore_errors=True)


async def cmd_hdetect(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /hdetect <hash>")
        return
    h = context.args[0].strip()
    name, mode = detect_hash_type(h)
    if mode is None:
        await update.message.reply_text(f"Type : {name}\nMode hashcat : non determine")
    else:
        await update.message.reply_text(f"Type : {name}\nMode hashcat : -m {mode}")


async def cmd_hcrack(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /hcrack <hash>")
        return
    h = context.args[0].strip()
    if len(h) > 5000:
        await update.message.reply_text("Hash trop long.")
        return
    if not available_tools().get("hashcat"):
        await update.message.reply_text("hashcat indisponible.")
        return
    status = await update.message.reply_text("hashcat en cours (detection auto)...")
    result = None
    try:
        result = hashcat_crack(h)
        if result["cracked"]:
            await status.edit_text(
                f"Type : {result['hash_type']} (-m {result['mode']})\n"
                f"Mot de passe : {result['cracked']}"
            )
        else:
            await status.edit_text(
                f"Type : {result['hash_type']} (-m {result['mode']})\n"
                "Aucun mot de passe trouve avec rockyou."
            )
    except ExtraToolError as exc:
        await status.edit_text(f"Erreur hashcat : {exc}")
    finally:
        if result:
            hashcat_cleanup(result["workdir"])


async def cmd_hcrackm(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage : /hcrackm <mode> <hash>")
        return
    try:
        mode = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Mode numerique invalide.")
        return
    h = context.args[1].strip()
    if len(h) > 5000:
        await update.message.reply_text("Hash trop long.")
        return
    status = await update.message.reply_text(f"hashcat -m {mode}...")
    result = None
    try:
        result = hashcat_crack(h, mode=mode)
        if result["cracked"]:
            await status.edit_text(f"Mot de passe : {result['cracked']}")
        else:
            await status.edit_text("Aucun mot de passe trouve.")
    except ExtraToolError as exc:
        await status.edit_text(f"Erreur : {exc}")
    finally:
        if result:
            hashcat_cleanup(result["workdir"])


async def cmd_binwalk(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    doc = None
    if update.message.document:
        doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        doc = update.message.reply_to_message.document
    if not doc:
        await update.message.reply_text("Reponds a un fichier avec /binwalk.")
        return
    if doc.file_size and doc.file_size > GENERIC_FILE_MAX_SIZE:
        await update.message.reply_text("Fichier trop volumineux (max 30 Mo).")
        return
    if not available_tools().get("binwalk"):
        await update.message.reply_text("binwalk indisponible.")
        return
    workdir = "/tmp/binwalk_" + doc.file_unique_id
    status = await update.message.reply_text("binwalk en cours...")
    try:
        path = await _download_doc(doc, workdir)
        result = binwalk_scan(path)
        await status.edit_text(_truncate("binwalk :\n\n" + result["stdout"]))
    except ExtraToolError as exc:
        await status.edit_text(f"Erreur : {exc}")
    finally:
        if os.path.isdir(workdir):
            shutil.rmtree(workdir, ignore_errors=True)


async def cmd_strings(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    doc = None
    if update.message.document:
        doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        doc = update.message.reply_to_message.document
    if not doc:
        await update.message.reply_text("Reponds a un fichier avec /strings.")
        return
    workdir = "/tmp/strings_" + doc.file_unique_id
    status = await update.message.reply_text("Extraction de chaines...")
    try:
        path = await _download_doc(doc, workdir)
        output = strings_extract(path, min_len=6)
        await status.edit_text(_truncate("Chaines :\n\n" + output))
    except ExtraToolError as exc:
        await status.edit_text(f"Erreur : {exc}")
    finally:
        if os.path.isdir(workdir):
            shutil.rmtree(workdir, ignore_errors=True)


async def cmd_tool7z(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    doc = None
    if update.message.document:
        doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        doc = update.message.reply_to_message.document
    if not doc:
        await update.message.reply_text("Reponds a une archive avec /tool7z.")
        return
    workdir = "/tmp/7z_" + doc.file_unique_id
    status = await update.message.reply_text("Extraction 7z...")
    result = None
    try:
        path = await _download_doc(doc, workdir)
        result = extract_with_7z(path)
        if result["extracted"]:
            lines = ["Fichiers extraits :"]
            for f in result["extracted"][:15]:
                lines.append(f"- {os.path.basename(f)}")
            await status.edit_text(_truncate("\n".join(lines)))
        else:
            await status.edit_text("Aucun fichier extrait.\n" + result["stderr"][:500])
    except ExtraToolError as exc:
        await status.edit_text(f"Erreur : {exc}")
    finally:
        if result:
            shutil.rmtree(result["workdir"], ignore_errors=True)
        if os.path.isdir(workdir):
            shutil.rmtree(workdir, ignore_errors=True)


async def cmd_steginfo(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    doc = None
    if update.message.document:
        doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        doc = update.message.reply_to_message.document
    if not doc:
        await update.message.reply_text("Reponds a une image/audio avec /steginfo.")
        return
    if not available_tools().get("steghide"):
        await update.message.reply_text("steghide indisponible.")
        return
    workdir = "/tmp/steg_" + doc.file_unique_id
    status = await update.message.reply_text("Analyse stegano...")
    try:
        path = await _download_doc(doc, workdir)
        result = steghide_info(path)
        text = f"steghide info (rc={result['returncode']}):\n\n"
        text += result["stdout"] or result["stderr"]
        await status.edit_text(_truncate(text))
    except ExtraToolError as exc:
        await status.edit_text(f"Erreur : {exc}")
    finally:
        if os.path.isdir(workdir):
            shutil.rmtree(workdir, ignore_errors=True)


async def cmd_stegcrack(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    doc = None
    if update.message.document:
        doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        doc = update.message.reply_to_message.document
    if not doc:
        await update.message.reply_text("Reponds a une image/audio avec /stegcrack.")
        return
    if not available_tools().get("stegseek"):
        await update.message.reply_text("stegseek indisponible.")
        return
    workdir = "/tmp/stegseek_" + doc.file_unique_id
    status = await update.message.reply_text("stegseek en cours (rockyou)...")
    result = None
    try:
        path = await _download_doc(doc, workdir)
        result = stegseek_crack(path)
        if result["password"]:
            text = f"Passphrase trouvee : {result['password']}"
            if result["extracted_file"]:
                text += "\nFichier cache extrait."
                with open(result["extracted_file"], "rb") as fh:
                    await update.message.reply_document(
                        document=fh,
                        filename="extracted.dat",
                        caption=f"Passphrase : {result['password']}",
                    )
            await status.edit_text(text)
        else:
            await status.edit_text(
                "Aucune passphrase trouvee par stegseek.\n\n" + result["stdout"][:500]
            )
    except ExtraToolError as exc:
        await status.edit_text(f"Erreur : {exc}")
    finally:
        if result:
            stegseek_cleanup(result["workdir"])
        if os.path.isdir(workdir):
            shutil.rmtree(workdir, ignore_errors=True)


async def cmd_decode(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /decode <texte>")
        return
    text = " ".join(context.args)
    if not available_tools().get("ciphey"):
        await update.message.reply_text("ciphey indisponible.")
        return
    status = await update.message.reply_text("ciphey en cours...")
    try:
        result = ciphey_decode(text)
        await status.edit_text(_truncate("ciphey :\n\n" + (result["stdout"] or result["stderr"])))
    except ExtraToolError as exc:
        await status.edit_text(f"Erreur : {exc}")


async def cmd_harvest(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /harvest <domaine>")
        return
    domain = context.args[0].strip()
    if not DOMAIN_RE.match(domain):
        await update.message.reply_text("Domaine invalide.")
        return
    if not available_tools().get("theHarvester"):
        await update.message.reply_text("theHarvester indisponible.")
        return
    status = await update.message.reply_text(f"theHarvester sur {domain}...")
    try:
        result = theharvester_search(domain)
        await status.edit_text(_truncate(result["stdout"] or result["stderr"]))
    except ExtraToolError as exc:
        await status.edit_text(f"Erreur : {exc}")


async def cmd_broadcast(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text("Usage : /broadcast <message>")
        return
    await update.message.reply_text("Diffusion simulee : " + " ".join(context.args))


async def _process_pdf_crack(update, target_doc):
    file_name = _sanitize_filename(target_doc.file_name or "document.pdf")
    if not _is_pdf_document(target_doc):
        await update.message.reply_text("Pas un PDF.")
        return
    if target_doc.file_size and target_doc.file_size > PDF_MAX_FILE_SIZE:
        await update.message.reply_text("PDF trop volumineux (max 20 Mo).")
        return
    if not find_pdf2john() or not is_qpdf_available():
        await update.message.reply_text("pdf2john ou qpdf indisponible.")
        return
    if not os.path.isfile(WORDLIST_PATH):
        await update.message.reply_text("rockyou absente.")
        return

    session_id, workdir = make_session_dir()
    status_msg = await update.message.reply_text(f"PDF recu : {file_name}\nTelechargement...")
    try:
        tg_file = await target_doc.get_file()
        pdf_path = os.path.join(workdir, file_name)
        await tg_file.download_to_drive(pdf_path)
        try:
            validate_pdf(pdf_path)
        except PdfError as exc:
            await status_msg.edit_text(f"PDF invalide : {exc}")
            return
        await status_msg.edit_text("Extraction hash (pdf2john)...")
        try:
            extracted = extract_pdf_hash(pdf_path)
        except PdfError as exc:
            await status_msg.edit_text(f"Erreur extraction : {exc}")
            return
        hash_line = extracted["hash_line"]
        await status_msg.edit_text("Cassage avec rockyou + regles Jumbo...")
        crack_result = None
        try:
            crack_result = crack_hashes([hash_line], wordlist=WORDLIST_PATH)
        except JohnError as exc:
            await status_msg.edit_text(f"Erreur John : {exc}")
            return
        try:
            if not crack_result["cracked"]:
                await status_msg.edit_text(
                    "Aucun mot de passe trouve par John.\n"
                    "Tu peux essayer /pdfcrackcmd (pdfcrack) sur le meme PDF."
                )
                return
            password = next(iter(crack_result["cracked"].values()))
            await status_msg.edit_text(f"Mot de passe : {password}\nDeverrouillage...")
            unlocked_path = os.path.join(workdir, "unlocked_" + file_name)
            try:
                decrypt_pdf(pdf_path, password, unlocked_path)
            except PdfError as exc:
                await status_msg.edit_text(f"Echec deverrouillage : {exc}")
                return
            await status_msg.edit_text("Envoi du PDF deverrouille...")
            with open(unlocked_path, "rb") as fh:
                await update.message.reply_document(
                    document=fh,
                    filename="unlocked_" + file_name,
                    caption=f"Mot de passe : {password}",
                )
            await status_msg.edit_text(f"PDF envoye. Mot de passe : {password}")
        finally:
            if crack_result:
                cleanup_workdir(crack_result["workdir"])
    finally:
        cleanup_dir(workdir)


async def cmd_pdfcrack(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    doc = None
    if update.message.document:
        doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        doc = update.message.reply_to_message.document
    if not doc:
        await update.message.reply_text("Envoie un PDF ou reponds a un PDF avec /pdfcrack.")
        return
    await _process_pdf_crack(update, doc)


async def handle_message(update, context):
    user = update.effective_user
    if user:
        upsert_user(user.id, user.username, user.first_name)
    increment_stat("messages_processed")
    if update.message and update.message.text:
        await update.message.reply_text("Message recu : " + update.message.text[:200])


async def handle_document(update, context):
    if not update.message or not update.message.document:
        return
    doc = update.message.document
    caption = (update.message.caption or "").strip()
    parts = caption.split() if caption else []
    command = parts[0].split("@")[0] if parts else ""

    if not _is_admin(update):
        if _is_pdf_document(doc):
            await update.message.reply_text("Acces refuse.")
        return

    if command == "/extract" and len(parts) >= 2:
        extractor_name = parts[1].strip()
        if not FORMAT_RE.match(extractor_name):
            await update.message.reply_text("Nom d'extracteur invalide.")
            return
        if doc.file_size and doc.file_size > 50 * 1024 * 1024:
            await update.message.reply_text("Fichier trop gros.")
            return
        status_msg = await update.message.reply_text(f"Extraction {extractor_name}...")
        tmpdir = None
        try:
            tg_file = await doc.get_file()
            tmpdir = os.path.join("/tmp", f"extract_{doc.file_unique_id}")
            os.makedirs(tmpdir, exist_ok=True)
            path = os.path.join(tmpdir, _sanitize_filename(doc.file_name) or "input.bin")
            await tg_file.download_to_drive(path)
            result = extract_hash_from_file(path, extractor_name)
            await status_msg.edit_text(_truncate(f"Hash extrait :\n{result['hash_line']}"))
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
        "Document recu.\n"
        "- /binwalk : scan de signatures (repondre au fichier)\n"
        "- /strings : extraire les chaines\n"
        "- /tool7z : extraire archive\n"
        "- /steginfo : infos stegano\n"
        "- /stegcrack : casser steghide\n"
        "- /extract <type> : extraire hash *2john\n"
        "- PDFs : traitement automatique"
    )



async def cmd_hydra(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not is_hydra_available():
        await update.message.reply_text("Hydra indisponible.")
        return
    if len(context.args) < 3:
        await update.message.reply_text(
            "Usage : /hydra <protocole> <cible> <user> <pass> [port]\n"
            "Exemple : /hydra ssh 192.168.1.10 root toor 22\n"
            "Exemple : /hydra ftp 10.0.0.5 admin password\n\n"
            "Protocoles autorises : /hydraprotocols"
        )
        return
    protocol = context.args[0].strip()
    host = context.args[1].strip()
    username = context.args[2].strip()
    password = context.args[3].strip() if len(context.args) > 3 else None
    port = context.args[4].strip() if len(context.args) > 4 else None
    if not password:
        await update.message.reply_text("Mot de passe manquant.")
        return
    status = await update.message.reply_text(
        f"Hydra en cours sur {protocol}://{host}..."
    )
    result = None
    try:
        result = hydra_attack(
            host=host, protocol=protocol,
            username=username, password=password, port=port,
        )
        if result["found"]:
            text = "Identifiants trouves :\n"
            for line in result["found"]:
                text += f"- {line}\n"
            await status.edit_text(_truncate(text))
        else:
            await status.edit_text(
                "Aucun identifiant valide trouve.\n\n"
                f"Cible : {result['target']}\n"
                f"Code retour : {result['returncode']}"
            )
    except HydraError as exc:
        await status.edit_text(f"Erreur Hydra : {exc}")
    finally:
        if result:
            hydra_cleanup(result["workdir"])


async def cmd_hydrawordlist(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not _is_hydra_available():
        await update.message.reply_text("Hydra indisponible.")
        return
    if len(context.args) < 3:
        await update.message.reply_text(
            "Usage : /hydrawordlist <protocole> <cible> <user> [port]\n"
            "Utilise rockyou.txt comme passlist automatiquement."
        )
        return
    protocol = context.args[0].strip()
    host = context.args[1].strip()
    username = context.args[2].strip()
    port = context.args[3].strip() if len(context.args) > 3 else None
    if not os.path.isfile(WORDLIST_PATH):
        await update.message.reply_text("rockyou.txt absente.")
        return
    status = await update.message.reply_text(
        f"Hydra + rockyou sur {protocol}://{host}...\n"
        "(peut prendre plusieurs minutes)"
    )
    result = None
    try:
        result = hydra_attack(
            host=host, protocol=protocol, username=username,
            passlist=WORDLIST_PATH, port=port, tasks=4, stop_on_first=True,
        )
        if result["found"]:
            text = "Identifiants trouves :\n"
            for line in result["found"]:
                text += f"- {line}\n"
            await status.edit_text(_truncate(text))
        else:
            await status.edit_text(
                "Aucun mot de passe de rockyou n'a fonctionne.\n"
                f"Cible : {result['target']}"
            )
    except HydraError as exc:
        await status.edit_text(f"Erreur Hydra : {exc}")
    finally:
        if result:
            hydra_cleanup(result["workdir"])


async def cmd_hydraprotocols(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    protocols = list_supported_protocols()
    await update.message.reply_text(
        f"Protocoles autorises ({len(protocols)}) :\n\n" + "\n".join(protocols)
    )


async def cmd_hydrainfo(update, context):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not is_hydra_available():
        await update.message.reply_text("Hydra indisponible.")
        return
    version = get_hydra_version()
    await update.message.reply_text(f"Hydra :\n{version}")


async def error_handler(update, context):
    logger.error("Exception", exc_info=context.error)
    if update and update.effective_message:
        try:
            await update.effective_message.reply_text("Erreur. Reessaie plus tard.")
        except Exception:
            pass

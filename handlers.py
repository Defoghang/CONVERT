import logging
import os
import re
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

logger = logging.getLogger(__name__)

WORDLIST_PATH = "/usr/share/wordlists/rockyou.txt"
MAX_TELEGRAM_MESSAGE = 4000

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
        "/cracksingle <hash> - Mode single (username-aware)\n\n"
        "Extraction de hash depuis fichiers :\n"
        "/extractors - Lister les extracteurs disponibles\n"
        "/extract <type> - Extraire depuis un fichier envoye"
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
    await update.message.reply_text(
        f"Bot en ligne.\n"
        f"Base de donnees : OK\n"
        f"Rate limiter : actif\n"
        f"John the Ripper : {john_status}\n"
        f"Wordlist rockyou : {wordlist_status}\n"
        f"Extracteurs disponibles : {len(extractors)}"
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
        await update.message.reply_text(
            f"Wordlist absente : {WORDLIST_PATH}\n"
            "Elle sera installee par le workflow GitHub Actions."
        )


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
    header = f"{len(formats)} formats supportes :\n\n"
    await update.message.reply_text(header + chunks[0])
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
        await update.message.reply_text(
            "Usage : /crack <hash1> [hash2] ...\n"
            "Exemple : /crack 5f4dcc3b5aa765d61d8327deb882cf99"
        )
        return
    try:
        hashes = validate_hashes(" ".join(context.args))
    except JohnError as exc:
        await update.message.reply_text(f"Erreur de validation : {exc}")
        return
    await update.message.reply_text(f"Cassage de {len(hashes)} hash(es) par dictionnaire...")
    result = None
    try:
        result = crack_hashes(hashes, wordlist=WORDLIST_PATH)
    except JohnError as exc:
        await update.message.reply_text(f"Erreur John : {exc}")
        return
    try:
        await update.message.reply_text(_format_crack_result(result, "Mode : dictionnaire + regles Jumbo"))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackf(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text(
            "Usage : /crackf <format> <hash1> [hash2] ...\n"
            "Exemple : /crackf raw-md5 5f4dcc3b5aa765d61d8327deb882cf99"
        )
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
        await update.message.reply_text(
            "Usage : /crackrules <rules> <hash1> [hash2] ...\n"
            "Exemples de regles : Jumbo, best64, d3ad0ne, KoreLogic\n"
            "Exemple : /crackrules best64 5f4dcc3b5aa765d61d8327deb882cf99"
        )
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
        await update.message.reply_text(
            "Usage : /crackmask <mask> <hash1> [hash2] ...\n"
            "Placeholders : ?l minuscule, ?u majuscule, ?d chiffre, ?s symbole, ?a tous\n"
            "Exemple : /crackmask ?l?l?l?l?d?d 5f4dcc3b5aa765d61d8327deb882cf99"
        )
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
    if len(context.args) < 3:
        await update.message.reply_text(
            "Usage : /crackhybrid <mask> <hash1> [hash2] ...\n"
            "Combine rockyou.txt avec un masque en suffixe.\n"
            "Exemple : /crackhybrid ?d?d?d 5f4dcc3b5aa765d61d8327deb882cf99"
        )
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
    await update.message.reply_text(f"Attaque hybride wordlist + masque {mask}...")
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
        await update.message.reply_text(
            "Usage : /crackinc <hash1> [hash2] ...\n"
            "Mode incremental exhaustif (peut etre tres long)."
        )
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
        await update.message.reply_text(_format_crack_result(result, "Mode : incremental (1-8 chars)"))
    finally:
        cleanup_workdir(result["workdir"])


async def cmd_crackincm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if len(context.args) < 2:
        await update.message.reply_text(
            "Usage : /crackincm <mode> <hash1> [hash2] ...\n"
            "Modes courants : digits, alpha, alnum, all, lower, upper\n"
            "Exemple : /crackincm digits 5f4dcc3b5aa765d61d8327deb882cf99"
        )
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
        await update.message.reply_text(
            "Usage : /cracksingle <hash1> [hash2] ...\n"
            "Mode single : utilise les informations du hash comme base."
        )
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
        await update.message.reply_text(_format_crack_result(result, "Mode : single"))
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
    text = f"Extracteurs disponibles ({len(extractors)}) :\n\n" + "\n".join(
        f"/extract {name}" for name in extractors
    )
    await update.message.reply_text(_truncate(text))


async def cmd_extract(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Acces refuse.")
        return
    if not context.args:
        await update.message.reply_text(
            "Usage : /extract <type>\n"
            "Envoie ensuite le fichier en piece jointe avec la legende /extract <type>.\n"
            "Exemple : /extract zip2john (avec un fichier .zip en piece jointe)"
        )
        return
    extractor_name = context.args[0].strip()
    if not FORMAT_RE.match(extractor_name):
        await update.message.reply_text("Nom d'extracteur invalide.")
        return
    if not update.message.document and not update.message.reply_to_message:
        await update.message.reply_text(
            "Envoie un fichier avec la commande en legende.\n"
            "Ou reponds a un fichier deja envoye avec /extract <type>."
        )
        return
    target_doc = None
    if update.message.document:
        target_doc = update.message.document
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        target_doc = update.message.reply_to_message.document
    if not target_doc:
        await update.message.reply_text("Aucun document detecte.")
        return
    if target_doc.file_size and target_doc.file_size > 50 * 1024 * 1024:
        await update.message.reply_text("Fichier trop volumineux (max 50 Mo).")
        return
    status_msg = await update.message.reply_text(f"Telechargement du fichier pour {extractor_name}...")
    tmpdir = None
    try:
        tg_file = await target_doc.get_file()
        tmpdir = os.path.join("/tmp", f"extract_{target_doc.file_unique_id}")
        os.makedirs(tmpdir, exist_ok=True)
        file_path = os.path.join(tmpdir, target_doc.file_name or "input.bin")
        await tg_file.download_to_drive(file_path)
        await status_msg.edit_text(f"Extraction avec {extractor_name}...")
        result = extract_hash_from_file(file_path, extractor_name)
        text = (
            f"Extraction reussie.\n"
            f"Extracteur : {result['extractor']}\n"
            f"Taille : {result['file_size']} octets\n\n"
            f"Hash extrait :\n{result['hash_line']}\n\n"
            f"Pour casser : /crackf <format> {result['hash_line'].split(':')[0]}"
        )
        await status_msg.edit_text(_truncate(text))
    except JohnError as exc:
        await status_msg.edit_text(f"Erreur : {exc}")
    finally:
        if tmpdir and os.path.isdir(tmpdir):
            import shutil as _shutil
            _shutil.rmtree(tmpdir, ignore_errors=True)


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
    if not _is_admin(update):
        return
    if not update.message.document:
        return
    caption = update.message.caption or ""
    if caption.startswith("/extract"):
        parts = caption.split()
        if len(parts) >= 2:
            extractor_name = parts[1].strip()
            await cmd_extract(update, context, _forced_extractor=extractor_name)


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Exception lors du traitement d'une mise a jour", exc_info=context.error)
    if update and update.effective_message:
        try:
            await update.effective_message.reply_text("Une erreur est survenue. Reessaie plus tard.")
        except Exception:
            pass

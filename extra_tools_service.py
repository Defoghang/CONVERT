import os
import re
import shutil
import subprocess
import tempfile
import uuid

TOOL_TIMEOUT = 300
HASHCAT_TIMEOUT = 600
EXTRACT_TIMEOUT = 120
MAX_INPUT_LENGTH = 5000
MAX_FILE_SIZE = 30 * 1024 * 1024

WORDLIST_PATH = "/usr/share/wordlists/rockyou.txt"
RULES_PATH = "/opt/john/run/rules/best64.rule"


class ExtraToolError(Exception):
    pass


def _run(args, timeout=TOOL_TIMEOUT, cwd=None):
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired as exc:
        raise ExtraToolError(f"Delai depasse ({timeout}s) pour : {args[0]}") from exc
    except FileNotFoundError as exc:
        raise ExtraToolError(f"Binaire introuvable : {args[0]}") from exc
    except PermissionError as exc:
        raise ExtraToolError(f"Permission refusee : {args[0]}") from exc


def _tool_path(name):
    candidates = [
        f"/opt/john/run/{name}",
        f"/usr/local/bin/{name}",
        f"/usr/bin/{name}",
        f"/usr/sbin/{name}",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return shutil.which(name)


def is_tool_available(name):
    return _tool_path(name) is not None


def available_tools():
    names = [
        "hashcat", "pdfcrack", "pdftotext", "pdfinfo", "pdfimages",
        "mutool", "qpdf", "7z", "unrar", "cabextract",
        "steghide", "stegseek", "binwalk", "foremost", "testdisk",
        "fls", "strings", "file", "ciphey", "theHarvester",
    ]
    return {n: is_tool_available(n) for n in names}


def detect_hash_type(hash_value):
    hash_value = hash_value.strip()
    if not hash_value:
        raise ExtraToolError("Hash vide")
    if len(hash_value) > MAX_INPUT_LENGTH:
        raise ExtraToolError("Hash trop long")

    h = hash_value.lower()

    if re.match(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$", hash_value):
        return "bcrypt", 3200
    if re.match(r"^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$", hash_value):
        return "sha512crypt", 1800
    if re.match(r"^\$5\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$", hash_value):
        return "sha256crypt", 7400
    if re.match(r"^\$1\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$", hash_value):
        return "md5crypt", 500
    if re.match(r"^\$pdf\$", hash_value):
        return "pdf", 10500
    if re.match(r"^\$zip2\$", hash_value):
        return "zip", 13600
    if re.match(r"^\$rar5\$", hash_value):
        return "rar5", 13000
    if re.match(r"^\$7z\$", hash_value):
        return "7z", 11600
    if re.match(r"^[a-f0-9]{32}$", h):
        return "md5", 0
    if re.match(r"^[a-f0-9]{40}$", h):
        return "sha1", 100
    if re.match(r"^[a-f0-9]{64}$", h):
        return "sha256", 1400
    if re.match(r"^[a-f0-9]{128}$", h):
        return "sha512", 1700
    return "unknown", None


def hashcat_crack(hash_value, mode=None, wordlist=None):
    binary = _tool_path("hashcat")
    if not binary:
        raise ExtraToolError("hashcat introuvable sur cet environnement")

    detected_name, detected_mode = detect_hash_type(hash_value)
    use_mode = mode if mode is not None else detected_mode
    if use_mode is None:
        raise ExtraToolError(
            "Impossible de detecter automatiquement le type de hash. "
            "Precise le mode numerique hashcat (ex: 0 pour MD5)."
        )

    workdir = tempfile.mkdtemp(prefix="hashcat_")
    hash_file = os.path.join(workdir, "hash.txt")
    out_file = os.path.join(workdir, "out.txt")
    pot_file = os.path.join(workdir, "hashcat.potfile")

    with open(hash_file, "w", encoding="utf-8") as fh:
        fh.write(hash_value.strip() + "\n")

    wl = wordlist if wordlist and os.path.isfile(wordlist) else WORDLIST_PATH
    if not os.path.isfile(wl):
        raise ExtraToolError(f"Wordlist introuvable : {wl}")

    args = [
        binary,
        "-m", str(use_mode),
        "-a", "0",
        "--potfile-path", pot_file,
        "--outfile", out_file,
        "--outfile-format", "2",
        "--force",
        "--quiet",
        hash_file,
        wl,
    ]

    result = _run(args, timeout=HASHCAT_TIMEOUT, cwd=workdir)

    cracked = None
    if os.path.isfile(out_file):
        with open(out_file, "r", encoding="utf-8") as fh:
            line = fh.readline().strip()
            if line:
                cracked = line

    return {
        "workdir": workdir,
        "hash_type": detected_name,
        "mode": use_mode,
        "cracked": cracked,
        "stdout": result.stdout[-2000:] if result.stdout else "",
        "stderr": result.stderr[-2000:] if result.stderr else "",
        "returncode": result.returncode,
    }


def hashcat_cleanup(workdir):
    if workdir and os.path.isdir(workdir):
        shutil.rmtree(workdir, ignore_errors=True)


def pdfcrack_crack(pdf_path, wordlist=None):
    binary = _tool_path("pdfcrack")
    if not binary:
        raise ExtraToolError("pdfcrack introuvable")
    if not os.path.isfile(pdf_path):
        raise ExtraToolError("PDF introuvable")

    wl = wordlist if wordlist and os.path.isfile(wordlist) else WORDLIST_PATH
    if not os.path.isfile(wl):
        raise ExtraToolError(f"Wordlist introuvable : {wl}")

    result = _run([binary, "-f", pdf_path, "-w", wl, "-q"], timeout=HASHCAT_TIMEOUT)

    found = None
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.lower().startswith("found user-password:"):
            found = line.split(":", 1)[1].strip().strip("'")
            break
        if line.lower().startswith("found owner-password:"):
            found = line.split(":", 1)[1].strip().strip("'")
            break

    return {
        "cracked": found,
        "stdout": result.stdout[-2000:] if result.stdout else "",
        "stderr": result.stderr[-2000:] if result.stderr else "",
        "returncode": result.returncode,
    }


def pdf_analyze(pdf_path):
    results = {}
    for tool, args in [
        ("pdfinfo", ["pdfinfo", pdf_path]),
        ("pdftotext", ["pdftotext", "-l", "3", pdf_path, "-"]),
    ]:
        binary = _tool_path(tool)
        if not binary:
            results[tool] = "outil indisponible"
            continue
        try:
            r = _run([binary] + args[1:], timeout=EXTRACT_TIMEOUT)
            results[tool] = (r.stdout or r.stderr or "")[:3000]
        except ExtraToolError as exc:
            results[tool] = f"erreur : {exc}"
    return results


def binwalk_scan(file_path):
    binary = _tool_path("binwalk")
    if not binary:
        raise ExtraToolError("binwalk introuvable")
    if not os.path.isfile(file_path):
        raise ExtraToolError("Fichier introuvable")
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        raise ExtraToolError(f"Fichier trop volumineux (max {MAX_FILE_SIZE // (1024*1024)} Mo)")
    result = _run([binary, file_path], timeout=EXTRACT_TIMEOUT)
    return {
        "stdout": result.stdout[:3500] if result.stdout else "",
        "stderr": result.stderr[:1000] if result.stderr else "",
    }


def steghide_info(file_path, passphrase=None):
    binary = _tool_path("steghide")
    if not binary:
        raise ExtraToolError("steghide introuvable")
    if not os.path.isfile(file_path):
        raise ExtraToolError("Fichier introuvable")

    args = [binary, "info", file_path]
    if passphrase:
        args.extend(["-p", passphrase])
    else:
        args.extend(["-p", ""])

    result = _run(args, timeout=EXTRACT_TIMEOUT)
    return {
        "stdout": result.stdout[:3000] if result.stdout else "",
        "stderr": result.stderr[:1000] if result.stderr else "",
        "returncode": result.returncode,
    }


def stegseek_crack(file_path, wordlist=None):
    binary = _tool_path("stegseek")
    if not binary:
        raise ExtraToolError("stegseek introuvable")
    if not os.path.isfile(file_path):
        raise ExtraToolError("Fichier introuvable")

    wl = wordlist if wordlist and os.path.isfile(wordlist) else WORDLIST_PATH
    if not os.path.isfile(wl):
        raise ExtraToolError(f"Wordlist introuvable : {wl}")

    workdir = tempfile.mkdtemp(prefix="stegseek_")
    out_file = os.path.join(workdir, "extracted.dat")

    args = [binary, "--crack", file_path, wl, "-xf", out_file]
    result = _run(args, timeout=HASHCAT_TIMEOUT)

    password = None
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if "Found passphrase:" in line:
            password = line.split(":", 1)[1].strip().strip('"')
            break

    extracted_exists = os.path.isfile(out_file) and os.path.getsize(out_file) > 0

    return {
        "workdir": workdir,
        "password": password,
        "extracted_file": out_file if extracted_exists else None,
        "stdout": result.stdout[:3000] if result.stdout else "",
        "stderr": result.stderr[:1000] if result.stderr else "",
    }


def stegseek_cleanup(workdir):
    if workdir and os.path.isdir(workdir):
        shutil.rmtree(workdir, ignore_errors=True)


def strings_extract(file_path, min_len=6):
    binary = _tool_path("strings")
    if not binary:
        raise ExtraToolError("strings introuvable")
    if not os.path.isfile(file_path):
        raise ExtraToolError("Fichier introuvable")
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        raise ExtraToolError("Fichier trop volumineux")
    result = _run([binary, "-n", str(min_len), file_path], timeout=EXTRACT_TIMEOUT)
    return result.stdout[:3500] if result.stdout else ""


def ciphey_decode(text):
    binary = _tool_path("ciphey")
    if not binary:
        raise ExtraToolError("ciphey introuvable (pip install ciphey)")
    if not text or len(text) > MAX_INPUT_LENGTH:
        raise ExtraToolError("Texte invalide ou trop long")
    result = _run([binary, "-t", text, "-q"], timeout=EXTRACT_TIMEOUT)
    return {
        "stdout": result.stdout[:3500] if result.stdout else "",
        "stderr": result.stderr[:1000] if result.stderr else "",
        "returncode": result.returncode,
    }


def theharvester_search(domain):
    binary = _tool_path("theHarvester")
    if not binary:
        raise ExtraToolError("theHarvester introuvable (pip install theHarvester)")
    if not re.match(r"^[a-zA-Z0-9.\-]{1,253}$", domain):
        raise ExtraToolError("Domaine invalide")
    result = _run([binary, "-d", domain, "-b", "bing"], timeout=EXTRACT_TIMEOUT)
    return {
        "stdout": result.stdout[:3500] if result.stdout else "",
        "stderr": result.stderr[:1000] if result.stderr else "",
    }


def extract_with_7z(file_path, password=None):
    binary = _tool_path("7z")
    if not binary:
        raise ExtraToolError("7z introuvable")
    if not os.path.isfile(file_path):
        raise ExtraToolError("Fichier introuvable")

    workdir = tempfile.mkdtemp(prefix="7z_")
    args = [binary, "x", file_path, f"-o{workdir}", "-y"]
    if password:
        args.append(f"-p{password}")

    result = _run(args, timeout=EXTRACT_TIMEOUT)
    extracted = []
    for root, _, files in os.walk(workdir):
        for f in files[:20]:
            extracted.append(os.path.join(root, f))

    return {
        "workdir": workdir,
        "extracted": extracted,
        "stdout": result.stdout[:2000] if result.stdout else "",
        "stderr": result.stderr[:1000] if result.stderr else "",
    }

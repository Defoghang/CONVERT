import os
import shutil
import subprocess
import tempfile
import uuid

PDF_MAX_FILE_SIZE = 20 * 1024 * 1024
PDF_CRACK_TIMEOUT = 600
PDF_QPDF_TIMEOUT = 120


class PdfError(Exception):
    pass


def _run(args, timeout):
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PdfError(f"Delai depasse ({timeout}s) pour : {args[0]}") from exc
    except FileNotFoundError as exc:
        raise PdfError(f"Binaire introuvable : {args[0]}") from exc
    except PermissionError as exc:
        raise PdfError(f"Permission refusee pour : {args[0]}") from exc


def find_pdf2john():
    candidates = [
        "/opt/john/run/pdf2john.pl",
        "/opt/john/run/pdf2john.py",
        "/usr/share/john/pdf2john.pl",
        "/usr/share/john/pdf2john.py",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.R_OK):
            return c
    for name in ("pdf2john.pl", "pdf2john.py", "pdf2john"):
        found = shutil.which(name)
        if found:
            return found
    return None


def is_qpdf_available():
    return shutil.which("qpdf") is not None


def validate_pdf(path):
    if not os.path.isfile(path):
        raise PdfError("Fichier PDF introuvable")
    size = os.path.getsize(path)
    if size == 0:
        raise PdfError("Fichier vide")
    if size > PDF_MAX_FILE_SIZE:
        raise PdfError(f"PDF trop volumineux (max 20 Mo, recu {size} octets)")
    with open(path, "rb") as fh:
        header = fh.read(5)
    if header != b"%PDF-":
        raise PdfError("Le fichier n'est pas un PDF valide (en-tete manquant)")
    return size


def extract_pdf_hash(pdf_path):
    extractor = find_pdf2john()
    if not extractor:
        raise PdfError("pdf2john introuvable sur cet environnement")
    validate_pdf(pdf_path)

    if extractor.endswith(".py"):
        args = ["python3", extractor, pdf_path]
    elif extractor.endswith(".pl"):
        args = ["perl", extractor, pdf_path]
    else:
        args = [extractor, pdf_path]

    result = _run(args, timeout=60)

    hash_line = None
    for line in result.stdout.splitlines():
        line = line.strip()
        if "$pdf$" in line:
            hash_line = line
            break

    if not hash_line:
        raise PdfError(
            "Aucun hash PDF extrait. Le PDF n'est probablement pas chiffre "
            "ou utilise un format non supporte par pdf2john."
        )

    return {
        "extractor": extractor,
        "hash_line": hash_line,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def decrypt_pdf(input_path, password, output_path):
    if not is_qpdf_available():
        raise PdfError("qpdf introuvable sur cet environnement")
    if not os.path.isfile(input_path):
        raise PdfError("PDF source introuvable")
    if not password:
        raise PdfError("Mot de passe vide")

    result = _run(
        ["qpdf", f"--password={password}", "--decrypt", input_path, output_path],
        timeout=PDF_QPDF_TIMEOUT,
    )

    if result.returncode != 0 or not os.path.isfile(output_path):
        raise PdfError(
            "Echec du deverrouillage qpdf : "
            + (result.stderr.strip() or result.stdout.strip() or "erreur inconnue")
        )

    if os.path.getsize(output_path) == 0:
        raise PdfError("Le PDF de sortie est vide")

    return output_path


def make_session_dir():
    session_id = uuid.uuid4().hex[:12]
    return session_id, tempfile.mkdtemp(prefix=f"pdf_{session_id}_")


def cleanup_dir(path):
    if path and os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)

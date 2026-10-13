import os
import shutil
import subprocess
import tempfile
import uuid


JOHN_BINARY = shutil.which("john") or "/usr/sbin/john"
JOHN_MAX_HASHES = 20
JOHN_MAX_HASH_LENGTH = 512
JOHN_TIMEOUT_SECONDS = 300


class JohnError(Exception):
    pass


def _sanitize_hash_line(line):
    line = line.strip()
    if not line:
        return None
    if len(line) > JOHN_MAX_HASH_LENGTH:
        raise JohnError("Ligne de hash trop longue (max 512 caracteres)")
    if "\x00" in line or "\n" in line or "\r" in line:
        raise JohnError("Caracteres invalides detectes dans le hash")
    return line


def validate_hashes(raw_text):
    lines = [l for l in raw_text.splitlines() if l.strip()]
    if not lines:
        raise JohnError("Aucun hash fourni")
    if len(lines) > JOHN_MAX_HASHES:
        raise JohnError(f"Trop de hashes (max {JOHN_MAX_HASHES})")
    cleaned = []
    for line in lines:
        sanitized = _sanitize_hash_line(line)
        if sanitized:
            cleaned.append(sanitized)
    if not cleaned:
        raise JohnError("Aucun hash valide apres nettoyage")
    return cleaned


def is_john_available():
    return os.path.isfile(JOHN_BINARY) and os.access(JOHN_BINARY, os.X_OK)


def _run_command(args, timeout=JOHN_TIMEOUT_SECONDS):
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise JohnError(f"Delai depasse ({timeout}s) pour : {' '.join(args)}") from exc
    except FileNotFoundError as exc:
        raise JohnError(f"Binaire introuvable : {args[0]}") from exc
    except PermissionError as exc:
        raise JohnError(f"Permission refusee pour : {args[0]}") from exc
    return result


def crack_hashes(hashes, wordlist=None, john_format=None):
    if not is_john_available():
        raise JohnError("John the Ripper n'est pas installe sur cet environnement")

    session_id = uuid.uuid4().hex[:12]
    workdir = tempfile.mkdtemp(prefix=f"john_{session_id}_")
    hash_file = os.path.join(workdir, "hashes.txt")
    pot_file = os.path.join(workdir, "john.pot")

    with open(hash_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hashes) + "\n")

    base_args = [JOHN_BINARY, f"--pot={pot_file}", f"--session={session_id}"]

    if john_format:
        base_args.append(f"--format={john_format}")

    if wordlist:
        if not os.path.isfile(wordlist):
            raise JohnError(f"Wordlist introuvable : {wordlist}")
        base_args.append(f"--wordlist={wordlist}")

    base_args.append(hash_file)

    crack_result = _run_command(base_args)

    show_args = [JOHN_BINARY, f"--pot={pot_file}", "--show", hash_file]
    if john_format:
        show_args.insert(2, f"--format={john_format}")

    show_result = _run_command(show_args)

    cracked = {}
    for line in show_result.stdout.splitlines():
        if ":" not in line:
            continue
        if line.strip().endswith("password hash cracked, 0 left"):
            continue
        if line.startswith("0g"):
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            cracked[parts[0].strip()] = parts[1].strip()

    return {
        "session_id": session_id,
        "workdir": workdir,
        "hash_file": hash_file,
        "pot_file": pot_file,
        "cracked": cracked,
        "stdout": crack_result.stdout,
        "stderr": crack_result.stderr,
        "returncode": crack_result.returncode,
        "total": len(hashes),
        "cracked_count": len(cracked),
    }


def cleanup_workdir(workdir):
    if workdir and os.path.isdir(workdir):
        shutil.rmtree(workdir, ignore_errors=True)


def get_john_version():
    if not is_john_available():
        return None
    result = _run_command([JOHN_BINARY, "--list=build-info"], timeout=10)
    if result.returncode != 0:
        return "Version inconnue"
    for line in result.stdout.splitlines():
        if line.startswith("John the Ripper"):
            return line.strip()
    return "Version inconnue"

import os
import shutil
import subprocess
import tempfile
import uuid

JOHN_BINARY_CANDIDATES = [
    "/opt/john/run/john",
    "/usr/sbin/john",
    "/usr/bin/john",
]

JOHN_MAX_HASHES = 20
JOHN_MAX_HASH_LENGTH = 512
JOHN_TIMEOUT_SECONDS = 600
JOHN_EXTRACT_TIMEOUT_SECONDS = 60
JOHN_MAX_FILE_SIZE = 50 * 1024 * 1024


class JohnError(Exception):
    pass


def find_john_binary():
    for candidate in JOHN_BINARY_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("john")
    if found:
        return found
    return None


def find_extractor(name):
    binary = find_john_binary()
    if not binary:
        return None
    john_dir = os.path.dirname(binary)
    for ext in (name, name + ".py", name + ".pl"):
        path = os.path.join(john_dir, ext)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    found = shutil.which(name)
    return found


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
    return find_john_binary() is not None


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


def _parse_show_output(output):
    cracked = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        if "password hash cracked" in line:
            continue
        if line.startswith("0g"):
            continue
        if line.strip().endswith(" left"):
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            cracked[parts[0].strip()] = parts[1].strip()
    return cracked


def _crack_common(hashes, john_format=None, extra_args=None, timeout=JOHN_TIMEOUT_SECONDS):
    binary = find_john_binary()
    if not binary:
        raise JohnError("John the Ripper n'est pas installe sur cet environnement")

    session_id = uuid.uuid4().hex[:12]
    workdir = tempfile.mkdtemp(prefix=f"john_{session_id}_")
    hash_file = os.path.join(workdir, "hashes.txt")
    pot_file = os.path.join(workdir, "john.pot")

    with open(hash_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hashes) + "\n")

    base_args = [binary, f"--pot={pot_file}", f"--session={session_id}"]
    if john_format:
        base_args.append(f"--format={john_format}")
    if extra_args:
        base_args.extend(extra_args)
    base_args.append(hash_file)

    crack_result = _run_command(base_args, timeout=timeout)

    show_args = [binary, f"--pot={pot_file}", "--show", hash_file]
    if john_format:
        show_args.insert(2, f"--format={john_format}")

    show_result = _run_command(show_args, timeout=60)

    cracked = _parse_show_output(show_result.stdout)

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


def crack_hashes(hashes, wordlist=None, john_format=None):
    extra_args = []
    if wordlist and os.path.isfile(wordlist):
        extra_args.append(f"--wordlist={wordlist}")
        extra_args.append("--rules=Jumbo")
    return _crack_common(hashes, john_format=john_format, extra_args=extra_args)


def crack_incremental(hashes, john_format=None, incremental_mode=None, min_length=None, max_length=None):
    extra_args = ["--incremental"]
    if incremental_mode:
        extra_args = [f"--incremental={incremental_mode}"]
    if min_length is not None:
        extra_args.append(f"--min-length={min_length}")
    if max_length is not None:
        extra_args.append(f"--max-length={max_length}")
    return _crack_common(hashes, john_format=john_format, extra_args=extra_args)


def crack_mask(hashes, mask, john_format=None):
    extra_args = [f"--mask={mask}"]
    return _crack_common(hashes, john_format=john_format, extra_args=extra_args)


def crack_single(hashes, john_format=None):
    extra_args = ["--single"]
    return _crack_common(hashes, john_format=john_format, extra_args=extra_args)


def crack_hybrid(hashes, wordlist, mask, john_format=None):
    if not os.path.isfile(wordlist):
        raise JohnError(f"Wordlist introuvable : {wordlist}")
    extra_args = [f"--wordlist={wordlist}", f"--mask={mask}"]
    return _crack_common(hashes, john_format=john_format, extra_args=extra_args)


def crack_with_rules(hashes, rules, wordlist=None, john_format=None):
    extra_args = [f"--rules={rules}"]
    if wordlist and os.path.isfile(wordlist):
        extra_args.insert(0, f"--wordlist={wordlist}")
    return _crack_common(hashes, john_format=john_format, extra_args=extra_args)


def list_formats():
    binary = find_john_binary()
    if not binary:
        raise JohnError("John the Ripper n'est pas installe")
    result = _run_command([binary, "--list=formats"], timeout=30)
    if result.returncode != 0:
        raise JohnError(f"Erreur lors de la liste des formats : {result.stderr.strip()}")
    formats = []
    for line in result.stdout.replace("\n", " ").split(","):
        fmt = line.strip()
        if fmt:
            formats.append(fmt)
    return formats


def list_rules():
    binary = find_john_binary()
    if not binary:
        raise JohnError("John the Ripper n'est pas installe")
    result = _run_command([binary, "--list=rules"], timeout=30)
    if result.returncode != 0:
        raise JohnError(f"Erreur lors de la liste des regles : {result.stderr.strip()}")
    rules = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith("["):
            rules.append(line)
    return rules


def extract_hash_from_file(file_path, extractor_name):
    binary = find_extractor(extractor_name)
    if not binary:
        raise JohnError(f"Extracteur introuvable : {extractor_name}")
    if not os.path.isfile(file_path):
        raise JohnError(f"Fichier introuvable : {file_path}")
    size = os.path.getsize(file_path)
    if size > JOHN_MAX_FILE_SIZE:
        raise JohnError(f"Fichier trop volumineux (max 50 Mo, recu {size} octets)")

    if binary.endswith(".py"):
        args = ["python3", binary, file_path]
    elif binary.endswith(".pl"):
        args = ["perl", binary, file_path]
    else:
        args = [binary, file_path]

    result = _run_command(args, timeout=JOHN_EXTRACT_TIMEOUT_SECONDS)
    if result.returncode != 0 and not result.stdout.strip():
        raise JohnError(f"Extraction echouee : {result.stderr.strip() or 'erreur inconnue'}")

    hash_line = None
    for line in result.stdout.splitlines():
        line = line.strip()
        if ":" in line and "$" in line:
            hash_line = line
            break
    if not hash_line:
        raise JohnError("Aucun hash extrait du fichier")

    return {
        "extractor": extractor_name,
        "hash_line": hash_line,
        "raw_output": result.stdout,
        "file_size": size,
    }


def available_extractors():
    known = [
        "zip2john", "rar2john", "ssh2john", "pdf2john",
        "office2john", "keepass2john", "7z2john",
        "putty2john", "pwsafe2john", "truecrypt2john",
    ]
    return [name for name in known if find_extractor(name)]


def cleanup_workdir(workdir):
    if workdir and os.path.isdir(workdir):
        shutil.rmtree(workdir, ignore_errors=True)


def get_john_version():
    binary = find_john_binary()
    if not binary:
        return None
    result = _run_command([binary, "--list=build-info"], timeout=15)
    if result.returncode != 0:
        return "Version inconnue"
    for line in result.stdout.splitlines():
        if line.startswith("John the Ripper"):
            return line.strip()
    for line in result.stdout.splitlines():
        if line.strip():
            return line.strip()
    return "Version inconnue"

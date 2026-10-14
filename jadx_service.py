import os
import shutil
import subprocess
import tempfile
import uuid
import zipfile

JADX_TIMEOUT = 900
JADX_MAX_INPUT_SIZE = 50 * 1024 * 1024
JADX_MAX_OUTPUT_SIZE = 45 * 1024 * 1024

JADX_CANDIDATES = [
    "/opt/jadx/bin/jadx",
    os.path.expanduser("~/tools/jadx/bin/jadx"),
    "/usr/local/bin/jadx",
    "/usr/bin/jadx",
]

SUPPORTED_EXTENSIONS = (".apk", ".dex", ".jar", ".class", ".aar")


class JadxError(Exception):
    pass


def find_jadx_binary():
    env_path = os.environ.get("JADX_BINARY_PATH")
    if env_path and os.path.isfile(env_path) and os.access(env_path, os.X_OK):
        return env_path
    for candidate in JADX_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("jadx")


def is_jadx_available():
    return find_jadx_binary() is not None


def _run(args, timeout=JADX_TIMEOUT, cwd=None):
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
        raise JadxError(f"Timeout ({timeout}s) depasse") from exc
    except FileNotFoundError as exc:
        raise JadxError(f"Binaire introuvable : {args[0]}") from exc
    except PermissionError as exc:
        raise JadxError(f"Permission refusee : {args[0]}") from exc


def validate_input(path):
    if not os.path.isfile(path):
        raise JadxError("Fichier introuvable")
    size = os.path.getsize(path)
    if size == 0:
        raise JadxError("Fichier vide")
    if size > JADX_MAX_INPUT_SIZE:
        raise JadxError(f"Fichier trop volumineux (max {JADX_MAX_INPUT_SIZE // (1024*1024)} Mo)")
    return size


def _detect_kind(path):
    name = path.lower()
    if name.endswith(".apk"):
        return "apk"
    if name.endswith(".dex"):
        return "dex"
    if name.endswith(".jar"):
        return "jar"
    if name.endswith(".class"):
        return "class"
    if name.endswith(".aar"):
        return "aar"
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if magic == b"PK\x03\x04":
        return "apk"
    if magic[:3] == b"dex":
        return "dex"
    if magic == b"\xca\xfe\xba\xbe":
        return "class"
    return "unknown"


def decompile(input_path, workdir, deobf=True, show_bad_code=True, comments_level="info"):
    binary = find_jadx_binary()
    if not binary:
        raise JadxError("JADX introuvable")

    validate_input(input_path)
    kind = _detect_kind(input_path)

    output_dir = os.path.join(workdir, "jadx_out")
    os.makedirs(output_dir, exist_ok=True)

    args = [
        binary,
        "-d", output_dir,
        "--no-res",
        "--no-imports",
        "--threads-count", str(max(2, min(4, (os.cpu_count() or 2)))),
        "--comments-level", comments_level,
    ]
    if deobf:
        args.append("--deobf")
    if show_bad_code:
        args.append("--show-bad-code")
    args.append(input_path)

    result = _run(args, timeout=JADX_TIMEOUT, cwd=workdir)

    sources_dir = os.path.join(output_dir, "sources")
    if not os.path.isdir(sources_dir) or not os.listdir(sources_dir):
        raise JadxError(
            "Aucune source Java produite. "
            f"stderr: {(result.stderr or '')[:300]}"
        )

    files_count = 0
    java_count = 0
    total_bytes = 0
    for root, _, files in os.walk(sources_dir):
        for f in files:
            files_count += 1
            fp = os.path.join(root, f)
            try:
                total_bytes += os.path.getsize(fp)
            except OSError:
                pass
            if f.endswith(".java"):
                java_count += 1

    return {
        "kind": kind,
        "sources_dir": sources_dir,
        "output_dir": output_dir,
        "stdout": (result.stdout or "")[-2000:],
        "stderr": (result.stderr or "")[-2000:],
        "returncode": result.returncode,
        "files_count": files_count,
        "java_count": java_count,
        "total_bytes": total_bytes,
    }


def pack_sources(sources_dir, workdir):
    archive_path = os.path.join(workdir, "jadx_sources.zip")
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, _, files in os.walk(sources_dir):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, sources_dir)
                zf.write(full, rel)
    size = os.path.getsize(archive_path)
    if size > JADX_MAX_OUTPUT_SIZE:
        raise JadxError(
            f"Archive trop volumineuse : {size // (1024*1024)} Mo "
            f"(max {JADX_MAX_OUTPUT_SIZE // (1024*1024)} Mo)"
        )
    return archive_path, size


def cleanup_dir(path):
    if path and os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)


def get_jadx_version():
    binary = find_jadx_binary()
    if not binary:
        return None
    result = _run([binary, "--version"], timeout=20)
    output = (result.stdout or "") + (result.stderr or "")
    for line in output.splitlines():
        if "jadx" in line.lower() and any(c.isdigit() for c in line):
            return line.strip()
    return "Version inconnue"

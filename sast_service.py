import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import uuid
import zipfile

SAST_TIMEOUT = 600
SAST_MAX_INPUT_SIZE = 50 * 1024 * 1024
SAST_MAX_REPORT_SIZE = 5 * 1024 * 1024
SAST_MAX_ZIP_SIZE = 45 * 1024 * 1024
SAST_MAX_FILES = 500

ARCHIVE_EXTENSIONS = (
    ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2",
    ".tar.xz", ".txz", ".gz", ".bz2", ".xz", ".rar", ".7z",
)

SOURCE_EXTENSIONS = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".kts",
    ".go", ".rb", ".php", ".cs", ".c", ".cpp", ".cc", ".cxx",
    ".h", ".hpp", ".rs", ".swift", ".sh", ".bash", ".zsh",
    ".yml", ".yaml", ".sql", ".html", ".htm", ".xml", ".json",
    ".pl", ".pm", ".lua", ".r", ".scala", ".m", ".mm",
)

SUPPORTED_EXTENSIONS = ARCHIVE_EXTENSIONS + SOURCE_EXTENSIONS


class SastError(Exception):
    pass


def find_semgrep():
    for c in ["/usr/local/bin/semgrep", "/usr/bin/semgrep"]:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    home = os.path.expanduser("~")
    local = os.path.join(home, ".local", "bin", "semgrep")
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    return shutil.which("semgrep")


def find_bandit():
    for c in ["/usr/local/bin/bandit", "/usr/bin/bandit"]:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    home = os.path.expanduser("~")
    local = os.path.join(home, ".local", "bin", "bandit")
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    return shutil.which("bandit")


def is_semgrep_available():
    return find_semgrep() is not None


def is_bandit_available():
    return find_bandit() is not None


def _run(args, timeout=SAST_TIMEOUT, cwd=None, env=None):
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=cwd,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise SastError(f"Timeout ({timeout}s) depasse") from exc
    except FileNotFoundError as exc:
        raise SastError(f"Binaire introuvable : {args[0]}") from exc
    except PermissionError as exc:
        raise SastError(f"Permission refusee : {args[0]}") from exc


def _detect_language(path):
    ext_map = {
        ".py": "python", ".js": "javascript", ".jsx": "javascript",
        ".ts": "typescript", ".tsx": "typescript",
        ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
        ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp",
        ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
        ".h": "c", ".hpp": "cpp", ".rs": "rust", ".swift": "swift",
        ".sh": "bash", ".bash": "bash", ".zsh": "bash",
        ".yml": "yaml", ".yaml": "yaml", ".json": "json",
        ".xml": "xml", ".html": "html", ".htm": "html",
        ".sql": "sql", ".pl": "perl", ".pm": "perl",
        ".lua": "lua", ".r": "r", ".scala": "scala",
        ".m": "objective-c", ".mm": "objective-c",
    }
    ext = os.path.splitext(path)[1].lower()
    return ext_map.get(ext)


def _detect_kind(path):
    name = path.lower()
    if name.endswith(".zip"):
        return "zip"
    for suffix in (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar"):
        if name.endswith(suffix):
            return "tar"
    if name.endswith(".gz"):
        return "gz"
    if name.endswith(".bz2"):
        return "bz2"
    if name.endswith(".xz"):
        return "xz"
    if name.endswith(".rar"):
        return "rar"
    if name.endswith(".7z"):
        return "7z"
    return "file"


def _is_safe_member(member):
    if not member:
        return False
    if member.startswith("/") or member.startswith("\\"):
        return False
    parts = member.replace("\\", "/").split("/")
    if ".." in parts:
        return False
    return True


def _extract_zip(path, workdir):
    with zipfile.ZipFile(path, "r") as zf:
        for member in zf.namelist():
            if not _is_safe_member(member):
                continue
            try:
                zf.extract(member, workdir)
            except (OSError, zipfile.BadZipFile):
                continue


def _extract_tar(path, workdir):
    with tarfile.open(path, "r:*") as tf:
        for member in tf.getmembers():
            if not _is_safe_member(member.name):
                continue
            try:
                tf.extract(member, workdir)
            except (OSError, tarfile.TarError):
                continue


def _extract_with_command(cmd_list, workdir, tool_name):
    if not cmd_list:
        raise SastError(f"{tool_name} indisponible sur cet environnement")
    result = _run(cmd_list, timeout=180, cwd=workdir)
    if result.returncode not in (0, 1):
        err = (result.stderr or result.stdout or "")[:200]
        raise SastError(f"Extraction {tool_name} echouee : {err}")


def _prepare_workdir(input_path):
    workdir = tempfile.mkdtemp(prefix=f"sast_{uuid.uuid4().hex[:12]}_")

    if os.path.isdir(input_path):
        shutil.copytree(input_path, os.path.join(workdir, "src"))
        return workdir

    if not os.path.isfile(input_path):
        raise SastError("Entree invalide")

    kind = _detect_kind(input_path)
    name = os.path.basename(input_path)

    if kind == "zip":
        _extract_zip(input_path, workdir)
        return workdir

    if kind == "tar":
        _extract_tar(input_path, workdir)
        return workdir

    if kind in ("gz", "bz2", "xz"):
        try:
            _extract_tar(input_path, workdir)
            return workdir
        except (tarfile.TarError, OSError):
            pass
        if kind == "gz":
            tool = shutil.which("gunzip")
            if tool:
                out_name = name[:-3] if name.lower().endswith(".gz") else name + ".out"
                out_path = os.path.join(workdir, out_name)
                _run([tool, "-c", input_path], timeout=120)
                try:
                    with open(input_path, "rb") as src:
                        import gzip
                        with gzip.open(src, "rb") as gz:
                            with open(out_path, "wb") as dst:
                                shutil.copyfileobj(gz, dst)
                    return workdir
                except OSError as exc:
                    raise SastError(f"Decompression gz echouee : {exc}") from exc
        if kind == "bz2":
            import bz2
            try:
                out_name = name[:-4] if name.lower().endswith(".bz2") else name + ".out"
                out_path = os.path.join(workdir, out_name)
                with bz2.open(input_path, "rb") as src, open(out_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                return workdir
            except OSError as exc:
                raise SastError(f"Decompression bz2 echouee : {exc}") from exc
        if kind == "xz":
            import lzma
            try:
                out_name = name[:-3] if name.lower().endswith(".xz") else name + ".out"
                out_path = os.path.join(workdir, out_name)
                with lzma.open(input_path, "rb") as src, open(out_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                return workdir
            except (OSError, lzma.LZMAError) as exc:
                raise SastError(f"Decompression xz echouee : {exc}") from exc
        raise SastError("Decompression impossible")

    if kind == "rar":
        unrar = shutil.which("unrar") or shutil.which("unrar-free")
        if not unrar:
            raise SastError("RAR non supporte (unrar indisponible)")
        _extract_with_command([unrar, "x", "-y", input_path, workdir + "/"], workdir, "unrar")
        return workdir

    if kind == "7z":
        sz = shutil.which("7z") or shutil.which("7za") or shutil.which("7zr")
        if not sz:
            raise SastError("7Z non supporte (7z indisponible)")
        _extract_with_command([sz, "x", input_path, f"-o{workdir}", "-y"], workdir, "7z")
        return workdir

    shutil.copy2(input_path, os.path.join(workdir, os.path.basename(input_path)))
    return workdir


def _find_source_files(root, max_files=SAST_MAX_FILES):
    files = []
    skip_dirs = {
        ".git", "node_modules", "venv", ".venv", "__pycache__",
        "dist", "build", ".next", "target", ".idea", ".vscode",
        ".gradle", ".mvn", "bin", "obj", "coverage", ".pytest_cache",
    }
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
        for f in filenames:
            if len(files) >= max_files:
                return files
            full = os.path.join(dirpath, f)
            if _detect_language(full):
                files.append(full)
    return files


def run_semgrep(workdir):
    binary = find_semgrep()
    if not binary:
        raise SastError("Semgrep introuvable")

    json_out = os.path.join(workdir, "_semgrep.json")
    env = os.environ.copy()
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"

    args = [
        binary, "scan",
        "--config=auto",
        "--json",
        f"--output={json_out}",
        "--quiet",
        "--no-git-ignore",
        "--max-target-bytes=2000000",
        "--timeout=30",
        workdir,
    ]
    result = _run(args, timeout=SAST_TIMEOUT, cwd=workdir, env=env)

    findings = []
    if os.path.isfile(json_out):
        try:
            with open(json_out, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for r in data.get("results", []):
                extra = r.get("extra", {})
                metadata = extra.get("metadata", {})
                findings.append({
                    "tool": "semgrep",
                    "rule_id": r.get("check_id", "unknown"),
                    "file": os.path.relpath(r.get("path", ""), workdir),
                    "line": r.get("start", {}).get("line", 0),
                    "column": r.get("start", {}).get("col", 0),
                    "severity": extra.get("severity", "INFO"),
                    "message": extra.get("message", ""),
                    "cwe": metadata.get("cwe", []),
                    "owasp": metadata.get("owasp", []),
                    "references": metadata.get("references", []),
                    "snippet": extra.get("lines", ""),
                })
        except (json.JSONDecodeError, OSError):
            pass

    return findings, (result.stdout or "")[-1500:], (result.stderr or "")[-1500:]


def run_bandit(workdir):
    binary = find_bandit()
    if not binary:
        return [], "", "bandit indisponible"

    json_out = os.path.join(workdir, "_bandit.json")
    args = [
        binary, "-r", workdir,
        "-f", "json",
        "-o", json_out,
        "-ll",
        "--exclude", ".git,node_modules,venv,.venv,__pycache__,dist,build",
    ]
    result = _run(args, timeout=SAST_TIMEOUT, cwd=workdir)

    findings = []
    if os.path.isfile(json_out):
        try:
            with open(json_out, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for r in data.get("results", []):
                findings.append({
                    "tool": "bandit",
                    "rule_id": r.get("test_id", "unknown"),
                    "file": os.path.relpath(r.get("filename", ""), workdir),
                    "line": r.get("line_number", 0),
                    "column": r.get("col_offset", 0),
                    "severity": r.get("issue_severity", "LOW"),
                    "confidence": r.get("issue_confidence", "LOW"),
                    "message": r.get("issue_text", ""),
                    "cwe": [r.get("issue_cwe", {}).get("id", "")] if r.get("issue_cwe") else [],
                    "more_info": r.get("more_info", ""),
                    "snippet": r.get("code", ""),
                })
        except (json.JSONDecodeError, OSError):
            pass

    return findings, (result.stdout or "")[-1500:], (result.stderr or "")[-1500:]


def _severity_rank(sev):
    order = {
        "CRITICAL": 0, "ERROR": 1, "HIGH": 1, "WARNING": 2, "MEDIUM": 2,
        "INFO": 3, "LOW": 3, "NOTE": 4,
    }
    return order.get(str(sev).upper(), 5)


def _fix_suggestion(rule_id, message, tool):
    rule = rule_id.lower()
    msg = message.lower()
    suggestions = []

    if tool == "bandit":
        if "b301" in rule or "yaml" in msg:
            suggestions.append("Utiliser yaml.safe_load() au lieu de yaml.load().")
        if "b303" in rule or "md5" in msg or "sha1" in msg:
            suggestions.append("Remplacer MD5/SHA1 par SHA-256 ou bcrypt pour les mots de passe.")
        if "b105" in rule or "hardcoded" in msg or "password" in msg:
            suggestions.append("Deplacer les secrets vers des variables d'environnement ou un coffre (Vault, AWS Secrets Manager).")
        if "b307" in rule or "eval" in msg:
            suggestions.append("Supprimer eval(). Utiliser ast.literal_eval() ou une table de dispatch.")
        if "b602" in rule or "subprocess" in msg or "shell" in msg:
            suggestions.append("Passer shell=False et fournir une liste d'arguments a subprocess.")
        if "b608" in rule or "sql" in msg:
            suggestions.append("Utiliser des requetes parametrees (placeholders ? / %s) au lieu de concatenation SQL.")
        if "b506" in rule or "unsafe" in msg:
            suggestions.append("Utiliser yaml.safe_load() / defusedxml au lieu des parseurs non surs.")
        if "b324" in rule or "hashlib" in msg:
            suggestions.append("Utiliser hashlib.sha256() au lieu de hashlib.md5()/sha1().")
        if "b311" in rule or "random" in msg:
            suggestions.append("Utiliser le module secrets pour la generation de tokens.")
        if "b201" in rule or "flask" in msg:
            suggestions.append("Desactiver debug=True en production.")
        if "b501" in rule or "verify" in msg:
            suggestions.append("Activer la verification des certificats TLS (verify=True).")
        if "b506" in rule:
            suggestions.append("Utiliser defusedxml au lieu du parseur XML standard.")

    if tool == "semgrep":
        if "sql" in msg or "injection" in msg:
            suggestions.append("Utiliser des requetes parametrees / ORM.")
        if "xss" in msg:
            suggestions.append("Echapper les sorties utilisateur (html.escape, framework auto-escape).")
        if "csrf" in msg:
            suggestions.append("Activer la protection CSRF sur les formulaires sensibles.")
        if "command" in msg and "injection" in msg:
            suggestions.append("Eviter shell=True. Valider les entrees. Utiliser subprocess avec liste d'arguments.")
        if "hardcoded" in msg or "secret" in msg:
            suggestions.append("Externaliser les secrets dans des variables d'environnement.")
        if "jwt" in msg:
            suggestions.append("Verifier la signature JWT, refuser alg=none, utiliser des libs maintenues.")
        if "deserialization" in msg or "pickle" in msg:
            suggestions.append("Ne jamais deserialiser des donnees non fiables. Utiliser JSON.")
        if "path traversal" in msg or "directory traversal" in msg:
            suggestions.append("Normaliser les chemins et refuser les entrees contenant '..'.")
        if "ssrf" in msg:
            suggestions.append("Valider et whitelister les URLs sortantes.")
        if "open redirect" in msg:
            suggestions.append("Valider les URLs de redirection contre une whitelist.")
        if "regex" in msg and ("dos" in msg or "redos" in msg):
            suggestions.append("Simplifier les regex ou ajouter un timeout.")
        if "cors" in msg:
            suggestions.append("Restreindre les origines CORS autorisees.")
        if "weak" in msg and "crypto" in msg:
            suggestions.append("Utiliser des algorithmes modernes (AES-GCM, ChaCha20, SHA-256+).")

    if not suggestions:
        suggestions.append("Revoir le code autour de la ligne indiquee et appliquer le principe de moindre privilege.")

    return suggestions


def build_report(workdir, findings, semgrep_stderr, bandit_stderr):
    by_file = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)

    lines = []
    lines.append("=" * 70)
    lines.append("RAPPORT D'ANALYSE DE SECURITE (SAST)")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Total findings : {len(findings)}")

    sev_count = {}
    for f in findings:
        s = str(f.get("severity", "INFO")).upper()
        sev_count[s] = sev_count.get(s, 0) + 1

    for s in sorted(sev_count, key=_severity_rank):
        lines.append(f"  {s} : {sev_count[s]}")

    lines.append("")
    lines.append(f"Fichiers analyses : {len(by_file)}")
    lines.append(f"Semgrep : {'OK' if is_semgrep_available() else 'INDISPONIBLE'}")
    lines.append(f"Bandit : {'OK' if is_bandit_available() else 'INDISPONIBLE'}")
    lines.append("")
    lines.append("=" * 70)
    lines.append("")

    for file_path in sorted(by_file.keys()):
        file_findings = sorted(
            by_file[file_path],
            key=lambda x: (_severity_rank(x["severity"]), x["line"]),
        )
        lines.append(f"FICHIER : {file_path}")
        lines.append("-" * 70)
        for i, f in enumerate(file_findings, 1):
            lines.append(f"  [{i}] {f['severity']} - {f['rule_id']} ({f['tool']})")
            lines.append(f"      Ligne {f['line']}, colonne {f['column']}")
            lines.append(f"      {f['message'][:500]}")

            if f.get("cwe"):
                cwes = [c for c in f["cwe"] if c]
                if cwes:
                    lines.append(f"      CWE : {', '.join(str(c) for c in cwes)}")

            if f.get("owasp"):
                lines.append(f"      OWASP : {', '.join(str(o) for o in f['owasp'][:3])}")

            if f.get("snippet"):
                snippet = f["snippet"].strip()
                lines.append("      Code :")
                for ln in snippet.splitlines()[:5]:
                    lines.append(f"        {ln[:120]}")

            suggestions = _fix_suggestion(f["rule_id"], f["message"], f["tool"])
            lines.append("      CORRECTIONS SUGGEREES :")
            for s in suggestions:
                lines.append(f"        - {s}")
            lines.append("")
        lines.append("")

    lines.append("=" * 70)
    lines.append("FIN DU RAPPORT")
    lines.append("=" * 70)

    report_text = "\n".join(lines)
    if len(report_text) > SAST_MAX_REPORT_SIZE:
        report_text = report_text[:SAST_MAX_REPORT_SIZE] + "\n\n...(rapport tronque)"

    report_path = os.path.join(workdir, "rapport_securite.txt")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(report_text)

    return report_path, report_text


def pack_workdir(workdir):
    archive_path = os.path.join(workdir, "code_analyse.zip")
    skip_names = {"_semgrep.json", "_bandit.json", "rapport_securite.txt", "code_analyse.zip"}
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, dirs, files in os.walk(workdir):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
            for f in files:
                if f in skip_names:
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, workdir)
                try:
                    zf.write(full, rel)
                except OSError:
                    continue
    size = os.path.getsize(archive_path)
    if size > SAST_MAX_ZIP_SIZE:
        raise SastError(f"Archive trop volumineuse : {size // (1024*1024)} Mo")
    return archive_path, size


def is_supported_filename(filename):
    if not filename:
        return False
    low = filename.lower()
    for ext in SUPPORTED_EXTENSIONS:
        if low.endswith(ext):
            return True
    return False


def analyze(input_path):
    if not os.path.isfile(input_path) and not os.path.isdir(input_path):
        raise SastError("Entree introuvable")

    if os.path.isfile(input_path):
        size = os.path.getsize(input_path)
        if size > SAST_MAX_INPUT_SIZE:
            raise SastError(
                f"Fichier trop volumineux (max {SAST_MAX_INPUT_SIZE // (1024*1024)} Mo)"
            )

    workdir = _prepare_workdir(input_path)

    source_files = _find_source_files(workdir)
    if not source_files:
        raise SastError(
            "Aucun fichier source reconnu dans l'archive. "
            "Extensions supportees : " + ", ".join(SOURCE_EXTENSIONS[:20]) + "..."
        )

    semgrep_findings = []
    semgrep_stderr = ""
    if is_semgrep_available():
        try:
            semgrep_findings, _, semgrep_stderr = run_semgrep(workdir)
        except SastError as exc:
            semgrep_stderr = str(exc)

    bandit_findings = []
    bandit_stderr = ""
    if is_bandit_available():
        try:
            bandit_findings, _, bandit_stderr = run_bandit(workdir)
        except SastError as exc:
            bandit_stderr = str(exc)

    all_findings = semgrep_findings + bandit_findings
    all_findings.sort(key=lambda f: (_severity_rank(f["severity"]), f["file"], f["line"]))

    report_path, report_text = build_report(
        workdir, all_findings, semgrep_stderr, bandit_stderr
    )

    archive_path, archive_size = pack_workdir(workdir)

    return {
        "workdir": workdir,
        "findings": all_findings,
        "findings_count": len(all_findings),
        "files_scanned": len(source_files),
        "report_path": report_path,
        "report_text": report_text,
        "archive_path": archive_path,
        "archive_size": archive_size,
        "semgrep_stderr": semgrep_stderr[:500],
        "bandit_stderr": bandit_stderr[:500],
    }


def cleanup_workdir(workdir):
    if workdir and os.path.isdir(workdir):
        shutil.rmtree(workdir, ignore_errors=True)


def get_versions():
    out = {}
    sg = find_semgrep()
    if sg:
        try:
            r = _run([sg, "--version"], timeout=20)
            out["semgrep"] = (r.stdout or r.stderr or "").strip().splitlines()[0] if (r.stdout or r.stderr) else "?"
        except SastError:
            out["semgrep"] = "erreur"
    bd = find_bandit()
    if bd:
        try:
            r = _run([bd, "--version"], timeout=20)
            out["bandit"] = (r.stdout or r.stderr or "").strip().splitlines()[0] if (r.stdout or r.stderr) else "?"
        except SastError:
            out["bandit"] = "erreur"
    return out

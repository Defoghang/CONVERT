import json
import os
import shutil
import subprocess
import tempfile
import uuid
import zipfile

SAST_TIMEOUT = 600
SAST_MAX_INPUT_SIZE = 50 * 1024 * 1024
SAST_MAX_REPORT_SIZE = 5 * 1024 * 1024
SAST_MAX_ZIP_SIZE = 45 * 1024 * 1024


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
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".kt": "kotlin", ".go": "go", ".rb": "ruby",
        ".php": "php", ".cs": "csharp", ".c": "c", ".cpp": "cpp",
        ".h": "c", ".hpp": "cpp", ".rs": "rust", ".swift": "swift",
        ".sh": "bash", ".bash": "bash", ".yml": "yaml", ".yaml": "yaml",
        ".json": "json", ".xml": "xml", ".html": "html", ".sql": "sql",
    }
    ext = os.path.splitext(path)[1].lower()
    return ext_map.get(ext)


def _find_source_files(root, max_files=500):
    files = []
    skip_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__",
                 "dist", "build", ".next", "target", ".idea", ".vscode"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
        for f in filenames:
            if len(files) >= max_files:
                return files
            full = os.path.join(dirpath, f)
            if _detect_language(full):
                files.append(full)
    return files


def _prepare_workdir(input_path):
    workdir = tempfile.mkdtemp(prefix=f"sast_{uuid.uuid4().hex[:12]}_")
    if os.path.isfile(input_path):
        name = os.path.basename(input_path)
        if name.lower().endswith(".zip"):
            with zipfile.ZipFile(input_path, "r") as zf:
                for member in zf.namelist():
                    if member.startswith("/") or ".." in member:
                        continue
                    zf.extract(member, workdir)
        else:
            shutil.copy2(input_path, os.path.join(workdir, name))
    elif os.path.isdir(input_path):
        shutil.copytree(input_path, os.path.join(workdir, "src"))
    else:
        raise SastError("Entree invalide")
    return workdir


def run_semgrep(workdir):
    binary = find_semgrep()
    if not binary:
        raise SastError("Semgrep introuvable")

    json_out = os.path.join(workdir, "_semgrep.json")
    env = os.environ.copy()
    env["SEMGREP_SEND_METRICS"] = "off"
    args = [
        binary, "scan",
        "--config=auto",
        "--json",
        f"--output={json_out}",
        "--quiet",
        "--no-git-ignore",
        "--max-target-bytes=2000000",
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
        "--exclude", ".git,node_modules,venv,.venv,__pycache__",
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
    order = {"CRITICAL": 0, "ERROR": 1, "HIGH": 1, "WARNING": 2, "MEDIUM": 2,
             "INFO": 3, "LOW": 3, "NOTE": 4}
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
            suggestions.append("Utiliser secrets module pour la generation de tokens.")
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
        file_findings = sorted(by_file[file_path], key=lambda x: (_severity_rank(x["severity"]), x["line"]))
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
                lines.append(f"      Code :")
                for ln in snippet.splitlines()[:5]:
                    lines.append(f"        {ln[:120]}")
            suggestions = _fix_suggestion(f["rule_id"], f["message"], f["tool"])
            lines.append(f"      CORRECTIONS SUGGEREES :")
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


def analyze(input_path):
    if not os.path.isfile(input_path) and not os.path.isdir(input_path):
        raise SastError("Entree introuvable")

    if os.path.isfile(input_path):
        size = os.path.getsize(input_path)
        if size > SAST_MAX_INPUT_SIZE:
            raise SastError(f"Fichier trop volumineux (max {SAST_MAX_INPUT_SIZE // (1024*1024)} Mo)")

    workdir = _prepare_workdir(input_path)

    source_files = _find_source_files(workdir)
    if not source_files:
        raise SastError("Aucun fichier source reconnu dans l'archive")

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

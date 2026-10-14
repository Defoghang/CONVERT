import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"
MAX_ITERATIONS = 5
AI_TIMEOUT = 120
TEST_TIMEOUT = 180
MAX_FILE_SIZE_FOR_AI = 15000
MAX_FILES_FOR_AI = 20


class AIError(Exception):
    pass


def get_api_key():
    key = os.environ.get("GROQ_API_KEY", "").strip()
    if not key:
        raise AIError(
            "GROQ_API_KEY non configuree. "
            "Ajoute le secret GROQ_API_KEY dans les secrets GitHub."
        )
    return key


def is_ai_available():
    return bool(os.environ.get("GROQ_API_KEY", "").strip())


def _call_groq(messages, temperature=0.1, max_tokens=4096):
    import urllib.request
    import urllib.error

    api_key = get_api_key()
    payload = {
        "model": GROQ_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        GROQ_API_URL,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Origin": "https://console.groq.com",
            "Referer": "https://console.groq.com/",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")[:500]
        raise AIError(f"Groq HTTP {exc.code} : {err_body}") from exc
    except urllib.error.URLError as exc:
        raise AIError(f"Reseau Groq : {exc.reason}") from exc

    try:
        parsed = json.loads(body)
        return parsed["choices"][0]["message"]["content"]
    except (KeyError, IndexError, json.JSONDecodeError) as exc:
        raise AIError(f"Reponse Groq invalide : {body[:300]}") from exc


def _extract_code_blocks(text):
    pattern = re.compile(r"```(?:[\w+\-]*)\n(.*?)```", re.DOTALL)
    return [m.group(1) for m in pattern.finditer(text)]


def _detect_language(filename):
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php",
        ".cs": "csharp", ".c": "c", ".cpp": "cpp", ".rs": "rust",
    }
    ext = os.path.splitext(filename)[1].lower()
    return ext_map.get(ext, "text")


def _read_source_files(workdir):
    files = []
    skip_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
    for root, dirs, names in os.walk(workdir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in names:
            ext = os.path.splitext(name)[1].lower()
            if ext not in {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs", ".c", ".cpp", ".rs"}:
                continue
            full = os.path.join(root, name)
            try:
                size = os.path.getsize(full)
                if size > MAX_FILE_SIZE_FOR_AI:
                    continue
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                files.append({
                    "path": os.path.relpath(full, workdir),
                    "full": full,
                    "content": content,
                    "language": _detect_language(name),
                })
                if len(files) >= MAX_FILES_FOR_AI:
                    return files
            except OSError:
                continue
    return files


def _build_fix_prompt(file_info, findings, iteration):
    findings_text = ""
    for f in findings:
        findings_text += (
            f"- [{f.get('severity', 'INFO')}] {f.get('rule_id', '')} "
            f"ligne {f.get('line', 0)} : {f.get('message', '')[:200]}\n"
        )
        suggestions = f.get("suggestions", [])
        for s in suggestions:
            findings_text += f"  -> {s}\n"

    system = (
        "Tu es un expert en securite applicative. "
        "Tu corriges du code source en appliquant des correctifs precis. "
        "Tu reponds UNIQUEMENT avec le contenu complet du fichier corrige, "
        "sans explication, sans markdown, sans commentaire. "
        "Le code doit rester fonctionnel et conserver la logique metier."
    )
    user = (
        f"Iteration {iteration}/{MAX_ITERATIONS}\n"
        f"Fichier : {file_info['path']}\n"
        f"Langage : {file_info['language']}\n\n"
        f"Vulnerabilites detectees :\n{findings_text}\n"
        f"Code actuel :\n{file_info['content']}\n\n"
        f"Renvoie le fichier corrige complet."
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _apply_fix(file_info, fixed_code):
    if not fixed_code or not fixed_code.strip():
        return False
    fixed_code = fixed_code.strip()
    if fixed_code == file_info["content"].strip():
        return False
    backup = file_info["full"] + ".bak"
    try:
        shutil.copy2(file_info["full"], backup)
        with open(file_info["full"], "w", encoding="utf-8") as fh:
            fh.write(fixed_code)
        return True
    except OSError as exc:
        raise AIError(f"Ecriture impossible : {exc}") from exc


def _restore_backup(file_info):
    backup = file_info["full"] + ".bak"
    if os.path.isfile(backup):
        try:
            shutil.copy2(backup, file_info["full"])
            os.remove(backup)
        except OSError:
            pass


def _commit_backup(file_info):
    backup = file_info["full"] + ".bak"
    if os.path.isfile(backup):
        try:
            os.remove(backup)
        except OSError:
            pass


def _run_python_syntax_check(file_info):
    if file_info["language"] != "python":
        return True, ""
    result = subprocess.run(
        ["python3", "-m", "py_compile", file_info["full"]],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "")[:500]
    return True, ""


def _run_tests_for_file(file_info):
    workdir = os.path.dirname(file_info["full"])
    test_files = []
    for root, dirs, names in os.walk(os.path.dirname(workdir) or workdir):
        for name in names:
            if name.startswith("test_") and name.endswith(".py"):
                test_files.append(os.path.join(root, name))
            elif name.endswith("_test.py"):
                test_files.append(os.path.join(root, name))

    if not test_files:
        return True, "aucun test detecte"

    for tf in test_files[:5]:
        try:
            result = subprocess.run(
                ["python3", "-m", "pytest", tf, "-x", "-q", "--tb=short"],
                capture_output=True, text=True, timeout=TEST_TIMEOUT,
                check=False, cwd=os.path.dirname(tf) or workdir,
            )
            if result.returncode != 0:
                output = (result.stdout or "") + (result.stderr or "")
                return False, output[:1000]
        except subprocess.TimeoutExpired:
            return False, f"timeout sur {tf}"
        except FileNotFoundError:
            return True, "pytest non installe"
    return True, "tests passes"


def fix_file_with_validation(file_info, findings):
    if not findings:
        return {"fixed": False, "reason": "aucun finding", "iterations": 0}

    iterations_log = []
    for iteration in range(1, MAX_ITERATIONS + 1):
        messages = _build_fix_prompt(file_info, findings, iteration)
        try:
            response = _call_groq(messages, temperature=0.1)
        except AIError as exc:
            return {
                "fixed": False,
                "reason": f"IA erreur : {exc}",
                "iterations": iteration,
                "log": iterations_log,
            }

        code_blocks = _extract_code_blocks(response)
        fixed_code = code_blocks[0] if code_blocks else response

        applied = _apply_fix(file_info, fixed_code)
        if not applied:
            iterations_log.append(f"iter {iteration}: pas de changement")
            _restore_backup(file_info)
            break

        syntax_ok, syntax_err = _run_python_syntax_check(file_info)
        if not syntax_ok:
            iterations_log.append(f"iter {iteration}: syntaxe invalide ({syntax_err[:80]})")
            _restore_backup(file_info)
            findings = findings + [{
                "severity": "ERROR", "rule_id": "syntax",
                "line": 0, "message": f"Erreur de syntaxe introduite : {syntax_err[:200]}",
                "suggestions": ["Corrige la syntaxe sans casser le code."],
            }]
            continue

        tests_ok, test_output = _run_tests_for_file(file_info)
        if tests_ok:
            _commit_backup(file_info)
            iterations_log.append(f"iter {iteration}: tests OK")
            return {
                "fixed": True,
                "reason": "fix valide apres tests",
                "iterations": iteration,
                "log": iterations_log,
            }

        iterations_log.append(f"iter {iteration}: tests echoues ({test_output[:80]})")
        findings = findings + [{
            "severity": "ERROR", "rule_id": "test_failure",
            "line": 0, "message": f"Tests echoues : {test_output[:400]}",
            "suggestions": ["Corrige sans casser les tests."],
        }]

    _restore_backup(file_info)
    return {
        "fixed": False,
        "reason": "aucune correction validee apres tests",
        "iterations": MAX_ITERATIONS,
        "log": iterations_log,
    }


def fix_all_files(workdir, findings):
    results = []
    findings_by_file = {}
    for f in findings:
        fpath = f.get("file", "")
        if not fpath:
            continue
        findings_by_file.setdefault(fpath, []).append(f)

    source_files = _read_source_files(workdir)
    for file_info in source_files:
        rel = file_info["path"]
        file_findings = findings_by_file.get(rel, [])
        if not file_findings:
            continue
        result = fix_file_with_validation(file_info, file_findings)
        result["file"] = rel
        result["findings_count"] = len(file_findings)
        results.append(result)

    return results


def generate_fix_summary(results):
    lines = []
    lines.append("=" * 70)
    lines.append("RAPPORT DE CORRECTION AUTOMATIQUE (IA)")
    lines.append("=" * 70)
    lines.append("")
    fixed_count = sum(1 for r in results if r.get("fixed"))
    total = len(results)
    lines.append(f"Fichiers analyses : {total}")
    lines.append(f"Fichiers corriges et valides : {fixed_count}")
    lines.append(f"Fichiers non corriges : {total - fixed_count}")
    lines.append("")

    for r in results:
        status = "CORRIGE" if r.get("fixed") else "ECHEC"
        lines.append(f"[{status}] {r.get('file', '?')}")
        lines.append(f"  Findings : {r.get('findings_count', 0)}")
        lines.append(f"  Iterations : {r.get('iterations', 0)}")
        lines.append(f"  Raison : {r.get('reason', '')}")
        for log_line in r.get("log", []):
            lines.append(f"    {log_line}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)

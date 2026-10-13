import os
import re
import shutil
import subprocess
import tempfile
import uuid

HYDRA_TIMEOUT = 600
HYDRA_MAX_FILE_SIZE = 10 * 1024 * 1024

ALLOWED_PROTOCOLS = {
    "ssh", "ftp", "ftps", "telnet", "http-get", "http-post",
    "http-get-form", "http-post-form", "https-get", "https-post",
    "smtp", "smtp-enum", "pop3", "imap", "mysql", "mssql",
    "postgres", "rdp", "vnc", "smb", "ldap2", "ldap3",
    "redis", "mongodb", "sftp", "cisco", "cisco-enable",
}

HOST_RE = re.compile(r"^[a-zA-Z0-9.\-]{1,253}$")
PORT_RE = re.compile(r"^[0-9]{1,5}$")
USER_RE = re.compile(r"^[a-zA-Z0-9._\-@]{1,64}$")
PROTOCOL_RE = re.compile(r"^[a-z0-9\-]{1,30}$")


class HydraError(Exception):
    pass


def find_hydra_binary():
    for candidate in ["/usr/bin/hydra", "/usr/local/bin/hydra"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("hydra")


def is_hydra_available():
    return find_hydra_binary() is not None


def _run(args, timeout=HYDRA_TIMEOUT):
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HydraError(f"Delai depasse ({timeout}s)") from exc
    except FileNotFoundError as exc:
        raise HydraError(f"Binaire introuvable : {args[0]}") from exc
    except PermissionError as exc:
        raise HydraError(f"Permission refusee : {args[0]}") from exc


def validate_target(host, port=None):
    if not host:
        raise HydraError("Cible vide")
    if not HOST_RE.match(host):
        raise HydraError("Cible invalide (nom ou IP uniquement)")
    if port is not None:
        if not PORT_RE.match(str(port)):
            raise HydraError("Port invalide (1-65535)")
        p = int(port)
        if p < 1 or p > 65535:
            raise HydraError("Port hors plage")
        return host, p
    return host, None


def validate_protocol(protocol):
    if not protocol:
        raise HydraError("Protocole vide")
    p = protocol.lower().strip()
    if not PROTOCOL_RE.match(p):
        raise HydraError("Protocole invalide (caracteres interdits)")
    if p not in ALLOWED_PROTOCOLS:
        allowed = ", ".join(sorted(ALLOWED_PROTOCOLS))
        raise HydraError(f"Protocole non autorise. Autorises : {allowed}")
    return p


def validate_username(username):
    if not username:
        raise HydraError("Nom d'utilisateur vide")
    if not USER_RE.match(username):
        raise HydraError("Nom d'utilisateur invalide (max 64, alphanumeriques ._-@)")
    return username


def hydra_attack(
    host,
    protocol,
    username=None,
    userlist=None,
    password=None,
    passlist=None,
    port=None,
    tasks=4,
    stop_on_first=True,
    extra_form=None,
):
    binary = find_hydra_binary()
    if not binary:
        raise HydraError("Hydra introuvable sur cet environnement")

    host, port = validate_target(host, port)
    protocol = validate_protocol(protocol)

    if not username and not userlist:
        raise HydraError("Fournis un username ou une userlist")
    if username:
        username = validate_username(username)
    if userlist and not os.path.isfile(userlist):
        raise HydraError(f"Userlist introuvable : {userlist}")
    if not password and not passlist:
        raise HydraError("Fournis un password ou une passlist")
    if passlist and not os.path.isfile(passlist):
        raise HydraError(f"Passlist introuvable : {passlist}")

    session_id = uuid.uuid4().hex[:12]
    workdir = tempfile.mkdtemp(prefix=f"hydra_{session_id}_")
    out_file = os.path.join(workdir, "results.txt")

    args = [binary, "-o", out_file, "-t", str(max(1, min(16, tasks))), "-I"]
    if stop_on_first:
        args.append("-f")

    if username:
        args.extend(["-l", username])
    elif userlist:
        args.extend(["-L", userlist])

    if password:
        args.extend(["-p", password])
    elif passlist:
        args.extend(["-P", passlist])

    if port:
        args.extend(["-s", str(port)])

    if protocol in ("http-get-form", "http-post-form", "https-get-form", "https-post-form"):
        if not extra_form:
            raise HydraError("Ce protocole necessite un parametre de formulaire")
        if len(extra_form) > 500:
            raise HydraError("Parametre de formulaire trop long (max 500)")
        args.append(extra_form)

    target = f"{protocol}://{host}"
    args.append(target)

    result = _run(args, timeout=HYDRA_TIMEOUT)

    found = []
    if os.path.isfile(out_file):
        with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "login:" in line and "password:" in line:
                    found.append(line)

    return {
        "session_id": session_id,
        "workdir": workdir,
        "out_file": out_file,
        "target": target,
        "protocol": protocol,
        "found": found,
        "stdout": (result.stdout or "")[-2500:],
        "stderr": (result.stderr or "")[-1500:],
        "returncode": result.returncode,
    }


def cleanup_workdir(workdir):
    if workdir and os.path.isdir(workdir):
        shutil.rmtree(workdir, ignore_errors=True)


def list_supported_protocols():
    return sorted(ALLOWED_PROTOCOLS)


def get_hydra_version():
    binary = find_hydra_binary()
    if not binary:
        return None
    result = _run([binary, "-h"], timeout=15)
    output = (result.stdout or "") + (result.stderr or "")
    for line in output.splitlines():
        if line.startswith("Hydra"):
            return line.strip()
    return "Version inconnue"

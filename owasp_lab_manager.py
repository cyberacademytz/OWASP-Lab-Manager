#!/usr/bin/env python3
"""
owasp_lab_manager.py - interactive manager for existing, intentionally vulnerable
OWASP training applications (Juice Shop, WebGoat/WebWolf, crAPI, Security Shepherd,
Mutillidae II) running in Docker.

Author: www.tca.ac.tz

FOR AUTHORIZED TRAINING USE ONLY. The applications deployed by this tool contain
deliberate vulnerabilities. Keep them on localhost / an isolated lab machine.

Design notes
  * Python standard library only. Docker CLI + Docker Compose are the deployment interface.
  * All subprocesses are executed with argument lists (never through a shell).
  * Everything the tool creates lives under $LAB_HOME (default ~/.owasp_lab) and every
    Docker resource it manages belongs to a Compose project named "owasplab-<app id>".
    Cleanup only ever touches those projects.
  * Application definitions live in catalog.json (+ optional $LAB_HOME/catalog.local.json).
  * Auto-fix (v1.2): when an install/start finds a missing prerequisite (Docker, Compose plugin, git,
    stopped Docker service, docker permission, busy default port, flaky image pull) the tool repairs it
    itself instead of stopping with an error. Disable with --no-auto-fix.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import logging
import logging.handlers
import os
import platform
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VERSION = "1.2.0"
SCRIPT_DIR = Path(__file__).resolve().parent
CATALOG_PATH = Path(os.environ.get("LAB_CATALOG", SCRIPT_DIR / "catalog.json"))
LAB_HOME = Path(os.environ.get("LAB_HOME", Path.home() / ".owasp_lab"))
APPS_DIR = LAB_HOME / "apps"
LOG_DIR = LAB_HOME / "logs"
LOG_FILE = LOG_DIR / "lab.log"
STATE_FILE = LAB_HOME / "state.json"
LOCAL_CATALOG = LAB_HOME / "catalog.local.json"
PROJECT_PREFIX = "owasplab-"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
SUPPORTED_METHODS = {"template-compose", "download-compose", "git-compose", "alias"}
TIER_LABELS = {
    "official-owasp": "OFFICIAL OWASP project",
    "community": "COMMUNITY / THIRD-PARTY (not an OWASP project)",
    "third-party": "COMMUNITY / THIRD-PARTY (not an OWASP project)",
}

# Built-in copies of the bundled compose templates. They are used automatically when the compose/ folder
# is not next to this script, so the script keeps working if only the .py and catalog.json were copied.
EMBEDDED_TEMPLATES: Dict[str, str] = {
    "compose/juice-shop.yml": '# Script-owned deployment template for OWASP Juice Shop.\n# Upstream reference: https://github.com/juice-shop/juice-shop (README -> "Docker Container":\n#   docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop)\n# Host binding is localhost-only by default (LAB_BIND). No privileged mode, no host mounts.\nservices:\n  juice-shop:\n    image: ${LAB_IMAGE_JUICE_SHOP:-bkimminich/juice-shop:latest}\n    container_name: owasplab-juice-shop\n    ports:\n      - "${LAB_BIND:-127.0.0.1}:${LAB_PORT_JUICE_SHOP:-3000}:3000"\n    security_opt:\n      - no-new-privileges:true\n    restart: "no"\n',
    "compose/webgoat.yml": '# Script-owned deployment template for OWASP WebGoat (+ WebWolf, bundled in the same image).\n# Upstream reference: https://github.com/WebGoat/WebGoat (README -> "Run using Docker":\n#   docker run -it -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat)\n# WebGoat serves on 8080 (/WebGoat) and WebWolf on 9090 (/WebWolf) inside the container.\nservices:\n  webgoat:\n    image: ${LAB_IMAGE_WEBGOAT:-webgoat/webgoat:latest}\n    container_name: owasplab-webgoat\n    ports:\n      - "${LAB_BIND:-127.0.0.1}:${LAB_PORT_WEBGOAT_HTTP:-8080}:8080"\n      - "${LAB_BIND:-127.0.0.1}:${LAB_PORT_WEBWOLF_HTTP:-9090}:9090"\n    environment:\n      - TZ=${LAB_TZ:-UTC}\n    security_opt:\n      - no-new-privileges:true\n    restart: "no"\n',
}

# --------------------------------------------------------------------------- #
# Terminal helpers
# --------------------------------------------------------------------------- #
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None and os.name != "nt"


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def ok(msg: str) -> None:
    print(_c("1;32", "[ OK ] ") + msg)


def warn(msg: str) -> None:
    print(_c("1;33", "[WARN] ") + msg)


def err(msg: str) -> None:
    print(_c("1;31", "[FAIL] ") + msg)


def info(msg: str) -> None:
    print(_c("1;36", "[INFO] ") + msg)


_ANSI_RE = re.compile(r"\033\[[0-9;]*m")
UNICODE = (getattr(sys.stdout, "encoding", "") or "").lower().startswith("utf")
AUTHOR = "www.tca.ac.tz"
SCREEN_CLEAR = sys.stdout.isatty()      # never clear when output is piped/redirected

LOGO_UNICODE = [
    " ██████╗ ██╗    ██╗ █████╗ ███████╗██████╗ ",
    "██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔══██╗",
    "██║   ██║██║ █╗ ██║███████║███████╗██████╔╝",
    "██║   ██║██║███╗██║██╔══██║╚════██║██╔═══╝ ",
    "╚██████╔╝╚███╔███╔╝██║  ██║███████║██║     ",
    " ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝     ",
]
LOGO_ASCII = ["  O W A S P  "]


def visible_len(text: str) -> int:
    return len(_ANSI_RE.sub("", text))


def term_width() -> int:
    return max(shutil.get_terminal_size((100, 24)).columns, 40)


def center(text: str, width: Optional[int] = None) -> str:
    width = width or term_width()
    return " " * max((width - visible_len(text)) // 2, 0) + text


def clear_screen() -> None:
    if SCREEN_CLEAR:
        print("\033[2J\033[3J\033[H", end="")


def banner(compact: bool = False) -> None:
    """Centered, coloured banner. The full version is used on menus, the compact one on action screens."""
    w = term_width()
    line = "═" if UNICODE else "="
    if compact or w < 50:
        print(center(_c("1;36", "OWASP VULNERABLE LAB MANAGER") + _c("2", f"  v{VERSION}"), w))
        print(center(_c("33", f"Author: {AUTHOR}"), w))
        print(_c("34", line * w))
        return
    print()
    for row in (LOGO_UNICODE if UNICODE else LOGO_ASCII):
        print(center(_c("1;36", row), w))
    print(center(_c("1;37", "V U L N E R A B L E   L A B   M A N A G E R"), w))
    print(center(_c("2", f"Version {VERSION}  |  Docker-based OWASP training lab automation"), w))
    print(center(_c("1;33", f"Author: {AUTHOR}"), w))
    print(center(_c("1;31", "FOR AUTHORIZED SECURITY TRAINING USE ONLY"), w))
    print(_c("34", line * w))


def header(title: str, clear: bool = True) -> None:
    """Start a new screen: clear, banner, centered section title."""
    w = term_width()
    if clear:
        clear_screen()
        banner(compact=True)
    line = "─" if UNICODE else "-"
    print()
    print(center(_c("1;30;46", f"  {title.upper()}  "), w))
    print(center(_c("34", line * min(len(title) + 8, w)), w))
    print()


def table(rows: List[List[str]], headers: List[str]) -> None:
    cols = [headers] + rows
    widths = [max(visible_len(str(r[i])) for r in cols) for i in range(len(headers))]
    total = sum(widths) + 2 * (len(widths) - 1)
    pad = " " * max((term_width() - total) // 2, 0)
    sep = "  "
    print(pad + _c("1;36", sep.join(str(h).ljust(widths[i]) for i, h in enumerate(headers))))
    print(pad + _c("34", sep.join(("─" if UNICODE else "-") * w for w in widths)))
    for r in rows:
        print(pad + sep.join(str(v).ljust(widths[i]) for i, v in enumerate(r)))


# --------------------------------------------------------------------------- #
# Structured logging (JSON lines)
# --------------------------------------------------------------------------- #
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        ctx = getattr(record, "ctx", None)
        if isinstance(ctx, dict):
            data.update(ctx)
        return json.dumps(data, ensure_ascii=False, default=str)


def setup_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("owasp_lab")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        handler = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    return logger


LOG = logging.getLogger("owasp_lab")


def log(level: int, event: str, **ctx: Any) -> None:
    LOG.log(level, event, extra={"ctx": ctx})


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
class App:
    """Thin wrapper around a catalog entry."""

    def __init__(self, data: Dict[str, Any]):
        self.d = data

    def __getattr__(self, item: str) -> Any:  # convenient dict access
        try:
            return self.d[item]
        except KeyError:
            raise AttributeError(item) from None

    def __getitem__(self, item: str) -> Any:
        return self.d[item]

    def get(self, key: str, default: Any = None) -> Any:
        return self.d.get(key, default)

    @property
    def project(self) -> str:
        return PROJECT_PREFIX + self.d["id"]

    @property
    def dir(self) -> Path:
        return APPS_DIR / self.d["id"]

    @property
    def compose_file(self) -> Path:
        if self.d["method"] == "git-compose":
            return self.dir / "repo" / self.d["compose_file"]
        return self.dir / "docker-compose.yml"

    @property
    def tier_label(self) -> str:
        return TIER_LABELS.get(self.d.get("tier", "community"), TIER_LABELS["community"])

    @property
    def is_alias(self) -> bool:
        return self.d["method"] == "alias"


def validate_app(d: Dict[str, Any]) -> List[str]:
    errs: List[str] = []
    for key in ("id", "name", "method"):
        if key not in d:
            errs.append(f"missing '{key}'")
    if errs:
        return errs
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", d["id"]):
        errs.append("id must match [a-z0-9-]+")
    m = d["method"]
    if m not in SUPPORTED_METHODS:
        errs.append(f"unsupported method '{m}'")
    elif m == "template-compose" and "compose_template" not in d:
        errs.append("template-compose needs 'compose_template'")
    elif m == "download-compose" and not str(d.get("compose_url", "")).startswith("https://"):
        errs.append("download-compose needs an https 'compose_url'")
    elif m == "git-compose":
        if not str(d.get("git_url", "")).startswith("https://"):
            errs.append("git-compose needs an https 'git_url'")
        if "compose_file" not in d:
            errs.append("git-compose needs 'compose_file'")
        if Path(str(d.get("compose_file", ""))).is_absolute() or ".." in Path(str(d.get("compose_file", ""))).parts:
            errs.append("'compose_file' must be a relative path inside the repo")
    elif m == "alias" and "alias_of" not in d:
        errs.append("alias needs 'alias_of'")
    for p in d.get("ports", []):
        if not isinstance(p.get("default"), int) or not (1 <= p["default"] <= 65535):
            errs.append(f"invalid port entry {p}")
    return errs


def load_catalog() -> Tuple[List[App], List[str]]:
    problems: List[str] = []
    entries: List[Dict[str, Any]] = []
    for path in (CATALOG_PATH, LOCAL_CATALOG):
        if not path.exists():
            if path == CATALOG_PATH:
                raise SystemExit(f"Catalog not found: {path}")
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            if path == CATALOG_PATH:
                raise SystemExit(f"Cannot read catalog {path}: {exc}")
            problems.append(f"{path}: {exc}")
            continue
        for e in data.get("apps", []):
            if path == LOCAL_CATALOG:
                e.setdefault("tier", "community")
            entries.append(e)
    apps: Dict[str, App] = {}
    for e in entries:
        errs = validate_app(e)
        if errs:
            problems.append(f"catalog entry {e.get('id', '?')}: " + "; ".join(errs))
            continue
        apps[e["id"]] = App(e)  # later entries (local) override earlier ones
    for a in list(apps.values()):
        if a.is_alias and a.alias_of not in apps:
            problems.append(f"alias {a.id} points to unknown app {a.alias_of}")
            del apps[a.id]
    return list(apps.values()), problems


# --------------------------------------------------------------------------- #
# State (JSON, atomic writes)
# --------------------------------------------------------------------------- #
class State:
    def __init__(self) -> None:
        self.data: Dict[str, Any] = {"bind": "127.0.0.1", "selected": [], "apps": {}, "acknowledged": False}
        if STATE_FILE.exists():
            try:
                self.data.update(json.loads(STATE_FILE.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                warn(f"State file {STATE_FILE} is unreadable; starting with defaults (file kept as .corrupt).")
                try:
                    STATE_FILE.rename(STATE_FILE.with_suffix(".corrupt"))
                except OSError:
                    pass

    def save(self) -> None:
        LAB_HOME.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        os.replace(tmp, STATE_FILE)

    def app(self, app_id: str) -> Dict[str, Any]:
        return self.data["apps"].setdefault(app_id, {})


@dataclass
class Result:
    rc: int
    out: str = ""
    err: str = ""
    skipped: bool = False


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------------------- #
# HTTP / port helpers (localhost only)
# --------------------------------------------------------------------------- #
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):  # noqa: D401
        return None


def http_probe(url: str, timeout: float = 5.0) -> Tuple[bool, str]:
    """Return (responding, detail). Any HTTP status < 500 counts as 'responding'."""
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname not in LOOPBACK:
        return False, "refused: probes are restricted to localhost"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # lab apps use self-signed certs on localhost only
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(urllib.request.Request(url, method="GET"), timeout=timeout) as r:
            return True, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return (e.code < 500), f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def port_in_use(host: str, port: int) -> bool:
    """True if something already accepts connections or blocks binding on host:port."""
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "", "localhost") else host
    if tcp_open(probe_host, port, 1.0):
        return True
    if port < 1024 and hasattr(os, "geteuid") and os.geteuid() != 0:
        return False  # cannot bind-test privileged ports; Docker daemon (root) will bind it
    fam = socket.AF_INET6 if ":" in probe_host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    try:
        s.bind((probe_host, port))
        return False
    except OSError:
        return True
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# The lab manager
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.dry = args.dry_run
        self.assume_yes = args.yes
        self.apps, self.catalog_problems = load_catalog()
        self.by_id = {a.id: a for a in self.apps}
        self.state = State()
        if args.bind:
            self.state.data["bind"] = args.bind
        self.compose: Optional[List[str]] = None
        self.compose_is_v1 = False
        self.use_sudo = False          # set when docker needs elevated rights (we never touch the docker group)
        self._detect_compose()

    # ------------------------------------------------------------- basics ---
    @property
    def real_apps(self) -> List[App]:
        return [a for a in self.apps if not a.is_alias]

    def resolve(self, app: App) -> App:
        return self.by_id[app.alias_of] if app.is_alias else app

    @property
    def bind(self) -> str:
        return self.state.data.get("bind", "127.0.0.1")

    @property
    def browse_host(self) -> str:
        return "127.0.0.1" if self.bind in ("0.0.0.0", "", "localhost") else self.bind

    def run(self, cmd: List[str], *, env: Optional[Dict[str, str]] = None, cwd: Optional[Path] = None,
            timeout: Optional[int] = 120, stream: bool = False, mutating: bool = False) -> Result:
        """Run a command WITHOUT a shell. Mutating commands are skipped in dry-run mode."""
        if self.use_sudo and cmd and cmd[0] in ("docker", "docker-compose"):
            cmd = ["sudo", "env"] + [f"{k}={v}" for k, v in (env or {}).items()] + list(cmd)
            env = None
        shown = shlex.join(cmd)
        if self.dry and mutating:
            print(_c("35", "[dry-run] $ ") + shown)
            log(logging.INFO, "dry-run command", cmd=shown)
            return Result(0, skipped=True)
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        log(logging.DEBUG, "exec", cmd=shown, cwd=str(cwd) if cwd else None)
        try:
            if stream:
                cp = subprocess.run(cmd, env=full_env, cwd=cwd, check=False)
                log(logging.INFO, "exec finished", cmd=shown, rc=cp.returncode)
                return Result(cp.returncode)
            cp = subprocess.run(cmd, env=full_env, cwd=cwd, capture_output=True, text=True,
                                timeout=timeout, check=False)
            log(logging.DEBUG, "exec finished", cmd=shown, rc=cp.returncode,
                stderr=cp.stderr[-800:] if cp.stderr else "")
            return Result(cp.returncode, cp.stdout or "", cp.stderr or "")
        except FileNotFoundError:
            return Result(127, "", f"command not found: {cmd[0]}")
        except subprocess.TimeoutExpired:
            log(logging.ERROR, "exec timeout", cmd=shown)
            return Result(124, "", f"timed out after {timeout}s")

    def docker(self, *args: str, **kw: Any) -> Result:
        r = self.run(["docker", *args], **kw)
        if r.rc != 0 and "permission denied" in r.err.lower():
            warn("Docker reported 'permission denied'. Either run this script with sudo, or add your user to the "
                 "'docker' group (note: that group is root-equivalent) and log in again.")
        return r

    def _detect_compose(self) -> None:
        if shutil.which("docker"):
            r = self.run(["docker", "compose", "version"], timeout=15)
            if r.rc == 0:
                self.compose = ["docker", "compose"]
                return
        if shutil.which("docker-compose"):
            self.compose = ["docker-compose"]
            self.compose_is_v1 = True

    def confirm(self, question: str, default: bool = False, optional_destructive: bool = False) -> bool:
        """--yes auto-confirms normal prompts, but never optional data/image/file deletion (auto-no)."""
        if self.assume_yes:
            if optional_destructive:
                print(f"{question} [auto-no under --yes]")
                return False
            print(f"{question} [auto-yes]")
            return True
        suffix = "[y/N]" if not default else "[Y/n]"
        ans = self.ask(f"{question} {suffix} ").strip().lower()
        if not ans:
            return default
        return ans in ("y", "yes")

    def ask(self, prompt: str) -> str:
        try:
            return input(prompt)
        except EOFError:
            raise KeyboardInterrupt from None

    def pause(self) -> None:
        if not self.args.run and not self.assume_yes:
            self.ask("\n" + center(_c("2", "Press Enter to continue...")) + " ")

    # ---------------------------------------------------- environment info ---
    def os_info(self) -> Dict[str, str]:
        system = platform.system()
        machine = platform.machine().lower()
        arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)
        distro = distro_id = like = ""
        wsl = False
        if system == "Linux":
            try:
                kv = dict(l.strip().split("=", 1) for l in Path("/etc/os-release").read_text().splitlines()
                          if "=" in l)
                distro = kv.get("PRETTY_NAME", "").strip('"')
                distro_id = kv.get("ID", "").strip('"')
                like = kv.get("ID_LIKE", "").strip('"')
            except OSError:
                pass
            try:
                wsl = "microsoft" in Path("/proc/version").read_text().lower()
            except OSError:
                pass
        return {"system": system, "arch": arch, "distro": distro, "distro_id": distro_id,
                "like": like, "wsl": str(wsl), "release": platform.release()}

    def docker_versions(self) -> Tuple[Optional[str], Optional[str], str]:
        """(server_version, compose_version, error)"""
        if not shutil.which("docker"):
            return None, None, "docker CLI not found"
        r = self.run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=20)
        server = r.out.strip() if r.rc == 0 and r.out.strip() else None
        errtxt = "" if server else (r.err.strip().splitlines()[-1] if r.err.strip() else "daemon not reachable")
        comp = None
        if self.compose:
            rc = self.run(self.compose + ["version", "--short"], timeout=20)
            comp = rc.out.strip() if rc.rc == 0 else None
        return server, comp, errtxt

    def require_docker(self) -> bool:
        server, comp, e = self.docker_versions()
        if self.dry and not (server and self.compose):
            if not getattr(self, "_dry_warned", False):
                warn(f"Docker/Compose not usable here ({e or 'compose missing'}); dry-run continues with catalog data only.")
                self._dry_warned = True
            if not self.compose:
                self.compose = ["docker", "compose"]
            return True
        if not server:
            err(f"Docker is not usable: {e}. Use 'Environment & Docker > Install and Verify Docker'.")
            return False
        if not self.compose:
            err("Docker Compose not found (need the 'docker compose' plugin). Use 'Environment & Docker > Install and Verify Docker'.")
            return False
        return True

    # ------------------------------------------------ auto-fix prerequisites ---
    def _is_root(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def _sudo(self) -> Optional[List[str]]:
        """[] when already root, ['sudo'] when sudo exists, None when neither is possible."""
        if self._is_root():
            return []
        return ["sudo"] if shutil.which("sudo") else None

    def _sys_run(self, cmd: List[str]) -> bool:
        """Run a system-modifying command, streaming its output. Prints it first; skipped in --dry-run."""
        info("Running: " + shlex.join(cmd))
        r = self.run(cmd, stream=True, mutating=True, timeout=None)
        if r.rc != 0:
            err(f"Command failed (rc={r.rc}): {shlex.join(cmd)}")
            return False
        return True

    def _apt_has(self, pkg: str) -> bool:
        r = self.run(["apt-cache", "policy", pkg], timeout=30)
        m = re.search(r"Candidate:\s*(\S+)", r.out)
        return bool(m and m.group(1) != "(none)")

    def _apt_install(self, want_docker: bool, want_compose: bool, want_git: bool) -> bool:
        sudo = self._sudo()
        if sudo is None:
            err("Root rights are needed to install packages but 'sudo' is not available. Re-run this script as root.")
            return False
        env = ["env", "DEBIAN_FRONTEND=noninteractive"]
        if not self._sys_run(sudo + env + ["apt-get", "update"]):
            warn("'apt-get update' failed; trying with the existing package lists.")
        pkgs: List[str] = []
        if want_docker:
            if not self.dry and not self._apt_has("docker.io"):
                err("Package 'docker.io' is not in your apt sources. Add Docker's official repository: "
                    "https://docs.docker.com/engine/install/")
                return False
            pkgs.append("docker.io")
        if want_compose:
            for cp in ("docker-compose-v2", "docker-compose-plugin", "docker-compose"):
                if self.dry or self._apt_has(cp):
                    pkgs.append(cp)
                    break
            else:
                warn("No Docker Compose package found in apt; installing the rest.")
        if want_git:
            pkgs.append("git")
        if not pkgs:
            return False
        return self._sys_run(sudo + env + ["apt-get", "install", "-y", *pkgs])

    def _start_docker_service(self) -> None:
        osi = self.os_info()
        if osi["system"] == "Darwin":
            self.run(["open", "-a", "Docker"], mutating=True)
            return
        sudo = self._sudo()
        if sudo is None:
            return
        if shutil.which("systemctl") and Path("/run/systemd/system").exists():
            self._sys_run(sudo + ["systemctl", "enable", "--now", "docker"])
        elif shutil.which("service"):
            self._sys_run(sudo + ["service", "docker", "start"])

    def _wait_for_daemon(self, timeout: int) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            server, _c, e = self.docker_versions()
            if server:
                return True
            if "permission denied" in e.lower() and not self.use_sudo and self._sudo() == ["sudo"]:
                info("Docker is running but your user may not use it; running docker through sudo in this session "
                     "(your account is NOT added to the docker group).")
                self.use_sudo = True
                self._detect_compose()
                continue
            time.sleep(3)
        return False

    def ensure_docker(self, ask: bool = False) -> bool:
        """Make Docker + Compose usable, fixing whatever is missing. True when ready (or when --dry-run)."""
        server, comp, e = self.docker_versions()
        if server and self.compose:
            return True
        osi = self.os_info()
        warn(f"Docker is not ready ({e or 'Docker Compose missing'}). Fixing it now...")
        # 1) installed but the user may not talk to the daemon
        if shutil.which("docker") and "permission denied" in e.lower() and self._sudo() == ["sudo"]:
            info("Docker needs elevated rights; running docker through sudo in this session "
                 "(your account is NOT added to the docker group).")
            self.use_sudo = True
            self._detect_compose()
            server, comp, e = self.docker_versions()
            if server and self.compose:
                ok(f"Docker {server} ready (via sudo).")
                return True
        # 2) install what is missing
        need_docker = not shutil.which("docker")
        need_compose = not self.compose
        if need_docker or need_compose:
            what = " and ".join(x for x, n in (("Docker", need_docker), ("Docker Compose", need_compose)) if n)
            if ask and not self.confirm(f"Install {what} now?", default=True):
                return False
            if osi["system"] == "Linux" and shutil.which("apt-get"):
                if not self._apt_install(need_docker, need_compose, False):
                    return False
            elif osi["system"] == "Darwin" and shutil.which("brew"):
                if need_docker and not self._sys_run(["brew", "install", "--cask", "docker"]):
                    return False
                if not need_docker and need_compose and not self._sys_run(["brew", "install", "docker-compose"]):
                    return False
            else:
                err("Automatic installation is not supported on this system. Install Docker manually: "
                    "https://docs.docker.com/engine/install/ (macOS needs Homebrew or Docker Desktop; "
                    "Windows needs WSL2 + Docker Desktop).")
                return False
            self._detect_compose()
        # 3) the daemon must be running
        server, comp, e = self.docker_versions()
        if not server:
            if ask and not self.confirm("Start the Docker service now?", default=True):
                return False
            info("Starting the Docker service...")
            self._start_docker_service()
            if self.dry:
                return True
            if not self._wait_for_daemon(120 if osi["system"] == "Darwin" else 45):
                err("Docker was installed but its daemon is not reachable. On macOS open Docker Desktop once and accept "
                    "its prompts, then re-run. On Linux check: systemctl status docker")
                return False
        self._detect_compose()
        server, comp, e = self.docker_versions()
        if server and self.compose:
            ok(f"Docker {server} is ready (Compose {comp or '?'}).")
            return True
        err(f"Docker is still not usable ({e or 'Compose plugin missing'}).")
        return False

    def ensure_git(self) -> bool:
        if shutil.which("git"):
            return True
        warn("git is missing (needed for this application). Installing it...")
        osi = self.os_info()
        if osi["system"] == "Linux" and shutil.which("apt-get"):
            self._apt_install(False, False, True)
        elif osi["system"] == "Darwin" and shutil.which("brew"):
            self._sys_run(["brew", "install", "git"])
        else:
            err("Install git manually, then re-run.")
            return False
        return self.dry or bool(shutil.which("git"))

    def ensure_prerequisites(self, app: App) -> bool:
        """Auto-fix everything an install/start needs, then confirm Docker is usable."""
        if getattr(self.args, "no_auto_fix", False):
            return self.require_docker()
        if not self.ensure_docker():
            return False
        if app.method == "git-compose" and not self.ensure_git():
            return False
        return self.require_docker()

    # ------------------------------------------------ app/env construction ---
    def app_state(self, app: App) -> Dict[str, Any]:
        return self.state.app(app.id)

    def port_value(self, app: App, p: Dict[str, Any]) -> int:
        if p.get("env"):
            ov = self.app_state(app).get("ports", {}).get(p["env"])
            if ov:
                return int(ov)
        return int(p["default"])

    def app_env(self, app: App) -> Dict[str, str]:
        env: Dict[str, str] = {"LAB_BIND": self.bind}
        for k, v in app.get("env_defaults", {}).items():
            if k not in os.environ:
                env[k] = v
        for k, v in app.get("env_static", {}).items():
            env[k] = v.replace("{bind}", self.bind)
        for p in app.get("ports", []):
            if p.get("env"):
                val = str(self.port_value(app, p))
                fmt = p.get("env_format")
                env[p["env"]] = fmt.format(bind=self.bind, value=val) if fmt else val
        return env

    def compose_args(self, app: App, *args: str) -> List[str]:
        assert self.compose
        cmd = self.compose + ["-p", app.project, "-f", str(app.compose_file)]
        cmd += list(app.get("compose_args", []))
        return cmd + list(args)

    def compose_run(self, app: App, *args: str, **kw: Any) -> Result:
        return self.run(self.compose_args(app, *args), env=self.app_env(app),
                        cwd=app.compose_file.parent if app.compose_file.exists() else None, **kw)

    # ---------------------------------------------------------- inspection ---
    def project_containers(self, app: App) -> List[Dict[str, Any]]:
        r = self.run(["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={app.project}"],
                     timeout=30)
        ids = r.out.split()
        if r.rc != 0 or not ids:
            return []
        ri = self.run(["docker", "inspect", *ids], timeout=60)
        try:
            return json.loads(ri.out) if ri.rc == 0 else []
        except json.JSONDecodeError:
            return []

    def app_status(self, app: App) -> str:
        if not shutil.which("docker"):
            return "unknown (docker missing)"
        cs = self.project_containers(app)
        tracked = bool(self.app_state(app).get("installed"))
        if not cs:
            return "installed (containers removed)" if tracked else "not installed"
        states = [c["State"]["Status"] for c in cs]
        unhealthy = any(c["State"].get("Health", {}).get("Status") == "unhealthy" for c in cs)
        if all(s == "running" for s in states):
            return "running (unhealthy)" if unhealthy else "running"
        if any(s == "running" for s in states):
            return "partially running"
        return "stopped"

    def published_ports(self, app: App) -> List[Dict[str, Any]]:
        out = []
        for c in self.project_containers(app):
            name = c["Name"].lstrip("/")
            for cport, binds in (c["NetworkSettings"].get("Ports") or {}).items():
                for b in binds or []:
                    out.append({"container": name, "container_port": cport, "host_ip": b.get("HostIp", ""),
                                "host_port": int(b["HostPort"])})
        return out

    def planned_ports(self, app: App) -> List[Dict[str, Any]]:
        """Ports we expect to publish. Prefer `compose config` (real file); fall back to catalog."""
        if app.compose_file.exists() and self.compose and not self.compose_is_v1:
            r = self.compose_run(app, "config", "--format", "json", timeout=60)
            if r.rc == 0:
                try:
                    cfg = json.loads(r.out)
                    ports = []
                    for svc, sd in (cfg.get("services") or {}).items():
                        for p in sd.get("ports") or []:
                            if p.get("published"):
                                ports.append({"service": svc, "host_ip": p.get("host_ip") or "0.0.0.0",
                                              "port": int(p["published"]), "target": p.get("target"),
                                              "proto": p.get("protocol", "tcp")})
                    if ports:
                        return ports
                except (json.JSONDecodeError, ValueError, TypeError):
                    pass
        return [{"service": p["name"], "host_ip": self.bind, "port": self.port_value(app, p),
                 "target": None, "proto": "tcp"} for p in app.get("ports", [])]

    def planned_container_names(self, app: App) -> List[str]:
        if app.compose_file.exists() and self.compose and not self.compose_is_v1:
            r = self.compose_run(app, "config", "--format", "json", timeout=60)
            if r.rc == 0:
                try:
                    cfg = json.loads(r.out)
                    return [sd["container_name"] for sd in (cfg.get("services") or {}).values()
                            if sd.get("container_name")]
                except (json.JSONDecodeError, TypeError):
                    pass
        return []

    # ------------------------------------------------------------ URL logic ---
    def url_for(self, app: App, p: Dict[str, Any], port: Optional[int] = None) -> Optional[str]:
        if p.get("internal_service") or not p.get("scheme"):
            return None
        port = port or self.port_value(app, p)
        default = {"http": 80, "https": 443}[p["scheme"]]
        hp = "" if port == default else f":{port}"
        return f"{p['scheme']}://{self.browse_host}{hp}{p.get('path', '/')}"

    # ------------------------------------------------------- app selection ---
    def pick_apps(self, prompt: str, allow_many: bool = False) -> List[App]:
        listing = self.real_apps
        if self.args.app:
            tokens = [t.strip() for t in self.args.app.split(",") if t.strip()]
        else:
            print()
            for i, a in enumerate(listing, 1):
                print(f"  {i}. {a.name}  [{self.app_status(a)}]")
            hint = "numbers/ids separated by commas, or 'all'" if allow_many else "number or id"
            raw = self.ask(f"{prompt} ({hint}; blank to cancel): ").strip()
            if not raw:
                return []
            tokens = [t.strip() for t in raw.split(",") if t.strip()]
        chosen: List[App] = []
        if tokens == ["all"] or tokens == ["ALL"]:
            return list(listing) if allow_many else []
        for t in tokens:
            app = None
            if t.isdigit() and 1 <= int(t) <= len(listing):
                app = listing[int(t) - 1]
            elif t in self.by_id:
                app = self.by_id[t]
            if app is None:
                err(f"Unknown application '{t}'.")
                return []
            if app.is_alias:
                info(f"{app.name} is deployed together with {self.by_id[app.alias_of].name}.")
                app = self.resolve(app)
            if app not in chosen:
                chosen.append(app)
        if len(chosen) > 1 and not allow_many:
            err("Please select only one application for this action.")
            return []
        return chosen

    def pick_one(self, prompt: str) -> Optional[App]:
        sel = self.pick_apps(prompt)
        return sel[0] if sel else None

    # ------------------------------------------------------- acknowledgment ---
    def ensure_acknowledged(self) -> bool:
        if self.state.data.get("acknowledged"):
            return True
        header("Security notice")
        print(
            "The applications managed by this tool are INTENTIONALLY VULNERABLE.\n"
            " * Run them only on a machine/network where you are authorized to practice.\n"
            " * Keep them bound to localhost (default). Never expose them to untrusted networks or the Internet.\n"
            " * Do not enter real credentials or personal data into them.\n"
            " * Only attack targets you own or have written permission to test.")
        if self.args.accept_risk:
            self.state.data["acknowledged"] = True
            self.state.save()
            return True
        if self.ask("Type I UNDERSTAND to continue: ").strip() != "I UNDERSTAND":
            warn("Not acknowledged; aborting.")
            return False
        self.state.data["acknowledged"] = True
        self.state.save()
        log(logging.INFO, "risk acknowledged")
        return True

    # ============================================================ MENU ACTIONS
    # 1 ------------------------------------------------------------------
    def check_requirements(self) -> None:
        header("System requirements")
        osi = self.os_info()
        rows = []
        rows.append(["Operating system", f"{osi['system']} {osi['release']} {osi['distro']}".strip()])
        rows.append(["Architecture", osi["arch"]])
        rows.append(["WSL2", "yes" if osi["wsl"] == "True" else "no"])
        rows.append(["Python", platform.python_version() + (" (OK)" if sys.version_info >= (3, 8) else " (need >= 3.8)")])
        server, comp, e = self.docker_versions()
        rows.append(["Docker CLI", shutil.which("docker") or "NOT FOUND"])
        rows.append(["Docker daemon", f"reachable, server {server}" if server else f"NOT reachable ({e})"])
        rows.append(["Docker Compose", f"{' '.join(self.compose)} {comp or ''}".strip() if self.compose else "NOT FOUND"])
        rows.append(["git", shutil.which("git") or "not found (needed for Security Shepherd, Mutillidae II)"])
        LAB_HOME.mkdir(parents=True, exist_ok=True)
        free = shutil.disk_usage(LAB_HOME).free / 1e9
        rows.append(["Free disk at LAB_HOME", f"{free:.1f} GB" + ("" if free >= 10 else "  (low: images can need several GB)")])
        mem = self._mem_gb()
        rows.append(["RAM (total)", f"{mem:.1f} GB" if mem else "unknown"])
        rows.append(["LAB_HOME", str(LAB_HOME)])
        rows.append(["Bind address", self.bind + ("" if self.bind in LOOPBACK else "   <-- NOT localhost-only!")])
        table(rows, ["Check", "Result"])
        print()
        if osi["system"] == "Windows":
            warn("Native Windows is not supported. Install WSL2 + Docker Desktop (WSL integration) and run this inside WSL.")
        elif osi["system"] == "Darwin":
            info("macOS: use Docker Desktop. Apple Silicon (arm64) runs amd64-only images under emulation, if at all.")
        elif osi["wsl"] == "True":
            info("WSL2 detected: Docker Desktop with WSL integration (or Docker Engine inside WSL) works; "
                 "browse to the localhost URLs from Windows.")
        elif osi["system"] == "Linux":
            if not any(x in (osi["distro_id"] + " " + osi["like"]) for x in ("kali", "ubuntu", "debian")):
                warn("Only Kali/Ubuntu/Debian are primary targets; other distros may work but are untested.")
        if self.compose_is_v1:
            warn("Legacy docker-compose (v1) detected. It is end-of-life; the Docker Compose v2 plugin is recommended.")
        print(_c("1", "\nPer-application compatibility:"))
        for a in self.real_apps:
            notes = []
            if a.get("method") == "git-compose" and not shutil.which("git"):
                notes.append("git missing")
            if a.get("min_ram_gb") and mem and mem < a["min_ram_gb"]:
                notes.append(f"RAM below suggested {a['min_ram_gb']} GB")
            print(f"  - {a.name}: {'; '.join(notes) if notes else 'no blocking issue found'}"
                  f"  (image architecture is checked at install time)")
        if not server or not self.compose:
            warn("Docker/Compose not ready - see 'Environment & Docker > Install and Verify Docker'.")

    @staticmethod
    def _mem_gb() -> Optional[float]:
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / 1024 / 1024
        except OSError:
            pass
        return None

    # 2 ------------------------------------------------------------------
    def install_docker(self) -> None:
        header("Install and verify Docker")
        if self.ensure_docker(ask=True):
            if not self.dry and self.confirm("Run 'docker run --rm hello-world' to verify end-to-end (pulls a tiny image)?"):
                r = self.docker("run", "--rm", "hello-world", stream=True, mutating=True)
                (ok if r.rc == 0 else err)("hello-world " + ("succeeded." if r.rc == 0 else "failed."))
        else:
            warn("Docker still not ready. Official instructions: https://docs.docker.com/engine/install/  |  "
                 "https://docs.docker.com/desktop/")

    # 3 ------------------------------------------------------------------
    def list_catalog(self) -> None:
        header("Available vulnerable applications")
        for p in self.catalog_problems:
            warn(p)
        for i, a in enumerate(self.apps, 1):
            print(_c("1", f"\n{i}. {a.name}") + f"   [{a.tier_label}]")
            print(f"   {a.get('description', '')}")
            if a.is_alias:
                print(f"   Deployment : bundled with {self.by_id[a.alias_of].name}")
                print(f"   Docs       : {a.get('docs', '-')}")
                continue
            print(f"   Method     : {a.method}")
            if a.get("packaging"):
                print(f"   Packaging  : {a.packaging}")
            print(f"   Docs       : {a.get('docs', '-')}")
            print(f"   Repository : {a.get('repo', '-')}")
            print(f"   Prereqs    : {'; '.join(a.get('prerequisites', [])) or '-'}")
            ports = ", ".join(f"{p['name']}={self.port_value(a, p)}{' (fixed)' if p.get('fixed') else ''}"
                              for p in a.get("ports", []))
            print(f"   Ports      : {ports}")
            print(f"   Status     : {self.app_status(a)}")
            for n in a.get("notes", []):
                print(f"   Note       : {n}")
            if a.get("verification"):
                print(_c("2", f"   Verified   : {a.verification}"))
        print("\n" + "\n".join(self.catalog_extra()))

    def catalog_extra(self) -> List[str]:
        try:
            raw = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
            return [_c("2", "Not included: " + c) for c in raw.get("unverified_candidates", [])]
        except (OSError, json.JSONDecodeError):
            return []

    # ----------------------------------------------------- pre-flight checks ---
    def preflight(self, app: App, *, for_install: bool) -> bool:
        """Return True when it's safe to proceed. Prints findings."""
        good = True
        if not self.require_docker():
            return False
        if app.method == "git-compose" and not shutil.which("git"):
            err("git is required for this application. Install it (e.g. 'sudo apt install git').")
            good = False
        osi = self.os_info()
        mem = self._mem_gb()
        if app.get("min_ram_gb") and mem and mem < app.min_ram_gb:
            warn(f"System RAM {mem:.1f} GB is below the suggested {app.min_ram_gb} GB (rule-of-thumb, not an upstream requirement).")
        if self.bind not in LOOPBACK:
            warn(f"Bind address is {self.bind}: the vulnerable services will be reachable from other machines!")
        # image architecture probe (best effort)
        for img in app.get("probe_images", [])[:2]:
            key = "LAB_IMAGE_" + app.id.upper().replace("-", "_")
            image = os.environ.get(key, img)
            archs = self.image_archs(image)
            if archs is None:
                info(f"Could not determine architectures of {image} (offline or manifest unavailable); continuing.")
            elif osi["arch"] not in archs:
                warn(f"{image} lists architectures {sorted(archs)} but this host is {osi['arch']}; "
                     "it may fail or run under emulation.")
            else:
                ok(f"{image} provides {osi['arch']}.")
        # port + name conflicts (ignore what our own running containers already hold)
        conflicts = self._port_conflicts(app)
        if conflicts and not getattr(self.args, "no_auto_fix", False) and self._auto_move_ports(app, conflicts):
            conflicts = self._port_conflicts(app)
        if conflicts:
            good = False
            for p in conflicts:
                err(f"Port {p['port']}/{p['proto']} ({p['service']}) is already in use on {p['host_ip']}.")
            movable = [x for x in app.get("ports", []) if x.get("env") and not x.get("fixed")]
            if movable:
                info("You can choose another host port with 'Environment & Docker > Check / Change Ports'.")
            else:
                info("This application's ports are fixed by upstream. Stop whatever uses them "
                     "('Monitor & Diagnose > List Running Containers' shows lab containers) and retry.")
        mine = {c["Name"].lstrip("/") for c in self.project_containers(app)}
        existing = self.run(["docker", "ps", "-a", "--format", "{{.Names}}"], timeout=30).out.split()
        for name in self.planned_container_names(app):
            if name in existing and name not in mine:
                err(f"A container named '{name}' already exists and is not managed by this tool. "
                    "Remove/rename it yourself; this tool will not touch it.")
                good = False
        for p in self.planned_ports(app):
            if p["host_ip"] in ("0.0.0.0", "::", "") and self.bind in LOOPBACK:
                warn(f"Port {p['port']} would be published on ALL interfaces by the compose file.")
        return good

    def _port_conflicts(self, app: App) -> List[Dict[str, Any]]:
        own = {p["host_port"] for p in self.published_ports(app)}
        return [p for p in self.planned_ports(app)
                if p["port"] not in own and port_in_use(p["host_ip"], p["port"])]

    def _auto_move_ports(self, app: App, conflicts: List[Dict[str, Any]]) -> bool:
        """Move busy, movable host ports to the next free one. Fixed upstream ports are left for the user."""
        moved = False
        taken = {p["port"] for p in self.planned_ports(app)}
        for c in conflicts:
            cat = next((x for x in app.get("ports", [])
                        if x.get("env") and not x.get("fixed") and self.port_value(app, x) == c["port"]), None)
            if not cat:
                continue
            new = next((n for n in range(c["port"] + 1, c["port"] + 200)
                        if n not in taken and not port_in_use(c["host_ip"], n)), None)
            if new is None:
                continue
            self.app_state(app).setdefault("ports", {})[cat["env"]] = new
            taken.add(new)
            moved = True
            warn(f"Port {c['port']} is busy; '{cat['name']}' will use host port {new} instead.")
        if moved and not self.dry:
            self.state.save()
        return moved

    def image_archs(self, image: str) -> Optional[set]:
        r = self.run(["docker", "manifest", "inspect", image], timeout=40)
        if r.rc != 0:
            return None
        try:
            data = json.loads(r.out)
        except json.JSONDecodeError:
            return None
        manifests = data.get("manifests") if isinstance(data, dict) else data
        if manifests is None:
            return None
        archs = set()
        for m in manifests if isinstance(manifests, list) else []:
            plat = m.get("platform") or {}
            if plat.get("architecture") and plat["architecture"] != "unknown":
                archs.add(plat["architecture"])
        return archs or None

    # ------------------------------------------------------ file provisioning ---
    def write_managed_file(self, app: App, dst: Path, content: bytes) -> bool:
        """Write dst without clobbering user edits. Returns False if the existing file was kept."""
        new_hash = sha256_bytes(content)
        rec = self.app_state(app).setdefault("files", {})
        if dst.exists():
            cur = sha256_bytes(dst.read_bytes())
            if cur == new_hash:
                info(f"{dst} is up to date.")
                rec[str(dst)] = cur
                return True
            if rec.get(str(dst)) != cur:
                warn(f"{dst} was modified outside this tool.")
                if not self.confirm("Replace it with the upstream version? (a .bak copy is kept)"):
                    info("Keeping your version.")
                    return False
                if not self.dry:
                    shutil.copy2(dst, dst.with_suffix(dst.suffix + ".bak"))
        if self.dry:
            print(_c("35", "[dry-run] would write ") + str(dst))
            return True
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.with_suffix(dst.suffix + ".tmp")
        tmp.write_bytes(content)
        os.replace(tmp, dst)
        rec[str(dst)] = new_hash
        return True

    def fetch_url(self, app: App, url: str) -> Optional[bytes]:
        p = urllib.parse.urlparse(url)
        allowed = app.get("allowed_download_hosts") or [p.hostname]
        if p.scheme != "https" or p.hostname not in allowed:
            err(f"Refusing to download from {url} (https and host allow-list required).")
            return None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": f"owasp-lab-manager/{VERSION}"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read(2_000_000)
        except Exception as exc:  # noqa: BLE001
            err(f"Download failed: {exc}")
            return None
        if b"services:" not in data:
            err("Downloaded file does not look like a Compose file; aborting.")
            return None
        return data

    def provision(self, app: App) -> bool:
        """Create/refresh the files needed to deploy. Never overwrites user changes silently."""
        m = app.method
        if m == "template-compose":
            src = SCRIPT_DIR / app.compose_template
            if src.exists():
                content = src.read_bytes()
            elif app.compose_template in EMBEDDED_TEMPLATES:
                info(f"{src} not found; using the template built into the script.")
                content = EMBEDDED_TEMPLATES[app.compose_template].encode("utf-8")
            else:
                err(f"Template missing: {src}. Copy the 'compose' folder from the project next to this script.")
                return False
            return self.write_managed_file(app, app.compose_file, content) or app.compose_file.exists()
        if m == "download-compose":
            if self.dry:
                print(_c("35", "[dry-run] would download ") + app.compose_url)
                print(_c("35", "[dry-run] would write ") + str(app.compose_file))
                return True
            data = self.fetch_url(app, app.compose_url)
            if data is None:
                return app.compose_file.exists()
            self.write_managed_file(app, app.compose_file, data)
            return app.compose_file.exists()
        if m == "git-compose":
            repo = app.dir / "repo"
            if repo.exists():
                info(f"Repository already present at {repo} (kept as is; use 'Update Images').")
                return app.compose_file.exists()
            cmd = ["git", "clone", "--depth", "1", "--branch", app.get("git_ref", "main"), app.git_url, str(repo)]
            if not self.dry:
                app.dir.mkdir(parents=True, exist_ok=True)
            r = self.run(cmd, stream=True, mutating=True, timeout=None)
            if r.rc != 0:
                err("git clone failed. Check your network connection and that the URL/branch in the catalog is valid.")
                return False
            if not self.dry:
                head = self.run(["git", "-C", str(repo), "rev-parse", "HEAD"]).out.strip()
                self.app_state(app)["git_commit"] = head
                if not app.compose_file.exists():
                    err(f"Compose file {app.compose_file} not found in the cloned repository.")
                    return False
            return True
        return False

    # ----------------------------------------------------------- installation ---
    def show_plan(self, app: App) -> None:
        header(f"Deployment plan: {app.name}", clear=False)
        print(f"Method           : {app.method}")
        print(f"Compose project  : {app.project}  (all resources are namespaced to this project)")
        print(f"Files            : {app.compose_file}")
        if app.method == "git-compose":
            print(f"Source           : {app.git_url} @ {app.get('git_ref', 'main')} (shallow clone)")
        if app.method == "download-compose":
            print(f"Source           : {app.compose_url}")
        print(f"Bind address     : {self.bind}")
        for p in app.get("ports", []):
            suffix = "" if p.get("env") and not p.get("fixed") else " (fixed by upstream)"
            print(f"  port {self.port_value(app, p):<6} {p['name']}{suffix}")
        print("Actions          : provision files -> pull images -> start containers -> verify HTTP")
        print("Isolation        : dedicated compose network; no privileged mode; no host mounts; no docker.sock")
        print("Existing data    : nothing is deleted; existing containers/volumes of this project are reused")

    def install_app(self, app: App, start_after: bool = True) -> bool:
        app = self.resolve(app)
        if not self.ensure_acknowledged():
            return False
        status = self.app_status(app)
        if status == "running":
            ok(f"{app.name} is already running - nothing to do.")
            self.print_urls(app)
            return True
        self.show_plan(app)
        if not self.ensure_prerequisites(app):
            return False
        if not self.confirm("Proceed with this deployment?", default=True):
            info("Cancelled.")
            return False
        # Provision first so pre-flight can read the real compose file for ports/names.
        if not self.provision(app):
            err("Could not prepare deployment files.")
            return False
        if not self.preflight(app, for_install=True):
            err("Pre-flight checks failed; nothing was started.")
            return False
        if not self.pull_images(app):
            return False
        st = self.app_state(app)
        st["installed"] = True
        st.setdefault("installed_at", time.strftime("%Y-%m-%d %H:%M:%S"))
        self.state.save() if not self.dry else None
        if start_after:
            return self.start_app(app, skip_checks=True)
        return True

    def pull_images(self, app: App) -> bool:
        info("Pulling images (this can take a while)...")
        r = self.compose_run(app, "pull", stream=True, mutating=True, timeout=None)
        attempt = 1
        while r.rc != 0 and not self.dry and attempt < 3 and not getattr(self.args, "no_auto_fix", False):
            wait = 5 * attempt
            warn(f"Image pull failed (attempt {attempt}/3). Retrying in {wait}s (network or registry hiccup?)...")
            time.sleep(wait)
            attempt += 1
            r = self.compose_run(app, "pull", stream=True, mutating=True, timeout=None)
        if r.rc == 0:
            if not self.dry:
                self.record_digests(app)
            return True
        if app.get("build_fallback") and self.confirm(
                "Pull failed. Build the images from upstream sources instead (slow, needs network)?"):
            app.d["_force_build"] = True
            return True
        err("Image pull failed. Common causes: no network/registry rate limit (try 'docker login'), image removed upstream, "
            f"or unsupported CPU architecture. See 'Monitor & Diagnose > Troubleshooting Log' for logs and {app.get('repo', 'the project docs')}.")
        return False

    def record_digests(self, app: App) -> None:
        r = self.compose_run(app, "config", "--images", timeout=60)
        digests = {}
        for img in r.out.split():
            ri = self.run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", img], timeout=30)
            if ri.rc == 0:
                try:
                    digests[img] = json.loads(ri.out.strip() or "[]")
                except json.JSONDecodeError:
                    pass
        if digests:
            self.app_state(app)["images"] = digests
            self.state.save()

    def start_app(self, app: App, skip_checks: bool = False) -> bool:
        app = self.resolve(app)
        if not self.ensure_acknowledged():
            return False
        if not (self.require_docker() if skip_checks else self.ensure_prerequisites(app)):
            return False
        if not self.app_state(app).get("installed") and not app.compose_file.exists():
            if self.confirm(f"{app.name} is not installed. Install it now?", default=True):
                return self.install_app(app)
            return False
        if self.app_status(app) == "running":
            ok(f"{app.name} is already running.")
            self.print_urls(app)
            return True
        if not skip_checks and not self.preflight(app, for_install=False):
            err("Pre-flight checks failed; not starting.")
            return False
        up = ["up", "-d"] + list(app.get("up_args", []))
        if app.d.pop("_force_build", False):
            up = ["up", "-d", "--build"]
        info(f"Starting {app.name}...")
        r = self.compose_run(app, *up, stream=True, mutating=True, timeout=None)
        if r.rc != 0:
            self.explain_failure(app)
            return False
        if self.dry:
            return True
        self.app_state(app)["installed"] = True
        self.state.save()
        return self.wait_ready(app)

    def explain_failure(self, app: App) -> None:
        err(f"'compose up' failed for {app.name}.")
        print("  Next steps:\n"
              "   - Monitor & Diagnose > View Container Logs for this app.\n"
              "   - Environment & Docker > Check / Change Ports to look for conflicts.\n"
              "   - Monitor & Diagnose > Troubleshooting Log shows the script's commands and results.\n"
              f"   - Check upstream docs: {app.get('docs', '')}")

    def wait_ready(self, app: App) -> bool:
        timeout = int(app.get("startup_timeout", 180))
        primary = next((p for p in app.get("ports", []) if p.get("primary")), None)
        url = self.url_for(app, primary) if primary else None
        info(f"Waiting up to {timeout}s for containers and {url or 'services'} ...")
        start = time.time()
        last = ""
        while time.time() - start < timeout:
            cs = self.project_containers(app)
            bad = [c["Name"].lstrip("/") for c in cs
                   if c["State"]["Status"] in ("dead",) or
                   (c["State"]["Status"] == "exited" and c["State"].get("ExitCode", 0) != 0)]
            if bad:
                err(f"Container(s) failed: {', '.join(bad)}")
                self.explain_failure(app)
                return False
            running = cs and all(c["State"]["Status"] == "running" or
                                 (c["State"]["Status"] == "exited" and c["State"].get("ExitCode") == 0) for c in cs)
            if running and url:
                good, detail = http_probe(url.replace(self.browse_host, "127.0.0.1"))
                last = detail
                if good:
                    ok(f"{app.name} is up ({detail}) after {int(time.time() - start)}s.")
                    self.print_urls(app)
                    return True
            elif running and not url:
                ok("Containers are running.")
                return True
            time.sleep(3)
        err(f"Timed out after {timeout}s (last probe: {last or 'no response'}). Containers may still be starting - "
            "check Monitor & Diagnose > Container Health / Logs in a minute.")
        return False

    # 4 ------------------------------------------------------------------
    def install_selected(self) -> None:
        header("Install all selected applications")
        sel_ids = self.state.data.get("selected", [])
        if self.args.app:
            chosen = self.pick_apps("Applications", allow_many=True)
        else:
            if sel_ids:
                print("Currently selected: " + ", ".join(sel_ids))
            if not sel_ids or self.confirm("Change the selection?"):
                chosen = self.pick_apps("Select applications to install", allow_many=True)
                if chosen:
                    self.state.data["selected"] = [a.id for a in chosen]
                    self.state.save() if not self.dry else None
            else:
                chosen = [self.by_id[i] for i in sel_ids if i in self.by_id]
        if not chosen:
            info("Nothing selected.")
            return
        seen: Dict[int, str] = {}
        for a in chosen:
            for p in a.get("ports", []):
                port = self.port_value(a, p)
                if port in seen and seen[port] != a.id:
                    warn(f"Port {port} is used by both {seen[port]} and {a.id}; they cannot run at the same time.")
                seen.setdefault(port, a.id)
        results = []
        for a in chosen:
            try:
                results.append((a.name, self.install_app(a)))
            except KeyboardInterrupt:
                warn(f"Interrupted during {a.name}. Re-running is safe (idempotent).")
                results.append((a.name, False))
                break
        print()
        table([[n, "OK" if r else "FAILED / skipped"] for n, r in results], ["Application", "Result"])

    # 5 ------------------------------------------------------------------
    def install_one(self) -> None:
        header("Install an individual application")
        app = self.pick_one("Application to install")
        if app:
            self.install_app(app)

    # 6/7/8 --------------------------------------------------------------
    def menu_start(self) -> None:
        header("Start an application")
        app = self.pick_one("Application to start")
        if app:
            self.start_app(app)

    def stop_app(self, app: App) -> bool:
        app = self.resolve(app)
        if not self.require_docker():
            return False
        if self.app_status(app) in ("not installed", "installed (containers removed)"):
            info(f"{app.name} has no containers to stop.")
            return True
        r = self.compose_run(app, "stop", stream=True, mutating=True, timeout=None)
        (ok if r.rc == 0 else err)(f"{app.name}: stop " + ("done." if r.rc == 0 else "failed."))
        return r.rc == 0

    def menu_stop(self) -> None:
        header("Stop an application")
        app = self.pick_one("Application to stop")
        if app:
            self.stop_app(app)

    def menu_restart(self) -> None:
        header("Restart an application")
        app = self.pick_one("Application to restart")
        if not app:
            return
        app = self.resolve(app)
        if self.app_status(app) in ("not installed", "installed (containers removed)"):
            warn("Not installed/created yet; starting instead.")
            self.start_app(app)
            return
        if self.stop_app(app):
            self.start_app(app)

    # 9 ------------------------------------------------------------------
    def status_all(self) -> None:
        header("Application status")
        rows = []
        for a in self.real_apps:
            cs = self.project_containers(a) if shutil.which("docker") else []
            rows.append([a.name, a.tier_label.split(" ")[0], self.app_status(a), str(len(cs))])
        table(rows, ["Application", "Tier", "Status", "Containers"])
        if self.bind not in LOOPBACK:
            warn(f"Bind address is {self.bind} (not localhost-only).")

    # 10 -----------------------------------------------------------------
    def print_urls(self, app: App) -> None:
        app = self.resolve(app)
        running = self.published_ports(app)
        print(_c("1", f"\n{app.name}") + f"  [{self.app_status(app)}]")
        rows = []
        for p in app.get("ports", []):
            port = self.port_value(app, p)
            actual = [r for r in running if r["host_port"] == port]
            where = f"{actual[0]['host_ip'] or '*'}:{actual[0]['host_port']}" if actual else "(not published)"
            url = self.url_for(app, p, port) or "-"
            rows.append([p["name"], where, url])
        table(rows, ["Service", "Host binding (actual)", "Browse from THIS host"])
        for r in running:
            if r["host_ip"] in ("0.0.0.0", "::", ""):
                warn(f"{r['container']} publishes port {r['host_port']} on ALL interfaces (reachable from your network).")
        cs = self.project_containers(app)
        if cs:
            print(_c("2", "Container-internal addresses (only reachable from other containers on the same lab network; "
                          "NOT usable from your browser):"))
            for c in cs:
                svc = c["Config"]["Labels"].get("com.docker.compose.service", c["Name"].lstrip("/"))
                for net, nd in c["NetworkSettings"].get("Networks", {}).items():
                    ports = ",".join(k.split("/")[0] for k in (c["Config"].get("ExposedPorts") or {})) or "-"
                    print(_c("2", f"   {svc}  ->  {nd.get('IPAddress') or '-'}  (network {net}, container ports {ports})"))

    def show_urls(self) -> None:
        header("Application URLs and ports")
        for a in self.real_apps:
            self.print_urls(a)
        print("\nNote: URLs use the host's loopback address. Inside a container, 'localhost' means the container itself.")

    # 11 -----------------------------------------------------------------
    def view_logs(self) -> None:
        header("Container logs")
        app = self.pick_one("Application")
        if not app or not self.require_docker():
            return
        app = self.resolve(app)
        if not self.project_containers(app):
            warn("No containers exist for this application yet.")
            return
        n = "100"
        if not self.args.run:
            raw = self.ask("Number of lines [100]: ").strip()
            n = raw if raw.isdigit() else "100"
        follow = (not self.args.run) and self.confirm("Follow live output (Ctrl+C to stop)?")
        args = ["logs", "--tail", n] + (["-f"] if follow else [])
        try:
            self.compose_run(app, *args, stream=True, timeout=None)
        except KeyboardInterrupt:
            print()
            info("Stopped following logs.")

    # 12 -----------------------------------------------------------------
    def container_health(self) -> None:
        header("Container health")
        if not self.require_docker():
            return
        rows = []
        for a in self.real_apps:
            for c in self.project_containers(a):
                s = c["State"]
                health = s.get("Health", {}).get("Status", "no healthcheck")
                rows.append([a.id, c["Name"].lstrip("/"), s["Status"], health, str(c.get("RestartCount", 0)),
                             "yes" if s.get("OOMKilled") else "no", str(s.get("ExitCode", 0))])
        if not rows:
            info("No lab containers exist.")
        else:
            table(rows, ["App", "Container", "State", "Health", "Restarts", "OOM", "ExitCode"])
        print()
        for a in self.real_apps:
            if self.app_status(a).startswith("running"):
                p = next((x for x in a.get("ports", []) if x.get("primary")), None)
                if p:
                    good, detail = http_probe(self.url_for(a, p).replace(self.browse_host, "127.0.0.1"))
                    (ok if good else warn)(f"{a.name}: HTTP check {detail}")

    # 13 -----------------------------------------------------------------
    def update_images(self) -> None:
        header("Update application images")
        print("Updating an image only downloads newer layers. Running containers keep using the OLD image until they are\n"
              "recreated. Recreating replaces the container (data inside the container filesystem is lost; named volumes\n"
              "are kept). This tool asks before recreating.\n")
        app = self.pick_one("Application to update")
        if not app or not self.require_docker():
            return
        app = self.resolve(app)
        if not app.compose_file.exists():
            warn("Not installed.")
            return
        if app.method == "git-compose" and (app.dir / "repo").exists():
            dirty = self.run(["git", "-C", str(app.dir / "repo"), "status", "--porcelain"]).out.strip()
            if dirty:
                warn("The cloned repository has local modifications; skipping 'git pull'.")
            elif self.confirm("Fast-forward the cloned upstream repository (git pull --ff-only)?", default=True):
                self.run(["git", "-C", str(app.dir / "repo"), "pull", "--ff-only"], stream=True, mutating=True,
                         timeout=None)
        elif app.method in ("download-compose", "template-compose"):
            self.provision(app)
        before = self._image_ids(app)
        r = self.compose_run(app, "pull", stream=True, mutating=True, timeout=None)
        if r.rc != 0:
            err("Pull failed.")
            return
        if self.dry:
            return
        self.record_digests(app)
        changed = [i for i, v in self._image_ids(app).items() if before.get(i) != v]
        if not changed:
            ok("Images are already current.")
            return
        ok("New image(s): " + ", ".join(changed))
        if self.app_status(app).startswith(("running", "stopped", "partially")) and self.confirm(
                "Recreate the containers now to use the new images?"):
            self.compose_run(app, "up", "-d", *app.get("up_args", []), stream=True, mutating=True, timeout=None)
            self.wait_ready(app)

    def _image_ids(self, app: App) -> Dict[str, str]:
        out = {}
        for img in self.compose_run(app, "config", "--images", timeout=60).out.split():
            r = self.run(["docker", "image", "inspect", "--format", "{{.Id}}", img], timeout=30)
            out[img] = r.out.strip() if r.rc == 0 else ""
        return out

    # 14 -----------------------------------------------------------------
    def check_ports(self) -> None:
        header("Port availability")
        rows = []
        for a in self.real_apps:
            own = {p["host_port"] for p in self.published_ports(a)}
            for p in self.planned_ports(a):
                if p["port"] in own:
                    state = "in use by this lab's running container"
                elif port_in_use(p["host_ip"], p["port"]):
                    state = "IN USE by something else"
                else:
                    state = "free"
                rows.append([a.id, p["service"], f"{p['host_ip']}:{p['port']}", state])
        table(rows, ["App", "Service", "Binding", "State"])
        if self.args.run or self.assume_yes:
            return
        movable = [a for a in self.real_apps if any(p.get("env") and not p.get("fixed") for p in a.get("ports", []))]
        if movable and self.confirm("\nChange a host port for an application?"):
            app = self.pick_one("Application")
            if not app:
                return
            app = self.resolve(app)
            for p in [x for x in app.get("ports", []) if x.get("env") and not x.get("fixed")]:
                cur = self.port_value(app, p)
                raw = self.ask(f"New host port for '{p['name']}' [{cur}] (Enter keeps): ").strip()
                if not raw:
                    continue
                if not raw.isdigit() or not (1 <= int(raw) <= 65535):
                    err("Port must be a number from 1 to 65535.")
                    continue
                new = int(raw)
                if new < 1024:
                    warn("Ports below 1024 are privileged on many systems.")
                if port_in_use(self.bind, new):
                    err(f"Port {new} is in use. Not changed.")
                    continue
                self.app_state(app).setdefault("ports", {})[p["env"]] = new
                self.state.save()
                ok(f"{p['name']} -> host port {new}. Restart the app (Start / Stop / Restart) for it to take effect.")
            if all(x.get("fixed") or not x.get("env") for x in app.get("ports", [])):
                info("All ports of this application are fixed by the upstream compose file.")

    # 15 -----------------------------------------------------------------
    def connectivity_tests(self) -> None:
        header("Basic connectivity tests (localhost only)")
        rows = []
        for a in self.real_apps:
            if not self.app_status(a).startswith(("running", "partially")):
                continue
            for p in a.get("ports", []):
                port = self.port_value(a, p)
                tcp = tcp_open("127.0.0.1", port)
                http = "-"
                if tcp and p.get("scheme"):
                    good, detail = http_probe(self.url_for(a, p).replace(self.browse_host, "127.0.0.1"))
                    http = detail
                rows.append([a.id, p["name"], str(port), "open" if tcp else "closed", http])
        if not rows:
            info("No running applications to test.")
        else:
            table(rows, ["App", "Service", "Port", "TCP", "HTTP"])
        info("Only 127.0.0.1 ports of lab applications are contacted; no other hosts are scanned.")

    # 16 -----------------------------------------------------------------
    def list_containers(self) -> None:
        header("Lab containers")
        if not self.require_docker():
            return
        rows = []
        for a in self.real_apps:
            r = self.run(["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={a.project}",
                          "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"], timeout=30)
            for line in r.out.splitlines():
                rows.append([a.id] + line.split("\t"))
        if rows:
            table(rows, ["App", "Container", "Image", "Status", "Ports"])
        else:
            info("No containers managed by this tool exist.")

    # 17 -----------------------------------------------------------------
    def stop_all(self) -> None:
        header("Stop all lab applications")
        if not self.require_docker():
            return
        running = [a for a in self.real_apps if self.app_status(a).startswith(("running", "partially"))]
        if not running:
            info("Nothing is running.")
            return
        print("Will stop: " + ", ".join(a.name for a in running))
        if self.confirm("Stop these applications?"):
            for a in running:
                self.stop_app(a)

    # 18 -----------------------------------------------------------------
    def remove_app(self, app: Optional[App] = None) -> None:
        header("Remove an application")
        app = app or self.pick_one("Application to remove")
        if not app or not self.require_docker():
            return
        app = self.resolve(app)
        print(f"This removes the containers and the dedicated network of {app.name} (project {app.project}).")
        print("Unrelated containers, images, networks and volumes are NOT touched.")
        if not self.confirm("Continue?"):
            return
        vols = self.confirm("ALSO delete this app's named volumes (database/user data)? [default: keep]", optional_destructive=True)
        down = ["down", "--remove-orphans"] + (["-v"] if vols else [])
        if app.compose_file.exists():
            r = self.compose_run(app, *down, stream=True, mutating=True, timeout=None)
            if r.rc != 0:
                err("compose down failed; see Monitor & Diagnose > Troubleshooting Log.")
                return
        else:
            self._remove_by_label(app, vols)
        if self.confirm("Also remove the images used by this app? (shared images in use elsewhere are refused by Docker)", optional_destructive=True):
            if app.compose_file.exists():
                for img in self.compose_run(app, "config", "--images", timeout=60).out.split():
                    self.docker("image", "rm", img, mutating=True)
        if self.confirm(f"Also delete downloaded files in {app.dir}?", optional_destructive=True):
            if not self.dry:
                self._safe_rmtree(app.dir)
            else:
                print(_c("35", "[dry-run] would delete ") + str(app.dir))
        if not self.dry:
            st = self.app_state(app)
            st["installed"] = False
            self.state.save()
        ok(f"{app.name} removed.")

    def _remove_by_label(self, app: App, vols: bool) -> None:
        r = self.run(["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={app.project}"])
        ids = r.out.split()
        if ids:
            self.docker("rm", "-f", *ids, mutating=True)
        self._remove_networks([app.project])
        if vols:
            self._remove_volumes([app.project])

    def _remove_networks(self, projects: List[str]) -> None:
        for proj in projects:
            if not proj.startswith(PROJECT_PREFIX):
                continue
            r = self.run(["docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={proj}"])
            for nid in r.out.split():
                self.docker("network", "rm", nid, mutating=True)

    def _remove_volumes(self, projects: List[str]) -> None:
        for proj in projects:
            if not proj.startswith(PROJECT_PREFIX):
                continue
            r = self.run(["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={proj}"])
            for vid in r.out.split():
                self.docker("volume", "rm", vid, mutating=True)

    def _safe_rmtree(self, path: Path) -> None:
        resolved = path.resolve()
        if APPS_DIR.resolve() in resolved.parents and resolved != APPS_DIR.resolve():
            shutil.rmtree(resolved, ignore_errors=True)
        else:
            err(f"Refusing to delete {resolved}: outside the managed apps directory.")

    # 19 -----------------------------------------------------------------
    def remove_all(self) -> None:
        header("Remove ALL lab containers and networks")
        if not self.require_docker():
            return
        projects = sorted({a.project for a in self.real_apps} | {PROJECT_PREFIX + k for k in self.state.data["apps"]})
        found = []
        for a in self.real_apps:
            cs = self.project_containers(a)
            if cs:
                found.append((a, cs))
        print("Managed Compose projects: " + ", ".join(projects))
        if not found:
            info("No lab containers exist (leftover lab networks, if any, will still be cleaned).")
        for a, cs in found:
            print(f"  - {a.name}: {', '.join(c['Name'].lstrip('/') for c in cs)}")
        print("Only resources labelled with these projects are removed. Volumes are kept unless you opt in.")
        if not self.assume_yes:  # --yes is the explicit non-interactive consent
            if self.ask("Type DELETE to confirm: ").strip() != "DELETE":
                info("Cancelled.")
                return
        vols = self.confirm("ALSO delete named volumes of these projects (database/user data)? [default: keep]", optional_destructive=True)
        for a, _ in found:
            if a.compose_file.exists():
                self.compose_run(a, "down", "--remove-orphans", *(["-v"] if vols else []),
                                 stream=True, mutating=True, timeout=None)
            else:
                self._remove_by_label(a, vols)
        self._remove_networks(projects)
        if vols:
            self._remove_volumes(projects)
        if not self.dry:
            for k in self.state.data["apps"]:
                self.state.data["apps"][k]["installed"] = False
            self.state.save()
        ok("Lab containers and networks removed. Downloaded files remain in " + str(APPS_DIR) +
           " (delete that directory manually if you want a full uninstall).")

    # 20 -----------------------------------------------------------------
    def show_logs(self) -> None:
        header("Installation and troubleshooting log")
        print(f"Log file: {LOG_FILE}")
        if not LOG_FILE.exists():
            info("No log yet.")
            return
        n, errors_only = 40, False
        if not self.args.run and not self.assume_yes:
            raw = self.ask("Lines to show [40]: ").strip()
            n = int(raw) if raw.isdigit() else 40
            errors_only = self.confirm("Show only warnings/errors?")
        lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        shown = []
        for l in lines:
            try:
                d = json.loads(l)
            except json.JSONDecodeError:
                continue
            if errors_only and d.get("level") not in ("WARNING", "ERROR", "CRITICAL"):
                continue
            extra = {k: v for k, v in d.items() if k not in ("ts", "level", "event")}
            shown.append(f"{d.get('ts', '')} {d.get('level', ''):7} {d.get('event', '')} "
                         f"{json.dumps(extra, ensure_ascii=False) if extra else ''}")
        print("\n".join(shown[-n:]) or "(no matching entries)")

    # 21 -----------------------------------------------------------------
    def help_text(self) -> None:
        header("Help and documentation")
        print(f"""
owasp_lab_manager {VERSION}
Deploys EXISTING vulnerable OWASP training apps with Docker. Data and files live in {LAB_HOME}.

Typical flow:  Environment & Docker -> Install Applications -> Monitor & Diagnose (URLs)
               -> practise (only on your own lab) -> Start/Stop > Stop All -> Remove & Cleanup.

Key concepts
  * Every app is its own Compose project "owasplab-<id>" with a dedicated network.
  * Default bind address is 127.0.0.1. Change only with --bind and only on isolated networks.
  * Updating an image ('Update Images') downloads new layers; the running container is replaced only when you agree.
  * Removing (18/19) keeps volumes unless you explicitly opt in. Nothing outside owasplab-* projects is touched.
  * --dry-run prints the commands that would modify anything; read-only checks still run.
  * Non-interactive: --run <action number|name> [--app id[,id]|all] [--yes] [--accept-risk]

Documentation links:""")
        for a in self.apps:
            print(f"  {a.name:<42} {a.get('docs', '')}")
        print(f"""
Add your own application: create {LOCAL_CATALOG} with the same JSON format as catalog.json.
Entries from that file are labelled COMMUNITY unless you set "tier".
Troubleshooting: Monitor & Diagnose > Troubleshooting Log / Container Logs, Environment & Docker > Check Ports, README.md.""")


# --------------------------------------------------------------------------- #
# Menu (8 sections; related actions live in submenus)
# --------------------------------------------------------------------------- #
# Flat action list, kept for scripting:  --run N  (numbers are stable) or --run <action name>
ACTIONS = [
    "check_requirements", "install_docker", "list_catalog", "install_selected", "install_one",
    "menu_start", "menu_stop", "menu_restart", "status_all", "show_urls", "view_logs",
    "container_health", "update_images", "check_ports", "connectivity_tests", "list_containers",
    "stop_all", "remove_app", "remove_all", "show_logs", "help_text",
]

# (label, hint, target) - target is an action name or a list of (label, action) for a submenu
MAIN_MENU: List[Tuple[str, str, Any]] = [
    ("Environment & Docker", "requirements, Docker setup, ports", [
        ("Check System Requirements", "check_requirements"),
        ("Install and Verify Docker", "install_docker"),
        ("Check / Change Ports", "check_ports"),
    ]),
    ("Application Catalog", "descriptions, docs, ports, status", "list_catalog"),
    ("Install Applications", "one app or a selection", [
        ("Install an Individual Application", "install_one"),
        ("Install All Selected Applications", "install_selected"),
    ]),
    ("Start / Stop / Restart", "control running labs", [
        ("Start an Application", "menu_start"),
        ("Stop an Application", "menu_stop"),
        ("Restart an Application", "menu_restart"),
        ("Stop All Lab Applications", "stop_all"),
    ]),
    ("Monitor & Diagnose", "status, URLs, health, logs", [
        ("Application Status", "status_all"),
        ("Application URLs and Ports", "show_urls"),
        ("Container Health", "container_health"),
        ("Connectivity Tests", "connectivity_tests"),
        ("List Running Containers", "list_containers"),
        ("View Container Logs", "view_logs"),
        ("Installation / Troubleshooting Log", "show_logs"),
    ]),
    ("Update Images", "pull newer images, optional recreate", "update_images"),
    ("Remove & Cleanup", "one app or the whole lab", [
        ("Remove a Selected Application", "remove_app"),
        ("Remove All Lab Containers and Networks", "remove_all"),
    ]),
    ("Help & Documentation", "usage, safety, links", "help_text"),
]

BOX_W = 66


def _box_line(text: str = "", color: str = "") -> str:
    side = _c("34", "║" if UNICODE else "|")
    plain_len = visible_len(text)
    body = text + " " * max(BOX_W - plain_len, 0)
    return center(side + (_c(color, body) if color else body) + side)


def _box_edge(kind: str) -> str:
    if UNICODE:
        l, m, r = {"top": ("╔", "═", "╗"), "mid": ("╟", "─", "╢"), "bot": ("╚", "═", "╝")}[kind]
    else:
        l, m, r = "+", "-", "+"
    return center(_c("34", l + m * BOX_W + r))


def render_menu(lab: Lab, title: str, entries: List[Tuple[str, str]], zero_label: str) -> None:
    """entries: (label, hint). Draws a centered, coloured menu box after clearing the screen."""
    clear_screen()
    banner(compact=False)
    server, comp, _ = lab.docker_versions()
    docker_txt = _c("1;32", "ready") if server and lab.compose else _c("1;31", "not ready")
    bind_txt = _c("1;32", lab.bind) if lab.bind in LOOPBACK else _c("1;31", lab.bind + " (EXPOSED!)")
    print(center(f"Docker: {docker_txt}    Bind: {bind_txt}" + (_c("1;35", "    DRY-RUN") if lab.dry else "")))
    print()
    print(_box_edge("top"))
    print(_box_line(center(_c("1;37", title.upper()), BOX_W)))
    print(_box_edge("mid"))
    for i, (label, hint) in enumerate(entries, 1):
        num = _c("1;33", f"{i:>2}")
        hint_txt = _c("2", hint) if hint else ""
        gap = BOX_W - 2 - 3 - 1 - len(label) - 1 - visible_len(hint) - 1
        print(_box_line(f"  {num}  {_c('1;37', label)}" + " " * max(gap, 1) + hint_txt))
    print(_box_edge("mid"))
    print(_box_line(f"  {_c('1;31', ' 0')}  {_c('1;37', zero_label)}"))
    print(_box_edge("bot"))


def read_choice(lab: Lab, count: int) -> Optional[int]:
    raw = lab.ask("\n" + center(_c("1;36", f"Select an option [0-{count}]") + " > ")).strip()
    if raw.isdigit() and 0 <= int(raw) <= count:
        return int(raw)
    err(f"Please enter a number between 0 and {count}.")
    time.sleep(1.2)
    return None


def run_action(lab: Lab, action: str) -> None:
    log(logging.INFO, "menu action", action=action)
    try:
        getattr(lab, action)()
    except KeyboardInterrupt:
        print()
        warn("Interrupted. Any partially completed step is safe to repeat (operations are idempotent).")
        log(logging.WARNING, "interrupted", action=action)
    except Exception as exc:  # noqa: BLE001
        err(f"Unexpected error: {exc}. Details were written to {LOG_FILE}.")
        LOG.exception("unhandled exception in action %s", action)


def submenu(lab: Lab, title: str, items: List[Tuple[str, str]]) -> None:
    while True:
        render_menu(lab, title, [(label, "") for label, _ in items], "Back to main menu")
        choice = read_choice(lab, len(items))
        if choice is None:
            continue
        if choice == 0:
            return
        run_action(lab, items[choice - 1][1])
        lab.pause()


def main_loop(lab: Lab) -> None:
    while True:
        render_menu(lab, "Main menu", [(label, hint) for label, hint, _ in MAIN_MENU], "Exit")
        choice = read_choice(lab, len(MAIN_MENU))
        if choice is None:
            continue
        if choice == 0:
            return
        label, _, target = MAIN_MENU[choice - 1]
        if isinstance(target, list):
            submenu(lab, label, target)
        else:
            run_action(lab, target)
            lab.pause()


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=f"Manage intentionally vulnerable OWASP training apps in Docker. Author: {AUTHOR}",
                                 epilog="FOR AUTHORIZED TRAINING USE ONLY.")
    ap.add_argument("--dry-run", action="store_true", help="show what would change; do not modify anything")
    ap.add_argument("--yes", "-y", action="store_true", help="auto-confirm prompts (never auto-deletes data/images/files)")
    ap.add_argument("--accept-risk", action="store_true", help="acknowledge the vulnerable-apps notice non-interactively")
    ap.add_argument("--no-auto-fix", action="store_true",
                    help="do not repair missing prerequisites automatically (report errors instead)")
    ap.add_argument("--bind", help="host address for published ports (default 127.0.0.1; persisted)")
    ap.add_argument("--run", metavar="ACTION", help=f"run one action non-interactively and exit: a number 1-{len(ACTIONS)} "
                    "or a name (" + ", ".join(ACTIONS) + ")")
    ap.add_argument("--app", help="application id(s) for --run (comma separated, or 'all')")
    ap.add_argument("--version", action="version", version=f"{VERSION} (author: {AUTHOR})")
    return ap.parse_args(argv)


def resolve_action(token: str) -> Optional[str]:
    if token.isdigit() and 1 <= int(token) <= len(ACTIONS):
        return ACTIONS[int(token) - 1]
    return token if token in ACTIONS else None


def main(argv: Optional[List[str]] = None) -> int:
    global LOG
    args = parse_args(argv)
    if args.bind and args.bind not in LOOPBACK:
        print(_c("1;33", f"WARNING: binding to {args.bind} exposes intentionally vulnerable services beyond this machine."))
        if not args.yes and input("Type EXPOSE to accept this risk: ").strip() != "EXPOSE":
            return 2
    LAB_HOME.mkdir(parents=True, exist_ok=True)
    LOG = setup_logging()
    log(logging.INFO, "start", version=VERSION, argv=sys.argv[1:])
    if platform.system() == "Windows":
        print("Native Windows is not supported. Please run inside WSL2 (Docker Desktop with WSL integration).")
        return 2
    lab = Lab(args)
    if args.run:
        action = resolve_action(str(args.run))
        if not action:
            err(f"--run must be 1..{len(ACTIONS)} or one of: {', '.join(ACTIONS)}")
            return 2
        run_action(lab, action)
        return 0
    for p in lab.catalog_problems:
        warn(p)
    try:
        main_loop(lab)
    except KeyboardInterrupt:
        print()
    clear_screen()
    banner(compact=True)
    print()
    print(center(_c("1;32", "Goodbye!") + " Stop lab applications you are not using (Start / Stop > Stop All)."))
    print(center(_c("33", AUTHOR)))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
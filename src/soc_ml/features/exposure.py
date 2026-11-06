"""Sensitive-file exposure: a client got back a file that should never be public.

The alert an analyst can act on is not "this address scanned us" (thousands a
day, almost all finding nothing). It is "this site handed out its ``.git``
repository / ``.env`` / database dump, and here is who took it". That fact is
in the access log: a 2xx answer, with a body, to a path whose *kind* is
sensitive.

Why this replaced the broad finding (D-034, rule in D-040): "a success on a
file type the site never served during training" escalated 39 alerts on prod
between 22 Oct and 2 Nov, and 30 of them were legitimate services that went
live after the training snapshot (Anubis challenge pages, ONLYOFFICE, the VPN
host checker, web fonts). Novelty of a file type says nothing about its
sensitivity. The kinds below do: each names what an attacker gains and what
the responder does next, so an alert can say both.

Three things keep it from firing on what only looks like an exposure:

* **Catch-all pages.** Many sites answer every unknown path with 200 and the
  same page (an SPA shell, a soft 404). A response whose size this site also
  returned for other paths is the site's answer to everything, not the file
  (on prod a ``/.git.tar.gz`` "success" was the 936-byte home page). The sizes
  are learned live per site, in :class:`WindowFeatureBuilder`. A page that
  prints the requested path changes size with the path's length; its
  directory's other answers give it away (D-041).
* **Empty bodies.** HEAD probes and 204s prove nothing about content.
* **Verification.** :func:`verify` fetches the file once, from the SOC side,
  and checks the content against the kind's signature (a git config begins
  ``[core]``, a web.config is XML with ``<configuration>``). Only the verdict,
  the signature name and a digest are stored — never the content, which may be
  a secret.

The kinds are a specification of what is sensitive, like the spec's gates
(FR-62 concerns config, and nothing here is compared against a traffic
quantity). An operator who serves one of these on purpose lists it under
``exposure.allow`` in the config — policy, not a threshold.
"""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ml.core.contracts import Severity

__all__ = [
    "ExposureKind",
    "KINDS",
    "classify",
    "exposure_url",
    "ExposureTracker",
    "verify",
    "VERIFY_VERDICTS",
]


@dataclass(frozen=True, slots=True)
class ExposureKind:
    slug: str
    title: str
    severity: Severity
    #: What an attacker gains — the alert's "why this matters".
    impact: str
    #: What the responder does, in order.
    actions: tuple[str, ...]
    #: Delivered as an alert (True) or recorded in the digest only.
    alert: bool = True


_BLOCK = ("Block the path in the web server for this site and reload it, then "
          "re-check the URL from outside (the dashboard's Re-check button).")

KINDS: dict[str, ExposureKind] = {k.slug: k for k in (
    ExposureKind(
        "vcs", "Source-code repository (.git / .svn / .hg)", Severity.CRITICAL,
        "The whole repository can be rebuilt from these files: source code, full "
        "history, and any password, key or token ever committed.",
        (_BLOCK + " For nginx: location ~ /\\.(git|svn|hg) { deny all; }",
         "Ask the site owner which credentials, keys or tokens the repository "
         "contains or ever contained, and rotate every one of them.",
         "List the addresses that downloaded it (Other clients, below) and treat "
         "each as having the source code.")),
    ExposureKind(
        "secrets", "Secrets file (.env, keys, credentials)", Severity.CRITICAL,
        "Files like these hold database passwords, API keys, mail credentials or "
        "private keys in plain text.",
        (_BLOCK,
         "Rotate every credential or key in the file now — assume the downloader "
         "has them.",
         "Check the services those credentials open (database, mail, cloud) for "
         "logins from the downloading addresses or since the download time.")),
    ExposureKind(
        "dump", "Database dump", Severity.CRITICAL,
        "A database export: user records, password hashes and application data.",
        (_BLOCK + " Then remove the file from the web root.",
         "Find out what the dump contains; if it holds personal data, this is a "
         "data breach and the institute's breach process applies.",
         "Force password resets for the accounts it contains.")),
    ExposureKind(
        "backup", "Site or source backup archive", Severity.HIGH,
        "An archive of the site or its source: code, configuration and often "
        "embedded credentials.",
        (_BLOCK + " Then remove the archive from the web root.",
         "Check the archive for configuration files and rotate any credentials "
         "in them.")),
    ExposureKind(
        "source", "Server-side source code (editor or backup copy)", Severity.HIGH,
        "A copy of a server-side script served as plain text instead of being "
        "executed: application logic, and often database credentials.",
        (_BLOCK + " Then delete the stray copy.",
         "Read the copy for credentials and rotate any it contains.")),
    ExposureKind(
        "debug", "Debug, status or log output", Severity.HIGH,
        "Internal state: environment variables, file paths, versions, session "
        "data or request logs that help an attacker plan the next step.",
        (_BLOCK + " Or switch the debug endpoint off.",
         "Check the output for secrets (environment, tokens, session ids) and "
         "rotate any found.")),
    ExposureKind(
        "server_config", "Web server configuration file", Severity.MEDIUM,
        "The server's own rules (.htaccess, web.config): which paths are "
        "protected and how. Usually no secrets, but it shows the web server is "
        "serving files it should refuse.",
        (_BLOCK + " For nginx: location ~ /\\.ht { deny all; } and deny "
                  "web.config.",)),
    ExposureKind(
        "metadata", "Development metadata", Severity.LOW,
        "Directory listings and tooling files (.DS_Store, .idea, lock files) "
        "that reveal file names and versions.",
        (_BLOCK,), alert=False),
)}

_VCS_DIRS = (".git", ".svn", ".hg", ".bzr", "_darcs")
_SECRET_DIRS = (".aws", ".ssh", ".docker", ".kube", ".gnupg", ".azure")
_SECRET_NAMES = frozenset((
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".htpasswd", ".npmrc", ".pypirc",
    ".netrc", ".pgpass", ".my.cnf", ".git-credentials", "credentials.json",
    "secrets.yml", "secrets.yaml", "secrets.json", "service-account.json",
    ".s3cfg", ".boto", "wp-config.php.bak", "localsettings.php.bak",
))
_SECRET_EXTS = ("pem", "key", "p12", "pfx", "jks", "keystore", "ppk", "kdbx", "ovpn")
_CONFIG_STEMS = ("wp-config", "configuration", "config", "settings", "database", "db",
                 "local.settings", "parameters", "localsettings", "settings.local",
                 "local", "connection", "conn")
_BACKUP_SUFFIXES = ("bak", "old", "orig", "save", "swp", "swo", "backup", "tmp", "1",
                    "2", "copy", "dist", "txt")
_SCRIPT_EXTS = ("php", "php5", "phtml", "inc", "asp", "aspx", "jsp", "py", "rb", "pl", "cgi")
_ARCHIVE_EXTS = ("zip", "tar", "tar.gz", "tgz", "gz", "rar", "7z", "bz2", "tar.bz2",
                 "xz", "tar.xz", "war")
_BACKUP_STEMS = frozenset((
    "backup", "backups", "bak", "db", "database", "dump", "site", "sites", "www",
    "wwwroot", "htdocs", "public_html", "html", "web", "webroot", "src", "source",
    "archive", "old", "website", "home", "root",
))
_DUMP_EXTS = ("sql", "sql.gz", "sql.zip", "sql.bz2", "sql.xz", "sql.7z", "sql.tar.gz",
              "dump", "sqlite", "sqlite3", "mdb", "accdb")
_SERVER_CONFIG = frozenset((".htaccess", ".user.ini", "web.config", "php.ini",
                            "nginx.conf", "httpd.conf", "apache2.conf"))
_DEBUG_NAMES = frozenset(("phpinfo.php", "info.php", "php_info.php", "pinfo.php",
                          "sftp-config.json", "elmah.axd", "trace.axd", "error_log",
                          "laravel.log"))
_DEBUG_PATHS = ("/server-status", "/server-info", "/actuator/env", "/actuator/heapdump",
                "/actuator/configprops", "/actuator/threaddump", "/debug/pprof",
                "/_profiler", "/.vscode/sftp.json", "/storage/logs/")
_METADATA_NAMES = frozenset((".ds_store", "composer.json", "composer.lock",
                             "package-lock.json", "yarn.lock", "gemfile.lock",
                             ".gitignore", ".eslintignore", ".dockerignore",
                             "dockerfile", "docker-compose.yml", "docker-compose.yaml",
                             ".gitlab-ci.yml", ".travis.yml", "thumbs.db"))
_METADATA_DIRS = (".idea", ".vscode", ".github", ".circleci")


def _split(path: str) -> list[str]:
    return [s for s in path.split("?", 1)[0].split("#", 1)[0].split("/") if s]


def _ends(name: str, exts: tuple[str, ...]) -> str | None:
    for ext in sorted(exts, key=len, reverse=True):
        if name.endswith("." + ext) and len(name) > len(ext) + 1:
            return ext
    return None


def classify(path: str | None) -> tuple[ExposureKind, str] | None:
    """The sensitive kind of a URL path and its exposure root, or None.

    The root is what one exposure *is*: every object of one ``.git`` directory
    is the same exposure (``/~group/.git/``); any other file is its own.
    """
    if not path:
        return None
    segs = _split(path)
    if not segs:
        return None
    low = [s.lower() for s in segs]
    if low[0] == ".well-known":
        return None  # published by design (RFC 8615)
    name = low[-1]

    def root_to(i: int) -> str:
        return "/" + "/".join(segs[: i + 1]) + "/"

    for i, seg in enumerate(low):
        if seg in _VCS_DIRS and i < len(low) - 1:
            return KINDS["vcs"], root_to(i)
    full = "/" + "/".join(low)
    exact = "/" + "/".join(segs)
    for i, seg in enumerate(low):
        if seg in _SECRET_DIRS and i < len(low) - 1:
            return KINDS["secrets"], exact
    if name == ".env" or name.startswith(".env.") or (name.endswith(".env") and len(name) > 4):
        return KINDS["secrets"], exact
    if name in _SECRET_NAMES or _ends(name, _SECRET_EXTS):
        return KINDS["secrets"], exact
    # config.php.bak, wp-config.php~, settings.inc.old, #config.php#
    bare = name.strip("#").rstrip("~")
    script = _script_backup(name)
    if script:
        stem = bare.split(".", 1)[0]
        kind = "secrets" if stem in _CONFIG_STEMS else "source"
        return KINDS[kind], exact
    if _ends(name, _DUMP_EXTS) and name != "thumbs.db":
        return KINDS["dump"], exact
    arch = _ends(name, _ARCHIVE_EXTS)
    if arch:
        stem = name[: -(len(arch) + 1)]
        if stem.startswith((".git", ".svn", ".hg")) or stem in _BACKUP_STEMS:
            return KINDS["backup"], exact
    if _ends(name, ("bak", "backup")) or (
            _ends(name, ("old", "orig")) and name.count(".") >= 2):
        return KINDS["backup"], exact
    if name in _SERVER_CONFIG:
        return KINDS["server_config"], exact
    if name in _DEBUG_NAMES or _ends(name, ("log",)) or any(
            full == p or full.startswith(p + "/") or (p.endswith("/") and full.startswith(p))
            for p in _DEBUG_PATHS):
        return KINDS["debug"], exact
    if name in _METADATA_NAMES or any(seg in _METADATA_DIRS for seg in low[:-1]):
        return KINDS["metadata"], exact
    return None


def _script_backup(name: str) -> bool:
    """``x.php~``, ``x.php.bak``, ``#x.php#``, ``.x.php.swp`` — a script copy."""
    if name.startswith("#") and name.endswith("#"):
        name = name.strip("#")
        return _ends(name, _SCRIPT_EXTS) is not None
    if name.endswith("~"):
        return _ends(name[:-1], _SCRIPT_EXTS) is not None
    parts = name.lstrip(".").split(".")
    if len(parts) >= 3 and parts[-1] in _BACKUP_SUFFIXES and parts[-2] in _SCRIPT_EXTS:
        return True
    return False


def exposure_url(domain: str | None, root: str) -> str | None:
    """The public URL of an exposure (https; the log does not carry the scheme)."""
    if not domain:
        return None
    return f"https://{domain}{root}"


# --------------------------------------------------------------------------- #
# Delivery: one alert per exposure, not per downloader
# --------------------------------------------------------------------------- #

#: An exposure already alerted is raised again only if it is still being
#: downloaded this long after the last alert — the reminder that it is open.
#: A delivery horizon, like EPISODE_GAP, not a data threshold.
REALERT_AFTER = timedelta(days=7)


class ExposureTracker:
    """Folds every later download of one exposure into its first alert.

    On prod, scanners fetched one site's ``/.htaccess`` five times in a week,
    each a separate escalation; it is one misconfiguration with five
    downloaders. The key is (site, exposure root).
    """

    def __init__(self) -> None:
        #: key -> [alert id, last alert time, downloads since, distinct clients]
        self._open: dict[str, list] = {}
        self.stats = {"exposures_alerted": 0, "exposure_downloads_folded": 0}

    @staticmethod
    def key(domain: str | None, root: str) -> str:
        return f"{(domain or '_').lower()}|{root}"

    def decide(self, key: str, alert_id: str, now: datetime, client: str) -> tuple[str, str]:
        """("deliver", alert_id) for a new or re-opened exposure, else ("fold", into)."""
        known = self._open.get(key)
        if known is not None and now - known[1] < REALERT_AFTER:
            known[2] += 1
            if client not in known[3] and len(known[3]) < 256:
                known[3].append(client)
            self.stats["exposure_downloads_folded"] += 1
            return "fold", known[0]
        self._open[key] = [alert_id, now, 1, [client]]
        self.stats["exposures_alerted"] += 1
        return "deliver", alert_id

    def export_state(self) -> dict:
        return {"open": [[k, v[0], v[1].isoformat(), v[2], v[3]]
                         for k, v in self._open.items()]}

    def restore_state(self, doc: dict) -> None:
        for row in (doc or {}).get("open") or []:
            try:
                self._open[str(row[0])] = [str(row[1]), datetime.fromisoformat(row[2]),
                                           int(row[3]), list(row[4])]
            except (IndexError, TypeError, ValueError):
                continue


# --------------------------------------------------------------------------- #
# Verification: fetch once, check the content's signature, keep only the verdict
# --------------------------------------------------------------------------- #

VERIFY_VERDICTS = {
    "confirmed": "Confirmed: the file is publicly readable now and its content "
                 "matches a real {kind}.",
    "likely": "Likely: the URL returns non-HTML content, but no known signature "
              "matched.",
    "not_reproducible": "Not reproducible: the URL returns an ordinary web page, so "
                        "the logged success was probably the site's catch-all page.",
    "blocked_now": "Not exposed now: the site refuses or no longer has the file "
                   "(HTTP {status}). It was served when the client downloaded it.",
    "redirected": "Redirected (HTTP {status}): the file is not served at this URL now.",
    "unreachable": "Could not reach the site from the SOC host: {detail}.",
    "refused": "Not checked: {detail}.",
}

_READ_BYTES = 2048
_TIMEOUT_S = 8.0
_HTML = re.compile(rb"^\s*(<!doctype html|<html|<head|<body|<!--|<meta|<script|<title)", re.I)
#: A log line's timestamp: ISO ([2026-11-06 01:23), PHP's error_log
#: ([04-Apr-2025 09:25:09 UTC] — prod, 6 Nov: read as "likely" without it) and
#: Apache's error log ([Wed Nov 06 01:23:45.1 2026]).
_LOG_LINE = re.compile(rb"\[(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}|\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}"
                       rb"|[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2})")
_ENV_LINE = re.compile(rb"^[ \t]*(export[ \t]+)?[A-Za-z_][A-Za-z0-9_.]*[ \t]*=", re.M)
_APACHE = re.compile(rb"^\s*(#|<IfModule|<Files|<Directory|RewriteEngine|RewriteRule|"
                     rb"RewriteCond|Options|Order|Deny|Allow|Require|DirectoryIndex|"
                     rb"ErrorDocument|php_value|php_flag|AddType|Header|SetEnv|AuthType)",
                     re.I | re.M)


def _signature(kind: str, root: str, body: bytes) -> str | None:
    """Name of the content signature this body matches, or None."""
    head = body[:_READ_BYTES]
    if kind == "vcs":
        if head.startswith(b"ref: refs/") or re.match(rb"^[0-9a-f]{40}\s*$", head):
            return "git HEAD"
        if b"[core]" in head:
            return "git config"
        if head.startswith(b"DIRC"):
            return "git index"
        if head.startswith(b"SQLite format 3"):
            return "svn wc.db"
        if head[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
            return "git object (zlib)"
        if head.startswith(b"PACK"):
            return "git pack"
        if b"# pack-refs" in head:
            return "git packed-refs"
        if head.startswith(b"revlogv1") or b"dotencode" in head or b"fncache" in head:
            return "hg requires"
        return None
    if kind == "debug":
        # Status and phpinfo pages are HTML by nature: match before the HTML check.
        if b"phpinfo()" in head or b"PHP Version" in head:
            return "phpinfo"
        if (b"Server Version:" in head or b"Apache Server Status" in head
                or b"Server Status for" in head):
            return "server status"
        # ASP.NET's trace viewer opens with its own CSS class; ELMAH titles its page.
        if b"tracecontent" in head or b"Application Trace" in head:
            return "ASP.NET trace"
        if b"Error log for" in head and b"ELMAH" in head.upper():
            return "ELMAH error log"
        if _HTML.match(head):
            return None
        if _LOG_LINE.search(head) or b"Stack trace" in head:
            return "log file"
        if head.lstrip().startswith(b"{") and (b"activeProfiles" in head or b"propertySources" in head):
            return "actuator env"
        return None
    if _HTML.match(head):
        return None
    if kind == "secrets":
        if b"PRIVATE KEY-----" in head:
            return "private key"
        if b"CERTIFICATE-----" in head:
            return None  # a public certificate is public by design
        if b"-----BEGIN" in head:
            return "PEM block"
        if b"aws_access_key_id" in head.lower() or b"[default]" in head:
            return "cloud credentials"
        if _ENV_LINE.search(head):
            return "KEY=value settings"
        if head.lstrip().startswith(b"{") and b'"' in head:
            return "JSON credentials"
        if b"<?php" in head:
            return "PHP source"
        if root.lower().endswith("htpasswd") and re.search(
                rb"^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[\w./]{13}$)", head, re.M):
            return "password hashes"
        return None
    if kind == "dump":
        for magic, name in ((b"SQLite format 3", "SQLite database"),
                            (b"\x1f\x8b", "gzip archive"), (b"PK\x03\x04", "zip archive")):
            if head.startswith(magic):
                return name
        for marker, name in ((b"-- MySQL dump", "MySQL dump"), (b"-- MariaDB dump", "MariaDB dump"),
                             (b"PostgreSQL database dump", "PostgreSQL dump"),
                             (b"CREATE TABLE", "SQL"), (b"INSERT INTO", "SQL")):
            if marker in head:
                return name
        return None
    if kind == "backup":
        for magic, name in ((b"PK\x03\x04", "zip archive"), (b"\x1f\x8b", "gzip archive"),
                            (b"Rar!", "rar archive"), (b"7z\xbc\xaf", "7z archive"),
                            (b"BZh", "bzip2 archive"), (b"\xfd7zXZ", "xz archive")):
            if head.startswith(magic):
                return name
        if len(head) > 262 and head[257:262] == b"ustar":
            return "tar archive"
        if b"<?php" in head or b"<%@" in head:
            return "server-side source"
        return None
    if kind == "source":
        for marker, name in ((b"<?php", "PHP source"), (b"<%", "ASP/JSP source"),
                             (b"#!/", "script"), (b"import ", "Python source")):
            if marker in head:
                return name
        return None
    if kind == "server_config":
        if b"<configuration" in head and b"<?xml" in head[:64]:
            return "IIS web.config"
        if _APACHE.search(head):
            return "Apache directives"
        if re.search(rb"^\s*\[?[\w.]+\]?\s*=|^\s*\[[\w ]+\]\s*$", head, re.M):
            return "ini settings"
        return None
    if kind == "metadata":
        if head.startswith(b"\x00\x00\x00\x01Bud1"):
            return ".DS_Store"
        if head.lstrip()[:1] in (b"{", b"<") or b"\n" in head:
            return "text metadata"
        return None
    return None


def _domain_allowed(domain: str, allowed: tuple[str, ...]) -> bool:
    d = domain.lower().rstrip(".")
    if not allowed or not d or ":" in d or re.fullmatch(r"[\d.]+", d):
        return False
    return any(d == a or d.endswith("." + a) for a in (x.lower().lstrip(".") for x in allowed))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 — never follow
        return None


def verify(domain: str | None, root: str, kind: str, *,
           allowed_domains: tuple[str, ...],
           opener=None, now: datetime | None = None) -> dict[str, Any]:
    """Fetch the exposed file once and say whether it is really public.

    ``domain`` comes from the request's Host header, which the client chose, so
    only sites under ``allowed_domains`` (config ``exposure.verify_domains``)
    are ever contacted: a forged Host must not turn the SOC host into a
    fetcher of arbitrary addresses. Redirects are not followed, at most 2 KB is
    read, and the content itself is never returned — only its verdict, the
    signature name, and a SHA-256 so a later check can tell if it changed.
    """
    checked = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    base = {"checked_at": checked, "domain": domain, "root": root, "kind": kind}
    if not domain or not _domain_allowed(domain, allowed_domains):
        detail = ("no site name in the log" if not domain else
                  f"{domain} is not under exposure.verify_domains in the config")
        return {**base, "verdict": "refused", "detail": detail,
                "summary": VERIFY_VERDICTS["refused"].format(detail=detail)}
    probe = root
    if kind == "vcs":
        seg = root.rstrip("/").rsplit("/", 1)[-1].lower()
        probe = root + {".git": "HEAD", ".svn": "wc.db", ".hg": "requires"}.get(seg, "")
    opener = opener or urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=_insecure_context()))
    last_error = "no response"
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}{probe}"
        req = urllib.request.Request(url, headers={
            "Range": f"bytes=0-{_READ_BYTES - 1}",
            "User-Agent": "tlsoc-ml-exposure-verifier/1.0",
        })
        try:
            with opener.open(req, timeout=_TIMEOUT_S) as resp:
                status = resp.status
                ctype = resp.headers.get("Content-Type", "")
                body = resp.read(_READ_BYTES)
        except urllib.error.HTTPError as exc:
            status, ctype, body = exc.code, exc.headers.get("Content-Type", "") if exc.headers else "", b""
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError, ssl.SSLError) as exc:
            last_error = str(getattr(exc, "reason", exc))[:160]
            continue
        out = {**base, "url": url, "status": status, "content_type": ctype[:80],
               "bytes_read": len(body),
               "sha256": hashlib.sha256(body).hexdigest() if body else None}
        if 300 <= status < 400:
            verdict = "redirected"
        elif status >= 400:
            verdict = "blocked_now"
        else:
            sig = _signature(kind, root, body)
            if sig:
                out["signature"] = sig
                verdict = "confirmed"
            elif not body or _HTML.match(body) or ctype.startswith("text/html"):
                verdict = "not_reproducible"
            else:
                verdict = "likely"
        out["verdict"] = verdict
        out["summary"] = VERIFY_VERDICTS[verdict].format(
            kind=KINDS[kind].title.lower() if kind in KINDS else kind, status=status,
            detail="")
        return out
    return {**base, "verdict": "unreachable", "detail": last_error,
            "summary": VERIFY_VERDICTS["unreachable"].format(detail=last_error)}


def _insecure_context() -> ssl.SSLContext:
    # Whether the file is public does not depend on the certificate: internal
    # sites with self-signed or expired certificates still leak.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

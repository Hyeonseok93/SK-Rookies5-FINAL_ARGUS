"""Extract searchable text from responses and match payload-specific leak markers."""

from __future__ import annotations

import io
import re
from typing import Any

# Markers grouped by target file type (needles checked in priority order below)
_PASSWD_MARKERS = ("root:", "daemon:", "nobody:", "bin:", "sys:", "/bin/bash", "/usr/sbin/nologin")
_SHADOW_MARKERS = ("root:$", "$6$", "$y$", "$2y$", "$1$", ":*:")
_HTPASSWD_MARKERS = ("$apr1$", "$2y$", "$6$", "$1$")
_ENV_MARKERS = (
    "db_password",
    "database_url",
    "secret_key",
    "app_key",
    "api_key",
    "aws_access",
    "aws_secret",
    "password=",
    "mysql_password",
    "redis_password",
    "jwt_secret",
)
_WEB_CONFIG_MARKERS = ("connectionstrings", "<configuration>", "system.web", "appsettings", "machine.config")
_APP_CONFIG_MARKERS = ("spring:", "datasource:", "jdbc:", "hibernate.", "jpa:", "server.port")
_WP_CONFIG_MARKERS = ("define('db_name'", 'define("db_name"', "db_password", "db_user", "table_prefix")
_PHPINFO_MARKERS = ("php version", "phpinfo()", "configuration", "system </td>", "php license")
_GIT_MARKERS = ("[core]", "repositoryformatversion", "ref: refs/", "[remote")
_WIN_INI_MARKERS = ("[fonts]", "[extensions]", "[boot loader]", "[operating systems]", "mci extensions")
_HOSTS_MARKERS = ("127.0.0.1", "localhost", "::1", "0.0.0.0")
_ENVIRON_MARKERS = ("path=", "home=", "user=", "pwd=", "shell=", "lang=")
_HTACCESS_MARKERS = ("rewriteengine", "deny from", "allow from", "require all")
_SQL_MARKERS = ("insert into", "create table", "mysqldump", "drop table", "alter table")
_AUTH_LOG_MARKERS = ("sshd", "authentication failure", "sudo:", "failed password", "accepted password")
_PROC_VERSION_MARKERS = ("linux version", "gcc version", "ubuntu", "debian", "red hat")
_NGINX_APACHE_MARKERS = ("server {", "listen 80", "virtualhost", "<virtualhost", "documentroot")
_SSH_KEY_MARKERS = ("begin rsa private key", "begin openssh private key", "begin private key", "begin ec private key")
_SWAGGER_MARKERS = ('"swagger"', '"openapi"', '"paths":', '"info":', "swagger ui")
_ACTUATOR_MARKERS = ('"activeprofiles"', '"propertysources"', '"systemproperties"', "local.server.port")
_DOCKER_COMPOSE_MARKERS = ("services:", "image:", "ports:", "environment:", "volumes:")
_AWS_CRED_MARKERS = ("aws_access_key_id", "aws_secret_access_key", "[default]")
_LARAVEL_LOG_MARKERS = ("local.error", "production.error", "stack trace", "illuminate\\", "laravel")
_TOMCAT_MARKERS = ("<tomcat-users", "rolename=", "tomcat-users", "manager-gui")
_WEB_XML_MARKERS = ("<web-app", "<servlet", "display-name", "web-app xmlns")
_NPMRC_MARKERS = ("registry=", "//registry.npmjs.org", "_auth", "always-auth")
_PACKAGE_JSON_MARKERS = ('"name":', '"dependencies":', '"scripts":', '"version":')

GENERIC_SENSITIVE_MARKERS = (
    "root:",
    "[extensions]",
    "db_password",
    "app_key",
    "begin rsa private key",
    "begin openssh private key",
    "aws_access_key",
    "-----begin",
    "/bin/bash",
    "daemon:",
    "connectionstrings",
    "define('db_password",
)


def _payload_key(payload: str) -> str:
    return payload.lower().replace("\\", "/")


def expected_leak_rules(payload: str) -> list[tuple[tuple[str, ...], str]]:
    """
    Map payload → (markers, hint). Specific paths first to avoid .htpasswd → passwd confusion.
    """
    key = _payload_key(payload)
    rules: list[tuple[tuple[str, ...], str]] = []

    def add(markers: tuple[str, ...], hint: str) -> None:
        rules.append((markers, hint))

    if ".htpasswd" in key:
        add(_HTPASSWD_MARKERS, ".htpasswd")
    elif "shadow" in key and ("/shadow" in key or key.endswith("shadow")):
        add(_SHADOW_MARKERS, "/etc/shadow")
    elif "passwd" in key and ".htpasswd" not in key:
        add(_PASSWD_MARKERS, "/etc/passwd")
    if ".env" in key:
        add(_ENV_MARKERS, ".env")
    if "secrets.json" in key or "credentials.json" in key:
        add(_ENV_MARKERS + ("client_secret", "private_key"), "secrets/credentials.json")
    if "web.config" in key:
        add(_WEB_CONFIG_MARKERS, "web.config")
    if "application.yml" in key or "application.yaml" in key or "application.properties" in key:
        add(_APP_CONFIG_MARKERS, "application config")
    if "wp-config" in key:
        add(_WP_CONFIG_MARKERS, "wp-config.php")
    if "phpinfo" in key or key.endswith("info.php"):
        add(_PHPINFO_MARKERS, "phpinfo")
    if ".git" in key:
        add(_GIT_MARKERS, ".git")
    if "win.ini" in key or "boot.ini" in key:
        add(_WIN_INI_MARKERS, "win.ini")
    if "hosts" in key and ("etc/hosts" in key or "drivers/etc/hosts" in key):
        add(_HOSTS_MARKERS, "hosts")
    if "environ" in key or "proc/self" in key:
        add(_ENVIRON_MARKERS, "proc/environ")
    if ".htaccess" in key:
        add(_HTACCESS_MARKERS, ".htaccess")
    if ".sql" in key or "dump.sql" in key or "database.sql" in key or "db.sql" in key:
        add(_SQL_MARKERS, "SQL dump")
    if "auth.log" in key:
        add(_AUTH_LOG_MARKERS, "auth.log")
    if "proc/version" in key or key.endswith("/version"):
        add(_PROC_VERSION_MARKERS, "proc/version")
    if "nginx.conf" in key or "apache" in key or "httpd.conf" in key:
        add(_NGINX_APACHE_MARKERS, "web server config")
    if "id_rsa" in key or "id_dsa" in key or "authorized_keys" in key or ".ssh" in key:
        add(_SSH_KEY_MARKERS, "SSH private key")
    if "swagger" in key or "openapi" in key or "api-docs" in key:
        add(_SWAGGER_MARKERS, "OpenAPI/Swagger")
    if "actuator" in key:
        add(_ACTUATOR_MARKERS, "Spring actuator")
    if "docker-compose" in key:
        add(_DOCKER_COMPOSE_MARKERS, "docker-compose")
    if ".aws/credentials" in key or "aws/credentials" in key:
        add(_AWS_CRED_MARKERS, "AWS credentials")
    if "laravel.log" in key:
        add(_LARAVEL_LOG_MARKERS, "laravel.log")
    if "tomcat-users" in key:
        add(_TOMCAT_MARKERS, "tomcat-users.xml")
    if "web.xml" in key:
        add(_WEB_XML_MARKERS, "WEB-INF/web.xml")
    if ".npmrc" in key:
        add(_NPMRC_MARKERS, ".npmrc")
    if "package.json" in key:
        add(_PACKAGE_JSON_MARKERS, "package.json")
    if "error.log" in key or "access.log" in key or "debug.log" in key:
        add(("error", "warn", "info", "GET ", "POST ", "HTTP/"), "HTTP access/error log")

    return rules


def _mostly_printable(text: str, *, threshold: float = 0.85) -> bool:
    if not text or len(text) < 2:
        return False
    ok = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return ok / len(text) >= threshold


def extract_pdf_literal_strings(raw: bytes) -> str:
    """Pull readable literal strings from PDF syntax."""
    parts: list[str] = []
    for match in re.finditer(rb"\(([^\\)]*(?:\\.[^\\)]*)*)\)", raw[:2_000_000]):
        try:
            decoded = match.group(1).decode("utf-8", errors="replace")
        except Exception:
            continue
        if _mostly_printable(decoded):
            parts.append(decoded)
    return "\n".join(parts)


def extract_pdf_with_pypdf(raw: bytes) -> str:
    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(raw))
        pages: list[str] = []
        for page in reader.pages[:30]:
            text = page.extract_text()
            if text:
                pages.append(text)
        return "\n".join(pages)
    except Exception:
        return ""


def is_zip_bytes(raw: bytes) -> bool:
    return len(raw) >= 4 and raw[:2] == b"PK" and raw[2:4] in (b"\x03\x04", b"\x05\x06", b"\x07\x08")


def is_gzip_bytes(raw: bytes) -> bool:
    return len(raw) >= 2 and raw[:2] == b"\x1f\x8b"


def is_tar_bytes(raw: bytes) -> bool:
    return len(raw) >= 262 and raw[257:262] == b"ustar"


def extract_searchable_text(body: str | bytes, *, max_bytes: int = 2_000_000) -> str:
    raw = _as_bytes(body, max_bytes=max_bytes)
    chunks: list[str] = [raw.decode("utf-8", errors="replace")]
    if raw.startswith(b"%PDF"):
        chunks.append(extract_pdf_literal_strings(raw))
        chunks.append(extract_pdf_with_pypdf(raw))
    return "\n".join(chunks)


def extract_text_for_leak_scan(body: str | bytes, *, max_bytes: int = 2_000_000) -> str:
    raw = _as_bytes(body, max_bytes=max_bytes)
    if raw.startswith(b"%PDF"):
        pypdf_text = extract_pdf_with_pypdf(raw)
        literal_text = extract_pdf_literal_strings(raw)
        return "\n".join(p for p in (pypdf_text, literal_text) if p)
    return raw.decode("utf-8", errors="replace")


def build_extracted_text_preview(
    leak_scan_text: str,
    *,
    payload_leaks: list[str],
    generic_leaks: list[str],
) -> str:
    text = leak_scan_text or ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    preview_tokens = (
        "root:",
        "daemon:",
        "db_password",
        "app_key",
        "begin rsa",
        "connectionstrings",
        "[extensions]",
        "template/lfi",
        "security diagnosis",
        "define('db",
        "php version",
        '"openapi"',
        "services:",
        "insert into",
    )
    leakish = [ln for ln in lines if any(tok in ln.lower() for tok in preview_tokens)]
    if leakish:
        return " | ".join(leakish[:4])[:480]

    needles = [
        "root:",
        "daemon:",
        "db_password",
        "app_key",
        "-----begin",
        "connectionstrings",
        '"swagger"',
        "insert into",
    ]
    lower = text.lower()
    for needle in needles:
        idx = lower.find(needle)
        if idx >= 0:
            snippet = text[idx : idx + 220]
            cleaned = "".join(c if c.isprintable() or c in "\n\t" else " " for c in snippet)
            return cleaned.strip()[:480]

    readable = [ln for ln in lines if _mostly_printable(ln) and len(ln) >= 8]
    if readable:
        return " | ".join(readable[:3])[:480]
    return ""


def _as_bytes(body: str | bytes, *, max_bytes: int) -> bytes:
    if isinstance(body, bytes):
        return body[:max_bytes]
    return body.encode("utf-8", errors="replace")[:max_bytes]


def _binary_leak_hits(key: str, raw: bytes | None) -> list[str]:
    if not raw:
        return []
    hits: list[str] = []
    if key.endswith(".zip") or "backup.zip" in key or "site.zip" in key:
        if is_zip_bytes(raw):
            hits.append("PK\\x03\\x04 zip header ← expected from zip archive")
    if ".tar.gz" in key or key.endswith(".gz") or "sql.gz" in key:
        if is_gzip_bytes(raw):
            hits.append("\\x1f\\x8b gzip header ← expected from .gz archive")
    if key.endswith(".tar") or "backup.tar" in key:
        if is_tar_bytes(raw) or is_gzip_bytes(raw):
            hits.append("ustar/gzip ← expected from tar archive")
    return hits


def find_payload_leak_markers(payload: str, text: str, *, raw: bytes | None = None) -> list[str]:
    lower = (text or "")[:120_000].lower()
    hits: list[str] = []
    key = _payload_key(payload)

    hits.extend(_binary_leak_hits(key, raw))

    seen: set[str] = set()
    for markers, hint in expected_leak_rules(payload):
        for marker in markers:
            mk = marker.lower()
            if mk in lower and mk not in seen:
                seen.add(mk)
                hits.append(f"{marker} ← expected from {hint}")
    return hits


def text_overlap_ratio(a: str, b: str) -> float:
    wa = {w for w in re.findall(r"[a-zA-Z가-힣]{4,}", (a or "").lower())}
    wb = {w for w in re.findall(r"[a-zA-Z가-힣]{4,}", (b or "").lower())}
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


def find_sensitive_markers(text: str) -> list[str]:
    lower = (text or "")[:120_000].lower()
    return [m for m in GENERIC_SENSITIVE_MARKERS if m in lower]


def analyze_response_text(
    payload: str,
    baseline_body: str | bytes,
    payload_body: str | bytes,
) -> dict[str, Any]:
    baseline_text = extract_searchable_text(baseline_body)
    leak_scan_text = extract_text_for_leak_scan(payload_body)
    payload_raw = _as_bytes(payload_body, max_bytes=2_000_000)

    payload_leaks = find_payload_leak_markers(payload, leak_scan_text, raw=payload_raw)
    generic_leaks = find_sensitive_markers(leak_scan_text)
    overlap = text_overlap_ratio(baseline_text, extract_searchable_text(payload_body))

    preview = build_extracted_text_preview(
        leak_scan_text,
        payload_leaks=payload_leaks,
        generic_leaks=generic_leaks,
    )

    return {
        "payload_leak_markers": payload_leaks,
        "generic_sensitive_markers": generic_leaks,
        "pdf_text_overlap": round(overlap, 3),
        "extracted_text_preview": preview,
    }

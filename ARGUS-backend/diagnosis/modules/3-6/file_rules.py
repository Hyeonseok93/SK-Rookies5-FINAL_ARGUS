"""Classify httpx responses for backup / test file exposure (3-6)."""

from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_MODULE_DIR = Path(__file__).resolve().parent
_G22_DIR = _MODULE_DIR.parent / "2-2"


def _load_g22(name: str):
    path = _G22_DIR / f"{name}.py"
    mod_name = f"diag_g36_g22_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tf = _load_g22("traversal_fuzz")
_ra = _load_g22("response_analysis")

_BACKUP_EXT = frozenset(
    {
        "zip", "tar", "gz", "rar", "7z", "sql", "bak", "old", "backup",
        "dump", "tgz", "bz2", "war", "jar",
    }
)
_TEST_NAME = re.compile(
    r"(?i)(^|/)(test|demo|debug|staging|dev|tmp|temp|phpinfo|info)(\.|$|/)"
)


@dataclass
class FileExposureIssue:
    severity: str
    file_type: str
    reason: str
    trigger: str


def _body_fingerprint(body: str) -> str:
    import re

    return re.sub(r"\s+", " ", (body or "")[:8000].lower()).strip()


def _looks_like_spa_shell(body: str, content_type: str) -> bool:
    ct = content_type.lower()
    if "text/html" not in ct and "application/xhtml" not in ct:
        return False
    head = body[:4000].lower()
    return "<!doctype html" in head or "<html" in head and (
        'id="root"' in head or 'id="app"' in head or "vite" in head or "__next" in head
    )


def _path_category(path: str) -> str:
    key = path.lower().replace("\\", "/")
    segment = key.rsplit("/", 1)[-1]
    if ".env" in key or "secrets" in key or "credentials" in key:
        return "env_secrets"
    if any(x in key for x in (".sql", "dump", "db_backup", "database.sql")):
        return "backup_sql"
    if any(key.endswith(f".{ext}") or f".{ext}." in key for ext in _BACKUP_EXT):
        return "backup_archive"
    if _TEST_NAME.search(key) or "phpinfo" in key:
        return "test_debug"
    if ".git" in key or ".svn" in key:
        return "vcs_artifact"
    if segment.endswith(".log") or "/logs/" in key:
        return "log_file"
    if segment.endswith((".config", ".yml", ".yaml", ".properties", ".json")):
        return "config_backup"
    return "sensitive_file"


def classify_file_response(
    path: str,
    *,
    http_status: int | None,
    body: str,
    content_type: str,
    baseline_body: str = "",
    baseline_fp: str = "",
) -> FileExposureIssue | None:
    if http_status not in (200, 206):
        return None
    if not body and not content_type:
        return None

    headers = {"content-type": content_type}
    suspicious, trigger = _tf.response_suspicious(
        path,
        http_status,
        body,
        headers,
        baseline_headers={"content-type": "text/html"},
    )

    fp = _body_fingerprint(body)
    if baseline_fp and fp == baseline_fp and _looks_like_spa_shell(body, content_type):
        return None

    leak_markers = _ra.find_payload_leak_markers(
        path.lstrip("/"), body, raw=body.encode("utf-8", errors="replace")
    )
    file_type = _path_category(path)

    if leak_markers:
        sample = ", ".join(leak_markers[:3])
        return FileExposureIssue(
            severity="high",
            file_type=file_type,
            reason=f"Sensitive content detected ({sample})",
            trigger=trigger or "payload_target_leak_confirmed",
        )

    if suspicious:
        sev = "high" if file_type in ("env_secrets", "backup_sql", "vcs_artifact") else "medium"
        return FileExposureIssue(
            severity=sev,
            file_type=file_type,
            reason=trigger or "file_reachable",
            trigger=trigger or "file_reachable",
        )

    # Binary / download hints without text leak markers
    ct = content_type.lower()
    if "application/zip" in ct or "application/x-gzip" in ct or "application/sql" in ct:
        return FileExposureIssue(
            severity="high",
            file_type=file_type,
            reason="Downloadable archive/SQL content-type",
            trigger="content_type_download",
        )
    if "attachment" in ct or "application/octet-stream" in ct:
        if file_type.startswith("backup") or file_type == "env_secrets":
            return FileExposureIssue(
                severity="high",
                file_type=file_type,
                reason="Binary attachment on backup/test path",
                trigger="attachment_on_sensitive_path",
            )

    return None


def remediation_hint(file_type: str) -> str:
    hints = {
        "backup_archive": "Remove backup archives from web root; store outside public paths",
        "backup_sql": "Do not expose SQL dumps; restrict access and delete from production",
        "env_secrets": "Remove .env and credential files from public directories",
        "test_debug": "Remove test/debug pages (phpinfo, demo, staging) from production",
        "vcs_artifact": "Block .git/.svn exposure; deploy without VCS metadata",
        "log_file": "Move logs outside web root or deny HTTP access",
        "config_backup": "Remove config backups (.bak/.old) from accessible paths",
    }
    return hints.get(file_type, "Remove backup and test artifacts from publicly reachable URLs")

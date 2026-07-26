"""Dynamic malicious/edge-case upload payload generator (2-1).

Fully data-driven from ``assets/dangerous-extensions.yaml``. Nothing here is
hard-coded to "images" — the allow-list is a config default, and the set of
disallowed extensions/techniques is loaded from the asset file so ops can add
new extensions later without touching this module.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_MODULE_DIR = Path(__file__).resolve().parent
_RULES_PATH = _MODULE_DIR / "assets" / "dangerous-extensions.yaml"

# 1x1 transparent PNG — real magic bytes so polyglot/baseline payloads pass
# naive image-sniffing filters that only check the file header.
PNG_MAGIC = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)

UPLOAD_MARKER = "ARGUS-2-1-UPLOAD-PROBE"

_DEFAULT_RULES: dict[str, Any] = {
    "allowed_extensions_default": ["jpg", "jpeg", "png", "gif", "webp"],
    "disallowed_extensions": [],
}


@dataclass
class UploadPayload:
    payload_id: str
    filename: str
    content: bytes
    content_type: str
    technique: str
    ext: str
    category: str
    expect_reject: bool  # True when a spec-compliant server MUST reject this


def load_extension_rules() -> dict[str, Any]:
    if not _RULES_PATH.is_file():
        return dict(_DEFAULT_RULES)
    raw = yaml.safe_load(_RULES_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return dict(_DEFAULT_RULES)
    return raw


def _script_body(ext: str) -> bytes:
    return f"<!-- {UPLOAD_MARKER} ext={ext} -->\n".encode("utf-8")


def normalize_extensions(raw: list[str] | None) -> list[str]:
    return [str(e).lower().lstrip(".") for e in (raw or []) if str(e).strip()]


def build_baseline_payload(allowed_extensions: list[str]) -> UploadPayload:
    ext = allowed_extensions[0] if allowed_extensions else "png"
    return UploadPayload(
        payload_id=f"baseline-{ext}",
        filename=f"argus-probe.{ext}",
        content=PNG_MAGIC,
        content_type="image/png" if ext != "gif" else "image/gif",
        technique="baseline_valid",
        ext=ext,
        category="control",
        expect_reject=False,
    )


def build_upload_payloads(
    allowed_extensions: list[str] | None = None,
    *,
    rules: dict[str, Any] | None = None,
    include_baseline: bool = True,
) -> list[UploadPayload]:
    """Build the probe matrix: 1 baseline (should succeed) + N disallowed-
    extension bypass techniques (should all be rejected) per dangerous
    extension declared in the asset file.
    """
    raw_rules = rules if rules is not None else load_extension_rules()
    allowed = normalize_extensions(
        allowed_extensions or raw_rules.get("allowed_extensions_default")
    )
    allowed_set = set(allowed)
    allowed_ext = allowed[0] if allowed else "png"

    payloads: list[UploadPayload] = []
    if include_baseline and allowed:
        payloads.append(build_baseline_payload(allowed))

    for entry in raw_rules.get("disallowed_extensions") or []:
        if not isinstance(entry, dict):
            continue
        ext = str(entry.get("ext") or "").lower().lstrip(".")
        if not ext or ext in allowed_set:
            continue
        mime = str(entry.get("mime") or "application/octet-stream")
        category = str(entry.get("category") or "unknown")
        body = _script_body(ext)

        payloads.extend(
            [
                UploadPayload(
                    payload_id=f"{ext}-direct",
                    filename=f"argus-shell.{ext}",
                    content=body,
                    content_type=mime,
                    technique="direct_extension",
                    ext=ext,
                    category=category,
                    expect_reject=True,
                ),
                UploadPayload(
                    payload_id=f"{ext}-mime-spoof",
                    filename=f"argus-shell.{ext}",
                    content=body,
                    content_type="image/png",
                    technique="content_type_spoof",
                    ext=ext,
                    category=category,
                    expect_reject=True,
                ),
                UploadPayload(
                    payload_id=f"{ext}-polyglot-magic",
                    filename=f"argus-shell.{ext}",
                    content=PNG_MAGIC + body,
                    content_type=mime,
                    technique="magic_byte_polyglot",
                    ext=ext,
                    category=category,
                    expect_reject=True,
                ),
                UploadPayload(
                    payload_id=f"{ext}-double-ext",
                    filename=f"argus-shell.{ext}.{allowed_ext}",
                    content=body,
                    content_type=f"image/{allowed_ext}",
                    technique="double_extension",
                    ext=ext,
                    category=category,
                    expect_reject=True,
                ),
                UploadPayload(
                    payload_id=f"{ext}-double-ext-reverse",
                    filename=f"argus-shell.{allowed_ext}.{ext}",
                    content=body,
                    content_type=mime,
                    technique="double_extension_reverse",
                    ext=ext,
                    category=category,
                    expect_reject=True,
                ),
                UploadPayload(
                    payload_id=f"{ext}-null-byte",
                    filename=f"argus-shell.{ext}\x00.{allowed_ext}",
                    content=body,
                    content_type=mime,
                    technique="null_byte",
                    ext=ext,
                    category=category,
                    expect_reject=True,
                ),
                UploadPayload(
                    payload_id=f"{ext}-case-bypass",
                    filename=f"argus-shell.{ext.upper()}",
                    content=body,
                    content_type=mime,
                    technique="case_bypass",
                    ext=ext,
                    category=category,
                    expect_reject=True,
                ),
                UploadPayload(
                    payload_id=f"{ext}-trailing-dot",
                    filename=f"argus-shell.{ext}.",
                    content=body,
                    content_type=mime,
                    technique="trailing_dot",
                    ext=ext,
                    category=category,
                    expect_reject=True,
                ),
            ]
        )

    return payloads

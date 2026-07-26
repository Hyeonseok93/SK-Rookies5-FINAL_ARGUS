"""Compare login failure responses for account enumeration (6-2)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

MESSAGE_KEYS = (
    "message",
    "errorMessage",
    "error_message",
    "detail",
    "title",
    "description",
    "msg",
)
CODE_KEYS = ("code", "errorCode", "error_code", "status")
NESTED_MESSAGE_PATHS = (
    ("error", "message"),
    ("error", "systemMessage"),
    ("error", "detail"),
)
NESTED_CODE_PATHS = (
    ("error", "code"),
    ("error", "errorCode"),
    ("error", "error_code"),
)
_FINGERPRINT_STRIP_RE = re.compile(
    r'"(?:timestamp|time|datetime|createdAt|updatedAt)"\s*:\s*"[^"]*"',
    re.IGNORECASE,
)


def _norm(text: str | None) -> str:
    if not text:
        return ""
    return re.sub(r"\s+", " ", str(text).strip().lower())


def _pick_from_dict(data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        val = data.get(key)
        if val is None:
            continue
        if isinstance(val, (dict, list)):
            continue
        text = str(val).strip()
        if text:
            return text
    return None


def _pick_nested_field(
    data: dict[str, Any],
    paths: tuple[tuple[str, ...], ...],
) -> str | None:
    for path in paths:
        node: Any = data
        for key in path:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(key)
        if node is None or isinstance(node, (dict, list)):
            continue
        text = str(node).strip()
        if text:
            return text
    return None


def _pick_error_code(parsed: dict[str, Any]) -> str | None:
    code = _pick_from_dict(parsed, CODE_KEYS)
    if code:
        return code
    return _pick_nested_field(parsed, NESTED_CODE_PATHS)


def _pick_primary_message(parsed: dict[str, Any]) -> str | None:
    message = _pick_from_dict(parsed, MESSAGE_KEYS)
    if message:
        return message
    return _pick_nested_field(parsed, NESTED_MESSAGE_PATHS)


def _body_fingerprint(body: str) -> str:
    preview = body[:400].replace("\n", " ").strip() if body else ""
    if not preview:
        return ""
    scrubbed = _FINGERPRINT_STRIP_RE.sub('""', preview)
    return _norm(scrubbed)[:240]


def _collect_json_fields(parsed: dict[str, Any]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key in MESSAGE_KEYS + CODE_KEYS:
        val = parsed.get(key)
        if val is not None and not isinstance(val, (dict, list)):
            fields[key] = str(val)[:200]
    nested_code = _pick_nested_field(parsed, NESTED_CODE_PATHS)
    if nested_code:
        fields["error.code"] = nested_code[:200]
    nested_msg = _pick_nested_field(parsed, NESTED_MESSAGE_PATHS)
    if nested_msg:
        fields["error.message"] = nested_msg[:200]
    return fields


def _parse_json_body(body: str) -> dict[str, Any] | None:
    text = body.strip()
    if not text or text[0] not in "{[":
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


@dataclass
class LoginResponseSnapshot:
    scenario: str
    email: str
    http_status: int | None
    primary_message: str | None = None
    error_code: str | None = None
    content_type: str | None = None
    body_preview: str | None = None
    body_fingerprint: str | None = None
    json_fields: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "email": self.email,
            "http_status": self.http_status,
            "primary_message": self.primary_message,
            "error_code": self.error_code,
            "content_type": self.content_type,
            "body_preview": self.body_preview,
            "body_fingerprint": self.body_fingerprint,
            "json_fields": self.json_fields,
            "error": self.error,
        }


def snapshot_from_http(
    *,
    scenario: str,
    email: str,
    status: int | None,
    body: str,
    content_type: str | None,
    error: str | None = None,
) -> LoginResponseSnapshot:
    preview = body[:400].replace("\n", " ").strip() if body else ""
    fingerprint = _body_fingerprint(body)
    primary: str | None = None
    code: str | None = None
    json_fields: dict[str, str] = {}

    parsed = _parse_json_body(body)
    if parsed:
        json_fields = _collect_json_fields(parsed)
        primary = _pick_primary_message(parsed)
        code = _pick_error_code(parsed)

    if not primary and preview:
        primary = preview[:200]

    return LoginResponseSnapshot(
        scenario=scenario,
        email=email,
        http_status=status,
        primary_message=primary,
        error_code=code,
        content_type=content_type,
        body_preview=preview or None,
        body_fingerprint=fingerprint or None,
        json_fields=json_fields,
        error=error,
    )


@dataclass
class ComparisonResult:
    uniform: bool
    differences: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"uniform": self.uniform, "differences": self.differences}


def compare_login_snapshots(
    a: LoginResponseSnapshot,
    b: LoginResponseSnapshot,
    *,
    strict: bool = True,
) -> ComparisonResult:
    diffs: list[str] = []

    if a.error or b.error:
        if a.error != b.error:
            diffs.append(f"probe error: {a.error or 'ok'} vs {b.error or 'ok'}")
        return ComparisonResult(uniform=len(diffs) == 0, differences=diffs)

    if a.http_status != b.http_status:
        diffs.append(f"HTTP status {a.http_status} vs {b.http_status}")

    msg_a = _norm(a.primary_message)
    msg_b = _norm(b.primary_message)
    if msg_a and msg_b and msg_a != msg_b:
        diffs.append(f"message `{a.primary_message}` vs `{b.primary_message}`")
    elif (msg_a or msg_b) and msg_a != msg_b:
        diffs.append(f"message `{a.primary_message or '(empty)'}` vs `{b.primary_message or '(empty)'}`")

    code_a = _norm(a.error_code)
    code_b = _norm(b.error_code)
    if code_a and code_b and code_a != code_b:
        diffs.append(f"error code `{a.error_code}` vs `{b.error_code}`")
    elif strict and (code_a or code_b) and code_a != code_b:
        diffs.append(f"error code `{a.error_code or '(empty)'}` vs `{b.error_code or '(empty)'}`")

    fp_a = a.body_fingerprint or ""
    fp_b = b.body_fingerprint or ""
    if strict and fp_a and fp_b and fp_a != fp_b and not diffs:
        # Body differs but message might be nested — flag if fingerprints diverge strongly
        if abs(len(fp_a) - len(fp_b)) > 30 or fp_a[:80] != fp_b[:80]:
            diffs.append("response body shape differs")

    return ComparisonResult(uniform=len(diffs) == 0, differences=diffs)


SCENARIO_LABELS: dict[str, str] = {
    "exists_wrong_password": "A · exists + wrong PW",
    "nonexistent_wrong_password": "B · missing + wrong PW",
    "nonexistent_valid_password": "C · missing + valid PW",
}


def compare_login_snapshot_set(
    snapshots: list[LoginResponseSnapshot],
    *,
    strict: bool = True,
) -> ComparisonResult:
    """All failure scenarios must match pairwise (A/B/C uniformity)."""
    diffs: list[str] = []
    for i in range(len(snapshots)):
        for j in range(i + 1, len(snapshots)):
            left = snapshots[i]
            right = snapshots[j]
            result = compare_login_snapshots(left, right, strict=strict)
            if result.uniform:
                continue
            left_label = SCENARIO_LABELS.get(left.scenario, left.scenario)
            right_label = SCENARIO_LABELS.get(right.scenario, right.scenario)
            for item in result.differences:
                diffs.append(f"{left_label} vs {right_label}: {item}")
    return ComparisonResult(uniform=len(diffs) == 0, differences=diffs)

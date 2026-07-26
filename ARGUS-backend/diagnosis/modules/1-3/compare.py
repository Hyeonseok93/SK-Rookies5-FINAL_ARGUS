"""Response anomaly 1st-pass detection for guideline 1-3 (rule-based, no LLM).

Ported from ARGUS_Backend/scanners/param_manipulation/comparator.py.

Anomaly patterns:
    PRIVILEGE_BYPASS  baseline 401/403 -> test 200 (auth check bypassed)      -> high
    DATA_EXPOSURE     new JSON key(s) appear in test only                    -> high
    POTENTIAL_IDOR    test 200 + body grew >= 500 bytes vs baseline          -> medium
    ERROR_SUPPRESSED  baseline had error keyword, test (200) has none         -> medium

This module only performs deterministic, LLM-free detection so its runtime stays
bounded. Final severity/description confirmation is done by llm_interpret.py
(Phase 4) — see that module for why the LLM step was pushed there instead of
running before fuzzing (ARGUS_Backend incident: an LLM classification step with
no request timeout hung a celery worker for hours).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from diagnosis.probe_transport import ProbeResponse
from inventory.schema import Endpoint

ERROR_KEYWORDS = ("error", "invalid", "denied", "forbidden", "unauthorized", "exception", "fail")
IDOR_BODY_DELTA_THRESHOLD = 500

SEVERITY = {
    "PRIVILEGE_BYPASS": "high",
    "DATA_EXPOSURE": "high",
    "POTENTIAL_IDOR": "medium",
    "ERROR_SUPPRESSED": "medium",
}


@dataclass
class RawFinding:
    """1st-pass anomaly signal — input to llm_interpret.py's Phase 4 confirmation."""

    ep: Endpoint
    param_in: str
    param_name: str
    category: str          # rule-based category from candidates.py — reused as fallback
    payload_value: str
    payload_description: str
    anomaly_type: str
    anomaly_detail: str
    baseline_status: int | None
    test_status: int | None
    baseline_body: bytes
    test_body: bytes


def detect_anomaly(
    *,
    ep: Endpoint,
    param_in: str,
    param_name: str,
    category: str,
    payload_value: str,
    payload_description: str,
    baseline: ProbeResponse,
    test: ProbeResponse,
) -> RawFinding | None:
    if test.status is None or test.error:
        return None

    anomaly_type: str | None = None
    anomaly_detail = ""

    if baseline.status in (401, 403) and test.status == 200:
        anomaly_type = "PRIVILEGE_BYPASS"
        anomaly_detail = f"원본 응답 {baseline.status} → 조작 후 200 OK (권한 검증 우회 가능성)"
    else:
        new_keys = _new_json_keys(baseline.body, test.body)
        if new_keys and test.status == 200:
            anomaly_type = "DATA_EXPOSURE"
            anomaly_detail = f"조작 후 신규 응답 필드 출현: {new_keys}"
        elif test.status == 200 and len(test.body) - len(baseline.body) > IDOR_BODY_DELTA_THRESHOLD:
            delta = len(test.body) - len(baseline.body)
            anomaly_type = "POTENTIAL_IDOR"
            anomaly_detail = f"응답 크기 {delta:+d}byte 증가 — 타인 자원 노출 가능성"
        elif test.status == 200 and _has_error(baseline.body) and not _has_error(test.body):
            anomaly_type = "ERROR_SUPPRESSED"
            anomaly_detail = "에러 응답이 조작 후 사라짐 — 서버가 조작값을 수용한 것으로 추정"

    if anomaly_type is None:
        return None

    return RawFinding(
        ep=ep,
        param_in=param_in,
        param_name=param_name,
        category=category,
        payload_value=payload_value,
        payload_description=payload_description,
        anomaly_type=anomaly_type,
        anomaly_detail=anomaly_detail,
        baseline_status=baseline.status,
        test_status=test.status,
        baseline_body=baseline.body,
        test_body=test.body,
    )


def _has_error(body: bytes) -> bool:
    text = body.decode("utf-8", errors="replace").lower()
    return any(kw in text for kw in ERROR_KEYWORDS)


def _new_json_keys(baseline_body: bytes, test_body: bytes) -> list[str]:
    try:
        base_keys = set(_all_keys(json.loads(baseline_body.decode("utf-8", errors="replace"))))
        test_keys = set(_all_keys(json.loads(test_body.decode("utf-8", errors="replace"))))
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError):
        return []
    return sorted(test_keys - base_keys)


def _all_keys(obj: Any, prefix: str = "") -> list[str]:
    keys: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else k
            keys.append(full)
            keys.extend(_all_keys(v, full))
    elif isinstance(obj, list):
        for item in obj:
            keys.extend(_all_keys(item, prefix))
    return keys

"""Upload probe verdict helpers for 2-1 malicious file upload scans."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

_URL_KEYS = (
    "imageUrls",
    "imageUrl",
    "urls",
    "url",
    "fileUrl",
    "fileUrls",
    "thumbnailUrl",
    "uploadUrl",
    "uploadedUrl",
    "path",
    "filePath",
)


@dataclass
class UploadCaseResult:
    suite: str
    method: str
    endpoint: str
    filename: str
    attack_desc: str
    status_code: int
    verdict: str  # vulnerable | safe | review | error | skipped
    stored_url: str | None = None
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


def extract_stored_url(response: httpx.Response) -> str | None:
    try:
        res_data = response.json()
    except json.JSONDecodeError:
        return None
    data = res_data.get("data") or res_data
    if not isinstance(data, dict):
        return None
    for key in _URL_KEYS:
        val = data.get(key)
        if val:
            return val[0] if isinstance(val, list) else str(val)
    return None


def judge_upload_response(
    *,
    suite: str,
    method: str,
    endpoint: str,
    filename: str,
    attack_desc: str,
    response: httpx.Response | None,
    error: str | None = None,
) -> UploadCaseResult:
    if error:
        return UploadCaseResult(
            suite=suite,
            method=method,
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            status_code=0,
            verdict="error",
            detail=error,
        )
    assert response is not None
    code = response.status_code
    stored_url = None

    if code in (400, 403, 415):
        return UploadCaseResult(
            suite=suite,
            method=method,
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            status_code=code,
            verdict="safe",
            detail="서버가 파일을 거부했습니다",
        )
    if code == 413:
        return UploadCaseResult(
            suite=suite,
            method=method,
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            status_code=code,
            verdict="safe",
            detail="413 — 크기 제한으로 차단",
        )
    if code == 500:
        return UploadCaseResult(
            suite=suite,
            method=method,
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            status_code=code,
            verdict="safe",
            detail="500 — 서버 예외(파일 미저장 가능)",
        )
    if code == 401:
        return UploadCaseResult(
            suite=suite,
            method=method,
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            status_code=code,
            verdict="review",
            detail="401 인증 실패",
        )
    if code == 404:
        return UploadCaseResult(
            suite=suite,
            method=method,
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            status_code=code,
            verdict="review",
            detail="404 — 엔드포인트/리소스 없음",
        )
    if code == 422:
        return UploadCaseResult(
            suite=suite,
            method=method,
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            status_code=code,
            verdict="review",
            detail=f"422 파라미터 오류: {response.text[:120]}",
        )
    if code not in (200, 201):
        return UploadCaseResult(
            suite=suite,
            method=method,
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            status_code=code,
            verdict="review",
            detail=f"예상치 못한 응답 코드 {code}",
        )

    stored_url = extract_stored_url(response)
    return UploadCaseResult(
        suite=suite,
        method=method,
        endpoint=endpoint,
        filename=filename,
        attack_desc=attack_desc,
        status_code=code,
        verdict="vulnerable",
        stored_url=stored_url,
        detail="서버가 악성 파일 저장을 허용했습니다",
        evidence={"attack": attack_desc, "stored_url": stored_url},
    )


def result_to_finding(result: UploadCaseResult):
    from diagnosis.result import DiagnosisFinding

    if result.verdict == "vulnerable":
        sev = "high"
    elif result.verdict == "review":
        sev = "medium"
    elif result.verdict == "error":
        sev = "low"
    else:
        return None

    msg = (
        f"[{result.suite}] {result.method} {result.endpoint} — "
        f"{result.filename}: {result.detail or result.attack_desc}"
    )
    evidence = {
        "suite": result.suite,
        "method": result.method,
        "endpoint": result.endpoint,
        "filename": result.filename,
        "attack_desc": result.attack_desc,
        "status_code": result.status_code,
        "verdict": result.verdict,
        **result.evidence,
    }
    if result.stored_url:
        evidence["stored_url"] = result.stored_url
    return DiagnosisFinding(severity=sev, message=msg, evidence=evidence)

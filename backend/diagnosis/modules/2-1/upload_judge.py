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
    verdict: str           # vulnerable | safe | review | error | skipped
    stored_url: str | None = None
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    verify: Any | None = None          # VerifyResult | None
    original_content: bytes = field(default_factory=bytes, repr=False)


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


def _run_verify(
    stored_url: str | None,
    filename: str,
    original_content: bytes,
    *,
    timeout: float = 8.0,
) -> Any | None:
    """upload_verify.verify_or_skip을 동적으로 로드하여 실행."""
    try:
        import importlib.util
        from pathlib import Path

        _dir = Path(__file__).resolve().parent
        spec = importlib.util.spec_from_file_location(
            "diag_g21_upload_verify", _dir / "upload_verify.py"
        )
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        import sys
        sys.modules["diag_g21_upload_verify"] = mod
        spec.loader.exec_module(mod)
        return mod.verify_or_skip(
            stored_url,
            filename,
            original_content,
            timeout=timeout,
        )
    except Exception as exc:
        print(f"[2-1][verify] 검증 단계 오류 (non-fatal): {exc}")
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
    original_content: bytes = b"",
    verify_timeout: float = 8.0,
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
            original_content=original_content,
        )
    assert response is not None
    code = response.status_code

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
            original_content=original_content,
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
            original_content=original_content,
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
            original_content=original_content,
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
            original_content=original_content,
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
            original_content=original_content,
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
            original_content=original_content,
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
            original_content=original_content,
        )

    # ── 업로드 성공 (200/201) — 정탐/오탐 검증 실행 ──────────────────────
    stored_url = extract_stored_url(response)

    verify = _run_verify(
        stored_url,
        filename,
        original_content,
        timeout=verify_timeout,
    )

    # 검증 결과에 따라 verdict 세분화
    if verify is not None:
        vverdict = verify.verdict  # "정탐" | "오탐" | "수동검토"
        if vverdict == "정탐":
            final_verdict = "vulnerable"
            detail = f"[정탐] {verify.reason}"
        elif vverdict == "오탐":
            final_verdict = "false_positive"
            detail = f"[오탐] {verify.reason}"
        else:
            final_verdict = "review"
            detail = f"[수동검토] {verify.reason}"
    else:
        # stored_url 없음 → 검증 불가, 업로드 성공만으로 review
        final_verdict = "review"
        detail = "업로드 성공 — 저장 URL 없어 접근 가능 여부 미확인 (수동검토 필요)"

    evidence: dict[str, Any] = {
        "attack": attack_desc,
        "stored_url": stored_url,
    }
    if verify is not None:
        evidence["verification"] = verify.to_dict()

    return UploadCaseResult(
        suite=suite,
        method=method,
        endpoint=endpoint,
        filename=filename,
        attack_desc=attack_desc,
        status_code=code,
        verdict=final_verdict,
        stored_url=stored_url,
        detail=detail,
        evidence=evidence,
        verify=verify,
        original_content=original_content,
    )


def result_to_finding(result: UploadCaseResult):
    from diagnosis.result import DiagnosisFinding

    # verdict → severity 매핑
    SEVERITY_MAP = {
        "vulnerable": "high",       # 정탐 확정
        "false_positive": "low",    # 오탐 (업로드 됐지만 실질적 위험 없음)
        "review": "medium",         # 수동검토 필요
        "error": "low",
    }
    sev = SEVERITY_MAP.get(result.verdict)
    if sev is None:
        return None  # "safe", "skipped" → finding 생성 안 함

    # 메시지 접두사
    PREFIX_MAP = {
        "vulnerable": "🔴 [정탐] 취약",
        "false_positive": "🟢 [오탐] 안전",
        "review": "🟠 [수동검토]",
        "error": "⚠️ [오류]",
    }
    prefix = PREFIX_MAP.get(result.verdict, "")

    msg = (
        f"{prefix} [{result.suite}] {result.method} {result.endpoint} — "
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

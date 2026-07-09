"""Upload probe verdict helpers for 2-1 malicious file upload scans."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, FrozenSet, Optional

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

# 응답에서 URL 노출 여부 확인 시 탐색할 키 목록
_PATH_EXPOSURE_URL_KEYS = _URL_KEYS


@dataclass
class UploadCaseResult:
    suite: str
    method: str
    endpoint: str
    filename: str
    attack_desc: str
    status_code: int
    verdict: str           # vulnerable | safe | review | error | skipped | false_positive
    stored_url: str | None = None
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    verify: Any | None = None          # VerifyResult | None
    original_content: bytes = field(default_factory=bytes, repr=False)
    path_exposed: bool = False         # 응답에 파일 경로/URL이 노출됐는지 여부


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


def check_path_exposure(response: httpx.Response) -> tuple[bool, str | None]:
    """
    응답 body에 파일 경로 또는 URL이 포함되어 있는지 확인합니다. (조건 2)

    Returns:
        (exposed: bool, exposed_url: str | None)
    """
    try:
        res_data = response.json()
    except json.JSONDecodeError:
        return False, None

    data = res_data.get("data") or res_data
    if not isinstance(data, dict):
        return False, None

    for key in _PATH_EXPOSURE_URL_KEYS:
        val = data.get(key)
        if val:
            url = val[0] if isinstance(val, list) else str(val)
            return True, url
    return False, None


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
    allowed_extensions: Optional[FrozenSet[str]] = None,
) -> UploadCaseResult:
    """
    업로드 응답을 분석하여 취약점 여부를 판정합니다.

    판정 우선순위:
    1. 요청 오류 → error
    2. 서버가 명시적으로 거부 (400/403/413/415/500) → safe
    3. 서버가 위험 확장자 파일을 수락 (200/201) → vulnerable  [조건 1]
       + 응답에 파일 경로 노출 여부 → path_exposed 플래그  [조건 2]
    4. 서버가 안전 확장자(이미지)를 수락하되 내용 검증 → follow-up GET
    """
    from security_rules import ALLOWED_IMAGE_EXTENSIONS, is_dangerous_extension

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

    # ── 명시적 거부 코드 → safe ───────────────────────────────────────────
    if code in (400, 403, 415):
        return UploadCaseResult(
            suite=suite,
            method=method,
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            status_code=code,
            verdict="safe",
            detail=f"서버가 파일을 거부했습니다 (HTTP {code})",
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

    # ── 업로드 성공 (200/201) ─────────────────────────────────────────────
    # [조건 2] 응답에 파일 경로/URL 노출 여부 확인
    path_exposed, exposed_url = check_path_exposure(response)

    # [조건 1] 위험 확장자 파일이 수락됐는지 확인
    # 서버가 확장자/MIME 검증 없이 수락했다면 그 자체가 취약점
    effective_allowed = allowed_extensions if allowed_extensions is not None else ALLOWED_IMAGE_EXTENSIONS
    if is_dangerous_extension(filename, allowed_extensions=effective_allowed):
        # 위험 확장자 + 200/201 = 서버가 확장자 검증을 수행하지 않음 → 취약
        detail_parts = [
            f"서버가 위험 확장자 파일을 수락함 (HTTP {code})",
            f"공격 파일: {filename}",
        ]
        if path_exposed and exposed_url:
            detail_parts.append(f"[조건 2] 파일 경로 응답에 노출됨: {exposed_url}")

        return UploadCaseResult(
            suite=suite,
            method=method,
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            status_code=code,
            verdict="vulnerable",
            stored_url=exposed_url,
            detail=" / ".join(detail_parts),
            evidence={
                "attack": attack_desc,
                "stored_url": exposed_url,
                "path_exposed": path_exposed,
                "dangerous_extension": filename.rsplit(".", 1)[-1].lower() if "." in filename else "",
                "condition_1": "확장자 검증 미비 — 서버가 위험 확장자 파일을 차단하지 않음",
                "condition_2": f"파일 경로 노출: {exposed_url}" if path_exposed else "파일 경로 미노출",
            },
            path_exposed=path_exposed,
            original_content=original_content,
        )

    # ── 안전한 확장자(이미지 등) 파일 → follow-up GET으로 내용 검증 ───────
    stored_url = exposed_url or extract_stored_url(response)

    verify = _run_verify(
        stored_url,
        filename,
        original_content,
        timeout=verify_timeout,
    )

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
        final_verdict = "review"
        detail = "업로드 성공 — 저장 URL 없어 접근 가능 여부 미확인 (수동검토 필요)"

    evidence: dict[str, Any] = {
        "attack": attack_desc,
        "stored_url": stored_url,
        "path_exposed": path_exposed,
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
        path_exposed=path_exposed,
        original_content=original_content,
    )


def result_to_finding(result: UploadCaseResult):
    from diagnosis.result import DiagnosisFinding

    # verdict → severity 매핑
    SEVERITY_MAP = {
        "vulnerable": "high",       # 정탐 확정
        "review": "medium",         # 수동검토 필요
        "error": "low",
    }
    sev = SEVERITY_MAP.get(result.verdict)
    if sev is None:
        return None  # "safe", "skipped", "false_positive" → finding 생성 안 함

    # 메시지 접두사
    PREFIX_MAP = {
        "vulnerable": "🔴 [정탐] 취약",
        "review": "🟠 [수동검토]",
        "error": "⚠️ [오류]",
    }
    prefix = PREFIX_MAP.get(result.verdict, "")

    # 경로 노출 표시 추가
    path_tag = " 📂[경로노출]" if result.path_exposed else ""

    msg = (
        f"{prefix}{path_tag} [{result.suite}] {result.method} {result.endpoint} — "
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
        "path_exposed": result.path_exposed,
        **result.evidence,
    }
    if result.stored_url:
        evidence["stored_url"] = result.stored_url

    return DiagnosisFinding(severity=sev, message=msg, evidence=evidence)

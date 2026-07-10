"""
reflected_engine.py — 1-5(검증되지 않은 리다이렉트와 포워드, Reflected 전용) Phase 2+3 오케스트레이터
(ARGUS_Backend scanners/redirect_forward/engine.py 포트)

이 파일은 파라미터 "수집"(Phase 1, ZAP Ajax Spider/Swagger 크롤링)은 포함하지 않는다 —
이 모듈 폴더의 다른 파일(scanner.py/targets.py 등)이 이미 수집해 둔 파라미터 목록을
ReflectedParam 형태로 넘겨받아 후보 선별(Phase 2) + 페이로드 주입/판별(Phase 3)만 수행한다.

사용 예:
    from .reflected_engine import run_reflected_probe

    findings = run_reflected_probe(params)  # params: list[ReflectedParam]
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    """1-5 폴더는 이름에 하이픈이 있어 정식 패키지가 아니다 — scanner.py와 동일하게
    importlib로 동적 로딩해 sibling 모듈을 참조한다."""
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g15_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


select_candidates = _load_local("reflected_candidates").select_candidates
probe_candidate = _load_local("reflected_detector").probe_candidate
_models = _load_local("reflected_models")
ReflectedParam = _models.ReflectedParam
RedirectFinding = _models.RedirectFinding
DEFAULT_PAYLOAD_HOST = _load_local("reflected_payloads").DEFAULT_PAYLOAD_HOST


def run_reflected_probe(
    params:         list[ReflectedParam],
    payload_host:   str = DEFAULT_PAYLOAD_HOST,
    custom_header:  str = None,
) -> list[RedirectFinding]:
    """
    1-5(Reflected) Phase 2+3 진입점.

    Args:
        params:         이미 수집된 파라미터 목록 (ReflectedParam)
        payload_host:   리다이렉트 목적지로 주입할 미검증 외부 호스트
        custom_header:  인증 헤더/쿠키 등 요청에 그대로 실어 보낼 헤더 문자열

    Returns:
        List[RedirectFinding] — confirmed_redirect=True(확정 리다이렉트/포워드)와
        confirmed_redirect=False(반사만 확인됨, 참고용)가 섞인 전체 목록.
    """
    if not params:
        logger.info("[1-5][Phase 1] 수집된 파라미터 없음 — 종료")
        return []

    logger.info("[1-5][Phase 2] 후보 파라미터 선별 시작")
    candidates = select_candidates(params)
    if not candidates:
        logger.info("[1-5][Phase 2] 리다이렉트/포워드 후보 없음 — 종료")
        return []

    logger.info("[1-5][Phase 3] 페이로드 주입 및 Reflected 판별 시작")
    findings: list[RedirectFinding] = []
    for candidate in candidates:
        findings.extend(probe_candidate(candidate, payload_host=payload_host, custom_header=custom_header))

    confirmed = [f for f in findings if f.confirmed_redirect]
    reflected_only = [f for f in findings if not f.confirmed_redirect]
    high_count   = sum(1 for f in confirmed if f.severity == "HIGH")
    medium_count = sum(1 for f in confirmed if f.severity == "MEDIUM")
    logger.info(
        f"[1-5][완료] 후보 {len(candidates)}건 검사 — "
        f"확정 리다이렉트/포워드 findings: {len(confirmed)}건 (HIGH: {high_count}, MEDIUM: {medium_count}) / "
        f"반사만 확인된 참고 findings: {len(reflected_only)}건 (리다이렉트 실행 증거 없음, 1-5 확정 아님)"
    )

    return findings

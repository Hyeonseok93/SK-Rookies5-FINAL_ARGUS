"""
reflected_bridge.py — scanner.py의 phase A/B job과 reflected_* 포트 코드를 연결하는 어댑터.

scanner.py는 이미 자체 "sink" 토큰 방식으로 서버 사이드 open redirect(Location 헤더)를
검증하고 있다(targets.py + probes.run_redirect_jobs + redirect_rules.is_external_open_redirect).
하지만 그 sink 방식은 단일 고정 외부 URL 하나만 넣어 보는 방식이라, reflected_payloads.py가
만드는 화이트리스트 우회형 페이로드(protocol-relative `//host`, 역슬래시 `/\\host`,
`https:host` 콜론 트릭, 서브도메인 위장, `@` userinfo 등)는 전혀 시도하지 않는다 — 즉
"허용 도메인 문자열 포함 여부만 검사하는" 얕은 화이트리스트는 sink 방식으로는 절대 못 잡고
이 우회 페이로드들로만 잡힌다. 예전에는 LOCATION_HEADER 탐지 타입 전체를 "sink 방식과
중복"이라는 이유로 걸러냈지만, 그 결과 이 페이로드들이 실제로 유발하는 Location 헤더 반영을
전부 버리게 되어 리다이렉트/포워드 성 취약점을 사실상 하나도 못 잡는 문제가 있었다. 이제는
detection_type을 걸러내지 않고 네 가지 전부 확인한다:
    - LOCATION_HEADER   (3xx 응답의 Location 헤더 — 우회 페이로드로만 드러나는 케이스 포함)
    - META_REFRESH      (<meta http-equiv="refresh" ... url=...>)
    - JS_REDIRECT       (location.href / location.replace() / .assign())
    - REFLECTED_VALUE   (리다이렉트 실행 증거 없이 값만 그대로 반사됨 — 참고용, confirmed_redirect=False)
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Any

from diagnosis.result import DiagnosisFinding

logger = logging.getLogger(__name__)

_MODULE_DIR = Path(__file__).resolve().parent
_MAX_WORKERS = 32


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g15_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _content_type_of(headers: dict[str, str] | None) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == "content-type":
            return str(value)
    return ""


def _job_to_param(job: dict[str, Any], models_mod) -> Any:
    return models_mod.ReflectedParam(
        url=str(job.get("baseline_url") or job.get("test_url") or ""),
        method=str(job.get("method") or "GET"),
        param_name=str(job.get("param_name") or ""),
        param_value="",  # phase A/B 모두 원본 값 유무가 제각각이라 빈 값으로 시작 — _send()가 매 호출마다 이 필드를 페이로드 값으로 덮어쓴다
        param_type=str(job.get("param_in") or "query"),
        content_type=_content_type_of(job.get("headers")),
        raw_body=str(job.get("baseline_body") or job.get("body") or ""),
        # job["headers"]에는 scanner.py가 미리 조회해둔 로그인 세션의 Authorization/
        # Cookie가 들어 있다 — 이걸 안 넘기면 인증이 필요한 엔드포인트는 전부 401로
        # 막혀 반사/리다이렉트/XSS 판별 자체가 불가능해진다.
        extra_headers={str(k): str(v) for k, v in (job.get("headers") or {}).items()},
    )


def _to_diagnosis_finding(finding: Any, *, rule_id: str) -> DiagnosisFinding:
    return DiagnosisFinding(
        severity=finding.severity.lower(),
        # 응답 본문 스니펫(evidence)은 길이가 들쭉날쭉하고 payload 도중에 잘릴 수 있어
        # 한 줄 메시지에 넣지 않는다 — 전체 스니펫은 evidence_snippet으로 상세 화면에서
        # 확인한다. 메시지는 무엇이 어떻게 반사됐는지만 요약한다.
        message=(
            f"{finding.detection_type} ({'확정' if finding.confirmed_redirect else '반사만 확인, 리다이렉트 실행 증거 없음'}): "
            f"'{finding.param_name}' 파라미터에 페이로드 '{finding.payload_used}'가 이스케이프 없이 반사됨"
        ),
        evidence={
            "rule_id": rule_id,
            "trigger": finding.detection_type.lower(),
            "engine": "reflected_probe",
            # _dedupe_redirect_findings()는 rule_id|engine|test_url|location 조합으로
            # 키를 만든다 — 같은 url이라도 파라미터/탐지유형/페이로드가 다르면 서로 다른
            # finding이므로, test_url/location에 그 구분값을 실어 오탐 중복제거를 막는다.
            "test_url": f"{finding.url}#{finding.param_name}",
            "location": f"{finding.detection_type}:{finding.payload_used}",
            "confirmed_redirect": finding.confirmed_redirect,
            "url": finding.url,
            "method": finding.method,
            "param_name": finding.param_name,
            "payload_used": finding.payload_used,
            "payload_description": finding.payload_description,
            "baseline_status": finding.baseline_status,
            "test_status": finding.test_status,
            "evidence_snippet": finding.evidence,
            "description": finding.description,
            "recommendation": finding.recommendation,
            "request_body": finding.request_body,
            "related_sections": ["1-5"],
        },
    )


def _jobs_to_candidates(jobs: list[dict[str, Any]], models_mod) -> list[Any]:
    candidates = []
    for job in jobs:
        if not str(job.get("param_name") or ""):
            continue
        param = _job_to_param(job, models_mod)
        candidates.append(models_mod.RedirectCandidate(
            collected=param,
            reason="scanner.py phase A/B job (이미 선별된 파라미터)",
        ))
    return candidates


def count_login_redirect_candidates(jobs: list[dict[str, Any]]) -> int:
    """진행률 계산용 — 브라우저를 실제로 띄우지 않고 로그인 문맥 후보 수만 센다.

    scanner.py(수정 대상 아님)는 이 반환값으로 grand_total을 계산하고 이 호출을
    try/except로 감싸지 않는다 — 여기서 예외가 새어나가면 이 함수 뒤에 실행되는
    리다이렉트/CORS/crossdomain 검사까지 전부 중단된다. reflected 기능 쪽 버그가
    기존 검사에 영향을 주면 안 되므로 여기서 끝까지 방어하고 실패 시 0을 반환한다.
    """
    try:
        models_mod = _load_local("reflected_models")
        browser_mod = _load_local("reflected_browser_verify")
        candidates = _jobs_to_candidates(jobs, models_mod)
        return len(browser_mod.select_login_redirect_candidates(candidates))
    except Exception as exc:
        logger.warning(f"[1-5][reflected] 로그인 후보 집계 실패 — 0으로 대체: {exc}")
        return 0


def run_on_jobs(
    jobs: list[dict[str, Any]],
    *,
    payload_host: str | None = None,
    custom_header: str | None = None,
    on_progress: Any = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """scanner.py의 phase A/B job 목록을 받아 LOCATION_HEADER/META_REFRESH/JS_REDIRECT/
    REFLECTED_VALUE를 확인한다.

    job 하나당 baseline 1회 + 페이로드 최대 13회(build_payloads 참조), 즉 최대 14회의
    HTTP 요청이 필요하다. job이 최대 수백~1200개까지 생길 수 있어(targets.py의
    max_phase_a_jobs/max_phase_b_jobs) 순차 실행하면 수만 건의 블로킹 요청이 되어
    비현실적으로 느려진다 — job마다 완전히 독립적인 요청이므로 스레드풀로 병렬 처리한다.

    scanner.py(수정 대상 아님)는 이 호출을 try/except로 감싸지 않는다 — 여기서 예외가
    새어나가면 이 함수 뒤에 실행되는 브라우저 검증/CORS/crossdomain 검사까지 전부
    중단되므로, job 단위 실패뿐 아니라 준비 단계(모듈 로딩 등) 실패도 이 함수 안에서
    끝까지 방어하고 지금까지 모은 결과만 반환한다.
    """
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "jobs": len(jobs),
        "probed": 0,
        "confirmed": 0,       # LOCATION_HEADER / META_REFRESH / JS_REDIRECT (confirmed_redirect=True)
        "reflected_only": 0,  # REFLECTED_VALUE (confirmed_redirect=False, 참고용)
    }

    try:
        models_mod = _load_local("reflected_models")
        detector_mod = _load_local("reflected_detector")
        payloads_mod = _load_local("reflected_payloads")

        host = payload_host or payloads_mod.DEFAULT_PAYLOAD_HOST

        total = len(jobs)
        fuzzable_jobs = [job for job in jobs if str(job.get("param_name") or "")]
        stats["probed"] = len(fuzzable_jobs)

        done = 0
        lock = Lock()

        def _report(job: dict[str, Any] | None) -> None:
            nonlocal done
            if not on_progress:
                return
            with lock:
                done += 1
                local_done = done
            endpoint_id = str(job.get("test_url") or "")[:80] if job else ""
            on_progress(endpoints_done=local_done, endpoints_total=total, endpoint_id=endpoint_id)

        skipped = total - len(fuzzable_jobs)
        for _ in range(skipped):
            _report(None)

        def _probe_one(job: dict[str, Any]) -> list[Any]:
            param = _job_to_param(job, models_mod)
            candidate = models_mod.RedirectCandidate(
                collected=param,
                reason="scanner.py phase A/B job (이미 선별된 파라미터)",
            )
            return detector_mod.probe_candidate(candidate, payload_host=host, custom_header=custom_header)

        # xss_detector용 run_xss_on_jobs와 동일한 이유로 endpoint(base_url+path) 단위로
        # 묶어 그룹 내부는 순차, 그룹 간에는 병렬로 처리한다 — profile처럼 PATCH가 리소스
        # 전체를 덮어쓰는 API에서 같은 리소스의 다른 필드를 동시에 테스트하는 job끼리
        # 서로의 쓰기를 지워버리는 걸 막는다.
        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for job in fuzzable_jobs:
            key = (str(job.get("base_url") or ""), str(job.get("path") or job.get("test_url") or ""))
            groups.setdefault(key, []).append(job)

        def _probe_group(group_jobs: list[dict[str, Any]]) -> list[tuple[dict[str, Any], list[Any]]]:
            return [(job, _probe_one(job)) for job in group_jobs]

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = [pool.submit(_probe_group, group_jobs) for group_jobs in groups.values()]
            for future in as_completed(futures):
                try:
                    group_results = future.result()
                except Exception as exc:
                    logger.warning(f"[1-5][reflected] 그룹 처리 실패: {exc}")
                    continue
                for job, job_findings in group_results:
                    for finding in job_findings:
                        if finding.confirmed_redirect:
                            stats["confirmed"] += 1
                        else:
                            stats["reflected_only"] += 1
                        findings.append(_to_diagnosis_finding(finding, rule_id="1-5-reflected-probe"))
                    _report(job)
    except Exception as exc:
        logger.warning(f"[1-5][reflected] run_on_jobs 실패 — 지금까지 모은 결과만 반환: {exc}")
        stats["error"] = str(exc)[:200]

    return findings, stats


def _to_xss_diagnosis_finding(finding: Any) -> DiagnosisFinding:
    return DiagnosisFinding(
        severity=finding.severity.lower(),
        # 응답 본문 스니펫(evidence)은 길이가 들쭉날쭉하고 payload 도중에 잘릴 수 있어
        # 한 줄 메시지에 넣지 않는다 — 전체 스니펫은 evidence_snippet으로 상세 화면에서
        # 확인한다. 메시지는 무엇이 어떻게 반사됐는지만 요약한다.
        message=(
            f"REFLECTED_XSS ({'확정' if finding.confirmed else '반사만 확인, HTML 컨텍스트 아님'}): "
            f"'{finding.param_name}' 파라미터에 페이로드 '{finding.payload_used}'가 이스케이프 없이 반사됨"
        ),
        evidence={
            "rule_id": "1-5-reflected-xss-probe",
            "trigger": "reflected_xss",
            "engine": "xss_probe",
            "test_url": f"{finding.url}#{finding.param_name}",
            "location": f"REFLECTED_XSS:{finding.payload_used}",
            "confirmed_redirect": finding.confirmed,
            "url": finding.url,
            "method": finding.method,
            "param_name": finding.param_name,
            "payload_used": finding.payload_used,
            "payload_description": finding.payload_description,
            "baseline_status": finding.baseline_status,
            "test_status": finding.test_status,
            "content_type": finding.content_type,
            "stored": finding.stored,
            "evidence_snippet": finding.evidence,
            "description": finding.description,
            "recommendation": finding.recommendation,
            "request_body": finding.request_body,
            "related_sections": ["1-5", "1-1"],
        },
    )


def run_xss_on_jobs(
    jobs: list[dict[str, Any]],
    *,
    marker: str,
    custom_header: str | None = None,
    on_progress: Any = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """scanner.py의 phase A/B job 목록을 재사용해 posts/comments/profile 같은 일반 CRUD
    필드에서 스크립트/HTML 인젝션 페이로드가 이스케이프 없이 반사되는지 확인한다
    (reflected_detector.py의 리다이렉트 판별과 별개의 XSS 전용 판별 — xss_detector.py).

    scanner.py(수정 대상 아님)는 이 호출을 try/except로 감싸지 않는다 — run_on_jobs()와
    동일하게, 여기서 예외가 새어나가면 이 함수 뒤에 실행되는 브라우저 검증/CORS/
    crossdomain 검사까지 전부 중단되므로 준비 단계 실패까지 포함해 끝까지 방어하고
    지금까지 모은 결과만 반환한다.
    """
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "jobs": len(jobs),
        "probed": 0,
        "confirmed": 0,   # text/html 응답에 그대로 반사 — 확정 반사형 XSS
        "candidate": 0,   # HTML이 아닌 응답(JSON 등)에 반사 — 프런트엔드 렌더링 확인 필요
    }

    try:
        models_mod = _load_local("reflected_models")
        detector_mod = _load_local("xss_detector")

        total = len(jobs)
        fuzzable_jobs = [job for job in jobs if str(job.get("param_name") or "")]
        stats["probed"] = len(fuzzable_jobs)

        done = 0
        lock = Lock()

        def _report(job: dict[str, Any] | None) -> None:
            nonlocal done
            if not on_progress:
                return
            with lock:
                done += 1
                local_done = done
            endpoint_id = str(job.get("test_url") or "")[:80] if job else ""
            on_progress(endpoints_done=local_done, endpoints_total=total, endpoint_id=endpoint_id)

        skipped = total - len(fuzzable_jobs)
        for _ in range(skipped):
            _report(None)

        def _probe_one(job: dict[str, Any]) -> list[Any]:
            param = _job_to_param(job, models_mod)
            candidate = models_mod.RedirectCandidate(
                collected=param,
                reason="scanner.py phase A/B job (이미 선별된 파라미터)",
            )
            # marker에 job별 probe_id를 섞어 job마다 고유하게 만든다 — 전체 job이 같은
            # marker를 쓰면, 쓰기(POST/PATCH) job이 저장한 payload를 완전히 무관한 다른
            # job(예: memberId 쿼리 파라미터)이 같은 목록 조회 응답에서 우연히 보고
            # "반사됨"으로 오탐할 수 있다. 정확한 문자열이 job마다 달라지면 이 오탐 자체가
            # 원천적으로 불가능해진다.
            job_marker = f"{marker}{job.get('probe_id') or ''}"
            return detector_mod.probe_candidate_xss(candidate, marker=job_marker, custom_header=custom_header)

        # 같은 endpoint(base_url+path)를 대상으로 하는 job들을 병렬로 돌리면, profile
        # 수정처럼 "PATCH가 리소스 전체를 통째로 덮어쓰는" API에서 서로 다른 job이 서로의
        # 쓰기를 덮어써버린다 (예: name job이 쓴 값을 뒤이은 email job의 PATCH가 자신의
        # baseline 값으로 되돌려버려, name job의 read-back이 빈손이 됨). endpoint 단위로
        # 묶어 그룹 내부는 순차, 그룹 간에는 병렬로 처리해 같은 리소스를 대상으로 한
        # job끼리는 서로 겹치지 않게 한다.
        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for job in fuzzable_jobs:
            key = (str(job.get("base_url") or ""), str(job.get("path") or job.get("test_url") or ""))
            groups.setdefault(key, []).append(job)

        def _probe_group(group_jobs: list[dict[str, Any]]) -> list[tuple[dict[str, Any], list[Any]]]:
            return [(job, _probe_one(job)) for job in group_jobs]

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = [pool.submit(_probe_group, group_jobs) for group_jobs in groups.values()]
            for future in as_completed(futures):
                try:
                    group_results = future.result()
                except Exception as exc:
                    logger.warning(f"[1-5][xss] 그룹 처리 실패: {exc}")
                    continue
                for job, job_findings in group_results:
                    for finding in job_findings:
                        if finding.confirmed:
                            stats["confirmed"] += 1
                        else:
                            stats["candidate"] += 1
                        findings.append(_to_xss_diagnosis_finding(finding))
                    _report(job)
    except Exception as exc:
        logger.warning(f"[1-5][xss] run_xss_on_jobs 실패 — 지금까지 모은 결과만 반환: {exc}")
        stats["error"] = str(exc)[:200]

    return findings, stats


def run_login_redirect_browser_check(
    jobs: list[dict[str, Any]],
    *,
    payload_host: str | None = None,
    cookies: dict[str, str] | None = None,
    on_progress: Any = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """
    scanner.py의 phase A/B job 중 로그인/인증 문맥 URL만 골라 실제 헤드리스 브라우저로
    클라이언트 사이드(JS) 리다이렉트를 검증한다 (reflected_detector.py의 정적 문자열
    매칭으로는 SPA의 로그인 후 JS 리다이렉트를 원리적으로 잡을 수 없어서 보강한다).

    scanner.py(수정 대상 아님)는 이 호출도 try/except로 감싸지 않는다 — 여기서 예외가
    새어나가면 이 함수 뒤에 실행되는 CORS/crossdomain 검사까지 전부 중단되므로,
    reflected_browser_verify.run_login_redirect_browser_check 내부의 브라우저 실행
    실패 방어와 별개로 준비 단계(모듈 로딩, 후보 변환) 실패도 여기서 끝까지 방어한다.
    """
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {"candidates": 0, "confirmed": 0}
    try:
        models_mod = _load_local("reflected_models")
        payloads_mod = _load_local("reflected_payloads")
        browser_mod = _load_local("reflected_browser_verify")

        host = payload_host or payloads_mod.DEFAULT_PAYLOAD_HOST
        candidates = _jobs_to_candidates(jobs, models_mod)

        raw_findings, stats = browser_mod.run_login_redirect_browser_check(
            candidates, payload_host=host, cookies=cookies, on_progress=on_progress,
        )
        findings = [_to_diagnosis_finding(f, rule_id="1-5-client-redirect-browser") for f in raw_findings]
    except Exception as exc:
        logger.warning(f"[1-5][reflected] 브라우저 리다이렉트 검증 실패 — 건너뜀: {exc}")
        stats["error"] = str(exc)[:200]

    return findings, stats

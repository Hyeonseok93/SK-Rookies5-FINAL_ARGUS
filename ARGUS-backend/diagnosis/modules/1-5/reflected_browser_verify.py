"""
reflected_browser_verify.py — 로그인/인증 흐름의 클라이언트 사이드(JS) 리다이렉트를
실제 브라우저(Playwright)로 검증한다.

배경:
    reflected_detector.py의 META_REFRESH/JS_REDIRECT/REFLECTED_VALUE는 httpx로 받은
    "정적" 응답 문자열에서 패턴을 찾는다 — SPA(React 등)에서는 `?next=`/`?returnUrl=`
    같은 값이 서버 응답 HTML에 그대로 박히지 않고, 브라우저에 로드된 JS가 로그인 성공
    후 `window.location.search`를 읽어 그때 가서 location을 대입한다. 이 경우 서버는
    쿼리 파라미터와 무관하게 항상 같은 정적 index.html을 돌려주므로, 정적 문자열
    매칭으로는 원리적으로 잡을 수 없다 (JS가 실제로 실행돼야만 관찰 가능한 동작).

    diagnosis/replay/runner.py의 _BrowserSession과 동일한 Playwright 연동 방식
    (headless chromium, context.add_cookies로 인증 쿠키 주입, page.goto)을 따른다.

역할:
    - select_login_redirect_candidates: reflected_candidates.py가 이미 골라낸 후보 중
      로그인/인증 문맥(URL에 login/auth/signin 포함)인 것만 추린다 — 브라우저 실행은
      느리므로 전체 후보(수백~수천)가 아니라 이 소수 집합에만 적용한다.
    - verify_client_redirect: 후보 하나에 대해 실제 브라우저로 payload_host를 주입한
      URL을 로드하고, 최종 페이지 URL이 payload_host로 이동했는지 확인한다. 이동했다면
      JS가 실제로 실행되어 리다이렉트를 수행했다는 확정 증거이므로
      confirmed_redirect=True로 표시한다.
"""

from __future__ import annotations

import importlib.util
import logging
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

logger = logging.getLogger(__name__)

_MODULE_DIR = Path(__file__).resolve().parent

_LOGIN_CONTEXT_RE = re.compile(r"login|signin|sign-in|auth", re.IGNORECASE)

_GUIDE_REFERENCE = "SK Shieldus Web/API 개발보안 Guideline v3.0.0 항목 1-5 대응방안 참조"


def _raise_if_cancelled() -> None:
    from app.services import diagnosis_progress as dp
    from diagnosis.exceptions import DiagnosisCancelled

    if dp.is_cancel_requested():
        raise DiagnosisCancelled("User cancelled diagnosis")


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


RedirectFinding = _load_local("reflected_models").RedirectFinding


def select_login_redirect_candidates(candidates: list[Any]) -> list[Any]:
    """이미 선별된 RedirectCandidate 중 로그인/인증 문맥 URL만 추린다."""
    return [c for c in candidates if _LOGIN_CONTEXT_RE.search(c.collected.url or "")]


def _url_with_param(base_url: str, param_name: str, value: str) -> str:
    parsed = urlparse(base_url)
    qs = {k: v[0] if v else "" for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    qs[param_name] = value
    return urlunparse(parsed._replace(query=urlencode(qs)))


def _cookies_for_playwright(cookies: dict[str, str] | None, domain: str) -> list[dict[str, Any]]:
    """세션 쿠키 dict({name: value})를 Playwright add_cookies가 받는 형태로 바꾼다."""
    if not cookies:
        return []
    host = domain.split(":")[0]
    return [
        {"name": name, "value": value, "domain": host, "path": "/"}
        for name, value in cookies.items()
        if name and value
    ]


def verify_client_redirect(
    candidate: Any,
    payload_host: str,
    *,
    browser: Any,
    cookies: dict[str, str] | None = None,
    timeout_ms: int = 8000,
) -> Any | None:
    """
    실제 헤드리스 브라우저로 후보 URL(+ payload 주입)을 로드하고, 로드 완료 후 최종
    페이지 URL이 payload_host로 이동했는지 확인한다.

    browser는 호출측(run_login_redirect_browser_check)이 후보 전체에 대해 딱 한 번만
    launch해서 넘겨준다 — 후보마다 새로 launch하면 브라우저 프로세스 기동 자체가
    후보 하나당 1~2초씩 추가되어 후보 수가 늘수록 선형으로 느려진다.

    Returns:
        RedirectFinding(detection_type="CLIENT_JS_CONFIRMED", confirmed_redirect=True) — 확인됨
        None — 타임아웃/이동 안 함 (조용히 실패, 상위 로직에 영향 없음)
    """
    c = candidate.collected
    payload_val = f"https://{payload_host}/"
    test_url = _url_with_param(c.url, c.param_name, payload_val)

    try:
        context = browser.new_context(viewport={"width": 1280, "height": 900})
        try:
            context.add_cookies(_cookies_for_playwright(cookies, urlparse(c.url).netloc))
            page = context.new_page()
            # "networkidle"은 웹소켓/폴링 연결이 계속 열려 있는 SPA에서는 영영 도달하지
            # 않아 매 후보마다 timeout_ms 전체를 그대로 소모한다 — 리다이렉트 여부 판단에는
            # DOM 로드 이후 클라이언트 JS가 location을 대입할 시간만 있으면 충분하므로
            # "domcontentloaded"로 대기하고 짧게 한 번 더 유예를 준다.
            page.goto(test_url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.wait_for_timeout(500)
            final_url = page.url
        finally:
            context.close()
    except Exception as exc:
        logger.debug(f"[1-5][browser-verify] 페이지 로드 실패 {test_url}: {exc}")
        return None

    # final_url 전체 문자열에서 payload_host를 찾으면 안 된다 — 리다이렉트가 전혀
    # 일어나지 않아도 우리가 요청한 test_url 자체의 쿼리스트링 값에 이미 payload_host가
    # 들어있어서(주입한 값 그 자체) 항상 매치되는 논리 오류가 된다. 실제로 "이동"했는지는
    # 최종 페이지의 호스트(netloc)가 payload_host로 바뀌었는지로만 판단해야 한다.
    final_host = urlparse(final_url).netloc.split(":")[0].lower()
    if final_host != payload_host.lower():
        return None

    logger.info(
        f"[1-5][browser-verify] 클라이언트 사이드 리다이렉트 확인 — {c.url} | "
        f"{c.param_name}={payload_val!r} → 최종 페이지 {final_url}"
    )

    return RedirectFinding(
        url=c.url, method=c.method, param_name=c.param_name,
        payload_used=payload_val, payload_description="브라우저 실행 검증 (Playwright)",
        detection_type="CLIENT_JS_CONFIRMED",
        evidence=f"최종 페이지 URL: {final_url}",
        baseline_status=0, test_status=0,
        severity="HIGH",
        confirmed_redirect=True,
        description=(
            f"'{c.param_name}' 파라미터에 주입한 미검증 외부 목적지로 브라우저가 실제로 "
            f"이동했습니다 (최종 URL: {final_url}). 정적 응답에는 이 값이 나타나지 않지만, "
            f"클라이언트 사이드 JavaScript가 이 값을 읽어 location을 대입하는 것으로 실제 "
            f"브라우저 실행을 통해 확인됐습니다."
        ),
        recommendation=(
            "클라이언트 사이드에서 location을 대입하기 전에 목적지가 화이트리스트(자체 "
            f"도메인/경로) 안에 있는지 검증하세요. ({_GUIDE_REFERENCE})"
        ),
        request_body=test_url,
    )


_BROWSER_WORKERS = 2


def _run_chunk(
    chunk: list[Any],
    *,
    payload_host: str,
    cookies: dict[str, str] | None,
    on_done: Any,
) -> tuple[list[Any], int, str | None]:
    """워커 스레드 하나가 자기 몫의 후보를 전담 — Playwright sync API는 브라우저/인스턴스를
    여러 스레드가 동시에 공유하며 호출하는 걸 지원하지 않으므로, 스레드마다 별도의
    sync_playwright()+browser를 새로 launch해 완전히 독립적으로 처리한다(스레드 수만큼만
    launch — 후보 수만큼이 아니므로 오버헤드는 무시할 만하다).
    """
    from playwright.sync_api import sync_playwright

    findings: list[Any] = []
    confirmed = 0
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                for candidate in chunk:
                    # 후보 하나당 페이지 로드에 최대 8초(timeout_ms)가 걸린다 — 취소
                    # 요청 후에도 자기 몫의 나머지 후보를 계속 브라우저로 여는 걸 막는다.
                    _raise_if_cancelled()
                    finding = verify_client_redirect(candidate, payload_host, browser=browser, cookies=cookies)
                    if finding:
                        findings.append(finding)
                        confirmed += 1
                    on_done(str(candidate.collected.url))
            finally:
                browser.close()
        return findings, confirmed, None
    except Exception as exc:
        return findings, confirmed, str(exc)[:200]


def run_login_redirect_browser_check(
    candidates: list[Any],
    *,
    payload_host: str,
    cookies: dict[str, str] | None = None,
    on_progress: Any = None,
) -> tuple[list[Any], dict[str, Any]]:
    """로그인/인증 문맥 후보만 추려 브라우저 검증을 수행한다.

    후보 하나당 페이지 로드+대기로 1~2초가 걸려 순차 처리하면 후보 수(수백~천 단위)에
    비례해 스캔 전체 시간을 지배한다 — 후보를 워커 스레드 수만큼 나눠, 스레드마다 자기
    몫을 처리하는 독립된 브라우저 인스턴스를 하나씩 띄워 병렬로 처리한다.
    """
    login_candidates = select_login_redirect_candidates(candidates)
    stats: dict[str, Any] = {"candidates": len(login_candidates), "confirmed": 0}
    findings: list[Any] = []

    if not login_candidates:
        return findings, stats

    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        logger.warning("[1-5][browser-verify] playwright 미설치 — 클라이언트 리다이렉트 검증 건너뜀")
        return findings, stats

    from concurrent.futures import ThreadPoolExecutor
    from threading import Lock

    worker_count = max(1, min(_BROWSER_WORKERS, len(login_candidates)))
    chunks: list[list[Any]] = [login_candidates[i::worker_count] for i in range(worker_count)]

    done = 0
    lock = Lock()

    def _on_done(endpoint_id: str) -> None:
        nonlocal done
        if not on_progress:
            return
        with lock:
            done += 1
            local_done = done
        on_progress(endpoints_done=local_done, endpoints_total=len(login_candidates), endpoint_id=endpoint_id)

    # 브라우저 launch 자체가 실패할 수 있다 (브라우저 바이너리 미설치, 스캔이 메인 스레드가
    # 아닌 워커 스레드에서 실행되어 Playwright의 시그널 핸들러 등록이 거부되는 경우 등).
    # 예전에는 후보마다 이 실패를 개별적으로 삼켜서 스캔 전체(특히 이 뒤에 이어지는
    # CORS/crossdomain 단계)는 계속 진행됐는데, 여기서 launch를 try/except 밖에 두면
    # 예외가 run_g15_scan까지 그대로 전파돼 CORS/crossdomain 결과까지 통째로 사라진다 —
    # 그래서 launch 실패도 다른 브라우저 오류와 동일하게 조용히 건너뛰도록 감싼다.
    try:
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            futures = [
                pool.submit(_run_chunk, chunk, payload_host=payload_host, cookies=cookies, on_done=_on_done)
                for chunk in chunks
                if chunk
            ]
            for future in futures:
                chunk_findings, chunk_confirmed, error = future.result()
                findings.extend(chunk_findings)
                stats["confirmed"] += chunk_confirmed
                if error:
                    logger.warning(f"[1-5][browser-verify] 워커 브라우저 실행 실패 — 해당 몫 건너뜀: {error}")
                    stats["browser_error"] = error
    except Exception as exc:
        logger.warning(f"[1-5][browser-verify] 브라우저 실행 실패 — 클라이언트 리다이렉트 검증 건너뜀: {exc}")
        stats["browser_error"] = str(exc)[:200]

    # _run_chunk는 취소로 인한 DiagnosisCancelled도 다른 브라우저 오류와 동일하게 삼켜서
    # error 문자열로만 남긴다(위 launch 실패 방어와 같은 이유) — 그래서 그 취소 신호가
    # 이 함수 리턴값만 봐서는 사라져버린다. 여기서 다시 한번 확인해, 취소된 상태라면
    # 뒤에 이어지는 CORS/crossdomain 단계로 넘어가지 않도록 명시적으로 다시 던진다.
    _raise_if_cancelled()
    return findings, stats

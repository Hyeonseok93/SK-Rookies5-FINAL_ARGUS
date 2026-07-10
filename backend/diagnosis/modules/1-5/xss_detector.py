"""
xss_detector.py — reflected_detector.py의 XSS 변형.

scanner.py의 phase A/B job(=1-5가 이미 후보로 선별한 파라미터)에 리다이렉트 페이로드
대신 스크립트/HTML 인젝션 페이로드(xss_payloads.py)를 주입해, posts/comments/profile
같은 일반 CRUD 필드에서 값이 이스케이프 없이 그대로 반사되는지 판별한다.

요청 전송(파라미터 값 교체 + allow_redirects=False + 세션 재사용)은 페이로드 종류와
무관하게 동일하므로 reflected_detector.py의 _send()를 그대로 재사용한다. 판별 규칙만
다르다:
    - reflected_detector.py: Location 헤더 / meta refresh / JS location 대입 여부
    - xss_detector.py(여기): 페이로드 문자열이 이스케이프 없이(verbatim) 응답 본문에
      그대로 노출되는지 여부. 응답 Content-Type이 text/html이면 브라우저가 그대로
      파싱해 스크립트가 실행될 수 있으므로 확정(HIGH)으로, JSON 등 비-HTML 응답이면
      프런트엔드가 이 값을 다시 안전하지 않게 렌더링하는 경우에만 실행되므로 후보
      (LOW, confirmed=False)로만 표시한다.

쓰기(POST/PUT/PATCH) 응답 자체엔 반영된 값이 없는 API도 있다 — 예: 프로필 수정은
"저장되었습니다" 같은 상태 메시지만 반환하고, 실제로 반사된 값은 이후 별도 GET으로
조회해야만 보인다(1-1 SCOPE.md의 "Stored XSS: mutation 후 GET 검증"과 동일한 패턴).
`_read_back()`이 이 케이스를 보강한다 — 쓰기 응답 자체에서 못 찾으면 같은 URL로 GET을
한 번 더 보내 저장된 값이 반사되는지 확인한다.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_MODULE_DIR = Path(__file__).resolve().parent
_GUIDE_REFERENCE = "SK Shieldus Web/API 개발보안 Guideline v3.0.0 항목 1-1(XSS) 대응방안 참조"
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _raise_if_cancelled() -> None:
    from app.services import diagnosis_progress as dp
    from diagnosis.exceptions import DiagnosisCancelled

    if dp.is_cancel_requested():
        raise DiagnosisCancelled("User cancelled diagnosis")


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


_detector = _load_local("reflected_detector")
_send = _detector._send  # 파라미터 값 교체 + 요청 전송은 리다이렉트/XSS 공통 로직

_xss_models = _load_local("xss_models")
XssFinding = _xss_models.XssFinding

_payloads_mod = _load_local("xss_payloads")
build_xss_payloads = _payloads_mod.build_xss_payloads


def _read_back(c: Any, custom_header: str | None) -> dict | None:
    """쓰기 요청 직후 같은 URL을 GET으로 다시 읽어 저장된 값을 확인한다.

    reflected_detector._send()는 c.param_type/method 그대로 요청을 보내는 헬퍼라 GET
    재조회에는 맞지 않는다 — 여기서는 GET 전용으로 최소한만 직접 구현한다(파라미터 값
    교체가 필요 없고, 헤더도 인증 헤더만 있으면 충분하다).
    """
    import requests

    headers = dict(getattr(c, "extra_headers", None) or {})
    headers.pop("Content-Type", None)
    headers.pop("content-type", None)
    if custom_header:
        custom_header = custom_header.strip()
        if ":" in custom_header:
            h_name, h_val = custom_header.split(":", 1)
            headers[h_name.strip()] = h_val.strip()
        elif custom_header.startswith("Bearer ") or custom_header.startswith("eyJ"):
            headers["Authorization"] = custom_header if custom_header.startswith("Bearer ") else f"Bearer {custom_header}"
        else:
            headers["Authorization"] = custom_header
    try:
        session = _detector._session()
        resp = session.request("GET", c.url, headers=headers, timeout=_detector.TIMEOUT, allow_redirects=False)
        return {
            "status": resp.status_code,
            "body": resp.text,
            "location": resp.headers.get("Location", ""),
            "content_type": resp.headers.get("Content-Type", ""),
            "request_body": "",
        }
    except Exception as exc:
        logger.debug(f"[1-5][XSS] read-back 실패 {c.url}: {exc}")
        return None


def probe_candidate_xss(candidate: Any, *, marker: str, custom_header: str | None = None) -> list[XssFinding]:
    """단일 RedirectCandidate(reflected_models.ReflectedParam 재사용)에 XSS 페이로드를
    주입하고 반사 여부를 판별한다.

    Returns:
        list[XssFinding] — 반사가 확인된 항목만 (이상 없으면 빈 리스트)
    """
    c = candidate.collected
    payloads = build_xss_payloads(marker)
    baseline = _send(c, c.param_value, custom_header)
    is_write = c.method.upper() in _WRITE_METHODS

    findings: list[XssFinding] = []
    for payload_val, payload_desc in payloads:
        # reflected_detector.probe_candidate()와 동일한 이유 — 페이로드/read-back마다
        # 최대 TIMEOUT짜리 블로킹 요청이 나가므로 다음 요청 전에 취소 여부를 확인한다.
        _raise_if_cancelled()
        test = _send(c, payload_val, custom_header)
        finding = _judge(c, payload_val, payload_desc, baseline, test)
        if finding is None and is_write and 200 <= test.get("status", -1) < 300:
            readback = _read_back(c, custom_header)
            if readback is not None:
                finding = _judge(c, payload_val, payload_desc, baseline, readback, stored=True)
        if finding:
            findings.append(finding)
            logger.info(
                f"[1-5][XSS] 반사형 XSS 후보 — {c.url} | {c.param_name}={payload_val!r} "
                f"(confirmed={finding.confirmed})"
            )
    return findings


def _judge(
    c: Any,
    payload_val: str,
    payload_desc: str,
    baseline: dict,
    test: dict,
    *,
    stored: bool = False,
) -> "XssFinding | None":
    if test["status"] == -1:
        return None
    # 4xx/5xx는 값이 어떤 비즈니스 로직에도 도달하지 못했다는 뜻이라(타입 검증 실패
    # 에러 메시지 echo 등), reflected_detector.py의 REFLECTED_VALUE와 동일한 이유로
    # 대상에서 제외한다.
    if not (200 <= test["status"] < 400):
        return None

    # baseline(원본 값으로 보낸 이번 job의 응답)에 이미 이 payload 문자열이 있다면 이번
    # 주입과 무관하게 존재하던 값이다 — 같은 스캔 실행에서 다른 job(예: content 필드에
    # 페이로드를 저장하는 게시글/댓글 작성)이 남긴 값을 목록 조회 응답이 그대로 되돌려주는
    # 경우가 대표적이다. 이걸 안 거르면 전혀 무관한 파라미터에서도 "반사됨"으로 오탐되고,
    # job마다 다른 payload를 시도하므로 같은 오탐이 payload 개수만큼 중복 생성된다.
    baseline_body = str(baseline.get("body") or "")
    if payload_val in baseline_body:
        return None

    body = test.get("body") or ""
    if payload_val not in body:
        return None
    # HTML 엔티티로 인코딩됐다면(&lt;script&gt; 등) 이 시점에서 verbatim 매치가 될 수
    # 없으므로, 여기 도달했다는 것 자체가 이스케이프 없이 그대로 반영됐다는 증거다.

    idx = body.find(payload_val)
    snippet = body[max(0, idx - 100): idx + len(payload_val) + 100]
    content_type = str(test.get("content_type") or "").lower()
    is_html = "html" in content_type
    severity = "HIGH" if is_html else "LOW"

    description = (
        f"'{c.param_name}' 파라미터에 주입한 스크립트/HTML 인젝션 페이로드가 이스케이프 없이 "
        + ("이후 조회(GET) 응답에 그대로 저장·반사됩니다 (Stored XSS — 쓰기 응답 자체에는 "
           "값이 없어 별도 재조회로 확인함)." if stored else "응답에 그대로 반사됩니다.")
    )
    if is_html:
        description += (
            " 응답 Content-Type이 text/html이라 브라우저가 이를 그대로 파싱해 스크립트가 "
            "실행될 수 있습니다 (확정 반사형 XSS)."
        )
    else:
        description += (
            f" 다만 응답 Content-Type이 '{content_type or '알 수 없음'}'로 HTML이 아니므로, "
            "이 값을 프런트엔드가 그대로 안전하지 않게 렌더링(예: innerHTML/"
            "dangerouslySetInnerHTML)하는 지점이 있을 때만 실제로 실행됩니다 — 백엔드가 "
            "출력 인코딩을 하지 않는다는 근거로 후보(참고용)로만 표시하며, 프런트엔드 "
            "렌더링 지점 확인이 필요합니다."
        )

    return XssFinding(
        url=c.url, method=c.method, param_name=c.param_name,
        payload_used=payload_val, payload_description=payload_desc,
        evidence=snippet,
        baseline_status=baseline.get("status", 0), test_status=test["status"],
        content_type=content_type,
        severity=severity,
        confirmed=is_html,
        description=description,
        recommendation=(
            "사용자 입력을 응답/화면에 반영하기 전에 컨텍스트에 맞는 출력 인코딩(HTML entity "
            "encoding)을 적용하세요. 프런트엔드에서는 innerHTML/dangerouslySetInnerHTML 대신 "
            f"텍스트 바인딩(예: React의 기본 텍스트 렌더링)을 사용하세요. ({_GUIDE_REFERENCE})"
        ),
        request_body=test.get("request_body", ""),
        stored=stored,
    )

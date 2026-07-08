"""
reflected_detector.py — Phase 3: 페이로드 주입 + Reflected 리다이렉트/포워드 판별
(ARGUS_Backend scanners/redirect_forward/detector.py 포트)

역할:
    - reflected_candidates.py(Phase 2)가 골라낸 후보 파라미터마다 reflected_payloads.py의
      외부 목적지 페이로드를 주입해 요청을 전송한다.
    - "같은 요청/응답 왕복" 안에서 그 값이 검증 없이 그대로 반영되는지만 판별한다
      (Reflected 전용). 응답을 저장했다가 다른 요청에서 실행되는 Stored 케이스는
      별도의 생성→저장 확인→트리거 흐름이 필요해 범위 밖이다.
    - 반영 여부는 결정적 규칙(Location 헤더 / meta refresh / JS location 대입 /
      응답 본문 내 단순 반사에 payload_host 문자열 노출)로만 판단한다 — LLM 해석
      단계가 필요 없다.

주의:
    - allow_redirects=False로 요청해 Location 헤더를 직접 확인한다. requests가
      자동으로 리다이렉트를 따라가 버리면 Location 헤더 자체가 사라져 판별이 불가능해진다.
    - 요청 타임아웃: TIMEOUT 상수 (기본 10초)
"""

from __future__ import annotations

import importlib.util
import json
import logging
import re
import sys
import threading
from pathlib import Path
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import requests

logger  = logging.getLogger(__name__)
TIMEOUT = 10  # 초

_MODULE_DIR = Path(__file__).resolve().parent

# job마다 매번 requests.request()로 새 TCP/TLS 연결을 맺으면(연결 재사용 없음) job 수가
# 많을 때(최대 1200개 × 최대 14회 요청) 핸드셰이크 오버헤드만으로도 스캔이 매우 느려진다.
# reflected_bridge.run_on_jobs가 스레드풀로 이 모듈을 병렬 호출하므로, requests.Session은
# 스레드-세이프하지 않은 상태 변경(리다이렉트 이력 등)이 있어 스레드마다 하나씩 재사용한다.
_thread_local = threading.local()


def _session() -> requests.Session:
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        _thread_local.session = session
    return session


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


_models = _load_local("reflected_models")
ReflectedParam = _models.ReflectedParam
RedirectCandidate = _models.RedirectCandidate
RedirectFinding = _models.RedirectFinding

_payloads_mod = _load_local("reflected_payloads")
build_payloads = _payloads_mod.build_payloads
DEFAULT_PAYLOAD_HOST = _payloads_mod.DEFAULT_PAYLOAD_HOST

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# <meta http-equiv="refresh" content="0;url=https://evil.com/"> 형태에서 url= 뒤 목적지 추출
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>]+)',
    re.IGNORECASE,
)

# location.href = "..." / window.location = "..." / document.location = "..." /
# location.replace("...") / .assign("...") 형태
_JS_REDIRECT_RE = re.compile(
    r'(?:(?:window|document)\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_GUIDE_REFERENCE = "SK Shieldus Web/API 개발보안 Guideline v3.0.0 항목 1-5 대응방안 참조"


def probe_candidate(
    candidate:      RedirectCandidate,
    payload_host:   str = DEFAULT_PAYLOAD_HOST,
    custom_header:  str = None,
) -> list[RedirectFinding]:
    """
    단일 RedirectCandidate에 대해 페이로드를 주입하고 Reflected 여부를 판별한다.

    Returns:
        list[RedirectFinding] — 반영이 확인된 항목만 (이상 없으면 빈 리스트)
    """
    c = candidate.collected
    parsed_target   = urlparse(c.url)
    payloads        = build_payloads(payload_host=payload_host, allowlisted_host=parsed_target.netloc)

    baseline = _send(c, c.param_value, custom_header)

    findings: list[RedirectFinding] = []
    for payload_val, payload_desc in payloads:
        test = _send(c, payload_val, custom_header)
        finding = _judge(c, payload_val, payload_desc, baseline, test, payload_host)
        if finding:
            findings.append(finding)
            logger.info(
                f"[1-5][Phase 3] Reflected 판정 — {finding.detection_type} "
                f"(confirmed_redirect={finding.confirmed_redirect}) | "
                f"{c.url} | {c.param_name}={payload_val!r}"
            )

    return findings


# ──────────────────────────────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────────────────────────────

def _judge(
    c:             ReflectedParam,
    payload_val:   str,
    payload_desc:  str,
    baseline:      dict,
    test:          dict,
    payload_host:  str,
) -> RedirectFinding | None:
    """baseline/test 응답을 보고 payload_host가 그대로 반영됐는지 판별한다."""
    if test["status"] == -1:
        return None

    host_needle = payload_host.lower()
    # baseline은 원본 파라미터 값으로 보낸 "이번 job의" 응답이다 — 여기 이미 payload_host
    # 문자열이 있다면 이 job의 페이로드 주입과 무관하게 이미 존재하던 값이라는 뜻이다.
    # 흔한 원인: 같은 스캔 실행에서 다른 job(예: content 필드에 페이로드를 저장하는 게시글/
    # 댓글 작성)이 남긴 값을 목록 조회 응답이 그대로 되돌려주는 경우 — 이걸 걸러내지 않으면
    # 전혀 무관한 파라미터(예: memberId)에서도 "반사됨"으로 오탐되고, job마다 다른 페이로드를
    # 시도하므로 사실상 같은 오탐이 페이로드 개수만큼 중복 생성된다.
    baseline_body_lower = str(baseline.get("body") or "").lower()
    baseline_location_lower = str(baseline.get("location") or "").lower()
    already_in_baseline = host_needle in baseline_body_lower or host_needle in baseline_location_lower
    if already_in_baseline:
        return None

    # ── 패턴 1: Location 헤더 반영 (서버 사이드 리다이렉트 — 가장 확실한 증거) ──
    location = test.get("location", "")
    if test["status"] in _REDIRECT_STATUSES and host_needle in location.lower():
        return RedirectFinding(
            url=c.url, method=c.method, param_name=c.param_name,
            payload_used=payload_val, payload_description=payload_desc,
            detection_type="LOCATION_HEADER",
            evidence=f"Location: {location}",
            baseline_status=baseline["status"], test_status=test["status"],
            severity="HIGH",
            confirmed_redirect=True,
            description=(
                f"'{c.param_name}' 파라미터에 주입한 미검증 외부 목적지가 서버 검증 없이 "
                f"HTTP {test['status']} 응답의 Location 헤더에 그대로 반영됩니다. "
                f"공격자가 이 파라미터를 조작한 링크를 배포하면 피해자를 피싱/악성 사이트로 "
                f"리다이렉트시킬 수 있습니다."
            ),
            recommendation=(
                "목적지 URL을 파라미터로 직접 받지 말고, 사전에 정의한 경로/도메인 화이트리스트 "
                f"중에서만 선택하도록 서버측 검증을 적용하세요. ({_GUIDE_REFERENCE})"
            ),
            request_body=test.get("request_body", ""),
        )

    # ── 패턴 2/3: 응답 본문 내 클라이언트 사이드 리다이렉트 반영 ──
    # 3xx 응답이라도 body에 meta refresh/JS redirect가 함께 포함될 수 있으므로
    # 상태코드 조건 없이 body 유무만으로 검사한다.
    # search()로 첫 매치 하나만 보면, 페이로드와 무관한 조건부 리다이렉트가 본문
    # 앞부분에 먼저 나오고 실제 반영은 뒤쪽 매치에서만 일어나는 경우(SPA 라우팅
    # 분기 등)를 놓친다 — finditer()로 모든 매치를 훑어 payload_host가 하나라도
    # 나오면 반영으로 판정한다.
    if test.get("body"):
        meta_match = next(
            (m for m in _META_REFRESH_RE.finditer(test["body"]) if host_needle in m.group(1).lower()),
            None,
        )
        if meta_match:
            return RedirectFinding(
                url=c.url, method=c.method, param_name=c.param_name,
                payload_used=payload_val, payload_description=payload_desc,
                detection_type="META_REFRESH",
                evidence=meta_match.group(0)[:300],
                baseline_status=baseline["status"], test_status=test["status"],
                severity="MEDIUM",
                confirmed_redirect=True,
                description=(
                    f"'{c.param_name}' 파라미터에 주입한 미검증 외부 목적지가 응답 본문의 "
                    f"<meta http-equiv=\"refresh\"> 태그에 그대로 반영되어, 브라우저가 페이지를 "
                    f"자동으로 외부 사이트로 이동시킬 수 있습니다."
                ),
                recommendation=(
                    "클라이언트 사이드 리다이렉트에 사용할 목적지도 서버측 화이트리스트 검증을 "
                    f"거치도록 하세요. ({_GUIDE_REFERENCE})"
                ),
                request_body=test.get("request_body", ""),
            )

        js_match = next(
            (m for m in _JS_REDIRECT_RE.finditer(test["body"]) if host_needle in m.group(1).lower()),
            None,
        )
        if js_match:
            return RedirectFinding(
                url=c.url, method=c.method, param_name=c.param_name,
                payload_used=payload_val, payload_description=payload_desc,
                detection_type="JS_REDIRECT",
                evidence=js_match.group(0)[:300],
                baseline_status=baseline["status"], test_status=test["status"],
                severity="MEDIUM",
                confirmed_redirect=True,
                description=(
                    f"'{c.param_name}' 파라미터에 주입한 미검증 외부 목적지가 응답에 포함된 "
                    f"JavaScript의 location 대입 코드에 그대로 반영되어, 페이지 로드 시 브라우저가 "
                    f"외부 사이트로 이동될 수 있습니다."
                ),
                recommendation=(
                    "JS로 처리하는 리다이렉트도 서버가 내려준 값이 화이트리스트 안에 있는지 "
                    f"검증한 뒤에만 location에 대입하도록 하세요. ({_GUIDE_REFERENCE})"
                ),
                request_body=test.get("request_body", ""),
            )

        # ── 패턴 4: 단순 반사(Reflected) — 리다이렉트 문맥(Location/meta refresh/JS 대입)과
        # 무관하게, 주입한 외부 목적지 문자열이 응답 본문에 검증 없이 그대로 노출되는지만 본다.
        # 위 패턴들이 이미 실제 리다이렉트 실행 증거를 잡아내므로, 여기서는 그 외 나머지
        # 케이스(JSON 필드 echo 등)에서 payload_host 문자열 자체가 그대로 반사되는지만
        # 결정적으로 판별한다. 리다이렉트 실행 증거가 없으므로 confirmed_redirect=False로
        # 표시해 1-5 확정 취약점과 구분한다.
        #
        # 4xx/5xx(요청 실패) 응답은 여기서 제외한다 — 요청이 실패했다는 건 값이 어떤
        # 비즈니스 로직(당연히 리다이렉트 로직 포함)에도 도달하지 못했다는 뜻이라, 타입
        # 검증 실패 에러 메시지에 입력값이 그대로 echo되는 흔한 패턴만 양산하고 실제
        # 리다이렉트 가능성과는 무관하다.
        if not (200 <= test["status"] < 300):
            return None

        body_lower = test["body"].lower()
        if host_needle in body_lower:
            idx = body_lower.find(host_needle)
            snippet = test["body"][max(0, idx - 100): idx + 100]
            return RedirectFinding(
                url=c.url, method=c.method, param_name=c.param_name,
                payload_used=payload_val, payload_description=payload_desc,
                detection_type="REFLECTED_VALUE",
                evidence=snippet,
                baseline_status=baseline["status"], test_status=test["status"],
                severity="LOW",
                confirmed_redirect=False,
                description=(
                    f"[반사만 확인됨 — 리다이렉트 실행 증거 없음] '{c.param_name}' 파라미터에 주입한 "
                    f"미검증 외부 목적지 문자열이 응답 본문에 검증 없이 그대로 반사(echo)됩니다. "
                    f"Location 헤더/meta refresh/JS location 대입 등 실제 리다이렉트 실행 증거는 "
                    f"확인되지 않았으므로 1-5 확정 취약점은 아니며, 참고용 정보 노출 신호로만 "
                    f"취급해야 합니다. (예: 타입 검증 실패 에러 메시지가 입력값을 그대로 포함하는 "
                    f"경우에도 이 패턴이 발생하며, 이는 실제 리다이렉트와 무관합니다.)"
                ),
                recommendation=(
                    "사용자 입력을 응답에 반사하기 전에 화이트리스트 검증을 적용하거나, 반사가 "
                    f"불필요하다면 해당 값을 응답에서 제거하세요. ({_GUIDE_REFERENCE})"
                ),
                request_body=test.get("request_body", ""),
            )

    return None


def _send(c: ReflectedParam, value: str, custom_header: str = None) -> dict:
    """
    파라미터 값을 payload로 교체한 요청을 전송하고
    {"status": int, "body": str, "location": str, "request_body": str} 형태로 반환한다.
    리다이렉트를 자동으로 따라가지 않아야 Location 헤더를 확인할 수 있으므로
    allow_redirects=False로 고정한다. 요청 실패 시 status=-1.
    """
    # job의 원본 헤더(Authorization/Cookie 등)를 먼저 깔아준다 — 인증이 필요한
    # 엔드포인트는 이게 없으면 401로 막혀 반사/리다이렉트 판별 자체가 불가능해진다.
    # Content-Type/custom_header는 이 함수의 판단(페이로드 인코딩, 수동 지정 인증)이
    # 더 구체적이므로 아래에서 덮어쓴다.
    req_headers = dict(getattr(c, "extra_headers", None) or {})
    if "application/json" in (c.content_type or ""):
        req_headers["Content-Type"] = "application/json"

    if custom_header:
        custom_header = custom_header.strip()
        if ":" in custom_header:
            h_name, h_val = custom_header.split(":", 1)
            req_headers[h_name.strip()] = h_val.strip()
        elif custom_header.startswith("Bearer "):
            req_headers["Authorization"] = custom_header
        elif custom_header.startswith("eyJ"):
            req_headers["Authorization"] = f"Bearer {custom_header}"
        else:
            req_headers["Authorization"] = custom_header

    request_body_repr = ""
    try:
        content_type = c.content_type or ""

        session = _session()
        if "application/json" in content_type:
            body_obj = _apply_json(c.raw_body, c.param_name, value)
            request_body_repr = json.dumps(body_obj, ensure_ascii=False)
            resp = session.request(
                c.method, c.url, timeout=TIMEOUT, json=body_obj,
                headers=req_headers, allow_redirects=False,
            )
        elif "application/x-www-form-urlencoded" in content_type:
            body_obj = _apply_form(c.raw_body, c.param_name, value)
            request_body_repr = urlencode(body_obj)
            resp = session.request(
                c.method, c.url, timeout=TIMEOUT, data=body_obj,
                headers=req_headers, allow_redirects=False,
            )
        else:
            # query string (기본) — multipart/form-data 등 리다이렉트와 무관한 바이너리
            # 케이스는 1-5 대상이 아니므로 query 교체로 폴백해도 안전하다.
            parsed  = urlparse(c.url)
            qs      = parse_qs(parsed.query, keep_blank_values=True)
            qs[c.param_name] = [value]
            new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            request_body_repr = f"(query string) {new_url}"
            resp = session.request(
                c.method, new_url, timeout=TIMEOUT,
                headers=req_headers, allow_redirects=False,
            )

        return {
            "status":       resp.status_code,
            "body":         resp.text,
            "location":     resp.headers.get("Location", ""),  # CaseInsensitiveDict이므로 단일 조회로 충분
            "content_type": resp.headers.get("Content-Type", ""),
            "request_body": request_body_repr,
        }

    except requests.RequestException as e:
        logger.warning(f"요청 실패 ({c.method} {c.url} [{c.param_name}={value!r}]): {e}")
        return {"status": -1, "body": str(e), "location": "", "content_type": "", "request_body": request_body_repr}


def _apply_json(raw_body: str, param_name: str, value: str) -> dict:
    """raw_body(JSON)를 파싱해 param_name 위치의 값만 교체하고 다른 필드는 보존한다."""
    try:
        data = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}

    if not raw_body or "[" in param_name:
        return {param_name: value}

    keys = param_name.split(".")
    cur = data
    for key in keys[:-1]:
        nxt = cur.get(key)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[key] = nxt
        cur = nxt
    cur[keys[-1]] = value
    return data


def _apply_form(raw_body: str, param_name: str, value: str) -> dict:
    """raw_body(form-urlencoded)를 파싱해 param_name 값만 교체하고 나머지 필드는 보존한다."""
    if not raw_body:
        return {param_name: value}
    qs = parse_qs(raw_body, keep_blank_values=True)
    flat = {k: (v[0] if v else "") for k, v in qs.items()}
    flat[param_name] = value
    return flat

"""Build probe HTTP requests for every inventory endpoint (GET/POST/PUT/PATCH/DELETE)."""

from __future__ import annotations

import json
from typing import Any, Callable

from inventory.auth_util import auth_headers, is_auth_header
from inventory.schema import Endpoint, InputParam, build_full_url
from parsers.parse_endpoints import materialize_path_params

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})

DEFAULT_PAGINATION: dict[str, str] = {"page": "0", "size": "20"}


_GENERIC_PROBE_SAMPLES = frozenset({"", "1", "test", "sample", "argus"})

# 이름 기반 휴리스틱이 인식하는 카테고리별 "그럴듯한 형식" 정규식 — 캡처된 sample이
# 필드 이름이 암시하는 형식과 실제로 맞는지 검증하는 데 쓴다. 특정 플레이스홀더
# 문자열("John Doe" 같은)을 이름으로 나열하는 대신 형식 검증으로 일반화한다 — 어떤
# 타겟 앱이 어떤 범용 예시 문자열을 쓰든(예: "Jane Smith", "홍길동", "Test User")
# 형식이 안 맞으면 동일하게 걸러진다.
import re as _re

_SHAPE_PATTERNS: dict[str, "_re.Pattern[str]"] = {
    "phone": _re.compile(r"^\+?\d[\d\-\s]{6,}\d$"),
    "email": _re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    "date": _re.compile(r"^\d{4}-\d{2}-\d{2}"),
}


def _shape_category(name_compact: str) -> str | None:
    if "phone" in name_compact or "tel" in name_compact:
        return "phone"
    if name_compact == "email":
        return "email"
    if "birth" in name_compact or name_compact.endswith("date") or name_compact == "date":
        return "date"
    return None


def _is_generic_probe_sample(value: Any, name_compact: str = "") -> bool:
    text = str(value).strip()
    if text.lower() in _GENERIC_PROBE_SAMPLES:
        return True
    category = _shape_category(name_compact)
    if category is not None:
        pattern = _SHAPE_PATTERNS[category]
        if not pattern.match(text):
            # 캡처된 sample이 이 필드 이름이 암시하는 형식(전화번호/이메일/날짜)과
            # 맞지 않는다 — openapi/zap 캡처가 여러 필드에 같은 범용 예시 문자열을
            # 그대로 복사해 붙인 경우 흔히 생기는 패턴이다. 값 자체가 무엇이든
            # "이 필드에는 안 맞는 값"이라는 사실만으로 일반값 취급한다.
            return True
    return False


_OPTIONAL_PASSWORD_CHANGE_FIELDS = frozenset(
    {"newpassword", "newpwd", "changepassword", "passwordconfirm", "newpasswordconfirm"}
)


def _is_risky_optional_field(inp: InputParam) -> bool:
    """선택값(optional)인 새 비밀번호류 필드는 채우지 않고 생략한다.

    실제로 값을 채우면 두 가지 문제가 생긴다: (1) 이런 필드는 보통 비밀번호 정책
    (길이/문자 조합)이 있어 임의 샘플 값("John Doe" 등)을 넣으면 검증에서 항상 400으로
    막혀 다른 필드(예: name/nickname) 퍼징 결과 자체를 관찰할 수 없게 되고, (2) 정책을
    통과하는 그럴듯한 값을 넣으면 이번엔 실제로 테스트 계정 비밀번호가 바뀌어버려
    이후 로그인이 필요한 다른 검사들이 전부 깨진다. 서버가 이 필드의 부재를 "값 변경
    없음"으로 처리하는 게 일반적이므로(실측 확인됨), required가 아니면 아예 생략한다.
    """
    if inp.required:
        return False
    name = "".join(ch for ch in inp.name.lower() if ch.isalnum())
    return name in _OPTIONAL_PASSWORD_CHANGE_FIELDS


def _name_based_sample(inp: InputParam, path: str = "") -> Any | None:
    """필드 이름에서 흔한 형식/의미를 추론한다 — 특정 타겟 앱의 도메인(예약 종류,
    상품 등급 같은 enum 값)은 알 수 없으므로 다루지 않고, 어떤 REST API에나 널리
    나타나는 범용 필드 이름(이메일/전화번호/날짜/제목/본문/평점/금액/수량)만 다룬다.
    """
    name = inp.name.lower()
    compact = "".join(ch for ch in name if ch.isalnum())

    if "birth" in compact:
        return "1995-05-25"
    if compact.endswith("date") or compact == "date" or compact == "month":
        return "2026-07-01"
    if compact.endswith("time"):
        return "2026-07-01T09:00:00"

    if compact in {"title", "name", "nickname"}:
        return "argus-probe"
    if compact in {"content", "description", "message", "comment"}:
        return "probe"
    if compact == "email":
        return "argus-probe@example.com"
    if "phone" in compact or "tel" in compact:
        return "010-1234-5678"
    if compact == "rating":
        return 5
    if any(token in compact for token in ("amount", "price", "total")):
        return 10000
    if compact in {"guests", "capacity", "quantity", "count"}:
        return 2
    return None


def _valid_probe_header_name(name: str) -> bool:
    n = (name or "").strip()
    if not n or " " in n:
        return False
    upper = n.upper()
    return not (upper.startswith("GET ") or upper.startswith("POST ") or upper.startswith("HTTP/"))


def sample_value(inp: InputParam, path: str = "") -> Any:
    heuristic = _name_based_sample(inp, path)
    name_compact = "".join(ch for ch in inp.name.lower() if ch.isalnum())
    if heuristic is not None and (inp.sample is None or _is_generic_probe_sample(inp.sample, name_compact)):
        return heuristic
    if inp.sample is not None:
        if inp.type in ("integer", "int64", "number") and str(inp.sample).isdigit():
            return int(inp.sample)
        if inp.type == "boolean":
            return str(inp.sample).lower() in ("true", "1", "yes")
        return inp.sample
    if heuristic is not None:
        return heuristic
    if inp.type in ("integer", "int64"):
        return 1
    if inp.type == "boolean":
        return False
    if inp.type == "number":
        return 1.0
    return "1"


def frontend_gateway_path(base_url: str, path: str) -> str:
    """일부 프런트엔드 dev 서버는 API를 별도 경로 프리픽스로 프록시한다 — 그 프리픽스
    규칙(예: /user-api, /admin-api)은 타겟마다 다르므로 여기서 알 수 없다. 이 함수는
    확장 지점으로만 남겨두고 기본은 경로를 그대로 반환한다.
    """
    return path


def _heuristic_query(path: str, method: str) -> dict[str, str]:
    """선언된 쿼리 파라미터가 없는 GET류 요청에 쓸 최소 fallback. 페이지네이션은 REST
    API 전반에서 흔한 관례라 범용으로 다루지만, 그 외 타겟별 검색/필터 파라미터는 알 수
    없으므로 다루지 않는다."""
    if method not in ("GET", "DELETE", "HEAD", "OPTIONS"):
        return {}
    return dict(DEFAULT_PAGINATION)


def _multipart_body(fields: dict[str, str]) -> tuple[str, str]:
    boundary = "----ArgusProbeBoundary7MA4YWxk"
    chunks: list[str] = []
    for name, val in fields.items():
        chunks.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{val}\r\n'
        )
    chunks.append(f"--{boundary}--\r\n")
    body = "".join(chunks)
    ctype = f"multipart/form-data; boundary={boundary}"
    return ctype, body


def _heuristic_body(path: str, method: str) -> tuple[str, str] | None:
    """body_inputs가 아예 없는 엔드포인트(선언된 body 파라미터가 하나도 없을 때)에 쓸
    최후의 fallback body — POST는 "{}", 그 외(PATCH/PUT)는 "{"id": 1}". body_inputs로
    이미 실제 필드값이 채워진 body가 있는 경우에는 이 fallback으로 덮어쓰면 안 된다
    (build_probe_request 참고).
    """
    if method not in WRITE_METHODS:
        return None
    if method == "POST":
        return "application/json", "{}"
    return "application/json", json.dumps({"id": 1}, ensure_ascii=False)


def build_body_object(ep: Endpoint) -> dict[str, Any]:
    """Build JSON body dict — all fields at valid baseline; fuzzing overrides one param only."""
    body_inputs = [i for i in ep.request_params if i.in_ in ("body", "form") and i.role == "input"]
    if body_inputs:
        return {inp.name: sample_value(inp, ep.path) for inp in body_inputs if inp.in_ == "body"}

    guessed = _heuristic_body(ep.path, ep.method.upper())
    if guessed:
        _, body_str = guessed
        try:
            data = json.loads(body_str)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
    return {}


def build_probe_request(
    ep: Endpoint,
    *,
    probe_base_fn: Callable[[str], str] | None = None,
    account_auth: dict[str, Any] | None = None,
    path_param_defaults: dict[str, str] | None = None,
) -> dict[str, Any]:
    rewrite = probe_base_fn or (lambda u: u)
    path = frontend_gateway_path(
        ep.base_url,
        materialize_path_params(ep.path, path_param_defaults),
    )
    method = ep.method.upper()

    query: dict[str, str] = {}
    headers: dict[str, str] = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "ARGUS-Probe/1.0",
        "Connection": "close",
    }

    for inp in ep.request_params:
        if inp.in_ == "query" and inp.role == "input":
            if inp.required or inp.sample is not None:
                query[inp.name] = str(sample_value(inp, ep.path))
        elif inp.in_ == "header" and inp.role in ("input", "auth"):
            if is_auth_header(inp.name):
                continue
            if inp.name.lower() != "content-type" and _valid_probe_header_name(inp.name):
                headers[inp.name] = str(inp.sample or "1")

    for hdr in ep.request_headers:
        if hdr.name.lower() == "content-type":
            continue
        if is_auth_header(hdr.name):
            continue
        if not _valid_probe_header_name(hdr.name):
            continue
        if hdr.role in ("input", "auth") or hdr.sample:
            headers[hdr.name] = str(hdr.sample or "1")

    headers.update(auth_headers(account_auth))

    if not query and method in ("GET", "HEAD", "DELETE", "OPTIONS"):
        query.update(_heuristic_query(ep.path, method))

    body_str = ""
    body_inputs = [
        i
        for i in ep.request_params
        if i.in_ in ("body", "form") and i.role == "input" and not _is_risky_optional_field(i)
    ]

    if method in WRITE_METHODS:
        if body_inputs:
            if any(i.in_ == "form" for i in body_inputs):
                fields = {inp.name: str(sample_value(inp, ep.path)) for inp in body_inputs}
                ctype, body_str = _multipart_body(fields)
                headers["Content-Type"] = ctype
            else:
                obj = {inp.name: sample_value(inp, ep.path) for inp in body_inputs if inp.in_ == "body"}
                body_str = json.dumps(obj, ensure_ascii=False)
                headers["Content-Type"] = "application/json"
        else:
            guessed = _heuristic_body(ep.path, method)
            if guessed:
                ctype, body_str = guessed
                headers["Content-Type"] = ctype

    url = build_full_url(rewrite(ep.base_url.rstrip("/")), path, query or None)
    return {"method": method, "url": url, "headers": headers, "body": body_str}


def format_raw_http_request(probe: dict[str, Any]) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(probe["url"])
    host = parsed.netloc
    body = probe.get("body") or ""
    hdrs = dict(probe["headers"])
    if body:
        hdrs["Content-Length"] = str(len(body.encode("utf-8")))

    lines = [f"{probe['method']} {probe['url']} HTTP/1.1", f"Host: {host}"]
    for key, val in hdrs.items():
        if key.lower() != "host":
            lines.append(f"{key}: {val}")
    lines.append("")
    if body:
        return "\r\n".join(lines) + "\r\n" + body
    return "\r\n".join(lines) + "\r\n"

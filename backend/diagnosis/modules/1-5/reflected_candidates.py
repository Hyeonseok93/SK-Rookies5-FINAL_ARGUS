"""Phase 2: name-rule based redirect/forward candidate selection (ARGUS_Backend port).

이름 기반 정규식으로만 판단 → 결정적이고 실행시간이 사실상 0에 수렴한다.
대상 서비스로 나가는 불필요한 요청을 줄이기 위해 후보가 아닌 파라미터는
Phase 3(실 요청 + 페이로드 주입)로 넘기지 않는다.
"""

from __future__ import annotations

import importlib.util
import logging
import re
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


_models = _load_local("reflected_models")
ReflectedParam = _models.ReflectedParam
RedirectCandidate = _models.RedirectCandidate

# snake_case / 단어 경계 기준 리다이렉트·포워드 관련 파라미터명 패턴.
# SK Shieldus 가이드 예제(returl=evil.com)처럼 "return"류 축약형도 함께 커버한다.
_REDIRECT_NAME_PATTERN = re.compile(
    r"(^|_)("
    r"url|uri|link|href|"
    r"target|dest|destination|"
    r"redirect|redirecturl|redirecturi|redirectto|"
    r"return|returl|returnurl|returnto|"
    r"next|nexturl|nextpage|"
    r"forward|forwardurl|forwardto|"
    r"continue|continueurl|"
    r"callback|callbackurl|"
    r"success|successurl|"
    r"fail|failurl|"
    r"logout|logouturl|"
    r"checkout|checkouturl|"
    r"goto|out|jump|nav|navigate|"
    r"site|domain|host|"
    r"ref|referrer|referer"
    r")($|_)",
    re.IGNORECASE,
)

# camelCase / 대소문자 혼합 파라미터명 보조 패턴 — returnUrl, redirectUrl, nextPage, successUrl,
# redirectUri(전부 소문자), redirectURI(전부 대문자) 등 표기 불규칙 케이스까지 커버한다.
# re.IGNORECASE 적용으로 suffix(url/uri/page …)를 소문자 단일 표현으로 단순화.
_REDIRECT_CAMEL_PATTERN = re.compile(
    r"(return|redirect|forward|continue|callback|success|fail|logout|checkout|target|dest|next)"
    r"(url|uri|page|to|path|link|href)$",
    re.IGNORECASE,
)

# 값 자체가 URL/경로 형태인지 판별 — 이름만으로는 애매한 파라미터(예: "go", "page")를
# 값 신호로 보강할 때 사용한다.
_URL_LIKE_VALUE_PATTERN = re.compile(r"^(https?://|//|/)", re.IGNORECASE)
_WEAK_NAME_HINT_PATTERN = re.compile(r"url|link|path|page|go\b|move|nav", re.IGNORECASE)

# 검색(search) 엔드포인트 경로 판별 — 1-5를 실무에서 테스트할 때 가장 먼저 들여다보는
# 지점이다. 검색 결과/에러 응답이 입력값을 검증 없이 그대로 반사(echo)하는 경우가 흔해,
# 파라미터명이 리다이렉트 이름 규칙에 안 맞아도 검색 엔드포인트의 파라미터는 전부
# Reflected 후보로 포함한다.
_SEARCH_PATH_PATTERN = re.compile(r"(^|/|_|-)search($|/|_|-|\?)", re.IGNORECASE)


def select_candidates(params: list[ReflectedParam]) -> list[RedirectCandidate]:
    """
    수집된 전체 파라미터 중 리다이렉트/포워드 후보만 골라 태깅한다.

    Args:
        params: 크롤링/Swagger 등으로 수집된 ReflectedParam 전체 목록

    Returns:
        List[RedirectCandidate] — 후보로 선정된 파라미터만
    """
    candidates: list[RedirectCandidate] = []

    for p in params:
        # dot-notation(JSON 중첩) 파라미터는 마지막 세그먼트만 이름 판단에 사용
        # (예: "data.redirectUrl" → "redirectUrl")
        leaf_name = p.param_name.rsplit(".", 1)[-1]

        if _REDIRECT_NAME_PATTERN.search(leaf_name) or _REDIRECT_CAMEL_PATTERN.search(leaf_name):
            candidates.append(RedirectCandidate(
                collected=p,
                reason=f"파라미터명 '{p.param_name}'이 리다이렉트/포워드 이름 규칙에 매칭",
            ))
            continue

        # 이름 신호가 약하더라도(예: go, page) 값 자체가 URL/경로 형태이면 보조로 포함
        if _WEAK_NAME_HINT_PATTERN.search(leaf_name) and _URL_LIKE_VALUE_PATTERN.match(p.param_value or ""):
            candidates.append(RedirectCandidate(
                collected=p,
                reason=(
                    f"파라미터명 '{p.param_name}'에 약한 네비게이션 신호가 있고, "
                    f"값이 URL/경로 형태({p.param_value!r})"
                ),
            ))
            continue

        # 검색 엔드포인트는 이름 규칙과 무관하게 파라미터 전체를 후보로 포함 —
        # 검색 결과/에러 응답이 입력값을 그대로 반사하는 경우가 실무적으로 흔하다.
        if _SEARCH_PATH_PATTERN.search(p.url or ""):
            candidates.append(RedirectCandidate(
                collected=p,
                reason=f"검색 엔드포인트('{p.url}')의 파라미터라 이름 규칙과 무관하게 후보로 포함",
            ))

    logger.info(
        f"[1-5][Phase 2] 리다이렉트/포워드 후보 파라미터: {len(candidates)}개 "
        f"(전체 수집 {len(params)}개 중)"
    )
    return candidates

"""프론트엔드 화면 캡처

response finding에 대해, 인벤토리에 대응되는 프론트 라우트(kind=="frontend", 
설정 시 주는 URL 리스트/정의서에서 유입)가 있으면, 같은 계정으로 로그인한 상태의 실제 렌더링
화면도 함께 캡처 → 결과서에 "raw API 응답"뿐 아니라 "실제 눈에 보이는 노출"까지 남김

앱 종속 요소(프론트 로그인 쿠키 스킴, 404 감지 문구, API→화면 라우트 override)는 코드가
아니라 config의 `frontend` 섹션에 모여 있다. 코드엔 앱 식별자를 두지 않으며(쿠키 스킴
미설정 시 프론트 캡처는 조용히 비활성), 앱을 바꿀 땐 config만 바꾸면 된다. API↔화면 다리는
경로 휴리스틱이며, 이름이 안 겹치는 예외는 config `frontend.route_overrides`로 지정한다.
"""

from __future__ import annotations

import fnmatch
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from inventory.auth_surfaces import session_token_bundle
from inventory.net import probe_base_url
from inventory.schema import ApiTree

_API_PREFIXES = ("/api/v1", "/api", "/v1")
_MIN_HEURISTIC_SCORE = 2

_DEFAULT_COOKIE_NAMES: dict[str, str] = {}
# 논리 필드 이름(앱 무관). 이 값들이 세션에 있어야 로그인 쿠키를 만듦
_DEFAULT_COOKIE_REQUIRED = ("access", "member_id", "role", "username")
_DEFAULT_ERROR_PHRASES = (
    "page not found",
    "not found",
)


@dataclass
class FrontConfig:
    cookie_names: dict[str, str] = field(default_factory=lambda: dict(_DEFAULT_COOKIE_NAMES))
    cookie_required: tuple[str, ...] = _DEFAULT_COOKIE_REQUIRED
    error_phrases: tuple[str, ...] = _DEFAULT_ERROR_PHRASES


def load_front_config(raw_config: dict[str, Any] | None) -> FrontConfig:
    """config `frontend` 섹션에서 앱별 프론트 쿠키 스킴/404 문구를 읽는다(미설정 시 프론트 캡처 비활성)"""
    cfg = (raw_config or {}).get("frontend") or {}
    cookies = cfg.get("cookies") or {}
    names = {**_DEFAULT_COOKIE_NAMES, **(cookies.get("names") or {})}
    required = tuple(cookies.get("required") or _DEFAULT_COOKIE_REQUIRED)
    # 범용 영문 기본 문구 + 앱별 추가 문구를 합친다(교체가 아니라 병합)
    phrases = tuple(
        dict.fromkeys(
            str(p).lower()
            for p in (*_DEFAULT_ERROR_PHRASES, *(cfg.get("error_phrases") or ()))
        )
    )
    return FrontConfig(cookie_names=names, cookie_required=required, error_phrases=phrases)


@dataclass
class FrontRoute:
    path: str
    base_url: str
    source: str = "inventory"  # inventory | override


def load_frontend_routes(tree: ApiTree) -> list[FrontRoute]:
    """인벤토리의 kind=='frontend' 엔드포인트 = 설정 URL 리스트/정의서에서 온 프론트 페이지 목록"""
    out: list[FrontRoute] = []
    seen: set[tuple[str, str]] = set()
    for ep in tree.endpoints:
        if getattr(ep, "kind", "api") != "frontend":
            continue
        key = (ep.path, ep.base_url)
        if key in seen:
            continue
        seen.add(key)
        out.append(FrontRoute(path=ep.path, base_url=ep.base_url))
    return out


def load_frontend_routes_best(data_dir: Any) -> list[FrontRoute]:
    """프론트 라우트는 ready/legacy 트리에서 읽음

    verify는 API 재현성 기준으로 엔드포인트를 걸러 kind=='frontend' 페이지를 떨궈낼 수 있어(api-tree-verified.json), 
    프론트 페이지 목록은 전체 트리를 보존하는 api-tree-ready.json(→ 없으면 api-tree.json) 기준으로 읽음
    """
    from inventory.load import load_cached_tree

    for inv in ("ready", "verified"):
        try:
            tree = load_cached_tree(data_dir, inventory=inv)
        except Exception:
            tree = None
        if tree is not None:
            routes = load_frontend_routes(tree)
            if routes:
                return routes
    return []


def load_overrides(raw_config: dict[str, Any] | None) -> list[dict[str, str]]:
    """config `frontend.route_overrides`의 명시적 API→프론트 매핑(휴리스틱 예외).

    쿠키 스킴·404 문구와 함께 앱 특화 값을 한곳(config)에 모은다 — 모듈에는 앱 값이 없다.
    """
    cfg = (raw_config or {}).get("frontend") or {}
    routes = cfg.get("route_overrides") or []
    return [r for r in routes if isinstance(r, dict) and r.get("api_path") and r.get("front_path")]


def _strip_api_prefix(path: str) -> str:
    for p in _API_PREFIXES:
        if path == p:
            return "/"
        if path.startswith(p + "/"):
            return path[len(p):]
    return path


def _tokens(path: str) -> list[str]:
    """경로를 소문자 토큰으로 — 숫자 세그먼트(id)와 path-param 자리표시자는 제외"""
    return [t for t in re.split(r"[/{}]", path.lower()) if t and not t.isdigit()]


def _score(api_tokens: list[str], route_tokens: list[str]) -> int:
    if not route_tokens:
        return 0
    shared = len(set(api_tokens) & set(route_tokens))
    tail = 0
    for a, b in zip(reversed(api_tokens), reversed(route_tokens)):
        if a == b:
            tail += 1
        else:
            break
    score = shared + tail * 2
    if set(route_tokens) <= set(api_tokens):  # 프론트 토큰이 API 토큰의 부분집합
        score += 3
    return score


def match_route(
    api_path: str,
    routes: list[FrontRoute],
    overrides: list[dict[str, str]],
) -> tuple[FrontRoute | None, str]:
    """API 경로에 대응되는 프론트 라우트를 찾는다. (route, 방식) 반환."""
    for ov in overrides:
        if fnmatch.fnmatch(api_path, str(ov["api_path"])):
            base = str(ov.get("front_base") or (routes[0].base_url if routes else ""))
            return FrontRoute(path=str(ov["front_path"]), base_url=base, source="override"), "override"

    api_tokens = _tokens(_strip_api_prefix(api_path))
    if not api_tokens or not routes:
        return None, "no_route"

    best: FrontRoute | None = None
    best_score = 0
    for r in routes:
        s = _score(api_tokens, _tokens(r.path))
        if s > best_score:
            best_score, best = s, r
    if best is not None and best_score >= _MIN_HEURISTIC_SCORE:
        return best, "heuristic"
    return None, "no_match"


def resolve_front_base(route: FrontRoute) -> str:
    """도커 안 Chromium이 접근 가능하도록 localhost→ARGUS_PROBE_HOST 재작성"""
    return probe_base_url(route.base_url)


def build_front_cookies(
    session: dict[str, Any],
    front_base: str,
    fcfg: FrontConfig,
) -> list[dict[str, Any]]:
    """진단 세션 → 프론트 로그인 쿠키. 쿠키 이름 매핑은 config(FrontConfig)에서 옴

    session_token_bundle이 세션에서 논리 필드(access/refresh/member_id/role/username/…)를 뽑고, 
    fcfg.cookie_names가 그것을 앱별 실제 쿠키 이름에 매핑
    """
    b = session_token_bundle(session)
    values = {
        "access": b.get("access"),
        "refresh": b.get("refresh"),
        "member_id": b.get("member_id"),
        "role": b.get("role"),
        "username": b.get("username") or b.get("email"),
        "name": b.get("name"),
        "nickname": b.get("nickname"),
    }
    # 필수 논리 필드가 하나라도 비면 유효한 로그인 쿠키를 못 만든다.
    if any(not values.get(req) for req in fcfg.cookie_required):
        return []

    domain = urlparse(front_base).hostname or "localhost"
    expires_at = int(time.time()) + 7 * 24 * 60 * 60
    cookies: list[dict[str, Any]] = []
    for logical, cookie_name in fcfg.cookie_names.items():
        val = values.get(logical)
        if not val or not cookie_name:
            continue
        cookies.append(
            {
                "name": str(cookie_name),
                "value": str(val),
                "domain": domain,
                "path": "/",
                "sameSite": "Lax",
                "expires": expires_at,
            }
        )
    return cookies


class FrontBrowser:
    """쿠키를 심고 프론트 라우트로 이동해 1280×720으로 캡처하는 Playwright 세션.

    한 프로세스에서 sync_playwright를 두 번 start하면 충돌하므로, 정적 렌더용
    브라우저가 이미 있으면 그것을 넘겨받아 컨텍스트만 새로 연다(`browser=` 인자).
    """

    def __init__(self, browser: Any = None, error_phrases: tuple[str, ...] = _DEFAULT_ERROR_PHRASES) -> None:
        self._own = browser is None
        self._pw = None
        self._browser = browser
        self._error_phrases = error_phrases
        self._context = None
        self._page = None

    def __enter__(self) -> "FrontBrowser":
        if self._browser is None:
            from playwright.sync_api import sync_playwright

            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(headless=True)
        self._context = self._browser.new_context(viewport={"width": 1280, "height": 720})
        self._page = self._context.new_page()
        return self

    def __exit__(self, *_args: object) -> None:
        if self._context:
            self._context.close()
        if self._own:
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()

    def capture(
        self,
        front_base: str,
        route_path: str,
        cookies: list[dict[str, Any]],
        out_path: Path,
        highlight_values: list[str] | None = None,
    ) -> tuple[bool, str]:
        """프론트 라우트로 이동해 캡처. 404/에러면 (False, 'page_broken:...') 반환하고 저장 안 함.

        highlight_values(그 계정의 노출값)가 있으면 그 텍스트 위치로 스크롤해 개인정보가
        화면에 보이도록 한 뒤 캡처한다.
        """
        assert self._page is not None and self._context is not None
        try:
            self._context.clear_cookies()
            if cookies:
                self._context.add_cookies(cookies)
            root = front_base.rstrip("/") + "/"
            # SPA 세션 복원이 먼저 돌도록 루트를 한 번 로드한 뒤 목표 라우트로 이동.
            self._page.goto(root, wait_until="domcontentloaded", timeout=30000)
            target = front_base.rstrip("/") + (route_path if route_path.startswith("/") else "/" + route_path)
            self._page.goto(target, wait_until="networkidle", timeout=30000)
            self._page.wait_for_timeout(700)

            broken = self._broken_reason()
            if broken:
                return False, f"page_broken:{broken}"

            if highlight_values:
                self._scroll_to_value(highlight_values)
                self._page.wait_for_timeout(300)

            out_path.parent.mkdir(parents=True, exist_ok=True)
            self._page.screenshot(path=str(out_path))
            return True, target
        except Exception as exc:
            return False, str(exc)[:200]

    def _broken_reason(self) -> str | None:
        """404/에러/로그인 리다이렉트로 보이면 사유 문자열, 정상이면 None."""
        try:
            url = str(self._page.url).lower()  # type: ignore[union-attr]
        except Exception:
            url = ""
        for token in ("/404", "/401", "/403", "/500", "/503"):
            if url.rstrip("/").endswith(token):
                return f"redirect{token}"
        try:
            text = (self._page.inner_text("body") or "")[:1500].lower()  # type: ignore[union-attr]
        except Exception:
            return None
        for phrase in self._error_phrases:
            if phrase in text:
                return "not_found"
        return None

    def _scroll_to_value(self, values: list[str]) -> bool:
        for v in values:
            if not v:
                continue
            try:
                loc = self._page.get_by_text(v, exact=False)  # type: ignore[union-attr]
                if loc.count() > 0:
                    loc.first.scroll_into_view_if_needed(timeout=3000)
                    return True
            except Exception:
                continue
        return False

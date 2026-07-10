"""보호가 필요한 중요 페이지 후보 선정 규칙"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from inventory.schema import Endpoint

PROTECTED_RE = re.compile(
    r"(?i)(^|/)(admin|master|manager|manage|console|backoffice|cms|mypage|dashboard|board|게시판|post|notice|write|account|member|seller|user|profile|settings|config|order|payment|checkout|upload|internal|private)(/|$|\.|-)"
)
EXCLUDED_RE = re.compile(r"(?i)(^|/)(login|signin|sign-in|signup|logout|health|actuator|public|swagger)(/|$)")
STATIC_RE = re.compile(r"(?i)\.(css|js|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp)(\?|$)")
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# 서버가 인증을 "강제"한다는 증거로 인정할 헤더. Cookie 는 제외
# 브라우저는 공개 엔드포인트에도 동일 출처면 쿠키를 항상 붙이므로 "보호됨" 신호가 아님
TOKEN_AUTH_HEADERS = frozenset({"authorization", "x-api-key", "x-auth-token", "x-access-token"})


def _has_token_auth_header(ep: Endpoint) -> bool:
    return any(
        str(getattr(header, "name", "")).lower() in TOKEN_AUTH_HEADERS
        for header in ep.request_headers
    )


def candidate_score(ep: Endpoint) -> int:
    score = 0
    if PROTECTED_RE.search(ep.path or ""):
        score += 2
    if set(ep.auth or []) == {"authenticated"}:
        score += 3
    elif "authenticated" in (ep.auth or []):
        score += 2
    if _has_token_auth_header(ep):
        score += 2
    return score


def has_protected_signal(ep: Endpoint) -> bool:
    """이 엔드포인트가 '로그인이 필요해야 하는' 자원이라는 긍정적 근거가 있는가.

    익명 200 응답만으로는 공개/보호를 구분할 수 없으므로, HIGH/MEDIUM 판정은
    이 신호(민감 경로 · 인벤토리 인증 라벨 · 명시적 토큰 인증 헤더)가 있을 때로 제한
    """
    if PROTECTED_RE.search(ep.path or ""):
        return True
    if "authenticated" in (ep.auth or []):
        return True
    return _has_token_auth_header(ep)


def _allowed(ep: Endpoint, *, include_frontend: bool, include_write_methods: bool) -> bool:
    path = ep.path or "/"
    lower = path.lower()
    if EXCLUDED_RE.search(path) or lower.startswith("/api/auth/") or STATIC_RE.search(path):
        return False
    if ep.kind == "frontend" and not include_frontend:
        return False
    return include_write_methods or ep.method.upper() in SAFE_METHODS


def _forced_paths(module_dir: Path, extra: list[Any]) -> list[str]:
    paths: list[str] = []
    source = module_dir / "assets" / "forced_browse_paths.txt"
    if source.is_file():
        paths.extend(source.read_text(encoding="utf-8").splitlines())
    paths.extend(str(item) for item in extra)
    return [p.strip() for p in paths if p.strip() and not p.lstrip().startswith("#")]


def select_candidates(
    endpoints: list[Endpoint], *, module_dir: Path, bases: list[str], min_score: int,
    max_count: int, scan_all_inventory: bool, forced_browse_enabled: bool,
    include_frontend: bool, include_write_methods: bool, extra_protected_paths: list[Any],
) -> list[Endpoint]:
    ranked = [ep for ep in endpoints if _allowed(ep, include_frontend=include_frontend, include_write_methods=include_write_methods)]
    if not scan_all_inventory:
        ranked = [ep for ep in ranked if candidate_score(ep) >= min_score]
    ranked.sort(key=lambda ep: (-candidate_score(ep), ep.base_url, ep.path, ep.method))

    if forced_browse_enabled:
        existing = {(ep.base_url.rstrip("/"), ep.path) for ep in ranked}
        for base in bases:
            for path in _forced_paths(module_dir, extra_protected_paths):
                normalized = path if path.startswith("/") else f"/{path}"
                key = (base.rstrip("/"), normalized)
                if key not in existing:
                    ranked.append(Endpoint(method="GET", path=normalized, base_url=base.rstrip("/"), kind="frontend", tags=["4-4-forced-browse"]))
                    existing.add(key)
    return ranked if max_count <= 0 else ranked[:max_count]

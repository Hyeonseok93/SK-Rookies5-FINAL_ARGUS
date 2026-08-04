"""점검 항목 5-2 스크린샷 캡처: 요청 및 응답 값 내 주요정보 포함여부 확인

5-2 진단 리포트(data/report/5-2/latest.yaml)를 읽어 finding을 개별 케이스로 그룹핑하고, 
선택된 각 finding의 원본 프로브를 다시 전송해 실제 요청/응답 증거를 확보한 뒤, 
인스턴스마다 1280x720 PNG를 data/report/5-2/evidence/ 에 렌더링
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from diagnosis.auth_session_pool import DiagnosisAuthPool
from diagnosis.context import DiagnosisContext
from diagnosis.paths import section_evidence_dir, section_report_path
from diagnosis.probe_transport import HttpxTransport
from diagnosis.result import SectionReport, utc_now_iso
from inventory.load import load_api_tree

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    mod_name = f"screenshot_g52_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


grouping = _load_local("grouping")
capture = _load_local("capture")
render = _load_local("render")
front_capture = _load_local("front_capture")


@dataclass
class ScreenshotRunResult:
    ok: bool
    message: str
    cases_total: int = 0
    screenshots_total: int = 0
    evidence_dir: str = ""
    manifest_path: str = ""


_SLUG_RE = re.compile(r"[^a-zA-Z0-9]+")


def _slugify(text: str, *, max_len: int = 50) -> str:
    slug = _SLUG_RE.sub("-", text).strip("-").lower()
    return slug[:max_len] or "x"


def _path_of(url: str) -> str:
    return urlparse(url).path or "/"


def _get_header(headers: dict[str, str], name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _short_id(*parts: str) -> str:
    import hashlib

    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:8].upper()


def _markers_visible(expected: list[str], *texts: str) -> int:
    """렌더링된 요청/응답 텍스트에 실제로 나타난 기대 마커의 개수"""
    blob = "\n".join(texts)
    return sum(1 for m in expected if m and m in blob)


def _load_section_report(ctx: DiagnosisContext) -> SectionReport | None:
    path = section_report_path(ctx.data_dir, "5-2")
    if not path.is_file():
        return None
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return None
    return SectionReport.from_dict(raw)


def _clear_stale_evidence(evidence_dir: Path) -> None:
    """이 모듈이 만든 최상위 증거(png + manifest)만 삭제해 항상 최신 회차만 남긴다.

    파일명이 회차마다 달라져(seq/경로 기준) 옛 스크린샷이 orphan으로 쌓이는 걸 막는다.
    하위 폴더는 건드리지 않는다(다른 파이프라인의 산출물 보존).
    """
    if not evidence_dir.is_dir():
        return
    for p in evidence_dir.iterdir():
        if p.is_file() and (p.suffix.lower() == ".png" or p.name == "evidence_manifest.json"):
            try:
                p.unlink()
            except OSError:
                pass


def capture_from_findings(
    ctx: DiagnosisContext,
    findings: list[Any],
    *,
    sessions: list[dict[str, Any]] | None = None,
    timeout: float = 15.0,
) -> ScreenshotRunResult:
    """메모리상의 finding으로부터 증거 스크린샷을 캡처 (5-2 스캐너가 호출)

    (엔드포인트 × 계정) 노출당 스크린샷 1장 — 해당 계정이 그 엔드포인트에서 흘리는 모든 값을 함께 강조,
    `sessions`로 이미 인증된 진단 세션을 넘겨주면 로그인을 다시 수행하지 않음
    """
    # 회차 시작 시 옛 증거를 먼저 비운다 → 재진단 시 항상 최신 회차만 남김(0건이어도 정리됨).
    evidence_dir = section_evidence_dir(ctx.data_dir, "5-2")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    _clear_stale_evidence(evidence_dir)

    shots = grouping.select_shots(findings)
    if not shots:
        return ScreenshotRunResult(ok=False, message="5-2 report has no PII findings to screenshot.")

    tree = load_api_tree(ctx.data_dir)
    if tree is None:
        return ScreenshotRunResult(ok=False, message="No API inventory (api-tree) found — cannot re-issue probes.")

    if sessions is None:
        auth_pool = DiagnosisAuthPool(ctx.raw_config, data_dir=ctx.data_dir)
        sessions = auth_pool.sessions()

    # 프론트 화면 캡처(보조 증거) — 인벤토리에 프론트 라우트가 있을 때만 활성화.
    # 프론트 라우트는 verify가 떨궈낼 수 있어 전체(ready) 트리 기준으로 읽는다.
    # 앱 종속 요소(쿠키 스킴/404 문구)는 config `frontend` 섹션에서 온다(미설정 시 프론트 비활성).
    front_routes = front_capture.load_frontend_routes_best(ctx.data_dir)
    front_overrides = front_capture.load_overrides(ctx.raw_config)
    front_cfg = front_capture.load_front_config(ctx.raw_config)
    front_enabled = bool(front_routes or front_overrides)

    manifest_shots: list[dict[str, Any]] = []
    shots_captured = 0
    front_captured = 0
    front_cache: dict[tuple[str, str], dict[str, Any]] = {}  # (account, route) → 동일 화면 재사용

    with contextlib.ExitStack() as stack:
        transport = stack.enter_context(HttpxTransport(timeout=timeout))
        browser = stack.enter_context(render.ScreenshotBrowser())
        front_browser = None
        if front_enabled:
            try:
                # 같은 Chromium을 재사용(별도 컨텍스트) — sync_playwright 이중 start 방지.
                front_browser = stack.enter_context(
                    front_capture.FrontBrowser(browser=browser.browser, error_phrases=front_cfg.error_phrases)
                )
            except Exception:
                front_browser = None

        for shot in shots:
            endpoint = capture.find_endpoint(tree.endpoints, shot.endpoint_id)
            if endpoint is None:
                manifest_shots.append(
                    {
                        "seq": shot.seq,
                        "endpoint_id": shot.endpoint_id,
                        "kind": shot.kind,
                        "account": shot.account_label(),
                        "status": "skipped",
                        "reason": "endpoint_not_found_in_inventory",
                    }
                )
                continue

            # response shot은 특정 계정으로 재요청하고, request shot은 계정과 무관하므로 (프로브 본문이 동일) 익명으로 재요청
            if shot.kind == "response":
                session, matched = capture.resolve_session_for_auth_mode(shot.account, {}, sessions)
            else:
                session, matched = None, True

            result = capture.reprobe(endpoint, account_auth=session, transport=transport, timeout=timeout)

            content_type = _get_header(result.response_headers, "content-type")
            req_body_pretty = render.pretty_body(
                result.request_body, _get_header(result.request_headers, "content-type")
            )
            resp_body_pretty = render.pretty_body(result.response_body, content_type)

            note = "" if result.ok else f"reprobe error: {result.error}"
            if shot.kind == "response" and not matched:
                note = (note + " · " if note else "") + "해당 계정 세션 없음 — 익명으로 재요청됨"

            spec = render.ShotSpec(
                tab_label=f"ARGUS · {result.method} {_path_of(result.url)}",
                method=result.method,
                url=result.url,
                request_headers=result.request_headers,
                request_body=req_body_pretty,
                status_code=result.status_code,
                response_content_type=content_type,
                response_body_text=resp_body_pretty,
                severity=shot.severity,
                category_label=shot.category_label(),
                account_label=shot.account_label(),
                short_id=_short_id(shot.endpoint_id, shot.kind, shot.account),
                captured_at=utc_now_iso(),
                url_markers=shot.url_markers,
                request_body_markers=shot.request_body_markers,
                response_body_markers=shot.response_body_markers,
                note=note,
            )
            html_doc = render.render_html(spec)

            if shot.kind == "request":
                acct_slug = "probe"
            elif shot.account in ("", "anonymous"):
                acct_slug = "anon"
            else:
                acct_slug = _slugify(shot.account_label())
            filename = f"{shot.seq:02d}_{acct_slug}_{shot.kind}_{_slugify(_path_of(result.url))}.png"
            out_path = evidence_dir / filename
            browser.capture(html_doc, out_path)
            shots_captured += 1

            # 보조 증거: 이 계정으로 로그인한 실제 프론트 화면 (response shot + 대응 라우트 존재 시)
            front_info: dict[str, Any] | None = None
            if front_browser is not None and shot.kind == "response" and session is not None and matched:
                route, how = front_capture.match_route(endpoint.path, front_routes, front_overrides)
                if route is not None:
                    cache_key = (shot.account, route.path)
                    cached = front_cache.get(cache_key)
                    if cached is not None:
                        # 같은 (계정 × 프론트 라우트)는 화면이 동일하므로 한 번만 캡처하고 재사용.
                        front_info = {**cached, "deduped": True}
                    else:
                        front_base = front_capture.resolve_front_base(route)
                        cookies = front_capture.build_front_cookies(session, front_base, front_cfg)
                        front_name = f"{shot.seq:02d}_{acct_slug}_frontpage_{_slugify(route.path)}.png"
                        ok_f, info_f = front_browser.capture(
                            front_base,
                            route.path,
                            cookies,
                            evidence_dir / front_name,
                            highlight_values=shot.response_body_markers,
                        )
                        if ok_f:
                            front_captured += 1
                        front_info = {
                            "file": front_name if ok_f else None,
                            "front_url": info_f if ok_f else None,
                            "route_path": route.path,
                            "match": how,
                            "cookies_built": len(cookies),
                            "ok": ok_f,
                            "error": None if ok_f else info_f,
                            "deduped": False,
                        }
                        front_cache[cache_key] = front_info

            expected = shot.url_markers + shot.request_body_markers + shot.response_body_markers
            visible = _markers_visible(expected, spec.url, req_body_pretty, resp_body_pretty)
            manifest_shots.append(
                {
                    "seq": shot.seq,
                    "file": filename,
                    "endpoint_id": shot.endpoint_id,
                    "kind": shot.kind,
                    "account": shot.account_label(),
                    "severity": shot.severity,
                    "categories": shot.categories,
                    "rule_ids": shot.rule_ids,
                    "field_paths": shot.field_paths,
                    "markers_expected": len(expected),
                    "markers_visible": visible,
                    "auth_session_matched": matched,
                    "status_code": result.status_code,
                    "reprobe_ok": result.ok,
                    "reprobe_error": result.error,
                    "front": front_info,
                    "status": "captured",
                }
            )

    manifest = {
        "section_id": "5-2",
        "generated_at": utc_now_iso(),
        "shots_total": shots_captured,
        "front_shots_total": front_captured,
        "front_enabled": front_enabled,
        "shots": manifest_shots,
    }
    manifest_path = evidence_dir / "evidence_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    return ScreenshotRunResult(
        ok=True,
        message=(
            f"{shots_captured} API screenshot(s) + {front_captured} front-page screenshot(s) "
            f"captured ({len(shots)} exposure shot(s))."
        ),
        cases_total=len(shots),
        screenshots_total=shots_captured,
        evidence_dir=str(evidence_dir),
        manifest_path=str(manifest_path),
    )


def run(ctx: DiagnosisContext, *, timeout: float = 15.0) -> ScreenshotRunResult:
    """단독 실행 진입점: 저장된 5-2 리포트를 디스크에서 읽고 스크린샷을 캡처"""
    report = _load_section_report(ctx)
    if report is None:
        return ScreenshotRunResult(
            ok=False,
            message="5-2 report not found (data/report/5-2/latest.yaml) — run the 5-2 diagnosis scan first.",
        )
    return capture_from_findings(ctx, report.findings, timeout=timeout)


def _build_standalone_context() -> DiagnosisContext:
    """이 모듈을 직접 실행하기 위한 컨텍스트 빌더(app diagnosis_service._context와 동일)"""
    import os

    from app.config import BACKEND_ROOT, config_to_inventory_dict, load_config
    from app.services.test_accounts_service import load_test_accounts

    cfg = load_config()
    env_path = os.environ.get("CONFIG_PATH")
    config_path = Path(env_path) if env_path else (BACKEND_ROOT / "config.yaml")
    raw: dict[str, Any] = {}
    if config_path.is_file():
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    test_accs = load_test_accounts().get("accounts")
    if test_accs:
        raw.setdefault("auth", {})
        if not raw["auth"].get("accounts"):
            raw["auth"]["accounts"] = test_accs

    env = (os.environ.get("ARGUS_DATA_DIR") or "").strip()
    return DiagnosisContext(
        data_dir=Path(env) if env else (BACKEND_ROOT / "data"),
        config=config_to_inventory_dict(cfg),
        raw_config=raw,
    )


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO)
    _ctx = _build_standalone_context()
    _result = run(_ctx)
    print(_result)

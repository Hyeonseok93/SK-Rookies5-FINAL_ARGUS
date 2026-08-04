"""점검 항목 4-4 스크린샷 캡처: 비인증 상태로 중요 page접근 가능성

4-4 진단 리포트(data/report/4-4/latest.yaml)를 읽어 케이스(trigger)별 대표 finding을 최대 3건 선정하고, 
각 finding마다 1280x720 PNG 한 쌍을 data/report/4-4/evidence/ 에 캡처:

  * 기본 (정상)  — 유효 세션으로 접근한 페이지(권한 있는 정상 접근)
  * 비교 (비정상) — 자격증명 없이 접근했는데도 콘텐츠가 노출되는 동일 페이지

프론트엔드 페이지는 비정상 프레임을 실제 익명 브라우저 렌더로 만들고(로그인 없이 실제로 그려지는 화면), 
API 엔드포인트는 Burp 스타일 요청/응답 프레임으로 만듦,
여기엔 타깃 종속적인 부분이 없다 — 모든 엔드포인트/base URL은 api-tree에서 옴
"""

from __future__ import annotations

import hashlib
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
from diagnosis.endpoint_auth_passes import primary_session_for_endpoint
from diagnosis.paths import section_evidence_dir, section_report_path
from diagnosis.probe_transport import HttpxTransport
from diagnosis.result import SectionReport, utc_now_iso
from inventory.load import load_api_tree

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    mod_name = f"screenshot_g44_{name}"
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


@dataclass
class ScreenshotRunResult:
    ok: bool
    message: str
    cases_total: int = 0
    screenshots_total: int = 0
    evidence_dir: str = ""
    manifest_path: str = ""


_SLUG_RE = re.compile(r"[^a-zA-Z0-9]+")


def _slugify(text: str, *, max_len: int = 40) -> str:
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
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:8].upper()


def _account_label(session: dict[str, Any] | None) -> str:
    if not session:
        return "익명"
    return str(session.get("email") or "인증 계정")


def _is_html(content_type: str) -> bool:
    return "html" in content_type.lower()


def _is_success(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def _load_section_report(ctx: DiagnosisContext) -> SectionReport | None:
    path = section_report_path(ctx.data_dir, "4-4")
    if not path.is_file():
        return None
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return None
    return SectionReport.from_dict(raw)


def _clear_stale_evidence(evidence_dir: Path) -> None:
    """이 모듈이 만든 최상위 증거(png + manifest)만 삭제해 항상 최신 회차만 남긴다.

    파일명이 회차마다 달라져 옛 스크린샷이 orphan으로 쌓이는 걸 막는다. 하위 폴더
    (진단 replay가 만든 4-4-<hash>/ 등)는 건드리지 않는다.
    """
    if not evidence_dir.is_dir():
        return
    for p in evidence_dir.iterdir():
        if p.is_file() and (p.suffix.lower() == ".png" or p.name == "evidence_manifest.json"):
            try:
                p.unlink()
            except OSError:
                pass


def _normal_spec(
    shot: Any, session: dict[str, Any] | None, result: Any, sid: str
) -> Any:
    """기본(정상) 프레임 — 유효 세션으로 접근한 페이지(이번 실행에 세션이 없으면 '차단 기대' 기준 카드)"""
    if session is None or result is None:
        # 사용 가능한 자격증명이 없음 → 실제 인증 화면을 캡처할 수 없으므로,
        # 캡처를 조작하지 않고 명시적인 '기대 동작' 카드를 렌더
        return render.FrameSpec(
            frame_role="정상 접근 기대 (인증 요구)",
            role_kind="expected",
            case_label=shot.trigger_label(),
            severity=shot.severity,
            account_label="비교 계정 없음",
            short_id=sid,
            captured_at=utc_now_iso(),
            url=f"{shot.base_url.rstrip('/')}{shot.path}",
            method=shot.method,
            request_headers={},
            status_code=None,
            response_content_type="",
            response_body_text="",
            auth_present=False,
            note="정상 동작 기대: 인증 세션이 없으면 401/403 또는 로그인 리다이렉트가 반환되어야 한다.",
        )
    content_type = _get_header(result.response_headers, "content-type")
    return render.FrameSpec(
        frame_role="정상 접근 (인증)",
        role_kind="normal",
        case_label=shot.trigger_label(),
        severity=shot.severity,
        account_label=_account_label(session),
        short_id=sid,
        captured_at=utc_now_iso(),
        url=result.url,
        method=result.method,
        request_headers=result.request_headers,
        request_body=render.pretty_body(
            result.request_body, _get_header(result.request_headers, "content-type")
        ),
        status_code=result.status_code,
        response_content_type=content_type,
        response_body_text=render.pretty_body(result.response_body, content_type),
        auth_present=render.has_auth_header(result.request_headers),
        note="" if result.ok else f"reprobe error: {result.error}",
    )


def _abnormal_http_spec(shot: Any, result: Any, sid: str) -> Any:
    """비교(비정상) 프레임을 Burp 스타일 요청/응답으로 렌더(API 또는 비-HTML)"""
    content_type = _get_header(result.response_headers, "content-type")
    return render.FrameSpec(
        frame_role="비정상 접근 (비인증)",
        role_kind="abnormal",
        case_label=shot.trigger_label(),
        severity=shot.severity,
        account_label="익명",
        short_id=sid,
        captured_at=utc_now_iso(),
        url=result.url,
        method=result.method,
        request_headers=result.request_headers,
        request_body=render.pretty_body(
            result.request_body, _get_header(result.request_headers, "content-type")
        ),
        status_code=result.status_code,
        response_content_type=content_type,
        response_body_text=render.pretty_body(result.response_body, content_type),
        auth_present=render.has_auth_header(result.request_headers),
        note="" if result.ok else f"reprobe error: {result.error}",
    )


def _abnormal_page_spec(shot: Any, result: Any, sid: str, page_b64: str) -> Any:
    """비교(비정상) 프레임을 실제 익명 브라우저 렌더로(프런트엔드 페이지)"""
    return render.FrameSpec(
        frame_role="비정상 접근 (비인증)",
        role_kind="abnormal",
        case_label=shot.trigger_label(),
        severity=shot.severity,
        account_label="익명",
        short_id=sid,
        captured_at=utc_now_iso(),
        url=result.url,
        method=result.method,
        status_code=result.status_code,
        response_content_type=_get_header(result.response_headers, "content-type"),
        page_png_b64=page_b64,
        note="로그인하지 않은 브라우저에서 보호 페이지가 그대로 렌더링됨.",
    )


def capture_from_findings(
    ctx: DiagnosisContext,
    findings: list[Any],
    *,
    sessions: list[dict[str, Any]] | None = None,
    timeout: float = 15.0,
) -> ScreenshotRunResult:
    # 회차 시작 시 옛 증거를 먼저 비운다 → 재진단 시 항상 최신 회차만 남김(0건이어도 정리됨).
    evidence_dir = section_evidence_dir(ctx.data_dir, "4-4")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    _clear_stale_evidence(evidence_dir)

    shots = grouping.select_shots(findings)
    if not shots:
        return ScreenshotRunResult(ok=False, message="4-4 report has no page-access findings to screenshot.")

    tree = load_api_tree(ctx.data_dir)
    if tree is None:
        return ScreenshotRunResult(ok=False, message="No API inventory (api-tree) found — cannot re-issue probes.")

    if sessions is None:
        pool = DiagnosisAuthPool(ctx.raw_config, data_dir=ctx.data_dir)
        pool.ensure_valid()
        sessions = pool.sessions()

    manifest_shots: list[dict[str, Any]] = []
    shots_captured = 0

    with HttpxTransport(timeout=timeout) as anon_tx, HttpxTransport(timeout=timeout) as auth_tx, render.ScreenshotBrowser() as browser:
        for shot in shots:
            endpoint = capture.find_endpoint(tree.endpoints, shot.endpoint_id)
            if endpoint is None:
                manifest_shots.append({
                    "seq": shot.seq, "endpoint_id": shot.endpoint_id, "trigger": shot.trigger,
                    "status": "skipped", "reason": "endpoint_not_found_in_inventory",
                })
                continue

            sid = _short_id(shot.endpoint_id, shot.trigger)
            slug = f"{shot.case_slug()}_{_slugify(_path_of(f'{shot.base_url}{shot.path}'))}"

            # --- 비정상(비인증) pass: 항상 익명 ---
            anon = capture.reprobe(endpoint, account_auth=None, transport=anon_tx, timeout=timeout)

            # --- 정상(인증) pass: 이 엔드포인트에 맞는 유효 세션이 있으면 그걸로 재요청 ---
            session = primary_session_for_endpoint(endpoint, sessions or [], None)
            auth = (
                capture.reprobe(endpoint, account_auth=session, transport=auth_tx, timeout=timeout)
                if session
                else None
            )

            # 기본(정상) 프레임
            normal_spec = _normal_spec(shot, session, auth, sid)
            normal_file = f"{shot.seq:02d}a_{slug}_normal.png"
            browser.capture(render.render_html(normal_spec), evidence_dir / normal_file)
            shots_captured += 1

            # 비교(비정상) 프레임 — 프런트엔드 HTML 페이지는 실제 브라우저 렌더, 그 외엔 Burp 프레임
            page_b64 = ""
            anon_ct = _get_header(anon.response_headers, "content-type")
            if endpoint.kind == "frontend" and _is_success(anon.status_code) and _is_html(anon_ct):
                png = browser.render_page(anon.url, timeout=timeout)
                if png:
                    page_b64 = render.png_to_b64(png)
            if page_b64:
                abnormal_spec = _abnormal_page_spec(shot, anon, sid, page_b64)
                abnormal_mode = "page_render"
            else:
                abnormal_spec = _abnormal_http_spec(shot, anon, sid)
                abnormal_mode = "http_frame"
            abnormal_file = f"{shot.seq:02d}b_{slug}_abnormal.png"
            browser.capture(render.render_html(abnormal_spec), evidence_dir / abnormal_file)
            shots_captured += 1

            manifest_shots.append({
                "seq": shot.seq,
                "trigger": shot.trigger,
                "case": shot.trigger_label(),
                "severity": shot.severity,
                "endpoint_id": shot.endpoint_id,
                "method": shot.method,
                "path": shot.path,
                "kind": endpoint.kind,
                "normal_frame": {
                    "file": normal_file,
                    "role": normal_spec.role_kind,
                    "account": normal_spec.account_label,
                    "status_code": auth.status_code if auth else None,
                    "auth_present": normal_spec.auth_present,
                    "reprobe_ok": auth.ok if auth else None,
                },
                "abnormal_frame": {
                    "file": abnormal_file,
                    "mode": abnormal_mode,
                    "status_code": anon.status_code,
                    "reprobe_ok": anon.ok,
                    "reprobe_error": anon.error,
                },
                "status": "captured",
            })

    manifest = {
        "section_id": "4-4",
        "generated_at": utc_now_iso(),
        "findings_captured": len(manifest_shots),
        "screenshots_total": shots_captured,
        "shots": manifest_shots,
    }
    manifest_path = evidence_dir / "evidence_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    return ScreenshotRunResult(
        ok=True,
        message=f"{shots_captured} screenshot(s) captured for {len(shots)} finding(s).",
        cases_total=len(shots),
        screenshots_total=shots_captured,
        evidence_dir=str(evidence_dir),
        manifest_path=str(manifest_path),
    )


def run(ctx: DiagnosisContext, *, timeout: float = 15.0) -> ScreenshotRunResult:
    """단독 실행 진입점: 저장된 4-4 리포트를 디스크에서 읽고 스크린샷을 캡처"""
    report = _load_section_report(ctx)
    if report is None:
        return ScreenshotRunResult(
            ok=False,
            message="4-4 report not found (data/report/4-4/latest.yaml) — run the 4-4 diagnosis scan first.",
        )
    return capture_from_findings(ctx, report.findings, timeout=timeout)


def _build_standalone_context() -> DiagnosisContext:
    """이 모듈을 직접 실행하기 위한 컨텍스트 빌더"""
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

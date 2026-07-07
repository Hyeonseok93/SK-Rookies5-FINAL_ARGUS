"""익명/인증 2-pass 프로브와 리플레이 증거 생성"""

from __future__ import annotations

import hashlib
import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from app.services.zap_util import probe_url
from diagnosis.endpoint_auth_passes import primary_session_for_endpoint
from diagnosis.replay.normalize import probe_base_key
from diagnosis.replay.recorder import ReplaySession
from diagnosis.result import DiagnosisFinding
from inventory.probe_build import build_probe_request
from inventory.schema import Endpoint

_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    spec = importlib.util.spec_from_file_location(f"diag_g44_probes_{name}", _DIR / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"4-4 {name} 모듈을 불러올 수 없습니다")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_rules = _load_local("page_rules")
_candidates = _load_local("candidates")


@dataclass
class PageSnapshot:
    auth_mode: str
    http_status: int | None
    body: bytes
    headers: dict[str, str]
    url: str
    account_email: str | None = None
    error: str | None = None

    @property
    def fingerprint(self) -> dict[str, Any]:
        return {"sha256": hashlib.sha256(self.body).hexdigest(), "size": len(self.body)}


def _probe(transport: Any, ep: Endpoint, auth: dict[str, Any] | None, mode: str) -> PageSnapshot:
    probe = build_probe_request(ep, probe_base_fn=probe_url, account_auth=auth)
    body = str(probe.get("body") or "").encode("utf-8") or None
    response = transport.request(
        probe["method"], probe["url"], dict(probe.get("headers") or {}), body,
        follow_redirects=False,
    )
    return PageSnapshot(
        auth_mode=mode, http_status=response.status, body=response.body,
        headers=response.headers, url=probe["url"],
        account_email=str(auth.get("email") or "") if auth else None, error=response.error,
    )


def _snippet(snapshot: PageSnapshot) -> dict[str, Any]:
    ctype = snapshot.headers.get("content-type") or snapshot.headers.get("Content-Type") or ""
    text = snapshot.body[:500].decode("utf-8", errors="replace")
    return {"content_type": ctype, "body_snippet": text}


def _finding(ep: Endpoint, severity: str, trigger: str, meta: dict[str, Any], anonymous: PageSnapshot, authenticated: PageSnapshot | None, auth: dict[str, Any] | None, replay: ReplaySession | None) -> DiagnosisFinding:
    labels = {
        "unauth_access_confirmed": "인증이 필요한 중요 페이지가 비인증 상태로 접근됨",
        "anon_ok_auth_denied": "익명 요청은 성공했으나 유효 세션은 거부됨(이상 신호)",
        "unauth_access_no_account": "비인증 중요 페이지 접근 성공(비교 계정 없음)",
        "client_side_guard_only": "공개 SPA 셸과 동일하여 서버 측 노출로 확정하지 않음",
    }
    evidence = {
        "source": "httpx", "engine": "httpx", "analysis_mode": "active",
        "rule_id": "4-4-unauth-page-access", "trigger": trigger,
        "trigger_label": labels.get(trigger, trigger), "related_sections": ["4-4", "3-4", "4-3"],
        "endpoint_id": ep.endpoint_id, "method": ep.method, "path": ep.path,
        "base_url": ep.base_url, "http_status": anonymous.http_status,
        **_snippet(anonymous), **meta,
    }
    finding = DiagnosisFinding(
        severity=severity,
        message=f"비인증 중요 페이지 판정: {ep.method.upper()} {ep.path} ({labels.get(trigger, trigger)})",
        evidence=evidence,
    )
    if replay is None or severity not in ("high", "medium"):
        return finding
    recorder = replay.recorder(rule_id="4-4-unauth-page-access", path=ep.path, trigger=trigger)
    recorder.set_auth("anonymous")
    recorder.append_ui_flow(method=ep.method, path=ep.path)
    anon_probe = build_probe_request(ep, probe_base_fn=probe_url, account_auth=None)
    anon_step = recorder.record_http_from_probe(
        "anon", label="비인증 중요 페이지 요청", probe=anon_probe,
        response_status=anonymous.http_status, response_headers=anonymous.headers,
        response_body=anonymous.body, auth_mode="anonymous",
    )
    if authenticated is not None and auth is not None:
        recorder.set_auth("authenticated", account_email=authenticated.account_email)
        auth_probe = build_probe_request(ep, probe_base_fn=probe_url, account_auth=auth)
        auth_step = recorder.record_http_from_probe(
            "auth", label="인증 상태 비교 요청", probe=auth_probe,
            response_status=authenticated.http_status, response_headers=authenticated.headers,
            response_body=authenticated.body, auth_mode="authenticated",
            account_email=authenticated.account_email,
        )
        recorder.record_compare(anon_step, auth_step, label="비인증/인증 페이지 응답 비교")
    return recorder.attach_to(finding)


def run_page_probes(candidates: list[Endpoint], *, anonymous_transport: Any, authenticated_transport: Any, sessions: list[dict[str, Any]], login_report: dict[str, Any] | None, replay_session: ReplaySession | None, on_progress: Callable[..., None] | None = None):
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {"candidates": len(candidates), "probed": 0, "errors": 0, "auth_configured": bool(sessions)}
    shell_fingerprints: dict[str, str] = {}
    origin_enforces_auth: dict[str, bool] = {}
    probed: list[tuple[Endpoint, str, PageSnapshot, PageSnapshot | None, dict[str, Any] | None]] = []

    # 1단계: 전 후보를 프로빙하고, 출처별로 앱이 인증을 강제하는지(익명 401/403 관측) baseline 을 모음
    for ep in candidates:
        base = ep.base_url.rstrip("/")
        origin = probe_base_key(base)
        if ep.kind == "frontend" and base not in shell_fingerprints:
            shell_ep = Endpoint(method="GET", path="/", base_url=base, kind="frontend")
            shell = _probe(anonymous_transport, shell_ep, None, "anonymous")
            if shell.http_status is not None and 200 <= shell.http_status < 300:
                shell_fingerprints[base] = shell.fingerprint["sha256"]

        # 익명 요청은 인증 쿠키를 본 적 없는 전용 클라이언트에서만 실행
        anonymous = _probe(anonymous_transport, ep, None, "anonymous")
        auth = primary_session_for_endpoint(ep, sessions, login_report)
        authenticated = _probe(authenticated_transport, ep, auth, "authenticated") if auth else None
        stats["probed"] += 1
        if anonymous.error or (authenticated and authenticated.error):
            stats["errors"] += 1
        if anonymous.http_status in (401, 403):
            origin_enforces_auth[origin] = True
        else:
            origin_enforces_auth.setdefault(origin, False)
        probed.append((ep, origin, anonymous, authenticated, auth))
        if on_progress:
            on_progress(done=stats["probed"], total=len(candidates), message=ep.path)

    # 2단계: baseline 과 보호 신호를 반영해 판정
    for ep, origin, anonymous, authenticated, auth in probed:
        verdict = _rules.classify_unauth_page(
            path=ep.path, kind=ep.kind, anonymous=anonymous, authenticated=authenticated,
            protected_signal=_candidates.has_protected_signal(ep),
            origin_enforces_auth=origin_enforces_auth.get(origin, False),
            public_shell_sha256=shell_fingerprints.get(ep.base_url.rstrip("/")),
        )
        if verdict:
            severity, trigger, meta = verdict
            findings.append(_finding(ep, severity, trigger, meta, anonymous, authenticated, auth, replay_session))

    stats["findings"] = len(findings)
    stats["origins_enforcing_auth"] = sorted(o for o, v in origin_enforces_auth.items() if v)
    return findings, stats

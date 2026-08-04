"""Orchestrate guideline 1-5 redirect / CORS / crossdomain scan."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from diagnosis.probe_auth import all_account_auths_with_meta
from app.services.zap_util import ZapNotAvailableError
from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent

ProbeMode = Literal["base_only", "sample", "full"]


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g15_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


@dataclass
class ScanOptions:
    timeout: float = 8.0
    probe_mode: ProbeMode = "sample"
    sample_size: int = 60
    max_phase_a_jobs: int = 400
    max_phase_b_jobs: int = 800
    max_params_per_endpoint: int = 3
    zap_enabled: bool = False
    zap_max_minutes: int = 10
    zap_seed_cap: int = 200
    cors_enabled: bool = True
    crossdomain_enabled: bool = True


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_1_5") or raw.get("scan_1_5") or {}
    mode = str(cfg.get("probe_mode", "sample")).strip().lower()
    if mode not in ("base_only", "sample", "full"):
        mode = "sample"
    return ScanOptions(
        timeout=float(cfg.get("timeout", 8.0)),
        probe_mode=mode,  # type: ignore[arg-type]
        sample_size=max(10, min(int(cfg.get("sample_size", 60)), 500)),
        max_phase_a_jobs=max(20, min(int(cfg.get("max_phase_a_jobs", 400)), 5000)),
        max_phase_b_jobs=max(20, min(int(cfg.get("max_phase_b_jobs", 800)), 10000)),
        max_params_per_endpoint=max(1, min(int(cfg.get("max_params_per_endpoint", 3)), 10)),
        zap_enabled=bool(cfg.get("zap_enabled", False)),
        zap_max_minutes=max(1, min(int(cfg.get("zap_max_minutes", 10)), 120)),
        zap_seed_cap=max(20, min(int(cfg.get("zap_seed_cap", 200)), 5000)),
        cors_enabled=bool(cfg.get("cors_enabled", True)),
        crossdomain_enabled=bool(cfg.get("crossdomain_enabled", True)),
    )


def _primary_auth(raw: dict[str, Any], *, data_dir: Path | None = None) -> dict[str, Any] | None:
    sessions, _meta = all_account_auths_with_meta(raw, data_dir=data_dir, refresh=True)
    return sessions[0] if sessions else None


def _refresh_job_auth(
    jobs: list[dict[str, Any]], raw: dict[str, Any], *, data_dir: Path | None = None
) -> None:
    """job["headers"]에 박힌 로그인 세션(Authorization/Cookie)을 새로 받은 세션으로 갈아끼운다.

    phase A/B job의 헤더는 스캔 시작 시점에 한 번 캡처된다(build_phase_a/b_jobs). XSS 검증은
    sink 기반 redirect 검증(phase A+B, 최대 10,000+ job) + reflected_probe(같은 job 재검사)
    다음인 3번째 단계라, 그 사이 수만 건의 요청이 오간 뒤에야 실행된다 — 스캔이 오래 걸리면
    시작 시점 세션이 이 시점엔 만료돼 있을 수 있어, XSS 단계 직전에 한 번 더 로그인해 job의
    인증 헤더만 최신 값으로 덮어쓴다(다른 헤더/본문은 그대로 둔다).
    """
    from inventory.auth_util import auth_headers, is_auth_header

    try:
        fresh_auth = _primary_auth(raw, data_dir=data_dir)
    except Exception:
        return
    fresh_headers = auth_headers(fresh_auth)
    if not fresh_headers:
        return
    for job in jobs:
        headers = {k: v for k, v in (job.get("headers") or {}).items() if not is_auth_header(k)}
        headers.update(fresh_headers)
        job["headers"] = headers


def _dedupe_redirect_findings(items: list[DiagnosisFinding]) -> list[DiagnosisFinding]:
    seen: set[str] = set()
    out: list[DiagnosisFinding] = []
    for f in items:
        ev = f.evidence or {}
        # confirmed_redirect=False인 항목(REFLECTED_VALUE/REFLECTED_XSS 후보)은 어떤
        # payload를 썼는지만 다를 뿐 같은 endpoint+파라미터에 대해 같은 결론("이스케이프
        # 없이 반사됨")을 payload 개수(리다이렉트 13종/XSS 4종)만큼 반복 생성한다 — 이미
        # 하나로 결론이 났으면 나머지는 대표 finding 하나로 합친다. 확정 취약점
        # (LOCATION_HEADER/META_REFRESH/JS_REDIRECT/CLIENT_JS_CONFIRMED, 그리고
        # confirmed_redirect 필드가 없는 CORS/crossdomain/sink 기반 open redirect)은
        # payload/위치별로 구분 가치가 있으므로 기존대로 location까지 키에 포함한다.
        if ev.get("confirmed_redirect") is False:
            key = f"{ev.get('rule_id')}|{ev.get('engine')}|{ev.get('test_url') or ev.get('url')}"
        else:
            key = f"{ev.get('rule_id')}|{ev.get('engine')}|{ev.get('test_url') or ev.get('url')}|{ev.get('location')}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def run_g15_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    raw = ctx.raw_config or {}
    opts = _scan_options(raw)
    targets = _load_local("targets")
    rules = _load_local("redirect_rules")
    probes = _load_local("probes")

    tree = targets.load_api_tree(ctx.data_dir)
    bases = targets.collect_base_urls(raw)
    sink_base = targets.resolve_sink_base(raw)
    run_id = targets.new_run_id()
    cors_origin = targets.resolve_cors_probe_origin(raw, sink_base)

    if not tree and not bases:
        return ScanResult(
            status="skipped",
            message="No api-tree or base URLs — run inventory / Verify first",
            stats={"sink_base": sink_base},
        )

    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "probe_mode": opts.probe_mode,
        "sink_base": sink_base,
        "run_id": run_id,
        "cors_probe_origin": cors_origin,
    }

    # account_auth 없이 프로브를 보내면 로그인이 필요한 엔드포인트는 컨트롤러 로직에
    # 도달하기도 전에 401로 막혀, 페이로드가 반사/리다이렉트될 여지 자체가 없어져 실제
    # 취약점이 있어도 절대 못 잡는다 — phase A/B 모두 로그인 세션을 붙여서 보낸다.
    try:
        auth_session = _primary_auth(raw, data_dir=ctx.data_dir)
    except Exception:
        auth_session = None

    phase_a = targets.build_phase_a_jobs(
        tree,
        raw_config=raw,
        sink_base=sink_base,
        run_id=run_id,
        probe_mode=opts.probe_mode,
        sample_size=opts.sample_size,
        max_params_per_endpoint=opts.max_params_per_endpoint,
        max_jobs=opts.max_phase_a_jobs,
        account_auth=auth_session,
    )
    phase_b = targets.build_phase_b_jobs(
        tree,
        raw_config=raw,
        sink_base=sink_base,
        run_id=run_id,
        probe_mode=opts.probe_mode,
        sample_size=opts.sample_size,
        max_jobs=opts.max_phase_b_jobs,
        account_auth=auth_session,
    )
    redirect_jobs = phase_a + phase_b
    stats["phase_a_jobs"] = len(phase_a)
    stats["phase_b_jobs"] = len(phase_b)

    try:
        from app.services.redirect_sink_service import register_probes
        from app.workspace import current_user_id

        uid = current_user_id()
        if uid:
            register_probes(
                user_id=uid,
                run_id=run_id,
                probe_ids=[str(j.get("probe_id") or "") for j in redirect_jobs],
            )
    except Exception:
        pass

    from diagnosis.progress_reporter import phase, prepare, zap_phase

    cors_targets = targets.build_cors_targets(bases) if opts.cors_enabled and bases else []
    xd_targets = targets.build_crossdomain_targets(bases) if opts.crossdomain_enabled and bases else []
    # redirect_jobs는 실제로 세 번 순회된다 — sink 기반 확정 검증(run_redirect_jobs),
    # reflected_bridge의 META_REFRESH/JS_REDIRECT/REFLECTED_VALUE 보강 검증(run_on_jobs),
    # 그리고 그중 로그인 문맥만 추린 소수 후보에 대한 브라우저 검증. 이 셋을 모두
    # grand_total에 포함해야 진행률이 각 단계에서 실제로 올라간다.
    reflected_bridge = _load_local("reflected_bridge")
    login_candidate_count = reflected_bridge.count_login_redirect_candidates(redirect_jobs) if redirect_jobs else 0
    # redirect_jobs(phase A+B)는 sink 기반 확정 검증(run_redirect_jobs)과 reflected_bridge의
    # 리다이렉트 반사 보강 검증(run_on_jobs) 두 번 순회된다. XSS 반사 검증(run_xss_on_jobs)은
    # phase A(실제 선언된 endpoint 파라미터: posts/comments/profile 등)에만 적용한다 —
    # phase B는 GET 엔드포인트에 추측성 redirect 파라미터명(REDIRECT_PARAM_NAMES)을 쿼리로
    # 덧붙이는 것이라 서버가 아예 읽지 않는 파라미터일 가능성이 높아 XSS 관점에서는 값이
    # 거의 없는데 job 수만 크게 늘려(phase B가 보통 더 큼) 스캔 시간을 불필요하게 늘린다.
    grand_total = (
        len(redirect_jobs) * 2 + len(phase_a) + login_candidate_count
        + len(cors_targets) + len(xd_targets)
    )
    prepare(grand_total, f"1-5: {grand_total} probe(s)")
    progress_offset = 0

    def _seg_progress(segment_total: int, prefix: str):
        def _cb(**kw: Any) -> None:
            nonlocal progress_offset
            local_done = int(kw.get("endpoints_done") or 0)
            done = progress_offset + local_done
            item = str(kw.get("endpoint_id") or "")
            msg = f"{prefix}{done}/{grand_total}"
            if item:
                msg += f" · {item}"
            phase(msg, phase_name="httpx", done=done, total=grand_total)

        return _cb

    if redirect_jobs:
        rf, rstats = probes.run_redirect_jobs(
            redirect_jobs,
            sink_base=sink_base,
            is_open_redirect_fn=rules.is_external_open_redirect,
            timeout=opts.timeout,
            on_progress=_seg_progress(len(redirect_jobs), "redirect "),
        )
        findings.extend(rf)
        stats["redirect"] = rstats
        progress_offset += len(redirect_jobs)

        # sink 기반 검증은 Location 헤더(서버 사이드 리다이렉트)만 확인한다 — meta refresh /
        # JS location 대입 / 리다이렉트 실행 증거 없이 값만 반사되는 케이스는 다루지 않으므로
        # reflected_bridge로 같은 job 목록을 재사용해 그 세 가지만 보강 확인한다.
        vf, vstats = reflected_bridge.run_on_jobs(
            redirect_jobs,
            on_progress=_seg_progress(len(redirect_jobs), "reflected "),
        )
        findings.extend(vf)
        stats["reflected_probe"] = vstats
        progress_offset += len(redirect_jobs)

        # 위 두 검증은 리다이렉트 실행 여부만 본다 — posts/comments/profile 같은 일반
        # CRUD 필드에 스크립트/HTML이 이스케이프 없이 반사되는지(반사형 XSS)는 별도
        # 판별 규칙이 필요하므로 phase A job(실제 선언된 파라미터)만 xss_detector로
        # 재사용해 확인한다 — phase B(추측성 redirect 파라미터명)는 XSS 관점에서 값이
        # 거의 없어 제외한다(위 grand_total 주석 참고).
        if phase_a:
            _refresh_job_auth(phase_a, raw, data_dir=ctx.data_dir)
            xf, xstats = reflected_bridge.run_xss_on_jobs(
                phase_a,
                marker=run_id,
                on_progress=_seg_progress(len(phase_a), "xss "),
            )
            findings.extend(xf)
            stats["reflected_xss"] = xstats
            progress_offset += len(phase_a)

        # SPA는 로그인 성공 후 클라이언트 JS가 ?next=/?returnUrl= 값을 읽어 location을
        # 대입하는 경우가 흔한데, 이건 정적 응답 문자열 매칭(위 reflected_bridge)으로는
        # 원리적으로 못 잡는다 — 로그인/인증 문맥 후보만 추려 실제 헤드리스 브라우저로
        # 검증한다 (느리므로 소수 후보에만 적용).
        # auth_session은 위에서 이미 조회했다 — phase A/B job 생성에 쓴 것과 같은
        # 세션을 재사용해 여기서 다시 로그인하지 않는다.
        browser_cookies = None
        if auth_session and auth_session.get("delivery") == "cookie" and auth_session.get("token"):
            browser_cookies = {auth_session.get("cookie_name", "accessToken"): auth_session["token"]}
        bf, bstats = reflected_bridge.run_login_redirect_browser_check(
            redirect_jobs,
            cookies=browser_cookies,
            on_progress=_seg_progress(login_candidate_count, "browser "),
        )
        findings.extend(bf)
        stats["reflected_browser"] = bstats
        progress_offset += login_candidate_count

    if opts.cors_enabled and bases:
        cf, cstats = probes.run_cors_probes(
            cors_targets,
            probe_origin=cors_origin,
            analyze_cors_fn=rules.analyze_cors_headers,
            timeout=opts.timeout,
            on_progress=_seg_progress(len(cors_targets), "cors "),
        )
        findings.extend(cf)
        stats["cors"] = cstats
        progress_offset += len(cors_targets)

    if opts.crossdomain_enabled and bases:
        xf, xstats = probes.run_crossdomain_probes(
            xd_targets,
            analyze_crossdomain_fn=rules.analyze_crossdomain_xml,
            timeout=opts.timeout,
            on_progress=_seg_progress(len(xd_targets), "crossdomain "),
        )
        findings.extend(xf)
        stats["crossdomain"] = xstats
        progress_offset += len(xd_targets)

    probe_targets = [
        {"probe_url": j["test_url"], "base_url": j.get("base_url", ""), "label": j["test_url"]}
        for j in redirect_jobs[: opts.zap_seed_cap]
    ]
    for base in bases:
        probe = targets.probe_base_url(base)
        probe_targets.append({"probe_url": probe, "base_url": base, "label": base})

    if opts.zap_enabled:
        zap = _load_local("zap_scan")
        auth = _primary_auth(raw, data_dir=ctx.data_dir)
        try:
            zap_phase("ZAP 1-5 redirect scan…")
            zf, zstats = zap.run_zap_phase(
                raw,
                probe_targets,
                [targets.probe_base_url(b) for b in bases],
                auth,
                max_minutes=opts.zap_max_minutes,
                seed_cap=opts.zap_seed_cap,
                priority_seed_urls=[j["test_url"] for j in redirect_jobs[:50]],
            )
            findings.extend(zf)
            stats["zap"] = zstats
        except ZapNotAvailableError as exc:
            stats["zap"] = {"error": str(exc)}

    findings = _dedupe_redirect_findings(findings)

    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")
    stats["findings"] = len(findings)
    stats["by_severity"] = {"high": high, "medium": medium, "low": low, "info": sum(1 for f in findings if f.severity == "info")}

    if high:
        status = "fail"
        message = f"1-5 redirect/CORS: {high} high, {medium} medium finding(s)"
    elif medium:
        status = "warn"
        message = f"1-5 redirect/CORS review: {medium} medium finding(s)"
    else:
        status = "pass"
        message = "1-5 redirect/CORS checks completed — no high/medium issues"

    if opts.probe_mode == "base_only":
        message += " (base_only — redirect sweep skipped)"

    return ScanResult(findings=findings, stats=stats, status=status, message=message)

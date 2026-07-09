"""ZAP file upload scan phase for 2-1.

ZAP을 HTTP 프록시로 활용하는 방식으로 동작:
1. ZAP 설정 (인증 헤더 Replacer, OpenAPI import)
2. 업로드 엔드포인트에 httpx로 파일 업로드 요청을 ZAP 프록시를 통해 전송
   → ZAP이 passive scan 으로 이상 응답을 감지
3. ZAP 액티브 스캔 실행 (파일 업로드 정책)
4. ZAP alerts 수집 및 DetectionResult 반환
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from app.services.zap_util import ZapNotAvailableError, ensure_zap_proxy, probe_url
from diagnosis.replay.normalize import FRONTEND_PORTS, collect_probe_base_urls
from inventory.load import find_openapi_spec


def _proxy_host_port(proxy_url: str) -> tuple[str, str]:
    parsed = urlparse(proxy_url)
    host = parsed.hostname or "127.0.0.1"
    port = str(parsed.port or 8090)
    return host, port


def _api_probe_bases(bases: list[str]) -> list[str]:
    """프론트엔드 포트를 제외한 API 백엔드 base URL만 반환."""
    api_bases: list[str] = []
    seen: set[tuple[str, int]] = set()
    for base in bases:
        url = base.rstrip("/")
        if not url:
            continue
        parsed = urlparse(url)
        port = parsed.port
        if port is None:
            port = 443 if (parsed.scheme or "http") == "https" else 80
        if port in FRONTEND_PORTS:
            continue
        key = (parsed.hostname or "", port)
        if key in seen:
            continue
        seen.add(key)
        # Docker 환경 치환
        url = url.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")
        api_bases.append(url)
    return api_bases


def _make_httpx_proxy_client(proxy_url: str, auth_headers: dict[str, str] | None, timeout: float):
    """ZAP 프록시를 통해 요청하는 httpx 클라이언트 반환."""
    import httpx

    headers = dict(auth_headers or {})
    return httpx.Client(
        headers=headers,
        proxy=proxy_url,
        timeout=timeout,
        verify=False,
    )


def _probe_upload_endpoints_via_zap(
    bases: list[str],
    proxy_url: str,
    session_headers: dict[str, str] | None,
    security_rules: Any,
) -> int:
    """
    ZAP 프록시를 통해 파일 업로드 요청을 전송하여 ZAP이 트래픽을 캡처하도록 합니다.
    ZAP의 passive scan이 응답을 분석합니다.
    반환값: 전송된 프로브 요청 수
    """
    from security_rules import get_upload_payloads

    payloads = get_upload_payloads()
    # 파일 업로드가 있을 가능성이 높은 공통 엔드포인트 경로
    upload_paths = [
        "/api/v1/seller/accommodations",
        "/api/v1/seller/cars",
        "/api/v1/posts",
        "/api/v1/members/profile/image",
        "/api/v1/upload",
    ]

    sent = 0
    try:
        import httpx

        headers = dict(session_headers or {})

        for base in bases:
            base = base.rstrip("/")
            probed = probe_url(base)
            with httpx.Client(
                headers=headers,
                proxy=proxy_url,
                timeout=8.0,
                verify=False,
            ) as client:
                for path in upload_paths:
                    url = f"{probed}{path}"
                    for filename, content, content_type, _desc in payloads[:3]:  # 대표 3종만
                        try:
                            client.post(
                                url,
                                files={"file": (filename, content, content_type)},
                            )
                            sent += 1
                        except Exception:
                            pass
    except Exception as exc:
        print(f"[2-1][ZAP proxy probe] error: {exc}")

    return sent


def run_zap_upload_phase(
    raw_config: dict[str, Any],
    data_dir: Any,
    *,
    jwt_token: str = "",
    session_headers: dict[str, str] | None = None,
    max_minutes: int = 15,
    progress_cb: Any | None = None,
) -> tuple[list[Any], dict[str, Any]]:
    """
    ZAP 프록시를 활용한 파일 업로드 취약점 스캔.

    1단계: ZAP 설정 (인증 헤더, OpenAPI import)
    2단계: httpx → ZAP 프록시 → 대상 서버 (파일 업로드 페이로드 전송, ZAP passive capture)
    3단계: ZAP 액티브 스캔 (파일 업로드 정책)
    4단계: ZAP alerts 수집
    """
    from g21_zap_engine import ZapEngine

    bases = _api_probe_bases(collect_probe_base_urls(raw_config))
    if not bases:
        return [], {"error": "no_base_urls"}

    zap_cfg = raw_config.get("zap") or {}
    try:
        proxy_url = ensure_zap_proxy(zap_cfg)
    except ZapNotAvailableError as exc:
        return [], {"error": str(exc), "zap_alerts": 0}

    api_key = str(zap_cfg.get("api_key") or "argus_secret_key")
    host, port = _proxy_host_port(proxy_url)
    engine = ZapEngine(proxy_address=f"{host}:{port}", api_key=api_key)

    spec_path = find_openapi_spec(data_dir)
    swagger_url = str(spec_path.resolve()) if spec_path is not None else ""
    primary_target = probe_url(bases[0])

    # --- 1단계: ZAP 설정 ---
    try:
        engine.configure_scan(
            target_url=primary_target,
            swagger_url=swagger_url,
            jwt_token=jwt_token,
            session_headers=session_headers,
        )
    except RuntimeError as exc:
        # ZAP 미가동이면 ZAP 단계 전체 스킵 (httpx probe는 계속 진행)
        return [], {"error": str(exc), "zap_alerts": 0}

    # --- 2단계: ZAP 프록시 통해 업로드 요청 전송 (passive scan 유도) ---
    from security_rules import get_upload_payloads  # noqa: F401 (import check)

    probed_count = _probe_upload_endpoints_via_zap(
        bases=bases,
        proxy_url=proxy_url,
        session_headers=session_headers,
        security_rules=None,
    )
    print(f"[2-1][ZAP] Proxy probes sent: {probed_count}")

    # passive scan이 처리할 시간 확보
    import time
    time.sleep(3)

    # --- 3단계: ZAP 액티브 스캔 ---
    all_results: list[Any] = []
    scanned_targets: list[str] = []
    per_base_minutes = max(3, int(max_minutes / max(len(bases), 1)))
    zap_total = max(len(bases) * 100, 1)

    for idx, base in enumerate(bases):
        target_url = probe_url(base.rstrip("/"))
        scanned_targets.append(target_url)

        def _zap_progress(status: int, current_url: str, base_idx: int = idx) -> None:
            done = min(zap_total, base_idx * 100 + max(0, min(int(status), 100)))
            if progress_cb:
                progress_cb(done, zap_total, current_url, int(status))

        try:
            zap_results = engine.run_active_scan(
                target_url=target_url,
                max_minutes=per_base_minutes,
                progress_cb=_zap_progress,
            )
            all_results.extend(zap_results)
        except Exception as exc:
            print(f"[2-1][ZAP] Active scan failed for {target_url}: {exc}")
            # 액티브 스캔 실패 시 passive 결과만 수집
            try:
                passive_results = engine.collect_passive_results(target_url)
                all_results.extend(passive_results)
            except Exception:
                pass

    # --- 4단계: 중복 제거 ---
    deduped: list[Any] = []
    seen: set[tuple[Any, ...]] = set()
    for result in all_results:
        key = (result.method, result.url, result.param, result.plugin_id)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(result)

    return deduped, {
        "target_urls": scanned_targets,
        "swagger_path": swagger_url or None,
        "zap_alerts": len(deduped),
        "proxy_probes_sent": probed_count,
        "proxy": proxy_url,
        "cookie_auth": bool(
            (session_headers or {}).get("Cookie") or (session_headers or {}).get("cookie")
        ),
    }

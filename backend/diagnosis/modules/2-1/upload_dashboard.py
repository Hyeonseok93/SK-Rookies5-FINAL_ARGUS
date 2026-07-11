"""Generic upload probes for dashboard-configured endpoints (2-1)."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from app.services.transfer_endpoints_service import dashboard_transfer_entries
from security_rules import get_upload_payloads

_MODULE_DIR = Path(__file__).resolve().parent

def _judge():
    import importlib.util
    name = "diag_g21_upload_judge_dashboard"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _MODULE_DIR / "upload_judge.py")
        if spec is None or spec.loader is None:
            raise ImportError("upload_judge")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]

def run_dashboard_upload_probes(base_url: str, auth_headers: dict[str, str], timeout: float, raw_config: dict[str, Any]) -> list:
    rows = dashboard_transfer_entries("upload", raw_config)
    if not rows:
        return []

    judge = _judge()
    results: list = []
    
    upload_payloads = get_upload_payloads()
    futures = []

    def _probe_dashboard(client, method, url, path, filename, content, content_type, desc):
        files = {"file": (filename, content, content_type)}
        try:
            if method == "POST":
                response = client.post(url, files=files)
            elif method == "PUT":
                response = client.put(url, files=files)
            elif method == "PATCH":
                response = client.patch(url, files=files)
            else:
                return None
            return judge.judge_upload_response(
                suite="dashboard_upload",
                method=method,
                endpoint=path,
                filename=filename,
                attack_desc=desc,
                response=response,
            )
        except httpx.HTTPError as exc:
            return judge.judge_upload_response(
                suite="dashboard_upload",
                method=method,
                endpoint=path,
                filename=filename,
                attack_desc=desc,
                response=None,
                error=str(exc),
            )

    with httpx.Client(headers=auth_headers, timeout=timeout, verify=False) as client:
        with ThreadPoolExecutor(max_workers=5) as executor:
            for row in rows:
                url = row["url"]
                if not url.startswith("http"):
                    url = f"{base_url.rstrip('/')}{url}"
                method = str(row.get("method") or "POST").upper()
                path = row.get("path") or urlparse(url).path or "/"
                
                for filename, content, content_type, desc in upload_payloads:
                    futures.append(executor.submit(_probe_dashboard, client, method, url, path, filename, content, content_type, desc))
                    
            for future in as_completed(futures):
                res = future.result()
                if res:
                    results.append(res)
                    
    return results

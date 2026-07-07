"""Generic upload probes for dashboard-configured endpoints (2-1)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from app.services.transfer_endpoints_service import dashboard_transfer_entries

_MODULE_DIR = Path(__file__).resolve().parent


def _judge():
    name = "diag_g21_upload_judge_dashboard"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _MODULE_DIR / "upload_judge.py")
        if spec is None or spec.loader is None:
            raise ImportError("upload_judge")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def run_dashboard_upload_probes(ctx: Any, raw_config: dict[str, Any]) -> list:
    rows = dashboard_transfer_entries("upload", raw_config)
    if not rows:
        return []

    judge = _judge()
    results: list = []
    for row in rows:
        url = row["url"]
        method = str(row.get("method") or "POST").upper()
        path = row.get("path") or urlparse(url).path or "/"
        files = {"file": ("probe.jpg", b"<?php echo 'ARGUS'; ?>", "application/x-php")}
        try:
            if method == "POST":
                response = ctx.client.post(url, files=files, headers=ctx.headers)
            elif method == "PUT":
                response = ctx.client.put(url, files=files, headers=ctx.headers)
            elif method == "PATCH":
                response = ctx.client.patch(url, files=files, headers=ctx.headers)
            else:
                continue
            results.append(
                judge.judge_upload_response(
                    suite="dashboard_upload",
                    method=method,
                    endpoint=path,
                    filename="probe.jpg",
                    attack_desc="dashboard endpoint Content-Type 변조",
                    response=response,
                )
            )
        except httpx.HTTPError as exc:
            results.append(
                judge.judge_upload_response(
                    suite="dashboard_upload",
                    method=method,
                    endpoint=path,
                    filename="probe.jpg",
                    attack_desc="dashboard endpoint Content-Type 변조",
                    response=None,
                    error=str(exc),
                )
            )
    return results

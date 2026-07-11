"""1-2 Injection evidence screenshot adapter.

The directory name intentionally remains ``1-2``. Load this module by file path
or execute it directly instead of importing it with dotted Python syntax.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

from engine import capture_case  # noqa: E402
from credentials import load_replay_credentials  # noqa: E402
from models import EvidenceCase, HttpExchange  # noqa: E402
from redaction import redact_headers, redact_text  # noqa: E402
from replay import display_url, replay_case, ui_url_for_api  # noqa: E402
from selector import select_representatives, stable_finding_id  # noqa: E402


def _load_capture_context(config_path: Path, data_dir: Path) -> dict[str, Any]:
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) if config_path.is_file() else {}
    config = config or {}
    inventory = dict(config.get("inventory") or {})
    markdown = dict(inventory.get("markdown") or {})
    frontend_base_url = str(
        markdown.get("frontend_base_url")
        or inventory.get("frontend_base_url")
        or config.get("frontend_base_url")
        or ""
    )
    try:
        tree = json.loads((data_dir / "api-tree.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        tree = {}
    frontend_rows = [
        row
        for row in tree.get("endpoints") or []
        if str(row.get("kind") or "") == "frontend"
    ]
    if not frontend_base_url and frontend_rows:
        frontend_base_url = str(frontend_rows[0].get("base_url") or "")
    if not frontend_base_url:
        raise RuntimeError(
            "Frontend URL is unavailable. Set inventory.markdown.frontend_base_url "
            "or provide frontend endpoints in data/api-tree.json."
        )

    # frontend-kind routes are always navigated against frontend_base_url, so
    # their stored base_url (often the API port, e.g. :8080) is irrelevant —
    # take the path from every frontend row, dropping only API paths.
    routes = []
    for row in frontend_rows:
        path = str(row.get("path") or "/")
        if "/api/" not in path.lower():
            routes.append(path if path.startswith("/") else f"/{path}")
    routes = list(dict.fromkeys(routes))
    routes.sort(key=lambda path: (path == "/", path.count("/"), path))
    login_urls = []
    for row in tree.get("endpoints") or []:
        path = str(row.get("path") or "")
        if str(row.get("method") or "").upper() == "POST" and "login" in path.lower():
            base_url = str(row.get("base_url") or "").rstrip("/")
            if base_url:
                login_urls.append(f"{base_url}{path}")
    auth = dict(config.get("auth") or {})
    return {
        "frontend_base_url": frontend_base_url.rstrip("/"),
        "frontend_routes": routes[:40],
        "login_urls": list(dict.fromkeys(login_urls)),
        "id_field": str(auth.get("id_field") or "email"),
        "password_field": str(auth.get("pw_field") or "password"),
        "credentials": load_replay_credentials(data_dir),
    }


def _exchange(raw: dict[str, Any], fallback: dict[str, Any]) -> HttpExchange:
    elapsed_ms = raw.get("elapsed_ms")
    if elapsed_ms is None and raw.get("elapsed_sec") is not None:
        elapsed_ms = float(raw["elapsed_sec"]) * 1000
    url = str(raw.get("url") or fallback.get("url") or fallback.get("raw_request_url") or "")
    return HttpExchange(
        method=str(raw.get("method") or fallback.get("method") or "GET"),
        url=url,
        display_url=display_url(url),
        request_headers=dict(raw.get("request_headers") or fallback.get("raw_request_headers") or {}),
        request_body=str(raw.get("request_body") or fallback.get("raw_request_body") or ""),
        status_code=int(raw["status_code"]) if raw.get("status_code") is not None else None,
        response_headers=dict(raw.get("response_headers") or {}),
        response_body=str(raw.get("response_body") or ""),
        elapsed_ms=elapsed_ms,
    )


def case_from_finding(
    finding: dict[str, Any],
    *,
    frontend_base_url: str,
    frontend_routes: list[str],
) -> EvidenceCase:
    evidence = dict(finding.get("evidence") or finding)
    detail = dict(evidence.get("detail") or {})
    methods = dict(evidence.get("verification_methods") or detail.get("verification_methods") or {})
    baseline_raw = dict(evidence.get("baseline") or methods.get("baseline") or {})
    attack_raw = dict(evidence.get("attack") or {})
    fallback = {**detail, **evidence}
    finding_id = str(evidence.get("finding_id") or finding.get("finding_id") or stable_finding_id(finding))
    baseline = _exchange(baseline_raw, fallback)
    ui_url, ui_display_url = ui_url_for_api(frontend_base_url)

    return EvidenceCase(
        finding_id=finding_id,
        section_id="1-2",
        title=str(finding.get("message") or evidence.get("title") or "삽입(Injection) 공격 가능성"),
        parameter=str(evidence.get("parameter") or evidence.get("param") or "-"),
        payload=str(evidence.get("payload") or evidence.get("custom_payload") or evidence.get("zap_payload") or "-"),
        verification_type=str(evidence.get("verification_type") or evidence.get("classification") or "unverified"),
        confidence=str(evidence.get("confidence") or "unknown"),
        baseline=baseline,
        attack=_exchange(attack_raw, fallback),
        metadata={
            "verification_status": evidence.get("verification_status"),
            "engine": evidence.get("engine"),
            "plugin_id": evidence.get("plugin_id"),
            "classification": evidence.get("classification"),
            "merged_sources": evidence.get("merged_sources") or [],
            "duplicate_count": evidence.get("duplicate_count") or 1,
            "verification_methods": methods,
            "ui_url": ui_url,
            "ui_display_url": ui_display_url,
            "frontend_routes": frontend_routes,
        },
    )


def _safe_exchange(exchange: HttpExchange) -> dict[str, Any]:
    return {
        "method": exchange.method,
        "url": exchange.display_url or display_url(exchange.url),
        "request_headers": redact_headers(exchange.request_headers),
        "request_body": redact_text(exchange.request_body),
        "status_code": exchange.status_code,
        "response_headers": redact_headers(exchange.response_headers),
        "response_body": redact_text(exchange.response_body),
        "elapsed_ms": exchange.elapsed_ms,
    }


def capture_finding(
    finding: dict[str, Any],
    output_root: Path,
    *,
    frontend_base_url: str,
    frontend_routes: list[str],
    login_urls: list[str],
    id_field: str,
    password_field: str,
    credentials,
    perform_replay: bool = True,
) -> list[dict[str, str]]:
    case = case_from_finding(
        finding,
        frontend_base_url=frontend_base_url,
        frontend_routes=frontend_routes,
    )
    if perform_replay:
        case = replay_case(
            case,
            credentials=credentials,
            login_urls=login_urls,
            id_field=id_field,
            password_field=password_field,
        )
    case.metadata["login_urls"] = [display_url(url) for url in login_urls]
    case.metadata["id_field"] = id_field
    case.metadata["password_field"] = password_field
    output_dir = output_root / case.finding_id
    artifacts = capture_case(case, output_dir)

    manifest = {
        "section_id": case.section_id,
        "finding_id": case.finding_id,
        "viewport": {"width": 1280, "height": 720},
        "parameter": case.parameter,
        "verification_type": case.verification_type,
        "confidence": case.confidence,
        "baseline": _safe_exchange(case.baseline),
        "attack": _safe_exchange(case.attack),
        "metadata": case.metadata,
        "artifacts": [{"kind": item.kind, "path": item.path} for item in artifacts],
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return manifest["artifacts"]


def capture_latest(
    report_path: Path,
    output_root: Path,
    *,
    config_path: Path | None = None,
    limit: int = 3,
    perform_replay: bool = True,
) -> list[dict[str, Any]]:
    backend_root = _default_backend_root()
    resolved_config = config_path or Path(
        os.environ.get("CONFIG_PATH") or backend_root / "config.yaml"
    )
    capture_context = _load_capture_context(
        resolved_config,
        backend_root / "data",
    )
    report = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
    findings = list(report.get("findings") or [])
    selected = select_representatives(findings, limit=limit)
    selected_ids = {stable_finding_id(finding) for finding in selected}
    if output_root.is_dir():
        for stale_dir in output_root.glob("1-2-*"):
            if stale_dir.is_dir() and stale_dir.name not in selected_ids:
                shutil.rmtree(stale_dir)
    results: list[dict[str, Any]] = []
    for finding in selected:
        finding_id = stable_finding_id(finding)
        try:
            artifacts = capture_finding(
                finding,
                output_root,
                frontend_base_url=capture_context["frontend_base_url"],
                frontend_routes=capture_context["frontend_routes"],
                login_urls=capture_context["login_urls"],
                id_field=capture_context["id_field"],
                password_field=capture_context["password_field"],
                credentials=capture_context["credentials"],
                perform_replay=perform_replay,
            )
            results.append({"finding_id": finding_id, "ok": True, "artifacts": artifacts})
        except Exception as exc:
            results.append({"finding_id": finding_id, "ok": False, "error": str(exc)})

    summary = {
        "section_id": "1-2",
        "report": str(report_path),
        "selected": len(selected),
        "succeeded": sum(1 for row in results if row["ok"]),
        "failed": sum(1 for row in results if not row["ok"]),
        "results": results,
    }
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "capture-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return results


def _default_backend_root() -> Path:
    # /app/screenshot/modules/1-2 -> /app
    return _MODULE_DIR.parents[2]


def main() -> int:
    if not os.environ.get("DISPLAY"):
        os.execvp(
            "xvfb-run",
            [
                "xvfb-run",
                "-a",
                "-s",
                "-screen 0 1280x720x24",
                sys.executable,
                *sys.argv,
            ],
        )

    backend_root = _default_backend_root()
    parser = argparse.ArgumentParser(description="Capture 1-2 injection evidence screenshots")
    parser.add_argument(
        "--report",
        type=Path,
        default=backend_root / "data" / "report" / "1-2" / "latest.yaml",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=backend_root / "data" / "report" / "1-2" / "evidence",
    )
    parser.add_argument("--limit", type=int, default=3)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(os.environ.get("CONFIG_PATH") or backend_root / "config.yaml"),
    )
    parser.add_argument("--no-replay", action="store_true", help="Render saved evidence without HTTP replay")
    args = parser.parse_args()

    results = capture_latest(
        args.report,
        args.output,
        config_path=args.config,
        limit=max(1, args.limit),
        perform_replay=not args.no_replay,
    )
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0 if results and all(row["ok"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

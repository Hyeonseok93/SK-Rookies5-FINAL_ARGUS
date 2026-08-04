"""2-2 download / traversal evidence screenshot adapter."""

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
_BACKEND_ROOT = _MODULE_DIR.parents[2]
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from auth_context import (  # noqa: E402
    account_auth_for_evidence,
    authenticated_auth_for_evidence,
    create_auth_pool,
    is_unauth_download,
)
from engine import capture_case  # noqa: E402
from models import EvidenceCase, HttpExchange  # noqa: E402
from redaction import redact_headers, redact_text  # noqa: E402
from replay import build_case_exchanges, display_url, replay_case  # noqa: E402
from selector import select_representatives, stable_finding_id  # noqa: E402


def _frontend_context(config: dict[str, Any], data_dir: Path) -> dict[str, Any]:
    inventory = dict(config.get("inventory") or {})
    markdown = dict(inventory.get("markdown") or {})
    frontend_base_url = str(
        markdown.get("frontend_base_url")
        or inventory.get("frontend_base_url")
        or config.get("frontend_base_url")
        or ""
    ).rstrip("/")
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
        frontend_base_url = str(frontend_rows[0].get("base_url") or "").rstrip("/")

    routes: list[str] = []
    if frontend_base_url:
        frontend_origin = urlsplit(display_url(frontend_base_url)).netloc
        for row in frontend_rows:
            row_origin = urlsplit(display_url(str(row.get("base_url") or ""))).netloc
            path = str(row.get("path") or "/")
            if row_origin == frontend_origin and "/api/" not in path.lower():
                routes.append(path if path.startswith("/") else f"/{path}")
    routes = list(dict.fromkeys(routes))
    routes.sort(key=lambda path: (path == "/", path.count("/"), path))
    if "/" not in routes:
        routes.insert(0, "/")

    auth = dict(config.get("auth") or {})
    login_urls: list[str] = []
    for raw in auth.get("login_urls") or []:
        url = str(raw).strip()
        if url:
            login_urls.append(url)
    return {
        "frontend_base_url": frontend_base_url,
        "frontend_routes": routes[:40],
        "login_urls": list(dict.fromkeys(login_urls)),
        "id_field": str(auth.get("id_field") or "email"),
        "password_field": str(auth.get("pw_field") or "password"),
    }


def _load_capture_context(config_path: Path, data_dir: Path) -> dict[str, Any]:
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) if config_path.is_file() else {}
    config = config or {}
    auth_pool = create_auth_pool(config, data_dir=data_dir)
    frontend = _frontend_context(config, data_dir)
    return {
        "config": config,
        "data_dir": data_dir,
        "auth_pool": auth_pool,
        **frontend,
    }


def _login_metadata(
    *,
    authenticated_auth: dict[str, Any] | None,
    login_urls: list[str],
    id_field: str,
    password_field: str,
) -> dict[str, Any]:
    from inventory.net import probe_url

    if not authenticated_auth:
        return {"ok": False, "reason": "No authenticated session for UI capture"}
    login_url = str(authenticated_auth.get("login_url") or "")
    if not login_url and login_urls:
        login_url = login_urls[0]
    if not login_url:
        return {"ok": False, "reason": "No login URL available"}
    runtime = probe_url(login_url)
    return {
        "ok": True,
        "account_id": authenticated_auth.get("account_id") or authenticated_auth.get("id"),
        "email": authenticated_auth.get("email"),
        "login_url": display_url(login_url),
        "runtime_login_url": runtime,
        "id_field": id_field,
        "password_field": password_field,
    }


def case_from_finding(
    finding: dict[str, Any],
    *,
    data_dir: Path,
    account_auth: dict[str, Any] | None = None,
    authenticated_auth: dict[str, Any] | None = None,
    frontend_base_url: str = "",
    frontend_routes: list[str] | None = None,
    login_urls: list[str] | None = None,
    id_field: str = "email",
    password_field: str = "password",
    raw_config: dict[str, Any] | None = None,
) -> EvidenceCase:
    evidence = dict(finding.get("evidence") or finding)
    finding_id = str(evidence.get("finding_id") or finding.get("finding_id") or stable_finding_id(finding))
    baseline, attack = build_case_exchanges(
        evidence,
        data_dir=data_dir,
        account_auth=account_auth,
        authenticated_auth=authenticated_auth,
    )
    metadata: dict[str, Any] = {
        "rule_id": evidence.get("rule_id"),
        "classification": evidence.get("classification"),
        "trigger_label": evidence.get("trigger_label"),
        "engine": evidence.get("engine"),
        "merged_sources": evidence.get("merged_sources") or [],
        "duplicate_count": evidence.get("duplicate_count") or 1,
        "source_evidence": evidence,
        "frontend_routes": list(frontend_routes or ["/"]),
        "id_field": id_field,
        "password_field": password_field,
    }
    if raw_config:
        from diagnosis.g22_replay import resolve_spa_browser_session

        metadata["app_name"] = raw_config.get("app_name")
        spa = resolve_spa_browser_session(raw_config, prefer_module_asset=True)
        if spa is not None:
            metadata["spa_browser_session"] = spa.to_dict()
    if frontend_base_url:
        from inventory.net import probe_url

        main_url = probe_url(frontend_base_url.rstrip("/") + "/")
        metadata["main_url"] = main_url
        metadata["main_display_url"] = display_url(main_url)
        metadata["ui_url"] = main_url
        metadata["ui_display_url"] = display_url(main_url)
    rule_id = str(evidence.get("rule_id") or "")
    if is_unauth_download(evidence) or rule_id in {
        "2-2-path-traversal",
        "2-2-input-validation",
        "2-2-forced-browse",
        "2-2-idor",
    }:
        metadata["login"] = _login_metadata(
            authenticated_auth=authenticated_auth,
            login_urls=list(login_urls or []),
            id_field=id_field,
            password_field=password_field,
        )
    return EvidenceCase(
        finding_id=finding_id,
        section_id="2-2",
        title=str(finding.get("message") or evidence.get("title") or "2-2 download / traversal"),
        rule_id=str(evidence.get("rule_id") or "2-2-unknown"),
        parameter=str(evidence.get("param") or evidence.get("parameter") or "-"),
        payload=str(evidence.get("payload") or "-"),
        trigger=str(evidence.get("trigger") or ""),
        baseline=baseline,
        attack=attack,
        metadata=metadata,
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
    raw_config: dict[str, Any],
    data_dir: Path,
    auth_pool: Any,
    frontend_base_url: str = "",
    frontend_routes: list[str] | None = None,
    login_urls: list[str] | None = None,
    id_field: str = "email",
    password_field: str = "password",
    perform_replay: bool = True,
) -> list[dict[str, str]]:
    evidence = dict(finding.get("evidence") or finding)
    authenticated_auth = authenticated_auth_for_evidence(evidence, auth_pool=auth_pool)
    account_auth = account_auth_for_evidence(evidence, auth_pool=auth_pool)
    case = case_from_finding(
        finding,
        data_dir=data_dir,
        account_auth=account_auth,
        authenticated_auth=authenticated_auth,
        frontend_base_url=frontend_base_url,
        frontend_routes=frontend_routes,
        login_urls=login_urls,
        id_field=id_field,
        password_field=password_field,
        raw_config=raw_config,
    )
    if perform_replay:
        case = replay_case(
            case,
            raw_config=raw_config,
            data_dir=data_dir,
            auth_pool=auth_pool,
        )
    output_dir = output_root / case.finding_id
    artifacts = capture_case(case, output_dir)

    manifest = {
        "section_id": case.section_id,
        "finding_id": case.finding_id,
        "rule_id": case.rule_id,
        "viewport": {"width": 1280, "height": 720},
        "parameter": case.parameter,
        "payload": case.payload,
        "trigger": case.trigger,
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
    env = (os.environ.get("ARGUS_DATA_DIR") or "").strip()
    data_dir = Path(env) if env else (backend_root / "data")
    resolved_config = config_path or Path(
        os.environ.get("CONFIG_PATH") or backend_root / "config.yaml"
    )
    capture_context = _load_capture_context(resolved_config, data_dir)
    report = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
    findings = list(report.get("findings") or [])
    selected = select_representatives(findings, limit=limit)
    selected_ids = {stable_finding_id(finding) for finding in selected}
    if output_root.is_dir():
        for stale_dir in output_root.glob("2-2-*"):
            if stale_dir.is_dir() and stale_dir.name not in selected_ids:
                shutil.rmtree(stale_dir)

    results: list[dict[str, Any]] = []
    for finding in selected:
        finding_id = stable_finding_id(finding)
        try:
            artifacts = capture_finding(
                finding,
                output_root,
                raw_config=capture_context["config"],
                data_dir=data_dir,
                auth_pool=capture_context["auth_pool"],
                frontend_base_url=capture_context["frontend_base_url"],
                frontend_routes=capture_context["frontend_routes"],
                login_urls=capture_context["login_urls"],
                id_field=capture_context["id_field"],
                password_field=capture_context["password_field"],
                perform_replay=perform_replay,
            )
            results.append({"finding_id": finding_id, "ok": True, "artifacts": artifacts})
        except Exception as exc:
            results.append({"finding_id": finding_id, "ok": False, "error": str(exc)})

    summary = {
        "section_id": "2-2",
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
    error_path = output_root / "capture-error.json"
    if results and all(row["ok"] for row in results):
        error_path.unlink(missing_ok=True)
    elif results and not any(row["ok"] for row in results):
        error_path.write_text(
            json.dumps(
                {
                    "section_id": "2-2",
                    "ok": False,
                    "error": json.dumps(results, ensure_ascii=False, indent=2),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    return results


def _default_backend_root() -> Path:
    return _MODULE_DIR.parents[2]


def _report_needs_ui_capture(report_path: Path, *, limit: int) -> bool:
    try:
        report = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return False
    selected = select_representatives(list(report.get("findings") or []), limit=limit)
    return any(
        is_unauth_download(dict(finding.get("evidence") or finding))
        for finding in selected
    )


def main() -> int:
    backend_root = _default_backend_root()
    env = (os.environ.get("ARGUS_DATA_DIR") or "").strip()
    data_dir = Path(env) if env else (backend_root / "data")
    parser = argparse.ArgumentParser(description="Capture 2-2 download/traversal evidence screenshots")
    parser.add_argument(
        "--report",
        type=Path,
        default=data_dir / "report" / "2-2" / "latest.yaml",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=data_dir / "report" / "2-2" / "evidence",
    )
    parser.add_argument("--limit", type=int, default=3)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(os.environ.get("CONFIG_PATH") or backend_root / "config.yaml"),
    )
    parser.add_argument("--no-replay", action="store_true", help="Render saved evidence without HTTP replay")
    args = parser.parse_args()

    if (
        not os.environ.get("DISPLAY")
        and _report_needs_ui_capture(args.report, limit=max(1, args.limit))
    ):
        # Unauth UI capture prefers a virtual display for scrot-compatible shots.
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

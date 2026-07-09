"""Screenshot capture for guideline 5-2: 요청 및 응답 값 내 주요정보 포함여부 확인.

Reads the 5-2 diagnosis report (data/report/5-2/latest.yaml), groups findings into
distinct cases, re-issues each selected finding's original probe to capture real
request/response evidence, and renders a 1280x720 PNG per instance into
data/report/5-2/evidence/.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from diagnosis.auth_session_pool import DiagnosisAuthPool
from diagnosis.context import DiagnosisContext
from diagnosis.paths import section_evidence_dir, section_report_path
from diagnosis.probe_transport import HttpxTransport
from diagnosis.result import SectionReport, utc_now_iso
from inventory.load import load_api_tree

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    mod_name = f"screenshot_g52_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


grouping = _load_local("grouping")
capture = _load_local("capture")
render = _load_local("render")


@dataclass
class ScreenshotRunResult:
    ok: bool
    message: str
    cases_total: int = 0
    screenshots_total: int = 0
    evidence_dir: str = ""
    manifest_path: str = ""


_SLUG_RE = re.compile(r"[^a-zA-Z0-9]+")


def _slugify(text: str, *, max_len: int = 50) -> str:
    slug = _SLUG_RE.sub("-", text).strip("-").lower()
    return slug[:max_len] or "x"


def _path_of(url: str) -> str:
    return urlparse(url).path or "/"


def _get_header(headers: dict[str, str], name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _short_id(*parts: str) -> str:
    import hashlib

    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:8].upper()


def _markers_visible(expected: list[str], *texts: str) -> int:
    """How many expected markers actually appear in the rendered request/response text."""
    blob = "\n".join(texts)
    return sum(1 for m in expected if m and m in blob)


def _load_section_report(ctx: DiagnosisContext) -> SectionReport | None:
    path = section_report_path(ctx.data_dir, "5-2")
    if not path.is_file():
        return None
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return None
    return SectionReport.from_dict(raw)


def capture_from_findings(
    ctx: DiagnosisContext,
    findings: list[Any],
    *,
    sessions: list[dict[str, Any]] | None = None,
    timeout: float = 15.0,
) -> ScreenshotRunResult:
    """Capture evidence screenshots from in-memory findings (called by the 5-2 scanner).

    One screenshot per (endpoint × account) exposure — every value that account leaks on
    that endpoint is highlighted together. `sessions` lets the caller pass already-
    authenticated diagnosis sessions so we don't trigger a second round of logins.
    """
    shots = grouping.select_shots(findings)
    if not shots:
        return ScreenshotRunResult(ok=False, message="5-2 report has no PII findings to screenshot.")

    tree = load_api_tree(ctx.data_dir)
    if tree is None:
        return ScreenshotRunResult(ok=False, message="No API inventory (api-tree) found — cannot re-issue probes.")

    if sessions is None:
        auth_pool = DiagnosisAuthPool(ctx.raw_config, data_dir=ctx.data_dir)
        sessions = auth_pool.sessions()

    evidence_dir = section_evidence_dir(ctx.data_dir, "5-2")
    evidence_dir.mkdir(parents=True, exist_ok=True)

    manifest_shots: list[dict[str, Any]] = []
    shots_captured = 0

    with HttpxTransport(timeout=timeout) as transport, render.ScreenshotBrowser() as browser:
        for shot in shots:
            endpoint = capture.find_endpoint(tree.endpoints, shot.endpoint_id)
            if endpoint is None:
                manifest_shots.append(
                    {
                        "seq": shot.seq,
                        "endpoint_id": shot.endpoint_id,
                        "kind": shot.kind,
                        "account": shot.account_label(),
                        "status": "skipped",
                        "reason": "endpoint_not_found_in_inventory",
                    }
                )
                continue

            # response shots replay as the specific account; request shots are account-
            # independent (the probe body is identical), so replay anonymously.
            if shot.kind == "response":
                session, matched = capture.resolve_session_for_auth_mode(shot.account, {}, sessions)
            else:
                session, matched = None, True

            result = capture.reprobe(endpoint, account_auth=session, transport=transport, timeout=timeout)

            content_type = _get_header(result.response_headers, "content-type")
            req_body_pretty = render.pretty_body(
                result.request_body, _get_header(result.request_headers, "content-type")
            )
            resp_body_pretty = render.pretty_body(result.response_body, content_type)

            note = "" if result.ok else f"reprobe error: {result.error}"
            if shot.kind == "response" and not matched:
                note = (note + " · " if note else "") + "해당 계정 세션 없음 — 익명으로 재요청됨"

            spec = render.ShotSpec(
                tab_label=f"ARGUS · {result.method} {_path_of(result.url)}",
                method=result.method,
                url=result.url,
                request_headers=result.request_headers,
                request_body=req_body_pretty,
                status_code=result.status_code,
                response_content_type=content_type,
                response_body_text=resp_body_pretty,
                severity=shot.severity,
                category_label=shot.category_label(),
                account_label=shot.account_label(),
                short_id=_short_id(shot.endpoint_id, shot.kind, shot.account),
                captured_at=utc_now_iso(),
                url_markers=shot.url_markers,
                request_body_markers=shot.request_body_markers,
                response_body_markers=shot.response_body_markers,
                note=note,
            )
            html_doc = render.render_html(spec)

            if shot.kind == "request":
                acct_slug = "probe"
            elif shot.account in ("", "anonymous"):
                acct_slug = "anon"
            else:
                acct_slug = _slugify(shot.account_label())
            filename = f"{shot.seq:02d}_{acct_slug}_{shot.kind}_{_slugify(_path_of(result.url))}.png"
            out_path = evidence_dir / filename
            browser.capture(html_doc, out_path)
            shots_captured += 1

            expected = shot.url_markers + shot.request_body_markers + shot.response_body_markers
            visible = _markers_visible(expected, spec.url, req_body_pretty, resp_body_pretty)
            manifest_shots.append(
                {
                    "seq": shot.seq,
                    "file": filename,
                    "endpoint_id": shot.endpoint_id,
                    "kind": shot.kind,
                    "account": shot.account_label(),
                    "severity": shot.severity,
                    "categories": shot.categories,
                    "rule_ids": shot.rule_ids,
                    "field_paths": shot.field_paths,
                    "markers_expected": len(expected),
                    "markers_visible": visible,
                    "auth_session_matched": matched,
                    "status_code": result.status_code,
                    "reprobe_ok": result.ok,
                    "reprobe_error": result.error,
                    "status": "captured",
                }
            )

    manifest = {
        "section_id": "5-2",
        "generated_at": utc_now_iso(),
        "shots_total": shots_captured,
        "shots": manifest_shots,
    }
    manifest_path = evidence_dir / "evidence_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    return ScreenshotRunResult(
        ok=True,
        message=f"{shots_captured} screenshot(s) captured ({len(shots)} exposure shot(s)).",
        cases_total=len(shots),
        screenshots_total=shots_captured,
        evidence_dir=str(evidence_dir),
        manifest_path=str(manifest_path),
    )


def run(ctx: DiagnosisContext, *, timeout: float = 15.0) -> ScreenshotRunResult:
    """Standalone entry: read the saved 5-2 report from disk, then capture screenshots."""
    report = _load_section_report(ctx)
    if report is None:
        return ScreenshotRunResult(
            ok=False,
            message="5-2 report not found (data/report/5-2/latest.yaml) — run the 5-2 diagnosis scan first.",
        )
    return capture_from_findings(ctx, report.findings, timeout=timeout)


def _build_standalone_context() -> DiagnosisContext:
    """Context builder for running this module directly (mirrors app diagnosis_service._context)."""
    import os

    from app.config import BACKEND_ROOT, config_to_inventory_dict, load_config
    from app.services.test_accounts_service import load_test_accounts

    cfg = load_config()
    env_path = os.environ.get("CONFIG_PATH")
    config_path = Path(env_path) if env_path else (BACKEND_ROOT / "config.yaml")
    raw: dict[str, Any] = {}
    if config_path.is_file():
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    test_accs = load_test_accounts().get("accounts")
    if test_accs:
        raw.setdefault("auth", {})
        if not raw["auth"].get("accounts"):
            raw["auth"]["accounts"] = test_accs

    return DiagnosisContext(
        data_dir=BACKEND_ROOT / "data",
        config=config_to_inventory_dict(cfg),
        raw_config=raw,
    )


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO)
    _ctx = _build_standalone_context()
    _result = run(_ctx)
    print(_result)

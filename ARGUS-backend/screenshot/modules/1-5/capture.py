"""Capture representative 1-5 (unvalidated redirect/forward) evidence.

The directory name intentionally remains ``1-5``. Load this module by file
path or execute it directly instead of importing it with dotted Python
syntax (mirrors the 1-2 / 7-4 capture adapters).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import yaml

_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

import selector  # noqa: E402
from engine import capture_case  # noqa: E402
from models import RedirectCase  # noqa: E402

_KNOWN_FIELDS = [
    ("engine", "Engine"),
    ("trigger", "Trigger"),
    ("trigger_label", "ZAP Rule"),
    ("risk", "ZAP Risk"),
    ("plugin_id", "ZAP Plugin ID"),
    ("baseline_location", "Baseline Location"),
    ("location", "Location / Marker"),
    ("confirmed_redirect", "Confirmed redirect"),
    ("stored", "Stored (persisted reflect)"),
    ("content_type", "Content-Type"),
    ("acao", "Access-Control-Allow-Origin"),
    ("acac", "Access-Control-Allow-Credentials"),
    ("probe_origin", "Probe Origin"),
    ("reason", "Reason"),
    ("domain", "Domain"),
]

_SKIP_KEYS = {
    "rule_id",
    "related_sections",
    "url",
    "test_url",
    "base_url",
    "baseline_url",
    "param_name",
    "param",
    "payload_used",
    "payload",
    "payload_description",
    "description",
    "recommendation",
    "request_body",
    "label",
    "dedupe_key",
    "severity",
    "baseline_status",
    "test_status",
    "http_status",
    "evidence_snippet",
    "evidence",
    "merged_sources",
    "duplicate_count",
} | {key for key, _ in _KNOWN_FIELDS}


def _display_url(url: str) -> str:
    return str(url).replace("host.docker.internal", "localhost")


def _status_line(evidence: dict[str, Any]) -> str:
    if evidence.get("baseline_status") is not None or evidence.get("test_status") is not None:
        return f"HTTP {evidence.get('baseline_status', '-')} -> {evidence.get('test_status', '-')}"
    if evidence.get("http_status") is not None:
        return f"HTTP {evidence.get('http_status')}"
    return ""


def _detail_lines(evidence: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for key, label in _KNOWN_FIELDS:
        value = evidence.get(key)
        if value not in (None, ""):
            lines.append(f"{label}: {value}")
    for key in ("evidence_snippet", "evidence"):
        snippet = str(evidence.get(key) or "").strip()
        if snippet:
            lines.extend(["", "Response snippet:", snippet[:1200]])
            break
    request_body = str(evidence.get("request_body") or "").strip()
    if request_body:
        lines.extend(["", "Request body:", request_body[:800]])
    extras = {
        key: value
        for key, value in evidence.items()
        if key not in _SKIP_KEYS and value not in (None, "", [])
    }
    if extras:
        lines.append("")
        lines.append("Other evidence:")
        for key, value in sorted(extras.items()):
            lines.append(f"{key}: {str(value)[:300]}")
    return lines


def case_from_finding(finding: dict[str, Any]) -> RedirectCase:
    evidence = selector.finding_evidence(finding)
    target_url = selector.resolve_target_url(evidence)
    return RedirectCase(
        case_id=selector.stable_finding_id(finding),
        rule_id=str(evidence.get("rule_id") or ""),
        title=str(finding.get("message") or "1-5 미검증 리다이렉트/포워드"),
        severity=str(finding.get("severity") or "info"),
        target_url=target_url,
        display_url=_display_url(target_url),
        method=str(evidence.get("method") or "GET"),
        param_name=str(evidence.get("param_name") or evidence.get("param") or "-"),
        payload=str(evidence.get("payload_used") or evidence.get("payload") or "-"),
        status_line=_status_line(evidence),
        detail_lines=_detail_lines(evidence),
        description=str(evidence.get("description") or ""),
        recommendation=str(evidence.get("recommendation") or ""),
    )


def capture_finding(finding: dict[str, Any], output_root: Path) -> list[dict[str, str]]:
    case = case_from_finding(finding)
    output_dir = output_root / case.case_id
    artifacts = capture_case(case, output_dir)

    manifest = {
        "section_id": "1-5",
        "case_id": case.case_id,
        "rule_id": case.rule_id,
        "title": case.title,
        "severity": case.severity,
        "target_url": case.display_url,
        "method": case.method,
        "param_name": case.param_name,
        "payload": case.payload,
        "status_line": case.status_line,
        "description": case.description,
        "recommendation": case.recommendation,
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
    limit: int = 8,
) -> list[dict[str, Any]]:
    report = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
    findings = list(report.get("findings") or [])
    selected = selector.select_representatives(findings, limit=limit)
    selected_ids = {selector.stable_finding_id(finding) for finding in selected}
    if output_root.is_dir():
        for stale_dir in output_root.glob("1-5-*"):
            if stale_dir.is_dir() and stale_dir.name not in selected_ids:
                shutil.rmtree(stale_dir)

    results: list[dict[str, Any]] = []
    for finding in selected:
        finding_id = selector.stable_finding_id(finding)
        try:
            artifacts = capture_finding(finding, output_root)
            results.append({"finding_id": finding_id, "ok": True, "artifacts": artifacts})
        except Exception as exc:
            results.append({"finding_id": finding_id, "ok": False, "error": str(exc)})

    summary = {
        "section_id": "1-5",
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
    # /app/screenshot/modules/1-5 -> /app
    return _MODULE_DIR.parents[2]


def main() -> int:
    if not os.environ.get("DISPLAY"):
        os.execvp(
            "xvfb-run",
            ["xvfb-run", "-a", "-s", "-screen 0 1280x720x24", sys.executable, *sys.argv],
        )

    backend_root = _default_backend_root()
    parser = argparse.ArgumentParser(description="Capture 1-5 redirect/CORS/XSS evidence screenshots")
    parser.add_argument(
        "--report",
        type=Path,
        default=backend_root / "data" / "report" / "1-5" / "latest.yaml",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=backend_root / "data" / "report" / "1-5" / "evidence",
    )
    parser.add_argument("--limit", type=int, default=8)
    args = parser.parse_args()

    results = capture_latest(args.report, args.output, limit=max(1, args.limit))
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0 if results and all(row["ok"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

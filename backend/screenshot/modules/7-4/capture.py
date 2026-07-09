"""Capture representative 7-4 evidence without modifying diagnosis code."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml

_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

from engine import capture_sca, capture_web  # noqa: E402
from models import ScaCase, WebConfigCase  # noqa: E402
from selector import select_sca, select_web_groups, stable_id  # noqa: E402


def _display_url(url: str) -> str:
    return str(url).replace("host.docker.internal", "localhost")


def _probe_web(group: dict[str, Any]) -> WebConfigCase:
    findings = group["findings"]
    first = dict(findings[0].get("evidence") or {})
    target_url = str(first.get("url") or group["base_url"])
    status = None
    headers: dict[str, str] = {}
    body = ""
    try:
        parsed = urlsplit(target_url)
        request_headers = {}
        if parsed.hostname == "host.docker.internal":
            display_host = "localhost"
            if parsed.port:
                display_host = f"{display_host}:{parsed.port}"
            request_headers["Host"] = display_host
        response = httpx.get(
            target_url,
            headers=request_headers,
            timeout=10,
            follow_redirects=True,
        )
        status = response.status_code
        headers = dict(response.headers)
        body = response.text[:4000]
    except Exception as exc:
        body = f"Probe failed: {exc}"
    issues = []
    for finding in findings:
        evidence = dict(finding.get("evidence") or {})
        issues.append(
            {
                "severity": finding.get("severity"),
                "check_type": evidence.get("check_type"),
                "header": evidence.get("header"),
                "header_value": evidence.get("header_value"),
                "reason": evidence.get("reason"),
                "remediation": evidence.get("remediation"),
            }
        )
    case_id = stable_id("web", str(group["base_url"]))
    return WebConfigCase(
        case_id=case_id,
        target_url=target_url,
        display_url=_display_url(target_url),
        severity="high" if any(i["severity"] == "high" for i in issues) else "medium",
        status_code=status,
        response_headers=headers,
        response_body=body,
        issues=issues,
    )


def _dependency_lines(backend_root: Path, component: str, version: str) -> list[str]:
    needle = f"{component}:{version}"
    matches: list[str] = []
    for path in sorted((backend_root / "data" / "uploads").glob("*/deps_*.txt"), reverse=True):
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if needle in line:
                    matches.append(f"{path.name}: {line.strip()}")
                    if len(matches) >= 8:
                        return matches
        except OSError:
            continue
    return matches


def _sca_case(finding: dict[str, Any], backend_root: Path) -> ScaCase:
    evidence = dict(finding.get("evidence") or {})
    details = list(evidence.get("cve_details") or [])
    selected = next(
        (row for row in details if str(row.get("severity") or "").lower() == "high"),
        details[0] if details else {},
    )
    advisory_id = str(selected.get("id") or (evidence.get("cve_ids") or ["unknown"])[0])
    component = str(evidence.get("component") or "unknown")
    version = str(evidence.get("version") or "unknown")
    return ScaCase(
        case_id=stable_id("sca", f"{component}:{version}"),
        component=component,
        version=version,
        severity=str(finding.get("severity") or "medium"),
        advisory_id=advisory_id,
        advisory_url=f"https://github.com/advisories/{advisory_id}",
        advisory_summary=str(selected.get("summary") or evidence.get("evidence_summary") or ""),
        remediation=str(evidence.get("remediation") or ""),
        cve_ids=[str(item) for item in evidence.get("cve_ids") or []],
        dependency_lines=_dependency_lines(backend_root, component, version),
    )


def capture_latest(report_path: Path, output_root: Path, web_limit: int = 3, sca_limit: int = 3):
    backend_root = _MODULE_DIR.parents[2]
    report = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
    findings = list(report.get("findings") or [])
    web_cases = [_probe_web(row) for row in select_web_groups(findings, web_limit)]
    sca_cases = [_sca_case(row, backend_root) for row in select_sca(findings, sca_limit)]
    selected_ids = {case.case_id for case in [*web_cases, *sca_cases]}
    if output_root.is_dir():
        for stale in output_root.glob("7-4-*"):
            if stale.is_dir() and stale.name not in selected_ids:
                shutil.rmtree(stale)

    results = []
    for case in web_cases:
        try:
            artifacts = capture_web(case, output_root / case.case_id)
            results.append({"case_id": case.case_id, "type": "web", "ok": True, "artifacts": artifacts})
        except Exception as exc:
            results.append({"case_id": case.case_id, "type": "web", "ok": False, "error": str(exc)})
    for case in sca_cases:
        try:
            artifacts = capture_sca(case, output_root / case.case_id)
            results.append({"case_id": case.case_id, "type": "sca", "ok": True, "artifacts": artifacts})
        except Exception as exc:
            results.append({"case_id": case.case_id, "type": "sca", "ok": False, "error": str(exc)})
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "capture-summary.json").write_text(
        json.dumps({"section_id": "7-4", "results": results}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return results


def main() -> int:
    if not os.environ.get("DISPLAY"):
        os.execvp(
            "xvfb-run",
            ["xvfb-run", "-a", "-s", "-screen 0 1280x720x24", sys.executable, *sys.argv],
        )
    backend_root = _MODULE_DIR.parents[2]
    parser = argparse.ArgumentParser(description="Capture 7-4 evidence screenshots")
    parser.add_argument("--report", type=Path, default=backend_root / "data/report/7-4/latest.yaml")
    parser.add_argument("--output", type=Path, default=backend_root / "data/report/7-4/evidence")
    parser.add_argument("--web-limit", type=int, default=3)
    parser.add_argument("--sca-limit", type=int, default=3)
    args = parser.parse_args()
    results = capture_latest(args.report, args.output, args.web_limit, args.sca_limit)
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0 if results and all(row["ok"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Capture representative 7-4 evidence without modifying diagnosis code."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml

_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

from engine import capture_sca, capture_web  # noqa: E402
from advisory import enrich_advisories, select_representative  # noqa: E402
from models import ScaCase, WebConfigCase  # noqa: E402
from selector import select_sca, select_web_groups, stable_id  # noqa: E402


def _display_url(url: str) -> str:
    return str(url).replace("host.docker.internal", "localhost")


def _resolve_canvas_url(backend_root: Path) -> str:
    """Source the SCA canvas URL from config/inventory, mirroring module 1-2."""
    config_path = Path(os.environ.get("CONFIG_PATH") or backend_root / "config.yaml")
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
    if not frontend_base_url:
        try:
            env = (os.environ.get("ARGUS_DATA_DIR") or "").strip()
            data_dir = Path(env) if env else (backend_root / "data")
            tree = json.loads((data_dir / "api-tree.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            tree = {}
        for row in tree.get("endpoints") or []:
            if str(row.get("kind") or "") == "frontend":
                frontend_base_url = str(row.get("base_url") or "")
                if frontend_base_url:
                    break
    if not frontend_base_url:
        raise RuntimeError(
            "Frontend URL is unavailable. Set inventory.markdown.frontend_base_url "
            "or provide frontend endpoints in data/api-tree.json."
        )
    return _display_url(frontend_base_url.rstrip("/"))


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
    case_id = stable_id("web", f"{group['base_url']}|{group.get('check_type') or ''}")
    return WebConfigCase(
        case_id=case_id,
        target_url=target_url,
        display_url=_display_url(target_url),
        severity="high" if any(i["severity"] == "high" for i in issues) else "medium",
        status_code=status,
        response_headers=headers,
        response_body=body,
        issues=issues,
        affected_hosts=[_display_url(h) for h in group.get("affected_hosts") or []],
    )


def _dependency_lines(backend_root: Path, component: str, version: str) -> list[str]:
    needle = f"{component}:{version}"
    matches: list[str] = []
    env = (os.environ.get("ARGUS_DATA_DIR") or "").strip()
    data_dir = Path(env) if env else (backend_root / "data")
    for path in sorted((data_dir / "uploads").glob("*/deps_*.txt"), reverse=True):
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if needle in line:
                    matches.append(f"{path.name}: {line.strip()}")
                    if len(matches) >= 8:
                        return matches
        except OSError:
            continue
    return matches


def _matches_range(version: str, expression: str) -> bool:
    version_key = _version_key(version)
    if not version_key or not expression:
        return False
    for operator, boundary in re.findall(r"(>=|<=|>|<|=)\s*([^,\s]+)", expression):
        boundary_key = _version_key(boundary)
        if not boundary_key:
            continue
        width = max(len(version_key), len(boundary_key))
        left = version_key + (0,) * (width - len(version_key))
        right = boundary_key + (0,) * (width - len(boundary_key))
        if operator == ">=" and not left >= right:
            return False
        if operator == "<=" and not left <= right:
            return False
        if operator == ">" and not left > right:
            return False
        if operator == "<" and not left < right:
            return False
        if operator == "=" and not left == right:
            return False
    return True


def _matching_vulnerability(
    advisory: dict[str, Any],
    component: str,
    installed_version: str,
) -> dict[str, Any]:
    package_matches = []
    for vulnerability in advisory.get("vulnerabilities") or []:
        package = vulnerability.get("package") or {}
        if str(package.get("name") or "") == component:
            package_matches.append(dict(vulnerability))
    return next(
        (
            row
            for row in package_matches
            if _matches_range(installed_version, str(row.get("vulnerable_version_range") or ""))
        ),
        {},
    )


def _patched_version(vulnerability: dict[str, Any]) -> str:
    patched = vulnerability.get("first_patched_version")
    if isinstance(patched, dict):
        return str(patched.get("identifier") or "")
    return str(patched or vulnerability.get("patched_versions") or "")


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value))


def _recommended_version(
    candidates: list[dict[str, Any]],
    component: str,
    installed_version: str,
) -> str:
    installed_key = _version_key(installed_version)
    installed_major = installed_key[0] if installed_key else None
    versions = []
    for candidate in candidates:
        version = _patched_version(_matching_vulnerability(candidate, component, installed_version))
        key = _version_key(version)
        if not version or not key:
            continue
        if installed_major is not None and key[0] != installed_major:
            continue
        versions.append((key, version))
    return max(versions, default=((), ""), key=lambda item: item[0])[1]


def _sca_case(
    finding: dict[str, Any],
    backend_root: Path,
    advisory_cache: dict[str, dict[str, Any]],
    canvas_url: str,
) -> ScaCase:
    evidence = dict(finding.get("evidence") or {})
    component = str(evidence.get("component") or "unknown")
    version = str(evidence.get("version") or "unknown")
    details = list(evidence.get("cve_details") or [])
    advisory_ids = [str(item) for item in evidence.get("cve_ids") or []]
    candidates = enrich_advisories(advisory_ids, details, cache=advisory_cache)
    missing_metadata = [
        str(row.get("advisory_id") or "")
        for row in candidates
        if not row.get("metadata_available")
    ]
    if missing_metadata:
        raise RuntimeError(
            "GitHub Advisory metadata incomplete for "
            f"{component}: "
            f"{len(missing_metadata)} item(s). Wait for API rate-limit reset or set GITHUB_TOKEN."
        )
    selected = select_representative(candidates) or (
        details[0] if details else {}
    )
    advisory_id = str(selected.get("id") or (evidence.get("cve_ids") or ["unknown"])[0])
    advisory_id = str(selected.get("advisory_id") or advisory_id)
    selected_vulnerability = _matching_vulnerability(selected, component, version)
    representative_patch = _patched_version(selected_vulnerability)
    recommended_version = _recommended_version(candidates, component, version)
    cvss_prerequisites = str(selected.get("cvss_prerequisites") or "not available")
    selection_reason = (
        "installed version affected; "
        f"runtime applicability={selected.get('operating_conditions', 'unconfirmed')}; "
        f"severity={selected.get('severity', finding.get('severity', 'unknown'))}; "
        f"CVSS {selected.get('cvss_version') or '-'} {selected.get('cvss_score') or '-'}; "
        f"EPSS={float(selected.get('epss') or 0) * 100:.3f}%"
    )
    remediation = (
        f"Upgrade {component} to {recommended_version} or later."
        if recommended_version
        else f"Review {advisory_id} and upgrade {component} to a non-affected release."
    )
    return ScaCase(
        case_id=stable_id("sca", f"{component}:{version}"),
        component=component,
        version=version,
        severity=str(selected.get("severity") or finding.get("severity") or "medium"),
        advisory_id=advisory_id,
        advisory_url=f"https://github.com/advisories/{advisory_id}",
        advisory_summary=str(selected.get("summary") or evidence.get("evidence_summary") or ""),
        remediation=remediation,
        cve_id=str(selected.get("cve_id") or ""),
        cvss_version=str(selected.get("cvss_version") or ""),
        cvss_score=float(selected.get("cvss_score") or 0),
        cvss_vector=str(selected.get("cvss_vector") or ""),
        epss=float(selected.get("epss") or 0),
        remote=bool(selected.get("remote")),
        unauthenticated=bool(selected.get("unauthenticated")),
        public_poc=bool(selected.get("public_poc")),
        operating_conditions=str(selected.get("operating_conditions") or "unconfirmed"),
        cvss_prerequisites=cvss_prerequisites,
        vulnerable_range=str(selected_vulnerability.get("vulnerable_version_range") or ""),
        representative_patched_version=representative_patch,
        recommended_version=recommended_version,
        selection_reason=selection_reason,
        cve_ids=advisory_ids,
        dependency_lines=_dependency_lines(backend_root, component, version),
        canvas_url=canvas_url,
    )


def capture_latest(
    report_path: Path, output_root: Path, web_limit: int | None = None, sca_limit: int | None = None
):
    backend_root = _MODULE_DIR.parents[2]
    report = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
    findings = list(report.get("findings") or [])
    cache_path = output_root / "advisory-metadata-cache.json"
    try:
        advisory_cache = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        advisory_cache = {}
    web_cases = [_probe_web(row) for row in select_web_groups(findings, web_limit)]
    sca_rows = select_sca(findings, sca_limit)
    canvas_url = _resolve_canvas_url(backend_root) if sca_rows else ""
    sca_cases = []
    sca_error: Exception | None = None
    for row in sca_rows:
        try:
            sca_cases.append(_sca_case(row, backend_root, advisory_cache, canvas_url))
        except Exception as exc:
            sca_error = exc
            break
    output_root.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(advisory_cache, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if sca_error is not None:
        raise sca_error
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
            results.append(
                {
                    "case_id": case.case_id,
                    "type": "sca",
                    "ok": True,
                    "representative": {
                        "component": case.component,
                        "version": case.version,
                        "advisory_id": case.advisory_id,
                        "cve_id": case.cve_id,
                        "severity": case.severity,
                        "cvss_version": case.cvss_version,
                        "cvss_score": case.cvss_score,
                        "epss": case.epss,
                        "remote": case.remote,
                        "unauthenticated": case.unauthenticated,
                        "public_poc": case.public_poc,
                        "operating_conditions": case.operating_conditions,
                        "cvss_prerequisites": case.cvss_prerequisites,
                        "vulnerable_range": case.vulnerable_range,
                        "representative_patched_version": case.representative_patched_version,
                        "recommended_version": case.recommended_version,
                        "selection_reason": case.selection_reason,
                    },
                    "artifacts": artifacts,
                }
            )
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
    env = (os.environ.get("ARGUS_DATA_DIR") or "").strip()
    data_dir = Path(env) if env else (backend_root / "data")
    parser = argparse.ArgumentParser(description="Capture 7-4 evidence screenshots")
    parser.add_argument("--report", type=Path, default=data_dir / "report" / "7-4" / "latest.yaml")
    parser.add_argument("--output", type=Path, default=data_dir / "report" / "7-4" / "evidence")
    parser.add_argument("--web-limit", type=int, default=None,
                        help="Cap web cases (default: all distinct cases)")
    parser.add_argument("--sca-limit", type=int, default=None,
                        help="Cap SCA cases (default: all distinct cases)")
    args = parser.parse_args()
    results = capture_latest(args.report, args.output, args.web_limit, args.sca_limit)
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0 if results and all(row["ok"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

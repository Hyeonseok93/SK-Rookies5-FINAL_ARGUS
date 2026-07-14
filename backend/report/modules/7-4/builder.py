"""Build a normalized 7-4 document from diagnosis and capture output."""

from __future__ import annotations

import base64
import json
import mimetypes
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from guidelines import (
    DEPENDENCY_FILE_REQUIRED,
    GUIDELINE_REFERENCE,
    sca_test_method,
    web_guidance,
    web_test_method,
)
from models import EvidenceImage, FindingReport, ReportDocument


_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CAPTIONS = {
    "site": "진단 대상 서비스 화면",
    "headers": "실제 응답 헤더와 보안설정 판정 증거",
    "combined": "서비스 화면과 취약 설정을 결합한 증거",
    "dependency": "deps 파일에서 확인한 실제 의존성 및 설치 버전",
    "advisory": "공개 보안 권고 및 취약 버전 정보",
}


def _stable_id(prefix: str, value: str) -> str:
    return f"7-4-{prefix}-{sha256(value.encode('utf-8')).hexdigest()[:10]}"


def _evidence(finding: dict[str, Any]) -> dict[str, Any]:
    return dict(finding.get("evidence") or {})


def _rank(finding: dict[str, Any]) -> int:
    return _SEVERITY.get(str(finding.get("severity") or "").lower(), 0)


def _web_cases(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        evidence = _evidence(finding)
        if evidence.get("source") not in {"httpx", "zap"}:
            continue
        groups.setdefault(str(evidence.get("check_type") or "unknown"), []).append(finding)
    cases = []
    for check_type, rows in groups.items():
        representative = max(rows, key=_rank)
        evidence = _evidence(representative)
        base_url = str(evidence.get("base_url") or evidence.get("url") or "-")
        hosts = []
        for row in rows:
            row_evidence = _evidence(row)
            host = str(row_evidence.get("base_url") or row_evidence.get("url") or "")
            if host and host not in hosts:
                hosts.append(host)
        cases.append(
            {
                "case_id": _stable_id("web", f"{base_url}|{check_type}"),
                "check_type": check_type,
                "finding": representative,
                "affected_hosts": hosts,
            }
        )
    return sorted(cases, key=lambda row: _rank(row["finding"]), reverse=True)


def _sca_cases(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        evidence = _evidence(finding)
        if evidence.get("source") != "sca":
            continue
        component, version = str(evidence.get("component") or ""), str(evidence.get("version") or "")
        group_id = component.rsplit(":", 1)[0] if ":" in component else component
        key = (group_id, version)
        current = groups.get(key)
        score = (str(finding.get("severity") or "").lower() == "high", len(evidence.get("cve_ids") or []))
        if current is None:
            groups[key] = finding
        else:
            current_evidence = _evidence(current)
            current_score = (
                str(current.get("severity") or "").lower() == "high",
                len(current_evidence.get("cve_ids") or []),
            )
            if score > current_score:
                groups[key] = finding
    cases = []
    for finding in groups.values():
        evidence = _evidence(finding)
        component, version = str(evidence.get("component") or "unknown"), str(evidence.get("version") or "unknown")
        cases.append({"case_id": _stable_id("sca", f"{component}:{version}"), "finding": finding})
    return sorted(cases, key=lambda row: _rank(row["finding"]), reverse=True)


def _load_summary(evidence_dir: Path) -> dict[str, dict[str, Any]]:
    path = evidence_dir / "capture-summary.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {
        str(row.get("case_id")): row
        for row in raw.get("results") or []
        if isinstance(row, dict) and row.get("ok") and row.get("case_id")
    }


def _resolve_artifact(raw_path: str, evidence_dir: Path, case_id: str) -> Path | None:
    candidate = Path(raw_path)
    candidates = [candidate] if candidate.is_absolute() else []
    candidates.extend((evidence_dir / case_id / candidate.name, evidence_dir / candidate))
    root = evidence_dir.resolve()
    for item in candidates:
        try:
            resolved = item.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            return resolved
    return None


def _images(summary: dict[str, Any], evidence_dir: Path, case_id: str, case_type: str) -> list[EvidenceImage]:
    artifacts = {
        str(row.get("kind") or ""): str(row.get("path") or "")
        for row in summary.get("artifacts") or []
        if isinstance(row, dict)
    }
    order = ("combined", "headers", "site") if case_type == "web" else ("combined", "dependency", "advisory")
    images = []
    for kind in order:
        if not artifacts.get(kind):
            continue
        path = _resolve_artifact(artifacts[kind], evidence_dir, case_id)
        if path is None:
            continue
        mime = mimetypes.guess_type(path.name)[0] or "image/png"
        data_uri = f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode('ascii')}"
        images.append(EvidenceImage(kind, _CAPTIONS[kind], str(path), data_uri))
        if len(images) == 2:
            break
    return images


def _web_report(case: dict[str, Any], summary: dict[str, Any], evidence_dir: Path) -> FindingReport:
    finding, check_type = case["finding"], case["check_type"]
    evidence = _evidence(finding)
    guidance = web_guidance(check_type)
    target = str(evidence.get("url") or evidence.get("base_url") or "-")
    header = str(evidence.get("header") or "")
    reason = str(evidence.get("reason") or "보안 설정이 기준을 충족하지 않음")
    affected = case["affected_hosts"]
    assessment = (
        f"서비스 응답에서 {reason}이 확인되어 {guidance.label} 항목이 취약한 것으로 판정되었습니다. "
        f"대표 확인 URL은 `{target}`이며 총 {max(1, len(affected))}개 대상에서 동일 설정을 확인했습니다. "
        f"이로 인해 {guidance.impact}이 존재합니다."
    )
    facts = [("대상 URL", target), ("점검 항목", check_type), ("응답 헤더", header or "-")]
    if evidence.get("header_value") not in (None, ""):
        facts.append(("확인된 값", str(evidence["header_value"])))
    facts.append(("영향 대상 수", str(max(1, len(affected)))))
    return FindingReport(
        case_id=case["case_id"],
        case_type="web",
        # Scanner messages are frequently English and include the target URL.
        # The URL is already shown in the facts block, so keep the title concise.
        title=guidance.label,
        severity=str(finding.get("severity") or "info").lower(),
        finding_type=guidance.label,
        target=target,
        test_method=web_test_method(check_type, header),
        assessment=assessment,
        remediation=list(guidance.remediation),
        guideline_reference=GUIDELINE_REFERENCE,
        facts=facts,
        images=_images(summary, evidence_dir, case["case_id"], "web"),
    )


def _sca_report(case: dict[str, Any], summary: dict[str, Any], evidence_dir: Path) -> FindingReport:
    finding, representative = case["finding"], dict(summary.get("representative") or {})
    evidence = _evidence(finding)
    component = str(evidence.get("component") or "unknown")
    version = str(evidence.get("version") or "unknown")
    advisories = [str(row) for row in evidence.get("cve_ids") or []]
    advisory = str(representative.get("advisory_id") or (advisories[0] if advisories else "-"))
    recommended = str(representative.get("recommended_version") or "")
    target = f"{component}:{version}"
    assessment = (
        f"deps 파일에서 `{target}` 구성요소가 실제 의존성으로 확인되었고, 공개 보안 권고의 취약 버전 "
        f"범위에 포함되어 {advisory} 취약점의 영향을 받는 것으로 판정되었습니다. 이로 인해 취약점 특성에 "
        "따라 원격 코드 실행, 서비스 중단, 중요정보 노출 또는 보안 통제 우회가 발생할 가능성이 존재합니다."
    )
    remediation = []
    if recommended:
        remediation.append(f"{component}를 검증된 {recommended} 이상 버전으로 업그레이드해야 합니다.")
    else:
        remediation.append(f"{component}를 공개 보안 권고에서 제시한 비취약 버전으로 업그레이드해야 합니다.")
    remediation.extend(
        (
            "직접 의존성뿐 아니라 전이 의존성의 버전도 확인하고 lockfile 또는 빌드 설정으로 안전한 버전을 고정해야 합니다.",
            "업그레이드 후 deps 파일을 다시 생성해 취약 버전이 제거되었는지 재점검하고 정기적으로 SCA 점검을 수행해야 합니다.",
        )
    )
    facts = [
        ("구성요소", component),
        ("설치 버전", version),
        ("대표 권고", advisory),
        ("권고 URL", f"https://github.com/advisories/{advisory}" if advisory != "-" else "-"),
        ("CVE/권고 수", str(len(advisories))),
        ("권고 버전", recommended or "공개 권고 확인 필요"),
    ]
    if representative.get("cvss_score"):
        facts.append(("CVSS", f"{representative.get('cvss_version') or '-'} / {representative['cvss_score']}"))
    return FindingReport(
        case_id=case["case_id"],
        case_type="sca",
        title=f"오픈소스 의존성 취약점 - {component} {version}",
        severity=str(representative.get("severity") or finding.get("severity") or "info").lower(),
        finding_type="취약한 오픈소스 의존성",
        target=target,
        test_method=sca_test_method(),
        assessment=assessment,
        remediation=remediation,
        guideline_reference=GUIDELINE_REFERENCE,
        facts=facts,
        images=_images(summary, evidence_dir, case["case_id"], "sca"),
    )


def build_report(report_path: Path, evidence_dir: Path) -> ReportDocument:
    raw = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
    if str(raw.get("section_id") or "7-4") != "7-4":
        raise ValueError("The source report is not section 7-4")
    findings = [row for row in raw.get("findings") or [] if isinstance(row, dict)]
    summaries = _load_summary(evidence_dir)
    output: list[FindingReport] = []
    warnings: list[str] = []
    for case in _web_cases(findings):
        summary = summaries.get(case["case_id"])
        if summary:
            output.append(_web_report(case, summary, evidence_dir))
    for case in _sca_cases(findings):
        summary = summaries.get(case["case_id"])
        if summary:
            output.append(_sca_report(case, summary, evidence_dir))
    if not summaries:
        warnings.append("7-4 capture-summary.json이 없어 상세 보고서 항목을 생성하지 못했습니다.")
    elif not output:
        warnings.append("진단 finding과 성공한 증거 캡처 case가 일치하지 않습니다.")
    for item in output:
        if not item.images:
            warnings.append(f"{item.case_id}: 보고서에 사용할 증거 이미지가 없습니다.")
    now = datetime.now(UTC)
    return ReportDocument(
        section_id="7-4",
        title=str(raw.get("title") or "취약한 보안설정"),
        status=str(raw.get("status") or "unknown"),
        checked_at=str(raw.get("checked_at") or ""),
        generated_at=now.isoformat(),
        report_id=f"ARGUS-7-4-{now.strftime('%Y%m%d%H%M%S')}",
        source_report=str(report_path),
        dependency_file_required=DEPENDENCY_FILE_REQUIRED,
        findings=output,
        warnings=warnings,
    )

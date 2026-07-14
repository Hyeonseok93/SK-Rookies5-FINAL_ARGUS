"""Build a normalized 1-2 report document from diagnosis and evidence files."""

from __future__ import annotations

import base64
import json
import mimetypes
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from guidelines import (
    GUIDELINE_REFERENCE,
    classify_injection,
    detection_method_for,
    guidance_for,
)
from models import EvidenceImage, FindingReport, ReportDocument


_IMAGE_KINDS = ("baseline_evidence", "attack_evidence")
_CAPTIONS = {
    "baseline_site": "정상 입력값을 사용한 서비스 화면",
    "baseline_evidence": "정상 입력값을 사용한 요청 및 응답",
    "attack_burp": "Injection payload가 포함된 공격 요청 및 응답",
    "attack_site": "Injection payload 적용 후 서비스 화면",
    "attack_evidence": "Injection payload 적용 후 확인된 공격 요청 및 응답",
}


def _evidence(finding: dict[str, Any]) -> dict[str, Any]:
    return dict(finding.get("evidence") or finding)


def _stable_finding_id(finding: dict[str, Any]) -> str:
    evidence = _evidence(finding)
    explicit = evidence.get("finding_id") or finding.get("finding_id")
    if explicit:
        return str(explicit)
    raw_url = str(evidence.get("url") or evidence.get("raw_request_url") or "")
    path = urlsplit(raw_url).path.rstrip("/") or "/"
    key = "|".join(
        (
            str(evidence.get("method") or "GET").upper(),
            path,
            str(evidence.get("param") or evidence.get("parameter") or "").lower(),
            str(evidence.get("injection_type") or "SQL").upper(),
        )
    )
    return f"1-2-{sha256(key.encode('utf-8')).hexdigest()[:10]}"


def _load_manifests(evidence_dir: Path) -> dict[str, tuple[dict[str, Any], Path]]:
    manifests: dict[str, tuple[dict[str, Any], Path]] = {}
    if not evidence_dir.is_dir():
        return manifests
    for path in sorted(evidence_dir.glob("*/manifest.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        finding_id = str(raw.get("finding_id") or path.parent.name)
        manifests[finding_id] = (raw, path)
    return manifests


def _resolve_artifact(raw_path: str, manifest_path: Path, evidence_dir: Path) -> Path | None:
    candidate = Path(raw_path)
    candidates = [candidate] if candidate.is_absolute() else []
    candidates.extend((manifest_path.parent / candidate.name, evidence_dir / candidate))
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


def _data_uri(path: Path) -> str:
    mime = mimetypes.guess_type(path.name)[0] or "image/png"
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def _images(
    manifest: dict[str, Any],
    manifest_path: Path,
    evidence_dir: Path,
) -> list[EvidenceImage]:
    artifacts = {
        str(row.get("kind") or ""): str(row.get("path") or "")
        for row in manifest.get("artifacts") or []
        if isinstance(row, dict)
    }
    selected = [kind for kind in _IMAGE_KINDS if artifacts.get(kind)]
    if len(selected) < 2:
        for kind in ("attack_burp", "baseline_site", "attack_site"):
            if artifacts.get(kind) and kind not in selected:
                selected.append(kind)
            if len(selected) == 2:
                break
    images: list[EvidenceImage] = []
    for kind in selected:
        path = _resolve_artifact(artifacts[kind], manifest_path, evidence_dir)
        if path is None:
            continue
        images.append(
            EvidenceImage(
                kind=kind,
                caption=_CAPTIONS.get(kind, "증거 자료"),
                source_path=str(path),
                data_uri=_data_uri(path),
            )
        )
    return images


def _exchange(manifest: dict[str, Any], name: str) -> dict[str, Any]:
    value = manifest.get(name)
    return dict(value) if isinstance(value, dict) else {}


def _value(evidence: dict[str, Any], manifest: dict[str, Any], *keys: str, default: str = "-") -> str:
    for source in (evidence, manifest, dict(manifest.get("metadata") or {})):
        for key in keys:
            if source.get(key) not in (None, ""):
                return str(source[key])
    return default


def _observations(baseline: dict[str, Any], attack: dict[str, Any]) -> list[str]:
    rows: list[str] = []
    base_status, attack_status = baseline.get("status_code"), attack.get("status_code")
    if base_status is not None or attack_status is not None:
        rows.append(f"HTTP 상태: 정상 {base_status if base_status is not None else '-'} / 공격 {attack_status if attack_status is not None else '-'}")
    base_body, attack_body = str(baseline.get("response_body") or ""), str(attack.get("response_body") or "")
    if base_body or attack_body:
        rows.append(f"응답 크기: 정상 {len(base_body):,} bytes / 공격 {len(attack_body):,} bytes")
    base_ms, attack_ms = baseline.get("elapsed_ms"), attack.get("elapsed_ms")
    if base_ms is not None or attack_ms is not None:
        def fmt(value: Any) -> str:
            try:
                return f"{float(value):,.1f} ms"
            except (TypeError, ValueError):
                return "-"
        rows.append(f"처리 시간: 정상 {fmt(base_ms)} / 공격 {fmt(attack_ms)}")
    return rows


def _assessment(
    *,
    url: str,
    parameter: str,
    verification_type: str,
    verification_status: str,
    confidence: str,
    observations: list[str],
    cause: str,
    impact: str,
) -> str:
    target = f"`{url}`의 `{parameter}` 파라미터" if parameter not in ("", "-") else f"`{url}`"
    result = ", ".join(observations) if observations else f"{verification_type} 검증 조건에 해당하는 응답 변화"
    verified = verification_status.upper() == "VERIFIED"
    if verified:
        return (
            f"{cause} {target}에 공격 payload를 적용한 결과 {result}가 확인되었습니다. 동일 조건의 반복 요청에서 "
            f"결과가 재현되었고 검증 상태는 {verification_status}, 신뢰도는 {confidence}로 확인되어 취약한 것으로 "
            f"판정했습니다. 이로 인해 {impact} 등의 피해가 발생할 가능성이 존재합니다."
        )
    return (
        f"{target}에 공격 payload를 적용한 결과 {result}가 관찰되었습니다. 현재 검증 상태는 "
        f"{verification_status}, 신뢰도는 {confidence}이므로 취약점 확정 전 추가 수동 검증이 필요합니다."
    )


def build_report(report_path: Path, evidence_dir: Path) -> ReportDocument:
    raw = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
    if str(raw.get("section_id") or "1-2") != "1-2":
        raise ValueError("The source report is not section 1-2")
    manifests = _load_manifests(evidence_dir)
    warnings: list[str] = []
    findings: list[FindingReport] = []
    for finding in raw.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        evidence = _evidence(finding)
        finding_id = _stable_finding_id(finding)
        manifest_entry = manifests.get(finding_id)
        if manifest_entry is None:
            continue
        manifest, manifest_path = manifest_entry
        baseline, attack = _exchange(manifest, "baseline"), _exchange(manifest, "attack")
        method = str(attack.get("method") or baseline.get("method") or evidence.get("method") or "GET").upper()
        url = str(attack.get("url") or baseline.get("url") or evidence.get("url") or evidence.get("raw_request_url") or "-")
        parameter = _value(evidence, manifest, "parameter", "param")
        payload = _value(evidence, manifest, "payload", "custom_payload", "zap_payload")
        verification_type = _value(evidence, manifest, "verification_type", "classification", default="UNVERIFIED")
        verification_status = _value(evidence, manifest, "verification_status", default="UNVERIFIED")
        confidence = _value(evidence, manifest, "confidence", default="UNKNOWN")
        kind = classify_injection(evidence, str(finding.get("message") or ""))
        guidance = guidance_for(kind)
        observations = _observations(baseline, attack)
        images = _images(manifest, manifest_path, evidence_dir)
        if not images:
            warnings.append(f"{finding_id}: 보고서에 사용할 증거 이미지가 없습니다.")
        findings.append(
            FindingReport(
                finding_id=finding_id,
                # The engine message may be an English scanner sentence.  Use the
                # normalized Korean diagnosis name as the reader-facing title.
                title=f"{guidance.label} 취약점",
                severity=str(finding.get("severity") or "info").lower(),
                injection_type=guidance.label,
                method=method,
                url=url,
                parameter=parameter,
                payload=payload,
                verification_type=verification_type,
                verification_status=verification_status,
                confidence=confidence,
                detection_method=detection_method_for(kind, verification_type),
                assessment=_assessment(
                    url=url,
                    parameter=parameter,
                    verification_type=verification_type,
                    verification_status=verification_status,
                    confidence=confidence,
                    observations=observations,
                    cause=guidance.cause,
                    impact=guidance.impact,
                ),
                remediation=list(guidance.remediation),
                guideline_reference=GUIDELINE_REFERENCE,
                observations=observations,
                images=images,
            )
        )

    if not manifests:
        warnings.append("1-2 증거 manifest가 없어 finding 상세 페이지를 생성하지 못했습니다.")
    elif not findings:
        warnings.append("진단 finding과 증거 manifest가 일치하지 않습니다.")

    now = datetime.now(UTC)
    checked_at = str(raw.get("checked_at") or "")
    report_id = f"ARGUS-1-2-{now.strftime('%Y%m%d%H%M%S')}"
    return ReportDocument(
        section_id="1-2",
        title=str(raw.get("title") or "삽입(Injection) 공격 가능성"),
        status=str(raw.get("status") or "unknown"),
        checked_at=checked_at,
        generated_at=now.isoformat(),
        report_id=report_id,
        source_report=str(report_path),
        findings=findings,
        warnings=warnings,
    )

"""Build a downloadable per-finding evidence report for a diagnosis section.

Pilot scope: 2-1 (악성코드파일 업로드) only. Reads the section's saved
``latest.yaml`` + captured evidence screenshots, filters to findings with a
concrete verdict (확정 취약 / 잠재적 취약), and renders a single self-contained
HTML document (screenshots embedded as base64) with remediation text sourced
from the section's ``guideline.yaml``.
"""

from __future__ import annotations

import base64
import html
import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from app.config import BACKEND_ROOT

_INCLUDED_FINDING_TYPES = {"true_positive", "false_positive_candidate"}
_VERDICT_LABEL = {
    "true_positive": "확정 취약",
    "false_positive_candidate": "잠재적 취약 (추가 검증 필요)",
}


def _load_selector(section_id: str):
    path = BACKEND_ROOT / "screenshot" / "modules" / section_id / "selector.py"
    mod_name = f"report_service_{section_id.replace('-', '_')}_selector"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load selector for section {section_id}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_guideline(section_id: str) -> dict[str, Any]:
    path = BACKEND_ROOT / "diagnosis" / "modules" / section_id / "guideline.yaml"
    if not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}


def _guideline_lookup(guideline: dict[str, Any], reason: str) -> dict[str, Any]:
    reason_key, _, detail_kind = reason.partition(":")
    entry = guideline.get(reason_key)
    if not isinstance(entry, dict):
        return {}
    merged = {k: v for k, v in entry.items() if k != "detail"}
    detail = entry.get("detail") or {}
    detail_entry = detail.get(detail_kind) if detail_kind else None
    if isinstance(detail_entry, dict):
        merged.update(detail_entry)
    return merged


def _load_manifest_artifacts(evidence_dir: Path) -> list[dict[str, str]]:
    manifest_path = evidence_dir / "manifest.json"
    if not manifest_path.is_file():
        return []
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    artifacts = manifest.get("artifacts")
    return artifacts if isinstance(artifacts, list) else []


_JPEG_QUALITY = 80


def _compress_to_jpeg(png_bytes: bytes) -> tuple[bytes, str]:
    """Re-encode a PNG screenshot as JPEG to shrink the embedded report.

    These are full 1280x720 UI screenshots — PNG compresses them poorly
    (hundreds of KB each), and a report can easily embed dozens across
    findings. JPEG at this quality is visually lossless enough for evidence
    review and typically cuts size by 3-4x. Falls back to the original PNG
    bytes if Pillow can't decode the image for any reason.
    """
    try:
        from io import BytesIO

        from PIL import Image

        with Image.open(BytesIO(png_bytes)) as img:
            buf = BytesIO()
            img.convert("RGB").save(buf, format="JPEG", quality=_JPEG_QUALITY, optimize=True)
            return buf.getvalue(), "image/jpeg"
    except Exception:
        return png_bytes, "image/png"


def _embed_screenshots(evidence_dir: Path) -> list[dict[str, str]]:
    """Read this finding's captured PNGs from disk, recompress to JPEG, and
    base64-encode them.

    Only the filename from the manifest is trusted (not the stored absolute
    path, which reflects the container filesystem the capture ran in, not
    wherever the report is being generated).
    """
    embedded: list[dict[str, str]] = []
    for artifact in _load_manifest_artifacts(evidence_dir):
        name = Path(str(artifact.get("path") or "")).name
        if not name:
            continue
        image_path = evidence_dir / name
        if not image_path.is_file():
            continue
        payload, mime = _compress_to_jpeg(image_path.read_bytes())
        data = base64.b64encode(payload).decode("ascii")
        embedded.append({"kind": str(artifact.get("kind") or ""), "data_uri": f"data:{mime};base64,{data}"})
    return embedded


_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}


def _severity_rank(finding: dict[str, Any]) -> int:
    return _SEVERITY_RANK.get(str(finding.get("severity") or "info"), 0)


def build_report_items(section_id: str, *, data_dir: Path) -> list[dict[str, Any]]:
    """Assemble one report item per unique finding_id (확정 취약 / 잠재적 취약).

    ``latest.yaml`` can carry several raw findings that collapse to the same
    ``finding_id`` (same vulnerability, different auth mode/engine pass) —
    those are merged into a single card instead of repeating the same
    embedded screenshots once per variant.
    """
    report_path = data_dir / "report" / section_id / "latest.yaml"
    if not report_path.is_file():
        return []
    raw = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
    findings = raw.get("findings") or []

    selector = _load_selector(section_id)
    guideline = _load_guideline(section_id)
    evidence_root = data_dir / "report" / section_id / "evidence"

    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        evidence = finding.get("evidence") or {}
        finding_type = str(evidence.get("finding_type") or "")
        if finding_type not in _INCLUDED_FINDING_TYPES:
            continue
        finding_id = selector.stable_finding_id(finding)
        groups.setdefault(finding_id, []).append(finding)

    items: list[dict[str, Any]] = []
    for finding_id, group in groups.items():
        representative = max(group, key=_severity_rank)
        evidence = representative.get("evidence") or {}
        finding_type = str(evidence.get("finding_type") or "")
        reason = str(evidence.get("reason") or "")

        affected_urls: set[str] = set()
        auth_modes: set[str] = set()
        for f in group:
            ev = f.get("evidence") or {}
            urls = ev.get("affected_urls") or ([ev["url"]] if ev.get("url") else [])
            affected_urls.update(str(u) for u in urls)
            auth_modes.add(str(ev.get("auth_mode") or "anonymous"))

        items.append(
            {
                "finding_id": finding_id,
                "severity": str(representative.get("severity") or "info"),
                "message": str(representative.get("message") or ""),
                "verdict": _VERDICT_LABEL.get(finding_type, finding_type),
                "assessment": str(evidence.get("assessment") or ""),
                "reason": reason,
                "technique": str(evidence.get("technique") or ""),
                "extension": str(evidence.get("extension") or ""),
                "business_role": str(evidence.get("business_role") or ""),
                "feature_label": str(evidence.get("feature_label") or ""),
                "affected_urls": sorted(affected_urls),
                "auth_modes": sorted(auth_modes),
                "screenshots": _embed_screenshots(evidence_root / finding_id),
                "remediation": _guideline_lookup(guideline, reason),
            }
        )

    items.sort(key=lambda it: _SEVERITY_RANK.get(it["severity"], 0), reverse=True)
    return items


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def _render_item(item: dict[str, Any], index: int) -> str:
    urls_html = "".join(f"<li>{_esc(u)}</li>" for u in item["affected_urls"]) or "<li>(없음)</li>"

    if item["screenshots"]:
        shots_html = "".join(
            f'<figure><img src="{s["data_uri"]}" alt="{_esc(s["kind"])}"/>'
            f'<figcaption>{_esc(s["kind"])}</figcaption></figure>'
            for s in item["screenshots"]
        )
    else:
        shots_html = '<p class="no-shot">스크린샷 미보유 — 캡처가 아직 실행되지 않았거나 실패했습니다.</p>'

    remediation = item["remediation"]
    if remediation.get("guideline_ref"):
        quote_html = (
            f'<p class="quote">{_esc(remediation.get("quote", ""))}</p>' if remediation.get("quote") else ""
        )
        bullets = "".join(f"<li>{_esc(r)}</li>" for r in remediation.get("remediation") or [])
        note_html = f'<p class="note">{_esc(remediation["note"])}</p>' if remediation.get("note") else ""
        remediation_html = (
            f'<p class="ref">근거자료: {_esc(remediation["guideline_ref"])}</p>'
            f"{quote_html}{note_html}"
            + (f"<ul>{bullets}</ul>" if bullets else "")
        )
    elif remediation.get("note"):
        remediation_html = f'<p class="note">{_esc(remediation["note"])}</p>'
    else:
        remediation_html = "<p>해당 사유에 대한 대응방안이 아직 등록되지 않았습니다.</p>"

    severity_class = _esc(item["severity"])
    return f"""
<section class="finding">
  <header>
    <span class="idx">#{index}</span>
    <span class="badge severity-{severity_class}">{severity_class.upper()}</span>
    <span class="badge verdict">{_esc(item["verdict"])}</span>
    <h2>{_esc(item["feature_label"] or item["message"])}</h2>
  </header>
  <p class="message">{_esc(item["message"])}</p>
  <dl class="meta">
    <dt>탐지 사유</dt><dd>{_esc(item["reason"])}</dd>
    <dt>역할</dt><dd>{_esc(item["business_role"])}</dd>
    <dt>기법 / 확장자</dt><dd>{_esc(item["technique"])} / {_esc(item["extension"] or "-")}</dd>
    <dt>확인된 인증 모드</dt><dd>{_esc(", ".join(item.get("auth_modes") or []) or "-")}</dd>
  </dl>
  <h3>관련 URL</h3>
  <ul class="urls">{urls_html}</ul>
  <h3>증거 스크린샷</h3>
  <div class="shots">{shots_html}</div>
  <h3>해결방안</h3>
  <div class="remediation">{remediation_html}</div>
</section>
"""


_PAGE_CSS = """
body { font-family: -apple-system, "Malgun Gothic", "Noto Sans KR", sans-serif; margin: 0; padding: 24px; background: #f4f5f7; color: #1a1d22; }
.report-header { margin-bottom: 24px; }
.report-header h1 { margin: 0 0 4px; font-size: 20px; }
.report-header p { margin: 0; color: #555; font-size: 12px; }
.finding { background: #fff; border: 1px solid #dde1e6; border-radius: 6px; padding: 18px 22px; margin-bottom: 18px; }
.finding header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.finding header h2 { margin: 0; font-size: 15px; }
.idx { font-family: monospace; color: #888; font-size: 12px; }
.badge { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 999px; text-transform: uppercase; }
.badge.severity-high { background: #fde2e1; color: #b0261f; }
.badge.severity-medium { background: #fdecd2; color: #a15c06; }
.badge.severity-low { background: #dce8fb; color: #2c5f9e; }
.badge.severity-info { background: #e6e8eb; color: #555; }
.badge.verdict { background: #111; color: #fff; }
.message { color: #333; font-size: 13px; margin: 10px 0; }
.meta { display: grid; grid-template-columns: 110px 1fr; gap: 4px 10px; font-size: 12px; margin: 10px 0; }
.meta dt { color: #777; }
.meta dd { margin: 0; font-family: monospace; }
h3 { font-size: 12px; text-transform: uppercase; letter-spacing: .03em; color: #666; margin: 16px 0 6px; }
.urls { margin: 0; padding-left: 18px; font-family: monospace; font-size: 12px; }
.shots { display: flex; flex-wrap: wrap; gap: 12px; }
.shots figure { margin: 0; max-width: 320px; }
.shots img { max-width: 100%; border: 1px solid #ccc; border-radius: 4px; display: block; }
.shots figcaption { font-size: 10px; color: #777; text-align: center; margin-top: 4px; }
.no-shot { font-size: 12px; color: #999; font-style: italic; }
.remediation { font-size: 12px; line-height: 1.6; }
.remediation .ref { font-weight: 700; margin: 0 0 6px; }
.remediation .quote { background: #f2f0fb; border-left: 3px solid #7c6fd6; padding: 8px 12px; margin: 0 0 8px; font-style: italic; }
.remediation .note { color: #444; }
.remediation ul { margin: 4px 0 0; padding-left: 18px; }
.empty { background: #fff; border: 1px solid #dde1e6; border-radius: 6px; padding: 24px; text-align: center; color: #777; }
"""


def render_report_html(section_id: str, title: str, items: list[dict[str, Any]]) -> str:
    generated_at = datetime.now(UTC).isoformat(timespec="seconds")
    body = (
        "".join(_render_item(item, i + 1) for i, item in enumerate(items))
        if items
        else '<div class="empty">확정 취약 / 잠재적 취약으로 분류된 finding이 없습니다.</div>'
    )
    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8"/>
<title>ARGUS {_esc(section_id)} 진단 결과서</title>
<style>{_PAGE_CSS}</style>
</head>
<body>
<div class="report-header">
  <h1>ARGUS 취약점 진단 결과서 — {_esc(section_id)}. {_esc(title)}</h1>
  <p>생성 일시: {_esc(generated_at)} · 대상 finding {len(items)}건 (확정 취약 + 잠재적 취약)</p>
</div>
{body}
</body>
</html>
"""

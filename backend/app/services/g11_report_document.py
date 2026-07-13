from __future__ import annotations

import base64
import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


BACKEND_ROOT = Path(__file__).resolve().parents[2]
SK_SHIELDUS_G11_GUIDE = (
    BACKEND_ROOT
    / "diagnosis"
    / "modules"
    / "1-1"
    / "assets"
    / "sk_shieldus_g11_response.md"
)

CSRF_GUIDE = """1. CSRF Token 적용

서버는 예측 불가능한 CSRF Token을 발급해야 합니다.
POST, PUT, PATCH, DELETE 등 상태 변경 요청마다 CSRF Token을 검증해야 합니다.
Token은 사용자 세션과 연결되어야 하며, 요청 본문 또는 전용 헤더(`X-CSRF-Token`, `X-XSRF-Token`)로 전달하도록 구성합니다.
Token이 없거나 일치하지 않으면 요청을 거부해야 합니다.

2. Origin / Referer 검증

상태 변경 API는 `Origin` 또는 `Referer` 헤더를 검증해야 합니다.
허용된 도메인에서 온 요청만 처리하고, 외부 Origin 또는 누락된 Origin/Referer 요청은 차단합니다.
일부 환경에서 Referer가 제거될 수 있으므로 `Origin` 검증을 우선 적용하고 Referer는 보조 검증으로 사용하는 것이 좋습니다.

3. SameSite Cookie 설정

세션 쿠키에는 `SameSite=Lax` 또는 `SameSite=Strict`를 설정합니다.
인증 쿠키에는 함께 `HttpOnly`, `Secure` 옵션도 적용합니다.

예시:
`Set-Cookie: SESSION=...; HttpOnly; Secure; SameSite=Lax`

4. CORS Credential 제한

`Access-Control-Allow-Credentials: true`를 사용하는 경우, `Access-Control-Allow-Origin: *`를 사용하지 않습니다.
허용 Origin을 명시적으로 제한하고, 신뢰할 수 있는 프론트엔드 도메인만 허용합니다.

5. 중요 기능 추가 보호

결제, 예약, 회원정보 변경, 비밀번호 변경, 권한 변경 등 민감한 기능은 CSRF Token 외에도 추가 확인 절차를 둡니다.
예: 비밀번호 재입력, OTP, 재인증, 사용자 확인 팝업 등

6. GET 요청으로 상태 변경 금지

GET 요청은 조회 용도로만 사용합니다.
상태 변경은 반드시 POST, PUT, PATCH, DELETE 등 명확한 메서드로 처리하고, 해당 요청에 CSRF 방어를 적용합니다.
"""


def _value(value: Any, fallback: str = "-") -> str:
    if value is None or value == "":
        return fallback
    return str(value)


def _esc(value: Any) -> str:
    return html.escape(_value(value), quote=True)


def _slug(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "-", str(value or "").strip())
    return text.strip("-") or "x"


def _finding_id_prefix(evidence: dict[str, Any]) -> str:
    vuln_type = _value(evidence.get("vuln_type"), "").strip()
    method = _value(evidence.get("method"), "GET").upper()
    url = _value(evidence.get("url"), "/").rstrip("/") or "/"
    path = urlsplit(url).path.strip("/") or "root"
    param = _value(evidence.get("param"), "").lower()
    role = _value(evidence.get("account_role"), "").strip().upper()
    parts = [vuln_type, method, path, param]
    if role:
        parts.append(role)
    return "1-1_" + "_".join(_slug(part) for part in parts) + "_"


def _load_capture_results(evidence_root: Path) -> dict[str, list[dict[str, Any]]]:
    summary_path = evidence_root / "capture-summary.json"
    if not summary_path.is_file():
        return {}
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    results: dict[str, list[dict[str, Any]]] = {}
    for row in summary.get("results") or []:
        if not isinstance(row, dict):
            continue
        finding_id = str(row.get("finding_id") or "")
        artifacts = row.get("artifacts") or []
        if finding_id and isinstance(artifacts, list):
            results[finding_id] = [item for item in artifacts if isinstance(item, dict)]
    return results


def _image_data_uri(path: Path) -> str | None:
    if not path.is_file():
        return None
    suffix = path.suffix.lower()
    mime = "image/png"
    if suffix in {".jpg", ".jpeg"}:
        mime = "image/jpeg"
    elif suffix == ".webp":
        mime = "image/webp"
    return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode('ascii')}"


def _finding_images(
    evidence_root: Path,
    capture_results: dict[str, list[dict[str, Any]]],
    evidence: dict[str, Any],
) -> list[tuple[str, str]]:
    prefix = _finding_id_prefix(evidence)
    finding_id = next((key for key in capture_results if key.startswith(prefix)), "")
    if not finding_id:
        return []

    images: list[tuple[str, str]] = []
    root = evidence_root.resolve()
    for artifact in capture_results.get(finding_id, []):
        raw_path = str(artifact.get("path") or "")
        if not raw_path.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
            continue
        marker = "/evidence/"
        rel_path = raw_path.split(marker, 1)[1] if marker in raw_path else raw_path
        image_path = (evidence_root / rel_path).resolve()
        try:
            image_path.relative_to(root)
        except ValueError:
            continue
        data_uri = _image_data_uri(image_path)
        if data_uri:
            images.append((str(artifact.get("kind") or "evidence"), data_uri))
    return images


def _csrf_block(evidence: dict[str, Any]) -> str:
    if not _is_csrf_evidence(evidence):
        return ""
    csrf = evidence.get("csrf_defenses")
    if not isinstance(csrf, dict):
        return ""
    return f"""
      <div class="csrf">
        <strong>CSRF 방어 확인</strong>
        <span>Origin/Referer 우회: {_esc(csrf.get("origin_referer_bypass"))}</span>
        <span>CSRF Token 부재: {_esc(csrf.get("csrf_token_absent"))}</span>
        <span>SameSite 미흡: {_esc(csrf.get("unsafe_samesite"))}</span>
        <span>실패 방어 수: {_esc(csrf.get("failed_count"))}</span>
      </div>
    """


def _is_csrf_evidence(evidence: dict[str, Any]) -> bool:
    label = f"{evidence.get('vuln_type') or ''} {evidence.get('alert') or ''}"
    return "csrf" in label.lower()


def _load_sk_shieldus_guide() -> str:
    if not SK_SHIELDUS_G11_GUIDE.is_file():
        return ""
    return SK_SHIELDUS_G11_GUIDE.read_text(encoding="utf-8").strip()


def _guide_for_finding(evidence: dict[str, Any]) -> str:
    if _is_csrf_evidence(evidence):
        return CSRF_GUIDE
    return (
        _load_sk_shieldus_guide()
        or str(evidence.get("sk_shieldus_guide") or "")
        or str(evidence.get("remediation_guide") or "")
        or str(evidence.get("remediation_summary") or "")
        or "SK쉴더스 가이드 문구가 제공되면 이 영역에 반영합니다."
    )


def _inline_markdown(text: str) -> str:
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", _esc(text))


def _guide_to_html(markdown: str) -> str:
    lines = [line.rstrip() for line in markdown.splitlines()]
    html_parts: list[str] = []
    paragraph: list[str] = []
    bullet_items: list[str] = []
    table_rows: list[list[str]] = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            html_parts.append(f"<p>{_inline_markdown(' '.join(paragraph))}</p>")
            paragraph = []

    def flush_bullets() -> None:
        nonlocal bullet_items
        if bullet_items:
            html_parts.append("<ul>" + "".join(f"<li>{item}</li>" for item in bullet_items) + "</ul>")
            bullet_items = []

    def flush_table() -> None:
        nonlocal table_rows
        if not table_rows:
            return
        rows = [row for row in table_rows if not all(set(cell) <= {"-"} for cell in row)]
        if rows:
            head, *body = rows
            html_parts.append(
                "<table class='guide-table'><thead><tr>"
                + "".join(f"<th>{_inline_markdown(cell)}</th>" for cell in head)
                + "</tr></thead><tbody>"
                + "".join(
                    "<tr>" + "".join(f"<td>{_inline_markdown(cell)}</td>" for cell in row) + "</tr>"
                    for row in body
                )
                + "</tbody></table>"
            )
        table_rows = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            flush_bullets()
            flush_table()
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            flush_paragraph()
            flush_bullets()
            table_rows.append([cell.strip() for cell in stripped.strip("|").split("|")])
            continue
        flush_table()

        if re.match(r"^\d+\.\s+", stripped):
            flush_paragraph()
            flush_bullets()
            title = re.sub(r"^\d+\.\s+", "", stripped)
            html_parts.append(f"<h4>{_inline_markdown(title)}</h4>")
            continue

        if stripped.endswith(":") and len(stripped) < 40:
            flush_paragraph()
            flush_bullets()
            html_parts.append(f"<h5>{_inline_markdown(stripped[:-1])}</h5>")
            continue

        if stripped.startswith("- "):
            flush_paragraph()
            bullet_items.append(_inline_markdown(stripped[2:]))
            continue

        paragraph.append(stripped)

    flush_paragraph()
    flush_bullets()
    flush_table()
    return "<div class='guide'>" + "".join(html_parts) + "</div>"


def _finding_html(
    index: int,
    finding: dict[str, Any],
    evidence_root: Path,
    capture_results: dict[str, list[dict[str, Any]]],
) -> str:
    evidence = dict(finding.get("evidence") or {})
    title = evidence.get("vuln_type") or finding.get("message") or "Finding"
    images = _finding_images(evidence_root, capture_results, evidence)
    image_html = ""
    if images:
        image_html = "<div class='images'>" + "".join(
            f"""
            <figure>
              <img src="{src}" alt="{_esc(kind)} evidence">
              <figcaption>{_esc("실제 화면 증거" if kind == "site" else "요청/응답 증거")}</figcaption>
            </figure>
            """
            for kind, src in images
        ) + "</div>"
    else:
        image_html = "<p class='muted'>캡처 이미지가 연결되지 않았습니다.</p>"

    guide = _guide_for_finding(evidence)

    return f"""
    <section class="finding">
      <h2>{index}. {_esc(title)}</h2>
      <table>
        <tr><th>URL</th><td>{_esc(evidence.get("url"))}</td></tr>
        <tr><th>Method</th><td>{_esc(evidence.get("method"))}</td></tr>
        <tr><th>Parameter</th><td>{_esc(evidence.get("param"))}</td></tr>
        <tr><th>Payload</th><td><code>{_esc(evidence.get("attack"))}</code></td></tr>
        <tr><th>Severity</th><td>{_esc(finding.get("severity") or evidence.get("severity"))}</td></tr>
        <tr><th>Validation</th><td>{_esc(evidence.get("validation_status"))}</td></tr>
      </table>
      <h3>문제점</h3>
      <p>{_esc(evidence.get("vuln_description") or evidence.get("description") or finding.get("message"))}</p>
      <h3>판정 근거</h3>
      <p>{_esc(evidence.get("validation_reason") or evidence.get("evidence"))}</p>
      {_csrf_block(evidence)}
      <h3>캡처 증거</h3>
      {image_html}
      <h3>해결방안</h3>
      {_guide_to_html(str(guide))}
    </section>
    """


def generate_g11_report_document(report_dir: Path) -> Path:
    report_path = report_dir / "latest.yaml"
    if not report_path.is_file():
        raise FileNotFoundError(str(report_path))

    evidence_root = report_dir / "evidence"
    report = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
    capture_results = _load_capture_results(evidence_root)
    findings = [
        row for row in (report.get("findings") or [])
        if isinstance(row, dict) and not ((row.get("evidence") or {}).get("screenshot_capture"))
    ]
    report_findings = [
        row for row in findings
        if str(row.get("severity") or "").lower() not in {"info", "pass"}
    ] or findings

    body = "\n".join(
        _finding_html(index, finding, evidence_root, capture_results)
        for index, finding in enumerate(report_findings, start=1)
    )
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output_path = report_dir / "diagnosis-result.html"
    output_path.write_text(
        f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>ARGUS 1-1 진단 결과서</title>
  <style>
    body {{ margin: 0; background: #f6f8fb; color: #172033; font-family: Arial, 'Malgun Gothic', sans-serif; }}
    main {{ max-width: 980px; margin: 0 auto; padding: 32px 24px 56px; }}
    header {{ margin-bottom: 24px; border-bottom: 2px solid #172033; padding-bottom: 16px; }}
    h1 {{ margin: 0 0 8px; font-size: 28px; }}
    h2 {{ margin: 0 0 16px; font-size: 20px; color: #991b1b; }}
    h3 {{ margin: 18px 0 8px; font-size: 14px; color: #334155; }}
    .meta {{ color: #64748b; font-size: 13px; }}
    .finding {{ margin: 24px 0; padding: 22px; background: #fff; border: 1px solid #d9e2ef; page-break-inside: avoid; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ width: 130px; background: #eef3f8; text-align: left; color: #475569; }}
    th, td {{ border: 1px solid #d9e2ef; padding: 8px 10px; vertical-align: top; word-break: break-all; }}
    code {{ font-family: Consolas, monospace; }}
    p {{ margin: 0; line-height: 1.65; white-space: pre-wrap; }}
    ul {{ margin: 8px 0 0 18px; padding: 0; line-height: 1.65; }}
    li {{ margin: 3px 0; }}
    .images {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; }}
    figure {{ margin: 0; border: 1px solid #d9e2ef; background: #f8fafc; }}
    img {{ display: block; width: 100%; height: auto; }}
    figcaption {{ padding: 7px 9px; color: #64748b; font-size: 12px; border-top: 1px solid #d9e2ef; }}
    .csrf {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 6px; padding: 12px; background: #fff7ed; border: 1px solid #fed7aa; font-size: 13px; }}
    .csrf strong {{ grid-column: 1 / -1; }}
    .guide {{ display: grid; gap: 12px; }}
    .guide h4 {{ margin: 8px 0 0; padding: 9px 12px; background: #e8f1fb; border-left: 4px solid #2563eb; font-size: 14px; color: #1e3a8a; }}
    .guide h5 {{ margin: 3px 0 0; font-size: 13px; color: #334155; }}
    .guide p {{ margin: 0; }}
    .guide-table th {{ width: auto; text-align: center; }}
    .guide-table td {{ text-align: center; }}
    .guide code {{ display: inline-block; margin: 2px 2px 2px 0; padding: 2px 5px; border-radius: 4px; background: #eef2ff; color: #3730a3; font-size: 12px; }}
    .muted {{ color: #64748b; }}
    @media print {{ body {{ background: #fff; }} main {{ padding: 0; }} .finding {{ border-color: #999; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>ARGUS 1-1 진단 결과서</h1>
      <div class="meta">대상: XSS / CSRF attack surface · 상태: {_esc(report.get("status"))} · 생성: {_esc(generated_at)} · Finding: {len(report_findings)}</div>
    </header>
    {body or "<p class='muted'>표시할 진단 결과가 없습니다.</p>"}
  </main>
</body>
</html>
""",
        encoding="utf-8",
    )
    return output_path

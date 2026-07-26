"""Evidence screenshot runner for guideline 1-6.

This module is intentionally loaded by file path from
``diagnosis/modules/1-6/scanner.py`` because the section directory contains a
hyphen. It borrows the 1-2 screenshot package's idea of producing a stable
plan, a manifest, and deterministic 1280x720 evidence boards, but adapts it to
W16 raw findings.
"""

from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

VIEWPORT = {"width": 1280, "height": 720}
MAX_CAPTURE = 30


def _load_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _safe_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in value)
    cleaned = "-".join(part for part in cleaned.split("-") if part)
    return cleaned[:80] or "finding"


def _finding_id(raw: dict[str, Any], index: int) -> str:
    existing = str(raw.get("id") or raw.get("finding_id") or "").strip()
    if existing:
        return _safe_name(existing)
    seed = json.dumps(
        {
            "url": raw.get("normalized_url") or raw.get("url"),
            "payload": raw.get("payload_name"),
            "vector": raw.get("attack_vector"),
            "status": raw.get("status_code"),
            "index": index,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return f"w16-{hashlib.sha1(seed.encode('utf-8')).hexdigest()[:12]}"


def _severity_rank(raw: dict[str, Any]) -> int:
    cls = raw.get("classification") or {}
    status = str(cls.get("final_status") or "").lower()
    confidence = str(cls.get("confidence") or "").lower()
    bucket = str(raw.get("review_bucket") or "").lower()
    if bucket == "noise" or status == "not_vulnerable":
        return 0
    if status == "vulnerable" and confidence == "high":
        return 5
    if status == "vulnerable":
        return 4
    if status == "potential_vulnerable" and bucket == "report_candidate":
        return 3
    if status == "potential_vulnerable":
        return 2
    return 1


def _vuln_type_key(raw: dict[str, Any]) -> str:
    """Best-available vulnerability category, used to diversify evidence picks
    so one payload/type can't crowd out the rest of the selection."""
    kisa = str(raw.get("kisa_code") or "").strip()
    if kisa:
        return f"kisa:{kisa}"
    cwe = raw.get("cwe_id") or next(iter(raw.get("cwe") or []), None)
    if cwe:
        return f"cwe:{cwe}"
    owasp = str(raw.get("owasp_id") or raw.get("owasp") or "").strip()
    if owasp:
        return f"owasp:{owasp}"
    payload = str(raw.get("payload_name") or "").strip()
    if payload:
        return f"payload:{payload}"
    return f"vector:{raw.get('attack_vector') or 'unknown'}"


def _select_findings(raw_findings: list[Any], limit: int = MAX_CAPTURE) -> list[tuple[int, dict[str, Any]]]:
    """
    Rank-filter candidates, then diversify by vulnerability type: round-robin
    across types (each type's own candidates ordered by rank) so the top
    `limit` picks span as many distinct types as possible, instead of one
    type filling the whole quota just because it sorts first.
    """
    by_type: dict[str, list[tuple[int, int, dict[str, Any]]]] = {}
    for index, item in enumerate(raw_findings):
        if not isinstance(item, dict):
            continue
        rank = _severity_rank(item)
        if rank <= 0:
            continue
        by_type.setdefault(_vuln_type_key(item), []).append((rank, index, item))

    for group in by_type.values():
        group.sort(key=lambda row: (-row[0], row[1]))

    # Visit types best-rank-first so the strongest findings still lead overall.
    type_order = sorted(by_type, key=lambda k: (-by_type[k][0][0], by_type[k][0][1]))

    picked: list[tuple[int, dict[str, Any]]] = []
    cursors = dict.fromkeys(type_order, 0)
    while len(picked) < limit:
        progressed = False
        for key in type_order:
            if len(picked) >= limit:
                break
            cursor = cursors[key]
            group = by_type[key]
            if cursor >= len(group):
                continue
            _rank, index, item = group[cursor]
            picked.append((index, item))
            cursors[key] = cursor + 1
            progressed = True
        if not progressed:
            break

    return picked


def _status_line(raw: dict[str, Any]) -> str:
    cls = raw.get("classification") or {}
    parts = [
        f"status={raw.get('status_code', '-')}",
        f"final={cls.get('final_status', '-')}",
        f"confidence={cls.get('confidence', '-')}",
        f"bucket={raw.get('review_bucket', '-')}",
    ]
    elapsed = raw.get("elapsed_sec")
    if elapsed is not None:
        parts.append(f"time={elapsed}s")
    return " | ".join(parts)


def _request_text(raw: dict[str, Any]) -> str:
    method = str(raw.get("method") or raw.get("http_method") or "GET").upper()
    url = str(raw.get("normalized_url") or raw.get("url") or "")
    payload = raw.get("payload") or raw.get("payload_value") or raw.get("injected_value") or ""
    lines = [f"{method} {url} HTTP/1.1"]
    role = raw.get("role")
    if role:
        lines.append(f"X-ARGUS-Role: {role}")
    vector = raw.get("attack_vector")
    if vector:
        lines.append(f"X-ARGUS-Attack-Vector: {vector}")
    payload_name = raw.get("payload_name")
    if payload_name:
        lines.append(f"X-ARGUS-Payload: {payload_name}")
    if payload:
        lines.extend(["", str(payload)])
    return "\n".join(lines)


def _response_text(raw: dict[str, Any]) -> str:
    analysis = raw.get("response_analysis") or {}
    snippet = raw.get("response_text_snippet") or raw.get("body_snippet") or ""
    reason = raw.get("evidence_reason") or ""
    lines = [f"HTTP {raw.get('status_code', '-')}"]
    if analysis:
        for key in ("exception_type", "error_family", "matched_pattern", "server_signal"):
            if analysis.get(key):
                lines.append(f"{key}: {analysis.get(key)}")
    if reason:
        lines.extend(["", "Evidence reason:", str(reason)])
    if snippet:
        lines.extend(["", "Response snippet:", str(snippet)])
    return "\n".join(lines)


def _render_html(raw: dict[str, Any], finding_id: str) -> str:
    url = str(raw.get("normalized_url") or raw.get("url") or "")
    parsed = urlsplit(url)
    display_url = url.replace("host.docker.internal", "localhost")
    title = f"1-6 Input Validation Evidence - {raw.get('payload_name') or raw.get('attack_vector') or finding_id}"
    meta = {
        "source": raw.get("source"),
        "role": raw.get("role"),
        "kisa_code": raw.get("kisa_code"),
        "cwe_id": raw.get("cwe_id") or raw.get("cwe"),
        "owasp_id": raw.get("owasp_id") or raw.get("owasp"),
    }
    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<style>
* {{ box-sizing: border-box; }}
html, body {{ width: 1280px; height: 720px; margin: 0; overflow: hidden; }}
body {{ background: #101418; color: #e7edf3; font-family: Arial, 'Noto Sans KR', sans-serif; }}
.chrome {{ height: 72px; padding: 10px 18px; background: #eef1f4; color: #20242a; }}
.tab {{ font-size: 13px; margin-bottom: 7px; color: #4c545d; }}
.url {{ height: 32px; border: 1px solid #c6ccd4; border-radius: 17px; background: white; padding: 7px 15px; font: 13px ui-monospace, monospace; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }}
.hero {{ height: 178px; padding: 20px 26px; background: linear-gradient(135deg, #26384e, #182333); }}
.badge {{ display: inline-block; margin-right: 7px; padding: 5px 9px; border-radius: 5px; background: #344d69; font-size: 12px; font-weight: 700; }}
h1 {{ margin: 18px 0 8px; font-size: 24px; }}
.summary {{ color: #bfd0df; font-size: 14px; }}
.meta {{ margin-top: 13px; color: #8fa7be; font: 11px ui-monospace, monospace; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }}
.bar {{ height: 44px; padding: 12px 18px; border-top: 3px solid #ec7c32; background: #202328; font-size: 14px; font-weight: 700; }}
.panels {{ display: grid; grid-template-columns: 1fr 1fr; height: 426px; }}
.panel {{ min-width: 0; border-right: 1px solid #394049; background: #121417; }}
.panel-title {{ height: 38px; padding: 11px 14px; color: #7bd88f; background: #25292e; font-size: 13px; font-weight: 700; }}
pre {{ height: 388px; margin: 0; padding: 14px; overflow: hidden; white-space: pre-wrap; overflow-wrap: anywhere; color: #d5dbe2; font: 11px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; }}
</style>
</head>
<body>
  <section class="chrome">
    <div class="tab">ARGUS Evidence | { _esc(finding_id) } | { _esc(parsed.netloc or '-') }</div>
    <div class="url">{ _esc(display_url) }</div>
  </section>
  <section class="hero">
    <span class="badge">1-6</span><span class="badge">INPUT VALIDATION</span><span class="badge">{ _esc(str(raw.get('attack_vector') or '-').upper()) }</span>
    <h1>{ _esc(title) }</h1>
    <div class="summary">{ _esc(_status_line(raw)) }</div>
    <div class="meta">{ _esc(json.dumps(meta, ensure_ascii=False, sort_keys=True)) }</div>
  </section>
  <div class="bar">Request / Response Evidence Board</div>
  <section class="panels">
    <div class="panel"><div class="panel-title">Attack Request</div><pre>{ _esc(_request_text(raw)) }</pre></div>
    <div class="panel"><div class="panel-title">Observed Response</div><pre>{ _esc(_response_text(raw)) }</pre></div>
  </section>
</body>
</html>"""


def _artifact_entry(kind: str, path: Path, run_dir: Path) -> dict[str, str]:
    try:
        rel = path.resolve().relative_to(run_dir.resolve()).as_posix()
    except (OSError, ValueError):
        rel = str(path)
    return {"kind": kind, "path": str(path), "rel_path": rel}


async def _capture_png(html_path: Path, png_path: Path) -> None:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError("Playwright is required for 1-6 evidence screenshot capture") from exc

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page(viewport=VIEWPORT, locale="ko-KR")
        await page.goto(html_path.resolve().as_uri(), wait_until="load", timeout=15_000)
        await page.screenshot(path=str(png_path), full_page=False)
        await browser.close()


def _existing_steps(raw: dict[str, Any]) -> list[dict[str, Any]]:
    steps = raw.get("reproduction_flow")
    return steps if isinstance(steps, list) else []


async def run_capture(run_dir: Path | str, no_capture: bool = False) -> dict[str, Any]:
    run_dir = Path(run_dir)
    raw_path = run_dir / "raw_findings.json"
    raw_findings = _load_json(raw_path, [])
    if not isinstance(raw_findings, list):
        raw_findings = []

    selected = _select_findings(raw_findings)
    plan: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    evidence_root = run_dir / "evidence_screenshots"

    for index, raw in selected:
        fid = _finding_id(raw, index)
        case_dir = evidence_root / fid
        html_path = case_dir / "evidence.html"
        png_path = case_dir / "evidence.png"
        existing_steps = _existing_steps(raw)
        plan_row = {
            "finding_id": fid,
            "raw_index": index,
            "url": raw.get("normalized_url") or raw.get("url"),
            "payload_name": raw.get("payload_name"),
            "attack_vector": raw.get("attack_vector"),
            "status_code": raw.get("status_code"),
            "has_existing_steps": bool(existing_steps),
        }
        plan.append(plan_row)

        if no_capture:
            results.append({**plan_row, "ok": True, "captured": False, "reason": "plan_only"})
            continue

        try:
            case_dir.mkdir(parents=True, exist_ok=True)
            html_path.write_text(_render_html(raw, fid), encoding="utf-8")
            await _capture_png(html_path, png_path)
            steps = [
                {
                    "step": 1,
                    "label": "1-6 evidence board",
                    "path": str(png_path),
                    "rel_path": png_path.resolve().relative_to(run_dir.resolve()).as_posix(),
                    "highlight": "Captured request/response evidence for the selected W16 finding.",
                }
            ]
            if not existing_steps:
                raw["reproduction_flow"] = steps
                raw["screenshot_path"] = str(png_path)
                raw["overlay_applied"] = False
            raw["external_evidence_artifacts"] = [
                _artifact_entry("html", html_path, run_dir),
                _artifact_entry("screenshot", png_path, run_dir),
            ]
            results.append({
                **plan_row,
                "ok": True,
                "captured": True,
                "artifacts": raw["external_evidence_artifacts"],
            })
        except Exception as exc:
            results.append({**plan_row, "ok": False, "captured": False, "error": str(exc)})

    if not no_capture and selected:
        _write_json(raw_path, raw_findings)

    summary = {
        "section_id": "1-6",
        "run_dir": str(run_dir),
        "selected": len(selected),
        "succeeded": sum(1 for row in results if row.get("ok")),
        "failed": sum(1 for row in results if not row.get("ok")),
        "plan_only": bool(no_capture),
        "viewport": VIEWPORT,
        "results": results,
    }
    _write_json(run_dir / "screenshot_plan.json", plan)
    _write_json(run_dir / "screenshot_manifest.json", summary)
    return {"status": "ok" if summary["failed"] == 0 else "partial", "stats": summary, **summary}
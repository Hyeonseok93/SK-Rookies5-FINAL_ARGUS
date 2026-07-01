"""HTML evidence panel for Playwright screenshots (API-only findings)."""

from __future__ import annotations

import html
import json
from typing import Any


def _esc(text: Any) -> str:
    return html.escape(str(text) if text is not None else "")


def render_evidence_panel(
    *,
    title: str,
    section_id: str,
    finding_id: str,
    step_label: str,
    request: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
    expect: dict[str, Any] | None = None,
    note: str = "",
    compare: dict[str, Any] | None = None,
) -> str:
    req = request or {}
    resp = response or {}
    exp = expect or {}
    body = req.get("body") or ""
    if body and isinstance(body, str):
        try:
            body = json.dumps(json.loads(body), ensure_ascii=False, indent=2)
        except (json.JSONDecodeError, TypeError):
            pass

    resp_preview = resp.get("body_preview") or resp.get("extracted_text") or ""
    if not resp_preview and resp.get("sha256"):
        resp_preview = f"(binary response, sha256={resp.get('sha256')})"

    headers_json = json.dumps(req.get("headers") or {}, ensure_ascii=False, indent=2)
    expect_json = json.dumps(exp, ensure_ascii=False, indent=2)
    note_html = f'<div class="card"><h2>Note</h2><pre>{_esc(note)}</pre></div>' if note else ""
    compare_html = ""
    if compare:
        compare_html = f"""
        <section class="card">
          <h2>Compare</h2>
          <div class="grid">
            <div><h3>{_esc(compare.get("left_label", "Left"))}</h3>
              <pre>{_esc(compare.get("left_summary", ""))}</pre></div>
            <div><h3>{_esc(compare.get("right_label", "Right"))}</h3>
              <pre>{_esc(compare.get("right_summary", ""))}</pre></div>
          </div>
        </section>
        """

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <title>{_esc(title)}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{
      font-family: "Segoe UI", system-ui, sans-serif;
      margin: 0; padding: 24px;
      background: #0f1419; color: #e7ecf3;
      line-height: 1.45;
    }}
    h1 {{ margin: 0 0 8px; font-size: 1.35rem; color: #7dd3fc; }}
    h2 {{ margin: 0 0 12px; font-size: 1rem; color: #a5b4fc; }}
    h3 {{ margin: 0 0 8px; font-size: 0.85rem; color: #94a3b8; }}
    .meta {{ color: #94a3b8; font-size: 0.85rem; margin-bottom: 20px; }}
    .card {{
      background: #1a2332; border: 1px solid #2d3a4f;
      border-radius: 10px; padding: 16px; margin-bottom: 16px;
    }}
    pre {{
      margin: 0; padding: 12px; border-radius: 8px;
      background: #0b1020; border: 1px solid #243044;
      overflow-x: auto; white-space: pre-wrap; word-break: break-word;
      font-size: 0.8rem;
    }}
    .badge {{
      display: inline-block; padding: 2px 8px; border-radius: 6px;
      background: #312e81; color: #c4b5fd; font-size: 0.75rem;
    }}
    .ok {{ color: #86efac; }}
    .warn {{ color: #fcd34d; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
    .leak {{ color: #fca5a5; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>{_esc(title)}</h1>
  <div class="meta">
    <span class="badge">{_esc(section_id)}</span>
    finding <code>{_esc(finding_id)}</code> · step <strong>{_esc(step_label)}</strong>
  </div>
  {note_html}
  <section class="card">
    <h2>Request</h2>
    <pre>{_esc(req.get("method", ""))} {_esc(req.get("url", ""))}

Headers:
{headers_json}

Body:
{body}</pre>
  </section>
  <section class="card">
    <h2>Response</h2>
    <pre>HTTP {_esc(resp.get("status", ""))}
Content-Type: {_esc(resp.get("content_type", ""))}
SHA256: {_esc(resp.get("sha256", ""))}

{_esc(resp_preview)}</pre>
  </section>
  <section class="card">
    <h2>Expected (replay verify)</h2>
    <pre class="ok">{expect_json}</pre>
  </section>
  {compare_html}
</body>
</html>
"""

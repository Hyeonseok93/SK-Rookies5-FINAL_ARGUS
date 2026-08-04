"""Playwright screenshot engine for 2-1 malicious-upload evidence boards."""

from __future__ import annotations

import os
import re
import socket
import subprocess
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from credentials import load_replay_credentials
from models import CaptureArtifact, EvidenceCase
from renderer import render_burp_only, render_evidence_overlay

CAPTURES = (
    ("baseline_site", "01_baseline_site.png"),
    ("baseline_evidence", "02_baseline_evidence.png"),
    ("attack_burp", "03_attack_burp.png"),
    ("attack_site", "04_attack_site.png"),
    ("attack_evidence", "05_attack_evidence.png"),
)


def _authenticate_browser_context(context, case: EvidenceCase) -> None:
    login = dict(case.metadata.get("login") or {})
    if not login.get("ok"):
        case.metadata["browser_login"] = {"ok": False, "reason": login.get("reason") or "No session"}
        return
    email = str(login.get("email") or "")
    env = (os.environ.get("ARGUS_DATA_DIR") or "").strip()
    credentials = load_replay_credentials(
        Path(env) if env else Path(__file__).resolve().parents[3] / "data"
    )
    credential = next((item for item in credentials if item.identifier == email), None)
    if credential is None:
        case.metadata["browser_login"] = {"ok": False, "reason": "Replay account unavailable"}
        return
    login_url = str(case.metadata.get("runtime_login_url") or case.metadata.get("login_url") or "")
    if not login_url:
        case.metadata["browser_login"] = {"ok": False, "reason": "No login URL available"}
        return
    response = context.request.post(
        login_url,
        data={
            str(case.metadata.get("id_field") or "email"): credential.identifier,
            str(case.metadata.get("password_field") or "password"): credential.password,
        },
        timeout=15_000,
        fail_on_status_code=False,
    )
    frontend_url = str(case.metadata.get("ui_url") or "")
    if response.ok and frontend_url:
        frontend_origin = urlsplit(frontend_url)
        copied_cookies = []
        for cookie in context.cookies():
            copied_cookies.append(
                {
                    "name": cookie["name"],
                    "value": cookie["value"],
                    "url": f"{frontend_origin.scheme}://{frontend_origin.netloc}/",
                    "httpOnly": bool(cookie.get("httpOnly")),
                    "secure": bool(cookie.get("secure")),
                    "sameSite": cookie.get("sameSite") or "Lax",
                }
            )
        if copied_cookies:
            context.add_cookies(copied_cookies)
    case.metadata["browser_login"] = {
        "ok": response.ok,
        "status": response.status,
        "email": email,
    }


def _inject_overlay(page, css: str, markup: str) -> None:
    last_error = None
    for _ in range(3):
        try:
            page.wait_for_load_state("domcontentloaded", timeout=5_000)
            page.evaluate(
                """({css, markup}) => {
                  document.getElementById('argus-evidence-root')?.remove();
                  const root = document.createElement('div');
                  root.id = 'argus-evidence-root';
                  const style = document.createElement('style');
                  style.textContent = css;
                  root.appendChild(style);
                  const body = document.createElement('div');
                  body.innerHTML = markup;
                  while (body.firstChild) root.appendChild(body.firstChild);
                  document.documentElement.appendChild(root);
                }""",
                {"css": css, "markup": markup},
            )
            return
        except Exception as exc:
            last_error = exc
            page.wait_for_timeout(500)
    raise RuntimeError(f"Overlay injection failed after SPA navigation: {last_error}")


def _take_window_shot(page, path: Path) -> None:
    page.bring_to_front()
    page.wait_for_timeout(250)
    if os.environ.get("DISPLAY"):
        subprocess.run(["scrot", "--overwrite", str(path)], check=True)
    else:
        page.screenshot(path=str(path), full_page=False)


_VERSION_SEG_RE = re.compile(r"^v\d+$")


def _resource_segments(path: str) -> list[str]:
    """Meaningful resource segments of an API/route path: drops `api`, version
    (`v1`), path params (`{id}`) and numeric ids so the upload endpoint still
    maps to the page that lists/renders the same resource (e.g. `posts`)."""
    segments: list[str] = []
    for raw in path.strip("/").split("/"):
        seg = raw.split("?")[0].lower()
        if not seg or seg == "api" or _VERSION_SEG_RE.match(seg):
            continue
        if seg.startswith("{") or seg.isdigit():
            continue
        segments.append(seg)
    return segments


def _relatedness(target_segments: list[str], other_path: str) -> int:
    other = _resource_segments(other_path)
    shared = 0
    for a, b in zip(target_segments, other):
        if a != b:
            break
        shared += 1
    return shared


def _discover_related_page(context, case: EvidenceCase) -> str:
    frontend_base = str(case.metadata.get("ui_url") or "")
    routes = list(case.metadata.get("frontend_routes") or ["/"])
    target_path = urlsplit(case.baseline.url).path.rstrip("/")
    target_segments = _resource_segments(target_path)
    probe = context.new_page()
    best_candidate = frontend_base
    best_score = 0
    try:
        for route_path in routes:
            requested_paths: set[str] = set()

            def remember_request(request) -> None:
                requested_paths.add(urlsplit(request.url).path.rstrip("/"))

            probe.on("request", remember_request)
            candidate = urljoin(frontend_base.rstrip("/") + "/", route_path.lstrip("/"))
            try:
                probe.goto(candidate, wait_until="domcontentloaded", timeout=8_000)
                probe.wait_for_timeout(700)
            except Exception:
                probe.remove_listener("request", remember_request)
                continue
            probe.remove_listener("request", remember_request)
            if target_path in requested_paths:
                return candidate
            score = max(
                (_relatedness(target_segments, rp) for rp in requested_paths),
                default=0,
            )
            score = max(score, _relatedness(target_segments, route_path))
            if score > best_score:
                best_score = score
                best_candidate = candidate
    finally:
        probe.close()
    return best_candidate if best_score > 0 else frontend_base


_MARKER_RE = re.compile(r"ARGUS-2-1-UPLOAD-PROBE|argus-(?:probe|shell)")
_FIELD_VALUE_RE = re.compile(
    r'"(?:title|name|filename|fileName|imageUrl|fileUrl|url|thumbnail)"'
    r'\s*:\s*"((?:[^"\\]|\\.){2,80})"'
)


def _response_anchors(case: EvidenceCase) -> list[str]:
    """Distinctive text values from the upload response, used to scroll the
    related page to where the uploaded file/name is actually rendered."""
    body = str(getattr(case.attack, "response_body", "") or "")
    anchors: list[str] = []

    def add(token: str) -> None:
        token = (token or "").strip()
        if token and token not in anchors:
            anchors.append(token)

    for marker in _MARKER_RE.findall(body):
        add(marker)
    for value in _FIELD_VALUE_RE.findall(body):
        if "://" in value or value.count("/") >= 2:
            continue
        add(value)
    return anchors[:25]


def _focus_page_content(page, anchors: list[str] | None = None) -> None:
    page.evaluate(
        """({anchors}) => {
          const headerH =
            (document.querySelector('header')?.getBoundingClientRect().height) || 80;
          const scrollToEl = (el, pad) => {
            const top = el.getBoundingClientRect().top + window.scrollY;
            window.scrollTo({top: Math.max(0, top - headerH - pad), behavior: 'instant'});
          };

          for (const a of anchors || []) {
            if (!a) continue;
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            let node;
            while ((node = walker.nextNode())) {
              if (node.nodeValue && node.nodeValue.indexOf(a) !== -1 && node.parentElement) {
                const r = node.parentElement.getBoundingClientRect();
                if (r.width > 0 && r.height > 0) {
                  scrollToEl(node.parentElement, 40);
                  return;
                }
              }
            }
          }

          const root = document.querySelector('main') || document.body;
          const listScore = (el) => {
            const kids = Array.from(el.children).filter((c) => {
              const r = c.getBoundingClientRect();
              return r.width > 80 && r.height > 60;
            });
            if (kids.length < 3) return 0;
            const hs = kids.map((k) => k.getBoundingClientRect().height).sort((a, b) => a - b);
            const med = hs[Math.floor(hs.length / 2)] || 1;
            const similar = hs.filter((h) => Math.abs(h - med) <= med * 0.6).length;
            return similar >= 3 ? similar : 0;
          };
          let best = null;
          let bestScore = 0;
          root.querySelectorAll('*').forEach((el) => {
            const s = listScore(el);
            if (s > bestScore) { bestScore = s; best = el; }
          });
          if (best) { scrollToEl(best, 12); return; }

          const first = root.children[0] && root.children[0].getBoundingClientRect();
          if (first && first.height > window.innerHeight * 0.6) {
            window.scrollTo({top: Math.max(0, first.height - headerH), behavior: 'instant'});
          }
        }""",
        {"anchors": anchors or []},
    )
    page.wait_for_timeout(400)


def capture_case(case: EvidenceCase, output_dir: Path) -> list[CaptureArtifact]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Playwright is required for evidence capture. "
            "Install dependencies and run `playwright install chromium`."
        ) from exc

    output_dir.mkdir(parents=True, exist_ok=True)
    for previous in output_dir.glob("*.png"):
        previous.unlink()
    artifacts: list[CaptureArtifact] = []

    with sync_playwright() as playwright:
        host_gateway = socket.gethostbyname("host.docker.internal")
        browser = playwright.chromium.launch(
            headless=not bool(os.environ.get("DISPLAY")),
            args=[
                f"--host-resolver-rules=MAP localhost {host_gateway}",
                "--window-position=0,0",
                "--window-size=1280,720",
                "--force-device-scale-factor=1",
            ],
        )
        context = browser.new_context(no_viewport=True, locale="ko-KR")
        _authenticate_browser_context(context, case)
        ui_url = _discover_related_page(context, case)
        case.metadata["ui_url"] = ui_url
        case.metadata["ui_display_url"] = ui_url.replace("host.docker.internal", "localhost")
        case.metadata["ui_route_source"] = "network-discovery"
        content_anchors = _response_anchors(case)

        for kind, filename in CAPTURES:
            page = context.new_page()
            # attack_site reloads after the live replay already ran the malicious
            # upload, so a newly-listed item (if the server accepted it) shows up.
            page.goto(ui_url, wait_until="domcontentloaded", timeout=20_000)
            page.wait_for_timeout(1_200)
            try:
                page.wait_for_load_state("networkidle", timeout=5_000)
            except Exception:
                pass
            _focus_page_content(page, content_anchors if kind in {"attack_site", "attack_evidence"} else None)
            if kind == "baseline_evidence":
                css, markup = render_evidence_overlay(case, "baseline")
                _inject_overlay(page, css, markup)
            elif kind == "attack_evidence":
                css, markup = render_evidence_overlay(case, "attack")
                _inject_overlay(page, css, markup)
            elif kind == "attack_burp":
                css, markup = render_burp_only(case)
                _inject_overlay(page, css, markup)
            page.emulate_media(reduced_motion="reduce")
            try:
                page.evaluate("document.fonts.ready")
            except Exception:
                page.wait_for_timeout(500)
            path = output_dir / filename
            _take_window_shot(page, path)
            artifacts.append(CaptureArtifact(kind=kind, path=str(path)))
            page.close()

        context.close()
        browser.close()

    return artifacts

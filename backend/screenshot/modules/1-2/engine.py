"""Playwright screenshot engine."""

from __future__ import annotations

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
        case.metadata["browser_login"] = {"ok": False, "reason": "Replay login unavailable"}
        return
    account_id = str(login.get("account_id") or "")
    credentials = load_replay_credentials(Path(__file__).resolve().parents[3] / "data")
    credential = next((item for item in credentials if item.account_id == account_id), None)
    if credential is None:
        case.metadata["browser_login"] = {"ok": False, "reason": "Replay account unavailable"}
        return
    response = context.request.post(
        str(login.get("runtime_login_url") or login.get("login_url") or ""),
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
        "account_id": account_id,
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


def _route_attack_api(page, case: EvidenceCase) -> None:
    target_path = urlsplit(case.baseline.url).path.rstrip("/")

    def handler(route) -> None:
        request = route.request
        if (
            request.method.upper() == case.baseline.method.upper()
            and urlsplit(request.url).path.rstrip("/") == target_path
        ):
            route.continue_(url=case.attack.url)
        else:
            route.continue_()

    page.route("**/*", handler)


_VERSION_SEG_RE = re.compile(r"^v\d+$")


def _resource_segments(path: str) -> list[str]:
    """Meaningful resource segments of an API/route path: drops `api`, version
    (`v1`), path params (`{id}`) and numeric ids so POST/nested paths still map
    to the page that touches the same resource (e.g. `posts`, `feed`)."""
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
    """How many leading resource segments a request/route path shares with the
    injection target — method-agnostic, so a POST target still matches a page
    that only GETs the same resource on load."""
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
            # Exact hit (page fires the target path on load) — best possible.
            if target_path in requested_paths:
                return candidate
            # Otherwise rank by shared resource segments, considering both the
            # requests the page fires AND the route path itself. This lets a
            # POST/nested target land on /feed, /posts/... instead of main.
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


_ARGUS_MARKER_RE = re.compile(r"ARGUS_[A-Za-z0-9_]+|argus-probe")
# Distinctive data-field values from a JSON response, extracted from the raw
# text so it still works when the stored body is truncated.
_FIELD_VALUE_RE = re.compile(
    r'"(?:title|name|authorName|nickname|username|email|content|message|description)"'
    r'\s*:\s*"((?:[^"\\]|\\.){2,80})"'
)


def _response_anchors(case: EvidenceCase) -> list[str]:
    """Distinctive text values from the target API's own baseline response, used
    to scroll the page to where that data is actually rendered — no layout
    assumptions. ARGUS probe/injection markers first (unique & reflected), then
    other short data values (e.g. record titles/author names)."""
    body = str(getattr(case.baseline, "response_body", "") or "")
    anchors: list[str] = []

    def add(token: str) -> None:
        token = (token or "").strip()
        if token and token not in anchors:
            anchors.append(token)

    for marker in _ARGUS_MARKER_RE.findall(body):
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

          // 1) Anchor directly to where the target API's data is rendered.
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

          // 2) Fallback: repeated-card grid/list (structural heuristic).
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

          // 3) Fallback: skip a tall hero that fills the first screen.
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
            headless=False,
            args=[
                f"--host-resolver-rules=MAP localhost {host_gateway}",
                "--window-position=0,0",
                "--window-size=1280,720",
                "--force-device-scale-factor=1",
            ],
        )
        context = browser.new_context(
            no_viewport=True,
            locale="ko-KR",
        )
        _authenticate_browser_context(context, case)
        ui_url = _discover_related_page(context, case)
        case.metadata["ui_url"] = ui_url
        case.metadata["ui_display_url"] = ui_url.replace("host.docker.internal", "localhost")
        case.metadata["ui_route_source"] = "network-discovery"
        content_anchors = _response_anchors(case)
        for kind, filename in CAPTURES:
            page = context.new_page()
            if kind in {"attack_site", "attack_evidence"}:
                _route_attack_api(page, case)
            page.goto(ui_url, wait_until="domcontentloaded", timeout=20_000)
            page.wait_for_timeout(1_200)
            try:
                page.wait_for_load_state("networkidle", timeout=5_000)
            except Exception:
                pass
            _focus_page_content(page, content_anchors)
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
            page.bring_to_front()
            page.wait_for_timeout(250)
            subprocess.run(["scrot", "--overwrite", str(path)], check=True)
            artifacts.append(CaptureArtifact(kind=kind, path=str(path)))
            page.close()

        context.close()
        browser.close()

    return artifacts

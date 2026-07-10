"""Playwright screenshot engine."""

from __future__ import annotations

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


def _discover_related_page(context, case: EvidenceCase) -> str:
    frontend_base = str(case.metadata.get("ui_url") or "")
    routes = list(case.metadata.get("frontend_routes") or ["/"])
    target_path = urlsplit(case.baseline.url).path.rstrip("/")
    probe = context.new_page()
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
    finally:
        probe.close()
    return frontend_base


def _focus_page_content(page) -> None:
    page.evaluate(
        """() => {
          const main = document.querySelector('main');
          if (!main) return;
          const children = Array.from(main.children)
            .filter((element) => element.getBoundingClientRect().height > 20);
          const target = children.length > 1 ? children[1] : main;
          const top = target.getBoundingClientRect().top + window.scrollY;
          if (top > 120) {
            window.scrollTo({top: Math.max(0, top - 90), behavior: 'instant'});
          }
        }"""
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
            _focus_page_content(page)
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

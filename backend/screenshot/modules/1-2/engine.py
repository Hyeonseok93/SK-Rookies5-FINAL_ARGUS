"""Playwright screenshot engine."""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path

from models import CaptureArtifact, EvidenceCase
from renderer import render_burp_only, render_evidence_overlay

CAPTURES = (
    ("baseline_site", "01_baseline_site.png"),
    ("baseline_evidence", "02_baseline_evidence.png"),
    ("attack_burp", "03_attack_burp.png"),
    ("attack_site", "04_attack_site.png"),
    ("attack_evidence", "05_attack_evidence.png"),
)


def _inject_overlay(page, css: str, markup: str) -> None:
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


def _route_attack_api(page, case: EvidenceCase) -> None:
    if "/api/v1/posts" not in case.baseline.url:
        return

    def handler(route) -> None:
        request = route.request
        if request.method.upper() == "GET" and "/api/v1/posts" in request.url:
            route.continue_(url=case.attack.url)
        else:
            route.continue_()

    page.route("**/api/v1/posts**", handler)


def _focus_related_page(page, ui_url: str) -> None:
    if "/feed" in ui_url:
        feed_anchor = page.locator("button", has_text="나의 여행 이야기 기록하기").first
        if feed_anchor.count():
            feed_anchor.evaluate(
                "(element) => window.scrollTo(0, "
                "element.getBoundingClientRect().top + window.scrollY - 90)"
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
        for kind, filename in CAPTURES:
            page = context.new_page()
            ui_url = str(case.metadata.get("ui_url") or "http://host.docker.internal:5173/")
            if kind in {"attack_site", "attack_evidence"}:
                _route_attack_api(page, case)
            page.goto(ui_url, wait_until="domcontentloaded", timeout=20_000)
            page.wait_for_timeout(1_200)
            _focus_related_page(page, ui_url)
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
            page.evaluate("document.fonts.ready")
            path = output_dir / filename
            page.bring_to_front()
            page.wait_for_timeout(250)
            subprocess.run(["scrot", "--overwrite", str(path)], check=True)
            artifacts.append(CaptureArtifact(kind=kind, path=str(path)))
            page.close()

        context.close()
        browser.close()

    return artifacts

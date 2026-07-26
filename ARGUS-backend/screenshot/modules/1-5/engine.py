"""Headed Chromium full-window capture for 1-5."""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path

from models import CaptureArtifact, RedirectCase
from renderer import evidence_overlay


def _inject(page, css: str, markup: str) -> None:
    page.evaluate(
        """({css, markup}) => {
          document.getElementById('g15-root')?.remove();
          const root = document.createElement('div');
          root.id = 'g15-root';
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


def _shot(page, path: Path) -> None:
    page.bring_to_front()
    page.wait_for_timeout(300)
    subprocess.run(["scrot", "--overwrite", str(path)], check=True)


def _browser_context(playwright):
    gateway = socket.gethostbyname("host.docker.internal")
    browser = playwright.chromium.launch(
        headless=False,
        args=[
            f"--host-resolver-rules=MAP localhost {gateway}",
            "--window-position=0,0",
            "--window-size=1280,720",
            "--force-device-scale-factor=1",
        ],
    )
    return browser, browser.new_context(no_viewport=True, locale="ko-KR", ignore_https_errors=True)


def capture_case(case: RedirectCase, output_dir: Path) -> list[CaptureArtifact]:
    from playwright.sync_api import sync_playwright

    output_dir.mkdir(parents=True, exist_ok=True)
    for previous in output_dir.glob("*.png"):
        previous.unlink()
    artifacts: list[CaptureArtifact] = []

    with sync_playwright() as playwright:
        browser, context = _browser_context(playwright)
        for kind, filename in (
            ("site", "01_site.png"),
            ("evidence", "02_evidence.png"),
            ("combined", "03_combined.png"),
        ):
            page = context.new_page()
            try:
                page.goto(case.target_url, wait_until="domcontentloaded", timeout=20_000)
            except Exception:
                pass
            page.wait_for_timeout(900)
            if kind != "site":
                css, markup = evidence_overlay(case, full=kind == "combined")
                _inject(page, css, markup)
            path = output_dir / filename
            _shot(page, path)
            artifacts.append(CaptureArtifact(kind=kind, path=str(path)))
            page.close()
        context.close()
        browser.close()

    return artifacts

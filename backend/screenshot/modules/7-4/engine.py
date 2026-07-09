"""Headed Chromium full-window capture for 7-4."""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path

from models import ScaCase, WebConfigCase
from renderer import sca_overlay, web_overlay


def _inject(page, css: str, markup: str) -> None:
    page.evaluate(
        """({css, markup}) => {
          document.getElementById('g74-root')?.remove();
          const root = document.createElement('div');
          root.id = 'g74-root';
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


def capture_web(case: WebConfigCase, output_dir: Path) -> list[dict[str, str]]:
    from playwright.sync_api import sync_playwright

    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = []
    with sync_playwright() as playwright:
        browser, context = _browser_context(playwright)
        for kind, filename in (
            ("site", "01_site.png"),
            ("headers", "02_headers.png"),
            ("combined", "03_combined.png"),
        ):
            page = context.new_page()
            page.goto(case.display_url, wait_until="domcontentloaded", timeout=20_000)
            page.wait_for_timeout(900)
            if kind != "site":
                css, markup = web_overlay(case, full=kind == "headers")
                _inject(page, css, markup)
            path = output_dir / filename
            _shot(page, path)
            artifacts.append({"kind": kind, "path": str(path)})
            page.close()
        context.close()
        browser.close()
    return artifacts


def capture_sca(case: ScaCase, output_dir: Path) -> list[dict[str, str]]:
    from playwright.sync_api import sync_playwright

    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = []
    with sync_playwright() as playwright:
        browser, context = _browser_context(playwright)
        for kind, filename in (
            ("dependency", "01_dependency.png"),
            ("advisory", "02_advisory.png"),
            ("combined", "03_combined.png"),
        ):
            page = context.new_page()
            target = (
                "http://localhost:8001/api/diagnosis/modules/7-4/report"
                if kind == "dependency"
                else case.advisory_url
            )
            try:
                page.goto(target, wait_until="domcontentloaded", timeout=25_000)
            except Exception:
                pass
            page.wait_for_timeout(1_000)
            if kind != "advisory":
                css, markup = sca_overlay(case, full=kind == "dependency")
                _inject(page, css, markup)
            path = output_dir / filename
            _shot(page, path)
            artifacts.append({"kind": kind, "path": str(path)})
            page.close()
        context.close()
        browser.close()
    return artifacts


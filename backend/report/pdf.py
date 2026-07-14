"""Render a self-contained HTML report document to PDF bytes.

Shared by every ``report/modules/{id}/`` module — none of them need their own
PDF plumbing, they just hand this a finished HTML string. Uses Playwright
(already a project dependency for screenshot capture) instead of adding a
separate PDF-rendering library.
"""

from __future__ import annotations


def html_to_pdf(html_doc: str) -> bytes:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.set_content(html_doc, wait_until="load")
            return page.pdf(format="A4", print_background=True, margin={"top": "0", "bottom": "0", "left": "0", "right": "0"})
        finally:
            browser.close()

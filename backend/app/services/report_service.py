"""Dispatch downloadable evidence reports to their per-module implementation.

Each section's actual report-building logic lives in
``backend/report/modules/{section_id}/report.py`` (dynamically loaded, same
pattern used for diagnosis/screenshot modules). This service just resolves a
section_id to that module and hands back report items / rendered HTML / PDF
bytes for the router to serve.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

from app.config import BACKEND_ROOT

EVIDENCE_REPORT_SECTIONS = {"2-1"}


def _load_report_module(section_id: str):
    path = BACKEND_ROOT / "report" / "modules" / section_id / "report.py"
    if not path.is_file():
        raise ImportError(f"No report module for section {section_id}")
    mod_name = f"report_module_{section_id.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load report module for section {section_id}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def build_report_items(section_id: str, *, data_dir: Path) -> list[dict[str, Any]]:
    mod = _load_report_module(section_id)
    return mod.build_report_items(data_dir=data_dir)


def render_report_html(section_id: str, title: str, items: list[dict[str, Any]]) -> str:
    mod = _load_report_module(section_id)
    return mod.render_report_html(title, items)


def render_report_pdf(section_id: str, title: str, items: list[dict[str, Any]]) -> bytes:
    from report.pdf import html_to_pdf

    html_doc = render_report_html(section_id, title, items)
    return html_to_pdf(html_doc)

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.routers.diagnosis import (
    _dedicated_report_pdf_response,
    _load_module_report_renderer,
    _report_pdf_filename,
)


def test_report_pdf_filename_includes_section_id():
    name = _report_pdf_filename("6-1")
    assert name.startswith("argus-6-1-report-")
    assert name.endswith(".pdf")


def test_load_module_report_renderer_finds_6_1():
    renderer = _load_module_report_renderer("6-1")
    assert renderer is not None
    assert hasattr(renderer, "render_pdf")


def test_load_module_report_renderer_none_for_section_without_one():
    assert _load_module_report_renderer("1-5") is None


def test_dedicated_report_pdf_response_404s_for_section_without_renderer():
    with pytest.raises(HTTPException) as exc_info:
        _dedicated_report_pdf_response("1-5")
    assert exc_info.value.status_code == 404

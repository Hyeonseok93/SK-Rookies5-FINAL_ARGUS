"""Tests for ZAP workspace reset helpers."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.services.zap_util import reset_zap_workspace, stop_zap_scans


def test_stop_zap_scans_calls_stop_all():
    zap = MagicMock()
    stop_zap_scans(zap)
    zap.ascan.stop_all_scans.assert_called_once()
    zap.spider.stop_all_scans.assert_called_once()
    zap.ajaxSpider.stop.assert_called_once()


def test_reset_zap_workspace_clears_session():
    zap = MagicMock()
    stats = reset_zap_workspace(zap, session_name="argus-test")
    zap.core.delete_all_alerts.assert_called_once()
    zap.core.new_session.assert_called()
    zap.core.run_garbage_collection.assert_called_once()
    assert stats["session_name"] == "argus-test"
    assert stats["new_session"] is True
    assert stats["alerts_cleared"] is True


def test_parse_send_request_full_pdf_body():
    from app.services.zap_util import parse_send_request_full

    resp = {
        "responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n\r\n",
        "responseBody": "%PDF-1.4 fake",
    }
    full = parse_send_request_full(resp)
    assert full is not None
    assert full.status == 200
    assert full.headers.get("Content-Type") == "application/pdf"
    assert full.body.startswith(b"%PDF")

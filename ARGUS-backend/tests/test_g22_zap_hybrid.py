"""Tests for 2-2 unified transport traversal analysis."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

from app.services.zap_util import ZapHttpResponse

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "2-2"


def _load(name: str):
    mod_name = f"diag_g22_{name}_unified_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _sample_endpoint():
    from inventory.schema import Endpoint, InputParam

    return Endpoint(
        method="POST",
        path="/api/v1/report/integrated",
        base_url="http://localhost:5173",
        request_params=[
            InputParam(in_="body", name="template", sample="report.html"),
        ],
    )


class FakeZapTransport:
    name = "zap"

    def __init__(self) -> None:
        self.baseline_body = b"normal report body"
        self.leak_text = (
            b"root:x:0:0:root:/root:/bin/bash\n"
            b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        )

    def request(self, method, url, headers, body=None, *, follow_redirects=True):
        _ = method, url, headers, follow_redirects
        raw = (body or b"").decode("utf-8", errors="replace")
        if "../../../../etc/passwd" in raw:
            return _load("transport").ProbeResponse(
                status=200,
                body=self.leak_text,
                headers={"Content-Type": "text/plain"},
            )
        return _load("transport").ProbeResponse(
            status=200,
            body=self.baseline_body,
            headers={"Content-Type": "text/plain"},
        )


def test_zap_transport_traversal_detects_passwd_leak():
    probes = _load("probes")
    ep = _sample_endpoint()
    findings = probes.run_traversal_probes(
        [ep],
        ["../", "../../../../etc/passwd"],
        transport=FakeZapTransport(),
        engine="zap",
        auth=None,
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].evidence["analysis_mode"] == "unified"
    assert findings[0].evidence["source"] == "zap"
    assert findings[0].evidence.get("payload_leak_confirmed") is True


def test_zap_scan_supplemental_rules_exclude_traversal_rule_6():
    zap_scan = _load("zap_scan")
    enabled = {str(r[0]) for r in zap_scan.SUPPLEMENTAL_SCANNER_RULES}
    assert "6" not in enabled
    assert "0" in enabled
    assert "40035" in enabled


def test_zap_supplemental_finding_tagged_native():
    zap_scan = _load("zap_scan")
    zap = MagicMock()
    zap.core.alerts.return_value = [
        {
            "pluginId": "40035",
            "alert": "Hidden File Found",
            "url": "http://localhost:5173/.env",
            "risk": "Medium",
        }
    ]
    findings = zap_scan.collect_zap_supplemental_findings(zap, ["http://localhost:5173"])
    assert len(findings) == 1
    assert findings[0].evidence["analysis_mode"] == "native"
    assert findings[0].evidence["engine"] == "zap"

"""Tests for 7-2 directory listing detection."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "7-2"


def _load_rules():
    mod_name = "diag_g72_listing_rules_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / "listing_rules.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


APACHE_LISTING = """
<html><head><title>Index of /uploads/</title></head>
<body><h1>Index of /uploads/</h1><hr><pre>
<a href="../">Parent Directory</a>
<a href="backup.zip">backup.zip</a>
<a href="photo.jpg">photo.jpg</a>
</pre></body></html>
"""

NGINX_LISTING = """
<html>
<head><title>Index of /static/</title></head>
<body><h1>Index of /static/</h1>
<a href="../">../</a>
<a href="app.js">app.js</a>
</body></html>
"""

SPA_SHELL = "<!DOCTYPE html><html><head></head><body><div id=root></div></body></html>"


def test_detect_apache_listing():
    rules = _load_rules()
    issue = rules.classify_listing_response(APACHE_LISTING, http_status=200)
    assert issue is not None
    assert issue.severity == "medium"
    assert "apache_index" in issue.matched_patterns


def test_detect_nginx_listing():
    rules = _load_rules()
    issue = rules.classify_listing_response(NGINX_LISTING, http_status=200)
    assert issue is not None
    assert issue.listing_type == "nginx_autoindex"


def test_spa_baseline_filtered():
    rules = _load_rules()
    fp = rules._body_fingerprint(SPA_SHELL)
    issue = rules.classify_listing_response(
        SPA_SHELL,
        http_status=200,
        baseline_body=SPA_SHELL,
        baseline_fp=fp,
    )
    assert issue is None


def test_wordlist_loaded():
    mod_name = "diag_g72_targets_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / "targets.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    paths, meta = mod.load_wordlist()
    assert len(paths) >= 150
    assert meta["wordlist_total"] >= 150
    assert "/examples" in paths or "/examples/jsp" in paths
    assert "/icons" in paths
    assert "/aspnet_client" in paths


def _load_zap_scan():
    mod_name = "diag_g72_zap_scan_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / "zap_scan.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_zap_select_seed_urls_caps_evenly():
    from app.services.zap_util import select_seed_urls

    targets = [{"probe_url": f"http://host/{i}/"} for i in range(1000)]
    sampled = select_seed_urls(targets, cap=100)
    assert len(sampled) == 100
    assert sampled[0] == "http://host/0/"


def test_zap_select_seed_urls_prioritizes_httpx_hits():
    from app.services.zap_util import select_seed_urls

    targets = [{"probe_url": f"http://host/{i}/"} for i in range(1000)]
    priority = ["http://host/assets/", "http://host/999/"]
    sampled = select_seed_urls(targets, cap=10, priority_urls=priority)
    assert sampled[0] == "http://host/assets/"
    assert sampled[1] == "http://host/999/"
    assert len(sampled) == 10


def test_zap_alert_maps_to_7_2_finding():
    zap = _load_zap_scan()
    finding = zap.zap_alert_to_finding(
        {
            "pluginId": "0",
            "alert": "Directory Browsing",
            "url": "http://localhost:5173/assets/",
            "risk": "Medium",
        },
        base_url="http://localhost:5173",
    )
    assert finding is not None
    assert finding.severity == "medium"
    assert finding.evidence["rule_id"] == "7-2-directory-listing"
    assert finding.evidence["listing_type"] == "zap_directory_browsing"
    assert finding.evidence["source"] == "zap"


def test_zap_passive_10033_maps_to_7_2_finding():
    zap = _load_zap_scan()
    finding = zap.zap_alert_to_finding(
        {
            "pluginId": "10033",
            "alert": "Directory Browsing",
            "url": "http://localhost:5173/assets/",
            "risk": "Medium",
        },
        base_url="http://localhost:5173",
    )
    assert finding is not None
    assert finding.evidence["listing_type"] == "zap_passive_directory_browsing"
    assert finding.evidence["plugin_id"] == "10033"


def test_unreachable_probe_does_not_emit_finding():
    mod_name = "diag_g72_probes_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / "probes.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)

    findings, stats = mod.run_listing_probes(
        [{"probe_url": "http://127.0.0.1:1/nope", "label": "dead", "base_url": "http://127.0.0.1:1"}],
        classify_fn=lambda *a, **k: None,
        remediation_fn=lambda _t: "",
        fingerprint_fn=lambda _b: "",
        timeout=0.5,
    )
    assert stats["unreachable"] == 1
    assert findings == []

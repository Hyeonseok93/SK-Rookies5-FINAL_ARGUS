"""Tests for guideline 3-4 admin/user separation heuristics."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from inventory.schema import ApiTree, Endpoint, InventoryMeta

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "3-4"


def _load(name: str):
    mod_name = f"test_g34_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _tree(*endpoints: Endpoint) -> ApiTree:
    return ApiTree(meta=InventoryMeta(), endpoints=list(endpoints))


def test_admin_subdomain_pair_onde():
    rules = _load("separation_rules")
    assert rules.is_admin_subdomain_host("admin.onde.click")
    assert not rules.is_admin_subdomain_host("onde.click")
    pairs = rules.admin_subdomain_pairs(
        {"admin.onde.click"},
        {"onde.click", "www.onde.click"},
    )
    assert ("onde.click", "admin.onde.click") in pairs
    assert ("www.onde.click", "admin.onde.click") in pairs


def test_classify_login_entries():
    rules = _load("separation_rules")
    user = {"url": "http://localhost:8080/api/v1/auth/login", "label": "user"}
    admin = {"url": "http://localhost:8080/api/v1/auth/admin/login", "label": "admin"}
    assert rules.classify_login_entry(user) == "user"
    assert rules.classify_login_entry(admin) == "admin"


def test_same_login_url_high():
    rules = _load("separation_rules")
    login_entries = [
        {"url": "http://localhost:8080/api/v1/auth/login", "label": "user"},
        {"url": "http://localhost:8080/api/v1/auth/login", "label": "admin"},
    ]
    inv = rules.slice_inventory(None)
    findings, stats = rules.analyze_separation(login_entries=login_entries, inventory=inv)
    rule_ids = {(f.evidence or {}).get("rule_id") for f in findings}
    assert "3-4-same-login-url" in rule_ids
    assert stats["shared_login_urls"]
    high = [f for f in findings if f.severity == "high"]
    assert high


def test_login_same_host_medium():
    rules = _load("separation_rules")
    login_entries = [
        {"url": "http://localhost:8080/api/v1/auth/login", "label": "user"},
        {"url": "http://localhost:8080/api/v1/auth/admin/login", "label": "admin"},
    ]
    inv = rules.slice_inventory(None)
    findings, _ = rules.analyze_separation(login_entries=login_entries, inventory=inv)
    rule_ids = {(f.evidence or {}).get("rule_id") for f in findings}
    assert "3-4-login-same-host" in rule_ids
    assert "3-4-host-separated" not in rule_ids


def test_subdomain_separation_info_not_same_host_warn():
    rules = _load("separation_rules")
    login_entries = [
        {"url": "https://onde.click/api/v1/auth/login", "label": "user"},
        {"url": "https://admin.onde.click/api/v1/auth/admin/login", "label": "admin"},
    ]
    inv = rules.slice_inventory(
        _tree(
            Endpoint(
                method="GET",
                path="/admin/dashboard",
                base_url="https://admin.onde.click",
                kind="frontend",
            ),
            Endpoint(method="GET", path="/", base_url="https://onde.click", kind="frontend"),
        ),
        extra_bases=["https://onde.click", "https://admin.onde.click"],
    )
    findings, _ = rules.analyze_separation(
        login_entries=login_entries,
        inventory=inv,
        extra_admin_hosts=["admin.onde.click"],
    )
    rule_ids = {(f.evidence or {}).get("rule_id") for f in findings}
    assert "3-4-host-separated" in rule_ids
    assert "3-4-login-same-host" not in rule_ids
    assert "3-4-ui-same-server" not in rule_ids


def test_admin_ui_same_base_medium():
    rules = _load("separation_rules")
    tree = _tree(
        Endpoint(method="GET", path="/", base_url="http://localhost:5173", kind="frontend"),
        Endpoint(method="GET", path="/admin", base_url="http://localhost:5173", kind="frontend"),
        Endpoint(method="GET", path="/admin/users", base_url="http://localhost:5173", kind="frontend"),
    )
    inv = rules.slice_inventory(tree)
    findings, stats = rules.analyze_separation(login_entries=[], inventory=inv)
    rule_ids = {(f.evidence or {}).get("rule_id") for f in findings}
    assert "3-4-ui-same-server" in rule_ids
    assert stats["admin_ui_same_base"] == 2


def test_guessable_path_info():
    rules = _load("separation_rules")
    tree = _tree(
        Endpoint(
            method="GET",
            path="/api/v1/admin/bookings",
            base_url="http://localhost:8080",
            kind="api",
        ),
    )
    inv = rules.slice_inventory(tree)
    findings, _ = rules.analyze_separation(login_entries=[], inventory=inv)
    rule_ids = {(f.evidence or {}).get("rule_id") for f in findings}
    assert "3-4-guessable-path" in rule_ids
    assert "3-4-api-same-server" in rule_ids

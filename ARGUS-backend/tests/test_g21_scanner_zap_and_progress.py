"""Tests for 2-1 scanner orchestration: ZAP-phase error handling and
progress accounting under an early ``max_requests`` budget cutoff.

Regression coverage for two bugs:
  - an unexpected (non-ZAP-connectivity) exception during the ZAP phase was
    silently swallowed and left the ZAP workspace un-reset with no trace;
  - the progress offset carried into later work always assumed the httpx
    phase fully completed, even when the shared request budget cut it short.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

MODULE_DIR = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "2-1"
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def _load_g21_module(name: str):
    path = MODULE_DIR / f"{name}.py"
    mod_name = f"test_g21_scanner_suite_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_run_phase_reports_actual_processed_count_under_budget_cutoff():
    scanner = _load_g21_module("scanner")
    probes = _load_g21_module("probes")

    targets = [SimpleNamespace(endpoint_id=f"t{i}") for i in range(3)]
    payloads_by_target = {id(t): ["p1", "p2"] for t in targets}
    budget = probes.RequestBudget(max_requests=2)

    def fake_run_upload_probes(target_list, payloads, *, transport, engine, rules_mod, multipart_mod,
                                timeout=15.0, auth_mode=None, request_headers=None, account_email=None,
                                login_label=None, interval_sec=0.0, budget=None, on_progress=None):
        sent = 0
        for _ in payloads:
            if budget is not None and not budget.consume():
                break
            sent += 1
        if on_progress:
            on_progress(endpoints_done=sent, endpoints_total=len(payloads))
        return [], {"requests_sent": sent, "requested_urls": []}

    probes.run_upload_probes = fake_run_upload_probes

    findings, stats = scanner._run_phase(
        transport=object(),
        engine="httpx",
        targets=targets,
        payloads_by_target=payloads_by_target,
        passes=[("anonymous", None)],
        probes_mod=probes,
        rules_mod=object(),
        multipart_mod=object(),
        opts=scanner.ScanOptions(max_requests=2),
        progress_cb_factory=lambda label: (lambda **kw: None),
        budget=budget,
    )

    # 3 targets x 2 payloads = 6 possible, but the shared budget (2) cuts it
    # short after the first target — "processed" must reflect that, not the
    # theoretical 6.
    assert stats["processed"] == 2
    assert budget.exhausted()


def test_zap_phase_unexpected_exception_still_resets_workspace_and_is_logged(monkeypatch, caplog):
    from app.services import diagnosis_progress

    scanner = _load_g21_module("scanner")

    reset_calls: list[str] = []

    class FakeZapScanMod:
        def open_zap_transport(self, raw_config, *, auth):
            return object(), object(), "http://zap-proxy:8090"

        def reset_workspace(self, zap, *, session_name):
            reset_calls.append(session_name)
            return {"session_name": session_name}

    class FakeTargets:
        def build_upload_targets(self, raw_config, *, data_dir, default_allowed_extensions):
            target = SimpleNamespace(endpoint_id="t0", allowed_extensions=default_allowed_extensions)
            return [target], {"source": "test"}

    class FakePayloads:
        def load_extension_rules(self):
            return {}

        def build_upload_payloads(self, allowed_extensions, *, rules):
            return ["payload-1"]

    fakes = {
        "targets": FakeTargets(),
        "payloads": FakePayloads(),
        "probes": object(),
        "rules": object(),
        "multipart": object(),
        "zap_scan": FakeZapScanMod(),
    }

    def fake_load_local(name):
        return fakes[name]

    def boom_run_phase(**kwargs):
        if kwargs["engine"] == "zap":
            raise RuntimeError("unexpected boom")
        return [], {"passes": [], "requested_urls": [], "processed": 0}

    monkeypatch.setattr(scanner, "_load_local", fake_load_local)
    monkeypatch.setattr(scanner, "primary_account_auth", lambda raw_config, data_dir: None)
    monkeypatch.setattr(scanner, "all_account_auths_with_meta", lambda raw_config, data_dir: ([], {}))
    monkeypatch.setattr(scanner, "_run_phase", boom_run_phase)
    monkeypatch.setattr(diagnosis_progress, "update", lambda **kw: None)

    ctx = SimpleNamespace(
        raw_config={"diagnosis_2_1": {"httpx_enabled": False, "zap_enabled": True}},
        data_dir=Path("."),
    )

    with caplog.at_level(logging.ERROR, logger=scanner.logger.name):
        result = scanner.run_g21_scan(ctx, MODULE_DIR)

    # The "start" reset must still be followed by a "done" reset even though
    # the ZAP phase blew up with a non-connectivity error in between.
    assert reset_calls == ["argus-g21-start", "argus-g21-done"]
    assert result.stats["zap"]["unexpected"] is True
    assert result.stats["zap"]["workspace_reset_after"] == {"session_name": "argus-g21-done"}
    assert any("2-1 ZAP phase failed unexpectedly" in rec.message for rec in caplog.records)

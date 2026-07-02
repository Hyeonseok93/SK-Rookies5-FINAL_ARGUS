"""Tests for injection scan sample-value helpers and merge behavior."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from inventory.merge import merge_inputs, restore_reference_samples
from inventory.schema import ApiTree, Endpoint, InputParam, InventoryMeta
from inventory.sources.openapi import _example_value

_MODULE_DIR = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "1-2"


def _load_g12(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g12_test_{name}"
    if "sample_values" not in sys.modules:
        sv_path = _MODULE_DIR / "sample_values.py"
        sv_spec = importlib.util.spec_from_file_location("sample_values", sv_path)
        assert sv_spec and sv_spec.loader
        sv_mod = importlib.util.module_from_spec(sv_spec)
        sys.modules["sample_values"] = sv_mod
        sv_spec.loader.exec_module(sv_mod)
    if "models" not in sys.modules and name not in ("models", "sample_values"):
        models_path = _MODULE_DIR / "models.py"
        models_spec = importlib.util.spec_from_file_location("models", models_path)
        assert models_spec and models_spec.loader
        models_mod = importlib.util.module_from_spec(models_spec)
        sys.modules["models"] = models_mod
        models_spec.loader.exec_module(models_mod)
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_example_value_uses_enum_first_value():
    assert _example_value({"enum": ["REVIEW", "PHOTO"]}) == "REVIEW"
    assert _example_value({"example": "X", "enum": ["REVIEW"]}) == "X"


def test_pick_sample_value_prefers_enum_like_name_fallback():
    sample_values = _load_g12("sample_values")
    assert sample_values.pick_sample_value("type", param_type="string", sample=None) == "REVIEW"
    assert sample_values.pick_sample_value("status", param_type="string", sample="ACTIVE") == "ACTIVE"
    assert sample_values.pick_sample_value("status", param_type="string", sample="argus-test") == "ACTIVE"


def test_targets_sample_value_uses_review_for_posts_type():
    targets = _load_g12("targets")
    param = InputParam(in_="query", name="type", type="string", sample=None)
    assert targets._sample_value(param) == "REVIEW"


def test_merge_inputs_prefers_openapi_sample_over_placeholder():
    probe = InputParam(
        in_="query",
        name="type",
        type="string",
        sample="argus-test",
        sources=["probe"],
    )
    openapi = InputParam(
        in_="query",
        name="type",
        type="string",
        sample="REVIEW",
        sources=["openapi"],
    )
    merged = merge_inputs([probe], [openapi])[0]
    assert merged.sample == "REVIEW"
    assert "openapi" in merged.sources


def test_restore_reference_samples_fills_missing_type_sample():
    ready = ApiTree(
        meta=InventoryMeta(),
        endpoints=[
            Endpoint(
                method="GET",
                path="/api/v1/posts",
                base_url="http://localhost:8080",
                request_params=[
                    InputParam(in_="query", name="type", type="string", sample="REVIEW", sources=["openapi"]),
                    InputParam(in_="query", name="status", type="string", sample="ACTIVE", sources=["openapi"]),
                ],
            )
        ],
    )
    verified = ApiTree(
        meta=InventoryMeta(),
        endpoints=[
            Endpoint(
                method="GET",
                path="/api/v1/posts",
                base_url="http://localhost:8080",
                request_params=[
                    InputParam(in_="query", name="type", type="string", sample=None, sources=["probe"]),
                    InputParam(in_="query", name="status", type="string", sample="ACTIVE", sources=["probe"]),
                ],
            )
        ],
    )
    restored = restore_reference_samples(verified, ready)
    params = {p.name: p.sample for p in verified.endpoints[0].request_params}
    assert params["type"] == "REVIEW"
    assert restored >= 1


def test_should_keep_direct_unstable_baseline_as_suspected_in_aggressive_mode():
    payload_injector = _load_g12("payload_injector")
    models = _load_g12("models")
    inj = payload_injector.BaseInjector(verification_mode="aggressive")
    result = models.DetectionResult(
        method="GET",
        url="http://example.test",
        param="status",
        risk="HIGH",
        plugin_id="ARGUS_DIRECT",
        plugin_name="test",
        injection_type=models.InjectionType.SQL,
        has_zap=True,
    )
    result.verification_methods = {
        "error_based": {"status": "FALSE_POSITIVE", "tried_payloads": 3},
    }
    baseline = payload_injector.ProbeResponse(
        elapsed=0.1,
        status_code="500",
        text="error",
        headers={},
    )
    assert inj._should_keep_as_suspected(result, baseline) is True

    direct = models.DetectionResult(
        method="GET",
        url="http://example.test",
        param="status",
        risk="UNKNOWN",
        plugin_id="ARGUS_DIRECT",
        plugin_name="test",
        injection_type=models.InjectionType.SQL,
        has_zap=False,
    )
    direct.verification_methods = {
        "error_based": {"status": "FALSE_POSITIVE", "tried_payloads": 2},
    }
    assert inj._should_keep_as_suspected(direct, baseline) is False

    noisy = models.DetectionResult(
        method="GET",
        url="http://example.test",
        param="status",
        risk="UNKNOWN",
        plugin_id="ARGUS_DIRECT",
        plugin_name="test",
        injection_type=models.InjectionType.SQL,
        has_zap=False,
    )
    noisy.verification_methods = {
        "boolean_based": {"status": "FALSE_POSITIVE", "tried_pairs": 4},
    }
    assert inj._should_keep_as_suspected(noisy, baseline) is False


def test_generic_5xx_without_sql_pattern_is_not_suspected():
    payload_injector = _load_g12("payload_injector")
    models = _load_g12("models")

    class FakeInjector(payload_injector.SqliInjector):
        def send_probe(self, method, url, body, headers):
            if "'" in url or "'" in (body or ""):
                return payload_injector.ProbeResponse(
                    elapsed=0.1, status_code="500", text="internal error", headers={}
                )
            return payload_injector.ProbeResponse(
                elapsed=0.1, status_code="200", text="ok", headers={}
            )

    inj = FakeInjector(verification_mode="strict")
    result = models.DetectionResult(
        method="GET",
        url="http://example.test/api?page=1",
        param="page",
        risk="UNKNOWN",
        plugin_id="ARGUS_DIRECT",
        plugin_name="test",
        injection_type=models.InjectionType.SQL,
        has_zap=False,
    )
    out = inj.verify_zap_alert(result)
    assert out.verification_status == models.VerificationStatus.FALSE_POSITIVE


def test_excluded_server_error_classification_not_reported():
    injector_runner = _load_g12("injector_runner")
    models = _load_g12("models")
    result = models.DetectionResult(
        method="GET",
        url="http://example.test",
        param="age",
        risk="UNKNOWN",
        plugin_id="ARGUS_DIRECT",
        plugin_name="test",
        injection_type=models.InjectionType.SQL,
        has_zap=False,
        verification_status=models.VerificationStatus.SUSPECTED,
        classification="SUSPECTED_SERVER_ERROR_SIGNAL",
    )
    assert injector_runner.should_report_injection_finding(result) is False

    weak = models.DetectionResult(
        method="POST",
        url="http://example.test/signup",
        param="name",
        risk="UNKNOWN",
        plugin_id="ARGUS_DIRECT",
        plugin_name="test",
        injection_type=models.InjectionType.SQL,
        has_zap=False,
        verification_status=models.VerificationStatus.SUSPECTED,
        classification="SUSPECTED_INJECTION",
    )
    assert injector_runner.should_report_injection_finding(weak) is False


def test_strict_mode_rejects_boolean_only_as_false_positive():
    payload_injector = _load_g12("payload_injector")
    models = _load_g12("models")
    inj = payload_injector.BaseInjector(verification_mode="strict")
    result = models.DetectionResult(
        method="GET",
        url="http://example.test",
        param="q",
        risk="UNKNOWN",
        plugin_id="ARGUS_DIRECT",
        plugin_name="test",
        injection_type=models.InjectionType.SQL,
        has_zap=False,
    )
    result.verification_methods = {
        "boolean_based": {"status": "VERIFIED"},
    }
    baseline = payload_injector.ProbeResponse(
        elapsed=0.1,
        status_code="200",
        text="ok",
        headers={},
    )
    finalized = inj._finalize_verified(result, ["boolean_based"], baseline, 0.0)
    assert finalized.verification_status == models.VerificationStatus.FALSE_POSITIVE

    result2 = models.DetectionResult(
        method="GET",
        url="http://example.test",
        param="q",
        risk="UNKNOWN",
        plugin_id="ARGUS_DIRECT",
        plugin_name="test",
        injection_type=models.InjectionType.SQL,
        has_zap=False,
    )
    result2.verification_methods = {
        "time_based": {"status": "VERIFIED"},
    }
    finalized2 = inj._finalize_verified(result2, ["time_based"], baseline, 3.1)
    assert finalized2.verification_status == models.VerificationStatus.VERIFIED

"""Tests for shared endpoint auth requirement classification."""

from diagnosis.endpoint_auth import (
    AuthRequirement,
    build_endpoint_auth_index,
    classify_endpoint_rows,
    filter_cookie_probe_endpoints,
)


class _Ep:
    def __init__(self, endpoint_id: str):
        self.endpoint_id = endpoint_id


def test_auth_required_when_anon_401_and_authed_ok():
    rows = [
        {"endpoint_id": "e1", "auth_mode": "anonymous", "http_status": 401, "include_in_final": True},
        {
            "endpoint_id": "e1",
            "auth_mode": "user@ex.com · login",
            "http_status": 200,
            "include_in_final": True,
        },
    ]
    cls = classify_endpoint_rows(rows)
    assert cls.requirement == "auth_required"
    assert cls.cookie_probe_relevant()


def test_public_when_anon_200_without_authed():
    rows = [
        {"endpoint_id": "e2", "auth_mode": "anonymous", "http_status": 200, "include_in_final": True},
    ]
    cls = classify_endpoint_rows(rows)
    assert cls.requirement == "public"
    assert not cls.cookie_probe_relevant()


def test_optional_auth_when_both_anon_and_authed_ok():
    rows = [
        {"endpoint_id": "e3", "auth_mode": "anonymous", "http_status": 200, "include_in_final": True},
        {
            "endpoint_id": "e3",
            "auth_mode": "user@ex.com · login",
            "http_status": 200,
            "include_in_final": True,
        },
    ]
    cls = classify_endpoint_rows(rows)
    assert cls.requirement == "optional_auth"
    assert not cls.cookie_probe_relevant()


def test_filter_cookie_probe_endpoints_skips_public():
    index = {
        "auth": classify_endpoint_rows(
            [
                {"endpoint_id": "auth", "auth_mode": "anonymous", "http_status": 403},
                {"endpoint_id": "auth", "auth_mode": "a · login", "http_status": 200},
            ]
        ),
        "pub": classify_endpoint_rows(
            [{"endpoint_id": "pub", "auth_mode": "anonymous", "http_status": 200}]
        ),
    }
    eps = [_Ep("auth"), _Ep("pub")]
    kept, stats = filter_cookie_probe_endpoints(eps, index, auth_required_only=True)
    assert [e.endpoint_id for e in kept] == ["auth"]
    assert stats["skipped"] == 1
    assert stats["counts"]["public"] == 1


def test_build_index_from_verify_report(tmp_path):
    report = {
        "results": [
            {"endpoint_id": "x:GET:/a", "auth_mode": "anonymous", "http_status": 401},
            {"endpoint_id": "x:GET:/a", "auth_mode": "u · login", "http_status": 200},
            {"endpoint_id": "x:GET:/b", "auth_mode": "anonymous", "http_status": 200},
        ]
    }
    (tmp_path / "verify-report.json").write_text(__import__("json").dumps(report), encoding="utf-8")
    index = build_endpoint_auth_index(tmp_path)
    assert index["x:GET:/a"].requirement == "auth_required"
    assert index["x:GET:/b"].requirement == "public"

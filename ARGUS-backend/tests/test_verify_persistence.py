import json

from inventory.schema import ApiTree, Endpoint, InventoryMeta
from app.services.verify_service import persist_verification


def test_empty_verify_result_reports_warning_and_keeps_previous_verified_tree(tmp_path, caplog):
    original = ApiTree(
        meta=InventoryMeta(),
        endpoints=[Endpoint(method="GET", path="/health", base_url="http://localhost:8080")],
    )
    previous = ApiTree(
        meta=InventoryMeta(),
        endpoints=[Endpoint(method="GET", path="/previous", base_url="http://localhost:8080")],
    )
    previous.save(tmp_path / "api-tree-verified.json")
    payload = {
        "checked_at": "2026-07-03T00:00:00+00:00",
        "total_checked": 1,
        "confirmed": 0,
        "params_issues": 0,
        "rejected": 1,
        "verified_count": 0,
        "params_enriched": 0,
        "results": [],
        "verified_tree": ApiTree(meta=InventoryMeta(), endpoints=[]),
    }

    artifacts = persist_verification(tmp_path, payload, original_tree=original)

    assert "api_tree_verified" not in artifacts
    assert payload["error"] == "verify_empty_result"
    assert "not updated" in payload["warning"]
    assert ApiTree.load(tmp_path / "api-tree-verified.json").endpoints[0].path == "/previous"
    report = json.loads((tmp_path / "verify-report.json").read_text(encoding="utf-8"))
    assert report["summary"]["persisted"] is False
    assert report["error"] == "verify_empty_result"
    assert "0 verified endpoints" in caplog.text

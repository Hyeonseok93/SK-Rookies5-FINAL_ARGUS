"""Export api-tree artifacts for ZAP API / Automation Framework."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from inventory.probe_build import build_probe_request
from inventory.schema import ApiTree, build_full_url

# Reuse path materialization from existing runner
DEFAULT_PATH_PARAMS = {
    "id": "1",
    "scheduleId": "1",
    "bookingId": "1",
    "policyId": "1",
    "paymentId": "1",
    "commentId": "1",
    "postId": "1",
    "roomId": "1",
    "settlementId": "1",
    "reservationId": "1",
    "booking_code": "TEST001",
}


def materialize_path(path: str) -> str:
    import re

    def repl(m: re.Match[str]) -> str:
        key = m.group(0)[1:-1]
        return DEFAULT_PATH_PARAMS.get(key, "1")

    return re.sub(r"\{[a-zA-Z0-9_]+\}", repl, path)


def _query_from_inputs(endpoint) -> dict[str, str]:
    q: dict[str, str] = {}
    for inp in endpoint.inputs:
        if inp.in_ == "query" and inp.sample is not None:
            q[inp.name] = inp.sample
    return q


def _body_json_from_inputs(endpoint) -> str | None:
    body_fields = [i for i in endpoint.inputs if i.in_ == "body"]
    if not body_fields:
        return None
    obj: dict[str, Any] = {}
    for inp in body_fields:
        if inp.sample is None:
            obj[inp.name] = ""
            continue
        if inp.type in ("integer", "int", "number"):
            try:
                obj[inp.name] = int(inp.sample)
                continue
            except ValueError:
                pass
        if inp.type == "boolean":
            obj[inp.name] = inp.sample.lower() in ("true", "1")
            continue
        obj[inp.name] = inp.sample
    return json.dumps(obj, ensure_ascii=False)


def export_requestor_seeds(tree: ApiTree) -> list[dict[str, Any]]:
    seeds: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for ep in tree.endpoints:
        probe = build_probe_request(ep)
        key = (probe["method"], probe["url"], ep.base_url)
        if key in seen:
            continue
        seen.add(key)

        seed: dict[str, Any] = {
            "name": ep.endpoint_id.replace(":", "-").replace("/", "-")[:120],
            "method": probe["method"],
            "url": probe["url"],
            "endpoint_id": ep.endpoint_id,
            "tags": ep.tags,
            "headers": [f"{k}: {v}" for k, v in probe["headers"].items()],
        }
        if probe.get("body"):
            seed["data"] = probe["body"]
        seeds.append(seed)
    return seeds


def export_zap_bundle(
    tree: ApiTree,
    openapi_path: Path | None = None,
    *,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    imports: list[dict[str, Any]] = []
    if openapi_path and openapi_path.is_file():
        from inventory.upload_batch import openapi_ref_for_bundle

        ref = (
            openapi_ref_for_bundle(openapi_path, data_dir)
            if data_dir is not None
            else str(openapi_path.resolve()).replace("\\", "/")
        )
        imports.append(
            {
                "type": "openapi",
                "file": ref,
                "note": "Uploaded via Dashboard Build — data/uploads/{batch-id}/openapi.*",
            }
        )

    return {
        "schema": "zap-inventory-bundle/1.0",
        "openapi_imports": imports,
        "context_urls": sorted({ep.base_url for ep in tree.endpoints}),
        "requestor_seeds": export_requestor_seeds(tree),
        "stats": {
            "endpoints": len(tree.endpoints),
            "with_query": sum(1 for e in tree.endpoints if any(i.in_ == "query" for i in e.inputs)),
            "with_body": sum(1 for e in tree.endpoints if any(i.in_ == "body" for i in e.inputs)),
        },
    }


def write_zap_exports(
    tree: ApiTree,
    out_dir: Path,
    openapi_path: Path | None = None,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle = export_zap_bundle(tree, openapi_path, data_dir=out_dir)
    (out_dir / "zap-requestor-seeds.json").write_text(
        json.dumps(bundle["requestor_seeds"], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (out_dir / "zap-inventory-bundle.json").write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.config import AppConfig, config_to_inventory_dict
from inventory.export_zap import write_zap_exports
from inventory.merge import merge_trees
from inventory.schema import ApiTree, InventoryMeta
from inventory.sources.openapi import load_openapi_inventory
from inventory.sources.txt_list import load_txt_api_list_inventory, load_txt_url_list_inventory
from inventory.sources.url_list import load_url_list_inventory as load_json_url_list_inventory


def _base_urls(cfg: dict, inv_cfg: dict) -> list[str]:
    if inv_cfg.get("base_urls"):
        return [str(u).rstrip("/") for u in inv_cfg["base_urls"]]
    return [t["base_url"].rstrip("/") for t in cfg.get("targets", [])]


def build_inventory_from_dict(
    cfg: dict,
    *,
    url_list: bool = False,
    api_list: bool = False,
    openapi: bool = False,
    json_url_list: bool = False,
    url_list_path: Path | None = None,
    api_list_path: Path | None = None,
    openapi_path: Path | None = None,
    json_url_list_path: Path | None = None,
    base_urls: list[str] | None = None,
) -> ApiTree:
    inv = cfg.get("inventory") or {}
    app_name = cfg.get("app_name", "")
    bases = base_urls if base_urls else _base_urls(cfg, inv)
    trees: list[ApiTree] = []
    missing: list[str] = []

    if url_list:
        if url_list_path and url_list_path.is_file():
            trees.append(load_txt_url_list_inventory(url_list_path, bases))
        else:
            missing.append("url_list")

    if api_list:
        if api_list_path and api_list_path.is_file():
            trees.append(load_txt_api_list_inventory(api_list_path, bases))
        else:
            missing.append("api_list")

    saved_openapi_path: Path | None = openapi_path
    if openapi:
        if saved_openapi_path and saved_openapi_path.is_file():
            oa_cfg = inv.get("openapi") or {}
            trees.append(
                load_openapi_inventory(
                    saved_openapi_path,
                    bases,
                    spec_base_url=oa_cfg.get("base_url"),
                )
            )
        else:
            missing.append("openapi")

    if json_url_list:
        if json_url_list_path and json_url_list_path.is_file():
            trees.append(load_json_url_list_inventory(json_url_list_path, bases))
        else:
            missing.append("json_url_list")

    if not trees:
        return ApiTree(
            meta=InventoryMeta(app_name=app_name, sources_missing=sorted(set(missing))),
            endpoints=[],
        )

    merged = merge_trees(trees, app_name=app_name)
    merged.meta.sources_missing = sorted(set(merged.meta.sources_missing + missing))
    from inventory.tags import tag_endpoint

    for ep in merged.endpoints:
        tag_endpoint(ep)
    return merged


def build_inventory(
    app_config: AppConfig,
    *,
    url_list: bool = False,
    api_list: bool = False,
    openapi: bool = False,
    json_url_list: bool = False,
    url_list_path: Path | None = None,
    api_list_path: Path | None = None,
    openapi_path: Path | None = None,
    json_url_list_path: Path | None = None,
    base_urls: list[str] | None = None,
) -> ApiTree:
    return build_inventory_from_dict(
        config_to_inventory_dict(app_config),
        url_list=url_list,
        api_list=api_list,
        openapi=openapi,
        json_url_list=json_url_list,
        url_list_path=url_list_path,
        api_list_path=api_list_path,
        openapi_path=openapi_path,
        json_url_list_path=json_url_list_path,
        base_urls=base_urls,
    )


def _target_key_from_base_url(base_url: str) -> str:
    """Derive stats bucket key from endpoint base_url (tolerates malformed URLs)."""
    parsed = urlparse(base_url)
    netloc = parsed.netloc or base_url
    port: int | None
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        return str(port)
    if netloc.startswith("localhost:"):
        return netloc.split(":", 1)[1]
    if ":" in netloc:
        host, maybe_port = netloc.rsplit(":", 1)
        if maybe_port.isdigit():
            return maybe_port
        return host or netloc
    return netloc or base_url


def compute_stats(tree: ApiTree) -> dict[str, Any]:
    endpoints = tree.endpoints
    api_eps = [e for e in endpoints if e.kind != "frontend"]
    write_methods = {"POST", "PUT", "PATCH", "DELETE"}

    with_body = sum(1 for e in api_eps if any(i.in_ == "body" for i in e.inputs))
    with_query = sum(1 for e in api_eps if any(i.in_ == "query" for i in e.inputs))
    schema_enriched = sum(
        1 for e in api_eps if any(i.in_ in ("body", "query") for i in e.inputs)
    )
    api_count = len(api_eps)
    schema_coverage_pct = round(100 * schema_enriched / api_count) if api_count else 0

    target_counts: dict[str, int] = {}
    for ep in api_eps:
        key = _target_key_from_base_url(ep.base_url)
        target_counts[key] = target_counts.get(key, 0) + 1

    return {
        "total_endpoints": len(endpoints),
        "frontend_endpoints": len(endpoints) - len(api_eps),
        "api_endpoints": api_count,
        "write_endpoints": sum(1 for e in api_eps if e.method.upper() in write_methods),
        "with_body": with_body,
        "with_query": with_query,
        "schema_coverage_pct": schema_coverage_pct,
        "schema_enriched": schema_enriched,
        "targets": target_counts,
        "sources_used": tree.meta.sources_used,
        "sources_missing": tree.meta.sources_missing,
    }


def persist_inventory(tree: ApiTree, data_dir: Path, openapi_path: Path | None = None) -> dict[str, str]:
    data_dir.mkdir(parents=True, exist_ok=True)
    api_tree_path = data_dir / "api-tree.json"
    ready_path = data_dir / "api-tree-ready.json"
    tree.save(api_tree_path)
    tree.save(ready_path)
    write_zap_exports(tree, data_dir, openapi_path)
    return {
        "api_tree": str(api_tree_path),
        "api_tree_ready": str(ready_path),
        "zap_seeds": str(data_dir / "zap-requestor-seeds.json"),
        "zap_bundle": str(data_dir / "zap-inventory-bundle.json"),
    }

"""Load supplemental URL/API list (JSON) — optional extra endpoints."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from inventory.schema import ApiTree, Endpoint, InputParam, InventoryMeta, split_path_query


def _inputs_from_dict(data: dict[str, Any], source: str) -> list[InputParam]:
    inputs: list[InputParam] = []
    for item in data.get("inputs") or []:
        inputs.append(
            InputParam(
                in_=item["in"],
                name=item["name"],
                type=item.get("type", "string"),
                required=bool(item.get("required", False)),
                sample=item.get("sample"),
                role=item.get("role", "input"),
                sources=[source],
            )
        )
    query = data.get("query") or {}
    if isinstance(query, dict):
        for name, val in query.items():
            inputs.append(
                InputParam(
                    in_="query",
                    name=str(name),
                    type="string",
                    sample=str(val) if val is not None else None,
                    sources=[source],
                )
            )
    headers = data.get("headers") or {}
    if isinstance(headers, dict):
        for name, val in headers.items():
            role = "auth" if name.lower() == "authorization" else "meta"
            inputs.append(
                InputParam(
                    in_="header",
                    name=str(name),
                    type="string",
                    sample=str(val) if val is not None else None,
                    role=role,
                    sources=[source],
                )
            )
    body = data.get("body")
    if isinstance(body, dict):
        for name, val in body.items():
            inputs.append(
                InputParam(
                    in_="body",
                    name=str(name),
                    type=type(val).__name__ if val is not None else "string",
                    sample=json.dumps(val, ensure_ascii=False) if isinstance(val, (dict, list)) else str(val),
                    sources=[source],
                )
            )
    return inputs


def load_url_list_inventory(path: Path, default_base_urls: list[str]) -> ApiTree:
    """
    JSON format (inventory-urls.json):

    {
      "endpoints": [
        {
          "method": "GET",
          "path": "/api/v1/accommodations/search",
          "base_urls": ["http://localhost:8080"],
          "query": {"region": "도쿄", "checkIn": "2026-06-28", "page": "0"},
          "headers": {"Accept": "application/json"},
          "body": {"template": "default.html"}
        }
      ]
    }
    """
    if not path.is_file():
        return ApiTree(meta=InventoryMeta(sources_missing=["url_list"]), endpoints=[])

    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("endpoints") or []
    endpoints: list[Endpoint] = []

    for row in rows:
        method = str(row.get("method", "GET")).upper()
        raw_path = row.get("path") or row.get("url", "")
        path_only, query_in_path = split_path_query(str(raw_path))
        if not path_only.startswith("/"):
            path_only = "/" + path_only

        bases = row.get("base_urls") or default_base_urls
        if isinstance(bases, str):
            bases = [bases]

        merged_query = dict(query_in_path)
        if isinstance(row.get("query"), dict):
            merged_query.update({k: str(v) for k, v in row["query"].items()})

        for base in bases:
            ep_data = dict(row)
            ep_data["query"] = merged_query
            inputs = _inputs_from_dict(ep_data, "url_list")
            endpoints.append(
                Endpoint(
                    method=method,
                    path=path_only,
                    base_url=str(base).rstrip("/"),
                    request_params=inputs,
                    sources=["url_list"],
                    auth=list(row.get("auth") or []),
                    kind=row.get("kind", "api"),
                )
            )

    return ApiTree(
        meta=InventoryMeta(sources_used=["url_list"] if endpoints else []),
        endpoints=endpoints,
    )

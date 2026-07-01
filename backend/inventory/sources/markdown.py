"""Load inventory from Markdown endpoint definition tables."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from inventory.schema import ApiTree, Endpoint, InputParam, InventoryMeta, split_path_query

PATH_PARAM_RE = re.compile(r"\{[a-zA-Z0-9_]+\}")


def _import_md_parser():
    root = Path(__file__).resolve().parent.parent.parent
    parsers = root / "parsers"
    if str(parsers) not in sys.path:
        sys.path.insert(0, str(parsers))
    from parse_endpoints import parse_markdown_tables  # noqa: WPS433

    return parse_markdown_tables


def path_template_params(path: str, source: str = "api_list") -> list[InputParam]:
    inputs: list[InputParam] = []
    for match in PATH_PARAM_RE.finditer(path):
        name = match.group(0)[1:-1]
        inputs.append(
            InputParam(
                in_="path",
                name=name,
                type="string",
                required=True,
                sources=[source],
            )
        )
    return inputs


def load_markdown_inventory(
    md_path: Path,
    base_urls: list[str],
    *,
    include_api: bool = True,
    include_frontend: bool = False,
    frontend_base_url: str | None = None,
) -> ApiTree:
    parse_markdown_tables = _import_md_parser()
    text = md_path.read_text(encoding="utf-8")
    rows = parse_markdown_tables(text)

    endpoints: list[Endpoint] = []
    used_sources: set[str] = set()
    for row in rows:
        kind = row.get("kind", "api")
        if kind == "frontend":
            if not include_frontend:
                continue
            source_tag = "homepage_urls"
        else:
            if not include_api:
                continue
            source_tag = "api_list"

        raw_url = row["url"]
        method = row["method"].upper()
        path_only, query_from_path = split_path_query(raw_url)
        if not path_only.startswith("/"):
            path_only = "/" + path_only

        if kind == "frontend" and frontend_base_url:
            bases = [frontend_base_url.rstrip("/")]
        else:
            bases = base_urls

        for base in bases:
            inputs = path_template_params(path_only, source_tag)
            for qname, qval in query_from_path.items():
                inputs.append(
                    InputParam(
                        in_="query",
                        name=qname,
                        type="string",
                        sample=qval or None,
                        sources=[source_tag],
                    )
                )
            endpoints.append(
                Endpoint(
                    method=method,
                    path=path_only,
                    base_url=base.rstrip("/"),
                        request_params=inputs,
                    sources=[source_tag],
                    kind=kind if kind == "frontend" else "api",
                )
            )
            used_sources.add(source_tag)

    return ApiTree(
        meta=InventoryMeta(sources_used=sorted(used_sources)),
        endpoints=endpoints,
    )

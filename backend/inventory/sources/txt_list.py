"""Load inventory from plain-text URL/API lists (one entry per line).

Line format
-----------
API list:
  METHOD /path
  METHOD /path | param1, param2
  METHOD /path | param1=sample, param2=sample

URL list:
  /path
  /path | param1, param2
  /path | param1=sample, param2=sample

Query params after ``|`` are optional. Name only = no sample; name=value = sample.
Path template params ``{id}`` in the path are always required.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from inventory.schema import ApiTree, Endpoint, InputParam, InventoryMeta, split_path_query

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
PATH_PARAM_RE = re.compile(r"\{[a-zA-Z0-9_]+\}")


def _iter_txt_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def path_template_params(path: str, source: str) -> list[InputParam]:
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


def _parse_query_suffix(suffix: str) -> dict[str, str | None]:
    """
    Parse optional query suffix after `|`.

    Examples:
      region=도쿄, page=0  -> {region: 도쿄, page: 0}
      region, page         -> {region: None, page: None}
    """
    params: dict[str, str | None] = {}
    for part in suffix.split(","):
        token = part.strip().lstrip("?")
        if not token:
            continue
        if "=" in token:
            name, value = token.split("=", 1)
            params[name.strip()] = value.strip() or None
        else:
            params[token] = None
    return params


def _split_optional_query(line: str) -> tuple[str, dict[str, str | None]]:
    if "|" not in line:
        return line.strip(), {}
    main, suffix = line.split("|", 1)
    return main.strip(), _parse_query_suffix(suffix)


def _query_inputs(query: dict[str, str | None], source: str) -> list[InputParam]:
    return [
        InputParam(
            in_="query",
            name=name,
            type="string",
            sample=sample,
            required=False,
            sources=[source],
        )
        for name, sample in query.items()
    ]


def _merge_query(
    from_path: dict[str, str],
    extra: dict[str, str | None],
) -> dict[str, str | None]:
    merged: dict[str, str | None] = {k: v or None for k, v in from_path.items()}
    merged.update(extra)
    return merged


def _resolve_web_target(line: str, base_urls: list[str]) -> list[tuple[str, str]]:
    """Return (base_url, path) pairs for one WEB URL list line."""
    if line.startswith("http://") or line.startswith("https://"):
        parsed = urlparse(line)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path_only = parsed.path or "/"
        if parsed.query:
            path_only = f"{path_only}?{parsed.query}"
        return [(base.rstrip("/"), path_only)]

    path_only = line if line.startswith("/") else f"/{line}"
    bases = base_urls
    return [(base.rstrip("/"), path_only) for base in bases]


def _parse_api_main(line: str) -> tuple[str, str]:
    parts = line.split(None, 1)
    if len(parts) == 1:
        raw = parts[0]
        return "GET", raw if raw.startswith("/") else f"/{raw}"

    maybe_method, rest = parts[0].upper(), parts[1].strip()
    if maybe_method in HTTP_METHODS:
        path = rest if rest.startswith("/") else f"/{rest}"
        return maybe_method, path

    raw = line.strip()
    return "GET", raw if raw.startswith("/") else f"/{raw}"


def _parse_api_line(line: str) -> tuple[str, str, dict[str, str | None]]:
    main, extra_query = _split_optional_query(line)
    method, raw_path = _parse_api_main(main)
    path_only, query_from_path = split_path_query(raw_path)
    if not path_only.startswith("/"):
        path_only = "/" + path_only
    merged_query = _merge_query(query_from_path, extra_query)
    return method, path_only, merged_query


def load_txt_url_list_inventory(txt_path: Path, base_urls: list[str]) -> ApiTree:
    text = txt_path.read_text(encoding="utf-8")
    endpoints: list[Endpoint] = []

    for line in _iter_txt_lines(text):
        main, extra_query = _split_optional_query(line)
        for base, raw_path in _resolve_web_target(main, base_urls):
            path_only, query_from_path = split_path_query(raw_path)
            merged_query = _merge_query(query_from_path, extra_query)
            inputs = path_template_params(path_only, "url_list")
            inputs.extend(_query_inputs(merged_query, "url_list"))
            endpoints.append(
                Endpoint(
                    method="GET",
                    path=path_only,
                    base_url=base,
                    request_params=inputs,
                    sources=["url_list"],
                    kind="frontend",
                )
            )

    return ApiTree(
        meta=InventoryMeta(sources_used=["url_list"] if endpoints else []),
        endpoints=endpoints,
    )


def load_txt_api_list_inventory(txt_path: Path, base_urls: list[str]) -> ApiTree:
    text = txt_path.read_text(encoding="utf-8")
    endpoints: list[Endpoint] = []

    for line in _iter_txt_lines(text):
        method, path_only, merged_query = _parse_api_line(line)
        for base in base_urls:
            inputs = path_template_params(path_only, "api_list")
            inputs.extend(_query_inputs(merged_query, "api_list"))
            endpoints.append(
                Endpoint(
                    method=method,
                    path=path_only,
                    base_url=base.rstrip("/"),
                    request_params=inputs,
                    sources=["api_list"],
                    kind="api",
                )
            )

    return ApiTree(
        meta=InventoryMeta(sources_used=["api_list"] if endpoints else []),
        endpoints=endpoints,
    )

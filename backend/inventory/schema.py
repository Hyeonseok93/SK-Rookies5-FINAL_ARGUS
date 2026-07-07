"""Canonical attack-surface map schema (ZAP-friendly)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qs, urlencode

InputLocation = Literal["path", "query", "body", "form", "header", "cookie"]
HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

SCHEMA_VERSION = "1.2"


@dataclass
class HeaderField:
    name: str
    sample: str | None = None
    role: str = "meta"  # input | auth | meta
    required: bool = False
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "role": self.role,
            "required": self.required,
            "sources": sorted(set(self.sources)),
        }
        if self.sample is not None:
            d["sample"] = self.sample
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HeaderField:
        return cls(
            name=data["name"],
            sample=data.get("sample"),
            role=data.get("role", "meta"),
            required=bool(data.get("required", False)),
            sources=list(data.get("sources", [])),
        )


@dataclass
class InputParam:
    in_: InputLocation
    name: str
    type: str = "string"
    required: bool = False
    sample: str | None = None
    role: str = "input"  # input | auth | meta
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "in": self.in_,
            "name": self.name,
            "type": self.type,
            "required": self.required,
            "role": self.role,
            "sources": sorted(set(self.sources)),
        }
        if self.sample is not None:
            d["sample"] = self.sample
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InputParam:
        return cls(
            in_=data["in"],
            name=data["name"],
            type=data.get("type", "string"),
            required=bool(data.get("required", False)),
            sample=data.get("sample"),
            role=data.get("role", "input"),
            sources=list(data.get("sources", [])),
        )


@dataclass
class Endpoint:
    method: str
    path: str
    base_url: str
    request_params: list[InputParam] = field(default_factory=list)
    response_params: list[InputParam] = field(default_factory=list)
    request_headers: list[HeaderField] = field(default_factory=list)
    response_headers: list[HeaderField] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    auth: list[str] = field(default_factory=list)
    kind: str = "api"  # api | frontend

    def __post_init__(self) -> None:
        import os
        if os.path.exists("/.dockerenv") and isinstance(self.base_url, str):
            self.base_url = self.base_url.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")

    @property
    def inputs(self) -> list[InputParam]:
        """Legacy aggregate used by stats/export."""
        return self.request_params + self.response_params

    @property
    def endpoint_id(self) -> str:
        base = self.base_url.rstrip("/")
        return f"{base}:{self.method.upper()}:{self.path}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.endpoint_id,
            "method": self.method.upper(),
            "path": self.path,
            "base_url": self.base_url.rstrip("/"),
            "kind": self.kind,
            "auth": sorted(set(self.auth)),
            "tags": sorted(set(self.tags)),
            "sources": sorted(set(self.sources)),
            "request_params": [i.to_dict() for i in self.request_params],
            "response_params": [i.to_dict() for i in self.response_params],
            "request_headers": [h.to_dict() for h in self.request_headers],
            "response_headers": [h.to_dict() for h in self.response_headers],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Endpoint:
        from inventory.merge import merge_header_fields, merge_inputs

        request_params = [InputParam.from_dict(i) for i in data.get("request_params", [])]
        response_params = [InputParam.from_dict(i) for i in data.get("response_params", [])]
        request_headers = [HeaderField.from_dict(h) for h in data.get("request_headers", [])]
        response_headers = [HeaderField.from_dict(h) for h in data.get("response_headers", [])]

        if not request_params and not response_params:
            for inp in [InputParam.from_dict(i) for i in data.get("inputs", [])]:
                if inp.in_ in ("header", "cookie"):
                    request_headers.append(
                        HeaderField(
                            name=inp.name,
                            sample=inp.sample,
                            role=inp.role if inp.role != "input" else ("auth" if inp.in_ == "cookie" else inp.role),
                            required=inp.required,
                            sources=list(inp.sources),
                        )
                    )
                else:
                    request_params.append(inp)

        return cls(
            method=data["method"],
            path=data["path"],
            base_url=data["base_url"],
            request_params=merge_inputs([], request_params),
            response_params=merge_inputs([], response_params),
            request_headers=merge_header_fields([], request_headers),
            response_headers=merge_header_fields([], response_headers),
            tags=list(data.get("tags", [])),
            sources=list(data.get("sources", [])),
            auth=list(data.get("auth", [])),
            kind=data.get("kind", "api"),
        )


@dataclass
class InventoryMeta:
    app_name: str = ""
    schema_version: str = SCHEMA_VERSION
    sources_used: list[str] = field(default_factory=list)
    sources_missing: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InventoryMeta:
        fields = cls.__dataclass_fields__
        return cls(**{k: v for k, v in data.items() if k in fields})


@dataclass
class ApiTree:
    meta: InventoryMeta
    endpoints: list[Endpoint] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta.to_dict(),
            "endpoints": [e.to_dict() for e in self.endpoints],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApiTree:
        meta = InventoryMeta.from_dict(data.get("meta", {}) or {})
        endpoints = [Endpoint.from_dict(e) for e in data.get("endpoints", [])]
        return cls(meta=meta, endpoints=endpoints)

    def save(self, path: str | Path) -> None:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> ApiTree:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def split_path_query(raw_path: str) -> tuple[str, dict[str, str]]:
    """'/foo?a=1&b=2' → ('/foo', {'a':'1','b':'2'})"""
    if "?" not in raw_path:
        return raw_path, {}
    path, qs = raw_path.split("?", 1)
    parsed = parse_qs(qs, keep_blank_values=True)
    query = {k: (v[0] if v else "") for k, v in parsed.items()}
    return path, query


def build_full_url(base_url: str, path: str, query: dict[str, str] | None = None) -> str:
    base = base_url.rstrip("/")
    p = path if path.startswith("/") else f"/{path}"
    url = f"{base}{p}"
    if query:
        url = f"{url}?{urlencode(query)}"
    return url

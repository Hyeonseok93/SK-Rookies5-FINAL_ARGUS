from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

BACKEND_ROOT = Path(__file__).resolve().parent.parent
ZAP_ROOT = BACKEND_ROOT.parent.parent


class MarkdownSourceConfig(BaseModel):
    enabled: bool = True
    path: str = ""
    include_frontend_routes: bool = False
    frontend_base_url: str | None = None


class OpenApiSourceConfig(BaseModel):
    enabled: bool = False
    path: str = ""
    base_url: str | None = None


class UrlListSourceConfig(BaseModel):
    enabled: bool = False
    path: str = "data/inventory-urls.json"


class InventoryConfig(BaseModel):
    markdown: MarkdownSourceConfig = Field(default_factory=MarkdownSourceConfig)
    openapi: OpenApiSourceConfig = Field(default_factory=OpenApiSourceConfig)
    url_list: UrlListSourceConfig = Field(default_factory=UrlListSourceConfig)
    base_urls: list[str] = Field(default_factory=list)


class TargetConfig(BaseModel):
    name: str
    base_url: str


class AppConfig(BaseModel):
    app_name: str = "argus"
    targets: list[TargetConfig] = Field(default_factory=list)
    inventory: InventoryConfig = Field(default_factory=InventoryConfig)


def resolve_path(path_str: str) -> Path:
    p = Path(path_str)
    if p.is_absolute():
        return p
    return (BACKEND_ROOT / p).resolve()


def load_config(config_path: Path | None = None) -> AppConfig:
    if config_path is None:
        env_path = os.environ.get("CONFIG_PATH")
        config_path = Path(env_path) if env_path else (BACKEND_ROOT / "config.yaml")
    if not config_path.is_file():
        return AppConfig()
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    
    # 도커 환경일 경우 localhost -> host.docker.internal 자동 치환
    if os.path.exists("/.dockerenv"):
        def replace_localhost(obj):
            if isinstance(obj, str):
                return obj.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")
            elif isinstance(obj, list):
                return [replace_localhost(item) for item in obj]
            elif isinstance(obj, dict):
                return {k: replace_localhost(v) for k, v in obj.items()}
            return obj
        raw = replace_localhost(raw)
                    
    return AppConfig.model_validate(raw)


def config_to_inventory_dict(cfg: AppConfig) -> dict:
    return {
        "app_name": cfg.app_name,
        "targets": [{"name": t.name, "base_url": t.base_url} for t in cfg.targets],
        "inventory": cfg.inventory.model_dump(),
    }

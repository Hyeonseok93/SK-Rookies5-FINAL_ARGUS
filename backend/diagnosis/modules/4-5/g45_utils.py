import json
from pathlib import Path
from typing import Any

NOISE_KEYS = {"timestamp", "traceId", "trace_id", "requestId", "request_id", "serverTime", "time", "createdAt", "updatedAt"}

def _read_api_tree(data_dir: Path) -> dict[str, Any] | None:
    for name in ["api-tree-verified.json", "api-tree-ready.json", "api-tree.json"]:
        path = data_dir / name
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"    [Error] Exception reading {name}: {e}")
    return None

def _extract_recursive(data: Any, result: dict[str, list[Any]]):
    if isinstance(data, dict):
        for k, v in data.items():
            k_lower = k.lower()
            if "id" in k_lower and isinstance(v, (int, str)) and v:
                result.setdefault(k, []).append(v)
            _extract_recursive(v, result)
    elif isinstance(data, list):
        for item in data:
            _extract_recursive(item, result)

def extract_ids_from_response(data: Any) -> dict[str, list[Any]]:
    result = {}
    _extract_recursive(data, result)
    for k in result:
        result[k] = list(set(result[k]))
    return result

def json_field_matches(data: Any, key: str, expected: str) -> bool:
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() == key.lower() and str(v) == expected:
                return True
            if json_field_matches(v, key, expected):
                return True
    elif isinstance(data, list):
        for item in data:
            if json_field_matches(item, key, expected):
                return True
    return False


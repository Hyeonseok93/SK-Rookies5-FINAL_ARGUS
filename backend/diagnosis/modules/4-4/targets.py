"""4-4 진단 입력 자료 로드"""

from __future__ import annotations

from typing import Any

from diagnosis.endpoint_auth_passes import load_login_report
from diagnosis.replay.normalize import collect_probe_base_urls, filter_endpoints_by_probe_bases, probe_base_keys
from inventory.load import load_api_tree


def load_targets(data_dir, raw_config: dict[str, Any]):
    tree = load_api_tree(data_dir)
    if tree is None:
        return None, [], [], None
    scoped = filter_endpoints_by_probe_bases(tree.endpoints, raw_config)
    bases = collect_probe_base_urls(raw_config)
    extra = [
        str(value).rstrip("/")
        for value in ((raw_config.get("diagnosis_4_4") or {}).get("extra_base_urls") or [])
        if str(value).strip()
    ]
    if extra:
        extra_keys = probe_base_keys(extra)
        known = {ep.endpoint_id for ep in scoped}
        scoped.extend(
            ep for ep in tree.endpoints
            if ep.endpoint_id not in known and probe_base_keys([ep.base_url]) & extra_keys
        )
        bases = list(dict.fromkeys([*bases, *extra]))
    if not bases:
        bases = sorted({ep.base_url.rstrip("/") for ep in scoped if ep.base_url})
    return tree, scoped, bases, load_login_report(data_dir, raw_config)

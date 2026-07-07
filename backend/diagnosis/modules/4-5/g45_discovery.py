import requests

import sys
from pathlib import Path
_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

from g45_auth import get_headers
from g45_utils import extract_ids_from_response
from g45_payloads import safe_body

def build_resource_inventory(account_token: str, endpoints: list[dict], base_url_global: str, logger=None) -> dict:
    inventory = {}
    headers = get_headers(account_token)
    
    for ep in endpoints:
        if ep.get("method", "GET").upper() != "GET":
            continue
        path = ep.get("path", "")
        # Skip if requires path params like {id} for discovery
        if "{" in path and "}" in path:
            continue
            
        url = ep.get("base_url", base_url_global) + path
        try:
            res = requests.get(url, headers=headers, timeout=3, verify=False)
            if res.status_code == 200:
                try:
                    data = res.json()
                    ids = extract_ids_from_response(data)
                    for k, v in ids.items():
                        inventory.setdefault(k, []).extend(v)
                except Exception as e:
                    print(f"    [Error] Exception parsing response from {url}: {e}")
        except Exception as e:
            print(f"    [Error] Exception hitting {url}: {e}")
            
    # Deduplicate globally
    for k in inventory:
        inventory[k] = list(set(inventory[k]))
    return inventory

def active_discovery_inventory(account_token: str, endpoints: list[dict], base_url_global: str, created_resources: list, logger=None) -> dict:
    inventory = {}
    headers = get_headers(account_token)
    
    for ep in endpoints:
        if ep.get("method", "POST").upper() != "POST":
            continue
        path = ep.get("path", "")
        if "{" in path and "}" in path:
            continue
            
        url = ep.get("base_url", base_url_global) + path
        body = safe_body(ep)
        try:
            res = requests.post(url, headers=headers, json=body, timeout=3, verify=False)
            if res.status_code in {200, 201}:
                try:
                    data = res.json()
                    ids = extract_ids_from_response(data)
                    for k, v in ids.items():
                        inventory.setdefault(k, []).extend(v)
                    # Track for cleanup
                    created_resources.append({"url": url, "method": "DELETE", "ids": ids})
                    if logger:
                        logger(f"    [Active Discovery] Created resource at {url} -> {ids}")
                except Exception as e:
                    print(f"    [Error] Exception parsing response from {url}: {e}")
        except Exception as e:
            print(f"    [Error] Exception hitting {url}: {e}")
            
    # Deduplicate globally
    for k in inventory:
        inventory[k] = list(set(inventory[k]))
    return inventory

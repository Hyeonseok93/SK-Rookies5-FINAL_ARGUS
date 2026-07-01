"""Probe request building tests."""

from __future__ import annotations

import json
from pathlib import Path

from inventory.probe_build import build_probe_request
from inventory.schema import ApiTree, Endpoint, HeaderField


def test_auth_cookie_wins_over_stored_sample():
    ep = Endpoint(
        method="POST",
        path="/api/v1/members/me/wallet/charge",
        base_url="http://localhost:5173",
        request_headers=[
            HeaderField(
                name="Cookie",
                role="auth",
                sample="accessToken=STALE",
                sources=["probe"],
            )
        ],
    )
    session = {
        "token": "FRESH_TOKEN",
        "delivery": "cookie",
        "cookie_name": "accessToken",
    }
    probe = build_probe_request(ep, account_auth=session)
    assert probe["headers"]["Cookie"] == "accessToken=FRESH_TOKEN"


def test_anonymous_skips_stored_cookie():
    ep = Endpoint(
        method="GET",
        path="/api/v1/members/me",
        base_url="http://localhost:8080",
        request_headers=[
            HeaderField(
                name="Cookie",
                role="auth",
                sample="accessToken=STALE",
                sources=["probe"],
            )
        ],
    )
    probe = build_probe_request(ep, account_auth=None)
    assert "Cookie" not in probe["headers"]


def test_empty_post_body_falls_back_to_braces():
    ep = Endpoint(
        method="POST",
        path="/api/v1/members/me/wallet/charge",
        base_url="http://localhost:8080",
    )
    probe = build_probe_request(ep)
    assert probe["body"] == "{}"


def test_tree_wallet_charge_uses_fresh_auth_not_sample():
    tree_path = Path(__file__).resolve().parents[1] / "data" / "api-tree.json"
    if not tree_path.is_file():
        return
    tree = ApiTree.from_dict(json.loads(tree_path.read_text(encoding="utf-8")))
    ep = next(
        e
        for e in tree.endpoints
        if e.path == "/api/v1/members/me/wallet/charge" and ":5173" in e.base_url
    )
    session = {"token": "NEW", "delivery": "cookie", "cookie_name": "accessToken"}
    probe = build_probe_request(ep, account_auth=session)
    assert probe["headers"]["Cookie"] == "accessToken=NEW"

"""Tests for cross-account identity leak assessment."""

from __future__ import annotations

from inventory.auth_identity import (
    cross_account_leak_assessment,
    is_cross_excluded_path,
    session_identity_tokens,
)


def test_version_root_excluded():
    assert is_cross_excluded_path("/api/v1")
    assert is_cross_excluded_path("/api/v2")
    assert not is_cross_excluded_path("/api/v1/members/me")


def test_generic_same_body_not_leak():
    generic = b'{"success":true,"data":{"content":[],"totalElements":0},"message":"ok"}' * 1
    assert len(generic) >= 48
    owner = {"email": "yerin@travel.com", "member_id": 1}
    other = {"email": "ondecar@travel.com", "member_id": 2}
    leaked, meta = cross_account_leak_assessment(generic, generic, owner, other, path="/api/v1/foo")
    assert not leaked
    assert meta["reason"] == "generic_response_no_owner_identity"


def test_api_v1_root_excluded():
    body = b'{"success":true,"data":{"email":"yerin@travel.com","id":1},"message":"x"}'
    owner = {"email": "yerin@travel.com", "member_id": 1}
    other = {"email": "ondecar@travel.com", "member_id": 2}
    leaked, meta = cross_account_leak_assessment(body, body, owner, other, path="/api/v1")
    assert not leaked
    assert meta["reason"] == "excluded_path"


def test_owner_identity_same_body_is_leak():
    body = b'{"success":true,"data":{"email":"yerin@travel.com","memberId":1,"wallet":5000}}'
    owner = {"email": "yerin@travel.com", "member_id": 1}
    other = {"email": "ondecar@travel.com", "member_id": 2}
    leaked, meta = cross_account_leak_assessment(
        body, body, owner, other, path="/api/v1/members/me/wallet"
    )
    assert leaked
    assert "yerin@travel.com" in meta.get("leak_tokens", [])


def test_different_bodies_not_leak():
    owner_body = b'{"success":true,"data":{"email":"yerin@travel.com","memberId":1}}'
    other_body = b'{"success":true,"data":{"email":"ondecar@travel.com","memberId":2}}'
    owner = {"email": "yerin@travel.com", "member_id": 1}
    other = {"email": "ondecar@travel.com", "member_id": 2}
    leaked, meta = cross_account_leak_assessment(
        owner_body, other_body, owner, other, path="/api/v1/members/me"
    )
    assert not leaked
    assert meta["reason"] == "body_mismatch"


def test_session_identity_tokens():
    tokens = session_identity_tokens({"email": "yerin@travel.com", "member_id": 7})
    assert "yerin@travel.com" in tokens
    assert "yerin" in tokens
    assert "7" in tokens

"""ARGUS login / register / me."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.auth_users import (
    create_user,
    find_user_by_username,
    issue_token,
    verify_password,
)
from app.deps import CurrentUser
from app.runtime_env import public_register_allowed

router = APIRouter(prefix="/auth", tags=["auth"])


class AuthCredentials(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=256)


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict[str, str]


class AuthUserResponse(BaseModel):
    id: str
    username: str
    created_at: str = ""


@router.post("/register", response_model=AuthTokenResponse)
def register(body: AuthCredentials) -> AuthTokenResponse:
    if not public_register_allowed():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Public registration is disabled. "
                "Set ARGUS_ALLOW_PUBLIC_REGISTER=true for local multi-user demos, "
                "or bootstrap users via ADMIN_USERNAME/ADMIN_PASSWORD."
            ),
        )
    try:
        user = create_user(body.username, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    token = issue_token({"id": user["id"], "username": user["username"]})
    return AuthTokenResponse(access_token=token, user=user)


@router.post("/login", response_model=AuthTokenResponse)
def login(body: AuthCredentials) -> AuthTokenResponse:
    user = find_user_by_username(body.username)
    if not user or not verify_password(body.password, str(user.get("password_hash") or "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    token = issue_token(user)
    return AuthTokenResponse(
        access_token=token,
        user={
            "id": user["id"],
            "username": user["username"],
            "created_at": user.get("created_at") or "",
        },
    )


@router.get("/me", response_model=AuthUserResponse)
def me(user: CurrentUser) -> AuthUserResponse:
    return AuthUserResponse(**user)

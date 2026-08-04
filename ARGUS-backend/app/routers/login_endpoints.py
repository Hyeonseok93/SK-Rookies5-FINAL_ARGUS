from __future__ import annotations

from fastapi import APIRouter

from app.deps import UserDataDir
from app.schemas import (
    LoginEndpointResolved,
    LoginEndpointsResponse,
    SaveLoginEndpointsRequest,
    SaveLoginEndpointsResponse,
)
from app.services.login_discovery_service import resolve_login_entries
from app.services.login_endpoints_service import load_login_endpoints, save_login_endpoints

router = APIRouter(prefix="/login-endpoints", tags=["login-endpoints"])


@router.get("", response_model=LoginEndpointsResponse)
def get_login_endpoints(data_dir: UserDataDir) -> LoginEndpointsResponse:
    data = load_login_endpoints(data_dir)
    resolved = [LoginEndpointResolved(**row) for row in resolve_login_entries(data_dir=data_dir)]
    return LoginEndpointsResponse(endpoints=data["endpoints"], resolved=resolved)


@router.put("", response_model=SaveLoginEndpointsResponse)
def put_login_endpoints(
    body: SaveLoginEndpointsRequest,
    data_dir: UserDataDir,
) -> SaveLoginEndpointsResponse:
    data = save_login_endpoints(data_dir, [e.model_dump() for e in body.endpoints])
    resolved = [LoginEndpointResolved(**row) for row in resolve_login_entries(data_dir=data_dir)]
    count = len(data["endpoints"])
    return SaveLoginEndpointsResponse(
        ok=True,
        endpoints=data["endpoints"],
        resolved=resolved,
        message=f"Saved {count} login endpoint(s).",
    )

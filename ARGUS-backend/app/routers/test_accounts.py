from __future__ import annotations

from fastapi import APIRouter

from app.schemas import SaveTestAccountsRequest, SaveTestAccountsResponse, TestAccountsResponse
from app.services.test_accounts_service import load_test_accounts, save_test_accounts

router = APIRouter(prefix="/test-accounts", tags=["test-accounts"])


@router.get("", response_model=TestAccountsResponse)
def get_test_accounts() -> TestAccountsResponse:
    data = load_test_accounts()
    return TestAccountsResponse(**data)


@router.put("", response_model=SaveTestAccountsResponse)
def put_test_accounts(body: SaveTestAccountsRequest) -> SaveTestAccountsResponse:
    data = save_test_accounts([a.model_dump() for a in body.accounts])
    filled = sum(1 for a in data["accounts"] if a.get("email"))
    return SaveTestAccountsResponse(
        ok=True,
        accounts=data["accounts"],
        message=f"Saved {filled} test account(s).",
    )

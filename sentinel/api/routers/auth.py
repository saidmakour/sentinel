from typing import Annotated

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from sqlalchemy.orm import Session

from sentinel.api.dependencies import get_session
from sentinel.api.schemas.auth import CurrentUserResponse
from sentinel.api.schemas.auth import LoginRequest
from sentinel.api.schemas.auth import TokenResponse
from sentinel.security.dependencies import CurrentUser
from sentinel.security.jwt import create_access_token
from sentinel.services.auth_service import AuthService

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=200,
)
def login(
    payload: LoginRequest,
    session: SessionDep,
) -> TokenResponse:

    service = AuthService(
        session,
    )

    user = service.authenticate(
        username=payload.username,
        password=payload.password,
    )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    access_token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    return TokenResponse(
        access_token=access_token,
    )


@router.get(
    "/me",
    response_model=CurrentUserResponse,
)
def get_me(
    current_user: CurrentUser,
) -> CurrentUserResponse:

    return CurrentUserResponse(
        id=current_user.id,
        username=current_user.username,
        is_active=current_user.is_active,
        is_admin=current_user.is_admin,
    )

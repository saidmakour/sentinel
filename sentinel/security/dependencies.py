from typing import Annotated

from fastapi import Depends
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from sentinel.api.dependencies import get_session
from sentinel.models.user import User
from sentinel.repositories.user_repository import UserRepository
from sentinel.security.jwt import JWTError
from sentinel.security.jwt import decode_access_token

security = HTTPBearer()

SessionDep = Annotated[
    Session,
    Depends(get_session),
]


def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials,
        Depends(security),
    ],
    session: SessionDep,
) -> User:

    try:
        payload = decode_access_token(
            credentials.credentials,
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    subject = payload.get("sub")

    if not isinstance(subject, str):
        raise HTTPException(
            status_code=401,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = int(subject)
    except ValueError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    repository = UserRepository(
        session,
    )

    user = repository.get_by_id(
        user_id,
    )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="Inactive user",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


CurrentUser = Annotated[
    User,
    Depends(get_current_user),
]


def get_current_admin(
    current_user: CurrentUser,
) -> User:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required",
        )

    return current_user


CurrentAdmin = Annotated[
    User,
    Depends(get_current_admin),
]

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from datetime import timedelta
from typing import Any

import jwt

from sentinel.config.settings import settings


class JWTError(Exception):
    """Base exception for JWT errors."""


def create_access_token(
    user_id: int,
    username: str,
) -> str:
    """
    Create a JWT access token for a user.
    """

    now = datetime.now(UTC)

    expires_at = now + timedelta(
        minutes=settings.api_access_token_expire_minutes,
    )

    payload: dict[str, Any] = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": expires_at,
    }

    token: str = jwt.encode(  # pyright: ignore[reportUnknownMemberType]
        payload,
        settings.api_jwt_secret,
        algorithm=settings.api_jwt_algorithm,
    )

    return token


def decode_access_token(
    token: str,
) -> dict[str, object]:
    """
    Decode and validate a JWT access token.
    """

    try:
        payload: dict[str, Any] = jwt.decode(  # pyright: ignore[reportUnknownMemberType]
            token,
            settings.api_jwt_secret,
            algorithms=[settings.api_jwt_algorithm],
        )

    except jwt.PyJWTError as exc:
        raise JWTError(
            "Invalid or expired access token",
        ) from exc

    return payload

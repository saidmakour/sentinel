from datetime import UTC
from datetime import datetime
from datetime import timedelta

import jwt
import pytest

from sentinel.config.settings import settings
from sentinel.security.jwt import JWTError
from sentinel.security.jwt import create_access_token
from sentinel.security.jwt import decode_access_token


def test_create_access_token() -> None:
    token = create_access_token(
        user_id=1,
        username="admin",
    )

    assert isinstance(token, str)
    assert token


def test_decode_access_token() -> None:
    token = create_access_token(
        user_id=42,
        username="admin",
    )

    payload = decode_access_token(
        token,
    )

    assert payload["sub"] == "42"
    assert payload["username"] == "admin"
    assert "iat" in payload
    assert "exp" in payload


def test_decode_access_token_rejects_invalid_token() -> None:
    with pytest.raises(JWTError):
        decode_access_token(
            "invalid-token",
        )


def test_decode_access_token_rejects_token_with_wrong_secret() -> None:
    now = datetime.now(UTC)

    token = jwt.encode(
        {
            "sub": "1",
            "username": "admin",
            "iat": now,
            "exp": now + timedelta(minutes=30),
        },
        "wrong-secret-for-testing-only-32-bytes",
        algorithm=settings.api_jwt_algorithm,
    )

    with pytest.raises(JWTError):
        decode_access_token(
            token,
        )


def test_decode_access_token_rejects_expired_token() -> None:
    now = datetime.now(UTC)

    token = jwt.encode(
        {
            "sub": "1",
            "username": "admin",
            "iat": now - timedelta(minutes=60),
            "exp": now - timedelta(minutes=30),
        },
        settings.api_jwt_secret,
        algorithm=settings.api_jwt_algorithm,
    )

    with pytest.raises(JWTError):
        decode_access_token(
            token,
        )

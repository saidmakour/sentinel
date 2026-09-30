from datetime import UTC
from datetime import datetime
from datetime import timedelta

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from sentinel.config.settings import settings
from sentinel.models.user import User
from sentinel.security.dependencies import get_current_admin
from sentinel.security.dependencies import get_current_user
from sentinel.security.jwt import create_access_token
from sentinel.services.auth_service import AuthService


def make_credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=token,
    )


def test_get_current_user_returns_user_for_valid_token(
    db_session,
) -> None:
    user = User(
        username="admin",
        password_hash="unused",
        is_active=True,
        is_admin=True,
    )

    db_session.add(user)
    db_session.flush()

    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    credentials = make_credentials(token)

    result = get_current_user(
        credentials,
        db_session,
    )

    assert result.id == user.id
    assert result.username == "admin"
    assert result.is_active is True
    assert result.is_admin is True


def test_get_current_user_rejects_invalid_token(
    db_session,
) -> None:
    credentials = make_credentials(
        "invalid-token",
    )

    try:
        get_current_user(
            credentials,
            db_session,
        )
    except HTTPException as exc:
        assert exc.status_code == 401
        assert exc.detail == "Invalid or expired access token"
        assert exc.headers == {
            "WWW-Authenticate": "Bearer",
        }
    else:
        raise AssertionError(
            "Expected HTTPException",
        )


def test_get_current_user_rejects_expired_token(
    db_session,
) -> None:
    now = datetime.now(UTC)

    payload = {
        "sub": "1",
        "username": "admin",
        "iat": now - timedelta(minutes=10),
        "exp": now - timedelta(minutes=5),
    }

    token = jwt.encode(
        payload,
        settings.api_jwt_secret,
        algorithm=settings.api_jwt_algorithm,
    )

    credentials = make_credentials(token)

    try:
        get_current_user(
            credentials,
            db_session,
        )
    except HTTPException as exc:
        assert exc.status_code == 401
        assert exc.detail == "Invalid or expired access token"
    else:
        raise AssertionError(
            "Expected HTTPException",
        )


def test_get_current_user_rejects_token_without_subject(
    db_session,
) -> None:
    now = datetime.now(UTC)

    payload = {
        "username": "admin",
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }

    token = jwt.encode(
        payload,
        settings.api_jwt_secret,
        algorithm=settings.api_jwt_algorithm,
    )

    credentials = make_credentials(token)

    try:
        get_current_user(
            credentials,
            db_session,
        )
    except HTTPException as exc:
        assert exc.status_code == 401
        assert exc.detail == "Invalid access token"
    else:
        raise AssertionError(
            "Expected HTTPException",
        )


def test_get_current_user_rejects_invalid_subject(
    db_session,
) -> None:
    now = datetime.now(UTC)

    payload = {
        "sub": "not-an-integer",
        "username": "admin",
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }

    token = jwt.encode(
        payload,
        settings.api_jwt_secret,
        algorithm=settings.api_jwt_algorithm,
    )

    credentials = make_credentials(token)

    try:
        get_current_user(
            credentials,
            db_session,
        )
    except HTTPException as exc:
        assert exc.status_code == 401
        assert exc.detail == "Invalid access token"
    else:
        raise AssertionError(
            "Expected HTTPException",
        )


def test_get_current_user_rejects_unknown_user(
    db_session,
) -> None:
    token = create_access_token(
        user_id=999,
        username="unknown",
    )

    credentials = make_credentials(token)

    try:
        get_current_user(
            credentials,
            db_session,
        )
    except HTTPException as exc:
        assert exc.status_code == 401
        assert exc.detail == "User not found"
    else:
        raise AssertionError(
            "Expected HTTPException",
        )


def test_get_current_user_rejects_inactive_user(
    db_session,
) -> None:
    user = User(
        username="disabled",
        password_hash="unused",
        is_active=False,
        is_admin=False,
    )

    db_session.add(user)
    db_session.flush()

    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    credentials = make_credentials(token)

    try:
        get_current_user(
            credentials,
            db_session,
        )
    except HTTPException as exc:
        assert exc.status_code == 401
        assert exc.detail == "Inactive user"
    else:
        raise AssertionError(
            "Expected HTTPException",
        )


def create_test_user(
    db_session: Session,
    username: str = "test-user",
    password: str = "TestPassword123!",
):
    service = AuthService(
        db_session,
    )

    user = service.create_user(
        username=username,
        password=password,
    )

    db_session.commit()
    db_session.refresh(user)

    return user


def test_get_current_admin_accepts_admin_user(
    db_session,
) -> None:
    user = create_test_user(
        db_session,
        username="admin",
    )

    user.is_admin = True

    result = get_current_admin(
        user,
    )

    assert result is user
    assert result.is_admin is True


def test_get_current_admin_rejects_non_admin_user(
    db_session,
) -> None:
    user = create_test_user(
        db_session,
        username="user",
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_admin(
            user,
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Admin privileges required"

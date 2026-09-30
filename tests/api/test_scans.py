from datetime import UTC
from datetime import datetime
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from sentinel.api.app import app
from sentinel.api.dependencies import get_session
from sentinel.dto.scan_comparison import ScanComparison
from sentinel.exceptions.scan import ScanNotFoundError
from sentinel.models.repository import Repository
from sentinel.models.scan import Scan
from sentinel.models.user import User
from sentinel.security.jwt import create_access_token
from sentinel.security.password import hash_password


def create_test_user(
    db_session: Session,
) -> User:
    user = User(
        username="scan-user",
        password_hash=hash_password("password"),
        is_active=True,
        is_admin=False,
    )

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    return user


def auth_headers(
    user: User,
) -> dict[str, str]:
    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    return {
        "Authorization": f"Bearer {token}",
    }


def test_compare_scan_returns_comparison(
    db_session: Session,
    monkeypatch,
) -> None:
    user = create_test_user(
        db_session,
    )
    app.dependency_overrides[get_session] = lambda: db_session

    comparison = ScanComparison(
        previous_scan_id=1,
        current_scan_id=2,
        added=[],
        resolved=[],
        unchanged=[],
    )

    service = MagicMock()

    service.compare_with_previous.return_value = comparison

    monkeypatch.setattr(
        "sentinel.api.routers.scans.ScanHistoryService",
        lambda session: service,
    )

    client = TestClient(
        app,
    )

    response = client.get("/scans/2/comparison", headers=auth_headers(user))

    assert response.status_code == 200

    data = response.json()

    assert data["previous_scan_id"] == 1
    assert data["current_scan_id"] == 2
    assert data["added_count"] == 0
    assert data["resolved_count"] == 0
    assert data["unchanged_count"] == 0

    service.compare_with_previous.assert_called_once_with(
        2,
    )

    app.dependency_overrides.clear()


def test_compare_scan_without_previous_returns_none(
    db_session: Session,
    monkeypatch,
) -> None:
    user = create_test_user(
        db_session,
    )
    app.dependency_overrides[get_session] = lambda: db_session

    service = MagicMock()

    service.compare_with_previous.return_value = None

    monkeypatch.setattr(
        "sentinel.api.routers.scans.ScanHistoryService",
        lambda session: service,
    )

    client = TestClient(
        app,
    )

    response = client.get(
        "/scans/10/comparison",
        headers=auth_headers(user),
    )

    assert response.status_code == 200
    assert response.json() is None

    service.compare_with_previous.assert_called_once_with(
        10,
    )

    app.dependency_overrides.clear()


def test_list_repository_scan_history(
    db_session,
) -> None:
    user = create_test_user(
        db_session,
    )
    repository = Repository(
        id=1,
        application_id=1,
        name="test-repository",
        local_path="/tmp/project",
        language="python",
    )

    scan = Scan(
        id=1,
        repository_id=1,
        profile_name="default",
        status="success",
        started_at=datetime.now(UTC),
    )

    db_session.add(
        repository,
    )

    db_session.add(
        scan,
    )

    db_session.commit()

    app.dependency_overrides[get_session] = lambda: db_session

    client = TestClient(
        app,
    )

    response = client.get(
        "/scans/repositories/1/history",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == 1
    assert data[0]["repository_id"] == 1
    assert data[0]["profile_name"] == "default"

    app.dependency_overrides.clear()


def test_compare_scan_with_previous_scan(
    db_session,
) -> None:

    user = create_test_user(
        db_session,
    )

    repository = Repository(
        id=1,
        application_id=1,
        name="test-repository",
        local_path="/tmp/project",
        language="python",
    )

    previous = Scan(
        id=1,
        repository_id=1,
        profile_name="default",
        status="success",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    current = Scan(
        id=2,
        repository_id=1,
        profile_name="default",
        status="success",
        started_at=datetime(2026, 2, 1, tzinfo=UTC),
    )

    db_session.add_all(
        [
            repository,
            previous,
            current,
        ],
    )

    db_session.commit()

    app.dependency_overrides[get_session] = lambda: db_session

    client = TestClient(
        app,
    )

    response = client.get(
        "/scans/2/comparison",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["previous_scan_id"] == 1
    assert data["current_scan_id"] == 2

    app.dependency_overrides.clear()


def test_compare_scan_returns_404_when_scan_not_found(
    client: TestClient,
    db_session: Session,
    monkeypatch,
) -> None:

    user = create_test_user(
        db_session,
    )

    def raise_not_found(
        self,
        scan_id: int,
    ):
        raise ScanNotFoundError(
            f"Scan '{scan_id}' not found",
        )

    monkeypatch.setattr(
        "sentinel.services.scan_history_service.ScanHistoryService.compare_with_previous",
        raise_not_found,
    )

    response = client.get(
        "/scans/999/comparison",
        headers=auth_headers(user),
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Scan '999' not found",
    }

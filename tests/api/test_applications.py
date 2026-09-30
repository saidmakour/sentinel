from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from sentinel.models.application import Application
from sentinel.security.jwt import create_access_token
from sentinel.services.auth_service import AuthService


def authenticate_client(
    client: TestClient,
    db_session: Session,
    username: str = "test-user",
    password: str = "TestPassword123!",
) -> None:
    service = AuthService(
        db_session,
    )

    user = service.create_user(
        username=username,
        password=password,
    )
    user.is_admin = True
    db_session.commit()

    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    client.headers.update(
        {
            "Authorization": f"Bearer {token}",
        },
    )


def test_list_applications_requires_authentication(
    client: TestClient,
) -> None:

    response = client.get(
        "/applications",
    )

    assert response.status_code == 401


def test_list_applications_empty(
    client: TestClient,
    db_session: Session,
) -> None:

    authenticate_client(
        client,
        db_session,
    )
    response = client.get(
        "/applications",
    )

    assert response.status_code == 200
    assert response.json() == []


def test_get_application_not_found(
    client: TestClient,
    db_session: Session,
) -> None:
    authenticate_client(
        client,
        db_session,
    )

    response = client.get(
        "/applications/999999",
    )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Application not found",
    }


def test_get_application(
    client: TestClient,
    db_session: Session,
) -> None:
    authenticate_client(
        client,
        db_session,
    )

    application = Application(
        name="Test Application",
        description="Application for API test",
        owner="Security",
        criticality=3,
    )

    db_session.add(application)
    db_session.commit()
    db_session.refresh(application)

    response = client.get(
        f"/applications/{application.id}",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == application.id
    assert data["name"] == "Test Application"


def test_create_application(
    client: TestClient,
    db_session: Session,
) -> None:
    authenticate_client(
        client,
        db_session,
    )
    response = client.post(
        "/applications",
        json={
            "name": "Sentinel",
            "description": "Vulnerability platform",
            "owner": "Security",
            "criticality": 4,
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["name"] == "Sentinel"
    assert data["description"] == "Vulnerability platform"
    assert data["owner"] == "Security"
    assert data["criticality"] == 4
    assert data["enabled"] is True


def test_create_application_duplicate(
    client: TestClient,
    db_session: Session,
) -> None:
    authenticate_client(
        client,
        db_session,
    )
    payload = {
        "name": "Sentinel",
        "description": "Vulnerability platform",
        "owner": "Security",
        "criticality": 4,
    }

    first = client.post(
        "/applications",
        json=payload,
    )

    assert first.status_code == 201

    second = client.post(
        "/applications",
        json=payload,
    )

    assert second.status_code == 409
    assert second.json() == {
        "detail": "Application 'Sentinel' already exists",
    }


def test_create_application_invalid_criticality(
    client: TestClient,
    db_session: Session,
) -> None:

    authenticate_client(
        client,
        db_session,
    )
    response = client.post(
        "/applications",
        json={
            "name": "Invalid",
            "description": "Test",
            "owner": "Security",
            "criticality": 10,
        },
    )

    assert response.status_code == 422


def test_update_application(
    client: TestClient,
    db_session: Session,
) -> None:
    authenticate_client(
        client,
        db_session,
    )
    application = Application(
        name="Old Name",
        description="Old description",
        owner="Old owner",
        criticality=2,
    )

    db_session.add(application)
    db_session.commit()
    db_session.refresh(application)

    response = client.patch(
        f"/applications/{application.id}",
        json={
            "name": "New Name",
            "description": "New description",
            "owner": "Security",
            "criticality": 4,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["name"] == "New Name"
    assert data["description"] == "New description"
    assert data["owner"] == "Security"
    assert data["criticality"] == 4


def test_update_application_not_found(
    client: TestClient,
    db_session: Session,
) -> None:

    authenticate_client(
        client,
        db_session,
    )
    response = client.patch(
        "/applications/999999",
        json={
            "name": "Unknown",
        },
    )

    assert response.status_code == 404


def test_delete_application(
    client: TestClient,
    db_session: Session,
) -> None:

    authenticate_client(
        client,
        db_session,
    )
    application = Application(
        name="To Delete",
        description="Temporary",
        owner="Security",
        criticality=3,
    )

    db_session.add(application)
    db_session.commit()
    db_session.refresh(application)

    response = client.delete(
        f"/applications/{application.id}",
    )

    assert response.status_code == 204

    deleted = (
        db_session.query(Application)
        .filter(
            Application.id == application.id,
        )
        .first()
    )

    assert deleted is None


def test_delete_application_not_found(
    client: TestClient,
    db_session: Session,
) -> None:
    authenticate_client(
        client,
        db_session,
    )
    response = client.delete(
        "/applications/999999",
    )

    assert response.status_code == 404

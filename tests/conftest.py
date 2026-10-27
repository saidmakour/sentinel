import os
from collections.abc import Generator
from pathlib import Path
from dotenv import load_dotenv
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from sentinel.api.app import app
from sentinel.api.dependencies import get_session
from sentinel.database.base import Base
from sentinel.profiles.default import DefaultProfile
from sentinel.security.jwt import create_access_token
from sentinel.services.auth_service import AuthService

# Import des modèles pour enregistrer les tables


PROJECT_ROOT = Path(__file__).resolve().parents[1]

load_dotenv(
    PROJECT_ROOT / ".env.test",
    override=True,
)

@pytest.fixture
def db_session() -> Session:

    engine = create_engine(
        "sqlite://",
        connect_args={
            "check_same_thread": False,
        },
        poolclass=StaticPool,
    )
    Base.metadata.create_all(
        engine,
    )

    session_factory = sessionmaker(
        bind=engine,
    )

    session = session_factory()

    try:
        yield session

    finally:
        session.close()
        Base.metadata.drop_all(
            engine,
        )


@pytest.fixture
def cli_session_factory(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    test_session_factory = sessionmaker(
        bind=engine,
        expire_on_commit=False,
    )

    # À adapter au module qui contient réellement les commandes user.
    monkeypatch.setattr(
        "sentinel.cli.user_cli.SessionLocal",
        test_session_factory,
    )

    yield test_session_factory

    Base.metadata.drop_all(engine)
    engine.dispose()
    
@pytest.fixture
def temp_project(tmp_path: Path) -> Path:
    """
    Create a temporary project directory.
    """
    return tmp_path


@pytest.fixture
def create_file():
    """
    Helper fixture to create files in tests.
    """

    def _create(
        project: Path,
        filename: str,
        content: str,
    ) -> Path:

        file = project / filename

        file.write_text(
            content,
            encoding="utf-8",
        )

        return file

    return _create


@pytest.fixture
def default_profile() -> DefaultProfile:
    return DefaultProfile()


@pytest.fixture
def client(
    db_session: Session,
) -> Generator[TestClient]:
    """
    FastAPI test client using test database session.
    """

    def override_get_session() -> Generator[Session]:
        yield db_session

    app.dependency_overrides[get_session] = override_get_session

    client = TestClient(app)

    yield client

    app.dependency_overrides.clear()


def authenticate_client(
    client: TestClient,
    db_session: Session,
    *,
    is_admin: bool = False,
    username: str = "test-user",
    password: str = "TestPassword123!",
) -> None:
    service = AuthService(
        db_session,
    )

    user = service.create_user(
        username=username,
        password=password,
        is_admin=is_admin,
    )

    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    client.headers.update(
        {
            "Authorization": f"Bearer {token}",
        },
    )

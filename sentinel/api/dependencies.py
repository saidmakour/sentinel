from collections.abc import Generator

from sqlalchemy.orm import Session

from sentinel.database.session import SessionLocal


def get_session() -> Generator[Session]:
    session = SessionLocal()

    try:
        yield session
    finally:
        session.close()

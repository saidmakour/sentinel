from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker

from sentinel.database.engine import engine

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)


@contextmanager
def session_scope() -> Generator[Session]:
    """
    Transaction scope.

    Commit automatiquement si tout se passe bien.
    Rollback en cas d'exception.
    """

    session = SessionLocal()

    try:
        yield session
        session.commit()

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()

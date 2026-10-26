from sentinel.database.base import Base
from sentinel.database.engine import engine


def create_database() -> None:
    """
    Create all ORM tables.
    """

    Base.metadata.create_all(
        bind=engine,
    )

# tests/repositories/test_base_repository.py

from unittest.mock import Mock

from sentinel.repositories.base import BaseRepository


def test_base_repository_stores_session() -> None:
    session = Mock()

    repository = BaseRepository(session=session)

    assert repository.session is session

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from sentinel.database.session import session_scope


def test_session_scope_commits_on_success():
    fake_session = MagicMock()

    with patch(
        "sentinel.database.session.SessionLocal", return_value=fake_session
    ):
        with session_scope() as session:
            assert session is fake_session

        fake_session.commit.assert_called_once()
        fake_session.rollback.assert_not_called()
        fake_session.close.assert_called_once()


def test_session_scope_rolls_back_on_exception():
    fake_session = MagicMock()

    with patch(
        "sentinel.database.session.SessionLocal", return_value=fake_session
    ):
        with pytest.raises(ValueError, match="boom"):
            with session_scope():
                raise ValueError("boom")

        fake_session.commit.assert_not_called()
        fake_session.rollback.assert_called_once()
        fake_session.close.assert_called_once()


def test_session_scope_always_closes_session():
    fake_session = MagicMock()

    with patch(
        "sentinel.database.session.SessionLocal", return_value=fake_session
    ):
        with session_scope():
            pass

        fake_session.close.assert_called_once()

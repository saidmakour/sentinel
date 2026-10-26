from unittest.mock import patch

from sentinel.database.init_db import create_database


def test_create_database_calls_create_all():
    with (
        patch(
            "sentinel.database.init_db.Base.metadata.create_all"
        ) as mock_create_all,
        patch("sentinel.database.init_db.engine", new="fake-engine"),
    ):
        create_database()

        mock_create_all.assert_called_once_with(bind="fake-engine")

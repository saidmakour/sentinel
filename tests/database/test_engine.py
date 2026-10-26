import importlib
import sys
from types import SimpleNamespace
from unittest.mock import patch

from sentinel.database.engine import engine


def test_engine_exists():
    assert engine is not None


def test_engine_is_created_with_expected_settings():
    module_name = "sentinel.database.engine"

    if module_name in sys.modules:
        del sys.modules[module_name]

    fake_settings = SimpleNamespace(database_url="sqlite:///test.db")

    with (
        patch("sqlalchemy.create_engine") as mock_create_engine,
        patch("sentinel.config.settings.settings", fake_settings),
    ):
        import sentinel.database.engine as engine_module

        importlib.reload(engine_module)

        mock_create_engine.assert_called_with(
            "sqlite:///test.db",
            future=True,
            echo=False,
            pool_pre_ping=True,
        )

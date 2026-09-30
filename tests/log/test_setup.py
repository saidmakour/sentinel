import logging
from pathlib import Path
from unittest.mock import patch

from sentinel.log.formatter import SentinelLogFormatter
from sentinel.log.setup import _get_log_level
from sentinel.log.setup import setup_logging


def test_setup_logging_uses_debug_level_when_debug_enabled(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(
        "sentinel.log.setup.settings.logs_dir",
        str(tmp_path),
    )
    monkeypatch.setattr(
        "sentinel.log.setup.settings.debug",
        True,
    )
    monkeypatch.setattr(
        "sentinel.log.setup.settings.log_level",
        "INFO",
    )

    setup_logging()

    root = logging.getLogger()

    assert root.level == logging.DEBUG


def test_setup_logging_uses_configured_log_level_when_debug_disabled(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(
        "sentinel.log.setup.settings.logs_dir",
        str(tmp_path),
    )
    monkeypatch.setattr(
        "sentinel.log.setup.settings.debug",
        False,
    )
    monkeypatch.setattr(
        "sentinel.log.setup.settings.log_level",
        "WARNING",
    )

    setup_logging()

    root = logging.getLogger()

    assert root.level == logging.WARNING


def test_setup_logging_falls_back_to_info_for_unknown_log_level(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(
        "sentinel.log.setup.settings.logs_dir",
        str(tmp_path),
    )
    monkeypatch.setattr(
        "sentinel.log.setup.settings.debug",
        False,
    )
    monkeypatch.setattr(
        "sentinel.log.setup.settings.log_level",
        "INVALID",
    )

    setup_logging()

    root = logging.getLogger()

    assert root.level == logging.INFO


def test_get_log_level_returns_debug_when_debug_is_enabled() -> None:
    with patch(
        "sentinel.log.setup.settings.debug",
        True,
    ):
        assert _get_log_level() == logging.DEBUG


def test_get_log_level_returns_settings_log_level() -> None:
    with (
        patch(
            "sentinel.log.setup.settings.debug",
            False,
        ),
        patch(
            "sentinel.log.setup.settings.log_level",
            "WARNING",
        ),
    ):
        assert _get_log_level() == logging.WARNING


def test_get_log_level_is_case_insensitive() -> None:
    with (
        patch(
            "sentinel.log.setup.settings.debug",
            False,
        ),
        patch(
            "sentinel.log.setup.settings.log_level",
            "error",
        ),
    ):
        assert _get_log_level() == logging.ERROR


def test_get_log_level_defaults_to_info_for_invalid_level() -> None:
    with (
        patch(
            "sentinel.log.setup.settings.debug",
            False,
        ),
        patch(
            "sentinel.log.setup.settings.log_level",
            "INVALID",
        ),
    ):
        assert _get_log_level() == logging.INFO


def test_setup_logging_creates_log_directory(
    tmp_path: Path,
) -> None:
    log_dir = tmp_path / "logs"

    with patch(
        "sentinel.log.setup.settings.logs_dir",
        str(log_dir),
    ):
        setup_logging()

    assert log_dir.exists()
    assert log_dir.is_dir()


def test_setup_logging_creates_log_file(
    tmp_path: Path,
) -> None:
    log_dir = tmp_path / "logs"

    with patch(
        "sentinel.log.setup.settings.logs_dir",
        str(log_dir),
    ):
        setup_logging()

    log_file = log_dir / "sentinel.log"

    assert log_file.exists()
    assert log_file.is_file()


def test_setup_logging_configures_root_logger() -> None:
    with (
        patch(
            "sentinel.log.setup.settings.debug",
            False,
        ),
        patch(
            "sentinel.log.setup.settings.log_level",
            "WARNING",
        ),
    ):
        setup_logging()

    root = logging.getLogger()

    assert root.level == logging.WARNING


def test_setup_logging_configures_handlers(
    tmp_path: Path,
) -> None:
    log_dir = tmp_path / "logs"

    with (
        patch(
            "sentinel.log.setup.settings.logs_dir",
            str(log_dir),
        ),
        patch(
            "sentinel.log.setup.settings.debug",
            False,
        ),
        patch(
            "sentinel.log.setup.settings.log_level",
            "INFO",
        ),
    ):
        setup_logging()

    root = logging.getLogger()

    assert len(root.handlers) == 2

    handler_types = {type(handler) for handler in root.handlers}

    assert logging.StreamHandler in handler_types
    assert logging.FileHandler in handler_types


def test_setup_logging_sets_handler_levels(
    tmp_path: Path,
) -> None:
    log_dir = tmp_path / "logs"

    with (
        patch(
            "sentinel.log.setup.settings.logs_dir",
            str(log_dir),
        ),
        patch(
            "sentinel.log.setup.settings.debug",
            False,
        ),
        patch(
            "sentinel.log.setup.settings.log_level",
            "ERROR",
        ),
    ):
        setup_logging()

    root = logging.getLogger()

    assert all(handler.level == logging.ERROR for handler in root.handlers)


def test_setup_logging_uses_sentinel_formatter(
    tmp_path: Path,
) -> None:
    log_dir = tmp_path / "logs"

    with patch(
        "sentinel.log.setup.settings.logs_dir",
        str(log_dir),
    ):
        setup_logging()

    root = logging.getLogger()

    assert all(
        isinstance(
            handler.formatter,
            SentinelLogFormatter,
        )
        for handler in root.handlers
    )

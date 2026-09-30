from logging import Logger

from sentinel.log.logger import get_logger


def test_get_logger_returns_logger() -> None:
    logger = get_logger(
        "sentinel.test",
    )

    assert isinstance(
        logger,
        Logger,
    )


def test_get_logger_returns_logger_with_expected_name() -> None:
    logger = get_logger(
        "sentinel.test",
    )

    assert logger.name == "sentinel.test"


def test_get_logger_returns_same_logger_for_same_name() -> None:
    first = get_logger(
        "sentinel.test",
    )

    second = get_logger(
        "sentinel.test",
    )

    assert first is second

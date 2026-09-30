from __future__ import annotations

import logging
from pathlib import Path

from sentinel.config.settings import settings
from sentinel.log.formatter import SentinelLogFormatter


def _get_log_level() -> int:
    """
    Return the configured logging level.
    """

    if settings.debug:
        return logging.DEBUG

    level_name = settings.log_level.upper()

    return getattr(
        logging,
        level_name,
        logging.INFO,
    )


def setup_logging() -> None:
    """
    Configure Sentinel logging.
    """

    log_dir = Path(
        settings.logs_dir,
    )

    log_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    level = _get_log_level()

    formatter = SentinelLogFormatter()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(
        level,
    )
    console_handler.setFormatter(
        formatter,
    )

    file_handler = logging.FileHandler(
        log_dir / "sentinel.log",
        encoding="utf-8",
    )
    file_handler.setLevel(
        level,
    )
    file_handler.setFormatter(
        formatter,
    )

    logging.basicConfig(
        level=level,
        handlers=[
            console_handler,
            file_handler,
        ],
        force=True,
    )

from __future__ import annotations

import logging
from logging import Logger


def get_logger(
    name: str,
) -> Logger:
    """
    Return a configured logger.
    """
    return logging.getLogger(
        name,
    )

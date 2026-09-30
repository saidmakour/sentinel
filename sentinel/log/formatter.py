from __future__ import annotations

import logging


class SentinelLogFormatter(logging.Formatter):
    """
    Formatter used by Sentinel logging handlers.
    """

    def __init__(self) -> None:
        super().__init__(
            fmt=("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"),
            datefmt="%Y-%m-%d %H:%M:%S",
        )

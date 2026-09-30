from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType
from typing import Self


@dataclass
class GitAuthContext:
    environment: dict[str, str] | None = None
    cleanup: Callable[[], None] | None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self.cleanup is not None:
            self.cleanup()

        self.environment = None
        self.cleanup = None

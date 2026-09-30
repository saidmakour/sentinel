from __future__ import annotations

from sentinel.exceptions.source import NoSourceAvailableError
from sentinel.log.logger import get_logger
from sentinel.models.repository import Repository
from sentinel.sources.base import BaseSource
from sentinel.sources.git.source import GitSource
from sentinel.sources.local import LocalSource

logger = get_logger(__name__)


class SourceRegistry:
    def __init__(
        self,
    ) -> None:
        self.sources: list[BaseSource] = [
            LocalSource(),
            GitSource(),
        ]

    def create(
        self,
        repository: Repository,
    ) -> BaseSource:

        for source in self.sources:
            if source.supports(repository):
                return source

        logger.error(
            "No source available: repository=%s",
            repository.name,
        )

        raise NoSourceAvailableError(
            "No source available.",
        )

from __future__ import annotations

from sentinel.log.logger import get_logger
from sentinel.models.repository import Repository
from sentinel.sources.prepared import PreparedSource
from sentinel.sources.registry import SourceRegistry

logger = get_logger(__name__)


class SourceService:
    def __init__(
        self,
        registry: SourceRegistry | None = None,
    ) -> None:
        self.registry = registry or SourceRegistry()

    def prepare(
        self,
        repository: Repository,
        forge_name: str | None = None,
    ) -> PreparedSource:

        logger.debug(
            "Preparing source: repository=%s forge=%s",
            repository.name,
            forge_name,
        )

        source = self.registry.create(
            repository,
        )

        logger.debug(
            "Source selected: repository=%s source=%s",
            repository.name,
            type(source).__name__,
        )

        prepared_source = source.prepare(
            repository,
            forge_name=forge_name,
        )

        logger.debug(
            "Source prepared: repository=%s source_type=%s "
            "reference=%s branch=%s commit=%s path=%s",
            repository.name,
            prepared_source.source_type,
            prepared_source.reference,
            prepared_source.branch,
            prepared_source.commit,
            prepared_source.path,
        )

        return prepared_source

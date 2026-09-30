from pathlib import Path

from sentinel.enums.source_type import SourceType
from sentinel.exceptions.source import SourcePreparationError
from sentinel.models.repository import Repository
from sentinel.sources.base import BaseSource
from sentinel.sources.prepared import PreparedSource


class LocalSource(BaseSource):
    def supports(
        self,
        repository: Repository,
    ) -> bool:
        return not repository.remote_url

    def prepare(
        self,
        repository: Repository,
        forge_name: str | None = None,
    ) -> PreparedSource:

        path = Path(repository.local_path)
        if not path.exists():
            raise SourcePreparationError(f"Local source not found: {path}")

        return PreparedSource(
            path=path,
            source_type=SourceType.LOCAL,
            reference=repository.local_path,
        )

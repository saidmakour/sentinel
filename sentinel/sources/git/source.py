from __future__ import annotations

from pathlib import Path

from sentinel.config.settings import Settings
from sentinel.enums.source_type import SourceType
from sentinel.exceptions.source import InvalidRepositoryError
from sentinel.log.logger import get_logger
from sentinel.models.repository import Repository
from sentinel.sources.base import BaseSource
from sentinel.sources.git.client import GitClient
from sentinel.sources.git.credentials_provider import GitCredentialsProvider
from sentinel.sources.git.forge_registry_factory import GitForgeRegistryFactory
from sentinel.sources.git.forge_resolver import GitForgeResolver
from sentinel.sources.prepared import PreparedSource

logger = get_logger(__name__)


class GitSource(BaseSource):
    def __init__(
        self,
        client: GitClient | None = None,
        credentials_provider: GitCredentialsProvider | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or Settings()

        self.client = client or GitClient()

        if credentials_provider is not None:
            self.credentials_provider = credentials_provider
        else:
            registry = GitForgeRegistryFactory.create(
                self.settings,
            )

            resolver = GitForgeResolver(
                registry=registry,
                settings=self.settings,
            )

            self.credentials_provider = GitCredentialsProvider(
                resolver=resolver,
            )

    def supports(
        self,
        repository: Repository,
    ) -> bool:
        return bool(repository.remote_url)

    def prepare(
        self,
        repository: Repository,
        forge_name: str | None = None,
    ) -> PreparedSource:

        path = Path(
            repository.local_path,
        )

        credentials = self.credentials_provider.get(
            repository.remote_url,
            forge_name=forge_name,
        )
        logger.debug(
            "Preparing Git repository: name=%s path=%s remote=%s forge=%s",
            repository.name,
            path,
            repository.remote_url,
            forge_name,
        )

        if self.client.is_repository(path):
            logger.debug(
                "Existing Git repository detected: path=%s",
                path,
            )

            current_remote = self.client.get_remote_url(
                path,
            )

            if current_remote != repository.remote_url:
                logger.error(
                    "Git repository remote mismatch: "
                    "path=%s expected=%s actual=%s",
                    path,
                    repository.remote_url,
                    current_remote,
                )

                raise InvalidRepositoryError(
                    "The existing repository remote "
                    "does not match the requested "
                    "remote URL.",
                )

            logger.debug(
                "Pulling Git repository: path=%s",
                path,
            )

            self.client.pull(
                path,
                auth_method=repository.auth_method,
                credentials=credentials,
            )

        else:
            logger.debug(
                "Cloning Git repository: remote=%s path=%s",
                repository.remote_url,
                path,
            )

            self.client.clone(
                repository.remote_url,
                path,
                auth_method=repository.auth_method,
                credentials=credentials,
            )

        if repository.default_branch:
            logger.debug(
                "Checking out Git branch: path=%s branch=%s",
                path,
                repository.default_branch,
            )

            self.client.checkout(
                path,
                repository.default_branch,
            )
        else:
            logger.debug(
                "Using Git default branch: path=%s",
                path,
            )

        prepared_source = PreparedSource(
            path=path,
            source_type=SourceType.GIT,
            reference=self.client.get_remote_url(
                path,
            ),
            branch=self.client.get_current_branch(
                path,
            ),
            commit=self.client.get_current_commit(
                path,
            ),
        )

        logger.debug(
            "Git repository prepared: path=%s branch=%s commit=%s",
            prepared_source.path,
            prepared_source.branch,
            prepared_source.commit,
        )

        return prepared_source

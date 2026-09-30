from __future__ import annotations

from pathlib import Path

from git import Repo
from git.exc import GitCommandError
from git.exc import (
    InvalidGitRepositoryError as GitPythonInvalidRepositoryError,
)

from sentinel.dto.git_credentials import GitCredentials
from sentinel.enums.git_auth_method import GitAuthMethod
from sentinel.exceptions.source import GitCheckoutError
from sentinel.exceptions.source import GitCloneError
from sentinel.exceptions.source import GitPullError
from sentinel.exceptions.source import InvalidRepositoryError
from sentinel.log.logger import get_logger
from sentinel.sources.git.authentication.factory import GitAuthenticatorFactory

logger = get_logger(__name__)


class GitClient:
    def __init__(
        self,
        authenticator_factory: GitAuthenticatorFactory | None = None,
    ) -> None:
        self.authenticator_factory = (
            authenticator_factory or GitAuthenticatorFactory()
        )

    def clone(
        self,
        url: str,
        destination: Path,
        auth_method: GitAuthMethod = GitAuthMethod.NONE,
        credentials: GitCredentials | None = None,
    ) -> Path:

        authenticator = self.authenticator_factory.create(
            auth_method,
        )

        context = authenticator.prepare(
            credentials,
        )

        try:
            with context:
                Repo.clone_from(
                    url,
                    destination,
                    env=context.environment,
                )

        except GitCommandError as exc:
            logger.exception(
                "Git clone failed: url=%s destination=%s",
                url,
                destination,
            )
            raise GitCloneError(
                str(exc),
            ) from exc

        return destination

    def pull(
        self,
        repository: Path,
        auth_method: GitAuthMethod = GitAuthMethod.NONE,
        credentials: GitCredentials | None = None,
    ) -> None:
        authenticator = self.authenticator_factory.create(
            auth_method,
        )

        context = authenticator.prepare(
            credentials,
        )

        try:
            with context:
                repo = self._get_repository(
                    repository,
                )

                repo.git.fetch(
                    "--prune",
                    "origin",
                    env=context.environment,
                )

                branch = repo.active_branch.name

                repo.git.reset(
                    "--hard",
                    f"origin/{branch}",
                    env=context.environment,
                )

        except GitCommandError as exc:
            logger.exception(
                "Git pull failed: path=%s",
                repository,
            )
            raise GitPullError(
                str(exc),
            ) from exc

    def checkout(
        self,
        repository: Path,
        branch: str,
    ) -> None:

        try:
            repo = self._get_repository(
                repository,
            )

            repo.git.checkout(
                branch,
            )

        except GitCommandError as exc:
            logger.exception(
                "Git checkout failed: path=%s branch=%s",
                repository,
                branch,
            )
            raise GitCheckoutError(
                str(exc),
            ) from exc

    def exists(
        self,
        repository: Path,
    ) -> bool:
        return repository.exists()

    def is_repository(
        self,
        repository: Path,
    ) -> bool:

        if not repository.is_dir():
            return False

        try:
            Repo(
                repository,
            )
        except GitPythonInvalidRepositoryError:
            return False

        return True

    def _get_repository(
        self,
        repository: Path,
    ) -> Repo:

        try:
            return Repo(
                repository,
            )

        except GitPythonInvalidRepositoryError as exc:
            logger.exception(
                "Invalid Git repository: path=%s",
                repository,
            )
            raise InvalidRepositoryError(
                str(exc),
            ) from exc

    def get_remote_url(
        self,
        repository: Path,
    ) -> str:

        repo = self._get_repository(
            repository,
        )

        return repo.remote().url

    def get_current_branch(
        self,
        repository: Path,
    ) -> str:

        repo = self._get_repository(
            repository,
        )

        return repo.active_branch.name

    def get_current_commit(
        self,
        repository: Path,
    ) -> str:

        repo = self._get_repository(
            repository,
        )

        return repo.head.commit.hexsha

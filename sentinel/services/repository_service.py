from pathlib import Path

from sqlalchemy.orm import Session

from sentinel.enums.git_auth_method import GitAuthMethod
from sentinel.exceptions.repository import RepositoryApplicationNotFoundError
from sentinel.exceptions.repository import RepositoryNameAlreadyExistsError
from sentinel.exceptions.repository import RepositoryNameNotEmptyError
from sentinel.exceptions.repository import RepositoryNotFoundError
from sentinel.exceptions.repository import RepositoryPathAlreadyExistsError
from sentinel.exceptions.repository import RepositoryPathNotEmptyError
from sentinel.exceptions.repository import RepositoryPathNotFoundError
from sentinel.exceptions.repository import RepositoryRemoteMetadataError
from sentinel.models.repository import Repository
from sentinel.repositories.application_repository import ApplicationRepository
from sentinel.repositories.repository_repository import RepositoryRepository


class RepositoryService:
    def __init__(
        self,
        session: Session,
    ) -> None:
        self.session = session
        self.repo = RepositoryRepository(session)
        self.application_repo = ApplicationRepository(session)

    def create(
        self,
        application_id: int,
        name: str,
        local_path: str,
        remote_url: str = "",
        auth_method: GitAuthMethod = GitAuthMethod.NONE,
        default_branch: str | None = None,
        language: str | None = None,
        package_manager: str | None = None,
    ) -> Repository:

        name = (name or "").strip()
        local_path = (local_path or "").strip()
        remote_url = (remote_url or "").strip()

        default_branch = (
            default_branch.strip() if default_branch is not None else ""
        )

        language = language.strip() if language is not None else ""

        package_manager = (
            package_manager.strip() if package_manager is not None else ""
        )

        # 1. Validation basique

        if not name:
            raise RepositoryNameNotEmptyError(
                "Repository name cannot be empty",
            )

        if not local_path:
            raise RepositoryPathNotEmptyError(
                "Local path cannot be empty",
            )

        # 2. Vérifier que l'application existe

        if not self.application_repo.get_by_id(
            application_id,
        ):
            raise RepositoryApplicationNotFoundError(
                f"Application '{application_id}' not found",
            )

        # 3. Vérifier que le dossier existe

        path = Path(
            local_path,
        )

        if not path.is_dir():
            raise RepositoryPathNotFoundError(
                f"Path does not exist: {local_path}",
            )

        # 4. Validation des métadonnées d'un dépôt distant

        if remote_url:
            if not default_branch:
                raise RepositoryRemoteMetadataError(
                    "Default branch is required for remote repositories",
                )

            if not language:
                raise RepositoryRemoteMetadataError(
                    "Language is required for remote repositories",
                )

            if not package_manager:
                raise RepositoryRemoteMetadataError(
                    "Package manager is required for remote repositories",
                )
        # 5. Unicité par application + nom

        existing = self.repo.get_by_name(
            application_id,
            name,
        )

        if existing:
            raise RepositoryNameAlreadyExistsError(
                f"Repository '{name}' already exists for this application",
            )

        # 6. Unicité par application + chemin

        existing_path = self.repo.get_by_path(
            application_id,
            local_path,
        )

        if existing_path:
            raise RepositoryPathAlreadyExistsError(
                "Repository already registered for this path",
            )

        # 7. Création du repository

        repo = Repository(
            application_id=application_id,
            name=name,
            local_path=local_path,
            remote_url=remote_url,
            auth_method=auth_method,
            default_branch=default_branch,
            language=language,
            package_manager=package_manager,
        )

        self.repo.create(
            repo,
        )

        self.session.commit()

        return repo

    def list_by_application(
        self,
        application_id: int,
    ) -> list[Repository]:

        return self.repo.list_by_application(
            application_id,
        )

    def list_all(
        self,
    ) -> list[Repository]:

        return self.repo.get_all()

    def get_by_id(
        self,
        repository_id: int,
    ) -> Repository:

        repository = self.repo.get_by_id(
            repository_id,
        )

        if repository is None:
            raise RepositoryNotFoundError(
                f"Repository '{repository_id}' not found",
            )

        return repository

    def update(
        self,
        repository_id: int,
        *,
        name: str | None = None,
        local_path: str | None = None,
        remote_url: str | None = None,
        auth_method: GitAuthMethod | None = None,
        default_branch: str | None = None,
        language: str | None = None,
        package_manager: str | None = None,
    ) -> Repository:

        repository = self.get_by_id(
            repository_id,
        )

        if name is not None:
            name = name.strip()

            if not name:
                raise RepositoryNameNotEmptyError(
                    "Repository name cannot be empty",
                )

            existing = self.repo.get_by_name(
                repository.application_id,
                name,
            )

            if existing and existing.id != repository.id:
                raise RepositoryNameAlreadyExistsError(
                    f"Repository '{name}' already exists",
                )

            repository.name = name

        if local_path is not None:
            local_path = local_path.strip()

            if not local_path:
                raise RepositoryPathNotEmptyError(
                    "Local path cannot be empty",
                )

            path = Path(
                local_path,
            )

            if not path.is_dir():
                raise RepositoryPathNotFoundError(
                    f"Path does not exist: {local_path}",
                )

            existing = self.repo.get_by_path(
                repository.application_id,
                local_path,
            )

            if existing and existing.id != repository.id:
                raise RepositoryPathAlreadyExistsError(
                    "Repository already registered for this path",
                )

            repository.local_path = local_path

        if remote_url is not None:
            repository.remote_url = remote_url.strip()

        if auth_method is not None:
            repository.auth_method = auth_method

        if default_branch is not None:
            repository.default_branch = default_branch.strip()

        if language is not None:
            repository.language = language.strip()

        if package_manager is not None:
            repository.package_manager = package_manager.strip()

        # Validation finale :
        # un repository distant doit avoir les métadonnées nécessaires.

        self._validate_remote_metadata(
            repository,
        )

        repository = self.repo.update(
            repository,
        )

        self.session.commit()

        return repository

    def delete(
        self,
        repository_id: int,
    ) -> None:

        repo = self.repo.get_by_id(
            repository_id,
        )

        if not repo:
            raise RepositoryNotFoundError(
                f"Repository '{repository_id}' not found",
            )

        self.repo.delete(
            repo,
        )

        self.session.commit()

    def _validate_remote_metadata(
        self,
        repository: Repository,
    ) -> None:
        """
        Validate metadata required for remote repositories.
        """

        remote_url = repository.remote_url or ""

        if not remote_url:
            return

        if not repository.default_branch:
            raise RepositoryRemoteMetadataError(
                "Default branch is required for remote repositories",
            )

        if not repository.language:
            raise RepositoryRemoteMetadataError(
                "Language is required for remote repositories",
            )

        if not repository.package_manager:
            raise RepositoryRemoteMetadataError(
                "Package manager is required for remote repositories",
            )

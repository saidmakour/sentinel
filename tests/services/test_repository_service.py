from unittest.mock import MagicMock

import pytest

from sentinel.enums.git_auth_method import GitAuthMethod
from sentinel.exceptions.repository import RepositoryApplicationNotFoundError
from sentinel.exceptions.repository import RepositoryNameAlreadyExistsError
from sentinel.exceptions.repository import RepositoryNameNotEmptyError
from sentinel.exceptions.repository import RepositoryNotFoundError
from sentinel.exceptions.repository import RepositoryPathAlreadyExistsError
from sentinel.exceptions.repository import RepositoryPathNotEmptyError
from sentinel.exceptions.repository import RepositoryPathNotFoundError
from sentinel.services.repository_service import RepositoryService


@pytest.fixture
def session():
    return MagicMock()


def create_repository_mock(
    *,
    repository_id: int = 1,
    application_id: int = 10,
    name: str = "backend",
    local_path: str = "/tmp/backend",
    remote_url: str = "",
    auth_method: GitAuthMethod = GitAuthMethod.NONE,
    default_branch: str = "",
    language: str = "",
    package_manager: str = "",
) -> MagicMock:

    repository = MagicMock()

    repository.id = repository_id
    repository.application_id = application_id
    repository.name = name
    repository.local_path = local_path
    repository.remote_url = remote_url
    repository.auth_method = auth_method
    repository.default_branch = default_branch
    repository.language = language
    repository.package_manager = package_manager

    return repository


@pytest.fixture
def service(session):
    service = RepositoryService(session)
    service.repo = MagicMock()
    service.application_repo = MagicMock()
    return service


def test_create_repository_success(
    service,
    session,
    tmp_path,
):
    application_id = 1
    repository_path = tmp_path / "backend"
    repository_path.mkdir()

    service.application_repo.get_by_id.return_value = MagicMock()
    service.repo.get_by_name.return_value = None
    service.repo.get_by_path.return_value = None

    result = service.create(
        application_id=application_id,
        name=" backend ",
        local_path=str(repository_path),
        remote_url=" https://github.com/example/backend.git ",
        auth_method=GitAuthMethod.NONE,
        default_branch=" main ",
        language=" python ",
        package_manager=" pip ",
    )

    assert result.name == "backend"
    assert result.local_path == str(repository_path)
    assert result.remote_url == ("https://github.com/example/backend.git")
    assert result.default_branch == "main"
    assert result.language == "python"
    assert result.package_manager == "pip"
    assert result.application_id == application_id
    assert result.auth_method == GitAuthMethod.NONE

    service.application_repo.get_by_id.assert_called_once_with(application_id)
    service.repo.get_by_name.assert_called_once_with(
        application_id,
        "backend",
    )
    service.repo.get_by_path.assert_called_once_with(
        application_id,
        str(repository_path),
    )
    service.repo.create.assert_called_once_with(result)
    session.commit.assert_called_once_with()


def test_create_repository_empty_name(
    service,
):
    with pytest.raises(RepositoryNameNotEmptyError):
        service.create(
            application_id=1,
            name="",
            local_path="/tmp/backend",
        )

    service.application_repo.get_by_id.assert_not_called()
    service.repo.create.assert_not_called()


def test_create_repository_empty_name_with_spaces(
    service,
):
    with pytest.raises(RepositoryNameNotEmptyError):
        service.create(
            application_id=1,
            name="   ",
            local_path="/tmp/backend",
        )

    service.application_repo.get_by_id.assert_not_called()
    service.repo.create.assert_not_called()


def test_create_repository_empty_local_path(
    service,
):
    with pytest.raises(RepositoryPathNotEmptyError):
        service.create(
            application_id=1,
            name="backend",
            local_path="",
        )

    service.application_repo.get_by_id.assert_not_called()
    service.repo.create.assert_not_called()


def test_create_repository_application_not_found(
    service,
):
    service.application_repo.get_by_id.return_value = None

    with pytest.raises(RepositoryApplicationNotFoundError):
        service.create(
            application_id=999,
            name="backend",
            local_path="/tmp/backend",
        )

    service.application_repo.get_by_id.assert_called_once_with(999)
    service.repo.create.assert_not_called()
    service.session.commit.assert_not_called()


def test_create_repository_path_not_found(
    service,
):
    service.application_repo.get_by_id.return_value = MagicMock()

    missing_path = "/tmp/path-that-does-not-exist"

    with pytest.raises(RepositoryPathNotFoundError):
        service.create(
            application_id=1,
            name="backend",
            local_path=missing_path,
        )

    service.repo.get_by_name.assert_not_called()
    service.repo.get_by_path.assert_not_called()
    service.repo.create.assert_not_called()
    service.session.commit.assert_not_called()


def test_create_repository_name_already_exists(
    service,
    tmp_path,
):
    repository_path = tmp_path / "backend"
    repository_path.mkdir()

    service.application_repo.get_by_id.return_value = MagicMock()
    service.repo.get_by_name.return_value = MagicMock()

    with pytest.raises(RepositoryNameAlreadyExistsError):
        service.create(
            application_id=1,
            name="backend",
            local_path=str(repository_path),
        )

    service.repo.get_by_name.assert_called_once_with(
        1,
        "backend",
    )
    service.repo.get_by_path.assert_not_called()
    service.repo.create.assert_not_called()
    service.session.commit.assert_not_called()


def test_create_repository_path_already_exists(
    service,
    tmp_path,
):
    repository_path = tmp_path / "backend"
    repository_path.mkdir()

    service.application_repo.get_by_id.return_value = MagicMock()
    service.repo.get_by_name.return_value = None
    service.repo.get_by_path.return_value = MagicMock()

    with pytest.raises(RepositoryPathAlreadyExistsError):
        service.create(
            application_id=1,
            name="backend",
            local_path=str(repository_path),
        )

    service.repo.get_by_name.assert_called_once_with(
        1,
        "backend",
    )
    service.repo.get_by_path.assert_called_once_with(
        1,
        str(repository_path),
    )
    service.repo.create.assert_not_called()
    service.session.commit.assert_not_called()


def test_list_repositories_by_application(
    service,
):
    repositories = [
        MagicMock(id=1, name="backend"),
        MagicMock(id=2, name="frontend"),
    ]

    service.repo.list_by_application.return_value = repositories

    result = service.list_by_application(1)

    assert result == repositories

    service.repo.list_by_application.assert_called_once_with(1)


def test_get_repository_by_id_success(
    service,
):
    repository = MagicMock(
        id=1,
        name="backend",
    )

    service.repo.get_by_id.return_value = repository

    result = service.get_by_id(1)

    assert result is repository

    service.repo.get_by_id.assert_called_once_with(1)


def test_get_repository_by_id_not_found(
    service,
):
    service.repo.get_by_id.return_value = None

    with pytest.raises(RepositoryNotFoundError):
        service.get_by_id(999)

    service.repo.get_by_id.assert_called_once_with(999)


def test_update_repository_not_found(
    service,
):
    service.repo.get_by_id.return_value = None

    with pytest.raises(RepositoryNotFoundError):
        service.update(999, name="backend")

    service.repo.get_by_id.assert_called_once_with(999)
    service.repo.update.assert_not_called()
    service.session.commit.assert_not_called()


def test_update_repository_name(
    service,
    session,
):
    repository = MagicMock(
        id=1,
        application_id=10,
        name="old-name",
    )

    service.repo.get_by_id.return_value = repository
    service.repo.get_by_name.return_value = None
    service.repo.update.return_value = repository

    result = service.update(
        1,
        name=" new-name ",
    )

    assert result is repository
    assert repository.name == "new-name"

    service.repo.get_by_name.assert_called_once_with(
        10,
        "new-name",
    )
    service.repo.update.assert_called_once_with(repository)
    session.commit.assert_called_once_with()


def test_update_repository_empty_name(
    service,
):
    repository = MagicMock(
        id=1,
        application_id=10,
        name="backend",
    )

    service.repo.get_by_id.return_value = repository

    with pytest.raises(RepositoryNameNotEmptyError):
        service.update(
            1,
            name="   ",
        )

    service.repo.get_by_name.assert_not_called()
    service.repo.update.assert_not_called()
    service.session.commit.assert_not_called()


def test_update_repository_name_already_exists(
    service,
):
    repository = MagicMock(
        id=1,
        application_id=10,
        name="backend",
    )

    existing_repository = MagicMock(
        id=2,
        application_id=10,
        name="new-name",
    )

    service.repo.get_by_id.return_value = repository
    service.repo.get_by_name.return_value = existing_repository

    with pytest.raises(RepositoryNameAlreadyExistsError):
        service.update(
            1,
            name="new-name",
        )

    service.repo.get_by_name.assert_called_once_with(
        10,
        "new-name",
    )
    service.repo.update.assert_not_called()
    service.session.commit.assert_not_called()


def test_update_repository_same_name_allowed(
    service,
    session,
):
    repository = MagicMock(
        id=1,
        application_id=10,
        name="backend",
    )

    service.repo.get_by_id.return_value = repository
    service.repo.get_by_name.return_value = repository
    service.repo.update.return_value = repository

    result = service.update(
        1,
        name=" backend ",
    )

    assert result is repository
    assert repository.name == "backend"

    service.repo.get_by_name.assert_called_once_with(
        10,
        "backend",
    )
    service.repo.update.assert_called_once_with(repository)
    session.commit.assert_called_once_with()


def test_update_repository_local_path(
    service,
    session,
    tmp_path,
):
    repository = MagicMock(
        id=1,
        application_id=10,
        local_path="/tmp/old-backend",
    )

    new_path = tmp_path / "new-backend"
    new_path.mkdir()

    service.repo.get_by_id.return_value = repository
    service.repo.get_by_path.return_value = None
    service.repo.update.return_value = repository

    result = service.update(
        1,
        local_path=f" {new_path} ",
    )

    assert result is repository
    assert repository.local_path == str(new_path)

    service.repo.get_by_path.assert_called_once_with(
        10,
        str(new_path),
    )
    service.repo.update.assert_called_once_with(repository)
    session.commit.assert_called_once_with()


def test_update_repository_empty_local_path(
    service,
):
    repository = MagicMock(
        id=1,
        application_id=10,
        local_path="/tmp/backend",
    )

    service.repo.get_by_id.return_value = repository

    with pytest.raises(RepositoryPathNotEmptyError):
        service.update(
            1,
            local_path="   ",
        )

    service.repo.get_by_path.assert_not_called()
    service.repo.update.assert_not_called()
    service.session.commit.assert_not_called()


def test_update_repository_local_path_not_found(
    service,
):
    repository = MagicMock(
        id=1,
        application_id=10,
        local_path="/tmp/backend",
    )

    service.repo.get_by_id.return_value = repository

    missing_path = "/tmp/path-that-does-not-exist"

    with pytest.raises(RepositoryPathNotFoundError):
        service.update(
            1,
            local_path=missing_path,
        )

    service.repo.get_by_path.assert_not_called()
    service.repo.update.assert_not_called()
    service.session.commit.assert_not_called()


def test_update_repository_local_path_already_exists(
    service,
    tmp_path,
):
    repository = MagicMock(
        id=1,
        application_id=10,
        local_path="/tmp/backend",
    )

    existing_repository = MagicMock(
        id=2,
        application_id=10,
        local_path=str(tmp_path),
    )

    service.repo.get_by_id.return_value = repository
    service.repo.get_by_path.return_value = existing_repository

    with pytest.raises(RepositoryPathAlreadyExistsError):
        service.update(
            1,
            local_path=str(tmp_path),
        )

    service.repo.get_by_path.assert_called_once_with(
        10,
        str(tmp_path),
    )
    service.repo.update.assert_not_called()
    service.session.commit.assert_not_called()


def test_update_repository_same_local_path_allowed(
    service,
    session,
    tmp_path,
):
    repository_path = tmp_path / "backend"
    repository_path.mkdir()

    repository = MagicMock(
        id=1,
        application_id=10,
        local_path=str(repository_path),
    )

    service.repo.get_by_id.return_value = repository
    service.repo.get_by_path.return_value = repository
    service.repo.update.return_value = repository

    result = service.update(
        1,
        local_path=f" {repository_path} ",
    )

    assert result is repository
    assert repository.local_path == str(repository_path)

    service.repo.get_by_path.assert_called_once_with(
        10,
        str(repository_path),
    )
    service.repo.update.assert_called_once_with(repository)
    session.commit.assert_called_once_with()


def test_update_repository_metadata(
    service,
    session,
):
    repository = MagicMock(
        id=1,
        application_id=10,
        remote_url="https://old.example.com",
        default_branch="main",
        language="python",
        package_manager="pip",
    )

    service.repo.get_by_id.return_value = repository
    service.repo.update.return_value = repository

    result = service.update(
        1,
        remote_url=" https://github.com/example/backend.git ",
        default_branch=" develop ",
        language=" javascript ",
        package_manager=" npm ",
    )

    assert result is repository
    assert repository.remote_url == ("https://github.com/example/backend.git")
    assert repository.default_branch == "develop"
    assert repository.language == "javascript"
    assert repository.package_manager == "npm"

    service.repo.update.assert_called_once_with(repository)
    session.commit.assert_called_once_with()


def test_update_repository_without_changes(
    service,
    session,
):
    repository = MagicMock(
        id=1,
        application_id=10,
    )

    service.repo.get_by_id.return_value = repository
    service.repo.update.return_value = repository

    result = service.update(1)

    assert result is repository

    service.repo.get_by_id.assert_called_once_with(1)
    service.repo.get_by_name.assert_not_called()
    service.repo.get_by_path.assert_not_called()
    service.repo.update.assert_called_once_with(repository)
    session.commit.assert_called_once_with()


def test_delete_repository_success(
    service,
    session,
):
    repository = MagicMock(
        id=1,
        application_id=10,
        name="backend",
    )

    service.repo.get_by_id.return_value = repository

    service.delete(1)

    service.repo.get_by_id.assert_called_once_with(1)
    service.repo.delete.assert_called_once_with(repository)
    session.commit.assert_called_once_with()


def test_delete_repository_not_found(
    service,
):
    service.repo.get_by_id.return_value = None

    with pytest.raises(RepositoryNotFoundError):
        service.delete(999)

    service.repo.get_by_id.assert_called_once_with(999)
    service.repo.delete.assert_not_called()
    service.session.commit.assert_not_called()


def test_create_repository_defaults_auth_method(
    service,
    tmp_path,
) -> None:
    repository_path = tmp_path / "backend-default-auth"
    repository_path.mkdir()

    service.application_repo.get_by_id.return_value = MagicMock()
    service.repo.get_by_name.return_value = None
    service.repo.get_by_path.return_value = None

    result = service.create(
        application_id=1,
        name="backend-default-auth",
        local_path=str(repository_path),
    )

    assert result.auth_method == GitAuthMethod.NONE

    service.repo.create.assert_called_once_with(result)
    service.session.commit.assert_called_once_with()


def test_create_repository_accepts_https_auth_method(
    service,
    tmp_path,
) -> None:
    repository_path = tmp_path / "backend-https-auth"
    repository_path.mkdir()

    service.application_repo.get_by_id.return_value = MagicMock()
    service.repo.get_by_name.return_value = None
    service.repo.get_by_path.return_value = None

    result = service.create(
        application_id=1,
        name="backend-https-auth",
        local_path=str(repository_path),
        auth_method=GitAuthMethod.HTTPS,
    )

    assert result.auth_method == GitAuthMethod.HTTPS

    service.repo.create.assert_called_once_with(result)
    service.session.commit.assert_called_once_with()


def test_update_repository_accepts_auth_method(
    service,
    session,
) -> None:
    repository = MagicMock(
        id=1,
        application_id=10,
        auth_method=GitAuthMethod.NONE,
    )

    service.repo.get_by_id.return_value = repository
    service.repo.update.return_value = repository

    result = service.update(
        1,
        auth_method=GitAuthMethod.SSH,
    )

    assert result is repository
    assert repository.auth_method == GitAuthMethod.SSH

    service.repo.update.assert_called_once_with(repository)
    session.commit.assert_called_once_with()

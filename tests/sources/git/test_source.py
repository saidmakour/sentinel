from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentinel.config.settings import Settings
from sentinel.dto.git_credentials import GitCredentials
from sentinel.enums.git_auth_method import GitAuthMethod
from sentinel.enums.source_type import SourceType
from sentinel.exceptions.source import InvalidRepositoryError
from sentinel.models.repository import Repository
from sentinel.sources.git.client import GitClient
from sentinel.sources.git.credentials_provider import GitCredentialsProvider
from sentinel.sources.git.forge_registry import GitForgeRegistry
from sentinel.sources.git.forge_resolver import GitForgeResolver
from sentinel.sources.git.source import GitSource
from sentinel.sources.prepared import PreparedSource


def create_repository(
    tmp_path: Path,
    remote_url: str = "https://github.com/test/project.git",
    default_branch: str = "main",
) -> Repository:
    return Repository(
        application_id=1,
        name="test-project",
        local_path=str(tmp_path / "project"),
        remote_url=remote_url,
        default_branch=default_branch,
    )


def create_credentials_provider() -> GitCredentialsProvider:
    registry = GitForgeRegistry()

    resolver = GitForgeResolver(
        registry=registry,
        settings=Settings(
            git_forge=None,
        ),
    )

    return GitCredentialsProvider(
        resolver=resolver,
    )


def test_git_source_can_be_created() -> None:
    source = GitSource()

    assert source is not None


def test_git_source_uses_provided_client() -> None:
    client = MagicMock(spec=GitClient)

    source = GitSource(
        client=client,
    )

    assert source.client is client


def test_supports_remote_repository(
    tmp_path: Path,
) -> None:
    source = GitSource()

    repository = create_repository(
        tmp_path,
    )

    assert (
        source.supports(
            repository,
        )
        is True
    )


def test_does_not_support_local_repository(
    tmp_path: Path,
) -> None:
    source = GitSource()

    repository = create_repository(
        tmp_path,
        remote_url="",
    )

    assert (
        source.supports(
            repository,
        )
        is False
    )


def test_prepare_pulls_existing_repository(
    tmp_path: Path,
) -> None:
    client = MagicMock(spec=GitClient)
    source = GitSource(
        client=client,
    )

    repository = create_repository(
        tmp_path,
    )

    path = Path(
        repository.local_path,
    )

    client.is_repository.return_value = True
    client.get_remote_url.return_value = repository.remote_url
    client.get_current_branch.return_value = repository.default_branch
    client.get_current_commit.return_value = "abc123456789"

    result = source.prepare(
        repository,
    )

    client.is_repository.assert_called_once_with(
        path,
    )

    client.get_remote_url.assert_called_with(
        path,
    )

    client.pull.assert_called_once_with(
        path,
        auth_method=repository.auth_method,
        credentials=None,
    )

    client.clone.assert_not_called()

    client.checkout.assert_called_once_with(
        path,
        repository.default_branch,
    )

    assert result == PreparedSource(
        path=path,
        source_type=SourceType.GIT,
        reference=repository.remote_url,
        branch=repository.default_branch,
        commit="abc123456789",
    )


def test_prepare_returns_git_metadata(
    tmp_path: Path,
) -> None:
    client = MagicMock(spec=GitClient)
    source = GitSource(
        client=client,
    )

    repository = create_repository(
        tmp_path,
    )

    client.is_repository.return_value = False
    client.get_remote_url.return_value = "https://github.com/test/project.git"
    client.get_current_branch.return_value = "develop"
    client.get_current_commit.return_value = "123456789abcdef"

    result = source.prepare(
        repository,
    )

    assert result.path == Path(
        repository.local_path,
    )

    assert result.source_type is SourceType.GIT

    assert result.reference == ("https://github.com/test/project.git")

    assert result.branch == "develop"

    assert result.commit == ("123456789abcdef")


def test_prepare_uses_repository_default_branch(
    tmp_path: Path,
) -> None:
    client = MagicMock(spec=GitClient)
    source = GitSource(
        client=client,
    )

    repository = create_repository(
        tmp_path,
        default_branch="develop",
    )

    client.is_repository.return_value = False
    client.get_remote_url.return_value = repository.remote_url
    client.get_current_branch.return_value = "develop"
    client.get_current_commit.return_value = "abc123"

    source.prepare(
        repository,
    )

    client.checkout.assert_called_once_with(
        Path(repository.local_path),
        "develop",
    )


def test_prepare_raises_error_when_remote_does_not_match(
    tmp_path: Path,
) -> None:
    client = MagicMock(spec=GitClient)
    source = GitSource(
        client=client,
    )

    repository = create_repository(
        tmp_path,
        remote_url="https://github.com/test/project-a.git",
    )

    path = Path(
        repository.local_path,
    )

    client.is_repository.return_value = True
    client.get_remote_url.return_value = (
        "https://github.com/test/project-b.git"
    )

    with pytest.raises(
        InvalidRepositoryError,
        match="does not match",
    ):
        source.prepare(
            repository,
        )

    client.is_repository.assert_called_once_with(
        path,
    )

    client.get_remote_url.assert_called_once_with(
        path,
    )

    client.pull.assert_not_called()
    client.clone.assert_not_called()
    client.checkout.assert_not_called()


def test_prepare_pulls_existing_repository_2(
    tmp_path: Path,
) -> None:
    client = MagicMock(spec=GitClient)
    credentials_provider = MagicMock(
        spec=GitCredentialsProvider,
    )

    credentials = GitCredentials(
        username="test-user",
        password="test-token",
    )

    credentials_provider.get.return_value = credentials

    source = GitSource(
        client=client,
        credentials_provider=credentials_provider,
    )

    repository = create_repository(
        tmp_path,
    )

    path = Path(
        repository.local_path,
    )

    client.is_repository.return_value = True
    client.get_remote_url.return_value = repository.remote_url
    client.get_current_branch.return_value = repository.default_branch
    client.get_current_commit.return_value = "abc123456789"

    result = source.prepare(
        repository,
    )

    credentials_provider.get.assert_called_once_with(
        repository.remote_url,
        forge_name=None,
    )

    client.is_repository.assert_called_once_with(
        path,
    )

    client.get_remote_url.assert_called_with(
        path,
    )

    client.pull.assert_called_once_with(
        path,
        auth_method=repository.auth_method,
        credentials=credentials,
    )

    client.clone.assert_not_called()

    client.checkout.assert_called_once_with(
        path,
        repository.default_branch,
    )

    assert result == PreparedSource(
        path=path,
        source_type=SourceType.GIT,
        reference=repository.remote_url,
        branch=repository.default_branch,
        commit="abc123456789",
    )


def test_prepare_clones_repository_with_credentials(
    tmp_path: Path,
) -> None:
    client = MagicMock(spec=GitClient)
    credentials_provider = MagicMock()

    source = GitSource(
        client=client,
        credentials_provider=credentials_provider,
    )

    repository = create_repository(
        tmp_path,
    )

    credentials = GitCredentials(
        username="test-user",
        token="test-token",
    )

    credentials_provider.get.return_value = credentials
    client.is_repository.return_value = False
    client.get_remote_url.return_value = repository.remote_url
    client.get_current_branch.return_value = repository.default_branch
    client.get_current_commit.return_value = "abc123456789"

    result = source.prepare(
        repository,
    )

    credentials_provider.get.assert_called_once_with(
        repository.remote_url,
        forge_name=None,
    )

    client.clone.assert_called_once_with(
        repository.remote_url,
        Path(repository.local_path),
        auth_method=repository.auth_method,
        credentials=credentials,
    )

    assert result.commit == "abc123456789"


def test_prepare_pulls_existing_repository_with_credentials(
    tmp_path: Path,
) -> None:
    client = MagicMock(spec=GitClient)
    credentials_provider = MagicMock()

    source = GitSource(
        client=client,
        credentials_provider=credentials_provider,
    )

    repository = create_repository(
        tmp_path,
    )

    credentials = GitCredentials(
        username="test-user",
        token="test-token",
    )

    credentials_provider.get.return_value = credentials
    client.is_repository.return_value = True
    client.get_remote_url.return_value = repository.remote_url
    client.get_current_branch.return_value = repository.default_branch
    client.get_current_commit.return_value = "abc123456789"

    result = source.prepare(
        repository,
    )

    credentials_provider.get.assert_called_once_with(
        repository.remote_url,
        forge_name=None,
    )

    client.pull.assert_called_once_with(
        Path(repository.local_path),
        auth_method=repository.auth_method,
        credentials=credentials,
    )

    client.clone.assert_not_called()

    assert result.commit == "abc123456789"


def create_repository_2(
    tmp_path: Path,
    *,
    auth_method: GitAuthMethod = GitAuthMethod.NONE,
    default_branch: str | None = "main",
) -> Repository:
    return Repository(
        application_id=1,
        name="backend",
        local_path=str(tmp_path / "backend"),
        remote_url="https://gitlab.example.com/backend.git",
        auth_method=auth_method,
        default_branch=default_branch,
        language="python",
        package_manager="pip",
    )


def test_prepare_clone_passes_credentials_and_auth_method(
    tmp_path: Path,
) -> None:
    client = MagicMock(spec=GitClient)
    credentials_provider = MagicMock(
        spec=GitCredentialsProvider,
    )

    source = GitSource(
        client=client,
        credentials_provider=credentials_provider,
    )

    repository = create_repository_2(
        tmp_path,
        auth_method=GitAuthMethod.HTTPS,
    )

    credentials = GitCredentials(
        username="test-user",
        token="test-token",
    )

    credentials_provider.get.return_value = credentials
    client.is_repository.return_value = False
    client.get_remote_url.return_value = repository.remote_url
    client.get_current_branch.return_value = repository.default_branch
    client.get_current_commit.return_value = "abc123456789"

    result = source.prepare(
        repository,
    )

    credentials_provider.get.assert_called_once_with(
        repository.remote_url,
        forge_name=None,
    )

    client.clone.assert_called_once_with(
        repository.remote_url,
        Path(repository.local_path),
        auth_method=GitAuthMethod.HTTPS,
        credentials=credentials,
    )

    client.pull.assert_not_called()

    assert result.path == Path(repository.local_path)
    assert result.source_type == SourceType.GIT
    assert result.reference == repository.remote_url
    assert result.branch == repository.default_branch
    assert result.commit == "abc123456789"


def test_prepare_pull_passes_credentials_and_auth_method(
    tmp_path: Path,
) -> None:
    client = MagicMock(spec=GitClient)
    credentials_provider = MagicMock(
        spec=GitCredentialsProvider,
    )

    source = GitSource(
        client=client,
        credentials_provider=credentials_provider,
    )

    repository = create_repository_2(
        tmp_path,
        auth_method=GitAuthMethod.SSH,
    )

    credentials = GitCredentials(
        username="git",
        private_key="private-key-content",
        passphrase="secret",
    )

    credentials_provider.get.return_value = credentials
    client.is_repository.return_value = True
    client.get_remote_url.return_value = repository.remote_url
    client.get_current_branch.return_value = repository.default_branch
    client.get_current_commit.return_value = "def987654321"

    result = source.prepare(
        repository,
    )

    credentials_provider.get.assert_called_once_with(
        repository.remote_url,
        forge_name=None,
    )

    client.pull.assert_called_once_with(
        Path(repository.local_path),
        auth_method=GitAuthMethod.SSH,
        credentials=credentials,
    )

    client.clone.assert_not_called()

    assert result.path == Path(repository.local_path)
    assert result.source_type == SourceType.GIT
    assert result.reference == repository.remote_url
    assert result.branch == repository.default_branch
    assert result.commit == "def987654321"


def test_prepare_clone_without_authentication(
    tmp_path: Path,
) -> None:
    client = MagicMock(spec=GitClient)
    credentials_provider = MagicMock(
        spec=GitCredentialsProvider,
    )

    source = GitSource(
        client=client,
        credentials_provider=credentials_provider,
    )

    repository = create_repository_2(
        tmp_path,
        auth_method=GitAuthMethod.NONE,
    )

    credentials_provider.get.return_value = None
    client.is_repository.return_value = False
    client.get_remote_url.return_value = repository.remote_url
    client.get_current_branch.return_value = repository.default_branch
    client.get_current_commit.return_value = "abc123456789"

    source.prepare(
        repository,
        forge_name=None,
    )

    credentials_provider.get.assert_called_once_with(
        repository.remote_url,
        forge_name=None,
    )

    client.clone.assert_called_once_with(
        repository.remote_url,
        Path(repository.local_path),
        auth_method=GitAuthMethod.NONE,
        credentials=None,
    )


def test_prepare_checks_out_explicit_default_branch(
    tmp_path: Path,
) -> None:
    client = MagicMock(spec=GitClient)
    credentials_provider = MagicMock(
        spec=GitCredentialsProvider,
    )

    source = GitSource(
        client=client,
        credentials_provider=credentials_provider,
    )

    repository = create_repository_2(
        tmp_path,
        default_branch="master",
    )

    path = Path(
        repository.local_path,
    )

    client.is_repository.return_value = False
    client.get_remote_url.return_value = repository.remote_url
    client.get_current_branch.return_value = "master"
    client.get_current_commit.return_value = "abc123456789"

    result = source.prepare(
        repository,
    )

    client.checkout.assert_called_once_with(
        path,
        "master",
    )

    assert result.branch == "master"


def test_prepare_uses_remote_default_branch_when_no_branch_is_configured(
    tmp_path: Path,
) -> None:
    client = MagicMock(spec=GitClient)
    credentials_provider = MagicMock(
        spec=GitCredentialsProvider,
    )

    source = GitSource(
        client=client,
        credentials_provider=credentials_provider,
    )

    repository = create_repository_2(
        tmp_path,
        default_branch=None,
    )

    path = Path(
        repository.local_path,
    )

    client.is_repository.return_value = False
    client.get_remote_url.return_value = repository.remote_url
    client.get_current_branch.return_value = "master"
    client.get_current_commit.return_value = "abc123456789"

    result = source.prepare(
        repository,
    )

    client.checkout.assert_not_called()

    assert result.path == path
    assert result.branch == "master"
    assert result.commit == "abc123456789"

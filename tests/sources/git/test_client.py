from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from git.exc import GitCommandError
from git.exc import InvalidGitRepositoryError

from sentinel.enums.git_auth_method import GitAuthMethod
from sentinel.exceptions.source import GitCheckoutError
from sentinel.exceptions.source import GitCloneError
from sentinel.exceptions.source import GitPullError
from sentinel.exceptions.source import InvalidRepositoryError
from sentinel.sources.git.client import GitClient


def test_git_client_can_be_created() -> None:
    client = GitClient()

    assert client is not None


def test_exists_returns_true(
    tmp_path: Path,
) -> None:
    client = GitClient()

    assert client.exists(tmp_path)


def test_exists_returns_false() -> None:
    client = GitClient()

    assert not client.exists(
        Path("/path/that/does/not/exist"),
    )


def test_is_repository_returns_false_for_missing_path() -> None:
    client = GitClient()

    repository = Path(
        "/path/that/does/not/exist",
    )

    assert not client.is_repository(
        repository,
    )


def test_is_repository_returns_false_for_file(
    tmp_path: Path,
) -> None:
    client = GitClient()

    file = tmp_path / "file.txt"
    file.write_text("test")

    assert not client.is_repository(
        file,
    )


@patch("sentinel.sources.git.client.Repo")
def test_is_repository_returns_true(
    repo_mock: MagicMock,
    tmp_path: Path,
) -> None:
    client = GitClient()

    result = client.is_repository(
        tmp_path,
    )

    repo_mock.assert_called_once_with(
        tmp_path,
    )

    assert result is True


@patch("sentinel.sources.git.client.Repo")
def test_is_repository_returns_false_for_invalid_repository(
    repo_mock: MagicMock,
    tmp_path: Path,
) -> None:
    repo_mock.side_effect = InvalidGitRepositoryError(
        "Invalid repository",
    )

    client = GitClient()

    result = client.is_repository(
        tmp_path,
    )

    assert result is False


@patch("sentinel.sources.git.client.Repo.clone_from")
def test_clone_calls_gitpython(
    clone_from: MagicMock,
    tmp_path: Path,
) -> None:
    factory = MagicMock()
    authenticator = MagicMock()

    context = MagicMock()
    context.environment = {
        "GIT_ASKPASS": "askpass",
    }

    factory.create.return_value = authenticator
    authenticator.prepare.return_value = context

    client = GitClient(
        authenticator_factory=factory,
    )

    destination = tmp_path / "repo"
    url = "https://github.com/test/project.git"

    result = client.clone(
        url,
        destination,
    )

    factory.create.assert_called_once_with(
        GitAuthMethod.NONE,
    )

    authenticator.prepare.assert_called_once_with(
        None,
    )

    clone_from.assert_called_once_with(
        url,
        destination,
        env=context.environment,
    )

    assert result == destination


@patch("sentinel.sources.git.client.Repo.clone_from")
def test_clone_raises_git_clone_error(
    clone_from: MagicMock,
    tmp_path: Path,
) -> None:
    clone_from.side_effect = GitCommandError(
        "clone",
        1,
    )

    client = GitClient()

    with pytest.raises(
        GitCloneError,
    ):
        client.clone(
            "https://github.com/test/project.git",
            tmp_path / "repo",
        )


@patch("sentinel.sources.git.client.Repo")
def test_pull_calls_gitpython(
    repo_mock: MagicMock,
    tmp_path: Path,
) -> None:
    client = GitClient()

    repo = repo_mock.return_value

    client.pull(
        tmp_path,
    )

    repo_mock.assert_called_once_with(
        tmp_path,
    )

    repo.git.pull.assert_called_once()


@patch("sentinel.sources.git.client.Repo")
def test_pull_raises_git_pull_error(
    repo_mock: MagicMock,
    tmp_path: Path,
) -> None:
    repo_mock.return_value.git.pull.side_effect = GitCommandError(
        "pull",
        1,
    )

    client = GitClient()

    with pytest.raises(
        GitPullError,
    ):
        client.pull(
            tmp_path,
        )


@patch("sentinel.sources.git.client.Repo")
def test_pull_raises_invalid_repository_error(
    repo_mock: MagicMock,
    tmp_path: Path,
) -> None:
    repo_mock.side_effect = InvalidGitRepositoryError(
        "Invalid repository",
    )

    client = GitClient()

    with pytest.raises(
        InvalidRepositoryError,
    ):
        client.pull(
            tmp_path,
        )


@patch("sentinel.sources.git.client.Repo")
def test_checkout_calls_gitpython(
    repo_mock: MagicMock,
    tmp_path: Path,
) -> None:
    client = GitClient()

    repo = repo_mock.return_value

    client.checkout(
        tmp_path,
        "main",
    )

    repo_mock.assert_called_once_with(
        tmp_path,
    )

    repo.git.checkout.assert_called_once_with(
        "main",
    )


@patch("sentinel.sources.git.client.Repo")
def test_checkout_raises_git_checkout_error(
    repo_mock: MagicMock,
    tmp_path: Path,
) -> None:
    repo_mock.return_value.git.checkout.side_effect = GitCommandError(
        "checkout",
        1,
    )

    client = GitClient()

    with pytest.raises(
        GitCheckoutError,
    ):
        client.checkout(
            tmp_path,
            "unknown",
        )


@patch("sentinel.sources.git.client.Repo")
def test_checkout_raises_invalid_repository_error(
    repo_mock: MagicMock,
    tmp_path: Path,
) -> None:
    repo_mock.side_effect = InvalidGitRepositoryError(
        "Invalid repository",
    )

    client = GitClient()

    with pytest.raises(
        InvalidRepositoryError,
    ):
        client.checkout(
            tmp_path,
            "main",
        )


@patch("sentinel.sources.git.client.Repo")
def test_get_remote_url(
    repo_mock: MagicMock,
    tmp_path: Path,
) -> None:
    remote_url = "https://github.com/test/project.git"

    repo = repo_mock.return_value
    repo.remote.return_value.url = remote_url

    client = GitClient()

    result = client.get_remote_url(
        tmp_path,
    )

    repo_mock.assert_called_once_with(
        tmp_path,
    )

    assert result == remote_url


@patch("sentinel.sources.git.client.Repo")
def test_get_current_branch(
    repo_mock: MagicMock,
    tmp_path: Path,
) -> None:
    repo = repo_mock.return_value
    repo.active_branch.name = "main"

    client = GitClient()

    result = client.get_current_branch(
        tmp_path,
    )

    repo_mock.assert_called_once_with(
        tmp_path,
    )

    assert result == "main"


@patch("sentinel.sources.git.client.Repo")
def test_get_current_commit(
    repo_mock: MagicMock,
    tmp_path: Path,
) -> None:
    repo = repo_mock.return_value
    repo.head.commit.hexsha = "abc123456789"

    client = GitClient()

    result = client.get_current_commit(
        tmp_path,
    )

    repo_mock.assert_called_once_with(
        tmp_path,
    )

    assert result == "abc123456789"


@patch("sentinel.sources.git.client.Repo.clone_from")
def test_clone_closes_authentication_context(
    clone_from: MagicMock,
    tmp_path: Path,
) -> None:
    factory = MagicMock()
    authenticator = MagicMock()

    context = MagicMock()
    context.environment = {}

    factory.create.return_value = authenticator
    authenticator.prepare.return_value = context

    client = GitClient(
        authenticator_factory=factory,
    )

    client.clone(
        "https://github.com/test/project.git",
        tmp_path / "repo",
    )

    context.__exit__.assert_called_once()

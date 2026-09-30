from pathlib import Path
from unittest.mock import MagicMock

from typer.testing import CliRunner

from sentinel.cli.app import app
from sentinel.cli.repository_cli import add_repo
from sentinel.cli.repository_cli import delete_repo
from sentinel.cli.repository_cli import list_repos
from sentinel.enums.git_auth_method import GitAuthMethod

runner = CliRunner()


def test_list_repos_success(
    monkeypatch,
    capsys,
) -> None:
    session = MagicMock()

    repository_service = MagicMock()

    repo1 = MagicMock()
    repo1.name = "backend"
    repo1.local_path = "/tmp/backend"

    repo2 = MagicMock()
    repo2.name = "frontend"
    repo2.local_path = "/tmp/frontend"

    repository_service.list_by_application.return_value = [
        repo1,
        repo2,
    ]

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.RepositoryService",
        lambda session: repository_service,
    )

    list_repos(
        application_id=1,
    )

    repository_service.list_by_application.assert_called_once_with(
        1,
    )

    captured = capsys.readouterr()

    assert "Repositories:" in captured.out
    assert "- backend (/tmp/backend)" in captured.out
    assert "- frontend (/tmp/frontend)" in captured.out

    session.close.assert_called_once_with()


def test_list_repos_when_empty(
    monkeypatch,
    capsys,
) -> None:
    session = MagicMock()

    repository_service = MagicMock()

    repository_service.list_by_application.return_value = []

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.RepositoryService",
        lambda session: repository_service,
    )

    list_repos(
        application_id=1,
    )

    repository_service.list_by_application.assert_called_once_with(
        1,
    )

    captured = capsys.readouterr()

    assert "No repositories found." in captured.out

    session.close.assert_called_once_with()


def test_list_repos_handles_value_error(
    monkeypatch,
) -> None:
    session = MagicMock()

    repository_service = MagicMock()

    repository_service.list_by_application.side_effect = ValueError(
        "Application not found",
    )

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.RepositoryService",
        lambda session: repository_service,
    )

    result = runner.invoke(
        app,
        [
            "repo",
            "list",
            "999",
        ],
    )

    assert result.exit_code == 1

    session.close.assert_called_once_with()


def test_add_repo_success(
    monkeypatch,
    capsys,
) -> None:
    session = MagicMock()

    repository_service = MagicMock()

    repo = MagicMock()
    repo.name = "backend"
    repo.default_branch = "main"
    repo.package_manager = "PYPI"
    repo.language = "python"
    repo.auth_method = None

    repository_service.create.return_value = repo

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.RepositoryService",
        lambda session: repository_service,
    )

    add_repo(
        application_id=1,
        name="backend",
        path=Path("/tmp/backend"),
        remote_url="https://gitlab.example.com/backend.git",
        branch="main",
        language="python",
        package_manager="PyPI",
    )

    captured = capsys.readouterr()
    assert "Repository created: backend" in captured.out

    session.close.assert_called_once_with()


def test_add_repo_handles_value_error(
    monkeypatch,
) -> None:
    session = MagicMock()

    repository_service = MagicMock()

    repository_service.create.side_effect = ValueError(
        "Repository already exists",
    )

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.RepositoryService",
        lambda session: repository_service,
    )

    result = runner.invoke(
        app,
        [
            "repo",
            "add",
            "1",
            "backend",
            "/tmp/backend",
            "--remote-url",
            "https://gitlab.example.com/backend.git",
        ],
    )
    assert result.exit_code == 1

    session.close.assert_called_once_with()


def test_delete_repo_success(
    monkeypatch,
    capsys,
) -> None:
    session = MagicMock()

    repository_service = MagicMock()

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.RepositoryService",
        lambda session: repository_service,
    )

    delete_repo(
        repo_id=42,
    )

    repository_service.delete.assert_called_once_with(
        42,
    )

    captured = capsys.readouterr()

    assert "Deleted repository: 42" in captured.out

    session.close.assert_called_once_with()


def test_delete_repo_handles_value_error(
    monkeypatch,
) -> None:
    session = MagicMock()

    repository_service = MagicMock()

    repository_service.delete.side_effect = ValueError(
        "Repository not found",
    )

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.RepositoryService",
        lambda session: repository_service,
    )

    result = runner.invoke(
        app,
        [
            "repo",
            "delete",
            "999",
        ],
    )

    assert result.exit_code == 1

    session.close.assert_called_once_with()


def test_add_repo_without_remote_url(
    monkeypatch,
) -> None:
    session = MagicMock()

    repository_service = MagicMock()

    repo = MagicMock()
    repo.name = "sentinel"
    repo.default_branch = "main"
    repo.package_manager = "uv"
    repo.language = "python"
    repo.auth_method = None

    repository_service.create.return_value = repo

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.repository_cli.RepositoryService",
        lambda session: repository_service,
    )

    result = runner.invoke(
        app,
        [
            "repo",
            "add",
            "1",
            "sentinel",
            "C:\\Sources\\sentinel",
        ],
    )

    assert result.exit_code == 0

    repository_service.create.assert_called_once_with(
        application_id=1,
        name="sentinel",
        local_path="C:\\Sources\\sentinel",
        remote_url=None,
        default_branch="main",
        language="python",
        package_manager="pip",
        auth_method=GitAuthMethod.NONE,
    )

    assert "Repository created: sentinel" in result.output

    session.close.assert_called_once_with()

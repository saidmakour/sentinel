from pathlib import Path

import pytest

from sentinel.exceptions.source import NoSourceAvailableError
from sentinel.models.repository import Repository
from sentinel.sources.git.source import GitSource
from sentinel.sources.local import LocalSource
from sentinel.sources.registry import SourceRegistry


def create_repository(
    tmp_path: Path,
    remote_url: str = "",
) -> Repository:
    return Repository(
        application_id=1,
        name="test-project",
        local_path=str(tmp_path / "project"),
        remote_url=remote_url,
        default_branch="main",
    )


def test_source_registry_can_be_created() -> None:
    registry = SourceRegistry()

    assert registry is not None


def test_create_returns_local_source_for_local_repository(
    tmp_path: Path,
) -> None:
    registry = SourceRegistry()

    repository = create_repository(
        tmp_path,
    )

    source = registry.create(
        repository,
    )

    assert isinstance(
        source,
        LocalSource,
    )


def test_create_returns_git_source_for_remote_repository(
    tmp_path: Path,
) -> None:
    registry = SourceRegistry()

    repository = create_repository(
        tmp_path,
        remote_url="https://github.com/test/project.git",
    )

    source = registry.create(
        repository,
    )

    assert isinstance(
        source,
        GitSource,
    )


def test_create_raises_error_when_no_source_is_available(
    tmp_path: Path,
) -> None:
    registry = SourceRegistry()

    repository = create_repository(
        tmp_path,
    )

    registry.sources = []

    with pytest.raises(
        NoSourceAvailableError,
        match="No source available",
    ):
        registry.create(
            repository,
        )

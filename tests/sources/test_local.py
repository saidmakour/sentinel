from pathlib import Path

import pytest

from sentinel.enums.source_type import SourceType
from sentinel.exceptions.source import SourcePreparationError
from sentinel.models.repository import Repository
from sentinel.sources.local import LocalSource
from sentinel.sources.prepared import PreparedSource


def create_repository(
    local_path: Path,
    remote_url: str = "",
) -> Repository:
    return Repository(
        application_id=1,
        name="test-project",
        local_path=str(local_path),
        remote_url=remote_url,
        default_branch="main",
    )


def test_local_source_can_be_created() -> None:
    source = LocalSource()

    assert source is not None


def test_supports_local_repository(
    tmp_path: Path,
) -> None:
    source = LocalSource()

    repository = create_repository(
        tmp_path,
    )

    assert (
        source.supports(
            repository,
        )
        is True
    )


def test_does_not_support_remote_repository(
    tmp_path: Path,
) -> None:
    source = LocalSource()

    repository = create_repository(
        tmp_path,
        remote_url="https://github.com/test/project.git",
    )

    assert (
        source.supports(
            repository,
        )
        is False
    )


def test_prepare_returns_prepared_local_source(
    tmp_path: Path,
) -> None:
    source = LocalSource()

    repository = create_repository(
        tmp_path,
    )

    result = source.prepare(
        repository,
    )

    assert result == PreparedSource(
        path=tmp_path,
        source_type=SourceType.LOCAL,
        reference=str(tmp_path),
    )


def test_prepare_raises_error_when_path_does_not_exist(
    tmp_path: Path,
) -> None:
    source = LocalSource()

    missing_path = tmp_path / "missing-project"

    repository = create_repository(
        missing_path,
    )

    with pytest.raises(
        SourcePreparationError,
        match="Local source not found",
    ):
        source.prepare(
            repository,
        )

from pathlib import Path

from sentinel.enums.source_type import SourceType
from sentinel.models.repository import Repository
from sentinel.sources.local import LocalSource


def create_repository(
    path: Path,
) -> Repository:
    return Repository(
        application_id=1,
        name="sentinel",
        local_path=str(path),
        remote_url="",
        language="python",
        package_manager="pip",
    )


def test_local_source_can_be_created() -> None:
    source = LocalSource()

    assert source is not None


def test_local_source_supports_local_repository(
    tmp_path: Path,
) -> None:
    source = LocalSource()

    repository = create_repository(
        tmp_path,
    )

    assert source.supports(repository)


def test_local_source_does_not_support_remote_repository(
    tmp_path: Path,
) -> None:
    source = LocalSource()

    repository = create_repository(
        tmp_path,
    )

    repository.remote_url = "https://github.com/openai/sentinel.git"

    assert not source.supports(repository)


def test_prepare_returns_repository_path(
    tmp_path: Path,
) -> None:
    source = LocalSource()

    repository = create_repository(
        tmp_path,
    )

    result = source.prepare(
        repository,
    )

    assert result.path == Path(repository.local_path)
    assert result.source_type == SourceType.LOCAL
    assert result.reference == repository.local_path


def test_prepare_returns_existing_directory(
    tmp_path: Path,
) -> None:
    source = LocalSource()

    repository = create_repository(
        tmp_path,
    )

    result = source.prepare(
        repository,
    )

    assert result.source_type == SourceType.LOCAL
    assert result.reference == repository.local_path
    assert result.path == tmp_path

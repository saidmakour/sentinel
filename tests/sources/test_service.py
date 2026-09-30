from pathlib import Path
from unittest.mock import MagicMock

from sentinel.enums.source_type import SourceType
from sentinel.models.repository import Repository
from sentinel.sources.prepared import PreparedSource
from sentinel.sources.registry import SourceRegistry
from sentinel.sources.service import SourceService


def create_repository(
    tmp_path: Path,
) -> Repository:
    return Repository(
        application_id=1,
        name="test-project",
        local_path=str(tmp_path / "project"),
        remote_url="",
        default_branch="main",
    )


def test_source_service_can_be_created() -> None:
    service = SourceService()

    assert service is not None


def test_service_can_be_created() -> None:
    service = SourceService()

    assert service is not None


def test_prepare_returns_local_path(
    tmp_path: Path,
) -> None:

    repository = Repository(
        application_id=1,
        name="sentinel",
        local_path=str(tmp_path),
        remote_url="",
        language="python",
        package_manager="pip",
    )

    service = SourceService()

    result = service.prepare(
        repository,
    )

    assert result.path == tmp_path


def test_prepare_returns_existing_directory(
    tmp_path: Path,
) -> None:

    repository = Repository(
        application_id=1,
        name="sentinel",
        local_path=str(tmp_path),
        remote_url="",
        language="python",
        package_manager="pip",
    )

    service = SourceService()

    result = service.prepare(
        repository,
    )

    assert result.path.exists()


def test_source_service_uses_provided_registry() -> None:
    registry = MagicMock(
        spec=SourceRegistry,
    )

    service = SourceService(
        registry=registry,
    )

    assert service.registry is registry


def test_prepare_delegates_to_selected_source(
    tmp_path: Path,
) -> None:
    registry = MagicMock(
        spec=SourceRegistry,
    )

    source = MagicMock()

    repository = create_repository(
        tmp_path,
    )

    prepared_source = PreparedSource(
        path=Path(
            repository.local_path,
        ),
        source_type=SourceType.LOCAL,
        reference=repository.local_path,
    )

    registry.create.return_value = source
    source.prepare.return_value = prepared_source

    service = SourceService(
        registry=registry,
    )

    result = service.prepare(
        repository,
    )

    registry.create.assert_called_once_with(
        repository,
    )

    source.prepare.assert_called_once_with(
        repository,
        forge_name=None,
    )

    assert result is prepared_source

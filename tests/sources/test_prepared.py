from pathlib import Path
from unittest.mock import MagicMock

from sentinel.enums.source_type import SourceType
from sentinel.services.scan_service import ScanService
from sentinel.sources.prepared import PreparedSource


def test_execute_scan_stores_prepared_source_metadata() -> None:
    source_service = MagicMock()

    source_service.prepare.return_value = PreparedSource(
        path=Path("/tmp/repository"),
        source_type=SourceType.GIT,
        reference="https://github.com/test/project.git",
        branch="main",
        commit="abc123",
    )

    engine = MagicMock()
    dependency_repo = MagicMock()
    finding_repo = MagicMock()
    vulnerability_service = MagicMock()

    service = ScanService(
        session=MagicMock(),
        engine=engine,
        source_service=source_service,
        vulnerability_service=vulnerability_service,
    )

    # On remplace les repositories créés dans le constructeur
    service.dependency_repo = dependency_repo
    service.finding_repo = finding_repo

    repository = MagicMock()
    repository.id = 1
    repository.language = "python"

    scan = MagicMock()
    profile = MagicMock()

    engine.scan_dependencies.return_value = []
    engine.find_vulnerabilities.return_value = []

    service._execute_scan(
        repository,
        scan,
        profile,
        forge_name=None,
    )

    source_service.prepare.assert_called_once_with(
        repository,
        forge_name=None,
    )

    assert scan.source_type == SourceType.GIT
    assert scan.source_reference == "https://github.com/test/project.git"
    assert scan.source_branch == "main"
    assert scan.source_commit == "abc123"

    engine.scan_dependencies.assert_called_once_with(
        "python",
        Path("/tmp/repository"),
    )


def test_execute_scan_stores_prepared_source_local() -> None:
    source_service = MagicMock()

    source_service.prepare.return_value = PreparedSource(
        path=Path("/tmp/repository"),
        source_type=SourceType.LOCAL,
        reference="/tmp/repository",
        branch="main",
        commit="abc123",
    )

    engine = MagicMock()
    dependency_repo = MagicMock()
    finding_repo = MagicMock()
    vulnerability_service = MagicMock()

    service = ScanService(
        session=MagicMock(),
        engine=engine,
        source_service=source_service,
        vulnerability_service=vulnerability_service,
    )

    # On remplace les repositories créés dans le constructeur
    service.dependency_repo = dependency_repo
    service.finding_repo = finding_repo

    repository = MagicMock()
    repository.id = 1
    repository.language = "python"

    scan = MagicMock()
    profile = MagicMock()

    engine.scan_dependencies.return_value = []
    engine.find_vulnerabilities.return_value = []

    service._execute_scan(
        repository,
        scan,
        profile,
        forge_name=None,
    )

    source_service.prepare.assert_called_once_with(
        repository,
        forge_name=None,
    )

    assert scan.source_type == SourceType.LOCAL
    assert scan.source_reference == "/tmp/repository"
    assert scan.source_branch == "main"
    assert scan.source_commit == "abc123"

    engine.scan_dependencies.assert_called_once_with(
        "python",
        Path("/tmp/repository"),
    )

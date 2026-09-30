from datetime import UTC
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.severity import Severity
from sentinel.enums.source_type import SourceType
from sentinel.exceptions.repository import RepositoryNotFoundError
from sentinel.models.repository import Repository
from sentinel.models.scan import Scan
from sentinel.services.scan_service import ScanService
from sentinel.sources.prepared import PreparedSource


def create_repository(
    *,
    repository_id: int = 1,
    application_id: int = 1,
    name: str = "test-repo",
    local_path: str = "/tmp/project",
    remote_url: str = "",
    language: str = "python",
) -> Repository:
    return Repository(
        id=repository_id,
        application_id=application_id,
        name=name,
        local_path=local_path,
        remote_url=remote_url,
        language=language,
        package_manager="pip",
    )


def create_scan(
    *,
    scan_id: int = 1,
    repository_id: int = 1,
) -> Scan:
    return Scan(
        id=scan_id,
        repository_id=repository_id,
        status=ScanStatus.STARTED,
        started_at=datetime.now(UTC),
    )


def create_service(
    monkeypatch,
    *,
    repository: Repository | None = None,
    dependencies: list | None = None,
    findings: list[VulnerabilityInfo] | None = None,
    profile: MagicMock | None = None,
) -> tuple[
    ScanService,
    MagicMock,
    MagicMock,
    MagicMock,
    MagicMock,
    MagicMock,
]:
    session = MagicMock()

    repo_repository = MagicMock()
    repo_repository.get_by_name.return_value = repository

    monkeypatch.setattr(
        "sentinel.services.scan_service.RepositoryRepository",
        lambda session: repo_repository,
    )

    scan_repository = MagicMock()
    scan_repository.create.side_effect = lambda scan: scan

    monkeypatch.setattr(
        "sentinel.services.scan_service.ScanRepository",
        lambda session: scan_repository,
    )

    dependency_repository = MagicMock()

    monkeypatch.setattr(
        "sentinel.services.scan_service.DependencyRepository",
        lambda session: dependency_repository,
    )

    finding_repository = MagicMock()

    monkeypatch.setattr(
        "sentinel.services.scan_service.FindingRepository",
        lambda session: finding_repository,
    )

    source_service = MagicMock()

    source_service.prepare.return_value = PreparedSource(
        path=Path("/tmp/project"),
        source_type=SourceType.LOCAL,
        reference="/tmp/project",
    )

    monkeypatch.setattr(
        "sentinel.services.scan_service.SourceService",
        lambda: source_service,
    )

    engine = MagicMock()
    engine.scan_dependencies.return_value = (
        dependencies if dependencies is not None else []
    )
    engine.find_vulnerabilities.return_value = (
        findings if findings is not None else []
    )

    monkeypatch.setattr(
        "sentinel.services.scan_service.SentinelEngine",
        lambda: engine,
    )

    profile_registry = MagicMock()

    if profile is None:
        profile = MagicMock()

    profile_registry.create.return_value = profile

    monkeypatch.setattr(
        "sentinel.services.scan_service.ProfileRegistry",
        lambda: profile_registry,
    )

    vulnerability_service = MagicMock()

    monkeypatch.setattr(
        "sentinel.services.scan_service.VulnerabilityService",
        lambda session: vulnerability_service,
    )

    service = ScanService(session)

    return (
        service,
        session,
        repo_repository,
        scan_repository,
        dependency_repository,
        finding_repository,
    )


def test_run_scan_success(
    monkeypatch,
) -> None:
    repository = create_repository()

    dependency = MagicMock()
    dependency.name = "requests"
    dependency.version = "2.32.3"

    finding = VulnerabilityInfo(
        identifier="CVE-2026-0001",
        aliases=["CVE-2026-0001"],
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        sources=[Provider.OSV],
        severity=Severity.HIGH,
        cvss=7.5,
        summary="Test vulnerability",
    )

    (
        service,
        session,
        repo_repository,
        scan_repository,
        dependency_repository,
        finding_repository,
    ) = create_service(
        monkeypatch,
        repository=repository,
        dependencies=[dependency],
        findings=[finding],
    )

    result = service.run(
        application_id=1,
        repository_name="test-repo",
    )

    assert result.repository_id == repository.id
    assert result.status == ScanStatus.SUCCESS

    repo_repository.get_by_name.assert_called_once_with(
        1,
        "test-repo",
    )

    scan_repository.create.assert_called_once()

    dependency_repository.add_many.assert_called_once_with(
        [dependency],
        result.id,
    )

    finding_repository.add_many.assert_called_once_with(
        [finding],
        result.id,
    )

    session.commit.assert_called()

    assert result.source_type == SourceType.LOCAL
    assert result.source_reference == "/tmp/project"
    assert result.source_branch is None
    assert result.source_commit is None


def test_run_scan_uses_local_source(
    monkeypatch,
) -> None:
    repository = create_repository(
        remote_url="",
    )

    service, _, _, _, _, _ = create_service(
        monkeypatch,
        repository=repository,
    )

    service.source_service.prepare.return_value = PreparedSource(
        path=Path("/tmp/project"),
        source_type=SourceType.LOCAL,
        reference="/tmp/project",
    )

    service.run(
        application_id=1,
        repository_name="test-repo",
    )

    service.source_service.prepare.assert_called_once_with(
        repository,
        forge_name=None,
    )

    service.engine.scan_dependencies.assert_called_once_with(
        "python",
        Path("/tmp/project"),
    )
    scan = service.scan_repo.create.call_args.args[0]
    assert scan.source_type == SourceType.LOCAL
    assert scan.source_reference == "/tmp/project"
    assert scan.source_branch is None
    assert scan.source_commit is None


def test_run_scan_uses_remote_source(
    monkeypatch,
) -> None:
    repository = create_repository(
        remote_url="https://gitlab.example.com/project.git",
    )

    service, _, _, _, _, _ = create_service(
        monkeypatch,
        repository=repository,
    )

    service.source_service.prepare.return_value = PreparedSource(
        path=Path("/tmp/workspace/repo"),
        source_type=SourceType.GIT,
        reference="https://gitlab.example.com/project.git",
        branch="main",
        commit="abc123",
    )

    service.run(
        application_id=1,
        repository_name="test-repo",
    )

    service.engine.scan_dependencies.assert_called_once_with(
        "python",
        Path("/tmp/workspace/repo"),
    )

    assert service.engine.scan_dependencies.call_args.args == (
        "python",
        Path("/tmp/workspace/repo"),
    )
    scan = service.scan_repo.create.call_args.args[0]

    assert scan.source_type == SourceType.GIT
    assert scan.source_reference == ("https://gitlab.example.com/project.git")
    assert scan.source_branch == "main"
    assert scan.source_commit == "abc123"


def test_run_scan_uses_requested_profile(
    monkeypatch,
) -> None:
    repository = create_repository()
    profile = MagicMock()

    service, _, _, _, _, _ = create_service(
        monkeypatch,
        repository=repository,
        profile=profile,
    )

    service.run(
        application_id=1,
        repository_name="test-repo",
        profile_name="enterprise",
    )

    service.profile_registry.create.assert_called_once_with(
        "enterprise",
    )

    service.engine.find_vulnerabilities.assert_called_once_with(
        [],
        profile,
    )


def test_run_scan_uses_default_profile(
    monkeypatch,
) -> None:
    repository = create_repository()

    service, _, _, _, _, _ = create_service(
        monkeypatch,
        repository=repository,
    )

    service.run(
        application_id=1,
        repository_name="test-repo",
    )

    service.profile_registry.create.assert_called_once_with(
        "default",
    )


def test_run_scan_syncs_vulnerabilities(
    monkeypatch,
) -> None:
    repository = create_repository()

    findings = [
        VulnerabilityInfo(
            identifier="CVE-2026-0001",
            aliases=["CVE-2026-0001"],
            dependency_name="requests",
            dependency_version="2.32.3",
            ecosystem=Ecosystem.PYPI,
            sources=[Provider.OSV],
            severity=Severity.HIGH,
            cvss=7.5,
            summary="Test vulnerability",
        ),
        VulnerabilityInfo(
            identifier="CVE-2026-0002",
            aliases=["CVE-2026-0002"],
            dependency_name="flask",
            dependency_version="3.1.0",
            ecosystem=Ecosystem.PYPI,
            sources=[Provider.NVD],
            severity=Severity.CRITICAL,
            cvss=9.8,
            summary="Critical vulnerability",
        ),
    ]

    service, _, _, _, _, _ = create_service(
        monkeypatch,
        repository=repository,
        findings=findings,
    )

    service.run(
        application_id=1,
        repository_name="test-repo",
    )

    assert service.vulnerability_service.sync.call_count == 2

    service.vulnerability_service.sync.assert_any_call(
        1,
        "CVE-2026-0001",
    )

    service.vulnerability_service.sync.assert_any_call(
        1,
        "CVE-2026-0002",
    )


def test_run_scan_resolves_missing_vulnerabilities(
    monkeypatch,
) -> None:
    repository = create_repository()

    finding = VulnerabilityInfo(
        identifier="CVE-2026-0001",
        aliases=["CVE-2026-0001"],
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        sources=[Provider.OSV],
        severity=Severity.LOW,
        cvss=1.0,
        summary="Test vulnerability",
    )

    service, _, _, _, _, _ = create_service(
        monkeypatch,
        repository=repository,
        findings=[finding],
    )

    service.run(
        application_id=1,
        repository_name="test-repo",
    )

    service.vulnerability_service.resolve_missing.assert_called_once_with(
        repository_id=1,
        identifiers={
            "CVE-2026-0001",
        },
    )


def test_run_scan_resolves_missing_with_empty_identifiers(
    monkeypatch,
) -> None:
    repository = create_repository()

    service, _, _, _, _, _ = create_service(
        monkeypatch,
        repository=repository,
        findings=[],
    )

    service.run(
        application_id=1,
        repository_name="test-repo",
    )

    service.vulnerability_service.resolve_missing.assert_called_once_with(
        repository_id=1,
        identifiers=set(),
    )


def test_run_scan_marks_scan_as_failed_when_engine_fails(
    monkeypatch,
) -> None:
    repository = create_repository()

    service, session, _, scan_repository, _, _ = create_service(
        monkeypatch,
        repository=repository,
    )

    service.engine.scan_dependencies.side_effect = RuntimeError(
        "Scan failed",
    )

    with pytest.raises(
        RuntimeError,
        match="Scan failed",
    ):
        service.run(
            application_id=1,
            repository_name="test-repo",
        )

    scan = scan_repository.create.call_args.args[0]

    assert scan.status == ScanStatus.FAILED

    session.rollback.assert_called_once()
    session.commit.assert_called()


def test_run_scan_reraises_original_exception(
    monkeypatch,
) -> None:
    repository = create_repository()

    service, _, _, _, _, _ = create_service(
        monkeypatch,
        repository=repository,
    )

    error = RuntimeError("Original error")

    service.engine.scan_dependencies.side_effect = error

    with pytest.raises(RuntimeError) as exc_info:
        service.run(
            application_id=1,
            repository_name="test-repo",
        )

    assert exc_info.value is error


def test_run_scan_repository_not_found(
    monkeypatch,
) -> None:
    service, _, repo_repository, _, _, _ = create_service(
        monkeypatch,
        repository=None,
    )

    with pytest.raises(
        RepositoryNotFoundError,
        match="Repository 'missing-repo' not found",
    ):
        service.run(
            application_id=1,
            repository_name="missing-repo",
        )

    repo_repository.get_by_name.assert_called_once_with(
        1,
        "missing-repo",
    )


def test_run_scan_does_not_execute_when_repository_not_found(
    monkeypatch,
) -> None:
    service, _, _, _, _, _ = create_service(
        monkeypatch,
        repository=None,
    )

    with pytest.raises(RepositoryNotFoundError):
        service.run(
            application_id=1,
            repository_name="missing-repo",
        )

    service.source_service.prepare.assert_not_called()
    service.engine.scan_dependencies.assert_not_called()
    service.engine.find_vulnerabilities.assert_not_called()


def test_mark_finished_sets_duration() -> None:
    scan = Scan(
        repository_id=1,
    )

    scan.mark_finished(42)

    assert scan.status == ScanStatus.SUCCESS
    assert scan.duration_seconds == 42
    assert scan.finished_at is not None


def test_run_scan_creates_local_scan_with_source_metadata(
    monkeypatch,
) -> None:
    repository = create_repository(
        remote_url="",
    )

    service, _, _, scan_repository, _, _ = create_service(
        monkeypatch,
        repository=repository,
    )

    service.source_service.prepare.return_value = PreparedSource(
        path=Path(repository.local_path),
        source_type=SourceType.LOCAL,
        reference=repository.local_path,
    )

    service.run(
        application_id=1,
        repository_name="test-repo",
    )

    scan = scan_repository.create.call_args.args[0]

    assert scan.source_type == SourceType.LOCAL
    assert scan.source_reference == repository.local_path
    assert scan.source_branch is None
    assert scan.source_commit is None


def test_fail_scan_rolls_back_marks_failed_and_commits() -> None:
    session = MagicMock()

    service = ScanService(
        session,
    )

    scan = Scan(
        id=1,
        repository_id=1,
        status=ScanStatus.STARTED,
        started_at=datetime.now(UTC),
    )

    error = RuntimeError("scan failed")

    service._fail_scan(
        scan,
        error,
    )

    assert scan.status == ScanStatus.FAILED
    assert scan.error_message == "scan failed"
    session.rollback.assert_called_once_with()
    session.commit.assert_called()
